"""YPtun's mixed-link subscription and lossless inbound codec (v1)."""
import base64
import datetime
import json
from engine import profile


def inbound(location):
    data=json.dumps(location,ensure_ascii=False,separators=(',',':')).encode()
    return 'yptun://inbound?v=1&d='+base64.urlsafe_b64encode(data).decode().rstrip('=')


def link(s,u):
    name=u['name'] if u.get('auto_name') else s['name']+' · '+u['name']
    if s['protocol']=='wdtt':
        return inbound(dict(id=u['id'],name=name,engine='vkturn',vkturn=dict(core='wdtt',vk_link=u['vk_hash'].replace(',','\n'),listen_port=s['local_port'],wdtt_peer=s['host'],wdtt_port=s['port'],wdtt_password=u['password'],wdtt_workers=18)))
    text=profile(s,u).strip()
    if text.startswith('[') and '[Interface]' in text:
        return inbound(dict(id=u['id'],name=name,engine='standard',proxy=dict(type='amneziawg',server=s['host'],server_port=s['port'],awg_config=text)))
    if text.startswith('{'):
        config=json.loads(text)
        if 'engine' in config:
            config['name']=name
            if config.get('engine') not in ('stealth','chain'):config['id']=u['id']
            return inbound(config)
        if 'outbounds' in config and any('protocol' in x for x in config['outbounds']):
            return inbound(dict(id=u['id'],name=name,engine='standard',core='xray',proxy=dict(type=s['protocol'],server=s['host'],server_port=s['port'],raw_xray_config=text)))
        if 'type' in config:
            return inbound(dict(id=u['id'],name=name,engine='standard',proxy=dict(type=config['type'],server=s['host'],server_port=s['port'],rawOutbound=text)))
        raise ValueError('Этот импортированный JSON не поддерживает общую подписку; используйте ссылку YPtun или полный Xray-конфиг')
    if '://' not in text or '\n' in text:raise ValueError('Для общей подписки нужен совместимый профиль подключения YPtun')
    return text


def service_available(service):
    return service.get('desired') != 'stopped'


def feed(person,connections,services,available):
    by_id={s['id']:s for s in services}
    links=[];unavailable=[]
    for u in connections:
        service=by_id.get(u['service_id'])
        if u.get('person_id')!=person['id'] or not service or service['protocol']=='webproxy' or not service_available(service) or not available(u):continue
        try:links.append(link(service,u))
        except (ValueError,KeyError):unavailable.append(dict(name=u['name'],reason='Импортированный профиль требует совместимой ссылки YPtun'))
    result=dict(version=1,subscriptionName=person['name'],updatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),links=links)
    if unavailable:result['unavailableProfiles']=unavailable
    return result
