"""qWDTT v1.4.3 adapter: TURN tunnel and personal subscriptions only."""
import datetime
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

IMAGE='yptun/wdtt:1.4.3'
class CoreNotFound(ValueError):pass
class CoreUnavailable(ValueError):pass

def hashes(value):
    items=[]
    for item in re.split(r'[,\s]+',str(value).strip()):
        if not item:continue
        if '://' in item:
            u=urllib.parse.urlsplit(item)
            if u.hostname not in ('vk.com','vk.ru','www.vk.com','www.vk.ru'):raise ValueError('Нужна ссылка звонка VK или VK-хеш')
            item=u.path.rstrip('/').split('/')[-1]
        if not re.fullmatch(r'[A-Za-z0-9_-]{3,256}',item):raise ValueError('Некорректный VK-хеш')
        if item not in items:items.append(item)
    if not 1<=len(items)<=4:raise ValueError('Укажите от 1 до 4 VK-хешей')
    return ','.join(items)

def validate(s):
    if ':' in s['host']:raise ValueError('WDTT URI: используйте домен или IPv4')
    if s.get('vk_hash'):s['vk_hash']=hashes(s['vk_hash'])
    s['wg_port']=int(s.get('wg_port',56001));s['local_port']=int(s.get('local_port',9000))
    if not all(1024<=s[k]<=65535 for k in ('port','wg_port','local_port')):raise ValueError('Порты WDTT: 1024–65535')
    s['dns']=s.get('dns') or '1.1.1.1'
    for addr in s['dns'].split(','):ipaddress.ip_address(addr.strip())
    if not s.get('admin_port'):
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));s['admin_port']=sock.getsockname()[1]
    s['admin_port']=int(s['admin_port'])
    if not 1024<=s['admin_port']<=65535 or s['admin_port']==s['port']:raise ValueError('Некорректный локальный admin-порт')
    if not s.get('admin_token'):
        s['admin_token']=secrets.token_urlsafe(32);s['owner_password']=secrets.token_urlsafe(24)
        with tempfile.TemporaryDirectory() as tmp:
            cert=Path(tmp)/'cert';key=Path(tmp)/'key'
            openssl=next((p for p in ['/opt/homebrew/opt/openssl@3/bin/openssl','/usr/local/opt/openssl@3/bin/openssl'] if Path(p).exists()),'openssl')
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','3650','-keyout',str(key),'-out',str(cert),'-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
            s.update(admin_cert=cert.read_text(),admin_key=key.read_text())
    return s

def bundle(s):
    files={'admin.token':s['admin_token'],'owner.password':s['owner_password'],'admin.pem':s['admin_cert'],'admin-key.pem':s['admin_key']}
    service=dict(image=IMAGE,restart='unless-stopped',cap_add=['NET_ADMIN'],devices=['/dev/net/tun:/dev/net/tun'],sysctls={'net.ipv4.ip_forward':'1'},volumes=['./runtime:/etc/wdtt','./admin.token:/run/secrets/admin.token:ro','./owner.password:/run/secrets/owner.password:ro','./admin.pem:/run/secrets/admin.pem:ro','./admin-key.pem:/run/secrets/admin-key.pem:ro'],ports=[f"{s['port']}:56000/udp",f"{s['port']}:56000/tcp",f"127.0.0.1:{s['admin_port']}:56002/tcp"],command=['-listen','0.0.0.0:56000','-wg-port',str(s['wg_port']),'-config-dir','/etc/wdtt','-password-file','/run/secrets/owner.password','-dns',s['dns'],'-admin-listen','0.0.0.0:56002','-admin-token-file','/run/secrets/admin.token','-admin-cert','/run/secrets/admin.pem','-admin-key','/run/secrets/admin-key.pem'],logging=dict(driver='json-file',options={'max-size':'10m','max-file':'3'}))
    files['compose.json']=json.dumps({'services':{'tunnel':service}},indent=2)
    return files

def request(s,path='',data=None):
    context=ssl.create_default_context(cadata=s['admin_cert'])
    req=urllib.request.Request(f"https://127.0.0.1:{s['admin_port']}/admin/passwords"+path,data=urllib.parse.urlencode(data).encode() if data is not None else None,headers={'Authorization':'Bearer '+s['admin_token'],'Content-Type':'application/x-www-form-urlencoded'})
    try:
        # Explicitly bypass proxy settings for the private loopback administration endpoint.
        op=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        return json.load(op.open(req,timeout=15))
    except urllib.error.HTTPError as e:
        error=CoreNotFound if e.code==404 else ValueError
        raise error('WDTT: '+e.read(2000).decode(errors='replace'))
    except (OSError,urllib.error.URLError):raise CoreUnavailable('WDTT API недоступен. Запустите туннель и проверьте его журнал')

def user_fields(s,data):
    name=str(data.get('name','')).strip()
    if not 1<=len(name)<=64:raise ValueError('Метка: от 1 до 64 символов')
    days=int(data.get('days') or 30);devices=int(data.get('max_devices') or 1)
    if not 1<=days<=365 or not 1<=devices<=10:raise ValueError('Срок: 1–365 дней; устройства: 1–10')
    return dict(label=name,vk_hash=hashes(s.get('vk_hash') or data.get('vk_hash','')),days=days,max_devices=devices,ports=f"{s['port']},{s['wg_port']},{s['local_port']}")

def apply_view(u,view):
    u.update(password=view['password'],name=view.get('label') or u['name'],vk_hash=view.get('vk_hash',''),expires_at=view.get('expires_at',0),max_devices=view.get('max_devices',1),enabled=not view.get('is_deactivated',False))
    return u

def link(s,u):
    # YPtun parses qwdtt://config; peer may carry the randomized DTLS port.
    return 'qwdtt://config?'+urllib.parse.urlencode(dict(name=u['name'],peer=f"{s['host']}:{s['port']}",hashes=u['vk_hash'],workers=18,port=s['local_port'],**{'pass':u['password']}))


def offline_change(database,path='',data=None):
    """Same password schema as v1.4.3; caller must prove the core is stopped."""
    passwords=database.setdefault('passwords',{});devices=database.setdefault('devices',{})
    now=int(time.time())
    if data is None:return dict(passwords=[dict(entry,password=password,**{k:entry.get(k,0) for k in ('up_bytes','down_bytes') if k not in entry}) for password,entry in passwords.items() if not entry.get('expires_at') or entry['expires_at']>now])
    password=data.get('password')
    if not path:
        for key,entry in list(passwords.items()):
            if entry.get('expires_at') and entry['expires_at']<=now:
                offline_change(database,'/delete',dict(password=key))
        if len(passwords)>=10:raise ValueError('Лимит TURN-подписок достигнут: 10/10')
        password=secrets.token_urlsafe(24)
        passwords[password]=dict(label=data['label'],vk_hash=data['vk_hash'],max_devices=int(data['max_devices']),expires_at=now+int(data['days'])*86400,ports=data['ports'],device_ids=[],is_deactivated=False)
    elif path=='/delete':
        entry=passwords.pop(password,None)
        if entry:
            ids=set(entry.get('device_ids') or [])|{entry.get('device_id')}
            for key,device in list(devices.items()):
                if key in ids or device.get('owner_id')==password or device.get('raw_owner_id')==password:devices.pop(key,None)
        return {}
    else:
        if password not in passwords:raise CoreNotFound('WDTT: подписка не найдена')
        entry=passwords[password]
        if path=='/update':
            for key in ('label','vk_hash','max_devices'):
                if key in data:entry[key]=data[key]
            if 'days' in data:entry['expires_at']=now+int(data['days'])*86400
        elif path in ('/activate','/deactivate'):entry['is_deactivated']=path=='/deactivate'
        else:raise ValueError('Неизвестная операция WDTT')
    return dict(passwords[password],password=password)

def subscription(s,u):
    return dict(version=1,subscriptionName=u['name'],description='Персональная подписка qWDTT',updatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),profiles=[dict(name=u['name'],peer=f"{s['host']}:{s['port']}",hashes=u['vk_hash'],workers=16,port=s['local_port'],password=u['password'],expiresAt=u.get('expires_at',0))])

def available(u):return not u.get('quota_blocked') and u.get('enabled',True) and (not u.get('expires_at') or u['expires_at']>time.time())


def counters(view,users):
    """Read password counters from the stock qWDTT 1.4.3 admin API."""
    entries=view if isinstance(view,list) else view.get('passwords') if isinstance(view,dict) else None
    if isinstance(entries,dict):entries=[dict(entry,password=password) for password,entry in entries.items()]
    if not isinstance(entries,list) or not all(isinstance(entry,dict) and isinstance(entry.get('password'),str) for entry in entries):
        raise ValueError('WDTT: некорректный ответ статистики')
    by_password={entry['password']:entry for entry in entries};result={}
    for u in users:
        entry=by_password.get(u['password'])
        if entry is None:
            if u.get('expires_at') and u['expires_at']<=time.time():continue
            raise ValueError('WDTT: доступ отсутствует в ответе статистики')
        values=[]
        for field in ('up_bytes','down_bytes'):
            raw=entry.get(field)
            if isinstance(raw,bool) or not (isinstance(raw,int) or isinstance(raw,str) and re.fullmatch(r'[0-9]+',raw)) or int(raw)<0:
                raise ValueError('WDTT: ядро не вернуло корректные счётчики трафика')
            values.append(int(raw))
        result[u['id']]=values
    return result


def sync_limits(panel,s):
    """Apply quota restrictions through the core API, preserving manual revocation."""
    for u in panel.members(s['id']):
        blocked=bool(u.get('quota_blocked'))
        if not blocked and not u.get('wdtt_quota_applied'):continue
        if u.get('expires_at') and u['expires_at']<=time.time():
            u['wdtt_quota_applied']=blocked;panel.put('user',u);continue
        desired=bool(u.get('enabled',True)) and not blocked
        panel.turn_request(s,'/activate' if desired else '/deactivate',dict(password=u['password']))
        u['wdtt_quota_applied']=blocked;panel.put('user',u)
