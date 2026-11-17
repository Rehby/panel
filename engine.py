import base64
import wdtt
import webproxy
import traffic
import images
import provision
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid
from urllib.parse import quote, urlencode
from catalog import BY_ID
from transports import BY_TRANSPORT, validate_transport, transport_settings, client_config, vision
from image_presets import validate_custom, custom_bundle


def credential():
    return dict(uuid=str(uuid.uuid4()), password=secrets.token_urlsafe(24))


def validate(s):
    if s.get('protocol') not in BY_ID:
        raise ValueError('Неизвестный протокол')
    if not str(s.get('name','')).strip() or len(s['name']) > 100:
        raise ValueError('Укажите название до 100 символов')
    host = str(s.get('host','')).strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?',host):
            raise ValueError('Укажите IP или домен без схемы и порта')
    s['host'] = host
    s['port'] = int(s.get('port',443))
    if not 1 <= s['port'] <= 65535:
        raise ValueError('Порт должен быть от 1 до 65535')
    s['transport'] = s.get('transport','tcp')
    s['security'] = s.get('security','none' if s['protocol']=='webproxy' else 'tls')
    s['sni'] = s.get('sni') or host
    s['path'] = s.get('path') or '/tunnel'
    if s['protocol']=='webproxy':return webproxy.validate(s)
    if s['protocol']=='wdtt':return wdtt.validate(s)
    if s.get('provisioned'):return provision.prepare(s)
    if BY_ID[s['protocol']]['mode']=='custom':return validate_custom(s)
    if s['protocol'] in ('vless','vmess','trojan'):validate_transport(s)
    elif s['transport'] not in ('tcp','ws','grpc'):raise ValueError('Для этого протокола доступны TCP, WS, gRPC')
    if s['security'] not in ('tls','reality','none'):
        raise ValueError('Неизвестный режим безопасности')
    try:ipaddress.ip_address(s.get('listen','0.0.0.0'))
    except ValueError:raise ValueError('Listen IP: укажите IPv4 или IPv6')
    s['listen']=s.get('listen','0.0.0.0')
    s['fingerprint']=s.get('fingerprint','chrome')
    if s['fingerprint'] not in ('chrome','firefox','safari','edge','random','randomized'):raise ValueError('Неизвестный fingerprint')
    if s['protocol']=='vless':
        s['flow']=s.get('flow','xtls-rprx-vision' if s['security']=='reality' and s['transport']=='tcp' else '')
        if s['flow'] not in ('','xtls-rprx-vision'):raise ValueError('Неизвестный flow')
        if s['flow'] and (s['transport']!='tcp' or s['security'] not in ('tls','reality')):raise ValueError('Vision доступен только с RAW/TCP + TLS/Reality')
    s['alpn']=[x.strip() for x in s.get('alpn','').split(',') if x.strip()] if isinstance(s.get('alpn',''),str) else s.get('alpn',[])
    if not isinstance(s['alpn'],list) or not all(x in ('h2','http/1.1','h3') for x in s['alpn']):raise ValueError('ALPN: доступны h2, http/1.1, h3')
    if s.get('tls_min','1.2') not in ('1.2','1.3'):raise ValueError('TLS min: выберите 1.2 или 1.3')
    if s['protocol'] in ('trojan','hysteria2') and s['security'] != 'tls':
        raise ValueError('Для Trojan и Hysteria2 нужен TLS')
    if s['security'] == 'reality' and (s['protocol'] != 'vless' or s['transport'] not in ('tcp','xhttp','grpc')):
        raise ValueError('Reality поддерживает VLESS RAW, XHTTP и gRPC')
    if s.get('self_sni'):
        if s['protocol']!='vless' or s['security']!='reality' or s['transport'] not in ('tcp','xhttp','grpc'):raise ValueError('Self-SNI доступен для VLESS RAW / XHTTP / gRPC + Reality')
        domain=s.get('self_sni_domain','')
        if not re.fullmatch(r'[a-zA-Z0-9.-]+',domain) or '.' not in domain:raise ValueError('Для self-SNI нужен домен с HTTPS')
        s['sni']=domain
    if s['protocol'] == 'shadowsocks':
        if s.get('method','chacha20-ietf-poly1305') not in ('chacha20-ietf-poly1305','aes-128-gcm','aes-256-gcm'):raise ValueError('Неподдерживаемый шифр Shadowsocks')
        s['security'] = 'none'
        s['transport'] = 'tcp'
    elif s['security'] == 'tls':
        if 'BEGIN CERTIFICATE' not in s.get('certificate','') or 'PRIVATE KEY' not in s.get('private_key',''):
            raise ValueError('Для TLS нужны сертификат и приватный ключ в PEM')
    if s['security'] == 'reality' and not s.get('reality_private'):
        openssl = os.environ.get('YPTUN_OPENSSL') or next((p for p in ['/opt/homebrew/opt/openssl@3/bin/openssl','/usr/local/opt/openssl@3/bin/openssl'] if Path(p).is_file()),'openssl')
        key = subprocess.run([openssl,'genpkey','-algorithm','X25519'],capture_output=True,check=True).stdout
        priv = subprocess.run([openssl,'pkey','-outform','DER'],input=key,capture_output=True,check=True).stdout[-32:]
        pub = subprocess.run([openssl,'pkey','-pubout','-outform','DER'],input=key,capture_output=True,check=True).stdout[-32:]
        s.update(reality_private=base64.urlsafe_b64encode(priv).decode().rstrip('='),reality_public=base64.urlsafe_b64encode(pub).decode().rstrip('='),short_id=secrets.token_hex(8))
    return s


def bundle(s, users):
    users=[dict(u,enabled=u.get('enabled',True) and not u.get('quota_blocked')) for u in users]
    files=traffic.configure(s,_bundle(s,users))
    compose=json.loads(files['compose.json'])
    if BY_ID[s['protocol']]['mode']!='custom' or s.get('provisioned'):
        for service in compose['services'].values():
            for image in images.CATALOG:
                if service.get('image')==image['reference']:service['image']=images.image_updates.current(image)['reference']
    files['compose.json']=json.dumps(compose,indent=2)
    if s.get('image_override'):
        compose=json.loads(files['compose.json'])
        main='warp' if s['protocol']=='warp' and s.get('provisioned') else 'tunnel'
        compose['services'][main]['image']=s['image_override']
        files['compose.json']=json.dumps(compose,indent=2)
    return files


def _bundle(s, users):
    p = s['protocol']
    if p=='webproxy':return webproxy.bundle(s,users)
    if s.get('provisioned'):return provision.bundle(s,users)
    if p=='wdtt':return wdtt.bundle(s)
    clients = [u for u in users if u.get('enabled',True)]
    files = {}
    if BY_ID[p]['mode'] == 'custom':
        files,service=custom_bundle(s)
    elif p == 'hysteria2':
        inbound = dict(type='hysteria2',tag='in',listen=s.get('listen','::'),listen_port=s['port'],users=[dict(name=u['name'],password=u['password']) for u in clients],tls=dict(enabled=True,certificate_path='/etc/yptun/cert.pem',key_path='/etc/yptun/key.pem'))
        if s.get('obfs'):
            inbound['obfs'] = dict(type='salamander',password=s['obfs'])
        files['config.json'] = json.dumps(dict(log=dict(level='info'),inbounds=[inbound],outbounds=[dict(type='direct',tag='direct')]),indent=2)
        service = dict(image='ghcr.io/sagernet/sing-box:v1.12.0',command=['run','-c','/etc/yptun/config.json'],volumes=['./config.json:/etc/yptun/config.json:ro'])
    else:
        if p == 'shadowsocks':
            # Xray multi-user Shadowsocks has different cipher constraints: isolate one access per service.
            if len(clients) > 1:
                raise ValueError('Shadowsocks: один пользователь на службу; создайте отдельную службу для другого доступа')
            settings = dict(method=s.get('method','chacha20-ietf-poly1305'),password=clients[0]['password'] if clients else secrets.token_urlsafe(32),network='tcp,udp')
        else:
            settings = dict(clients=[dict(id=u['uuid'],email=u['id'],**({'flow':'xtls-rprx-vision'} if vision(s) else {})) if p in ('vless','vmess') else dict(password=u['password'],email=u['id']) for u in clients])
            if p == 'vless': settings['decryption']='none'
        stream = dict(network=s['transport'],security=s['security'])
        if s['security'] == 'tls': stream['tlsSettings']=dict(minVersion=s.get('tls_min','1.2'),certificates=[dict(certificateFile='/etc/yptun/cert.pem',keyFile='/etc/yptun/key.pem')])
        if s['security']=='tls' and s.get('alpn'):stream['tlsSettings']['alpn']=s['alpn']
        if s['security'] == 'reality': stream['realitySettings']=dict(show=False,dest='127.0.0.1:9443' if s.get('self_sni') else s['sni']+':443',xver=0,serverNames=[s['sni']],privateKey=s['reality_private'],shortIds=[s['short_id']])
        if p in ('vless','vmess','trojan'):
            stream[BY_TRANSPORT[s['transport']]['key']]=transport_settings(s)
            if s['security']=='tls' and s['transport'] in ('ws','httpupgrade'):stream['tlsSettings']['alpn']=['http/1.1']
            if s['security']=='tls' and s['transport'] in ('hysteria','masque'):stream['tlsSettings']['alpn']=['h3']
        else:
            if s['transport']=='ws':stream['wsSettings']=dict(path=s['path'])
            if s['transport']=='grpc':stream['grpcSettings']=dict(serviceName=s['path'].strip('/'))
        inbound = dict(tag='in',listen=s.get('listen','0.0.0.0'),port=s['port'],protocol=p,settings=settings,streamSettings=stream)
        if s.get('sniffing'):inbound['sniffing']=dict(enabled=True,destOverride=['http','tls','quic'],routeOnly=True)
        files['config.json']=json.dumps(dict(log=dict(loglevel='warning'),inbounds=[inbound],outbounds=[dict(protocol='freedom',tag='direct')]),indent=2)
        service=dict(image='ghcr.io/xtls/xray-core:26.9.30',command=['run','-config','/etc/yptun/config.json'],volumes=['./config.json:/etc/yptun/config.json:ro'])
    if s.get('certificate'):
        files.update({'cert.pem':s['certificate'],'key.pem':s['private_key']})
        service['volumes'] += ['./cert.pem:/etc/yptun/cert.pem:ro','./key.pem:/etc/yptun/key.pem:ro']
    service.setdefault('ports',[f"{s['port']}:{s['port']}/tcp",f"{s['port']}:{s['port']}/udp"])
    if service.get('network_mode')=='host':service.pop('ports',None)
    service.update(restart='unless-stopped',logging=dict(driver='json-file',options={'max-size':'10m','max-file':'3'}))
    if BY_ID[p]['mode']=='native':
        service.update(user=str(os.getuid())+':'+str(os.getgid()),cap_drop=['ALL'],cap_add=['NET_BIND_SERVICE'],security_opt=['no-new-privileges:true'])
    if s.get('self_sni'):
        service.pop('ports',None);service['network_mode']='host'
    files['compose.json']=json.dumps(dict(services=dict(tunnel=service)),indent=2)
    return files


def profile(s,u):
    if s['protocol']=='webproxy':return webproxy.link(s,u)
    if s.get('provisioned'):return provision.profile(s,u)
    if s['protocol']=='wdtt':return wdtt.link(s,u)
    p=s['protocol']; host=s['host']; host='['+host+']' if ':' in host else host
    addr=f"{host}:{s['port']}"; label=quote(u['name'] if u.get('auto_name') else s['name']+' · '+u['name'])
    if BY_ID[p]['mode']=='custom':
        if not u.get('profile','').strip(): raise ValueError('Для этого движка добавьте клиентскую ссылку или конфиг пользователя')
        return u['profile']
    if p in ('vless','vmess','trojan') and (s['transport'] in ('kcp','hysteria','masque','xdrive') or s.get('transport_settings') or s.get('client_transport_settings') or s.get('alpn') or s.get('allow_insecure')):
        return json.dumps(client_config(s,u),indent=2,ensure_ascii=False)
    q=dict(security=s['security'],type=s['transport'],sni=s['sni'])
    if s['transport'] in ('ws','httpupgrade','xhttp'):q['path']=s['path']
    if s.get('transport_host'):q['host']=s['transport_host']
    if s['transport']=='xhttp':q['mode']=s.get('xhttp_mode','auto')
    if s['transport']=='grpc': q['serviceName']=s['path'].strip('/')
    if s['security']=='reality': q.update(pbk=s['reality_public'],sid=s['short_id'],fp=s.get('fingerprint','chrome'))
    if vision(s):q['flow']='xtls-rprx-vision'
    if s['security']=='tls':q['fp']=s.get('fingerprint','chrome')
    if p=='vless': q['encryption']='none'
    if p in ('vless','trojan'): return f"{p}://{quote(u['uuid'] if p=='vless' else u['password'],safe='')}@{addr}?{urlencode(q)}#{label}"
    if p=='hysteria2':
        q=dict(sni=s['sni'])
        if s.get('allow_insecure'):q['insecure']='1'
        if s.get('obfs'):q.update(obfs='salamander',**{'obfs-password':s['obfs']})
        return f"hysteria2://{quote(u['password'],safe='')}@{addr}?{urlencode(q)}#{label}"
    if p=='shadowsocks':
        auth=base64.urlsafe_b64encode((s.get('method','chacha20-ietf-poly1305')+':'+u['password']).encode()).decode().rstrip('=')
        return f'ss://{auth}@{addr}#{label}'
    data=dict(v='2',ps=u['name'] if u.get('auto_name') else s['name'],add=s['host'],port=str(s['port']),id=u['uuid'],aid='0',scy='auto',net=s['transport'],type='none',host=s['sni'],path=s['path'].strip('/') if s['transport']=='grpc' else s['path'],tls='tls' if s['security']=='tls' else '',sni=s['sni'],fp=s.get('fingerprint','chrome'))
    return 'vmess://'+base64.b64encode(json.dumps(data).encode()).decode()
