"""Typed server/client generators matching the YPtun installers and inbound codec.

Imported configurations remain an explicit advanced mode. Shared-secret room engines
use one access per instance, so revocation stops its only listener.
"""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from urllib.parse import quote, urlencode, urlsplit
import zlib
from images import BY_IMAGE

PROTOCOLS={'wireguard','amneziawg','olcrtc','vkturn','masterdns','openflux','trusttunnel','snolc','warp'}
SINGLE={'olcrtc','masterdns','openflux','snolc'}
RTC_TRANSPORTS={'jitsi':('datachannel','vp8channel','seichannel','videochannel'),'mtslink':('vp8channel',),'vkcalls':('vp8channel','seichannel','videochannel'),'salutejazz':('datachannel',),'telemost':('vp8channel','videochannel','seichannel','datachannel')}
IMAGE_IDS={'vkturn':'freeturn'}

def keypair():
    openssl=os.environ.get('YPTUN_OPENSSL') or next((p for p in ['/opt/homebrew/opt/openssl@3/bin/openssl','/usr/local/opt/openssl@3/bin/openssl'] if Path(p).is_file()),'openssl')
    pem=subprocess.run([openssl,'genpkey','-algorithm','X25519'],check=True,capture_output=True).stdout
    private=subprocess.run([openssl,'pkey','-outform','DER'],input=pem,check=True,capture_output=True).stdout[-32:]
    public=subprocess.run([openssl,'pkey','-pubout','-outform','DER'],input=pem,check=True,capture_output=True).stdout[-32:]
    return private,public

def prepare(s):
    p=s['protocol']
    if p not in PROTOCOLS:raise ValueError('Нет автоматического установщика этого движка')
    preset=BY_IMAGE[IMAGE_IDS.get(p,p)]
    s.update(provisioned=True,image_id=preset['id'],image=preset['reference'],raw_config='{}')
    if p in ('wireguard','amneziawg','vkturn','snolc','warp') and not s.get('server_private'):
        priv,pub=keypair();s.update(server_private=base64.b64encode(priv).decode(),server_public=base64.b64encode(pub).decode())
    if p in ('wireguard','amneziawg','vkturn'):
        s.setdefault('subnet','10.'+str(secrets.randbelow(200)+20)+'.'+str(secrets.randbelow(256))+'.0/24')
        ipaddress.IPv4Network(s['subnet'])
    if p=='amneziawg' and not s.get('awg'):
        headers=secrets.SystemRandom().sample(range(10,2**31),4)
        s['awg']=dict(Jc=4,Jmin=50,Jmax=1000,S1=86,S2=12,S3=50,S4=10,**{'H'+str(i+1):v for i,v in enumerate(headers)})
    if p=='olcrtc':
        s['provider']=s.get('provider') or 'jitsi'
        if s['provider'] not in RTC_TRANSPORTS:raise ValueError('Неизвестный сервис видеозвонков')
        s['rtc_transport']=s.get('rtc_transport') or RTC_TRANSPORTS[s['provider']][0]
        if s['rtc_transport'] not in RTC_TRANSPORTS[s['provider']]:raise ValueError('Этот транспорт olcRTC не поддерживается выбранным сервисом в YPtun')
        s['room']=str(s.get('room','')).strip()
        if not re.fullmatch(r'[A-Za-z0-9._~:/?#\[\]@!&*+,;=%-]{1,300}',s['room']):raise ValueError('Укажите комнату или ссылку на видеозвонок')
        s.setdefault('engine_key',secrets.token_hex(32))
    if p=='masterdns':
        s['dns_domain']=str(s.get('dns_domain') or s['host']).strip().lower()
        if len(s['dns_domain'])>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in s['dns_domain'].split('.')):raise ValueError('Укажите DNS-домен туннеля')
        try:ipaddress.ip_address(s['dns_domain'])
        except ValueError:pass
        else:raise ValueError('Для DNS-туннеля нужен домен, а не IP')
        resolver_ip=str(s.get('resolver_ip') or '').strip()
        if resolver_ip:
            try:
                address=ipaddress.ip_address(resolver_ip)
                if getattr(address,'scope_id',None):raise ValueError('Scoped IPv6 address')
            except ValueError as e:raise ValueError('Укажите IP-адрес прямого резолвера MasterDNS') from e
            resolver_ip=str(address)
        s['resolver_ip']=resolver_ip
        s.setdefault('engine_key',secrets.token_hex(16));s['encryption_method']=5
    if p=='openflux':
        s['room_url']=str(s.get('room_url','')).strip();url=urlsplit(s['room_url'])
        if url.scheme!='https' or not url.hostname or url.username or url.password:raise ValueError('Укажите HTTPS-ссылку комнаты / документа')
        s['flux_transport']=s.get('flux_transport') or 'yandex'
        if s['flux_transport'] not in ('yandex','vyandex','mailru','cupsonline','telemost'):raise ValueError('Этот транспорт OpenFlux не поддерживает автоматическую выдачу в YPtun')
        s.setdefault('engine_key',secrets.token_urlsafe(32))
    if p=='trusttunnel' and ('BEGIN CERTIFICATE' not in s.get('certificate','') or 'PRIVATE KEY' not in s.get('private_key','')):raise ValueError('Нажмите «Выпустить сертификат» для TrustTunnel')
    if p=='warp':
        s.setdefault('short_id',secrets.token_hex(8));s['security']='reality'
    if p=='vkturn':s.setdefault('engine_key',secrets.token_hex(32))
    return s

def user(s,u,others):
    p=s['protocol']
    if p in SINGLE and others:raise ValueError('У этого движка общий ключ комнаты / сервера. Создайте отдельную службу для другого подключения.')
    if p in ('wireguard','amneziawg','vkturn'):
        priv,pub=keypair();u.update(wg_private=base64.b64encode(priv).decode(),wg_public=base64.b64encode(pub).decode(),wg_psk=base64.b64encode(secrets.token_bytes(32)).decode())
        used={x.get('wg_address') for x in others};net=ipaddress.IPv4Network(s['subnet'])
        address=next((str(net[i]) for i in range(2,254) if str(net[i]) not in used),None)
        if not address:raise ValueError('Лимит WireGuard-пиров: 252')
        u['wg_address']=address
    if p=='vkturn':
        import wdtt
        u['vk_hash']=wdtt.hashes(u.get('vk_hash',''))
    return u

def wg_server(s,users,port=None):
    net=ipaddress.IPv4Network(s['subnet'])
    out=f"[Interface]\nPrivateKey = {s['server_private']}\nAddress = {net[1]}/24\nListenPort = {port or s['port']}\nMTU = 1280\n"
    if s['protocol']=='amneziawg':out+=''.join(f'{k} = {v}\n' for k,v in s['awg'].items())
    out+='PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\nPostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n'
    for u in users:
        out+=f"\n[Peer]\nPublicKey = {u['wg_public']}\n"
        # YPtun's FreeTURN parser imports WG keys but does not import PresharedKey.
        if s['protocol']!='vkturn':out+=f"PresharedKey = {u['wg_psk']}\n"
        out+=f"AllowedIPs = {u['wg_address']}/32\n"
    return out

def wg_client(s,u,endpoint=None):
    host='['+s['host']+']' if ':' in s['host'] else s['host']
    text=f"[Interface]\nPrivateKey = {u['wg_private']}\nAddress = {u['wg_address']}/32\nDNS = 1.1.1.1\nMTU = 1280\n"
    if s['protocol']=='amneziawg':text+=''.join(f'{k} = {v}\n' for k,v in s['awg'].items())
    text+=f"\n[Peer]\nPublicKey = {s['server_public']}\n"
    if s['protocol']!='vkturn':text+=f"PresharedKey = {u['wg_psk']}\n"
    return text+f"AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint or host+':'+str(s['port'])}\nPersistentKeepalive = 25\n"

def snolc_files(s):
    # Same limits and builtin module packages as YPtun's SnolcFiles.server.
    text='''wire_version = 1
[paths]
packages = "builtin"
state = "/etc/yptun/state"
[engine]
max_sessions = 4
max_flows = 512
max_pending_sessions = 4
max_pending_opens = 64
max_managed_bytes = 268435456
max_commands = 64
max_events = 256
max_io_chunk = 16384
max_ingress_packets_per_tick = 32
connect_timeout_ms = 15000
handshake_timeout_ms = 15000
shutdown_timeout_ms = 5000
[stack]
ipv4 = true
ipv6 = true
mtu = 1280
tcp_socket_rx_bytes = 65536
tcp_socket_tx_bytes = 65536
udp_socket_rx_bytes = 131072
udp_socket_tx_bytes = 131072
udp_metadata_slots = 8
packet_queue_bytes = 262144
max_udp_payload_bytes = 65507
reassembly_slots = 4
reassembly_timeout_ms = 15000
[yamux]
max_streams_per_session = 129
receive_window_bytes = 33816576
split_send_size = 16384
read_after_close = true
[logging]
mode = "file"
source = "toml"
levels = ["warning", "error"]
file = "/etc/yptun/state/snolc.log"
limit = "8mb"
queue_bytes = 65536
max_record_bytes = 2048
flush_interval_ms = 1000
on_io_error = "event"
[control]
mode = "off"
[[tunnels]]
name = "main"
role = "server"
adapters = ["modules/direct.toml"]
protection = "modules/noise.toml"
carrier = "modules/tcp.toml"
policy = "modules/policy.toml"
'''
    options={'direct':('adapter-direct','dns_mode = "system"\nmax_pending_opens = 64\nmax_resolved_addresses = 16\nresolve_timeout_ms = 15000\nconnect_timeout_ms = 15000\n'),'noise':('protection-noise','mode = "server"\nprivate_key_file = "../priv.hex"\n'),'tcp':('carrier-tcp',f'mode = "listen"\nendpoint_ip = "0.0.0.0:{s["port"]}"\nmax_connections = 4\nnodelay = true\n'),'policy':('policy-dummy','pump_buffer_bytes = 16384\n')}
    files={'runtime/snolc.toml':text,'runtime/priv.hex':base64.b64decode(s['server_private']).hex()}
    for key,(package,body) in options.items():files['runtime/modules/'+key+'.toml']=f'wire_version = 1\ninstance = "{key}-main"\npackage = "owenewans/{package}@0.0.4"\nrole = "server"\n\n[options]\n'+body
    return files

def base_service(image):return dict(image=image,restart='unless-stopped',logging=dict(driver='json-file',options={'max-size':'10m','max-file':'3'}))
def wg_container(s):
    svc=base_service(BY_IMAGE['amneziawg' if s['protocol']=='amneziawg' else 'wireguard']['reference'])
    svc.update(environment=dict(PUID=str(os.getuid()),PGID=str(os.getgid()),AWG_VERSION='2.0'),volumes=['./runtime:/config'],cap_add=['NET_ADMIN'],sysctls={'net.ipv4.ip_forward':'1','net.ipv4.conf.all.src_valid_mark':'1'})
    if s['protocol']=='amneziawg':svc['devices']=['/dev/net/tun:/dev/net/tun']
    return svc

def bundle(s,users):
    p=s['protocol'];active=[u for u in users if u.get('enabled',True)];files={};svc=base_service(s['image']);services={'tunnel':svc}
    svc['ports']=[f'{s["port"]}:{s["port"]}/tcp',f'{s["port"]}:{s["port"]}/udp']
    if p in ('wireguard','amneziawg'):
        files['runtime/wg_confs/wg0.conf']=wg_server(s,active);svc=wg_container(s);svc['ports']=[f'{s["port"]}:{s["port"]}/udp'];services['tunnel']=svc
    elif p=='snolc':
        files=snolc_files(s);svc.update(command=['run','/etc/yptun/snolc.toml'],volumes=['./runtime:/etc/yptun'])
    elif p=='olcrtc':
        files['runtime/config.yaml']='mode: srv\nauth:\n  provider: '+json.dumps(s['provider'])+'\nroom:\n  id: '+json.dumps(s['room'])+'\ncrypto:\n  key_file: /etc/yptun/key\nnet:\n  transport: '+json.dumps(s['rtc_transport'])+'\n  dns: "8.8.8.8:53"\nliveness:\n  interval: 10s\n  timeout: 15s\n  failures: 4\n';files['runtime/key']=s['engine_key']
        svc.update(command=['/etc/yptun/config.yaml'],volumes=['./runtime:/etc/yptun:ro']);svc.pop('ports')
    elif p=='masterdns':
        files['runtime/server_config.toml']=f'PROTOCOL_TYPE = "SOCKS5"\nDOMAIN = [{json.dumps(s["dns_domain"])}]\nUDP_HOST = "0.0.0.0"\nUDP_PORT = {s["port"]}\nDATA_ENCRYPTION_METHOD = 5\nENCRYPTION_KEY_FILE = "/data/encrypt_key.txt"\nSUPPORTED_UPLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]\nSUPPORTED_DOWNLOAD_COMPRESSION_TYPES = [0, 1, 2, 3]\nDNS_UPSTREAM_SERVERS = ["1.1.1.1:53", "8.8.8.8:53"]\nUSE_EXTERNAL_SOCKS5 = false\nLOG_LEVEL = "INFO"\n'
        files['runtime/encrypt_key.txt']=s['engine_key'];svc.update(command=['-nowait'],environment=dict(CONFIG_FILE='server_config.toml'),volumes=['./runtime:/data'])
    elif p=='openflux':
        files['runtime/key']=s['engine_key'];svc.update(command=['--role=exit','--mode=l4','--transport='+s['flux_transport'],'--url='+s['room_url'],'--encryption-key-file=/etc/yptun/key','--session-context='+openflux_context(s)],volumes=['./runtime:/etc/yptun:ro']);svc.pop('ports')
    elif p=='trusttunnel':
        files['runtime/vpn.toml']=f'listen_address = "0.0.0.0:{s["port"]}"\ncredentials_file = "credentials.toml"\nipv6_available = false\nallow_private_network_connections = false\n[forward_protocol.direct]\n[listen_protocols.http1]\n[listen_protocols.http2]\n[listen_protocols.quic]\n'
        files['runtime/hosts.toml']='[[main_hosts]]\nhostname = '+json.dumps(s['sni'])+'\ncert_chain_path = "cert.pem"\nprivate_key_path = "key.pem"\nallowed_sni = []\n'
        files['runtime/credentials.toml']=''.join('[[client]]\nusername = '+json.dumps(u['id'])+'\npassword = '+json.dumps(u['password'])+'\n' for u in active)
        files.update({'runtime/cert.pem':s['certificate'],'runtime/key.pem':s['private_key']});svc.update(volumes=['./runtime:/trusttunnel_endpoint:ro'],working_dir='/trusttunnel_endpoint')
    elif p=='vkturn':
        files['runtime/wg_confs/wg0.conf']=wg_server(s,active,51820);backend=wg_container(s);services['backend']=backend
        svc.update(environment=dict(CONNECT_ADDR='backend:51820',LISTEN_ADDR='0.0.0.0:'+str(s['port']),MODE='udp',OBF_PROFILE='rtpopus',OBF_KEY=s['engine_key']),depends_on=['backend'])
    elif p=='warp':
        # Authenticated VLESS public entry; WARP SOCKS remains private to this compose network.
        # The upstream image runs its wrapper as the warp user. A Docker volume
        # preserves its native directory ownership across daemon restarts.
        warp=svc;warp.pop('ports');warp.update(devices=['/dev/net/tun:/dev/net/tun'],cap_add=['NET_ADMIN','MKNOD','AUDIT_WRITE'],sysctls={'net.ipv6.conf.all.disable_ipv6':'0','net.ipv4.conf.all.src_valid_mark':'1'},volumes=['warp-state:/var/lib/cloudflare-warp'])
        services={'warp':warp,'tunnel':base_service(BY_IMAGE['xray']['reference'])};svc=services['tunnel']
        config=dict(log=dict(loglevel='warning'),inbounds=[dict(listen='0.0.0.0',port=s['port'],protocol='vless',settings=dict(clients=[dict(id=u['uuid'],email=u['id']) for u in active],decryption='none'),streamSettings=dict(network='tcp',security='reality',realitySettings=dict(dest=s['sni']+':443',xver=0,serverNames=[s['sni']],privateKey=base64.urlsafe_b64encode(base64.b64decode(s['server_private'])).decode().rstrip('='),shortIds=[s['short_id']])))],outbounds=[dict(protocol='socks',settings=dict(servers=[dict(address='warp',port=1080)]))])
        files['config.json']=json.dumps(config);svc.update(command=['run','-config','/etc/yptun/config.json'],volumes=['./config.json:/etc/yptun/config.json:ro'],ports=[f'{s["port"]}:{s["port"]}/tcp'],depends_on=['warp'],user=str(os.getuid())+':'+str(os.getgid()),cap_drop=['ALL'],security_opt=['no-new-privileges:true'])
    compose=dict(services=services)
    if p=='warp':compose['volumes']={'warp-state':{}}
    files['compose.json']=json.dumps(compose,indent=2)
    return files

def b64(text):return base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')
def varint(value):
    if value<64:return bytes([value])
    if value<16384:return (value|0x4000).to_bytes(2,'big')
    return (value|0x80000000).to_bytes(4,'big')
def tt_link(s,u):
    def tlv(tag,value):
        v=value.encode() if isinstance(value,str) else value
        return varint(tag)+varint(len(v))+v
    host='['+s['host']+']' if ':' in s['host'] else s['host']
    cert=b''.join(base64.b64decode(block) for block in re.findall(r'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----',s['certificate'],re.S))
    payload=b''.join(tlv(t,v) for t,v in [(0,b'\x01'),(1,s['sni']),(2,host+':'+str(s['port'])),(5,u['id']),(6,u['password']),(8,cert),(12,u['name'] if u.get('auto_name') else s['name']+' · '+u['name'])])
    return 'tt://?'+base64.urlsafe_b64encode(payload).decode().rstrip('=')

def openflux_context(s):
    # OpenFlux defaults to this context when the Cups carrier supplies no explicit context.
    return 'http://#' if s['flux_transport']=='cupsonline' else s['room_url']

def profile(s,u):
    p=s['protocol']
    host=(s.get('resolver_ip') or s['host']) if p=='masterdns' else s['host']
    if ':' in host:host='['+host+']'
    addr=host+':'+str(s['port'])
    if p in ('wireguard','amneziawg'):return wg_client(s,u)
    if p=='snolc':return 'snolc://'+addr+'?key='+base64.b64decode(s['server_public']).hex()+'#'+quote(u['name'] if u.get('auto_name') else s['name']+' · '+u['name'])
    if p=='masterdns':return 'masterdns://v1?'+urlencode(dict(domains=s['dns_domain'],key=s['engine_key'],enc=5,resolvers=addr))+'#'+quote(u['name'])
    if p=='trusttunnel':return tt_link(s,u)
    if p=='openflux':
        cfg=dict(name=u['name'],secret=s['engine_key'],context=openflux_context(s),transports=[dict(type=s['flux_transport'],url=s['room_url'])]);compress=zlib.compressobj(wbits=-15);data=compress.compress(json.dumps(cfg).encode())+compress.flush()
        return 'openflux://v1/'+base64.urlsafe_b64encode(data).decode().rstrip('=')
    if p=='olcrtc':return json.dumps(dict(engine='stealth',name=u['name'],id=s['room'],key=s['engine_key'],bypass_provider=s['provider'],transport=s['rtc_transport']))
    if p=='vkturn':
        # Both current FreeTURN and YPtun accept this versioned wire format.
        # TURN transport is tcp/udp; DTLS runs inside it and is not a valid value.
        config=dict(v=1,provider='vk',peer=addr,transport='tcp',mode='udp',obf='rtpopus',key=s['engine_key'],listen='127.0.0.1:9000',wg=wg_client(s,u,'127.0.0.1:9000'),vk=u['vk_hash'],name=u['name'])
        return 'freeturn://'+b64(json.dumps(config,separators=(',',':')))
    if p=='warp':return f'vless://{u["uuid"]}@{addr}?type=tcp&security=reality&encryption=none&sni={s["sni"]}&fp=chrome&pbk={base64.urlsafe_b64encode(base64.b64decode(s["server_public"])).decode().rstrip("=")}&sid={s["short_id"]}#'+quote(u['name'] if u.get('auto_name') else s['name']+' · '+u['name'])
    raise ValueError('Нет генератора профиля')
