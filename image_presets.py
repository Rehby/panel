"""Explicit per-image adapters; own-config mode remains available."""
import ipaddress
import os
import socket
import base64
import json
from pathlib import PurePosixPath
import re
from images import BY_IMAGE
from transports import object_value


def validate_custom(s):
    id=s.get('image_id')
    if id:
        preset=BY_IMAGE.get(id)
        if not preset or s['protocol'] not in preset['protocols']:raise ValueError('Образ не соответствует протоколу')
        if s.get('image') and s['image']!=preset['reference']:raise ValueError('Для своего образа выберите режим без пресета')
        s['image']=preset['reference']
        if not s.get('command'):s['command']=preset.get('command',[])
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/:@-]*',s.get('image','')):raise ValueError('Выберите Docker-образ')
    if not isinstance(s.get('command',[]),list) or not all(isinstance(x,str) for x in s.get('command',[])):raise ValueError('Команда: нужен JSON-массив строк')
    if s.get('container_port'):
        s['container_port']=int(s['container_port'])
        if not 1<=s['container_port']<=65535:raise ValueError('Некорректный внутренний порт')
    if not s.get('raw_config','').strip():raise ValueError('Вставьте конфигурацию движка')
    if id in ('trusttunnel','snolc'):
        package=object_value(s['raw_config'],'Пакет файлов')
        for name,value in package.items():
            path=PurePosixPath(name)
            if not (isinstance(value,str) or isinstance(value,dict) and set(value)=={'base64'}) or not re.fullmatch(r'[a-zA-Z0-9_./-]{1,180}',name) or path.is_absolute() or any(p in ('','.','..') for p in name.split('/')):raise ValueError('Недопустимое имя файла в пакете')
        for value in package.values():
            if isinstance(value,dict):
                try:base64.b64decode(value['base64'],validate=True)
                except Exception:raise ValueError('Некорректный файл base64')
        if id=='snolc' and 'config.conf' not in package:
            configs=[n for n,v in package.items() if n.endswith('.toml') and isinstance(v,str)]
            if len(configs)!=1:raise ValueError('snolc: загрузите один основной TOML-конфиг и необходимые модули')
            package['config.conf']=package[configs[0]]
            s['raw_config']=json.dumps(package)
        if id=='trusttunnel' and not all(n in package for n in ('vpn.toml','hosts.toml','credentials.toml')):raise ValueError('TrustTunnel: нужны vpn.toml, hosts.toml и credentials.toml')
    if id=='freeturn':
        env=object_value(s['raw_config'],'Переменные Free TURN')
        if not env.get('CONNECT_ADDR') or not env.get('OBF_KEY'):raise ValueError('Free TURN: укажите CONNECT_ADDR и OBF_KEY')
        if not all(re.fullmatch('[A-Z0-9_]+',k) and isinstance(v,(str,int,float,bool)) for k,v in env.items()):raise ValueError('Некорректные переменные Free TURN')
    return s


def custom_bundle(s):
    id=s.get('image_id');preset=BY_IMAGE.get(id,{})
    service=dict(image=s['image'],command=s.get('command',[]))
    path=preset.get('config_path','/etc/yptun/config.conf')
    if id in ('wireguard','amneziawg'):
        files={'runtime/wg_confs/wg0.conf':s['raw_config']}
        service.update(environment={'PUID':str(os.getuid()),'PGID':str(os.getgid())},volumes=['./runtime:/config'],cap_add=['NET_ADMIN'],sysctls={'net.ipv4.ip_forward':'1','net.ipv4.conf.all.src_valid_mark':'1'})
        if id=='amneziawg':service['devices']=['/dev/net/tun:/dev/net/tun']
    elif id=='masterdns':
        files={'runtime/server_config.toml':s['raw_config']};service.update(volumes=['./runtime:/data'],environment={'CONFIG_FILE':'server_config.toml'},ports=[f"{socket.gethostbyname(s['host'])}:{s['port']}:{s.get('container_port',53)}/{kind}" for kind in ('tcp','udp')])
    elif id=='trusttunnel':
        files={'runtime/'+n:(base64.b64decode(v['base64'],validate=True) if isinstance(v,dict) else v) for n,v in json.loads(s['raw_config']).items()};service.update(volumes=['./runtime:/trusttunnel_endpoint'],working_dir='/trusttunnel_endpoint')
    elif id=='snolc':
        files={'runtime/'+n:(base64.b64decode(v['base64'],validate=True) if isinstance(v,dict) else v) for n,v in json.loads(s['raw_config']).items()};service['volumes']=['./runtime:/etc/yptun:ro']
    elif id=='freeturn':
        files={'config.conf':s['raw_config']};env=json.loads(s['raw_config']);env.setdefault('LISTEN_ADDR','0.0.0.0:'+str(s['port']));service.update(environment={k:str(v) for k,v in env.items()},network_mode='host')
    elif id=='warp':
        env=object_value(s['raw_config'],'Переменные WARP')
        if any(k not in ('WARP_SLEEP','WARP_LICENSE_KEY') for k in env):raise ValueError('Для WARP доступны WARP_SLEEP и WARP_LICENSE_KEY; SOCKS5 доступен только локально')
        files={'config.conf':s['raw_config']};service.update(environment={k:str(v) for k,v in env.items()},volumes=['./runtime:/var/lib/cloudflare-warp'],devices=['/dev/net/tun:/dev/net/tun'],cap_add=['NET_ADMIN','MKNOD','AUDIT_WRITE'],sysctls={'net.ipv6.conf.all.disable_ipv6':'0','net.ipv4.conf.all.src_valid_mark':'1'},ports=[f"127.0.0.1:{s['port']}:1080/tcp"])
    else:
        files={'config.conf':s['raw_config']};service['volumes']=['./config.conf:'+path+':ro']
    if s.get('container_port') and 'ports' not in service and service.get('network_mode')!='host':
        service['ports']=[f"{s['port']}:{s['container_port']}/tcp",f"{s['port']}:{s['container_port']}/udp"]
    return files,service
