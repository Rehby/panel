"""Shared minimal setup defaults; explicit advanced inputs always win."""
import socket
import secrets
from catalog import BY_ID
from images import CATALOG


def free_port(protocol,reserved):
    candidates=[p for p in range(10000,65536) if p not in reserved]
    secrets.SystemRandom().shuffle(candidates)
    for port in candidates:
        sockets=[]
        try:
            for typ in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                s=socket.socket(socket.AF_INET,typ);sockets.append(s);s.bind(('0.0.0.0',port))
            return port
        except OSError:pass
        finally:
            for s in sockets:s.close()
    raise ValueError('Не найден свободный порт; укажите порт вручную')

def setup(protocol,host,reserved):
    if protocol not in BY_ID:raise ValueError('Неизвестный движок')
    port=free_port(protocol,reserved)
    s=dict(protocol=protocol,name=BY_ID[protocol]['name']+' · '+str(port),host=host or '127.0.0.1',port=port,transport='tcp',security='reality' if protocol=='vless' else 'none' if protocol=='shadowsocks' else 'tls',sni=host or 'www.microsoft.com',path='/tunnel')
    image=next((i for i in CATALOG if protocol in i['protocols']),None)
    if image and BY_ID[protocol]['mode']=='custom':s.update(image_id=image['id'],image=image['reference'],command=image.get('command',[]))
    return s
