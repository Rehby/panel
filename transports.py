"""Transport capabilities of Xray v26.9.30; aliases normalized before persistence."""
import copy
import json

TRANSPORTS = [
 dict(id='tcp',name='RAW / TCP',key='tcpSettings',security=['reality','tls','none'],defaults={}),
 dict(id='xhttp',name='XHTTP (HTTP/2 / HTTP/3)',key='xhttpSettings',security=['reality','tls','none'],defaults={'mode':'auto'}),
 dict(id='kcp',name='mKCP (UDP)',key='kcpSettings',security=['tls','none'],defaults={'mtu':1350,'tti':20,'header':{'type':'none'}}),
 dict(id='grpc',name='gRPC',key='grpcSettings',security=['reality','tls','none'],defaults={}),
 dict(id='ws',name='WebSocket',key='wsSettings',security=['tls','none'],defaults={}),
 dict(id='httpupgrade',name='HTTPUpgrade',key='httpupgradeSettings',security=['tls','none'],defaults={}),
 dict(id='hysteria',name='Hysteria 2 transport (UDP)',key='hysteriaSettings',security=['tls'],defaults={'version':2},json_only=True),
 dict(id='masque',protocols=['masque'],name='MASQUE (только протокол MASQUE)',key='masqueSettings',security=['tls'],defaults={},json_only=True),
 dict(id='xdrive',name='XDrive (экспериментальный)',key='xdriveSettings',security=['none'],defaults={},json_only=True),
]
BY_TRANSPORT={t['id']:t for t in TRANSPORTS}
ALIASES={'raw':'tcp','mkcp':'kcp','websocket':'ws','splithttp':'xhttp'}


def object_value(value,label):
    if isinstance(value,str):
        try:value=json.loads(value or '{}')
        except json.JSONDecodeError:raise ValueError(label+': нужен корректный JSON-объект')
    if value is None:value={}
    if not isinstance(value,dict):raise ValueError(label+': нужен JSON-объект')
    if len(json.dumps(value))>100_000:raise ValueError(label+': слишком большой JSON')
    return value


def validate_transport(s):
    s['transport']=ALIASES.get(s['transport'],s['transport'])
    t=BY_TRANSPORT.get(s['transport'])
    if t and s['protocol'] not in t.get('protocols',['vless','vmess','trojan']):raise ValueError('MASQUE transport доступен только протоколу MASQUE, не VLESS/VMess/Trojan')
    if not t:raise ValueError('Транспорт отсутствует в Xray 26.9.30; старые HTTP/H2 и QUIC удалены, используйте XHTTP')
    if s['security'] not in t['security']:raise ValueError(t['name']+': доступна защита '+', '.join(t['security']))
    s['transport_settings']=object_value(s.get('transport_settings'),'Серверные настройки транспорта')
    s['client_transport_settings']=object_value(s.get('client_transport_settings'),'Клиентские настройки транспорта')
    if s['transport']=='xhttp':
        mode=s.get('xhttp_mode','auto')
        if mode not in ('auto','packet-up','stream-up','stream-one'):raise ValueError('Неверный режим XHTTP')
        s['xhttp_mode']=mode
    if s['transport']=='xdrive':
        opts=s['transport_settings']
        if opts.get('service') not in ('local','Google Drive','template') or not opts.get('remoteFolder'):raise ValueError('XDrive: укажите service и remoteFolder в JSON транспорта')
        if opts['service']=='Google Drive' and len(opts.get('secrets',[]))!=3:raise ValueError('XDrive Google Drive: нужны ClientID, ClientSecret и RefreshToken')
        if opts['service']=='template' and not isinstance(opts.get('template'),dict):raise ValueError('XDrive template: нужен объект template')
    return s


def transport_settings(s,client=False):
    t=BY_TRANSPORT[s['transport']];out=copy.deepcopy(t['defaults']);typ=s['transport']
    if typ in ('ws','httpupgrade','xhttp'):out['path']=s['path']
    if typ=='xhttp':out['mode']=s.get('xhttp_mode','auto')
    if typ=='grpc':
        out['serviceName']=s['path'].strip('/')
        if s.get('transport_host'):out['authority']=s['transport_host']
    if s.get('transport_host') and typ in ('ws','httpupgrade','xhttp','masque'):out['host']=s['transport_host']
    if typ=='kcp' and s.get('kcp_seed'):out['seed']=s['kcp_seed']
    out.update(copy.deepcopy(s.get('transport_settings',{})))
    if client:out.update(copy.deepcopy(s.get('client_transport_settings',{})))
    return out


def vision(s):return s['protocol']=='vless' and s['transport']=='tcp' and s['security'] in ('tls','reality') and s.get('flow','xtls-rprx-vision' if s['security']=='reality' else '')=='xtls-rprx-vision'


def client_config(s,u):
    t=BY_TRANSPORT[s['transport']]
    stream=dict(network=s['transport'],security=s['security'],**{t['key']:transport_settings(s,True)})
    if s['security']=='tls':
        tls=dict(serverName=s['sni'],fingerprint=s.get('fingerprint','chrome'),allowInsecure=bool(s.get('allow_insecure')),minVersion=s.get('tls_min','1.2'))
        if s.get('alpn'):tls['alpn']=s['alpn']
        if s['transport'] in ('ws','httpupgrade'):tls['alpn']=['http/1.1']
        if s['transport'] in ('hysteria','masque'):tls['alpn']=['h3']
        stream['tlsSettings']=tls
    if s['security']=='reality':stream['realitySettings']=dict(serverName=s['sni'],publicKey=s['reality_public'],shortId=s['short_id'],fingerprint=s.get('fingerprint','chrome'))
    user=dict(id=u['uuid'],encryption='none') if s['protocol']=='vless' else dict(id=u['uuid'],alterId=0,security='auto') if s['protocol']=='vmess' else dict(password=u['password'])
    if vision(s):user['flow']='xtls-rprx-vision'
    return dict(log=dict(loglevel='warning'),inbounds=[dict(tag='socks',listen='127.0.0.1',port=10808,protocol='socks',settings=dict(auth='noauth',udp=True))],outbounds=[dict(tag='proxy',protocol=s['protocol'],settings=dict(servers=[dict(address=s['host'],port=s['port'],password=u['password'])]) if s['protocol']=='trojan' else dict(vnext=[dict(address=s['host'],port=s['port'],users=[user])]),streamSettings=stream)])
