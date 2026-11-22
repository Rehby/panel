"""Mieru (mita) adapter: obfuscated TCP/UDP proxy, built from pinned mita source."""
import json
import secrets
from urllib.parse import quote
from images import BY_IMAGE

MAX_PORTS = 32


def validate(s):
    if s.get('self_sni') or s['transport'] != 'tcp' or s['security'] != 'none':
        raise ValueError('Mieru: без TLS и self-SNI, внутренний транспорт — TCP')
    s['port_end'] = int(s.get('port_end') or s['port']+9)
    if not s['port'] <= s['port_end'] <= 65535:
        raise ValueError('Mieru: конечный порт должен быть не меньше начального и не больше 65535')
    if s['port_end']-s['port']+1 > MAX_PORTS:
        raise ValueError(f'Mieru: диапазон портов не более {MAX_PORTS}')
    s['udp'] = bool(s.get('udp'))
    s['mtu'] = int(s.get('mtu') or 1400)
    if not 576 <= s['mtu'] <= 9000:
        raise ValueError('Mieru: MTU от 576 до 9000')
    s['listen'] = '0.0.0.0'
    return s


def link(s, u):
    name = u['name'] if u.get('auto_name') else s['name']+' · '+u['name']
    userinfo = quote(u['id'], safe='')+':'+quote(u['password'], safe='')
    parts = ['profile=default', 'port='+str(s['port']), 'protocol=TCP']
    if s.get('udp'):
        parts += ['port='+str(s['port']), 'protocol=UDP']
    parts.append('multiplexing=MULTIPLEXING_HIGH')
    return f"mierus://{userinfo}@{s['host']}?{'&'.join(parts)}#{quote(name)}"


def bundle(s, users):
    active = [u for u in users if u.get('enabled', True)]
    bindings = []
    for port in range(s['port'], s['port_end']+1):
        bindings.append(dict(port=port, protocol='TCP'))
        if s.get('udp'):
            bindings.append(dict(port=port, protocol='UDP'))
    # mita refuses to start with an empty users list; keep a disabled placeholder so
    # a stopped/empty service still produces a valid config file.
    state_users = [dict(name=u['id'], password=u['password']) for u in active] or [dict(name='unused', password=secrets.token_urlsafe(24))]
    state = dict(portBindings=bindings, users=state_users, loggingLevel='INFO', mtu=s.get('mtu', 1400))
    ports = []
    for port in range(s['port'], s['port_end']+1):
        ports.append(f"{port}:{port}/tcp")
        if s.get('udp'):
            ports.append(f"{port}:{port}/udp")
    service = dict(image=BY_IMAGE['mieru']['reference'], command=[],
                   volumes=['./mita-state.json:/etc/yptun/mita-state.json:ro', './runtime:/root/.config/mita'],
                   ports=ports, restart='unless-stopped', cap_drop=['ALL'], cap_add=['NET_BIND_SERVICE'],
                   security_opt=['no-new-privileges:true'],
                   logging=dict(driver='json-file', options={'max-size': '10m', 'max-file': '3'}))
    return {'mita-state.json': json.dumps(state, indent=2), 'compose.json': json.dumps(dict(services=dict(tunnel=service)), indent=2)}
