"""Telegram WEB transport, served behind the panel's HTTPS nginx."""
import json
import os
import re
import secrets
from urllib.parse import urlencode
from images import BY_IMAGE


def secret(value=None):
    value=secrets.token_hex(16) if value in (None,'') else str(value).strip().lower()
    if not re.fullmatch(r'[a-f0-9]{32}',value):
        raise ValueError('WebProxy secret: нужны 32 шестнадцатеричных символа')
    return value


def validate(s):
    host=s['host'].lower()
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',host):
        raise ValueError('WebProxy: укажите отдельный публичный домен без схемы и порта')
    if s.get('self_sni') or s.get('provisioned') or s['transport']!='tcp' or s['security']!='none':
        raise ValueError('WebProxy: HTTPS завершает nginx, внутренний транспорт — TCP без TLS')
    if not 1024<=s['port']<=65535 or s['port'] in (8080,9443):
        raise ValueError('WebProxy: укажите свободный внутренний порт от 1024, кроме 8080 и 9443')
    s.update(host=host,listen='127.0.0.1')
    return s


def link(s,u):
    return 'tg://webproxy?'+urlencode(dict(server=s['host'],secret=secret(u['webproxy_secret'])))


def bundle(s,users):
    config='domain = '+json.dumps(s['host'])+'\nlisten = ":4600"\nbehind_proxy = true\n'
    active=[u for u in users if u.get('enabled',True)]
    # Upstream requires at least one secret even for a stopped, empty service.
    entries=active or [dict(id='unused',webproxy_secret=secrets.token_hex(16))]
    for u in entries:
        config+='\n[[secret]]\nvalue = '+json.dumps(secret(u['webproxy_secret']))+'\nlabel = '+json.dumps(u['id'])+'\n'
    service=dict(image=BY_IMAGE['webproxy']['reference'],command=['-config','/etc/yptun/relay.toml'],volumes=['./relay.toml:/etc/yptun/relay.toml:ro'],ports=[f"127.0.0.1:{s['port']}:4600/tcp"],restart='unless-stopped',user=str(os.getuid())+':'+str(os.getgid()),read_only=True,cap_drop=['ALL'],security_opt=['no-new-privileges:true'],logging=dict(driver='json-file',options={'max-size':'10m','max-file':'3'}))
    return {'relay.toml':config,'compose.json':json.dumps(dict(services=dict(tunnel=service)),indent=2)}
