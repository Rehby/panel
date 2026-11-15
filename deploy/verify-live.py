#!/usr/bin/env python3
"""External deployment smoke test. Password is read from TTY, never argv or a file."""
import getpass
import http.cookiejar
import json
import ssl
import sys
import urllib.request
import urllib.error
from urllib.parse import urlsplit

base=sys.argv[1].rstrip('/')+'/'
password=getpass.getpass('Panel password: ')
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def request(path,data=None):
    req=urllib.request.Request(base+'api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json'})
    return json.load(opener.open(req,timeout=200))

s=None
try:
    request('login',dict(username='admin',password=password));print('HTTPS login: OK',flush=True)
    state=request('state');assert state['https']['trusted'] and state['https']['self_sni_ready'];print('HTTPS / self-SNI availability: OK',flush=True)
    s=request('services',dict(name='Temporary deployment verification',protocol='vless',host=urlsplit(base).hostname,port=18443,security='reality',transport='tcp',self_sni=True))
    u=request('users',dict(name='Temporary verification user',service_id=s['id']))
    result=request('services/'+s['id']+'/start',{});
    if not result['running']:print(request('services/'+s['id']+'/logs')['content'],flush=True)
    assert result['running'];print('VLESS self-SNI container: RUNNING',flush=True)
    profile=request('users/'+u['id']+'/profile')['content'];assert 'sni='+urlsplit(base).hostname in profile
    # An ordinary TLS probe must receive the server's own trusted domain certificate.
    import socket
    with socket.create_connection((urlsplit(base).hostname,18443),timeout=20) as sock:
        with ssl.create_default_context().wrap_socket(sock,server_hostname=urlsplit(base).hostname) as tls:
            print('Reality fallback TLS:',tls.version(),tls.getpeercert()['subject'],flush=True)
    request('users/'+u['id']+'/toggle',{});state=request('state');assert not next(x for x in state['services'] if x['id']==s['id'])['running'];print('Last-user revocation stops container: OK',flush=True)
    request('services/'+s['id']+'/delete',{});s=None
    request('logout',{})
    try:request('state');raise AssertionError('Session was not revoked')
    except urllib.error.HTTPError as e:assert e.code==401
    print('Logout and cleanup: OK',flush=True)
finally:
    if s:
        try:request('services/'+s['id']+'/stop',{});request('services/'+s['id']+'/delete',{})
        except Exception as e:print('Cleanup needs attention:',str(e),file=sys.stderr)
