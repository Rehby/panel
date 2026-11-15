#!/usr/bin/env python3
"""External update QA; only temporary test objects are changed."""
import getpass
import http.cookiejar
import json
import socket
import ssl
import sys
import time
import urllib.request
import uuid
from urllib.parse import urlsplit

base=sys.argv[1].rstrip('/')+'/'
password=getpass.getpass('Panel password: ')
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,data=None):
 request=urllib.request.Request(base+'api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json'})
 try:return json.load(opener.open(request,timeout=180))
 except urllib.error.HTTPError as e:raise RuntimeError(e.read().decode()) from e

service=None
try:
 api('login',dict(username='admin',password=password))
 before=api('state');original={s['id']:s['running'] for s in before['services']}
 transports=[t for t in before['transports'] if 'vless' in t.get('protocols',['vless'])]
 assert len(transports)==8;print('VLESS transport choices: 8',flush=True)
 images=api('images');assert len(images)==11;print('Image catalog:',len(images),'entries;',sum(i['kind']=='registry' for i in images),'registry references',flush=True)
 # Dedicated ephemeral-test IP certificate; do not print key material.
 host=socket.gethostbyname(urlsplit(base).hostname)
 cert=api('certificates',dict(mode='ip',host=host));assert cert['certificate_id'] and 'BEGIN CERTIFICATE' in cert['certificate']
 print('Certificate button API: dedicated SAN IP certificate issued',flush=True)
 service=api('services',dict(name='Temporary HTTPS transport QA',host=host,port=19443,protocol='vless',security='tls',transport='httpupgrade',sni=host,certificate_id=cert['certificate_id'],allow_insecure=True,path='/test-upgrade'))
 user=api('users',dict(service_id=service['id'],name='Temporary verification',uuid=str(uuid.uuid4())))
 result=api('services/'+service['id']+'/start',{})
 if not result['running']:raise RuntimeError(api('services/'+service['id']+'/logs')['content'])
 context=ssl.create_default_context(cadata=cert['certificate'])
 with socket.create_connection((host,19443),timeout=20) as raw:
  with context.wrap_socket(raw,server_hostname=host) as tls:assert tls.getpeercert()
 config=json.loads(api('users/'+user['id']+'/config')['content']);assert config['outbounds'][0]['streamSettings']['network']=='httpupgrade'
 subscription=opener.open(base+'sub/'+user['token'],timeout=10).read();assert json.loads(subscription)['outbounds'][0]['protocol']=='vless'
 print('HTTPUpgrade + issued certificate + full JSON subscription: OK',flush=True)
 api('services/'+service['id']+'/stop',{});api('services/'+service['id']+'/delete',{});service=None
 after=api('state');assert original=={s['id']:s['running'] for s in after['services']};print('Existing services unchanged:',len(original),flush=True)
 api('images/freeturn/check',{})
 for _ in range(50):
  item=next(i for i in api('images') if i['id']=='freeturn')
  if item['job']['status']!='running':
   assert item['job']['status']=='succeeded',item['job'];print('Free TURN registry check from panel API: OK',flush=True);break
  time.sleep(1)
 else:raise RuntimeError('Registry job did not finish in time')
 api('logout',{});print('Cleanup and logout: OK',flush=True)
finally:
 if service:
  try:api('services/'+service['id']+'/stop',{});api('services/'+service['id']+'/delete',{})
  except Exception as e:print('Cleanup issue:',e,file=sys.stderr)
