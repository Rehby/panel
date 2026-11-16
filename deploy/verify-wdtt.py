import getpass,http.cookiejar,json,sys,time,urllib.request,urllib.error
from urllib.parse import urlsplit
base=sys.argv[1].rstrip('/')+'/'
op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,data=None):
 req=urllib.request.Request(base+'api/'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json'})
 try:return json.load(op.open(req,timeout=120))
 except urllib.error.HTTPError as e:raise RuntimeError(e.read().decode()) from e
def sub(token):
 try:
  r=urllib.request.urlopen('https://'+urlsplit(base).netloc+'/turn-sub/'+token,timeout=15);return r.status,json.load(r)
 except urllib.error.HTTPError as e:return e.code,None
s=None
try:
 api('login',dict(username='admin',password=getpass.getpass('Panel password: ')))
 s=api('services',dict(protocol='wdtt',host=urlsplit(base).hostname,port=56120,wg_port=56121,local_port=9000,name='Temporary qWDTT verification',vk_hash='verify_hash'))
 api('services/'+s['id']+'/start',{})
 for attempt in range(12):
  try:u=api('users',dict(service_id=s['id'],name='Temporary TURN user',vk_hash='configuration_test_only',days=1,max_devices=1));break
  except RuntimeError:
   if attempt==11:print(api('services/'+s['id']+'/logs')['content']);raise
   time.sleep(1)
 print('qWDTT start and native Admin API create: OK',flush=True)
 code,body=sub(u['token']);assert code==200 and body['profiles'][0]['password']==u['password'];assert body['profiles'][0]['peer'].endswith(':56120')
 assert api('users/'+u['id']+'/profile')['content'].startswith('qwdtt://')
 api('users/'+u['id']+'/toggle',{});assert sub(u['token'])[0]==404
 api('users/'+u['id']+'/toggle',{});assert sub(u['token'])[0]==200
 api('services/'+s['id']+'/edit',dict(vk_hash='configuration_test_two'))
 api('users/'+u['id']+'/edit',dict(name='Updated TURN',days=2,max_devices=2));assert sub(u['token'])[1]['profiles'][0]['hashes']=='configuration_test_two'
 api('users/'+u['id']+'/rotate',{});assert sub(u['token'])[0]==404
 api('users/'+u['id']+'/delete',{})
 print('Personal JSON, URI, update, deactivate/activate, rotate and delete: OK',flush=True)
 api('services/'+s['id']+'/stop',{});api('services/'+s['id']+'/delete',{});print('Test service removed:',s['id'],flush=True);s=None
 api('logout',{})
finally:
 if s:
  try:api('services/'+s['id']+'/stop',{});api('services/'+s['id']+'/delete',{})
  except Exception as e:print('Cleanup needs attention:',e)
