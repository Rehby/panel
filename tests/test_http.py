import base64
import http.client
import json
import sys
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server

class HTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.old=server.DATA;server.DATA=Path(cls.tmp.name);cls.credentials=server.init()
        cls.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.http.shutdown();cls.http.server_close();server.DATA=cls.old;cls.tmp.cleanup()
    def request(self,path,data=None,cookie=None,origin=None,raw=False):
        if not raw:path=server.auth.CONFIG['base_path']+path
        c=http.client.HTTPConnection('127.0.0.1',self.http.server_port)
        headers={'Content-Type':'application/json'}
        if cookie:headers['Cookie']=cookie
        if origin:headers['Origin']=origin
        c.request('GET' if data is None else 'POST',path,None if data is None else json.dumps(data),headers)
        r=c.getresponse();body=r.read();status=r.status;headers=dict(r.getheaders());c.close();return status,body,headers
    def test_end_to_end(self):
        self.assertEqual(self.request('/')[0],200)
        status,body,headers=self.request('/qrcode.js')
        self.assertEqual(status,200)
        self.assertIn('text/javascript',headers['Content-Type'])
        self.assertIn(b'qrcode',body)
        self.assertEqual(self.request('/',raw=True)[0],404)
        self.assertEqual(self.request('/api/state',raw=True)[0],404)
        self.assertEqual(self.request('/api/state')[0],401)
        self.assertEqual(self.request('/api/system')[0],401)
        self.assertEqual(self.request('/api/certificates',dict(mode='ip',host='127.0.0.1'))[0],401)
        self.assertEqual(self.request('/api/login',dict(username='admin',password='wrong'))[0],401)
        status,_,headers=self.request('/api/login',dict(username=self.credentials['username'],password=self.credentials['password']));self.assertEqual(status,200)
        cookie=headers['Set-Cookie'].split(';')[0];self.assertIn('HttpOnly',headers['Set-Cookie'])
        status,body,_=self.request('/api/system',cookie=cookie)
        self.assertEqual(status,200)
        system=json.loads(body)
        self.assertTrue(system['version'])
        self.assertIn('memory',system)
        self.assertIn('errors',system)
        self.assertEqual(self.request('/api/services',{},cookie,'https://attacker.invalid')[0],403)
        with patch.object(server,'certificate_helper',return_value=dict(host='127.0.0.1',certificate_id='a'*24,certificate='test cert',private_key='test key')) as helper:
            status,body,_=self.request('/api/certificates',dict(mode='ip',host='127.0.0.1'),cookie)
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body)['certificate'],'test cert')
            self.assertEqual(helper.call_args.args[0]['action'],'service-certificate')
        status,body,_=self.request('/api/services',dict(name='HTTP test',host='vpn.example.com',port=18443,protocol='vless',security='none'),cookie);self.assertEqual(status,200,body);s=json.loads(body)
        status,body,_=self.request('/api/users',dict(name='Tester',service_id=s['id']),cookie);self.assertEqual(status,200,body);u=json.loads(body)
        status,body,_=self.request('/sub/'+u['token']);self.assertEqual(status,200);self.assertIn(b'vless://',base64.b64decode(body))
        status,body,_=self.request('/api/state',cookie=cookie);self.assertEqual(status,200);self.assertNotIn('password',json.loads(body)['users'][0])
        self.assertTrue(self.request('/api/services/'+s['id']+'/export',cookie=cookie)[1].startswith(b'PK'))
        self.assertEqual(self.request('/api/users/'+u['id']+'/toggle',{},cookie)[0],200)
        self.assertEqual(self.request('/sub/'+u['token'])[0],404)
        self.assertEqual(self.request('/api/users/'+u['id']+'/delete',{},cookie)[0],200)
        self.assertEqual(self.request('/api/services/'+s['id']+'/delete',{},cookie)[0],200)
        self.assertEqual(self.request('/static/../server.py')[0],404)
        self.assertEqual(self.request('/api/logout',{},cookie)[0],200)
        self.assertEqual(self.request('/api/state',cookie=cookie)[0],401)

if __name__=='__main__':unittest.main()
