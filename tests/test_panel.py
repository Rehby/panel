import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
import server

class PanelTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=server.DATA;server.DATA=Path(self.tmp.name);server.init()
    def tearDown(self):server.DATA=self.old;self.tmp.cleanup()
    def service(self,protocol='vless',**kwargs):
        return server.mutate('/api/services',dict(name='Test',host='vpn.example.com',port=443,protocol=protocol,security='none',transport='tcp',**kwargs))
    def user(self,s):return server.mutate('/api/users',dict(name='User',service_id=s['id']))
    def test_vless_profile_and_revocation(self):
        s=self.service();u=self.user(s)
        self.assertIn(u['uuid'],engine.profile(s,u));self.assertIn(u['uuid'],engine.bundle(s,[u])['config.json'])
        server.mutate('/api/users/'+u['id']+'/toggle',{})
        self.assertNotIn(u['uuid'],engine.bundle(s,server.members(s['id']))['config.json'])
    def test_reality_key_pair(self):
        s=engine.validate(dict(protocol='vless',name='Reality',host='vpn.example.com',port=443,security='reality',transport='tcp',sni='www.microsoft.com'))
        self.assertEqual(len(base64.urlsafe_b64decode(s['reality_public']+'=')),32)
        u=dict(name='A',id='a',**engine.credential());q=parse_qs(urlsplit(engine.profile(s,u)).query)
        self.assertEqual(q['pbk'],[s['reality_public']]);self.assertEqual(q['flow'],['xtls-rprx-vision'])
    def test_all_native_configs(self):
        for protocol in ['vless','vmess','trojan','shadowsocks','hysteria2']:
            s=engine.validate(dict(protocol=protocol,name='N',host='2001:db8::1',port=443,transport='tcp',security='tls',certificate='-----BEGIN CERTIFICATE-----',private_key='-----BEGIN PRIVATE KEY-----'))
            u=dict(name='A',id='a',**engine.credential());files=engine.bundle(s,[u]);json.loads(files['config.json']);json.loads(files['compose.json'])
            uri=engine.profile(s,u)
            if protocol!='vmess':self.assertIn('[2001:db8::1]:443',uri)
    def test_port_collision(self):
        self.service()
        with self.assertRaisesRegex(ValueError,'порт'):self.service('vmess')
    def test_docker_disabled(self):
        s=self.service();self.user(s)
        with patch.dict(os.environ,{'YPTUN_ALLOW_DOCKER':'0'}):
            with self.assertRaisesRegex(ValueError,'отключён'):server.mutate('/api/services/'+s['id']+'/start',{})
    def test_rollback_user_on_runtime_failure(self):
        s=self.service();u=self.user(s);s['desired']='running';server.put('service',s)
        with patch.object(server,'compose',side_effect=ValueError('fail')):
            with self.assertRaises(ValueError):server.mutate('/api/users/'+u['id']+'/toggle',{})
        self.assertTrue(server.get(u['id'],'user')['enabled'])
        self.assertIn(u['uuid'],(server.DATA/s['id']/'config.json').read_text())
    def test_last_user_revocation_stops_listener(self):
        s=self.service();u=self.user(s);s['desired']='running';server.put('service',s)
        with patch.object(server,'compose',return_value='') as run:
            server.mutate('/api/users/'+u['id']+'/toggle',{})
            self.assertEqual(run.call_args.args[1],['down'])
        self.assertEqual(server.get(s['id'],'service')['desired'],'stopped')
    def test_self_sni_targets_private_https(self):
        s=engine.validate(dict(protocol='vless',name='Self',host='vpn.example.com',port=8443,security='reality',transport='tcp',self_sni=True,self_sni_domain='vpn.example.com'))
        u=dict(name='A',id='a',**engine.credential());files=engine.bundle(s,[u]);config=json.loads(files['config.json']);compose=json.loads(files['compose.json'])
        self.assertEqual(config['inbounds'][0]['streamSettings']['realitySettings']['dest'],'127.0.0.1:9443')
        self.assertEqual(compose['services']['tunnel']['network_mode'],'host')
        self.assertNotIn('ports',compose['services']['tunnel'])
        self.assertEqual(compose['services']['tunnel']['user'],str(os.getuid())+':'+str(os.getgid()))
        self.assertNotIn('DAC_OVERRIDE',compose['services']['tunnel']['cap_add'])
        self.assertIn('sni=vpn.example.com',engine.profile(s,u))
    def test_auth_persistence_and_rate_limit(self):
        import auth
        before=dict(auth.CONFIG);auth.initialize(server.DATA)
        self.assertEqual(auth.CONFIG['base_path'],before['base_path'])
        with patch.object(auth,'password_hash',return_value='wrong'):
            for _ in range(10):self.assertIsNone(auth.login('admin','wrong','rate-test'))
            with self.assertRaisesRegex(ValueError,'попыток'):auth.login('admin','wrong','rate-test')
    def test_duplicate_shadowsocks_user_rejected(self):
        s=self.service('shadowsocks');self.user(s)
        with self.assertRaises(ValueError):self.user(s)
    def test_custom_config_and_profile(self):
        s=self.service('wireguard',image='example/wireguard:1',raw_config='[Interface]\nPrivateKey = secret',command=['run'])
        u=server.mutate('/api/users',dict(name='WG',service_id=s['id'],profile='[Interface]\nPrivateKey = client'))
        self.assertTrue(engine.profile(s,u).startswith('[Interface]'))
        with self.assertRaisesRegex(ValueError,'отзовите'):server.mutate('/api/users/'+u['id']+'/toggle',{})
    def test_reject_bad_security_and_custom_args(self):
        with self.assertRaises(ValueError):engine.validate(dict(name='A',protocol='trojan',host='x.com',port=443,security='none'))
        with self.assertRaises(ValueError):self.service('raw',image='x:latest',raw_config='{}',command='sh -c whatever')
    def test_zip_bundle_secret_files(self):
        s=self.service();u=self.user(s)
        files=engine.bundle(s,[u]);self.assertIn('compose.json',files);self.assertEqual((server.DATA/s['id']/'config.json').stat().st_mode & 0o777,0o600)

if __name__=='__main__':unittest.main()
