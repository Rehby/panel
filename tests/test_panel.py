import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zlib
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
    def test_tls_services_use_panel_certificate_by_default(self):
        cert=dict(host='panel.example.com',certificate='-----BEGIN CERTIFICATE-----',private_key='-----BEGIN PRIVATE KEY-----')
        with patch.object(server,'certificate_helper',return_value=cert) as helper:
            for protocol in ('vless','vmess','trojan','hysteria2','trusttunnel'):
                data=dict(protocol=protocol,name='TLS',host='vpn.example.com',port=28443,security='tls',transport='tcp')
                if protocol=='trusttunnel':data['simple_engine']=True
                s=server.prepare_service(data)
                self.assertEqual(s['certificate_id'],'panel')
                self.assertEqual(s['sni'],'panel.example.com')
                self.assertEqual(s['certificate'],cert['certificate'])
                helper.assert_called_with(dict(action='read-panel-certificate'))
        with patch.object(server,'certificate_helper',side_effect=ValueError('HTTPS не настроен')):
            with self.assertRaisesRegex(ValueError,'HTTPS не настроен'):
                server.prepare_service(dict(protocol='trojan',name='TLS',host='vpn.example.com',port=28443,security='tls'))
    def test_explicit_certificate_is_preserved(self):
        with patch.object(server,'certificate_helper') as helper:
            s=server.prepare_service(dict(protocol='trojan',name='TLS',host='vpn.example.com',port=28443,security='tls',certificate='-----BEGIN CERTIFICATE-----',private_key='-----BEGIN PRIVATE KEY-----'))
        self.assertNotEqual(s.get('certificate_id'),'panel')
        helper.assert_not_called()
    def test_automatic_service_name_uses_vless_options_and_preserves_manual_names(self):
        fields=dict(protocol='vless',host='vpn.example.com',port=23456,transport='xhttp',security='reality',self_sni=True)
        with patch.object(server,'https_status',return_value=dict(host='vpn.example.com',self_sni_ready=True)):
            s=server.prepare_service(fields)
            self.assertEqual(s['name'],'VLESS · XHTTP · SELF')
            self.assertEqual(server.prepare_service(dict(fields,name='Моя служба'))['name'],'Моя служба')
            self.assertEqual(server.prepare_service(dict(fields,self_sni=False))['name'],'VLESS · XHTTP')
        s=server.prepare_service(dict(protocol='shadowsocks',host='vpn.example.com',port=23457))
        self.assertEqual(s['name'],'Shadowsocks')
    def test_existing_hysteria_transport_gets_persistent_auth_on_init(self):
        s=engine.validate(dict(protocol='vless',name='Old',host='vpn.example.com',port=23456,transport='hysteria',security='tls',certificate='-----BEGIN CERTIFICATE-----',private_key='-----BEGIN PRIVATE KEY-----'))
        s.update(id='legacy',desired='stopped');s.pop('hysteria_auth')
        server.put('service',s);server.init();saved=server.get('legacy','service')
        self.assertTrue(saved['hysteria_auth'])
        server.init();self.assertEqual(server.get('legacy','service')['hysteria_auth'],saved['hysteria_auth'])
        u=dict(id='u',name='User',**engine.credential())
        server_settings=json.loads(engine.bundle(saved,[u])['config.json'])['inbounds'][0]['streamSettings']['hysteriaSettings']
        client_settings=json.loads(engine.profile(saved,u))['outbounds'][0]['streamSettings']['hysteriaSettings']
        self.assertEqual(server_settings['auth'],saved['hysteria_auth'])
        self.assertEqual(client_settings['auth'],saved['hysteria_auth'])
    def test_auth_persistence_and_rate_limit(self):
        import auth
        before=dict(auth.CONFIG);auth.initialize(server.DATA)
        self.assertEqual(auth.CONFIG['base_path'],before['base_path'])
        with patch.object(auth,'password_hash',return_value='wrong'):
            for _ in range(10):self.assertIsNone(auth.login('admin','wrong','rate-test'))
            with self.assertRaisesRegex(ValueError,'попыток'):auth.login('admin','wrong','rate-test')
    def test_sessions_survive_reinitialize(self):
        import auth
        auth.initialize(server.DATA)
        with patch.object(auth,'password_hash',side_effect=lambda password,salt:auth.CONFIG['password_hash']):
            token=auth.login('admin','correct','restart-test')
        self.assertTrue(auth.authenticated(token))
        auth.initialize(server.DATA)
        self.assertTrue(auth.authenticated(token))
        auth.logout(token)
        auth.initialize(server.DATA)
        self.assertFalse(auth.authenticated(token))
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
    def test_openflux_cups_auto_rooms_match_profile_and_survive_edit(self):
        room='https://interview.cups.online/live-coding/?rooms=example'
        with patch.object(server,'create_openflux_rooms',return_value=room) as create:
            data=dict(name='Test',host='vpn.example.com',port=443,protocol='openflux',simple_engine=True,flux_transport='cupsonline',room_url='')
            s=server.mutate('/api/services',server.prepare_mutation('/api/services',data))
            u=self.user(s)
            path='/api/services/'+s['id']+'/edit'
            server.mutate(path,server.prepare_mutation(path,dict(name='Renamed',simple_engine=True,flux_transport='cupsonline',room_url=room)))
            saved=server.get(s['id'],'service')
            self.assertEqual(create.call_count,1)
        self.assertEqual(saved['room_url'],room);self.assertEqual(saved['engine_key'],s['engine_key'])
        encoded=engine.profile(saved,u).split('/v1/',1)[1]
        config=json.loads(zlib.decompress(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)),wbits=-15))
        command=json.loads(engine.bundle(saved,[u])['compose.json'])['services']['tunnel']['command']
        self.assertEqual(config['transports'][0]['url'],room);self.assertEqual(config['context'],'http://#')
        self.assertIn('--url='+room,command);self.assertIn('--session-context=http://#',command)
        self.assertEqual(config['secret'],saved['engine_key'])
        new_room='https://interview.cups.online/live-coding/?rooms=new'
        with patch.object(server,'create_openflux_rooms',return_value=new_room) as create:
            data=server.prepare_mutation(path,dict(room_url=''))
            server.mutate(path,data)
            create.assert_called_once()
        updated=server.get(s['id'],'service')
        self.assertEqual(updated['room_url'],new_room);self.assertEqual(updated['engine_key'],s['engine_key'])
        encoded=engine.profile(updated,u).split('/v1/',1)[1]
        config=json.loads(zlib.decompress(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)),wbits=-15))
        self.assertEqual(config['transports'][0]['url'],new_room)
        self.assertIn('--url='+new_room,json.loads(engine.bundle(updated,[u])['compose.json'])['services']['tunnel']['command'])
    def test_openflux_manual_urls_and_generation_errors(self):
        with patch.object(server,'create_openflux_rooms',side_effect=ValueError('rooms failed')) as create:
            with self.assertRaisesRegex(ValueError,'rooms failed'):
                server.prepare_mutation('/api/services',dict(protocol='openflux',simple_engine=True,flux_transport='cupsonline',room_url=''))
            self.assertFalse(server.rows('service'))
            for transport in ('yandex','vyandex','mailru','telemost'):
                with self.subTest(transport=transport):
                    with self.assertRaisesRegex(ValueError,'HTTPS'):
                        server.prepare_service(dict(protocol='openflux',simple_engine=True,flux_transport=transport,room_url='',name='Test',host='vpn.example.com',port=23456))
            data=dict(name='Test',host='vpn.example.com',port=443,protocol='openflux',simple_engine=True,flux_transport='cupsonline',room_url='https://example.com/room')
            s=server.mutate('/api/services',server.prepare_mutation('/api/services',data))
            self.assertEqual(s['room_url'],'https://example.com/room');self.assertEqual(create.call_count,1)
    def test_openflux_room_wizard_response_and_failures(self):
        ids=['12345678-1234-1234-1234-123456789abc']
        rooms=base64.urlsafe_b64encode(json.dumps(ids).encode()).decode().rstrip('=')
        success=SimpleNamespace(returncode=0,stdout=json.dumps(dict(id=1,ok=True,rooms=rooms)),stderr='')
        with patch.dict(os.environ,{'YPTUN_ALLOW_DOCKER':'1'}),patch.object(server.subprocess,'run',return_value=success) as run:
            self.assertEqual(server.create_openflux_rooms(),'https://interview.cups.online/live-coding/?rooms='+rooms)
            self.assertIn('--node-wizard',run.call_args.args[0]);self.assertEqual(json.loads(run.call_args.kwargs['input'])['method'],'createRooms')
            self.assertIn('CUPS_STRIPE=0',run.call_args.args[0])
            for response in (dict(id=1,ok=False,error='403'),dict(id=1,ok=True,rooms='bad!')):
                run.return_value=SimpleNamespace(returncode=0,stdout=json.dumps(response),stderr='')
                with self.assertRaises(ValueError):server.create_openflux_rooms()
            run.return_value=SimpleNamespace(returncode=1,stdout='',stderr='image missing')
            with self.assertRaisesRegex(ValueError,'соберите образ'):server.create_openflux_rooms()
            run.side_effect=subprocess.TimeoutExpired('docker',140)
            with self.assertRaisesRegex(ValueError,'время ожидания'):server.create_openflux_rooms()
        with patch.dict(os.environ,{'YPTUN_ALLOW_DOCKER':'0'}):
            with self.assertRaisesRegex(ValueError,'Docker'):server.create_openflux_rooms()

if __name__=='__main__':unittest.main()
