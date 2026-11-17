"""WEB transport links, credential lifecycle and HTTPS integration."""
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine, server, subscriptions, webproxy, wdtt

spec=importlib.util.spec_from_file_location('webproxy_https',Path(__file__).resolve().parents[1]/'deploy'/'https-admin.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)


class WebProxyTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.previous=server.DATA
        server.DATA=Path(self.tmp.name);server.init()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(setattr,server,'DATA',self.previous)
        self.compose=patch.object(server,'compose',return_value='').start()
        self.addCleanup(patch.stopall)
        self.service=server.mutate('/api/services',dict(protocol='webproxy',host='PROXY.example.com',port=28443,name='WEB'))
        self.person=server.mutate('/api/people',dict(name='Owner'))

    def grant(self,**data):
        return server.mutate('/api/people/'+self.person['id']+'/grant',dict(service_id=self.service['id'],**data))

    def test_link_and_private_listener(self):
        u=self.grant();other=self.grant()
        link=engine.profile(self.service,u)
        self.assertTrue(link.startswith('tg://webproxy?'))
        self.assertEqual(parse_qs(urlsplit(link).query),dict(server=['proxy.example.com'],secret=[u['webproxy_secret']]))
        self.assertRegex(u['webproxy_secret'],r'^[a-f0-9]{32}$')
        self.assertNotEqual(u['webproxy_secret'],other['webproxy_secret'])
        files=engine.bundle(self.service,[u,other])
        config=files['relay.toml']
        self.assertIn('behind_proxy = true',config)
        self.assertIn(u['webproxy_secret'],config);self.assertIn(other['webproxy_secret'],config)
        tunnel=json.loads(files['compose.json'])['services']['tunnel']
        self.assertEqual(tunnel['ports'],['127.0.0.1:28443:4600/tcp'])
        self.assertNotIn('network_mode',tunnel)

    def test_revocation_rotation_and_last_user_stop(self):
        u=self.grant();other=self.grant()
        server.mutate('/api/services/'+self.service['id']+'/start',{})
        server.mutate('/api/users/'+u['id']+'/toggle',{})
        config=(server.DATA/self.service['id']/'relay.toml').read_text()
        self.assertNotIn(u['webproxy_secret'],config);self.assertIn(other['webproxy_secret'],config)
        server.mutate('/api/users/'+other['id']+'/edit',dict(name=other['name'],webproxy_secret='ab'*16))
        config=(server.DATA/self.service['id']/'relay.toml').read_text()
        self.assertIn('ab'*16,config);self.assertNotIn(other['webproxy_secret'],config)
        server.mutate('/api/users/'+other['id']+'/delete',{})
        self.assertEqual(server.get(self.service['id'],'service')['desired'],'stopped')
        self.compose.assert_any_call(unittest.mock.ANY,['down'])

    def test_excluded_from_both_subscription_endpoints(self):
        u=self.grant()
        server.mutate('/api/services/'+self.service['id']+'/start',{})
        native=server.mutate('/api/services',dict(protocol='vless',host='vpn.example.com',port=28444,name='VPN',security='none'))
        server.mutate('/api/people/'+self.person['id']+'/grant',dict(service_id=native['id']))
        server.mutate('/api/services/'+native['id']+'/start',{})
        feed=subscriptions.feed(self.person,server.rows('user'),server.rows('service'),wdtt.available)
        self.assertEqual(len(feed['links']),1);self.assertTrue(feed['links'][0].startswith('vless://'))
        self.assertNotIn('unavailableProfiles',feed)
        listener=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start()
        try:
            for path,status in [(server.auth.CONFIG['base_path']+'/sub/'+u['token'],404),('/subscription/'+self.person['token'],200)]:
                conn=http.client.HTTPConnection('127.0.0.1',listener.server_port)
                conn.request('GET',path);response=conn.getresponse();body=response.read();conn.close()
                self.assertEqual(response.status,status)
                self.assertNotIn(u['webproxy_secret'].encode(),body)
            with patch.object(server.Handler,'auth',return_value=True):
                conn=http.client.HTTPConnection('127.0.0.1',listener.server_port)
                conn.request('GET',server.auth.CONFIG['base_path']+'/api/state');response=conn.getresponse();body=response.read();conn.close()
                self.assertEqual(response.status,200)
                self.assertNotIn(b'webproxy_secret',body)
                self.assertNotIn(u['webproxy_secret'].encode(),body)
        finally:listener.shutdown();listener.server_close();thread.join()

    def test_invalid_and_duplicate_secrets_and_host(self):
        u=self.grant(webproxy_secret='01'*16)
        for value in ('nope','ee'+'ab'*16,'ab'*17):
            with self.subTest(value=value),self.assertRaises(ValueError):self.grant(webproxy_secret=value)
        with self.assertRaisesRegex(ValueError,'уже используется'):self.grant(webproxy_secret=u['webproxy_secret'])
        for host in ('127.0.0.1','https://proxy.example.com','localhost'):
            with self.subTest(host=host),self.assertRaises(ValueError):server.prepare_service(dict(protocol='webproxy',name='WEB',host=host,port=28445))
        with self.assertRaisesRegex(ValueError,'уже используется'):
            server.prepare_service(dict(protocol='webproxy',name='WEB',host=self.service['host'],port=28445))
        with patch.object(server,'https_status',return_value=dict(host='panel.example.com')):
            with self.assertRaisesRegex(ValueError,'отдельный домен'):
                server.prepare_service(dict(protocol='webproxy',name='WEB',host='panel.example.com',port=28445))

    def test_failed_sync_restores_previous_secret(self):
        u=self.grant()
        with patch.object(server,'sync',side_effect=ValueError('Docker unavailable')):
            with self.assertRaises(ValueError):server.mutate('/api/users/'+u['id']+'/edit',dict(name=u['name'],webproxy_secret='ab'*16))
        self.assertEqual(server.get(u['id'],'user')['webproxy_secret'],u['webproxy_secret'])
        config=(server.DATA/self.service['id']/'relay.toml').read_text()
        self.assertIn(u['webproxy_secret'],config);self.assertNotIn('ab'*16,config)


class WebProxyHTTPSTest(unittest.TestCase):
    def test_route_certificate_websocket_delete_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);nginx=root/'panel.conf'
            registry={}
            def cert(data):
                import hashlib
                id=hashlib.sha256(('domain:'+data['host']).encode()).hexdigest()[:24]
                registry[id]=dict(cert='/etc/letsencrypt/live/test/fullchain.pem',key='/etc/letsencrypt/live/test/privkey.pem')
            with patch.object(helper,'NGINX',nginx),patch.object(helper,'CONFIG',root),patch.object(helper,'certificate_registry',return_value=registry),patch.object(helper,'service_certificate',side_effect=cert) as issue,patch.object(helper,'run',return_value='') as run:
                data=dict(id='a'*16,host='proxy.example.com',port=28443)
                helper.webproxy_route(data)
                path=root/('yptun-webproxy-'+data['id']+'.conf');text=path.read_text()
                self.assertIn('proxy_pass http://127.0.0.1:28443;',text)
                self.assertIn('proxy_set_header Upgrade $http_upgrade;',text)
                self.assertIn('proxy_buffering off;',text);self.assertIn('access_log off;',text)
                self.assertIn('listen 443 ssl',text)
                helper.webproxy_route(data);issue.assert_called_once()
                with patch.object(helper,'run',side_effect=ValueError('nginx failed')):
                    with self.assertRaises(ValueError):helper.webproxy_route(dict(data,port=28444))
                self.assertEqual(path.read_text(),text)
                for changes in (dict(id='../escape'),dict(host='proxy.example.com;'),dict(host='127.0.0.1'),dict(port=8080)):
                    with self.subTest(changes=changes),self.assertRaises(ValueError):helper.webproxy_route(dict(data,**changes))
                helper.webproxy_route(dict(id=data['id'],remove=True));self.assertFalse(path.exists())

if __name__=='__main__':unittest.main()
