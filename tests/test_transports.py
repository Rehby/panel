import json
import os
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
from transports import TRANSPORTS,client_config
from image_presets import validate_custom,custom_bundle
from images import CATALOG

class TransportTest(unittest.TestCase):
    def service(self,t,security='tls',**kw):
        s=dict(protocol='vless',name='Transport',host='vpn.example.com',port=18443,transport=t,security=security,certificate='-----BEGIN CERTIFICATE-----',private_key='-----BEGIN PRIVATE KEY-----',**kw)
        if t=='xdrive':s['transport_settings']={'service':'local','remoteFolder':'/tmp/transport-test'}
        return engine.validate(s)
    def test_every_transport_server_and_client_settings_match(self):
        self.assertEqual(len(TRANSPORTS),9)
        for t in TRANSPORTS:
            if 'vless' not in t.get('protocols',['vless']):continue
            with self.subTest(transport=t['id']):
                s=self.service(t['id'],t['security'][0]);u=dict(id='u',name='U',**engine.credential())
                server=json.loads(engine.bundle(s,[u])['config.json'])['inbounds'][0]
                client=client_config(s,u)['outbounds'][0]
                self.assertEqual(server['streamSettings'][t['key']],client['streamSettings'][t['key']])
                self.assertEqual(client['streamSettings']['network'],t['id'])
                if t['id']!='tcp':self.assertNotIn('flow',server['settings']['clients'][0])
    def test_reality_grpc_xhttp_without_vision(self):
        for t in ('grpc','xhttp'):
            s=self.service(t,'reality');u=dict(id='u',name='U',**engine.credential());profile=engine.profile(s,u)
            self.assertNotIn('flow=',profile)
            self.assertNotIn('flow',client_config(s,u)['outbounds'][0]['settings']['vnext'][0]['users'][0])
    def test_rejected_security_pairs(self):
        for t in ('ws','kcp','httpupgrade','hysteria','masque','xdrive'):
            with self.assertRaises(ValueError):self.service(t,'reality')
    def test_masque_rejected_for_vless(self):
        with self.assertRaisesRegex(ValueError,'только протоколу MASQUE'):self.service('masque')
    def test_removed_transports_not_exposed(self):
        for t in ('http','h2','h3','quic'):
            with self.assertRaisesRegex(ValueError,'удалены'):self.service(t)
    def test_client_override_does_not_change_server(self):
        s=self.service('xhttp',transport_settings={'mode':'stream-up','noSSEHeader':True},client_transport_settings={'host':'cdn.example.com'})
        u=dict(id='u',name='U',**engine.credential());server=json.loads(engine.bundle(s,[u])['config.json'])
        self.assertNotIn('host',server['inbounds'][0]['streamSettings']['xhttpSettings'])
        self.assertEqual(client_config(s,u)['outbounds'][0]['streamSettings']['xhttpSettings']['host'],'cdn.example.com')
        self.assertEqual(json.loads(engine.profile(s,u))['outbounds'][0]['protocol'],'vless')
    def test_images_cover_all_protocols(self):
        from catalog import PROTOCOLS
        for p in PROTOCOLS:self.assertTrue(any(p['id'] in image['protocols'] for image in CATALOG),p['id'])
        for image in CATALOG:
            if image.get('recipe'):
                self.assertEqual(len(image['revision']),40)
                self.assertTrue((Path(__file__).resolve().parents[1]/'images'/image['recipe']).is_file())
    def test_custom_package_traversal_rejected(self):
        for filename in ('../key','/etc/passwd','a/../../b','a//b'):
            with self.assertRaises(ValueError):validate_custom(dict(protocol='snolc',image_id='snolc',command=[],raw_config=json.dumps({filename:'bad'})))
    def test_wireguard_and_warp_are_scoped(self):
        wg=validate_custom(dict(protocol='wireguard',image_id='wireguard',raw_config='[Interface]',command=[]))
        files,service=custom_bundle(wg)
        self.assertIn('runtime/wg_confs/wg0.conf',files)
        self.assertEqual(service['cap_add'],['NET_ADMIN'])
        warp=validate_custom(dict(protocol='warp',image_id='warp',raw_config='{}',command=[],port=1080))
        _,service=custom_bundle(warp)
        self.assertEqual(service['ports'],['127.0.0.1:1080:1080/tcp'])
    def test_ss_methods_and_vision_tls(self):
        s=engine.validate(dict(protocol='shadowsocks',name='SS',host='x.com',port=10000,method='aes-256-gcm'))
        u=dict(id='u',name='U',**engine.credential());self.assertIn('aes-256-gcm',engine.bundle(s,[u])['config.json'])
        s=self.service('tcp',flow='xtls-rprx-vision');self.assertEqual(client_config(s,u)['outbounds'][0]['settings']['vnext'][0]['users'][0]['flow'],'xtls-rprx-vision')

if __name__=='__main__':unittest.main()
