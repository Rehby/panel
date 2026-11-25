import base64
import configparser
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
import images
import provision
import subscriptions


def unbase64(text):return base64.urlsafe_b64decode(text+'='*(-len(text)%4))


def tlv_items(data):
    offset=0
    def read():
        nonlocal offset
        size=1<<(data[offset]>>6)
        value=int.from_bytes(data[offset:offset+size],'big')&((1<<(size*8-2))-1)
        offset+=size
        return value
    items={}
    while offset<len(data):
        tag=read();size=read();items[tag]=data[offset:offset+size];offset+=size
    return items


class ProvisionTest(unittest.TestCase):
    def service(self,protocol,**extra):
        fields=dict(protocol=protocol,provisioned=True,host='vpn.example.com',sni='vpn.example.com',port=23456,name='Service',room='room-example',dns_domain='dns.example.com',room_url='https://docs.example.com/document/abc',certificate='-----BEGIN CERTIFICATE-----\nAQI=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAwQ=\n-----END CERTIFICATE-----',private_key='-----BEGIN PRIVATE KEY-----\nkey')
        if protocol=='masterdns':fields['host']='192.0.2.20'
        fields.update(extra)
        return engine.validate(fields)
    def access(self,s,id='user1',others=None):
        return provision.user(s,dict(id=id,name='Александр',enabled=True,vk_hash='vk_test_hash',**engine.credential()),others or [])
    def test_all_managed_engines_generate_server_and_client_without_upload(self):
        for protocol in sorted(provision.PROTOCOLS):
            with self.subTest(protocol=protocol):
                s=self.service(protocol);u=self.access(s)
                files=engine.bundle(s,[u]);compose=json.loads(files['compose.json'])
                self.assertIn('tunnel',compose['services'])
                self.assertTrue(s['provisioned'])
                self.assertTrue(engine.profile(s,u))
                link=subscriptions.link(s,u)
                self.assertIn('://',link)
                self.assertNotIn(s.get('server_private','private_placeholder'),link)
    def test_wireguard_peer_revocation_removes_key_and_preserves_other_peer(self):
        for protocol in ('wireguard','amneziawg','vkturn'):
            with self.subTest(protocol=protocol):
                s=self.service(protocol);one=self.access(s);two=self.access(s,'user2',[one])
                self.assertNotEqual(one['wg_address'],two['wg_address'])
                self.assertNotEqual(one['wg_public'],two['wg_public'])
                one['enabled']=False
                text=engine.bundle(s,[one,two])['runtime/wg_confs/wg0.conf']
                self.assertNotIn(one['wg_public'],text)
                self.assertIn(two['wg_public'],text)
    def test_keys_match_openssl_public_key_and_survive_service_edit(self):
        s=self.service('wireguard')
        raw=base64.b64decode(s['server_private'])
        der=bytes.fromhex('302e020100300506032b656e04220420')+raw
        openssl=next((p for p in ['/opt/homebrew/opt/openssl@3/bin/openssl','/usr/local/opt/openssl@3/bin/openssl'] if Path(p).is_file()),'openssl')
        public=subprocess.run([openssl,'pkey','-inform','DER','-pubout','-outform','DER'],input=der,capture_output=True,check=True).stdout[-32:]
        self.assertEqual(public,base64.b64decode(s['server_public']))
        self.assertEqual(provision.prepare(dict(s,name='Renamed'))['server_private'],s['server_private'])
    def test_shared_secret_engines_require_separate_instances(self):
        for protocol in provision.SINGLE:
            with self.subTest(protocol=protocol):
                s=self.service(protocol);u=self.access(s)
                with self.assertRaisesRegex(ValueError,'отдельную службу'):self.access(s,'user2',[u])
    def test_freeturn_wire_profile_matches_yptun_parser_and_server_backend(self):
        s=self.service('vkturn');u=self.access(s)
        payload=json.loads(unbase64(engine.profile(s,u).split('://',1)[1]))
        self.assertEqual(payload['v'],1)
        self.assertIn(payload['transport'],('tcp','udp'))
        self.assertEqual(payload['peer'],'vpn.example.com:23456')
        wg=configparser.ConfigParser();wg.read_string(payload['wg'])
        # YPtun's FreeturnUriParser only imports PrivateKey, PublicKey, Address,
        # Endpoint and MTU. A generated PSK would therefore make it unusable.
        self.assertNotIn('PresharedKey',wg['Peer'])
        self.assertEqual(wg['Peer']['PublicKey'],s['server_public'])
        self.assertEqual(wg['Peer']['Endpoint'],'127.0.0.1:9000')
        files=engine.bundle(s,[u]);self.assertNotIn('PresharedKey',files['runtime/wg_confs/wg0.conf'])
        compose=json.loads(files['compose.json']);tunnel=compose['services']['tunnel']
        self.assertEqual(tunnel['environment']['CONNECT_ADDR'],'backend:51820')
        self.assertEqual(tunnel['environment']['OBF_KEY'],payload['key'])
        self.assertNotIn('ports',compose['services']['backend'])
    def test_trusttunnel_tlv_preserves_user_auth_cert_chain_and_random_port(self):
        s=self.service('trusttunnel');u=self.access(s)
        payload=tlv_items(unbase64(engine.profile(s,u).split('?',1)[1]))
        self.assertEqual(payload[1],b'vpn.example.com')
        self.assertEqual(payload[2],b'vpn.example.com:23456')
        self.assertEqual(payload[5],u['id'].encode())
        self.assertEqual(payload[6],u['password'].encode())
        self.assertEqual(payload[8],b'\x01\x02\x03\x04')
        disabled=dict(u,enabled=False)
        self.assertNotIn(u['password'],engine.bundle(s,[disabled])['runtime/credentials.toml'])
    def test_masterdns_profile_uses_direct_resolver_ip_and_service_port(self):
        for host,resolver,expected in (
            ('vpn.example.com','192.0.2.10','192.0.2.10:23456'),
            ('vpn.example.com','2001:db8::10','[2001:db8::10]:23456'),
            ('192.0.2.20','','192.0.2.20:23456'),
        ):
            with self.subTest(resolver=resolver):
                s=self.service('masterdns',host=host,resolver_ip=resolver);u=self.access(s)
                link=engine.profile(s,u)
                query=parse_qs(urlsplit(link).query)
                self.assertEqual(query['resolvers'],[expected])
                self.assertEqual(query['domains'],['dns.example.com'])
                self.assertEqual(subscriptions.link(s,u),link)
        with self.assertRaisesRegex(ValueError,'IP-адрес прямого резолвера'):
            self.service('masterdns',resolver_ip='vpn.example.com')
        for invalid_domain in ('192.0.2.10','dns.example.com:23456'):
            with self.subTest(dns_domain=invalid_domain), self.assertRaises(ValueError):
                self.service('masterdns',dns_domain=invalid_domain)
    def test_masterdns_resolves_host_and_sets_tunnel_domain_when_omitted(self):
        s=self.service('masterdns',host='vpn.example.com',dns_domain='');u=self.access(s)
        ipv6=(socket.AF_INET6,socket.SOCK_DGRAM,17,'',('2001:db8::10',0,0,0))
        ipv4=(socket.AF_INET,socket.SOCK_DGRAM,17,'',('192.0.2.10',0))
        for answers,expected in (([ipv6,ipv4],'192.0.2.10:23456'),([ipv6],'[2001:db8::10]:23456')):
            with self.subTest(expected=expected), patch('provision.socket.getaddrinfo',return_value=answers) as lookup:
                query=parse_qs(urlsplit(subscriptions.link(s,u)).query)
                lookup.assert_called_once_with('vpn.example.com',None,type=socket.SOCK_DGRAM)
                self.assertEqual(query['resolvers'],[expected])
                self.assertEqual(query['domains'],['vpn.example.com'])
        self.assertIn('DOMAIN = ["vpn.example.com"]',engine.bundle(s,[u])['runtime/server_config.toml'])
        with patch('provision.socket.getaddrinfo',side_effect=socket.gaierror), self.assertRaisesRegex(ValueError,'не удалось определить IP'):
            engine.profile(s,u)
        s=self.service('masterdns',host='192.0.2.10',dns_domain='')
        query=parse_qs(urlsplit(engine.profile(s,u)).query)
        self.assertEqual(query['resolvers'],['192.0.2.10:23456'])
        self.assertEqual(query['domains'],['t.invalid'])
    def test_openflux_secret_and_context_match_server(self):
        s=self.service('openflux');u=self.access(s)
        config=json.loads(zlib.decompress(unbase64(engine.profile(s,u).split('/v1/',1)[1]),wbits=-15))
        compose=json.loads(engine.bundle(s,[u])['compose.json'])
        command=compose['services']['tunnel']['command']
        self.assertIn('--session-context='+config['context'],command)
        self.assertIn('--url='+config['transports'][0]['url'],command)
        self.assertEqual(config['secret'],engine.bundle(s,[u])['runtime/key'])
        with self.assertRaises(ValueError):self.service('openflux',flux_transport='boards')
    def test_snolc_uses_builtin_modules_and_matching_public_key(self):
        s=self.service('snolc');u=self.access(s);files=engine.bundle(s,[u])
        self.assertIn('packages = "builtin"',files['runtime/snolc.toml'])
        self.assertIn('max_streams_per_session = 129',files['runtime/snolc.toml'])
        private=bytes.fromhex(files['runtime/priv.hex'])
        self.assertEqual(private,base64.b64decode(s['server_private']))
        query=parse_qs(urlsplit(engine.profile(s,u)).query)
        self.assertEqual(query['key'][0],base64.b64decode(s['server_public']).hex())
        self.assertEqual(images.BY_IMAGE['snolc']['source'],'https://github.com/yanisplugg/yptun')
    def test_olcrtc_inbound_keeps_actual_room_and_supported_transport(self):
        s=self.service('olcrtc',provider='mtslink');u=self.access(s)
        location=json.loads(engine.profile(s,u))
        self.assertEqual(location['id'],s['room'])
        self.assertEqual(location['transport'],'vp8channel')
        inbound=json.loads(unbase64(parse_qs(urlsplit(subscriptions.link(s,u)).query)['d'][0]))
        self.assertEqual(inbound['id'],s['room'])
        self.assertEqual(inbound['key'],s['engine_key'])
        with self.assertRaises(ValueError):self.service('olcrtc',provider='mtslink',rtc_transport='datachannel')
    def test_warp_public_listener_has_auth_and_socks_stays_private(self):
        s=self.service('warp');u=self.access(s)
        files=engine.bundle(s,[u]);compose=json.loads(files['compose.json']);xray=json.loads(files['config.json'])
        self.assertNotIn('ports',compose['services']['warp'])
        self.assertIn('warp-state',compose['volumes'])
        self.assertEqual(xray['inbounds'][0]['settings']['clients'][0]['id'],u['uuid'])
        self.assertEqual(xray['inbounds'][0]['streamSettings']['security'],'reality')
        self.assertEqual(xray['outbounds'][0]['protocol'],'socks')
        self.assertEqual(xray['outbounds'][0]['settings']['servers'][0]['address'],'warp')
        self.assertEqual(parse_qs(urlsplit(engine.profile(s,u)).query)['security'],['reality'])
    def test_amneziawg_server_and_client_use_same_obfuscation(self):
        s=self.service('amneziawg');u=self.access(s)
        server=engine.bundle(s,[u])['runtime/wg_confs/wg0.conf'];client=engine.profile(s,u)
        for key,value in s['awg'].items():
            self.assertIn(f'{key} = {value}\n',server)
            self.assertIn(f'{key} = {value}\n',client)
        self.assertEqual(len(set(s['awg'][f'H{i}'] for i in range(1,5))),4)


if __name__=='__main__':unittest.main()
