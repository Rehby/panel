"""Regression checks for persistent owners and updating mixed YPtun subscriptions."""
import base64
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server, subscriptions, wdtt


def decode_inbound(link):
    assert link.startswith('yptun://inbound?')
    payload=parse_qs(urlsplit(link).query)['d'][0]
    return json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))


class PeopleTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.previous=server.DATA
        server.DATA=Path(self.tmp.name);server.init()
    def tearDown(self):
        server.DATA=self.previous;self.tmp.cleanup()
    def service(self,port=28443,**data):
        return server.mutate('/api/services',dict(protocol='vless',host='vpn.example.com',port=port,name='Entry '+str(port),security='none',**data))
    def person(self,name='Owner'):
        return server.mutate('/api/people',dict(name=name))
    def grant(self,p,s,**data):
        return server.mutate('/api/people/'+p['id']+'/grant',dict(service_id=s['id'],**data))
    def feed(self,p):
        return subscriptions.feed(server.get(p['id'],'person'),server.rows('user'),server.rows('service'),wdtt.available)

    def test_legacy_migration_is_idempotent_preserves_credentials_and_tokens(self):
        legacy=dict(id='legacy_access',name='Existing',service_id='old_service',token='a'*43,uuid=str(uuid.uuid4()),password='existing-password',enabled=True)
        server.put('user',legacy)
        server.init();migrated=server.get(legacy['id'],'user')
        self.assertEqual(migrated['person_id'],'person_'+legacy['id'])
        for key,value in legacy.items():self.assertEqual(migrated[key],value)
        person=server.get(migrated['person_id'],'person')
        self.assertEqual(person['token'],legacy['token'])
        server.init()
        self.assertEqual(server.rows('person'),[person]);self.assertEqual(server.get(legacy['id'],'user'),migrated)

    def test_one_owner_stable_feed_add_edit_revoke_delete_and_isolate(self):
        p=self.person();other=self.person('Other');s=self.service();second=self.service(28444)
        self.assertEqual(self.feed(p)['links'],[])
        first=self.grant(p,s,name='Phone');alien=self.grant(other,s,name='Other phone')
        initial=self.feed(p);self.assertEqual(len(initial['links']),1)
        self.assertIn(first['uuid'],initial['links'][0]);self.assertNotIn(alien['uuid'],json.dumps(initial))
        added=self.grant(p,second,name='Laptop');self.assertEqual(len(self.feed(p)['links']),2)
        new_id=str(uuid.uuid4())
        server.mutate('/api/users/'+first['id']+'/edit',dict(name='Renamed phone',uuid=new_id))
        text=json.dumps(self.feed(p));self.assertIn(new_id,text);self.assertNotIn(first['uuid'],text)
        server.mutate('/api/users/'+added['id']+'/toggle',{})
        self.assertEqual(len(self.feed(p)['links']),1)
        self.assertNotIn(added['uuid'],json.dumps(self.feed(p)))
        server.mutate('/api/users/'+added['id']+'/toggle',{})
        server.mutate('/api/users/'+first['id']+'/delete',{})
        self.assertEqual(len(self.feed(p)['links']),1)
        self.assertEqual(server.get(p['id'],'person')['token'],p['token'])
        self.assertEqual(len(self.feed(other)['links']),1)

    def test_delete_person_requires_revoke_connections(self):
        p=self.person();s=self.service();u=self.grant(p,s)
        with self.assertRaisesRegex(ValueError,'подключения'):server.mutate('/api/people/'+p['id']+'/delete',{})
        server.mutate('/api/users/'+u['id']+'/delete',{})
        server.mutate('/api/people/'+p['id']+'/delete',{})
        self.assertEqual(server.rows('person'),[])

    def test_missing_owner_is_rejected_before_core_mutation(self):
        s=self.service()
        with patch.object(server,'sync') as sync:
            with self.assertRaises(ValueError):server.mutate('/api/users',dict(person_id='missing',service_id=s['id'],name='No owner'))
        sync.assert_not_called();self.assertEqual(server.rows('user'),[])

    def test_edit_rollback_preserves_original_profile(self):
        p=self.person();s=self.service();u=self.grant(p,s);before=self.feed(p)['links']
        s['desired']='running';server.put('service',s)
        with patch.object(server,'compose',side_effect=ValueError('runtime failed')):
            with self.assertRaises(ValueError):server.mutate('/api/users/'+u['id']+'/edit',dict(name='Failed',uuid=str(uuid.uuid4())))
        self.assertEqual(server.get(u['id'],'user')['uuid'],u['uuid'])
        self.assertEqual(self.feed(p)['links'],before)

    def test_failed_new_access_does_not_create_a_person(self):
        s=self.service();s['desired']='running';server.put('service',s)
        with patch.object(server,'compose',side_effect=ValueError('runtime failed')):
            with self.assertRaises(ValueError):server.mutate('/api/users',dict(name='Failed new owner',service_id=s['id']))
        self.assertEqual(server.rows('user'),[]);self.assertEqual(server.rows('person'),[])

    def test_mixed_wdtt_and_raw_xray_keep_lossless_inbound_parameters(self):
        person=dict(id='one',name='Mixed')
        raw=dict(outbounds=[dict(protocol='vless',settings=dict(vnext=[dict(address='vpn.example.com',port=28445,users=[dict(id='client-id')])]))],dns=dict(hosts={'custom.example':'1.2.3.4'}))
        services=[dict(id='raw',name='Raw',protocol='raw',host='vpn.example.com',port=28445),dict(id='turn',name='TURN',protocol='wdtt',host='turn.example.com',port=28600,local_port=9000)]
        users=[dict(id='raw_u',person_id='one',name='Raw phone',service_id='raw',enabled=True,profile=json.dumps(raw)),dict(id='turn_u',person_id='one',name='TURN phone',service_id='turn',enabled=True,password='turn-secret',vk_hash='hash1,hash2',expires_at=time.time()+500),dict(id='expired_u',person_id='one',name='Expired',service_id='turn',enabled=True,password='expired-secret',vk_hash='hash1',expires_at=time.time()-500)]
        feed=subscriptions.feed(person,users,services,wdtt.available)
        self.assertEqual(len(feed['links']),2)
        decoded=[decode_inbound(link) for link in feed['links']]
        self.assertEqual(decoded[0]['engine'],'standard');self.assertEqual(decoded[0]['core'],'xray')
        self.assertEqual(json.loads(decoded[0]['proxy']['raw_xray_config']),raw)
        turn=decoded[1]['vkturn'];self.assertEqual(turn['core'],'wdtt');self.assertEqual(turn['wdtt_port'],28600)
        self.assertEqual(turn['wdtt_peer'],'turn.example.com');self.assertEqual(turn['vk_link'],'hash1\nhash2')
        self.assertEqual(turn['wdtt_password'],'turn-secret');self.assertNotIn('expired-secret',json.dumps(feed))

    def test_olcrtc_codec_keeps_room_id(self):
        location=dict(engine='stealth',name='RTC',id='meeting-room',key='0'*64,bypass_provider='jitsi',transport='datachannel')
        s=dict(protocol='raw',name='Room',host='vpn.example.com',port=28446)
        u=dict(id='access-id',name='Owner',profile=json.dumps(location))
        inbound=decode_inbound(subscriptions.link(s,u))
        self.assertEqual(inbound['id'],'meeting-room');self.assertEqual(inbound['key'],'0'*64)

    def test_wireguard_profile_survives_mixed_codec(self):
        conf='[Interface]\nPrivateKey = private\n[Peer]\nPublicKey = public\nEndpoint = vpn.example.com:28447\n'
        decoded=decode_inbound(subscriptions.link(dict(protocol='raw',name='WG',host='vpn.example.com',port=28447),dict(id='wg_u',name='Owner',profile=conf)))
        self.assertEqual(decoded['engine'],'standard');self.assertEqual(decoded['proxy']['awg_config'],conf.strip())


    def test_unsupported_legacy_profile_does_not_break_other_connections(self):
        p=self.person();s=self.service();self.grant(p,s)
        raw=dict(id='old-import',name='Legacy imported',protocol='raw',host='vpn.example.com',port=29448)
        server.put('service',raw)
        server.put('user',dict(id='old-profile',person_id=p['id'],service_id=raw['id'],name='Legacy profile',enabled=True,profile='{"unsupported":true}'))
        body=self.feed(p)
        self.assertEqual(len(body['links']),1)
        self.assertEqual(body['unavailableProfiles'][0]['name'],'Legacy profile')
        self.assertNotIn('unsupported',json.dumps(body))

    def test_managed_wireguard_rotate_key_and_revoke_update_actual_peer_config(self):
        p=self.person();s=server.mutate('/api/services',dict(protocol='wireguard',simple_engine=True,name='WG',host='vpn.example.com',port=29449))
        first=self.grant(p,s,name='Phone');second=self.grant(p,s,name='Laptop')
        target=server.DATA/s['id']/'runtime'/'wg_confs'/'wg0.conf'
        self.assertIn(first['wg_public'],target.read_text());self.assertIn(second['wg_public'],target.read_text())
        old_links=self.feed(p)['links'];old_token=server.get(p['id'],'person')['token']
        server.mutate('/api/users/'+first['id']+'/edit',dict(name='New key',rotate_key=True))
        new=server.get(first['id'],'user')
        self.assertNotEqual(new['wg_public'],first['wg_public']);self.assertNotEqual(new['wg_private'],first['wg_private'])
        self.assertEqual(new['wg_address'],first['wg_address'])
        self.assertNotIn(first['wg_public'],target.read_text());self.assertIn(new['wg_public'],target.read_text())
        self.assertNotEqual(self.feed(p)['links'],old_links)
        self.assertEqual(server.get(p['id'],'person')['token'],old_token)
        server.mutate('/api/users/'+first['id']+'/toggle',{})
        self.assertNotIn(new['wg_public'],target.read_text());self.assertIn(second['wg_public'],target.read_text())
        self.assertEqual(len(self.feed(p)['links']),1)

    def test_managed_free_turn_edit_hashes_keeps_generated_wg_keys(self):
        p=self.person();s=server.mutate('/api/services',dict(protocol='vkturn',simple_engine=True,name='VK',host='vpn.example.com',port=29450))
        u=self.grant(p,s,name='Phone',vk_hash='first_hash')
        before=self.feed(p)['links']
        server.mutate('/api/users/'+u['id']+'/edit',dict(name='Renamed',vk_hash='https://vk.com/call/next_hash'))
        updated=server.get(u['id'],'user')
        self.assertEqual(updated['vk_hash'],'next_hash');self.assertEqual(updated['wg_private'],u['wg_private'])
        self.assertNotEqual(self.feed(p)['links'],before)

    def test_managed_warp_uuid_rotation_updates_authenticated_entry(self):
        p=self.person();s=server.mutate('/api/services',dict(protocol='warp',simple_engine=True,name='WARP',host='vpn.example.com',port=29451))
        u=self.grant(p,s,name='Phone');next_uuid=str(uuid.uuid4())
        server.mutate('/api/users/'+u['id']+'/edit',dict(name='Renamed',uuid=next_uuid))
        config=json.loads((server.DATA/s['id']/'config.json').read_text())
        self.assertEqual(config['inbounds'][0]['settings']['clients'][0]['id'],next_uuid)
        self.assertEqual(config['inbounds'][0]['streamSettings']['security'],'reality')
        self.assertIn(next_uuid,self.feed(p)['links'][0]);self.assertNotIn(u['uuid'],json.dumps(config))

    def test_managed_trusttunnel_password_rotation_updates_credentials_file(self):
        # Profile codec fixture: the real certificate issuance/validation is exercised separately.
        cert='-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----'
        p=self.person();s=server.mutate('/api/services',dict(protocol='trusttunnel',simple_engine=True,name='TT',host='vpn.example.com',port=29452,certificate=cert,private_key='-----BEGIN PRIVATE KEY-----'))
        u=self.grant(p,s,name='Phone');before=self.feed(p)['links'][0]
        server.mutate('/api/users/'+u['id']+'/edit',dict(name='Renamed',password='replacement-password'))
        contents=(server.DATA/s['id']/'runtime'/'credentials.toml').read_text()
        self.assertIn('replacement-password',contents);self.assertNotIn(u['password'],contents)
        self.assertNotEqual(self.feed(p)['links'][0],before)


class PublicSubscriptionHTTPTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.previous=server.DATA
        server.DATA=Path(self.tmp.name);server.init()
        self.http=server.ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.http.shutdown();self.http.server_close();server.DATA=self.previous;self.tmp.cleanup()
    def request(self,token):
        connection=http.client.HTTPConnection('127.0.0.1',self.http.server_port)
        connection.request('GET','/subscription/'+token)
        result=connection.getresponse();body=result.read();status=result.status;headers=dict(result.getheaders());connection.close()
        return status,body,headers
    def test_public_feed_updates_in_place_and_old_token_is_revoked(self):
        p=server.mutate('/api/people',dict(name='Subscriber'))
        status,body,headers=self.request(p['token'])
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['links'],[])
        self.assertEqual(headers['Cache-Control'],'no-store');self.assertEqual(headers['Profile-Update-Interval'],'1')
        s=server.mutate('/api/services',dict(protocol='vless',name='Entry',host='vpn.example.com',port=28999,security='none'))
        server.mutate('/api/people/'+p['id']+'/grant',dict(service_id=s['id']))
        self.assertEqual(len(json.loads(self.request(p['token'])[1])['links']),1)
        server.mutate('/api/people/'+p['id']+'/rotate',{})
        self.assertEqual(self.request(p['token'])[0],404)
        self.assertEqual(self.request(server.get(p['id'],'person')['token'])[0],200)
        self.assertEqual(self.request('not-valid')[0],404)

if __name__=='__main__':unittest.main()
