"""WDTT password counters, persistent baselines and API-only quota changes."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server,traffic,wdtt


class WDTTTrafficTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=server.DATA
        server.DATA=Path(self.tmp.name);server.init()
        self.addCleanup(self.tmp.cleanup);self.addCleanup(setattr,server,'DATA',self.old)
        self.database=dict(passwords={},devices={})
        self.core=patch.object(wdtt,'request',side_effect=lambda s,path='',data=None:wdtt.offline_change(self.database,path,data)).start()
        self.compose=patch.object(server,'compose',side_effect=AssertionError('No container operations in WDTT traffic tests')).start()
        self.addCleanup(patch.stopall)
        self.s=server.mutate('/api/services',dict(protocol='wdtt',name='TURN',host='vpn.example.com',port=28560,vk_hash='call_hash'))
        self.p=server.mutate('/api/people',dict(name='Owner'))
        self.other=server.mutate('/api/people',dict(name='Other'))
        self.u=self.grant(self.p);self.v=self.grant(self.other)
        self.s['desired']='running';server.put('service',self.s)

    def grant(self,p):
        return server.mutate('/api/people/'+p['id']+'/grant',dict(service_id=self.s['id']))

    def counters(self,up,down,u=None):
        self.database['passwords'][(u or self.u)['password']].update(up_bytes=up,down_bytes=down)

    def summary(self):return traffic.summary(server,server.get(self.p['id'],'person'))

    def limit(self,value,reset=False):
        return server.mutate('/api/people/'+self.p['id']+'/traffic',dict(limit_bytes=value,reset=reset))

    def test_persistent_core_counters_are_not_recounted_after_restart(self):
        self.counters(100,200);traffic.collect(server,self.s)
        self.assertEqual(self.summary()['total'],300)
        server.init();self.s['traffic_enabled']=False;server.put('service',self.s)
        traffic.poll(server)
        self.assertEqual(self.summary()['total'],300)
        self.counters(110,220);traffic.poll(server)
        self.assertEqual(self.summary()['total'],330)
        self.compose.assert_not_called()

    def test_today_lifetime_and_current_survive_core_and_quota_reset(self):
        with patch.object(traffic,'day_key',return_value='2026-11-17'):
            self.counters(100,200);traffic.collect(server,self.s)
            self.assertEqual(self.summary()['today_total'],0)
            self.counters(130,240);traffic.collect(server,self.s)
            self.assertEqual(self.summary()['today_total'],70)
            self.limit(1000,reset=True)
            self.assertEqual(self.summary()['total'],0)
            self.assertEqual(self.summary()['lifetime_total'],370)
            self.assertEqual(self.summary()['current_total'],370)
            self.assertEqual(self.summary()['today_total'],70)
            self.assertEqual(traffic.access_summary(server,self.u)['lifetime_total'],370)
            self.assertEqual(self.database['passwords'][self.u['password']]['up_bytes'],130)
            self.counters(5,10);traffic.collect(server,self.s)
            self.assertEqual(self.summary()['total'],15)
            self.assertEqual(self.summary()['lifetime_total'],385)
            self.assertEqual(self.summary()['today_total'],85)
        with patch.object(traffic,'day_key',return_value='2026-11-18'):
            self.assertEqual(self.summary()['today_total'],0)
            self.counters(9,15);traffic.collect(server,self.s)
            self.assertEqual(self.summary()['today_total'],9)
            self.assertEqual(self.summary()['lifetime_total'],394)

    def test_limit_deactivates_only_owner_password_without_restart(self):
        self.counters(100,200);self.limit(300)
        self.assertTrue(self.database['passwords'][self.u['password']]['is_deactivated'])
        self.assertFalse(self.database['passwords'][self.v['password']]['is_deactivated'])
        self.assertTrue(server.get(self.u['id'],'user')['enabled'])
        self.assertTrue(server.get(self.u['id'],'user')['quota_blocked'])
        self.assertEqual(server.get(self.s['id'],'service')['desired'],'running')
        self.limit(1000)
        self.assertFalse(self.database['passwords'][self.u['password']]['is_deactivated'])
        self.compose.assert_not_called()

    def test_manual_revocation_is_preserved_and_enabling_cannot_bypass_quota(self):
        self.counters(100,200);self.limit(300)
        server.mutate('/api/users/'+self.u['id']+'/toggle',{})
        self.assertFalse(server.get(self.u['id'],'user')['enabled'])
        self.limit(1000)
        self.assertTrue(self.database['passwords'][self.u['password']]['is_deactivated'])
        self.assertFalse(server.get(self.u['id'],'user')['enabled'])
        self.limit(300)
        server.mutate('/api/users/'+self.u['id']+'/toggle',{})
        self.assertTrue(server.get(self.u['id'],'user')['enabled'])
        self.assertTrue(self.database['passwords'][self.u['password']]['is_deactivated'])
        self.limit(1000,reset=True)
        self.assertFalse(self.database['passwords'][self.u['password']]['is_deactivated'])

    def test_new_password_is_disabled_immediately_for_blocked_owner(self):
        self.counters(100,200);self.limit(300)
        u=self.grant(self.p)
        self.assertTrue(u['enabled']);self.assertTrue(u['quota_blocked'])
        self.assertTrue(self.database['passwords'][u['password']]['is_deactivated'])
        self.assertTrue(u['wdtt_quota_applied'])

    def test_edit_keeps_manual_intent_and_deactivated_core_password(self):
        self.counters(100,200);self.limit(300)
        server.mutate('/api/users/'+self.u['id']+'/edit',dict(name='Renamed'))
        u=server.get(self.u['id'],'user')
        self.assertTrue(u['enabled']);self.assertTrue(u['quota_blocked'])
        self.assertTrue(self.database['passwords'][u['password']]['is_deactivated'])
        self.limit(1000)
        self.assertFalse(self.database['passwords'][u['password']]['is_deactivated'])

    def test_missing_or_invalid_counters_are_reported_as_errors(self):
        for values in ({'password':self.u['password']},{'password':self.u['password'],'up_bytes':-1,'down_bytes':2}):
            with self.subTest(values=values),self.assertRaises(ValueError):wdtt.counters(dict(passwords=[values]),[self.u])
        with patch.object(wdtt,'request',side_effect=wdtt.CoreUnavailable('offline')),patch.object(server,'running',return_value=True):
            traffic.poll(server)
        self.assertTrue(self.summary()['errors'])
        self.assertIsNone(self.summary()['updated_at'])

    def test_renewed_password_starts_a_separate_persistent_baseline(self):
        self.counters(100,200);traffic.collect(server,self.s)
        u=server.get(self.u['id'],'user');u['expires_at']=1;server.put('user',u)
        self.database['passwords'][u['password']]['expires_at']=1
        server.mutate('/api/users/'+u['id']+'/edit',dict(name='Renewed',days=30))
        renewed=server.get(u['id'],'user')
        self.assertNotEqual(renewed['password'],u['password'])
        self.counters(500,20,renewed);traffic.collect(server,self.s)
        self.assertEqual(self.summary()['lifetime_total'],820)

    def test_pending_api_deactivation_is_retried(self):
        original=self.core.side_effect
        def failing(s,path='',data=None):
            if path=='/deactivate':raise ValueError('temporary error')
            return original(s,path,data)
        self.counters(100,200)
        self.core.side_effect=failing
        self.limit(300)
        self.assertTrue(self.summary()['pending'])
        self.core.side_effect=original;traffic.enforce(server)
        self.assertFalse(self.summary()['pending'])
        self.assertTrue(self.database['passwords'][self.u['password']]['is_deactivated'])


class TrafficSchemaMigrationTest(unittest.TestCase):
    def test_old_usage_is_preserved_in_lifetime_totals(self):
        with sqlite3.connect(':memory:') as c:
            c.execute('CREATE TABLE traffic (user_id TEXT PRIMARY KEY,person_id TEXT,service_id TEXT,upload INTEGER,download INTEGER,epoch TEXT,last_upload INTEGER,last_download INTEGER,sampled_at INTEGER)')
            c.execute("INSERT INTO traffic VALUES ('u','p','s',100,200,'epoch',10,20,123)")
            traffic.init(c);traffic.init(c)
            self.assertEqual(c.execute('SELECT upload,download,lifetime_upload,lifetime_download,day_upload,day_download FROM traffic').fetchone(),(100,200,100,200,0,0))

if __name__=='__main__':unittest.main()
