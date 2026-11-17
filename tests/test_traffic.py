"""Accounting persistence, quota isolation and generated telemetry configuration."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine,images,server,traffic,wdtt


class TrafficTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.previous=server.DATA
        server.DATA=Path(self.tmp.name);server.init()
        self.addCleanup(self.tmp.cleanup);self.addCleanup(setattr,server,'DATA',self.previous)
        self.compose=patch.object(server,'compose',return_value='').start();self.addCleanup(patch.stopall)
        self.s=server.mutate('/api/services',dict(protocol='vless',name='VPN',host='vpn.example.com',port=23456,security='none'))
        self.p=server.mutate('/api/people',dict(name='One'))
        self.other=server.mutate('/api/people',dict(name='Two'))
        self.u=self.grant(self.p)
        self.v=self.grant(self.other)

    def grant(self,p,**kwargs):
        return server.mutate('/api/people/'+p['id']+'/grant',dict(service_id=self.s['id'],**kwargs))

    def record(self,up,down,epoch='one'):
        traffic.record(server,self.s,[self.u],{self.u['id']:[up,down]},epoch)

    def summary(self):return traffic.summary(server,server.get(self.p['id'],'person'))

    def limit(self,value,reset=False):
        return server.mutate('/api/people/'+self.p['id']+'/traffic',dict(limit_bytes=value,reset=reset))

    def test_cumulative_counters_and_generation_survive_panel_restart(self):
        self.record(100,200);self.record(100,200);self.record(150,225)
        server.init();self.record(160,230)
        self.assertEqual(self.summary()['total'],390)
        self.record(10,20,epoch='recreated')
        self.assertEqual(self.summary()['total'],420)
        self.record(5,5,epoch='recreated')
        self.assertEqual(self.summary()['total'],430)

    def test_manual_reset_keeps_baseline_and_deleted_access_usage(self):
        self.record(100,200);self.limit(0,reset=True)
        self.record(120,230)
        self.assertEqual(self.summary()['total'],50)
        server.mutate('/api/users/'+self.u['id']+'/delete',{})
        self.assertEqual(self.summary()['total'],50)

    def test_limit_blocks_only_owner_and_core_config_and_subscription(self):
        self.record(100,200)
        server.mutate('/api/services/'+self.s['id']+'/start',{})
        self.limit(300)
        self.assertTrue(server.get(self.u['id'],'user')['quota_blocked'])
        self.assertFalse(server.get(self.v['id'],'user').get('quota_blocked'))
        config=json.loads((server.DATA/self.s['id']/'config.json').read_text())
        clients=config['inbounds'][0]['settings']['clients']
        self.assertEqual([x['id'] for x in clients],[self.v['uuid']])
        self.assertFalse(wdtt.available(server.get(self.u['id'],'user')))
        self.assertTrue(self.summary()['blocked'])
        server.mutate('/api/users/'+self.u['id']+'/toggle',{})
        self.limit(1000)
        self.assertFalse(server.get(self.u['id'],'user')['enabled'])
        self.assertFalse(self.summary()['blocked'])

    def test_last_quota_blocked_service_resumes_after_reset(self):
        server.mutate('/api/users/'+self.v['id']+'/delete',{})
        server.mutate('/api/services/'+self.s['id']+'/start',{})
        self.record(5,5);self.limit(10)
        self.assertEqual(server.get(self.s['id'],'service')['desired'],'stopped')
        self.assertTrue(server.get(self.s['id'],'service')['quota_stopped'])
        self.limit(10,reset=True)
        self.assertEqual(server.get(self.s['id'],'service')['desired'],'running')
        self.assertFalse(server.get(self.u['id'],'user')['quota_blocked'])

    def test_failed_core_sync_is_retried(self):
        self.record(10,10)
        with patch.object(server,'sync',side_effect=ValueError('Docker failed')):
            self.limit(10)
        self.assertTrue(server.get(self.s['id'],'service')['quota_sync_pending'])
        traffic.enforce(server)
        self.assertNotIn('quota_sync_pending',server.get(self.s['id'],'service'))
        config=json.loads((server.DATA/self.s['id']/'config.json').read_text())
        self.assertNotIn(self.u['uuid'],json.dumps(config))

    def test_manual_service_stop_is_preserved_when_limit_is_removed(self):
        server.mutate('/api/users/'+self.v['id']+'/delete',{})
        server.mutate('/api/services/'+self.s['id']+'/start',{})
        self.record(5,5);self.limit(10)
        server.mutate('/api/services/'+self.s['id']+'/stop',{})
        self.limit(0)
        self.assertEqual(server.get(self.s['id'],'service')['desired'],'stopped')

    def test_collector_checks_container_generation_and_preserves_counters(self):
        payload=json.dumps(dict(stat=[dict(name='user>>>'+self.u['id']+'>>>traffic>>>downlink',value='500')]))
        inspected=SimpleNamespace(returncode=0,stdout='container:started-once\n')
        with patch.object(server,'compose',side_effect=['container-id',payload]),patch.object(traffic.subprocess,'run',return_value=inspected):
            traffic.collect(server,self.s)
        self.assertEqual(self.summary()['download'],500)
        restarted=SimpleNamespace(returncode=0,stdout='container:started-again\n')
        with patch.object(server,'compose',side_effect=['container-id',payload]),patch.object(traffic.subprocess,'run',side_effect=[inspected,restarted]):
            with self.assertRaisesRegex(ValueError,'перезапустился'):traffic.collect(server,self.s)
        self.assertEqual(self.summary()['download'],500)

    def test_new_access_inherits_block_and_limit_cannot_be_bypassed_with_unsupported_core(self):
        self.record(1,1);self.limit(1)
        new=self.grant(self.p)
        self.assertTrue(new['quota_blocked'])
        unsupported=server.mutate('/api/services',dict(protocol='raw',name='Imported',host='vpn.example.com',port=23457,image='example/core:1',raw_config='{}',command=[]))
        with self.assertRaisesRegex(ValueError,'учётом'):
            server.mutate('/api/people/'+self.p['id']+'/grant',dict(service_id=unsupported['id'],name='Raw',profile='vless://test'))
        for value in (-1,True,'1.5',float('inf')):
            with self.subTest(value=value),self.assertRaises(ValueError):self.limit(value)

    def test_generated_configs_and_image_override(self):
        s=dict(self.s,image_override='example/xray:custom')
        files=engine.bundle(s,[self.u])
        config=json.loads(files['config.json']);compose=json.loads(files['compose.json'])
        self.assertEqual(compose['services']['tunnel']['image'],'example/xray:custom')
        self.assertEqual(config['api']['listen'],'127.0.0.1:'+str(s['stats_port']))
        self.assertTrue(config['policy']['levels']['0']['statsUserUplink'])
        self.assertFalse(any(str(s['stats_port']) in x for x in compose['services']['tunnel']['ports']))
        s=server.prepare_service(dict(protocol='webproxy',name='WEB',host='tg.example.com',port=23458))
        files=engine.bundle(s,[dict(self.u,webproxy_secret='ab'*16)])
        self.assertIn('listen = "/run/yptun/metrics.sock"',files['relay.toml'])
        self.assertIn('./runtime:/run/yptun',json.loads(files['compose.json'])['services']['tunnel']['volumes'])
        with self.assertRaises(ValueError):server.prepare_service(dict(self.s,image_override='invalid;command'))

    def test_counter_parsers_map_stable_access_ids(self):
        text=json.dumps(dict(stat=[dict(name='user>>>'+self.u['id']+'>>>traffic>>>uplink',value='120'),dict(name='user>>>'+self.u['id']+'>>>traffic>>>downlink',value='230'),dict(name='outbound>>>direct>>>traffic>>>uplink',value='999')]))
        self.assertEqual(traffic.xray_counters(text,[self.u])[self.u['id']],[120,230])
        text='tgwp_bytes_down_total{domain="tg.example.com",label="'+self.u['id']+'"} 230\ntgwp_bytes_up_total{domain="tg.example.com",label="'+self.u['id']+'"} 120\n'
        self.assertEqual(traffic.webproxy_counters(text,[self.u])[self.u['id']],[120,230])


class ImageInstallTest(unittest.TestCase):
    def test_install_builds_recipes_and_pulls_registry_images(self):
        items=[dict(id='build',name='Build',recipe='test.Dockerfile'),dict(id='registry',name='Registry')]
        with patch.object(images,'CATALOG',items),patch.object(images,'prepare_image') as prepare:
            images.install_images(Path('/tmp/data'))
        self.assertEqual([call.args[1] for call in prepare.call_args_list],['build','pull'])

    def test_failure_is_reported_and_stops_install(self):
        items=[dict(name='Broken',recipe='test.Dockerfile'),dict(name='Later')]
        with patch.object(images,'CATALOG',items),patch.object(images,'prepare_image',side_effect=ValueError('build failed')) as prepare:
            with self.assertRaises(ValueError):images.install_images(Path('/tmp/data'))
        self.assertEqual(prepare.call_count,1)

if __name__=='__main__':unittest.main()
