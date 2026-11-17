"""Image update rollout and recovery, with all container operations mocked."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine,image_updates,images,server

OLD='sha256:'+'1'*64
NEW='sha256:'+'2'*64
REFERENCE='ghcr.io/xtls/xray-core:99.1.1'


class ImageRolloutTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=server.DATA
        server.DATA=Path(self.tmp.name);server.init()
        self.addCleanup(self.tmp.cleanup);self.addCleanup(setattr,server,'DATA',self.old)
        self.addCleanup(image_updates.configure,server.DATA,[])
        self.image=images.BY_IMAGE['xray'];self.selected=dict(reference=REFERENCE,image_id=NEW)
        self.compose=patch.object(server,'compose',return_value='').start();self.addCleanup(patch.stopall)

    def service(self,id,desired='running',override=''):
        s=engine.validate(dict(id=id,protocol='vless',name=id,host='vpn.example.com',port=23456,transport='tcp',security='none',desired=desired,image_override=override))
        server.put('service',s)
        server.put('user',dict(id=id+'-user',name='User',person_id='owner',service_id=id,enabled=True,**engine.credential()))
        server.write_bundle(s)
        return s

    def select_update(self):image_updates.SELECTED['xray']=dict(reference=REFERENCE)

    def test_only_running_consumers_restart_and_keep_manual_overrides(self):
        active=self.service('active');stopped=self.service('stopped','stopped');custom=self.service('custom',override='custom/xray:v1')
        old_stopped=(server.DATA/stopped['id']/'compose.json').read_bytes()
        old_custom=(server.DATA/custom['id']/'compose.json').read_bytes()
        self.select_update();job={}
        with patch.object(server,'container_image',side_effect=[OLD,NEW]) as inspect:
            server.restart_image_services(self.image,self.selected,job)
        self.assertEqual(job['restarted_services'],['active'])
        self.assertEqual([call.args[0]['id'] for call in self.compose.call_args_list],['active'])
        self.assertEqual((server.DATA/stopped['id']/'compose.json').read_bytes(),old_stopped)
        self.assertEqual((server.DATA/custom['id']/'compose.json').read_bytes(),old_custom)
        self.assertEqual(json.loads((server.DATA/active['id']/'compose.json').read_text())['services']['tunnel']['image'],REFERENCE)

    def test_failed_start_restores_previous_files_and_actual_image_id(self):
        active=self.service('active');old_config=(server.DATA/active['id']/'config.json').read_bytes()
        self.select_update();job={};self.compose.side_effect=[ValueError('startup failed'),'']
        with patch.object(server,'container_image',return_value=OLD):
            with self.assertRaises(ValueError):server.restart_image_services(self.image,self.selected,job)
        restored=json.loads((server.DATA/active['id']/'compose.json').read_text())
        self.assertEqual(restored['services']['tunnel']['image'],OLD)
        self.assertEqual((server.DATA/active['id']/'config.json').read_bytes(),old_config)
        self.assertEqual(job['restored_services'],['active']);self.assertEqual(job['recovery_failed_services'],[])
        self.assertIn('never',self.compose.call_args.args[1])

    def test_all_previously_restarted_services_are_restored_on_later_failure(self):
        one=self.service('one');two=self.service('two');self.select_update();job={};attempts={}
        def compose(s,args,timeout=30):
            attempts[s['id']]=attempts.get(s['id'],0)+1
            if s['id']=='one' and attempts[s['id']]==1:raise ValueError('startup failed')
            return ''
        self.compose.side_effect=compose
        def inspect(s,name):return NEW if s['id']=='two' and attempts.get(s['id'])==1 else OLD
        with patch.object(server,'container_image',side_effect=inspect):
            with self.assertRaises(ValueError):server.restart_image_services(self.image,self.selected,job)
        self.assertCountEqual(job['restored_services'],['one','two'])
        for s in (one,two):self.assertEqual(json.loads((server.DATA/s['id']/'compose.json').read_text())['services']['tunnel']['image'],OLD)

    def test_service_already_using_new_image_is_not_recreated(self):
        self.service('active');self.select_update();job={}
        with patch.object(server,'container_image',return_value=NEW):server.restart_image_services(self.image,self.selected,job)
        self.compose.assert_not_called();self.assertEqual(job['restarted_services'],[])

    def test_failed_recovery_is_reported_explicitly(self):
        self.service('active');self.select_update();job={};self.compose.side_effect=ValueError('Docker unavailable')
        with patch.object(server,'container_image',return_value=OLD):
            with self.assertRaisesRegex(ValueError,'active'):server.restart_image_services(self.image,self.selected,job)
        self.assertEqual(job['recovery_failed_services'],['active'])

    def test_update_failure_restores_selected_version_and_mutable_tag(self):
        image_updates.CHECKS['xray']=dict(reference=self.image['reference'],digest='sha256:'+'3'*64,available=True,installed=True,current_reference=self.image['reference'],checked_at=1000)
        with patch.object(image_updates.time,'time',return_value=1001),patch.object(image_updates,'local_image',side_effect=[dict(Id=OLD),dict(Id=NEW)]),patch.object(images,'command') as command,patch.object(server,'restart_image_services',side_effect=ValueError('rollout failed')):
            with self.assertRaises(ValueError):image_updates.apply_update(self.image,server.DATA,{},images.prepare_image,command,restart_services=server.restart_image_services)
        self.assertEqual(image_updates.current(self.image)['reference'],self.image['reference'])
        self.assertTrue(image_updates.snapshot('xray')['available'])
        self.assertEqual(command.call_args.args[0],['docker','tag',OLD,self.image['reference']])

if __name__=='__main__':unittest.main()
