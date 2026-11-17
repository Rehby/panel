"""Cached update discovery and explicit update jobs without Docker or network calls."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine,images,image_updates,server

OLD='1'*40
NEW='2'*40
DIGEST='sha256:'+'3'*64
OLD_DIGEST='sha256:'+'4'*64


class ImageUpdatesTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.data=Path(self.tmp.name)
        self.image=dict(id='test',name='Test',reference='example/engine:latest',source='https://github.com/example/engine',protocols=['raw'])
        image_updates.configure(self.data,[self.image])
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(image_updates.configure,self.data,[])

    def check_result(self,**extra):
        return dict(available=True,installed=True,reference=self.image['reference'],digest=DIGEST,current_reference=self.image['reference'],checked_at=1000,**extra)

    def test_automatic_checks_use_daily_cache_manual_check_bypasses_it(self):
        with patch.object(image_updates.time,'time',return_value=1000),patch.object(image_updates,'discover',return_value=self.check_result()) as discover:
            image_updates.check_one(self.image);image_updates.check_one(self.image)
            image_updates.check_all([self.image]);self.assertEqual(discover.call_count,1)
            image_updates.check_one(self.image,force=True);self.assertEqual(discover.call_count,2)
        with patch.object(image_updates.time,'time',return_value=1000+86400),patch.object(image_updates,'discover',return_value=self.check_result()) as discover:
            image_updates.check_one(self.image);discover.assert_called_once()

    def test_cache_survives_restart_including_failed_checks(self):
        with patch.object(image_updates.time,'time',return_value=1000),patch.object(image_updates,'discover',side_effect=ValueError('registry unavailable')):
            image_updates.check_one(self.image)
        image_updates.configure(self.data,[self.image])
        with patch.object(image_updates.time,'time',return_value=1100),patch.object(image_updates,'discover') as discover:
            result=image_updates.check_one(self.image);discover.assert_not_called()
        self.assertIn('registry unavailable',result['error'])

    def test_registry_digest_and_new_tag_detection_are_read_only(self):
        local=dict(Id='local',RepoDigests=['example/engine@'+OLD_DIGEST])
        with patch.object(image_updates,'local_image',return_value=local),patch.object(image_updates,'manifest',return_value=dict(digest=DIGEST)),patch.object(image_updates,'release_reference',return_value=self.image['reference']),patch.object(images,'command') as command:
            result=image_updates.discover(self.image)
        self.assertTrue(result['available']);command.assert_not_called()
        with patch.object(image_updates,'local_image',return_value=dict(Id='local',RepoDigests=['example/engine@'+DIGEST])),patch.object(image_updates,'manifest',return_value=dict(digest=DIGEST)),patch.object(image_updates,'release_reference',return_value=self.image['reference']):
            self.assertFalse(image_updates.discover(self.image)['available'])
        with patch.object(image_updates,'local_image',return_value=local),patch.object(image_updates,'manifest',return_value=dict(digest=OLD_DIGEST)),patch.object(image_updates,'release_reference',return_value='example/engine:v2'):
            self.assertTrue(image_updates.discover(self.image)['available'])

    def test_source_updates_compare_oci_revision_and_pin_build_target(self):
        source=dict(self.image,recipe='test.Dockerfile',revision=OLD)
        with patch.object(image_updates,'local_image',return_value=dict(Config=dict(Labels={'org.opencontainers.image.revision':OLD}))),patch.object(image_updates,'output',return_value=NEW+'\tHEAD\n'):
            result=image_updates.discover(source)
        self.assertTrue(result['available']);self.assertEqual(result['revision'],NEW)
        self.assertEqual(result['reference'],'example/engine:'+NEW[:12])

    def test_registry_update_pulls_checked_digest_and_persists_selection(self):
        image_updates.CHECKS['test']=self.check_result()
        with patch.object(image_updates.time,'time',return_value=1001),patch.object(image_updates,'local_image',return_value=dict(Id='new-id')),patch.object(images,'prepare_image') as prepare,patch.object(images,'command') as command:
            image_updates.apply_update(self.image,self.data,{},prepare,command)
        prepare.assert_not_called()
        self.assertEqual(command.call_args_list[0].args[0],['docker','pull','example/engine@'+DIGEST])
        self.assertEqual(command.call_args_list[1].args[0],['docker','tag','example/engine@'+DIGEST,'example/engine:latest'])
        self.assertFalse(image_updates.snapshot('test')['available'])
        image_updates.configure(self.data,[self.image])
        self.assertEqual(image_updates.current(self.image)['image_id'],'new-id')

    def test_failed_source_build_keeps_previous_selection_and_notification(self):
        source=dict(self.image,recipe='test.Dockerfile',revision=OLD)
        image_updates.CHECKS['test']=dict(self.check_result(),reference='example/engine:'+NEW[:12],revision=NEW)
        with patch.object(image_updates.time,'time',return_value=1001),patch.object(images,'prepare_image',side_effect=ValueError('build failed')) as prepare:
            with self.assertRaises(ValueError):image_updates.apply_update(source,self.data,{},prepare,images.command)
        self.assertEqual(prepare.call_args.args[0]['revision'],NEW)
        self.assertEqual(image_updates.current(source)['revision'],OLD)
        self.assertTrue(image_updates.snapshot('test')['available'])

    def test_untrusted_candidate_repository_is_rejected(self):
        image_updates.CHECKS['test']=dict(self.check_result(),reference='untrusted/engine:latest')
        with patch.object(image_updates.time,'time',return_value=1001),patch.object(images,'command') as command:
            with self.assertRaises(ValueError):image_updates.apply_update(self.image,self.data,{},images.prepare_image,command)
        command.assert_not_called()

    def test_no_local_image_is_not_reported_as_an_update(self):
        with patch.object(image_updates,'local_image',return_value=None),patch.object(image_updates,'manifest',return_value=dict(digest=DIGEST)),patch.object(image_updates,'release_reference',return_value=self.image['reference']):
            result=image_updates.discover(self.image)
        self.assertFalse(result['available']);self.assertFalse(result['installed'])

    def test_registry_inspection_falls_back_without_buildx_and_selects_platform(self):
        entries=[dict(Descriptor=dict(digest=OLD_DIGEST,platform=dict(os='linux',architecture='arm64'))),dict(Descriptor=dict(digest=DIGEST,platform=dict(os='linux',architecture='amd64')),SchemaV2Manifest=dict(config=dict(digest='config-id')))]
        with patch.object(image_updates,'output',side_effect=[ValueError('buildx missing'),json.dumps(entries)]):
            result=image_updates.manifest(self.image['reference'],platform=dict(os='linux',architecture='amd64'))
        self.assertEqual(result,dict(digest=DIGEST,config_digest='config-id'))

    def test_source_update_persists_new_revision_and_reuses_it_for_services(self):
        source=dict(self.image,recipe='test.Dockerfile',revision=OLD)
        image_updates.CHECKS['test']=dict(self.check_result(),reference='example/engine:'+NEW[:12],revision=NEW)
        local=dict(Id='new-id',Config=dict(Labels={'org.opencontainers.image.revision':NEW}))
        with patch.object(image_updates.time,'time',return_value=1001),patch.object(image_updates,'local_image',return_value=local),patch.object(images,'prepare_image') as prepare:
            image_updates.apply_update(source,self.data,{},prepare,images.command)
        image_updates.configure(self.data,[source])
        self.assertEqual(image_updates.current(source)['revision'],NEW)
        self.assertFalse(image_updates.summary()['count'])

    def test_catalog_version_change_invalidates_old_selection_and_cache(self):
        image_updates.CHECKS['test']=self.check_result()
        with patch.object(image_updates.time,'time',return_value=1001),patch.object(image_updates,'local_image',return_value=dict(Id='new-id')),patch.object(images,'command'):
            image_updates.apply_update(self.image,self.data,{},images.prepare_image,images.command)
        newer=dict(self.image,reference='example/engine:v3')
        image_updates.configure(self.data,[newer])
        self.assertEqual(image_updates.current(newer)['reference'],newer['reference'])
        self.assertEqual(image_updates.snapshot('test'),{})

    def test_stable_release_maps_version_prefix_and_never_downgrades(self):
        image=dict(self.image,id='xray',reference='ghcr.io/xtls/xray-core:26.9.30',source='https://github.com/XTLS/Xray-core')
        class Response:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,*args):return json.dumps(dict(tag_name='v26.11.1')).encode()
        with patch.object(image_updates.urllib.request,'urlopen',return_value=Response()):
            self.assertEqual(image_updates.release_reference(image),'ghcr.io/xtls/xray-core:26.11.1')
            self.assertEqual(image_updates.release_reference(dict(image,reference='ghcr.io/xtls/xray-core:27.1.1')),'ghcr.io/xtls/xray-core:27.1.1')

    def test_failure_retains_previous_available_notification(self):
        image_updates.CHECKS['test']=self.check_result()
        with patch.object(image_updates,'discover',side_effect=ValueError('temporary error')):
            result=image_updates.check_one(self.image,force=True)
        self.assertTrue(result['available']);self.assertIn('error',result)
        self.assertEqual(image_updates.summary()['count'],1)

    def test_engine_uses_selected_image_after_regeneration_but_keeps_override(self):
        image=images.BY_IMAGE['xray'];image_updates.SELECTED['xray']=dict(reference='ghcr.io/xtls/xray-core:99.1.1')
        service=engine.validate(dict(protocol='vless',name='VPN',host='vpn.example.com',port=23456,security='none',transport='tcp'))
        user=dict(id='access',name='User',**engine.credential())
        config=json.loads(engine.bundle(service,[user])['compose.json'])
        self.assertEqual(config['services']['tunnel']['image'],'ghcr.io/xtls/xray-core:99.1.1')
        config=json.loads(engine.bundle(dict(service,image_override='custom/xray:v1'),[user])['compose.json'])
        self.assertEqual(config['services']['tunnel']['image'],'custom/xray:v1')

if __name__=='__main__':unittest.main()
