import base64
import json
import os
import threading
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import wdtt,server,subscriptions

class WDTTTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.old=server.DATA;server.DATA=Path(self.tmp.name);server.init()
 def tearDown(self):server.DATA=self.old;self.tmp.cleanup()
 def service(self):return server.mutate('/api/services',dict(protocol='wdtt',host='vpn.example.com',name='TURN',port=56000,vk_hash='abc'))
 def test_compose_scope_and_owner_secrets(self):
  s=self.service();files=wdtt.bundle(s);svc=json.loads(files['compose.json'])['services']['tunnel']
  self.assertEqual(svc['cap_add'],['NET_ADMIN']);self.assertNotIn('network_mode',svc)
  self.assertIn(f"127.0.0.1:{s['admin_port']}:56002/tcp",svc['ports'])
  self.assertNotIn(s['admin_token'],' '.join(svc['command']))
 def test_hashes(self):
  self.assertEqual(wdtt.hashes('https://vk.com/call/abc_DEF?x=1 abc_DEF'),'abc_DEF')
  for val in ('','https://evil.com/foo','x;curl','a,b,c,d,e'):
   with self.assertRaises(ValueError):wdtt.hashes(val)
 def test_real_revocation_and_subscription_shape(self):
  s=self.service();v=dict(password='testpassword123',label='Test',vk_hash='abc',expires_at=int(time.time())+86400,max_devices=1,is_deactivated=False)
  with patch.object(wdtt,'request',return_value=v) as core:
   u=server.mutate('/api/users',dict(service_id=s['id'],name='Test',vk_hash='abc'))
   self.assertEqual(core.call_args.args[2]['vk_hash'],'abc')
   sub=wdtt.subscription(s,u);self.assertEqual(sub['profiles'][0]['peer'],'vpn.example.com:56000');self.assertNotIn('admin_token',json.dumps(sub));self.assertTrue(wdtt.link(s,u).startswith('qwdtt://config?'))
  with patch.object(wdtt,'request',return_value=dict(v,is_deactivated=True)) as core:
   server.mutate('/api/users/'+u['id']+'/toggle',{});self.assertEqual(core.call_args.args[1],'/deactivate')
  self.assertFalse(wdtt.available(server.get(u['id'],'user')))
 def test_automatic_name_in_turn_subscription(self):
  s=self.service();s['country']='NL';server.put('service',s)
  p=server.mutate('/api/people',dict(name='Owner'))
  view=dict(password='testpassword123',label='🇳🇱 VK-TURN / qWDTT',vk_hash='abc',expires_at=int(time.time())+86400,max_devices=1,is_deactivated=False)
  with patch.object(wdtt,'request',return_value=view) as core:
   u=server.mutate('/api/people/'+p['id']+'/grant',dict(service_id=s['id'],vk_hash='abc'))
  self.assertEqual(core.call_args.args[2]['label'],view['label'])
  self.assertEqual(u['name'],view['label'])
  self.assertEqual(wdtt.subscription(s,u)['profiles'][0]['name'],view['label'])
  encoded=parse_qs(urlsplit(subscriptions.link(s,u)).query)['d'][0]
  decoded=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
  self.assertEqual(decoded['name'],view['label'])
 def test_api_failure_does_not_create_local_user(self):
  s=self.service()
  with patch.object(wdtt,'request',side_effect=ValueError('offline')):
   with self.assertRaises(ValueError):server.mutate('/api/users',dict(service_id=s['id'],name='Test',vk_hash='abc'))
  self.assertEqual(server.rows('user'),[])
 def test_expiration(self):self.assertFalse(wdtt.available(dict(enabled=True,expires_at=time.time()-1)))
 def test_shared_call_is_used_for_all_and_updated_in_core(self):
  s=self.service();database=dict(passwords={},devices={})
  with patch.object(wdtt,'request',side_effect=lambda service,path='',data=None:wdtt.offline_change(database,path,data)):
   first=server.mutate('/api/users',dict(service_id=s['id'],name='First',vk_hash='ignored'))
   second=server.mutate('/api/users',dict(service_id=s['id'],name='Second'))
   self.assertEqual(first['vk_hash'],'abc');self.assertEqual(second['vk_hash'],'abc')
   server.mutate('/api/services/'+s['id']+'/edit',dict(vk_hash='https://vk.com/call/new_hash'))
   for u in (first,second):
    self.assertEqual(server.get(u['id'],'user')['vk_hash'],'new_hash')
    self.assertEqual(database['passwords'][u['password']]['vk_hash'],'new_hash')
    self.assertEqual(database['passwords'][u['password']]['expires_at'],u['expires_at'])
   server.mutate('/api/users/'+first['id']+'/edit',dict(name='First',vk_hash='different'))
   self.assertEqual(server.get(first['id'],'user')['vk_hash'],'new_hash')
 def test_failed_shared_call_update_restores_previous_values(self):
  s=self.service();database=dict(passwords={},devices={});fail=[False]
  def request(service,path='',data=None):
   if path=='/update' and data['vk_hash']=='new_hash':
    if fail[0]:raise ValueError('core failure')
    fail[0]=True
   return wdtt.offline_change(database,path,data)
  with patch.object(wdtt,'request',side_effect=request):
   users=[server.mutate('/api/users',dict(service_id=s['id'],name=name)) for name in ('First','Second')]
   with self.assertRaisesRegex(ValueError,'core failure'):server.mutate('/api/services/'+s['id']+'/edit',dict(vk_hash='new_hash'))
  self.assertEqual(server.get(s['id'],'service')['vk_hash'],'abc')
  for u in users:
   self.assertEqual(server.get(u['id'],'user')['vk_hash'],'abc')
   self.assertEqual(database['passwords'][u['password']]['vk_hash'],'abc')
 def test_new_service_requires_call(self):
  with self.assertRaisesRegex(ValueError,'VK-ссылку'):server.mutate('/api/services',dict(protocol='wdtt',host='vpn.example.com',port=56000,name='TURN'))


class WDTTOfflineTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.previous=server.DATA;server.DATA=Path(self.tmp.name);server.init()
 def tearDown(self):server.DATA=self.previous;self.tmp.cleanup()
 def service(self):return server.mutate('/api/services',dict(protocol='wdtt',host='vpn.example.com',name='Offline TURN',port=28560,vk_hash='test_hash'))
 def fields(self,name='Phone'):return dict(label=name,vk_hash='test_hash',days=30,max_devices=1,ports='28560,56001,9000')
 def test_offline_create_edit_revoke_delete_preserves_other_data(self):
  database=dict(passwords={},devices={},extension=dict(preserve=True))
  first=wdtt.offline_change(database,data=self.fields())
  password=first['password'];entry=database['passwords'][password]
  entry.update(device_ids=['device1'],down_bytes=12345,up_bytes=5678)
  database['devices']['device1']=dict(owner_id=password,private_key='keep-until-delete')
  second=wdtt.offline_change(database,data=self.fields('Other'))
  database['devices']['other']=dict(owner_id=second['password'],private_key='preserve')
  edited=wdtt.offline_change(database,'/update',dict(password=password,label='Renamed',vk_hash='new_hash',max_devices=3))
  self.assertEqual(edited['expires_at'],first['expires_at']);self.assertEqual(edited['down_bytes'],12345)
  self.assertEqual(edited['device_ids'],['device1']);self.assertEqual(edited['max_devices'],3)
  wdtt.offline_change(database,'/deactivate',dict(password=password))
  self.assertTrue(database['passwords'][password]['is_deactivated'])
  wdtt.offline_change(database,'/activate',dict(password=password))
  self.assertFalse(database['passwords'][password]['is_deactivated'])
  wdtt.offline_change(database,'/delete',dict(password=password))
  self.assertNotIn(password,database['passwords']);self.assertNotIn('device1',database['devices'])
  self.assertIn('other',database['devices']);self.assertEqual(database['extension'],dict(preserve=True))
 def test_expired_entries_are_replaced_and_deactivated_entries_keep_slots(self):
  database=dict(passwords={},devices={})
  for index in range(10):
   item=wdtt.offline_change(database,data=self.fields(str(index)))
   wdtt.offline_change(database,'/deactivate',dict(password=item['password']))
  with self.assertRaisesRegex(ValueError,'10/10'):wdtt.offline_change(database,data=self.fields('Overflow'))
  expired=next(iter(database['passwords']));database['passwords'][expired]['expires_at']=int(time.time())-10
  view=wdtt.offline_change(database)
  self.assertEqual(len(view['passwords']),9)
  created=wdtt.offline_change(database,data=self.fields('Replacement'))
  self.assertEqual(len(database['passwords']),10);self.assertNotIn(expired,database['passwords'])
  self.assertFalse(created['is_deactivated'])
 def test_offline_server_adapter_writes_private_atomic_database_and_backup(self):
  s=self.service();target=server.DATA/s['id']/'runtime'/'passwords.json'
  with patch.object(wdtt,'request',side_effect=wdtt.CoreUnavailable('offline')),patch.object(server,'running',return_value=False):
   created=server.turn_request(s,data=self.fields())
   self.assertEqual(target.stat().st_mode&0o777,0o600)
   server.turn_request(s,'/update',dict(password=created['password'],label='Changed'))
  database=json.loads(target.read_text());previous=json.loads(target.with_suffix('.previous').read_text())
  self.assertEqual(database['passwords'][created['password']]['label'],'Changed')
  self.assertEqual(previous['passwords'][created['password']]['label'],'Phone')
  self.assertEqual(target.with_suffix('.previous').stat().st_mode&0o777,0o600)
  self.assertFalse(target.with_name('passwords.panel.tmp').exists())
 def test_live_or_restarting_core_never_falls_back_to_database_write(self):
  s=self.service();target=server.DATA/s['id']/'runtime'/'passwords.json'
  with patch.object(wdtt,'request',side_effect=wdtt.CoreUnavailable('offline')),patch.object(server,'compose',return_value=json.dumps([dict(State='restarting')])) as compose:
   with self.assertRaisesRegex(ValueError,'API'):server.turn_request(s,data=self.fields())
   self.assertIn('--all',compose.call_args.args[1])
  self.assertFalse(target.exists())
 def test_unverifiable_container_state_never_changes_database(self):
  s=self.service();target=server.DATA/s['id']/'runtime'/'passwords.json'
  with patch.object(wdtt,'request',side_effect=wdtt.CoreUnavailable('offline')),patch.object(server,'compose',side_effect=ValueError('docker unavailable')):
   with self.assertRaisesRegex(ValueError,'состояние'):server.turn_request(s,data=self.fields())
  self.assertFalse(target.exists())
 def test_capacity_uses_offline_core_database_including_external_passwords(self):
  s=self.service();target=server.DATA/s['id']/'runtime'/'passwords.json';database=dict(passwords={},devices={})
  for index in range(10):
   view=wdtt.offline_change(database,data=self.fields(str(index)))
   wdtt.offline_change(database,'/deactivate',dict(password=view['password']))
  target.write_text(json.dumps(database))
  with patch.dict(os.environ,{'YPTUN_ALLOW_DOCKER':'1'}),patch.object(wdtt,'request',side_effect=wdtt.CoreUnavailable('offline')),patch.object(server,'running',return_value=False):
   capacity=server.turn_capacity(s)
   self.assertEqual(capacity['used'],10);self.assertEqual(capacity['free'],0);self.assertFalse(capacity['unavailable'])
   with self.assertRaisesRegex(ValueError,'Лимит TURN'):server.require_turn_slot(s)
  self.assertEqual(server.members(s['id']),[])
 def test_limit_is_enforced_before_core_create_for_two_concurrent_grants(self):
  s=self.service();s['desired']='running';server.put('service',s)
  database=dict(passwords={},devices={})
  for index in range(9):wdtt.offline_change(database,data=self.fields(str(index)))
  creates=[]
  def request(service,path='',data=None):
   if data is not None and not path:creates.append(data['label'])
   return wdtt.offline_change(database,path,data)
  barrier=threading.Barrier(2);results=[]
  def grant(name):
   barrier.wait()
   try:
    with server.LOCK:result=server.mutate('/api/users',dict(name=name,service_id=s['id'],vk_hash='hash_test'))
    results.append(result)
   except ValueError as error:results.append(error)
  with patch.object(wdtt,'request',side_effect=request):
   threads=[threading.Thread(target=grant,args=(name,)) for name in ('One','Two')]
   for thread in threads:thread.start()
   for thread in threads:thread.join(timeout=10);self.assertFalse(thread.is_alive())
  self.assertEqual(len(creates),1);self.assertEqual(len(server.rows('user')),1)
  self.assertEqual(sum(isinstance(result,ValueError) for result in results),1)
  self.assertEqual(len(database['passwords']),10)

if __name__=='__main__':unittest.main()
