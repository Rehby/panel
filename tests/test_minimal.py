import base64,json,socket,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import defaults,minimal,provision
from image_presets import validate_custom,custom_bundle
class MinimalTest(unittest.TestCase):
 def test_defaults_cover_all_engines(self):
  from catalog import PROTOCOLS
  for p in PROTOCOLS:
   with self.subTest(protocol=p['id']):
    s=defaults.setup(p['id'],'vpn.example.com',{8443,56000});self.assertTrue(s['name']);self.assertEqual(s['host'],'vpn.example.com');self.assertNotIn(s['port'],{8443,56000,22,80,443,8080,9443})
    if p['mode']=='custom':self.assertTrue(s['image']);self.assertIsInstance(s['command'],list)
 def test_bound_port_is_not_selected(self):
  with socket.socket() as sock:
   sock.bind(('0.0.0.0',8443));self.assertNotEqual(defaults.free_port('vless',set()),8443)
 def test_free_turn_generates_backend_without_manual_config(self):
  s=minimal.apply(dict(protocol='vkturn',simple_engine=True,host='vpn.example.com',port=29400))
  self.assertTrue(s['provisioned']);self.assertEqual(len(s['engine_key']),64)
  old_key=s['engine_key'];old_private=s['server_private'];s=minimal.apply(s)
  self.assertEqual(s['engine_key'],old_key);self.assertEqual(s['server_private'],old_private)
  files=provision.bundle(s,[]);compose=json.loads(files['compose.json'])
  self.assertEqual(compose['services']['tunnel']['environment']['CONNECT_ADDR'],'backend:51820')
  self.assertIn('backend',compose['services']);self.assertIn('runtime/wg_confs/wg0.conf',files)
 def test_openflux_generates_server_command_and_secret(self):
  s=minimal.apply(dict(protocol='openflux',simple_engine=True,host='vpn.example.com',port=29401,room_url='https://docs.example.com/room'))
  files=provision.bundle(s,[]);svc=json.loads(files['compose.json'])['services']['tunnel']
  self.assertIn('--url=https://docs.example.com/room',svc['command']);self.assertIn('--encryption-key-file=/etc/yptun/key',svc['command'])
  self.assertEqual(files['runtime/key'],s['engine_key']);self.assertGreaterEqual(len(s['engine_key']),32)
  with self.assertRaises(ValueError):minimal.apply(dict(protocol='openflux',simple_engine=True,room_url='javascript:x'))
 def test_imported_internal_port_maps_to_free_external_port(self):
  s=validate_custom(dict(protocol='wireguard',image_id='wireguard',port=51821,container_port=51820,raw_config='[Interface]'))
  _,svc=custom_bundle(s);self.assertIn('51821:51820/udp',svc['ports'])
 def test_warp_no_inputs(self):self.assertEqual(minimal.apply(dict(protocol='warp',simple_engine=True))['raw_config'],'{}')
 def test_binary_modules_are_not_encoded_as_text(self):
  data=b'\x7fELF\x00\xff';s=validate_custom(dict(protocol='snolc',image_id='snolc',raw_config=json.dumps({'config.conf':'abc','module.so':dict(base64=base64.b64encode(data).decode())})))
  files,_=custom_bundle(s);self.assertEqual(files['runtime/module.so'],data)
  with self.assertRaises(ValueError):validate_custom(dict(protocol='snolc',image_id='snolc',raw_config=json.dumps({'x.so':dict(base64='?bad')})))
if __name__=='__main__':unittest.main()
