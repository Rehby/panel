import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
import server

class MieruTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.old=server.DATA;server.DATA=Path(self.tmp.name);server.init()
    def tearDown(self):server.DATA=self.old;self.tmp.cleanup()
    def test_validate_rejects_tls_and_oversized_range(self):
        base=dict(protocol='mieru',name='M',host='vpn.example.com',port=20000,transport='tcp',security='none')
        with self.assertRaisesRegex(ValueError,'TLS'):
            engine.validate(dict(base,security='tls'))
        with self.assertRaisesRegex(ValueError,'диапазон'):
            engine.validate(dict(base,port_end=20200))
        with self.assertRaisesRegex(ValueError,'MTU'):
            engine.validate(dict(base,mtu=100))
    def test_bundle_and_profile_through_full_flow(self):
        s=server.mutate('/api/services',dict(name='Mieru',host='vpn.example.com',port=30000,port_end=30004,protocol='mieru',security='none',transport='tcp'))
        u=server.mutate('/api/users',dict(name='User',service_id=s['id']))
        files=engine.bundle(s,[u])
        state=json.loads(files['mita-state.json']);compose=json.loads(files['compose.json'])
        self.assertEqual(len(state['portBindings']),5)
        self.assertEqual(state['users'],[dict(name=u['id'],password=u['password'])])
        self.assertEqual(compose['services']['tunnel']['cap_drop'],['ALL'])
        self.assertIn('./runtime:/etc/mita',compose['services']['tunnel']['volumes'])
        self.assertEqual(len(compose['services']['tunnel']['ports']),5)
        link=engine.profile(s,u)
        self.assertTrue(link.startswith('mierus://'))
        self.assertIn(u['id']+':'+u['password'],link)
        server.mutate('/api/users/'+u['id']+'/toggle',{})
        disabled_state=json.loads(engine.bundle(s,server.members(s['id']))['mita-state.json'])
        self.assertNotIn(u['id'],[x['name'] for x in disabled_state['users']])

if __name__=='__main__':unittest.main()
