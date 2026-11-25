"""Host-only bridge contract/authentication checks, no device access."""
import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'runtime'))
from tools_bridge import Bridge
from tools_bluetooth import BluetoothDiscovery

class Input:
    def __init__(self,data):self.data=data
    def settimeout(self,value):pass
    def recv(self,size):result=self.data[:size];self.data=self.data[size:];return result

class Contract(unittest.TestCase):
    def setUp(self):
        self.bridge=Bridge.__new__(Bridge)
        self.bridge.token='fixturetoken'
        self.bridge.host='127.0.0.1:12345'
        self.bridge.bluetooth=BluetoothDiscovery(lambda event:None,_autostart=False)
    def tearDown(self):self.bridge.bluetooth.close()
    def request(self,path='/api/bt',token='fixturetoken',origin='null',host='127.0.0.1:12345'):
        return Input(('GET '+path+' HTTP/1.1\r\nHost: '+host+'\r\nX-P011-Token: '+token+'\r\nOrigin: '+origin+'\r\n\r\n').encode('ascii'))
    def test_authenticated_snapshot_path(self):
        self.assertEqual(self.bridge.parse(self.request()),('GET','/api/bt',''))
    def test_unauthenticated_or_foreign_origin_rejected(self):
        for request in (self.request(token='bad'),self.request(origin='https://example.com'),self.request(host='example.com')):
            with self.assertRaises(PermissionError):self.bridge.parse(request)
    def test_no_arbitrary_bluetooth_method_or_path(self):
        for path in ('/api/bt/Pair','/api/bt?scan=1','/api/bt/start'):
            with self.assertRaises(ValueError):self.bridge.parse(self.request(path=path))
        for action in ('bt_pair:stock:r1','bt_start:other:r1','bt_start:stock:r/1','bt_start:stock:r1:extra'):
            with self.assertRaises(ValueError):self.bridge.action(action)
    def test_start_stop_identity_passed_to_service(self):
        sample=self.bridge.action('bt_start:stock:r123')
        self.assertEqual((sample['owner'],sample['request_id'],sample['status']),('stock','r123','starting'))
        old=self.bridge.action('bt_stop:toolbox:old')
        self.assertTrue(old['active'])
        sample=self.bridge.action('bt_stop:stock:r123')
        self.assertEqual(sample['status'],'stopped')
    def test_delayed_start_cancelled(self):
        self.bridge.action('bt_stop:toolbox:r99')
        self.assertFalse(self.bridge.action('bt_start:toolbox:r99')['active'])

if __name__=='__main__':unittest.main(verbosity=2)
