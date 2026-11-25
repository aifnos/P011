import http.client
import json
import pathlib
import sys
import tempfile
import threading
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'runtime'))
from mta_service import State,Server


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.state=State(self.temp.name,self.temp.name+'/no-bluez',self.temp.name+'/no-network')
        self.server=Server(self.state,bootstrap=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.server.server_close();self.thread.join(3);self.state.close();self.temp.cleanup()
    def request(self,path,method='GET',value=None,headers=None):
        conn=http.client.HTTPConnection(*self.server.server_address,timeout=3)
        hdr={'X-P011-MTA-Token':self.state.token}
        if headers:hdr.update(headers)
        body=json.dumps(value).encode() if value is not None else None
        if body:hdr['Content-Type']='application/json'
        conn.request(method,path,body,hdr);result=conn.getresponse();data=result.read();code=result.status;conn.close()
        return code,json.loads(data)
    def test_status_default_no_radio(self):
        code,value=self.request('/v1/status');self.assertEqual(code,200)
        self.assertFalse(value['discoverable']);self.assertFalse(value['scanning'])
        self.assertFalse(value['capabilities']['send']['available']);self.assertIsNone(self.state.helper)
    def test_unauthorized(self):
        for headers in [{'X-P011-MTA-Token':'bad'},{'Host':'other.invalid'},{'Origin':'http://other.invalid'}]:
            self.assertEqual(self.request('/v1/status',headers=headers)[0],403)
    def test_bootstrap_once(self):
        self.assertEqual(self.request('/v1/bootstrap',headers={'X-P011-MTA-Token':''})[0],200)
        self.assertEqual(self.request('/v1/bootstrap',headers={'X-P011-MTA-Token':''})[0],403)
    def test_no_shell_and_missing_capability(self):
        for value in [{'action':'shell','cmd':'id'},{'action':'discover_start'},{'action':'scan'},
                      {'action':'send','deviceId':'x','fileIds':['../etc/passwd']}, {'action':'rename','nickname':'x','extra':1}]:
            self.assertEqual(self.request('/v1/action','POST',value)[0],409)
        self.assertIsNone(self.state.helper)
    def test_rename_and_files(self):
        self.assertEqual(self.request('/v1/action','POST',{'action':'rename','nickname':'学习笔'})[0],200)
        self.assertEqual(self.state.nickname,'学习笔')
        self.assertEqual(self.request('/v1/files')[1],{'files':[]})
    def test_request_ids(self):
        self.state.request={'id':'new','name':'HOST','fileCount':1,'totalBytes':3}
        self.assertEqual(self.request('/v1/action','POST',{'action':'accept','requestId':'old'})[0],409)
        self.assertFalse(self.state.decision.is_set())
        self.assertEqual(self.request('/v1/action','POST',{'action':'reject','requestId':'new'})[0],200)
        self.assertTrue(self.state.decision.is_set());self.assertFalse(self.state.accepted)

if __name__=='__main__':unittest.main()
