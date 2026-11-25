import ast
import hashlib
import http.client
import io
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.parse

BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'runtime'))
from storage import FileStore,components,MAX_FILE
from metrics import parse_cpu,cpu_percent,parse_memory,parse_network,Sampler
from server import State,BoundedServer,local_addresses
from audio import parse_gst_play_frame


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=FileStore(self.temp.name)
    def tearDown(self):self.store.close();self.temp.cleanup()
    def test_roundtrip_unicode(self):
        data='你好，学习笔'.encode();self.store.write_new('Text/中文.txt',io.BytesIO(data),len(data))
        self.assertEqual(self.store.text('Text/中文.txt')['text'],'你好，学习笔')
        self.assertEqual(self.store.listing('Text')['entries'][0]['name'],'中文.txt')
    def test_no_clobber(self):
        self.store.write_new('Text/a.txt',io.BytesIO(b'a'),1)
        with self.assertRaises(FileExistsError):self.store.write_new('Text/a.txt',io.BytesIO(b'b'),1)
        self.assertEqual(self.store.text('Text/a.txt')['text'],'a')
    def test_aborted_upload_not_published(self):
        with self.assertRaises(ValueError):self.store.write_new('Text/a.txt',io.BytesIO(b'a'),2)
        self.assertEqual(os.listdir(os.path.join(self.temp.name,'Text')),[])
    def test_paths(self):
        for path in ('../etc/passwd','/etc/passwd','Text/../a.txt','Text//a.txt','Text/.a','Text/a\\b','Text/c:a','Text/a\x00b','Unknown/a.txt'):
            with self.subTest(path=path),self.assertRaises(ValueError):components(path)
    def test_disallowed_extensions_and_size(self):
        for name in ('a.py','a.qml','a.js','a.html','a.exe','a.sh','a.ttf'):
            with self.assertRaises(ValueError):self.store.write_new('Text/'+name,io.BytesIO(b'x'),1)
        with self.assertRaises(ValueError):self.store.write_new('Text/a.txt',io.BytesIO(b'x'),MAX_FILE+1)
    def test_pagination(self):
        for n in range(105):(pathlib.Path(self.temp.name)/'Text'/('%03d.txt'%n)).write_text('x')
        first=self.store.listing('Text');second=self.store.listing('Text',100)
        self.assertEqual(len(first['entries']),100);self.assertEqual(first['next'],100)
        self.assertEqual(len(second['entries']),5);self.assertIsNone(second['next'])
    def test_text_limit(self):
        (pathlib.Path(self.temp.name)/'Text/a.txt').write_bytes(b'x'*70000)
        result=self.store.text('Text/a.txt');self.assertTrue(result['truncated']);self.assertEqual(len(result['text']),65536)
    def test_symlink_escape(self):
        if os.name=='nt':self.skipTest('Linux O_NOFOLLOW test is run separately in WSL')
        with tempfile.TemporaryDirectory() as outside:
            pathlib.Path(outside,'secret.txt').write_text('not exposed')
            os.symlink(outside,os.path.join(self.temp.name,'Text','linked'))
            os.symlink(os.path.join(outside,'secret.txt'),os.path.join(self.temp.name,'Text','file.txt'))
            self.assertEqual(self.store.listing('Text')['entries'],[])
            for p in ('Text/linked/secret.txt','Text/file.txt'):
                with self.assertRaises((OSError,ValueError)):self.store.open_file(p)
            with self.assertRaises((OSError,ValueError)):self.store.write_new('Text/linked/new.txt',io.BytesIO(b'x'),1)
            self.assertFalse(pathlib.Path(outside,'new.txt').exists())


class MetricsTests(unittest.TestCase):
    def test_cpu_guest_not_double_counted(self):
        self.assertEqual(parse_cpu('cpu 10 0 20 50 5 0 5 10 30 5\n'),(100,55))
        self.assertEqual(cpu_percent((100,50),(200,100)),50)
        self.assertIsNone(cpu_percent((200,100),(100,50)))
    def test_memory_available(self):
        result=parse_memory('MemTotal: 1000 kB\nMemFree: 10 kB\nMemAvailable: 400 kB\n')
        self.assertEqual(result['used'],600*1024)
        self.assertIsNone(parse_memory('MemTotal: 1000 kB\n')['used'])
    def test_network_parse(self):
        self.assertEqual(parse_network('a\nb\n wlan0: 1024 1 0 0 0 0 0 0 2048 1 0 0 0 0 0 0')['wlan0'],(1024,2048))
    def test_gst_real_position(self):
        self.assertIsNone(parse_gst_play_frame('Prerolling...'))
        self.assertEqual(parse_gst_play_frame(b'0:00:02.250 / 0:00:08.100'),{'position_ms':2250,'duration_ms':8100})
    def test_python35_syntax(self):
        for path in (BASE/'runtime').glob('*.py'):ast.parse(path.read_text(encoding='utf-8'),feature_version=(3,5))


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.state=State(self.temp.name,True)
        self.server=BoundedServer(('127.0.0.1',0),self.state)
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.daemon=True;self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.state.close();self.temp.cleanup()
    def request(self,path,method='GET',body=None,headers=None,server=None):
        server=server or self.server
        h={'X-P011-Token':self.state.token} if not server.lan else {'X-P011-Code':self.state.lan_code}
        if headers:h.update(headers)
        conn=http.client.HTTPConnection(*server.server_address,timeout=5)
        conn.request(method,path,body,h);response=conn.getresponse();data=response.read();conn.close()
        return response.status,data
    def test_loopback_auth_and_origin(self):
        self.assertEqual(self.request('/api/state',headers={'X-P011-Token':'wrong'})[0],403)
        self.assertEqual(self.request('/api/state',headers={'Origin':'http://evil.test'})[0],403)
        self.assertEqual(self.request('/api/state',headers={'Host':'evil.test'})[0],403)
        self.assertEqual(self.request('/api/state')[0],200)
    def test_native_bootstrap_is_one_shot_local_only(self):
        route='/api/native/bootstrap';header={'X-P011-Native-UI':'qml-runtime','X-P011-Token':''}
        self.assertEqual(self.request(route,headers=header)[0],403)
        self.state.arm_native_bootstrap()
        self.assertEqual(self.request(route)[0],403)
        self.assertEqual(self.request(route,headers=dict(header,Origin='http://evil.test'))[0],403)
        status,body=self.request(route,headers=header)
        self.assertEqual(status,200)
        self.assertTrue(json.loads(body)['data']['token']==self.state.token,'Bootstrap did not return matching in-memory identity')
        self.assertEqual(self.request(route,headers=header)[0],403)
        self.state.start_lan('127.0.0.1')
        self.assertEqual(self.request(route,server=self.state.lan)[0],404)
    def test_ui_events_are_fixed_and_pathless(self):
        self.assertEqual(self.request('/api/ui/event','POST',b'event=page_Files')[0],200)
        self.assertEqual(self.request('/api/ui/event','POST',b'event=arbitrary-user-data')[0],400)
    def test_lan_default_off_and_narrow_bind(self):
        self.assertIsNone(self.state.lan)
        for address in ('0.0.0.0','8.8.8.8','192.168.8.100'):
            with self.assertRaises(ValueError):self.state.start_lan(address)
    def test_transfer_roundtrip_and_scope(self):
        self.state.start_lan('127.0.0.1');server=self.state.lan
        self.assertEqual(self.request('/',server=server,headers={'X-P011-Code':''})[0],200)
        self.assertEqual(self.request('/api/files',server=server,headers={'X-P011-Code':''})[0],403)
        content=b'my test audio bytes'
        self.assertEqual(self.request('/api/upload?path=Music%2Ftest.mp3','POST',content,server=server)[0],200)
        self.assertEqual(self.request('/api/download?path=Music%2Ftest.mp3',server=server)[1],content)
        self.assertEqual(self.request('/api/upload?path=Music%2Ftest.mp3','POST',b'x',server=server)[0],409)
        for path in ('/api/state','/api/processes','/api/audio','/api/open?path=Music/test.mp3'):
            self.assertEqual(self.request(path,server=server)[0],404)
        self.assertEqual(self.request('/api/transfer/start','POST',b'address=0.0.0.0',server=server)[0],404)
    def test_early_rejection_consumes_small_split_form(self):
        for attempt in range(12):
            with socket.create_connection(self.server.server_address,timeout=5) as conn:
                head=('POST /api/unknown HTTP/1.1\r\nHost: '+self.server.expected_host+
                      '\r\nX-P011-Token: '+self.state.token+'\r\nContent-Length: 3\r\n\r\n')
                conn.sendall(head.encode('ascii'));time.sleep(.008);conn.sendall(b'a=1')
                response=http.client.HTTPResponse(conn);response.begin()
                self.assertEqual(response.status,404);response.read();response.close()
    def test_encoded_traversal(self):
        for value in ('../etc/passwd','Text/../x.txt','/etc/passwd','Text/%2e%2e/x.txt'):
            self.assertNotEqual(self.request('/api/download?path='+urllib.parse.quote(value,safe=''))[0],200)
    def test_transfer_expiry_and_rekey(self):
        self.state.start_lan('127.0.0.1');old=self.state.lan_code;server=self.state.lan
        self.state.lan_deadline=time.monotonic()-1
        self.assertEqual(self.request('/api/files',server=server)[0],403)
        self.state.start_lan('127.0.0.1');self.assertNotEqual(old,self.state.lan_code)
    def test_wrong_code_throttle(self):
        self.state.start_lan('127.0.0.1');server=self.state.lan
        for _ in range(8):self.assertEqual(self.request('/api/files',server=server,headers={'X-P011-Code':'bad'})[0],403)
        self.assertEqual(self.request('/api/files',server=server)[0],403)
    def test_scores_persist_and_monotonic(self):
        for score in (100,10):self.assertEqual(self.request('/api/scores','POST',('game=snake&score='+str(score)).encode())[0],200)
        self.assertEqual(self.state.scores['snake'],100)
        self.assertEqual(pathlib.Path(self.state.score_path).read_text(),'snake=100')
    def test_export_and_no_shell(self):
        status,raw=self.request('/api/export','POST',b'what=samples');self.assertEqual(status,200)
        path=json.loads(raw)['data']['path'];self.assertTrue(path.startswith('Exports/'))
        self.assertEqual(self.request('/api/exec','POST',b'cmd=whoami')[0],404)
    def test_failed_score_write_can_be_retried(self):
        with mock.patch('server.os.replace',side_effect=OSError('simulated disk failure')):
            with self.assertRaises(OSError):self.state.save_score('snake',200)
        self.assertNotIn('snake',self.state.scores)
        self.assertFalse(list(pathlib.Path(self.state.state_dir).glob('scores.txt.tmp-*')))
        self.state.save_score('snake',200)
        self.assertEqual(pathlib.Path(self.state.score_path).read_text(),'snake=200')
    def test_stale_audio_command_cannot_restart(self):
        self.assertEqual(self.request('/api/audio/stop','POST',b'command=10')[0],200)
        self.assertEqual(self.request('/api/audio/play','POST',b'command=9&path=Music/x.mp3')[0],400)
    def raw(self,raw):
        conn=socket.create_connection(self.server.server_address,timeout=5)
        data=b''
        try:
            conn.sendall(raw);conn.shutdown(socket.SHUT_WR)
            while True:
                try:block=conn.recv(8192)
                except ConnectionResetError:break  # Early bounded rejection may reset unread excess bytes.
                if not block:break
                data+=block
        finally:conn.close()
        return data
    def test_strict_http_framing(self):
        base=('Host: '+self.server.expected_host+'\r\nX-P011-Token: '+self.state.token+'\r\n').encode()
        for extra in (b'Content-Length: 1\r\nContent-Length: 1\r\n',b'Transfer-Encoding: chunked\r\n',
                      b'Content-Length: -1\r\n',b' folded: x\r\n',b'Invalid Header: x\r\n',
                      b'Content-Length: 67108865\r\n'):
            response=self.raw(b'POST /api/scores HTTP/1.1\r\n'+base+extra+b'\r\nx')
            self.assertTrue(response.startswith((b'HTTP/1.0 400',b'HTTP/1.0 413')))
        self.assertIn(b' 403 ',self.raw(b'GET /api/state HTTP/1.1\r\n'+base+b'Host: evil\r\n\r\n').split(b'\r\n')[0])
    def test_headers_bounded(self):
        self.assertIn(b' 431 ',self.raw(b'GET / HTTP/1.1\r\nX: '+b'x'*20000+b'\r\n\r\n').split(b'\r\n')[0])
    def test_shutdown_aborts_upload_and_removes_partial(self):
        self.state.start_lan('127.0.0.1');server=self.state.lan
        conn=socket.create_connection(server.server_address,timeout=5)
        head=('POST /api/upload?path=Text/partial.txt HTTP/1.1\r\nHost: '+server.expected_host+
              '\r\nX-P011-Code: '+self.state.lan_code+'\r\nContent-Length: 100000\r\n\r\n')
        conn.sendall(head.encode()+b'x'*100)
        time.sleep(.05);self.state.stop_lan();conn.close()
        self.assertEqual(os.listdir(os.path.join(self.temp.name,'Text')),[])
    def test_ip_interface_filter(self):
        output=b'1: lo    inet 127.0.0.1/8 scope host\n2: wlan0    inet 192.168.1.2/24 scope global\n3: seth0    inet 10.1.1.1/8 scope global\n4: eth0    inet 8.8.8.8/24 scope global\n'
        with mock.patch('server.os.path.isfile',return_value=True),mock.patch('server.subprocess.run') as run:
            run.return_value=type('Result',(),{'returncode':0,'stdout':output})()
            self.assertEqual(local_addresses(),[{'name':'wlan0','address':'192.168.1.2'}])
            self.assertNotIn('shell',run.call_args.kwargs)


if __name__=='__main__':unittest.main(verbosity=2)
