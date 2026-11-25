"""One new HOST composition/loopback/retained-media method.

Actual new QML, original confined FileStore/Toolbox HTTP, companion and audio
actor adapter execute. MTA endpoint and Owner guard are explicitly HOST models;
the original formal Owner/Gate/restore, P011 Qt/FD mode and phone do not run.
gst-play is replaced only at Popen with a real bounded HOST Python child.
"""
import ast
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import quote, urlsplit
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT/'candidate/receive-filecenter-v1'
sys.path.insert(0, str(ROOT/'integration/ToolboxMta-v0.1/runtime'))
sys.path.insert(0, str(PRODUCT/'runtime'))
import mta_toolbox_minhttp as http
import mta_filecenter_companion as C
import mta_filecenter_audio as A
import mta_toolbox_audio as ORIGINAL_AUDIO

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '0'
from PyQt5.QtCore import QObject, QUrl, QT_VERSION_STR
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQuick import QQuickView


class _MtaModelHandler(http.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append((self.command, self.path))
        if self.path == '/v1/status': value = {'status':dict(self.server.model)}
        elif self.path == '/v1/files': value = {'files':[{'id':'host-opaque', 'name':'Received/测试.txt', 'size':13}]}
        else: value = {}
        self.reply(value)
    def do_POST(self):
        self.server.calls.append((self.command, self.path))
        body = self.rfile.read(int(self.headers.get('Content-Length','0')))
        if self.path == '/v1/action' and json.loads(body).get('action') == 'cancel':
            self.server.cancelled = True
        self.reply({'ok':True})
    def reply(self, value):
        raw=json.dumps(value,ensure_ascii=True).encode('ascii')
        self.send_response(200);self.send_header('Content-Length',str(len(raw)))
        self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(raw)


class ReceiveFileCenterProductTests(unittest.TestCase):
    def test_new_actual_composition_and_retained_media(self):
        cases = []
        app = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
        with tempfile.TemporaryDirectory(prefix='p011-filecenter-product-host-') as temporary:
            folder=Path(temporary);user=folder/'user';user.mkdir()
            live={'value':True}
            companion=C._Companion(str(user), float(time.monotonic()+45), lambda:live['value'])
            server=http.HTTPServer(('127.0.0.1',0),_MtaModelHandler)
            server.calls=[];server.cancelled=False
            server.model={'state':'idle','discoverable':False,'scanning':False,'restorePending':False,
                'request':None,'devices':[],'received':[],'nickname':'HOST fixture',
                'capabilities':{},'networkRecovery':{'restorePending':False,'recoveryLocked':False}}
            mta_thread=threading.Thread(target=server.serve_forever);mta_thread.daemon=True;mta_thread.start()
            view=None;warnings=[]
            try:
                received=user/'Received'
                (received/'测试.txt').write_bytes('HOST 收件预览'.encode('utf-8'))
                image=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+j2ioAAAAASUVORK5CYII=')
                (received/'image.png').write_bytes(image)
                (received/'video.mp4').write_bytes(b'HOST-NOT-A-REAL-VIDEO')
                (received/'sound.mp3').write_bytes(b'HOST-NOT-A-REAL-AUDIO')
                (received/'unknown.exe').write_bytes(b'HOST unsupported')
                credentials=companion.credentials();base=credentials['endpoint']
                def request(path, form=None, token=True, extra=None):
                    headers={'X-P011-Token':credentials['token']} if token else {}
                    headers.update(extra or {})
                    payload=None if form is None else urllib.parse.urlencode(form).encode('ascii')
                    req=urllib.request.Request(base+path,data=payload,headers=headers)
                    try:
                        with urllib.request.urlopen(req,timeout=3) as response:
                            return response.status,response.read(),dict(response.headers)
                    except urllib.error.HTTPError as error:
                        return error.code,error.read(),dict(error.headers)
                for path,form in (('/api/transfer/start',{'address':'127.0.0.1'}),
                        ('/api/upload',{'path':'Received/x.txt'}),('/api/export',{'what':'logs'}),
                        ('/api/scores',{'game':'snake','score':'1'}),('/api/native/bootstrap',None),
                        ('/api/processes',None),('/api/download?path=Received/image.png',None)):
                    self.assertEqual(403,request(path,form)[0])
                self.assertIsNone(companion.state.lan);cases.append('fixed_route_allowlist_no_lan_bootstrap_write')
                self.assertEqual(403,request('/api/files',token=False)[0]);cases.append('token_required')
                code,raw,_=request('/api/files?path=Received&offset=0')
                self.assertEqual(200,code);listing=json.loads(raw)['data']
                self.assertIn('测试.txt',[row['name'] for row in listing['entries']]);cases.append('actual_same_root_listing')
                code,raw,_=request('/api/open?path='+quote('Received/测试.txt',safe=''))
                value=json.loads(raw)['data'];self.assertEqual(200,code)
                self.assertEqual('HOST 收件预览',value['text']);self.assertNotIn('url',value)
                cases.append('actual_utf8_text_bounded_original_store')
                for path in ('../outside.txt','Received/../outside.txt','Received/.hidden',
                             'Received/%2e%2e/outside','Pictures\\outside.png','Other/x.png'):
                    self.assertEqual(400,request('/api/open?path='+quote(path,safe=''))[0])
                self.assertEqual(400,request('/api/open?path=Received/unknown.exe')[0]);cases.append('invalid_paths_and_unknown_kind_rejected')
                code,raw,_=request('/api/open?path=Received/image.png');opened=json.loads(raw)['data']
                self.assertEqual(200,code);media=urlsplit(opened['url']);self.assertEqual('127.0.0.1',media.hostname)
                self.assertNotIn(credentials['token'],opened['url']);self.assertNotIn('Received',opened['url'])
                media_path=media.path+'?'+media.query
                code,raw,headers=request(media_path,token=False);self.assertEqual((200,image),(code,raw))
                self.assertEqual('image/png',headers['Content-Type']);cases.append('held_fd_media_cap_no_path_or_service_token')
                code,raw,headers=request(media_path,token=False,extra={'Range':'bytes=2-5'})
                self.assertEqual((206,image[2:6]),(code,raw));self.assertEqual('bytes 2-5/'+str(len(image)),headers['Content-Range'])
                code,raw,_=request(media_path,token=False,extra={'Range':'bytes=-4'});self.assertEqual((206,image[-4:]),(code,raw))
                self.assertEqual(400,request(media_path,token=False,extra={'Range':'bytes=1-3,5-6'})[0]);cases.append('bounded_single_ranges')
                self.assertEqual(400,request('/api/media?cap='+'0'*64,token=False)[0]);cases.append('unguessable_cap_required')
                # A pathname replaced after opening cannot redirect the held handle.
                held=received/'image.png'
                try: held.rename(received/'old-image.png')
                except PermissionError as error:
                    self.assertEqual('nt',os.name);self.assertEqual(32,error.winerror)
                    # Windows denies rename while held. Linux replacement is
                    # a SOURCE property here, not target runtime acceptance.
                else: held.write_bytes(b'REPLACED')
                self.assertEqual(image,request(media_path,token=False)[1]);cases.append('held_media_fd_not_path_chase_platform_specific')
                audio=companion.open_file('Received/sound.mp3')
                fd=companion.audio_source_fd(str(received/'sound.mp3'));self.assertEqual(fd,companion.media[-1]['fd'])
                self.assertRaises(ValueError,companion.audio_source_fd,str(folder/'outside.mp3'))
                cases.append('audio_fd_original_only')
                original_popen=subprocess.Popen;argv=[]
                def launch(command,**kwargs):
                    argv.append(command)
                    return original_popen([sys.executable,'-I','-B','-c',
                        "import time; print('0:00:00.100 / 0:00:01.000', flush=True); time.sleep(.15); print('Reached end of play list.', flush=True)"],**kwargs)
                real_isfile=os.path.isfile
                # Windows select() cannot select pipe FDs. Only readiness is
                # modelled; os.read, parse/read_audio, child and streams are real.
                # Fixture child has two tiny frames and exits within .15 s.
                with mock.patch.object(A.os.path,'isfile',side_effect=lambda p:p=='/usr/bin/gst-play-1.0' or real_isfile(p)), \
                        mock.patch.object(A.subprocess,'Popen',side_effect=launch), \
                        mock.patch.object(ORIGINAL_AUDIO.select,'select',side_effect=lambda readers,*args:(list(readers),[],[])):
                    companion.audio.play(str(received/'sound.mp3'),25)
                    deadline=time.monotonic()+4
                    while time.monotonic()<deadline and not companion.audio.actors_closed():time.sleep(.02)
                self.assertTrue(companion.audio.actors_closed());self.assertEqual(1,len(argv))
                self.assertEqual('file:///proc/%d/fd/%d'%(os.getpid(),fd),argv[0][-1])
                self.assertFalse(any(value in argv[0] for value in ('sh','bash','cmd')))
                self.assertEqual(100,companion.audio.audio_snapshot()['position_ms'])
                companion.audio.stop_audio();self.assertIsNone(companion.audio.audio)
                self.assertIsNotNone(companion.audio.tickets[0]['process']);cases.append('retained_real_host_child_reader_raw_streams')

                # Load the actual new credential entry, composition, MTA page
                # and original-v68 derived file page, not an inert UI callee.
                staged=folder/'qml';shutil.copytree(PRODUCT/'device',staged)
                session='HOST_FILECENTER_MODEL'
                record={'session':session,'endpoint':'http://127.0.0.1:'+str(server.server_address[1]),
                    'token':'1'*64,'toolboxEndpoint':base,'toolboxToken':credentials['token']}
                (folder/'credentials.json').write_text(json.dumps(record),encoding='ascii')
                template=(staged/'FormalEntry.qml').read_text(encoding='utf-8')
                remote=QUrl.fromLocalFile(str(folder)).toString()[7:]
                (staged/'FormalEntry.qml').write_text(template.replace('@SESSION@',session).replace('@REMOTE@',remote),encoding='utf-8')
                view=QQuickView();view.engine().warnings.connect(lambda rows:warnings.extend(r.toString() for r in rows))
                view.rootContext().setContextProperty('nativeFontFamily','sans-serif')
                view.setSource(QUrl.fromLocalFile(str(staged/'FormalEntry.qml')))
                self.assertNotEqual(QQuickView.Error,view.status(),[e.toString() for e in view.errors()])
                view.resize(800,268);view.show();entry=view.rootObject()
                def wait_for(predicate,seconds=5):
                    until=time.monotonic()+seconds
                    while time.monotonic()<until:
                        app.processEvents()
                        if predicate():return True
                        time.sleep(.01)
                    return False
                self.assertTrue(wait_for(lambda:entry.property('readyLogged') is True),warnings)
                surface=entry.findChild(QObject,'receiveFileCenterComposition');self.assertIsNotNone(surface)
                self.assertEqual((800,268),(surface.property('width'),surface.property('height')))
                self.assertFalse(surface.property('bootstrapAllowed'));self.assertFalse(surface.property('mtaBootstrapAllowed'))
                self.assertTrue(surface.property('compositionLoaded'));cases.append('actual_credential_entry_waits_complete_composition')
                engine=view.engine();engine.globalObject().setProperty('product',engine.newQObject(surface))
                def evaluate(script):
                    result=engine.evaluate(script);self.assertFalse(result.isError(),result.toString());app.processEvents();return result
                embedded=entry.findChild(QObject,'mtaEmbedded');self.assertIsNotNone(embedded)
                engine.globalObject().setProperty('embedded',engine.newQObject(embedded))
                self.assertTrue(wait_for(lambda:embedded.property('knownStatus') is True))
                server.model.update(state='transferring',restorePending=True)
                evaluate('embedded.refresh()')
                self.assertTrue(wait_for(lambda:embedded.property('networkBusy') is True))
                evaluate('product.openReceivedDirectory()')
                self.assertTrue(wait_for(lambda:server.cancelled))
                self.assertEqual('Mta',surface.property('pageName'));cases.append('cancel_ack_not_restore_receipt')
                server.model.update(state='completed',restorePending=False)
                self.assertTrue(wait_for(lambda:surface.property('pageName')=='Files'))
                files=entry.findChild(QObject,'filesPage');self.assertIsNotNone(files)
                self.assertTrue(wait_for(lambda:files.property('loading') is False))
                self.assertEqual('Received',files.property('directory'));cases.append('observed_model_quiescence_opens_received_directory')
                engine.globalObject().setProperty('files',engine.newQObject(files))
                evaluate('files.openWhenReady("Received/测试.txt")')
                self.assertTrue(wait_for(lambda:engine.evaluate('files.selected.kind').toString()=='text'))
                self.assertEqual('HOST 收件预览',engine.evaluate('files.selected.text').toString())
                self.assertEqual('Received/测试.txt',engine.evaluate('files.selected.path').toString())
                self.assertNotIn('/api/transfer/start',[path for command,path in server.calls])
                cases.append('actual_qml_filecenter_text_from_actual_companion')
                self.assertTrue(evaluate('files.handleBack()').toBool())
                evaluate('files.openFile({kind:"file",path:"Received/unknown.exe"})')
                self.assertTrue(wait_for(lambda:files.property('loading') is False))
                self.assertEqual('',engine.evaluate('files.selected.kind||""').toString())
                self.assertTrue(surface.property('message'));cases.append('actual_qml_unknown_file_message')
                self.assertTrue(QT_VERSION_STR.startswith('5.'))
                source=(PRODUCT/'device/toolbox/FilesPage.qml').read_text(encoding='utf-8')
                self.assertNotIn('/api/transfer/start',source);self.assertNotIn('rotation:',source)
                self.assertNotIn('y:106',source);cases.append('small_screen_no_second_rotation_or_lan_controls')
                compatibility='Implicitly defined onFoo properties in Connections are deprecated.'
                self.assertTrue(all('QML Connections:' in warning and compatibility in warning for warning in warnings),warnings)
                print('HOST_QML_CONNECTIONS_COMPAT_WARNINGS='+str(len(warnings)))
                live['value']=False
                self.assertEqual(400,request('/api/files')[0]);cases.append('original_guard_change_fails_closed')
                self.assertRaises(ValueError,C.create,object(),None,lambda value:None);cases.append('public_factory_rejects_nonowner')
            finally:
                if view is not None:
                    view.setSource(QUrl());view.close();app.processEvents();view.deleteLater();app.processEvents()
                server.shutdown();server.server_close();mta_thread.join(3)
                self.assertFalse(mta_thread.is_alive())
                self.assertTrue(companion.close(),companion.public())
                self.assertTrue(companion.closed());self.assertTrue(companion.close())
                self.assertEqual(-1,companion.socket_original.fileno())
                self.assertFalse(companion.thread.is_alive());self.assertIsNone(companion.state.worker)
                self.assertTrue(companion.server.actors_closed());self.assertGreater(len(companion.server.actor_rows),0)
                self.assertTrue(all(row['closed'] for row in companion.media))
                with socket.socket() as probe:
                    probe.settimeout(.2);self.assertNotEqual(0,probe.connect_ex(companion.address))
                cases.append('actual_retained_listener_http_threads_media_child_closure')
            self.assertEqual(20,len(cases));self.assertEqual(len(cases),len(set(cases)))
            print('RECEIVE_FILECENTER_PRODUCT_CONTRACTS=20')


if __name__=='__main__':unittest.main(verbosity=0)
