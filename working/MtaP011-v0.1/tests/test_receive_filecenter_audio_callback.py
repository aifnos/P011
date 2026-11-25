"""One new actual HOST-QML callback ticket test, delayed request model only."""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
os.environ['QT_QPA_PLATFORM']='offscreen'
os.environ['QT_QUICK_BACKEND']='software'
from PyQt5.QtCore import QUrl
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQuick import QQuickView
ROOT=Path(__file__).resolve().parents[1]
HARNESS='''import QtQuick 2.10
Item {
 id:app;objectName:"audioCallbackHost";width:800;height:268
 property var telemetry:({transfer:{},addresses:[]})
 property bool mtaAvailable:false
 property var requests:[]
 property var messages:[]
 property alias files:page
 function request(path,form,done){requests.push({path:path,form:form,done:done});}
 function reply(index,ok,value){requests[index].done(ok,value);}
 function toast(value){messages.push(value);}
 FilesPage {id:page;anchors.fill:parent;app:app}
}
'''

class AudioCallbackTests(unittest.TestCase):
 def test_new_callback_tickets(self):
  app=QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
  with tempfile.TemporaryDirectory(prefix='p011-audio-callback-host-') as temporary:
   directory=Path(temporary)
   for name in ('FilesPage.qml','Theme.js','Button.qml','Label.qml','VideoPane.qml'):
    shutil.copyfile(ROOT/'candidate/receive-filecenter-v1/device/toolbox'/name,directory/name)
   (directory/'Harness.qml').write_text(HARNESS,encoding='utf-8')
   view=QQuickView();warnings=[]
   view.engine().warnings.connect(lambda rows:warnings.extend(row.toString() for row in rows))
   view.rootContext().setContextProperty('nativeFontFamily','sans-serif')
   view.setSource(QUrl.fromLocalFile(str(directory/'Harness.qml')))
   self.assertNotEqual(QQuickView.Error,view.status(),[error.toString() for error in view.errors()])
   engine=view.engine();engine.globalObject().setProperty('callbackHost',engine.newQObject(view.rootObject()))
   def evaluate(text):
    result=engine.evaluate(text);self.assertFalse(result.isError(),result.toString());app.processEvents();return result
   def snapshot():return json.loads(evaluate('JSON.stringify({loading:callbackHost.files.loading,generation:callbackHost.files.audioGeneration,path:callbackHost.files.selected.path||"",backend:callbackHost.files.backendAudio,requests:callbackHost.requests.length})').toString())
   try:
    evaluate('callbackHost.reply(0,true,{entries:[],next:null,limited:false})')
    evaluate('callbackHost.files.selected={kind:"audio",path:"Received/old.mp3"};callbackHost.files.playAudio()')
    old=snapshot()['requests']-1
    evaluate('callbackHost.files.stop();callbackHost.files.selected={}')
    # stop() owns the newer command and invalidates open generation.
    before=snapshot()
    evaluate('callbackHost.reply('+str(old)+',true,{generation:1,status:"playing",process_alive:true})')
    self.assertEqual(before,snapshot())
    evaluate('callbackHost.files.selected={kind:"audio",path:"Received/new.mp3"};callbackHost.files.playAudio()')
    current=snapshot()['requests']-1
    evaluate('callbackHost.reply('+str(old)+',false,{error:"HOST stale failure"})')
    self.assertTrue(snapshot()['loading']);self.assertEqual(-1,snapshot()['generation'])
    evaluate('callbackHost.reply('+str(current)+',true,{generation:2,status:"playing",process_alive:true})')
    self.assertEqual(2,snapshot()['generation']);self.assertFalse(snapshot()['loading']);self.assertTrue(snapshot()['backend'])
    evaluate('callbackHost.files.playAudio()');pending=snapshot()['requests']-1
    evaluate('callbackHost.files.handleBack()')
    before=snapshot();evaluate('callbackHost.reply('+str(pending)+',true,{generation:3,status:"playing",process_alive:true})')
    self.assertEqual(before,snapshot());self.assertEqual([],warnings)
    print('RECEIVE_FILECENTER_AUDIO_CALLBACK_CONTRACTS=3')
   finally:
    view.setSource(QUrl());view.close();app.processEvents();view.deleteLater();app.processEvents()

if __name__=='__main__':unittest.main(verbosity=0)
