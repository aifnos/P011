"""One new actual HOST-QML pending-audio/loading ownership method only."""
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
 id:app;width:800;height:268
 property var telemetry:({transfer:{},addresses:[]})
 property bool mtaAvailable:false
 property var requests:[]
 property alias files:page
 function request(path,form,done){requests.push({path:path,form:form,done:done});}
 function reply(index,ok,value){requests[index].done(ok,value);}
 function toast(value){}
 FilesPage {id:page;anchors.fill:parent;app:app}
}
'''
class AudioLoadingTests(unittest.TestCase):
 def test_new_pending_audio_loading_owner(self):
  app=QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
  with tempfile.TemporaryDirectory(prefix='p011-audio-loading-host-') as temporary:
   directory=Path(temporary)
   for name in ('FilesPage.qml','Theme.js','Button.qml','Label.qml','VideoPane.qml'):
    shutil.copyfile(ROOT/'candidate/receive-filecenter-v1/device/toolbox'/name,directory/name)
   (directory/'Harness.qml').write_text(HARNESS,encoding='utf-8')
   view=QQuickView();warnings=[];view.engine().warnings.connect(lambda rows:warnings.extend(row.toString() for row in rows))
   view.rootContext().setContextProperty('nativeFontFamily','sans-serif')
   view.setSource(QUrl.fromLocalFile(str(directory/'Harness.qml')))
   self.assertNotEqual(QQuickView.Error,view.status(),[row.toString() for row in view.errors()])
   engine=view.engine();engine.globalObject().setProperty('loadingHost',engine.newQObject(view.rootObject()))
   def evaluate(text):
    value=engine.evaluate(text);self.assertFalse(value.isError(),value.toString());app.processEvents();return value
   def snapshot():return json.loads(evaluate('JSON.stringify({loading:loadingHost.files.loading,pending:loadingHost.files.pendingAudioCommand,selected:loadingHost.files.selected.path||"",requests:loadingHost.requests.length})').toString())
   try:
    evaluate('loadingHost.reply(0,true,{entries:[],next:null,limited:false})')
    evaluate('loadingHost.files.selected={kind:"audio",path:"Received/a.mp3"};loadingHost.files.playAudio()')
    old=snapshot()['requests']-1;self.assertTrue(snapshot()['loading']);self.assertGreaterEqual(snapshot()['pending'],0)
    evaluate('loadingHost.files.handleBack()')
    self.assertFalse(snapshot()['loading']);self.assertEqual(-1,snapshot()['pending']);self.assertEqual('',snapshot()['selected'])
    before=snapshot();evaluate('loadingHost.reply('+str(old)+',true,{generation:1,status:"playing",process_alive:true})')
    self.assertEqual(before,snapshot())
    # New listing owns loading; an old audio response must not clear it.
    evaluate('loadingHost.files.selected={kind:"audio",path:"Received/b.mp3"};loadingHost.files.playAudio()')
    second=snapshot()['requests']-1
    evaluate('loadingHost.files.directory="Received";loadingHost.files.load()')
    listing=snapshot()['requests']-1;self.assertTrue(snapshot()['loading']);self.assertEqual(-1,snapshot()['pending'])
    evaluate('loadingHost.reply('+str(second)+',false,{error:"HOST obsolete audio"})')
    self.assertTrue(snapshot()['loading'])
    evaluate('loadingHost.reply('+str(listing)+',true,{entries:[],next:null,limited:false})')
    self.assertFalse(snapshot()['loading'])
    # Current audio response revokes only its own ticket and clears its loading.
    evaluate('loadingHost.files.playAudio()');third=snapshot()['requests']-1
    self.assertTrue(snapshot()['loading'])
    evaluate('loadingHost.reply('+str(third)+',true,{generation:2,status:"ended",process_alive:false})')
    self.assertFalse(snapshot()['loading']);self.assertEqual(-1,snapshot()['pending'])
    self.assertEqual([],warnings)
    print('RECEIVE_FILECENTER_AUDIO_LOADING_CONTRACTS=3')
   finally:view.setSource(QUrl());view.close();app.processEvents();view.deleteLater();app.processEvents()
if __name__=='__main__':unittest.main(verbosity=0)
