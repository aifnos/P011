# -*- coding: utf-8 -*-
"""One new HOST Qt method for the composed formal front end, not reception.

The complete six-file candidate is byte-pinned and staged privately. The real
copied toolbox wrapper selects that fixed MtaHost through mtaHostSource. That
fixture uses empty credentials and the real request methods, so no XHR starts.
The action fixture derives only request() as delayed in-memory HTTP; the new
composition's real properties, gates, labels and MouseAreas run in HOST Qt.
No old test is imported, and no State, service, RF, admission or phone runs.
Two unedited labelled 800x268 HOST captures are written only to the explicitly
supplied new capture directory. This file is not included in the formal UI.
ROOT alone performs the first execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

os.environ['QT_QPA_PLATFORM'] = 'windows'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '0'
os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '0'
os.environ['QT_SCALE_FACTOR'] = '1'

from PyQt5.QtCore import QPoint, QPointF, Qt, QUrl, QT_VERSION_STR
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQuick import QQuickItem, QQuickView
from PyQt5.QtTest import QTest


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIRECTORY = None
CAPTURES = ('host-formal-ui-receive.png', 'host-formal-ui-go-wait.png')
MARKER = ('HOST_FORMAL_UI_COMPOSITION_V1 new_methods=1 old_methods=0 cases=4 '
          'qt_host=true http_model=true service=false device=false phone=false\n')
SOURCES = (
    ('MtaHost.qml', 6205,
     '371f705136fb1e03aec7d283120f6915b798edd4b96cdec670f29c971d508380'),
    ('MtaPage.qml', 26088,
     '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('MtaButton.qml', 757,
     '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('MtaLabel.qml', 351,
     'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('MtaKeyboard.qml', 5344,
     '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('MtaTheme.js', 261,
     'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
)
WRAPPER_SOURCES = (
    ('MtaEmbedded.qml', 6183,
     '4a86f69039054af1b0493338249310e5da4e6d49bf696c0b861fb45359d641ea'),
    ('Button.qml', 665,
     'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015'),
    ('Label.qml', 269,
     '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc'),
    ('Theme.js', 244,
     '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb'),
)

EMBEDDED_QML = '''import QtQuick 2.10
import "./toolbox" as Copied
Item {
    id:surface; width:800; height:268
    property string mtaServiceUrl:""
    property string mtaAccessToken:""
    property bool mtaBootstrapAllowed:false
    property bool hostPreview:true
    property url mtaHostSource:Qt.resolvedUrl("formal-ui/MtaHost.qml")
    property alias embeddedValue:embedded
    property var messages:[]
    property var destinations:[]
    function toast(value){messages.push(value);}
    function open(value){destinations.push(value);}
    function openReceivedDirectory(){destinations.push("Received");}
    Copied.MtaEmbedded {id:embedded;anchors.fill:parent;app:surface}
}
'''

ACTION_QML = '''import QtQuick 2.10
import "./formal-ui" as Formal
Item {
    id:surface; width:800; height:268
    property alias pageValue:page
    property var requests:[]
    property var actions:[]
    property var fileModes:[]
    function record(path,form,done){requests.push({path:path,
        form:form===null?null:JSON.parse(JSON.stringify(form)),done:done,replied:false});}
    function reply(index,ok,value){
        if(index<0||index>=requests.length||requests[index].replied)throw new Error("HOST response identity");
        requests[index].replied=true;requests[index].done(ok,value);
    }
    function requestRows(){var rows=[];for(var i=0;i<requests.length;i++)
        rows.push({path:requests[i].path,form:requests[i].form,replied:requests[i].replied});return rows;}
    Formal.MtaPage {
        id:page; anchors.fill:parent;hostPreview:true;nicknameEditorAvailable:true
        function request(path,form,done){surface.record(path,form,done);}
        onActionObserved:function(action){surface.actions.push(action);}
        onFileCenterRequested:function(mode){surface.fileModes.push(mode);}
    }
}
'''


def status(state='idle', send=False, rename=False, scanning=False, transfer=None,
           go_stage=None, legacy_stage=None, devices=None, request=None,
           restore_pending=False):
    value = dict(state=state, nickname='HOST 组合界面模型', devices=devices or [],
                 received=[], scanning=scanning, discoverable=False,
                 restorePending=restore_pending, request=request,
                 capabilities=dict(send=dict(available=send),
                                   receive=dict(available=False),
                                   scan=dict(available=False),
                                   rename=dict(available=rename)))
    if transfer is not None:
        value['transfer'] = transfer
    if go_stage is not None:
        value['goSendLifecycle'] = dict(progress=dict(state=go_stage))
    if legacy_stage is not None:
        value['sendLifecycle'] = dict(stage=legacy_stage)
    return value


FILES = [dict(id='HOST-COMPOSED-FILE-A', name='HOST 文件 A'),
         dict(id='HOST-COMPOSED-FILE-B', name='HOST 文件 B')]
PEERS = [dict(id='HOST-COMPOSED-PEER', name='HOST 设备', available=True)]


class ViewFixture(object):
    def __init__(self, test, application, embedded=False):
        self.test, self.application = test, application
        self.directory = tempfile.TemporaryDirectory(prefix='p011-formal-ui-composition-')
        self.view = None
        self.warnings = []
        self.page = None
        directory = Path(self.directory.name)
        self.test.assertEqual(6, len(SOURCES), 'new composition pins must be frozen')
        self._copy(directory / 'formal-ui', SOURCES, 'candidate/formal-ui-v1/device')
        if embedded:
            self._copy(directory / 'toolbox', WRAPPER_SOURCES,
                       'integration/ToolboxMta-v0.1/device')
        raw = (EMBEDDED_QML if embedded else ACTION_QML).encode('utf-8')
        path = directory / 'Harness.qml'
        with path.open('xb') as handle:
            handle.write(raw)
        self.test.assertEqual(raw, path.read_bytes())
        self.view = QQuickView()
        self.view.setTitle('P011 MTA - HOST formal UI composition fixture')
        self.view.engine().warnings.connect(
            lambda rows: self.warnings.extend(row.toString() for row in rows))
        self.view.setResizeMode(QQuickView.SizeRootObjectToView)
        self.view.rootContext().setContextProperty('nativeFontFamily', 'Microsoft YaHei')
        self.view.setSource(QUrl.fromLocalFile(str(path)))
        self.test.assertEqual(QQuickView.Ready, self.view.status(),
                              [row.toString() for row in self.view.errors()])
        self.root = self.view.rootObject()
        self.test.assertIsNotNone(self.root)
        self.view.resize(800, 268)
        self.view.show()
        self.settle()
        self.page = self.item('mtaPage')
        self.engine = self.view.engine()
        self.engine.globalObject().setProperty('compositionRoot', self.engine.newQObject(self.root))
        self.engine.globalObject().setProperty('compositionPage', self.engine.newQObject(self.page))
        self.test.assertEqual((800, 268), (self.page.width(), self.page.height()))
        self.test.assertEqual('', self.page.property('serviceUrl'))
        self.test.assertEqual('', self.page.property('token'))
        if not embedded:
            self.test.assertEqual(1, len(self.rows()))
            self.reply(0, True, status())

    def _copy(self, destination, rows, relative):
        destination.mkdir()
        for name, size, digest in rows:
            raw = (ROOT / relative / name).read_bytes()
            self.test.assertEqual(size, len(raw), name)
            self.test.assertEqual(digest, hashlib.sha256(raw).hexdigest(), name)
            path = destination / name
            with path.open('xb') as handle:
                handle.write(raw)
            self.test.assertEqual(raw, path.read_bytes())

    def settle(self):
        self.application.processEvents()
        QTest.qWait(10)
        self.application.processEvents()
        self.test.assertEqual([], self.warnings)

    def item(self, name):
        value = self.root.findChild(QQuickItem, name)
        if value is None:
            pending = [self.root]
            while pending:
                current = pending.pop()
                if current.objectName() == name:
                    value = current
                    break
                pending.extend(current.childItems())
        self.test.assertIsNotNone(value, name)
        return value

    def evaluate(self, expression):
        value = self.engine.evaluate(expression)
        self.test.assertFalse(value.isError(), value.toString())
        self.settle()
        return value

    def call(self, method, *args):
        values = ','.join(json.dumps(value, ensure_ascii=True) for value in args)
        return self.evaluate('compositionPage.' + method + '(' + values + ')').toVariant()

    def data(self, expression):
        value = self.evaluate('JSON.stringify(' + expression + ')')
        return json.loads(value.toString())

    def rows(self):
        return self.data('compositionRoot.requestRows()')

    def apply(self, value):
        self.call('applyStatus', value)

    def reply(self, index, ok, value):
        self.evaluate('compositionRoot.reply(' + str(index) + ',' + json.dumps(ok) + ',' +
                      json.dumps(value, ensure_ascii=True) + ')')

    def click(self, name):
        value = self.item(name)
        self.test.assertTrue(value.isVisible(), name)
        self.test.assertIs(value.property('enabled'), True, name)
        point = value.mapToScene(QPointF(value.width() / 2, value.height() / 2))
        self.test.assertTrue(0 <= point.x() < 800 and 0 <= point.y() < 268)
        QTest.mouseClick(self.view, Qt.LeftButton, Qt.NoModifier,
                         QPoint(int(point.x()), int(point.y())), 1)
        self.settle()

    def capture(self, name):
        self.test.assertIsNotNone(CAPTURE_DIRECTORY)
        path = CAPTURE_DIRECTORY / name
        self.test.assertFalse(path.exists())
        self.test.assertTrue(self.item('mtaPreviewBadge').isVisible())
        self.settle()
        image = self.view.grabWindow()
        self.test.assertFalse(image.isNull())
        self.test.assertEqual((800, 268), (image.width(), image.height()))
        self.test.assertTrue(image.save(str(path), 'PNG'))
        raw = path.read_bytes()
        self.test.assertGreater(len(raw), 100)
        self.test.assertEqual(b'\x89PNG\r\n\x1a\n', raw[:8])

    def close(self):
        if self.view is not None:
            if self.page is not None and hasattr(self, 'engine'):
                self.call('prepareLeave')
            self.view.close()
            self.view.setSource(QUrl())
            self.application.processEvents()
            self.test.assertEqual([], self.warnings)
            self.view.deleteLater()
            self.application.processEvents()
            self.view = None
        self.directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class FormalUiCompositionV1Tests(unittest.TestCase):
    def test_fixed_host_go_and_receive_composition(self):
        self.assertTrue(QT_VERSION_STR.startswith('5.15.'), 'HOST only, not target Qt')
        self.assertIsNotNone(CAPTURE_DIRECTORY)
        self.assertEqual([], list(CAPTURE_DIRECTORY.iterdir()))
        application = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
        completed = []

        with ViewFixture(self, application, embedded=True) as fixture:
            embedded = fixture.item('mtaEmbedded')
            self.assertIsNotNone(embedded.property('host'))
            self.assertIs(fixture.page.property('backendOnline'), False)
            self.assertIs(fixture.page.property('archiveProgressKnown'), False)
            self.assertFalse(fixture.call('canPrepareSend'))
            self.assertEqual([], fixture.data('compositionPage.pending'))
            self.assertEqual([], fixture.data('compositionPage.preparedFileIds'))
            self.assertEqual([], fixture.data('compositionRoot.destinations'))
            self.assertIs(embedded.property('knownStatus'), False)
            completed.append('toolbox_fixed_host_source_empty_credentials')

        with ViewFixture(self, application) as fixture:
            fixture.apply(status(state='transferring',
                transfer=dict(archiveBytes=8192, bytes=1024, totalBytes=4096,
                              localCommitVerified=False, peerAckVerified=False),
                go_stage='awaiting_result'))
            self.assertIs(fixture.page.property('archiveProgressKnown'), True)
            self.assertEqual('归档已下载 8 KB', fixture.item('mtaProgressText').property('text'))
            self.assertEqual('解包校验 1 KB / 4 KB', fixture.item('mtaProgressDetails').property('text'))
            self.assertEqual('', fixture.call('sendWaitingText'))
            self.assertEqual('正在传输', fixture.item('mtaState').property('text'))
            self.assertAlmostEqual(.25, fixture.page.property('progressRatio'))
            self.assertEqual([], fixture.data('compositionRoot.actions'))
            fixture.capture(CAPTURES[0])
            fixture.apply(status(state='transferring', request=dict(id='HOST-REQUEST', name='HOST', fileCount=1, totalBytes=4096),
                                 transfer=dict(archiveBytes=8192, bytes=4096, totalBytes=4096)))
            self.assertEqual('收到文件请求', fixture.item('mtaState').property('text'))
            self.assertEqual('接受', fixture.item('mtaPrimary').property('text'))
            self.assertFalse(fixture.item('mtaProgressText').isVisible())
            completed.append('receive_archive_branch_survives_go_composition')

        with ViewFixture(self, application) as fixture:
            fixture.apply(status(send=True, rename=True))
            fixture.click('mtaSendTab')
            fixture.evaluate('compositionPage.selectedFiles=' + json.dumps(FILES))
            fixture.click('mtaPrimary')
            prepare = len(fixture.rows()) - 1
            self.assertEqual(dict(action='send_prepare', fileIds=[row['id'] for row in FILES]), fixture.rows()[prepare]['form'])
            self.assertIs(fixture.page.property('selectionBusy'), True)
            self.assertIs(fixture.item('mtaFiles').property('enabled'), False)
            fixture.reply(prepare, True, status(state='scanning', send=True, rename=True, scanning=True, devices=PEERS))
            fixture.click('mtaDevice0')
            fixture.click('mtaSecondary')
            send = len(fixture.rows()) - 1
            self.assertEqual(dict(action='send', deviceId=PEERS[0]['id'], fileIds=[row['id'] for row in FILES]), fixture.rows()[send]['form'])
            fixture.reply(send, True, status(state='connecting', send=True,
                transfer=dict(direction='send', archiveBytes=999999, bytes=1024, totalBytes=1024, totalFiles=2),
                go_stage='awaiting_confirmation', legacy_stage='awaiting_result'))
            self.assertIs(fixture.page.property('archiveProgressKnown'), False)
            self.assertEqual('等待对方确认', fixture.item('mtaState').property('text'))
            fixture.apply(status(state='transferring', send=True,
                transfer=dict(direction='send', archiveBytes=999999, bytes=1024, totalBytes=1024, totalFiles=2),
                go_stage='awaiting_result'))
            self.assertEqual('等待完成结果', fixture.item('mtaState').property('text'))
            self.assertEqual('1 KB / 1 KB · 100.0%', fixture.item('mtaProgressText').property('text'))
            self.assertEqual('发送 2 个文件', fixture.item('mtaProgressDetails').property('text'))
            fixture.capture(CAPTURES[1])
            self.assertEqual(['send_prepare', 'send'], fixture.data('compositionRoot.actions'))
            completed.append('composed_go_prepare_real_buttons_and_send_progress')

        with ViewFixture(self, application) as fixture:
            fixture.apply(status(send=True, rename=True))
            fixture.click('mtaSendTab')
            fixture.evaluate('compositionPage.selectedFiles=' + json.dumps(FILES))
            fixture.click('mtaPrimary')
            prepare = len(fixture.rows()) - 1
            fixture.reply(prepare, True, status(state='scanning', send=True, scanning=True, devices=PEERS))
            fixture.click('mtaDevice0')
            fixture.apply(status(state='restoring', send=True, restore_pending=True,
                transfer=dict(direction='send', archiveBytes=2048, bytes=1024, totalBytes=1024),
                go_stage='awaiting_result'))
            self.assertEqual('正在恢复网络', fixture.item('mtaState').property('text'))
            self.assertEqual('网络恢复后即可继续使用', fixture.item('mtaProgressText').property('text'))
            self.assertFalse(fixture.item('mtaPrimary').property('enabled'))
            self.assertFalse(fixture.item('mtaSecondary').property('enabled'))
            fixture.call('resetConnection')
            self.assertEqual([], fixture.data('compositionPage.preparedFileIds'))
            self.assertEqual('', fixture.page.property('selectedDeviceId'))
            self.assertIs(fixture.page.property('archiveProgressKnown'), False)
            before = len(fixture.rows())
            fixture.call('prepareLeave')
            for method in ('prepareSelected', 'sendSelected', 'openFileCenter', 'refresh'):
                fixture.call(method)
            self.assertEqual(before, len(fixture.rows()))
            self.assertEqual([], fixture.data('compositionRoot.fileModes'))
            completed.append('composed_restore_and_connection_invalidation')

        self.assertEqual([
            'toolbox_fixed_host_source_empty_credentials',
            'receive_archive_branch_survives_go_composition',
            'composed_go_prepare_real_buttons_and_send_progress',
            'composed_restore_and_connection_invalidation',
        ], completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-directory', required=True)
    args = parser.parse_args()
    CAPTURE_DIRECTORY = Path(args.capture_directory).resolve(strict=True)
    if not CAPTURE_DIRECTORY.is_dir() or CAPTURE_DIRECTORY.is_symlink():
        raise SystemExit('new private capture directory required')
    suite = unittest.TestSuite([
        FormalUiCompositionV1Tests('test_fixed_host_go_and_receive_composition')])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
