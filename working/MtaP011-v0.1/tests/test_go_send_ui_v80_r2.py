# -*- coding: utf-8 -*-
"""One new HOST Qt/QML UI method, six remaining inert-HTTP action fixtures.

The frozen UI80 QML and its three unchanged dependencies are byte-verified and
copied into a private HOST directory for each fixture. Actual QML definitions,
computed gates and MouseArea/button handlers run under HOST Qt 5.15. The only
derived method is request(): it records delayed, in-memory HTTP actions. No
server, XHR, service token, GATT, radio, file transport or admission is exercised.
Reset/leave epoch and field invalidation are actual QML; late XHR callbacks are
not tested through the overridden request seam. No old TestCase is imported.

The original UI80 method remains whole FAIL. Its first two fixtures reached
their end before the third fixture could not find a visual ListView delegate
through QObject.findChild. This r2 method runs only fixtures 3..8; it does not
replay the completed first two or combine their partial evidence into a PASS.

The screenshot is an actual HOST QQuickView capture, labelled HOST, using only
fixed non-private fixture labels. It is not P011 Qt 5.10.1, touch, phone,
physical display, interoperability, restoration or usable-send evidence.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
os.environ['QT_QUICK_BACKEND'] = 'software'

from PyQt5.QtCore import QPoint, QPointF, Qt, QUrl, QT_VERSION_STR
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQuick import QQuickItem, QQuickView
from PyQt5.QtTest import QTest


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('MtaPage.qml', 'candidate/go-send-ui-v80/device/MtaPage.qml',
     '2729358896390175557a2ec907286f8413fa600d0dee0397517ae4c9cd133c0a', 25341),
    ('MtaButton.qml', 'device/MtaButton.qml',
     '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339', 757),
    ('MtaLabel.qml', 'device/MtaLabel.qml',
     'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3', 351),
    ('MtaTheme.js', 'device/MtaTheme.js',
     'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c', 261),
)
SCREENSHOT_NAME = 'host-ui80.png'
MARKER = ('HOST80R2_GO_SEND_UI new_methods=1 old_methods=0 cases=6 '
          'qt_host=true http_model=true device=false phone=false\n')


HARNESS_QML = '''import QtQuick 2.10
Item {
    id:host;objectName:"host80Fixture";width:800;height:268
    property var requests:[]
    property var actions:[]
    property var fileModes:[]
    property var renames:[]
    property int exits:0
    property alias pageValue:page
    function recordRequest(path,form,done){
        // Inert HTTP entry seam only. Do not copy the candidate's XHR guard.
        requests.push({path:path,form:form===null?null:JSON.parse(JSON.stringify(form)),done:done,replied:false});
    }
    function reply(index,ok,value){
        if(index<0||index>=requests.length||requests[index].replied||typeof requests[index].done!=="function")throw new Error("HOST missing response");
        requests[index].replied=true;requests[index].done(ok,value);
    }
    function snapshot(){
        var rows=[];
        for(var i=0;i<requests.length;i++)rows.push({path:requests[i].path,form:requests[i].form,replied:requests[i].replied});
        return {requests:rows,actions:actions.slice(0),fileModes:fileModes.slice(0),renames:renames.slice(0),exits:exits,
                selectedIds:page.selectedFileIds(),preparedIds:page.preparedFileIds.slice(0),selectedDevice:page.selectedDeviceId,
                preparedMatch:page.preparedFilesMatch(),canPrepare:page.canPrepareSend(),activeScan:page.activeScan(),
                preparing:page.preparing,transferring:page.transferring,restoring:page.restoring,
                selectionBusy:page.selectionBusy,radioBusy:page.radioBusy,actionPending:page.actionPending,
                statusPending:page.statusPending,preparationPending:page.sendPreparationPending,
                backendOnline:page.backendOnline,leaving:page.leaving,epoch:page.lifetime.epoch,
                currentState:page.currentState,tab:page.tab,sendCapability:page.capability("send"),
                friendly:page.friendlyState(),info:page.infoText(),waiting:page.sendWaitingText(),
                width:page.width,height:page.height,serviceUrl:page.serviceUrl,token:page.token};
    }
    MtaPage {
        id:page;anchors.fill:parent;hostPreview:true;nicknameEditorAvailable:true
        // Actual page logic and handlers; only HTTP is an in-memory fixture.
        function request(path,form,done){host.recordRequest(path,form,done);}
        onActionObserved:function(action){host.actions.push(action);}
        onFileCenterRequested:function(mode){host.fileModes.push(mode);}
        onNicknameEditRequested:function(currentName){host.renames.push(currentName);}
        onExitRequested:host.exits++
    }
}
'''


def _status(state='idle', send=False, rename=False, scanning=False,
            restore_pending=False, devices=None, transfer=None, go_stage=None,
            legacy_stage=None):
    value = dict(state=state, nickname='HOST 界面模型', devices=devices or [],
                 received=[], scanning=scanning, discoverable=False,
                 restorePending=restore_pending,
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


FILES = [dict(id='HOST-FILE-A', name='HOST 示例 A'),
         dict(id='HOST-FILE-B', name='HOST 示例 B')]
PEERS = [dict(id='HOST-PEER', name='HOST 示例设备', available=True)]


class _QtFixture(object):
    def __init__(self, test, application):
        self.test = test
        self.application = application
        self.directory = tempfile.TemporaryDirectory(prefix='p011-host80-private-')
        self.view = None
        self.root = None
        self.warnings = []
        directory = Path(self.directory.name)
        for name, relative, digest, size in SOURCES:
            raw = (ROOT / relative).read_bytes()
            test.assertEqual(size, len(raw), relative)
            test.assertEqual(digest, hashlib.sha256(raw).hexdigest(), relative)
            (directory / name).write_bytes(raw)
            test.assertEqual(raw, (directory / name).read_bytes())
        (directory / 'Harness.qml').write_bytes(HARNESS_QML.encode('utf-8'))
        self.view = QQuickView()
        self.view.engine().warnings.connect(
            lambda values: self.warnings.extend(value.toString() for value in values))
        self.view.setResizeMode(QQuickView.SizeRootObjectToView)
        self.view.rootContext().setContextProperty('nativeFontFamily',
                                                 'Microsoft YaHei' if os.name == 'nt' else 'sans-serif')
        self.view.setSource(QUrl.fromLocalFile(str(directory / 'Harness.qml')))
        test.assertNotEqual(QQuickView.Error, self.view.status(),
                            [value.toString() for value in self.view.errors()])
        self.root = self.view.rootObject()
        test.assertIsNotNone(self.root)
        self.page = self.root.findChild(QQuickItem, 'mtaPage')
        test.assertIsNotNone(self.page)
        self.engine = self.view.engine()
        self.engine.globalObject().setProperty('host80', self.engine.newQObject(self.root))
        self.view.resize(800, 268)
        self.view.show()
        self.settle()
        first = self.snapshot()
        test.assertEqual((800, 268), (first['width'], first['height']))
        test.assertEqual('', first['serviceUrl'])
        test.assertEqual('', first['token'])
        test.assertEqual([dict(path='/v1/status', form=None, replied=False)], first['requests'])
        test.assertTrue(first['statusPending'])
        self.reply(0, True, _status())
        test.assertFalse(self.snapshot()['sendCapability'])
        test.assertFalse(self.snapshot()['statusPending'])

    def settle(self):
        self.application.processEvents()
        QTest.qWait(5)
        self.application.processEvents()
        self.test.assertEqual([], self.warnings)

    def evaluate(self, source):
        value = self.engine.evaluate(source)
        self.test.assertFalse(value.isError(), value.toString())
        self.settle()
        return value

    def call(self, method, *args):
        text = ','.join(json.dumps(value, ensure_ascii=True) for value in args)
        return self.evaluate('host80.pageValue.' + method + '(' + text + ')').toVariant()

    def apply(self, value):
        self.call('applyStatus', value)

    def snapshot(self):
        value = self.engine.evaluate('JSON.stringify(host80.snapshot())')
        self.test.assertFalse(value.isError(), value.toString())
        return json.loads(value.toString())

    def item(self, name):
        item = self.root.findChild(QQuickItem, name)
        if item is None:
            # A ListView delegate may have a visual parent without belonging to
            # the root QObject child tree. Walk only actual retained Qt items.
            visual_items = [self.root]
            while visual_items:
                current = visual_items.pop()
                if current.objectName() == name:
                    item = current
                    break
                visual_items.extend(current.childItems())
        self.test.assertIsNotNone(item, name)
        return item

    def text(self, name):
        return self.item(name).property('text')

    def enabled(self, name):
        return bool(self.item(name).property('enabled'))

    def click(self, name, enabled=True):
        item = self.item(name)
        self.test.assertEqual(enabled, bool(item.property('enabled')), name)
        self.test.assertTrue(item.isVisible(), name)
        position = item.mapToScene(QPointF(item.width() / 2.0, item.height() / 2.0))
        self.test.assertTrue(0 <= position.x() < 800 and 0 <= position.y() < 268)
        QTest.mouseClick(self.view, Qt.LeftButton, Qt.NoModifier,
                         QPoint(int(position.x()), int(position.y())), 1)
        self.settle()

    def click_peer(self):
        # Actual candidate ListView delegate and its MouseArea, not a synthetic
        # GoSendPeer, credential, server admission or assigned selection method.
        self.click('mtaDevice0')

    def reply(self, index, ok, value):
        self.evaluate('host80.reply(' + str(index) + ',' + json.dumps(ok) + ',' +
                      json.dumps(value, ensure_ascii=True) + ')')

    def files(self, rows=FILES):
        if self.snapshot()['tab'] != 'send':
            self.click('mtaSendTab')
        self.evaluate('host80.pageValue.selectedFiles=' + json.dumps(rows, ensure_ascii=True))

    def last(self, action=None):
        value = self.snapshot()
        index = len(value['requests']) - 1
        row = value['requests'][index]
        if action is not None:
            self.test.assertEqual('/v1/action', row['path'])
            self.test.assertEqual(action, row['form']['action'])
        return index, row

    def prepare_to_scan(self):
        self.apply(_status(send=True, rename=True))
        self.files()
        self.click('mtaPrimary')
        index, row = self.last('send_prepare')
        self.test.assertEqual(['HOST-FILE-A', 'HOST-FILE-B'], row['form']['fileIds'])
        self.reply(index, True, _status(state='scanning', send=True, rename=True,
                                      scanning=True, devices=PEERS))
        value = self.snapshot()
        self.test.assertTrue(value['activeScan'])
        self.test.assertTrue(value['preparedMatch'])
        self.test.assertFalse(value['actionPending'])

    def capture(self):
        path = ROOT / SCREENSHOT_NAME
        self.test.assertFalse(path.exists(), 'HOST screenshot must be new, not overwrite evidence')
        self.settle()
        QTest.qWait(30)
        self.application.processEvents()
        image = self.view.grabWindow()
        self.test.assertFalse(image.isNull())
        self.test.assertEqual((800, 268), (image.width(), image.height()))
        self.test.assertTrue(image.save(str(path), 'PNG'))
        raw = path.read_bytes()
        self.test.assertTrue(raw.startswith(b'\x89PNG\r\n\x1a\n'))
        self.test.assertGreater(len(raw), 100)
        self.test.assertTrue(self.item('mtaPreviewBadge').isVisible())
        self.test.assertEqual('HOST · 界面测试', self.text('mtaPreviewBadge'))

    def close(self):
        if self.view is not None:
            if self.root is not None:
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


class GoSendUi80R2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not QT_VERSION_STR.startswith('5.15.'):
            raise RuntimeError('HOST80 requires the fixed HOST Qt 5.15 environment, not P011')
        cls.application = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])

    def fixture(self):
        return _QtFixture(self, self.application)

    def test_remaining_selection_busy_restore_and_epoch_gates(self):
        completed = []

        with self.fixture() as fixture:
            fixture.prepare_to_scan()
            self.assertFalse(fixture.enabled('mtaSecondary'))
            self.assertTrue(fixture.call('deviceSelectable', PEERS[0]))
            fixture.click_peer()
            self.assertEqual('HOST-PEER', fixture.snapshot()['selectedDevice'])
            fixture.click('mtaSecondary')
            index, request = fixture.last('send')
            self.assertEqual(dict(action='send', deviceId='HOST-PEER',
                                  fileIds=['HOST-FILE-A', 'HOST-FILE-B']), request['form'])
            self.assertEqual(['send_prepare', 'send'], fixture.snapshot()['actions'])
            fixture.reply(index, True, _status(state='connecting', send=True,
                         transfer=dict(direction='send', bytes=0, totalBytes=1024, totalFiles=2),
                         go_stage='awaiting_confirmation'))
            self.assertEqual('', fixture.snapshot()['selectedDevice'])
            self.assertFalse(fixture.enabled('mtaSecondary'))
            completed.append('current_delegate_and_original_ids_send')

        with self.fixture() as fixture:
            fixture.prepare_to_scan()
            fixture.click_peer()
            fixture.files([dict(id='HOST-FILE-C', name='HOST 示例 C')])
            value = fixture.snapshot()
            self.assertEqual(['HOST-FILE-A', 'HOST-FILE-B'], value['preparedIds'])
            self.assertEqual(['HOST-FILE-C'], value['selectedIds'])
            self.assertEqual('', value['selectedDevice'])
            self.assertFalse(value['preparedMatch'])
            self.assertFalse(fixture.call('deviceSelectable', PEERS[0]))
            self.assertFalse(fixture.enabled('mtaSecondary'))
            fixture.click_peer()
            self.assertEqual('', fixture.snapshot()['selectedDevice'])
            fixture.call('sendSelected')
            fixture.call('prepareSelected')
            self.assertEqual(['send_prepare'], fixture.snapshot()['actions'])
            completed.append('busy_selection_does_not_reuse_prepared_ids')

        with self.fixture() as fixture:
            fixture.prepare_to_scan()
            self.assertTrue(fixture.snapshot()['selectionBusy'])
            for name in ('mtaFiles', 'mtaRename', 'mtaReceiveTab'):
                fixture.click(name, enabled=False)
            fixture.call('openFileCenter')
            fixture.call('applyNickname', 'HOST 新名字')
            self.assertEqual([], fixture.snapshot()['fileModes'])
            self.assertEqual([], fixture.snapshot()['renames'])
            self.assertEqual(['send_prepare'], fixture.snapshot()['actions'])
            self.assertEqual('停止搜索', fixture.text('mtaPrimary'))
            fixture.click('mtaPrimary')
            index, request = fixture.last('scan_stop')
            self.assertEqual(dict(action='scan_stop'), request['form'])
            fixture.reply(index, True, _status(send=True, rename=True, devices=PEERS))
            self.assertFalse(fixture.snapshot()['activeScan'])
            self.assertFalse(fixture.call('deviceSelectable', PEERS[0]))
            self.assertTrue(fixture.enabled('mtaFiles'))
            self.assertTrue(fixture.enabled('mtaRename'))
            self.assertEqual(['send_prepare', 'scan_stop'], fixture.snapshot()['actions'])
            completed.append('scan_stop_and_busy_picker_rename_mode_locks')

        with self.fixture() as fixture:
            fixture.files()
            fixture.apply(_status(send=True, rename=True, restore_pending=True))
            self.assertFalse(fixture.snapshot()['canPrepare'])
            self.assertFalse(fixture.enabled('mtaPrimary'))
            fixture.call('prepareSelected')
            self.assertIn('恢复仍待核验', fixture.snapshot()['info'])
            self.assertEqual('刷新状态', fixture.text('mtaRefresh'))
            fixture.click('mtaRefresh')
            index, request = fixture.last()
            self.assertEqual(dict(path='/v1/status', form=None, replied=False), request)
            fixture.reply(index, True, _status(send=True, rename=True, restore_pending=True))
            fixture.apply(_status(state='restoring', send=True, rename=True, restore_pending=True))
            self.assertTrue(fixture.snapshot()['restoring'])
            for name in ('mtaPrimary', 'mtaSecondary', 'mtaFiles', 'mtaRename'):
                self.assertFalse(fixture.enabled(name))
            fixture.click('mtaRefresh')
            index, request = fixture.last()
            self.assertEqual('/v1/status', request['path'])
            self.assertIsNone(request['form'])
            fixture.reply(index, True, _status(state='restoring', restore_pending=True))
            self.assertEqual([], fixture.snapshot()['actions'])
            self.assertEqual(['/v1/status'] * 3,
                             [row['path'] for row in fixture.snapshot()['requests']])
            completed.append('restore_pending_blocks_prepare_refresh_only_get')

        with self.fixture() as fixture:
            fixture.files([])
            transfer = dict(direction='send', bytes=1024, totalBytes=1024,
                            totalFiles=2, peerCompletionVerified=False)
            fixture.apply(_status(state='connecting', transfer=transfer,
                                  go_stage='awaiting_confirmation', legacy_stage='awaiting_result'))
            self.assertFalse(fixture.snapshot()['sendCapability'])
            self.assertEqual('等待对方确认', fixture.text('mtaState'))
            self.assertEqual('请在对方设备上确认接收文件', fixture.text('mtaInfo'))
            fixture.apply(_status(state='transferring', transfer=transfer, go_stage='awaiting_result'))
            self.assertEqual('等待完成结果', fixture.text('mtaState'))
            self.assertIn('等待对方完成确认', fixture.text('mtaInfo'))
            self.assertEqual('1 KB / 1 KB · 100.0%', fixture.text('mtaProgressText'))
            self.assertEqual('发送 2 个文件', fixture.text('mtaProgressDetails'))
            self.assertNotIn('传输完成', fixture.snapshot()['friendly'])
            self.assertFalse(fixture.enabled('mtaSecondary'))
            fixture.capture()
            for state, expected in (('restoring', '正在恢复网络'),
                                    ('failed', '传输未完成'), ('completed', '传输完成')):
                fixture.apply(_status(state=state, transfer=transfer, go_stage='awaiting_result'))
                self.assertEqual(expected, fixture.text('mtaState'))
                self.assertEqual('', fixture.snapshot()['waiting'])
            self.assertEqual([], fixture.snapshot()['actions'])
            completed.append('go_waiting_not_peer_completion_and_host_capture')

        with self.fixture() as fixture:
            fixture.apply(_status(send=True, rename=True))
            fixture.files()
            fixture.click('mtaPrimary')
            old_epoch = fixture.snapshot()['epoch']
            request_count = len(fixture.snapshot()['requests'])
            fixture.call('resetConnection')
            value = fixture.snapshot()
            self.assertEqual(old_epoch + 1, value['epoch'])
            self.assertFalse(value['backendOnline'])
            self.assertFalse(value['actionPending'])
            self.assertFalse(value['preparationPending'])
            self.assertEqual([], value['preparedIds'])
            self.assertEqual('', value['selectedDevice'])
            self.assertEqual(request_count, len(value['requests']))
            # Do not deliver the old model callback: real XHR guard is a separate
            # SOURCE-audited boundary, not exercised through this request seam.
            fixture.apply(_status(send=True, rename=True))
            fixture.files()
            fixture.click('mtaPrimary')
            before = fixture.snapshot()
            fixture.call('prepareLeave')
            value = fixture.snapshot()
            self.assertTrue(value['leaving'])
            self.assertEqual(before['epoch'] + 1, value['epoch'])
            self.assertFalse(value['actionPending'])
            self.assertFalse(value['statusPending'])
            self.assertFalse(value['canPrepare'])
            self.assertFalse(fixture.call('deviceSelectable', PEERS[0]))
            for method, args in (('prepareSelected', ()), ('sendSelected', ()),
                                 ('openFileCenter', ()), ('issue', ('cancel',)), ('refresh', ())):
                fixture.call(method, *args)
            self.assertEqual(len(before['requests']), len(fixture.snapshot()['requests']))
            self.assertEqual([], fixture.snapshot()['fileModes'])
            self.assertEqual(['send_prepare', 'send_prepare'], fixture.snapshot()['actions'])
            completed.append('reset_and_leave_invalidate_actual_fields')

        self.assertEqual([
            'current_delegate_and_original_ids_send',
            'busy_selection_does_not_reuse_prepared_ids',
            'scan_stop_and_busy_picker_rename_mode_locks',
            'restore_pending_blocks_prepare_refresh_only_get',
            'go_waiting_not_peer_completion_and_host_capture',
            'reset_and_leave_invalidate_actual_fields',
        ], completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    if sys.argv[1:] not in ([], ['-q']):
        raise SystemExit(2)
    suite = unittest.TestSuite([
        GoSendUi80R2Test('test_remaining_selection_busy_restore_and_epoch_gates')])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
