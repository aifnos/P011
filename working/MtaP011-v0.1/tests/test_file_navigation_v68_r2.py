# -*- coding: utf-8 -*-
"""One new actual HOST-QML navigation test; no HTTP, ADB or media playback.

The v68 FilesPage definitions and unchanged Theme/Button/Label are copied into
one private HOST directory per case. QML navigation and /api/open callbacks
are the actual candidate. app.request is a delayed in-memory fixture, not a
server. A derived playAudio method and an inert VideoPane record dispatch
only: original playAudio callbacks and QtMultimedia are not exercised.
HOST Qt is not the pen's Qt 5.10.1, a touch test, or physical output evidence.
No old TestCase/method is imported or executed.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.parse import quote

os.environ['QT_QPA_PLATFORM'] = 'offscreen'
os.environ['QT_QUICK_BACKEND'] = 'software'

from PyQt5.QtCore import QObject, QUrl, QT_VERSION_STR
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtQuick import QQuickView


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ('FilesPage.qml', 'candidate/file-navigation-v68/device/FilesPage.qml',
     '34ecbd37bb0eabe36bf4f6d0a64086f29fe28340df54dbb97c066387e48ec523', 12524),
    ('Theme.js', 'integration/ToolboxMta-v0.1/device/Theme.js',
     '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb', 244),
    ('Button.qml', 'integration/ToolboxMta-v0.1/device/Button.qml',
     'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015', 665),
    ('Label.qml', 'integration/ToolboxMta-v0.1/device/Label.qml',
     '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc', 269),
)

HARNESS_QML = '''import QtQuick 2.10
Item {
    id:host;objectName:"host68Fixture";width:800;height:268
    property var telemetry:({transfer:{},addresses:[]})
    property bool mtaAvailable:false
    property var requests:[]
    property var toastRows:[]
    property int audioEntrypoints:0
    property int videoEntrypoints:0
    property int videoStops:0
    property alias filePage:files
    function request(path,form,done){requests.push({path:path,form:form,done:done});}
    function reply(index,ok,value){
        if(index<0||index>=requests.length||typeof requests[index].done!=="function")throw new Error("HOST missing callback");
        requests[index].done(ok,value);
    }
    function toast(value){toastRows.push(value);}
    function open(value){throw new Error("HOST forbids application navigation");}
    function refresh(){throw new Error("HOST forbids telemetry IO");}
    function snapshot(){
        var paths=[];for(var i=0;i<requests.length;i++)paths.push(requests[i].path);
        return {directory:files.directory,selectedPath:files.selected.path||"",selectedKind:files.selected.kind||"",
                selectedText:files.selected.text||"",loading:files.loading,leaving:files.leaving,
                pendingPath:files.pendingOpenPath,epoch:files.openGeneration,
                transferView:files.transferView,audio:audioEntrypoints,video:videoEntrypoints,
                backendAudio:files.backendAudio,toastCount:toastRows.length,
                requestCount:requests.length,paths:paths,width:files.width,height:files.height};
    }
    FilesPage {
        id:files;anchors.fill:parent;app:host
        // Inert downstream callee: test open dispatch, not audio lifecycle.
        function playAudio(){host.audioEntrypoints++;}
    }
}
'''

VIDEO_QML = '''import QtQuick 2.10
Item {
    id:pane;property var app;property url mediaUrl;property real volume:.25
    property int position:0;property int duration:0;property bool playing:false
    function play(){playing=true;}
    function pause(){playing=false;}
    function stop(){playing=false;if(app)app.videoStops++;}
    Component.onCompleted:{playing=true;if(app)app.videoEntrypoints++;}
}
'''


class _QtFixture(object):
    def __init__(self, test, application):
        self.test = test
        self.application = application
        self.temp = tempfile.TemporaryDirectory(prefix='p011-host68-private-')
        self.view = None
        self.warnings = []
        directory = Path(self.temp.name)
        for name, relative, expected_hash, expected_size in SOURCES:
            raw = (ROOT / relative).read_bytes()
            test.assertEqual(expected_size, len(raw))
            test.assertEqual(expected_hash, hashlib.sha256(raw).hexdigest())
            (directory / name).write_bytes(raw)
        (directory / 'Harness.qml').write_bytes(HARNESS_QML.encode('utf-8'))
        (directory / 'VideoPane.qml').write_bytes(VIDEO_QML.encode('utf-8'))
        self.view = QQuickView()
        self.view.engine().warnings.connect(
            lambda values: self.warnings.extend(value.toString() for value in values))
        self.view.setResizeMode(QQuickView.SizeRootObjectToView)
        self.view.rootContext().setContextProperty('nativeFontFamily', 'sans-serif')
        self.view.setSource(QUrl.fromLocalFile(str(directory / 'Harness.qml')))
        test.assertNotEqual(QQuickView.Error, self.view.status(),
                            [value.toString() for value in self.view.errors()])
        self.root = self.view.rootObject()
        test.assertIsNotNone(self.root)
        test.assertIsNotNone(self.root.findChild(QObject, 'filesPage'))
        self.view.resize(800, 268)
        self.view.show()
        self.engine = self.view.engine()
        self.engine.globalObject().setProperty('host68', self.engine.newQObject(self.root))
        self.application.processEvents()
        test.assertEqual([], self.warnings)
        initial = self.snapshot()
        test.assertEqual((800, 268), (initial['width'], initial['height']))
        test.assertEqual(1, initial['requestCount'])
        test.assertEqual(['/api/files?path=&offset=0'], initial['paths'])
        test.assertTrue(initial['loading'])
        self.reply(0, True, {'entries': [], 'next': None, 'limited': False})
        test.assertFalse(self.snapshot()['loading'])

    def evaluate(self, script):
        value = self.engine.evaluate(script)
        self.test.assertFalse(value.isError(), value.toString())
        self.application.processEvents()
        self.test.assertEqual([], self.warnings)
        return value

    def call_page(self, method, *args):
        text = ','.join(json.dumps(value, ensure_ascii=True) for value in args)
        return self.evaluate('host68.filePage.' + method + '(' + text + ')').toVariant()

    def snapshot(self):
        value = self.engine.evaluate('JSON.stringify(host68.snapshot())')
        self.test.assertFalse(value.isError(), value.toString())
        return json.loads(value.toString())

    def reply(self, index, ok, data):
        return self.evaluate('host68.reply(' + str(index) + ',' +
                             json.dumps(ok) + ',' + json.dumps(data, ensure_ascii=True) + ')')

    def listing(self):
        index = self.snapshot()['requestCount'] - 1
        self.test.assertTrue(self.snapshot()['paths'][index].startswith('/api/files?'))
        self.reply(index, True, {'entries': [], 'next': None, 'limited': False})
        self.test.assertFalse(self.snapshot()['loading'])
        return index

    def folder(self, name):
        self.call_page('openFile', {'kind': 'directory', 'path': name})
        self.test.assertEqual(name, self.snapshot()['directory'])
        self.listing()

    def open_file(self, kind, path):
        before = self.snapshot()['requestCount']
        self.call_page('openFile', {'kind': kind, 'path': path})
        current = self.snapshot()
        self.test.assertEqual(before + 1, current['requestCount'])
        self.test.assertEqual('/api/open?path=' + quote(path, safe=''), current['paths'][-1])
        self.test.assertEqual(path, current['pendingPath'])
        self.test.assertTrue(current['loading'])
        return before

    def unselected(self, loading):
        value = self.snapshot()
        self.test.assertEqual('', value['selectedPath'])
        self.test.assertEqual('', value['selectedKind'])
        self.test.assertEqual(loading, value['loading'])
        self.test.assertEqual((0, 0, 0), (value['audio'], value['video'], value['toastCount']))
        return value

    def close(self):
        if self.view is not None:
            if self.root is not None:
                self.call_page('prepareLeave')
            self.view.close()
            self.view.setSource(QUrl())
            self.application.processEvents()
            self.test.assertEqual([], self.warnings)
            self.view.deleteLater()
            self.application.processEvents()
            self.view = None
        self.temp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


class FileNavigationV68Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])

    def fixture(self):
        return _QtFixture(self, self.application)

    def test_only_new_open_epoch_path_navigation_and_loading_ownership(self):
        completed = []
        with self.fixture() as fixture:
            fixture.folder('Text')
            old = fixture.open_file('audio', 'Text/old.mp3')
            self.assertTrue(fixture.call_page('handleBack'))
            self.assertEqual('', fixture.snapshot()['directory'])
            current_listing = fixture.snapshot()['requestCount'] - 1
            fixture.reply(old, True, {'kind': 'audio', 'path': 'Text/old.mp3', 'url': 'inert://old'})
            fixture.unselected(True)
            fixture.listing()
            self.assertGreater(current_listing, old)
            fixture.unselected(False)
            completed.append('back_preserves_new_listing')

        with self.fixture() as fixture:
            fixture.folder('Text')
            old = fixture.open_file('video', 'Text/old.mp4')
            fixture.evaluate('host68.filePage.directory="Received";host68.filePage.offset=0;host68.filePage.load()')
            self.assertEqual('Received', fixture.snapshot()['directory'])
            fixture.reply(old, True, {'kind': 'video', 'path': 'Text/old.mp4', 'url': 'inert://old'})
            fixture.unselected(True)
            fixture.listing()
            fixture.unselected(False)
            completed.append('directory_change')

        with self.fixture() as fixture:
            fixture.folder('Text')
            old = fixture.open_file('audio', 'Text/old.mp3')
            fixture.call_page('prepareLeave')
            count = fixture.snapshot()['requestCount']
            self.assertTrue(fixture.snapshot()['leaving'])
            fixture.reply(old, True, {'kind': 'audio', 'path': 'Text/old.mp3', 'url': 'inert://old'})
            fixture.unselected(False)
            fixture.call_page('openFile', {'kind': 'audio', 'path': 'Text/new.mp3'})
            fixture.call_page('load')
            self.assertEqual(count, fixture.snapshot()['requestCount'])
            completed.append('leave_refuses_late_and_future_open')

        with self.fixture() as fixture:
            fixture.folder('Text')
            old = fixture.open_file('text', 'Text/old.txt')
            fixture.call_page('load')
            fixture.reply(old, False, {'error': 'HOST delayed open failure'})
            fixture.unselected(True)
            fixture.listing()
            fixture.unselected(False)
            completed.append('refresh_supersedes_open_error')

        with self.fixture() as fixture:
            fixture.folder('Text')
            old = fixture.open_file('text', 'Text/same.txt')
            self.assertTrue(fixture.call_page('handleBack'))
            fixture.listing()
            fixture.folder('Text')
            current = fixture.open_file('text', 'Text/same.txt')
            epoch = fixture.snapshot()['epoch']
            fixture.reply(old, True, {'kind': 'audio', 'path': 'Text/same.txt', 'url': 'inert://old'})
            retained = fixture.unselected(True)
            self.assertEqual('Text/same.txt', retained['pendingPath'])
            self.assertEqual(epoch, retained['epoch'])
            fixture.reply(current, True, {'kind': 'text', 'path': 'Text/same.txt', 'text': 'HOST current text'})
            value = fixture.snapshot()
            self.assertFalse(value['loading'])
            self.assertEqual(('text', 'Text/same.txt', 'HOST current text'),
                             (value['selectedKind'], value['selectedPath'], value['selectedText']))
            self.assertEqual('', value['pendingPath'])
            self.assertEqual((0, 0, 0), (value['audio'], value['video'], value['toastCount']))
            completed.append('new_same_path_open_owns_loading')

        with self.fixture() as fixture:
            fixture.folder('Text')
            old = fixture.open_file('audio', 'Text/old.mp3')
            fixture.call_page('primaryAction')
            self.assertTrue(fixture.snapshot()['transferView'])
            fixture.reply(old, False, {'error': 'HOST obsolete transfer-view reply'})
            fixture.unselected(False)
            self.assertTrue(fixture.call_page('handleBack'))
            self.assertFalse(fixture.snapshot()['transferView'])
            completed.append('transfer_view_invalidates_open')

        with self.fixture() as fixture:
            fixture.folder('Music')
            request = fixture.open_file('audio', 'Music/current.mp3')
            fixture.reply(request, True, {'kind': 'audio', 'path': 'Music/current.mp3', 'url': 'inert://current'})
            value = fixture.snapshot()
            self.assertEqual(('audio', 'Music/current.mp3'), (value['selectedKind'], value['selectedPath']))
            self.assertFalse(value['loading'])
            self.assertEqual((1, 0), (value['audio'], value['video']))
            self.assertFalse(value['backendAudio'])  # Derived callee, not original playAudio.
            self.assertFalse(any(path.startswith('/api/audio') for path in value['paths']))
            self.assertEqual('', value['pendingPath'])
            completed.append('current_audio_dispatch_only')

        with self.fixture() as fixture:
            fixture.folder('Music')
            request = fixture.open_file('video', 'Music/current.mp4')
            fixture.reply(request, True, {'kind': 'video', 'path': 'Music/current.mp4', 'url': 'inert://current'})
            value = fixture.snapshot()
            self.assertEqual(('video', 'Music/current.mp4'), (value['selectedKind'], value['selectedPath']))
            self.assertFalse(value['loading'])
            self.assertEqual((0, 1), (value['audio'], value['video']))
            self.assertEqual('', value['pendingPath'])
            self.assertEqual((800, 268), (value['width'], value['height']))
            self.assertTrue(fixture.call_page('handleBack'))
            returned = fixture.snapshot()
            self.assertEqual(('', '', False),
                             (returned['selectedPath'], returned['selectedKind'], returned['loading']))
            self.assertEqual((0, 1, 0),
                             (returned['audio'], returned['video'], returned['toastCount']))
            completed.append('current_video_inert_loader_dispatch')

        self.assertEqual(8, len(completed))
        self.assertEqual(8, len(set(completed)))
        self.assertTrue(QT_VERSION_STR.startswith('5.'))
        print('HOST68_FILE_NAV new_methods=1 cases=8 old_methods=0 qt_host=true device=false physical_playback=false')


if __name__ == '__main__':
    unittest.main(verbosity=0)
