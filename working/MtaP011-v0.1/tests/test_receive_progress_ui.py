# -*- coding: utf-8 -*-
"""New HOST Qt check of receive download/file-processing display only.

Actual current MtaPage.qml and its three existing QML dependencies are loaded
by QQuickView. The eight statuses are explicit HOST data fixtures, not network
events, native consent, a State result, a commit or restoration proof. Endpoint
and token stay empty; no request seam, State, transport or old test is imported.
No archive total is invented from the payload size. Partial file bytes mean
unpacking/checking progress, not completed CRC/commit. Sending/legacy receive
fallbacks are checked only as the boundary of the new receive branch. Two
unedited 800x268 grabWindow captures show an explicit HOST status fixture;
their new private directory is supplied by the fixed checker.

ROOT alone executes this new method. HOST Qt is not P011 Qt 5.10.1, a physical
touch/display, external phone, GATT, Wi-Fi or usable MTA reception evidence.
"""
import argparse
import os
from pathlib import Path
import sys
import unittest

# Child-local HOST display settings, not machine-global configuration.
os.environ['QT_QPA_PLATFORM'] = 'windows'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '0'
os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '0'
os.environ['QT_SCALE_FACTOR'] = '1'

from PyQt5.QtCore import QObject, QUrl
from PyQt5.QtGui import QFont, QGuiApplication
from PyQt5.QtQuick import QQuickView
from PyQt5.QtTest import QTest


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_DIRECTORY = None
CAPTURES = ('host-receive-download.png', 'host-receive-verification.png')
MARKER = ('HOST_RECEIVE_PROGRESS_UI new_methods=1 old_methods=0 cases=8 '
          'qt_host=true status_model=true network=false device=false phone=false\n')


class _PageFixture(object):
    """One real QML view; only status input is a declared HOST fixture."""
    def __init__(self, test, app):
        self.test, self.app = test, app
        self.warnings, self.actions = [], []
        self.view = QQuickView()
        self.view.setTitle('P011 MTA - HOST receive status fixture')
        self.view.engine().warnings.connect(
            lambda rows: self.warnings.extend(row.toString() for row in rows))
        self.view.setResizeMode(QQuickView.SizeRootObjectToView)
        self.view.rootContext().setContextProperty(
            'nativeFontFamily', 'Microsoft YaHei' if os.name == 'nt' else 'sans-serif')
        self.view.setSource(QUrl.fromLocalFile(str(ROOT / 'device' / 'MtaPage.qml')))
        test.assertEqual(QQuickView.Ready, self.view.status(),
                         [row.toString() for row in self.view.errors()])
        self.page = self.view.rootObject()
        test.assertIsNotNone(self.page)
        self.page.actionObserved.connect(self.actions.append)
        self.page.setProperty('hostPreview', True)
        self.view.resize(800, 268)
        self.view.show()
        self.app.processEvents()
        test.assertEqual(800, self.page.property('width'))
        test.assertEqual(268, self.page.property('height'))
        self.assert_no_io_or_admission()

    def item(self, name):
        value = self.page.findChild(QObject, name)
        self.test.assertIsNotNone(value, name)
        return value

    def text(self, name):
        return self.item(name).property('text')

    def apply(self, transfer, state='transferring', reason='', request=None,
              send_stage='transferring'):
        self.page.setProperty('status', {
            'state': state, 'nickname': 'HOST', 'devices': [], 'received': [],
            'request': request, 'transfer': dict(transfer), 'reason': reason,
            'sendLifecycle': {'stage': send_stage},
            'discoverable': False, 'scanning': False, 'restorePending': False,
            'capabilities': {'receive': {'available': False},
                             'send': {'available': False}, 'scan': False},
        })
        self.page.setProperty('backendOnline', True)
        self.app.processEvents()
        self.assert_no_io_or_admission()

    def assert_no_io_or_admission(self):
        self.test.assertEqual('', self.page.property('serviceUrl'))
        self.test.assertEqual('', self.page.property('token'))
        self.test.assertIs(self.page.property('actionPending'), False)
        self.test.assertEqual([], self.actions)
        self.test.assertEqual([], self.warnings)

    def receive_texts(self, archive_text, processing_text, ratio):
        self.test.assertEqual(archive_text, self.text('mtaProgressText'))
        self.test.assertEqual(processing_text, self.text('mtaProgressDetails'))
        self.test.assertNotIn('%', self.text('mtaProgressText'))
        self.test.assertNotIn('%', self.text('mtaProgressDetails'))
        self.test.assertNotIn('已完成', self.text('mtaProgressDetails'))
        self.test.assertNotIn('已校验', self.text('mtaProgressDetails'))
        self.test.assertAlmostEqual(ratio, self.page.property('progressRatio'))
        track = self.item('mtaProgressTrack')
        self.test.assertEqual(1, len(track.childItems()))
        self.test.assertAlmostEqual(track.property('width') * ratio,
                                    track.childItems()[0].property('width'))
        for name in ('mtaProgressText', 'mtaProgressDetails'):
            label = self.item(name)
            self.test.assertLessEqual(label.property('paintedWidth'),
                                      label.property('width') + 1.0)

    def capture(self, name):
        self.test.assertIn(name, CAPTURES)
        path = CAPTURE_DIRECTORY / name
        self.test.assertFalse(path.exists(), 'new HOST capture must not overwrite evidence')
        self.test.assertTrue(QTest.qWaitForWindowExposed(self.view, 2000))
        QTest.qWait(30)
        self.app.processEvents()
        badge = self.item('mtaPreviewBadge')
        self.test.assertIs(badge.property('visible'), True)
        self.test.assertEqual('HOST · 界面测试', badge.property('text'))
        self.assert_no_io_or_admission()
        image = self.view.grabWindow()
        self.test.assertFalse(image.isNull())
        self.test.assertEqual((800, 268), (image.width(), image.height()))
        self.test.assertTrue(image.save(str(path), 'PNG'))
        raw = path.read_bytes()
        self.test.assertTrue(raw.startswith(b'\x89PNG\r\n\x1a\n'))
        self.test.assertGreater(len(raw), 100)

    def close(self):
        self.assert_no_io_or_admission()
        self.view.close()
        self.view.deleteLater()
        self.app.processEvents()


class ReceiveProgressUiTests(unittest.TestCase):
    def test_archive_download_and_verified_file_stages(self):
        self.assertIsNotNone(CAPTURE_DIRECTORY, 'fixed checker must supply private capture directory')
        self.assertTrue(CAPTURE_DIRECTORY.is_dir())
        self.assertEqual([], list(CAPTURE_DIRECTORY.iterdir()))
        app = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
        if os.name == 'nt':
            app.setFont(QFont('Microsoft YaHei', 12))
        completed = []
        for case in ('archive_download', 'file_verification',
                     'unknown_file_total', 'legacy_receive_fallback',
                     'sending_unchanged', 'commit_without_peer_ack',
                     'restoring_and_unconfirmed_result', 'confirmation_precedence'):
            with self.subTest(case=case):
                fixture = _PageFixture(self, app)
                try:
                    if case == 'archive_download':
                        fixture.apply({'archiveBytes': 2097152, 'bytes': 0,
                                       'totalBytes': 8388608, 'totalFiles': 2, 'filesDone': 0})
                        fixture.receive_texts('归档已下载 2.0 MB',
                                              '解包校验 0 B / 8.0 MB', 0.0)
                        self.assertIs(fixture.page.property('archiveProgressKnown'), True)
                        self.assertEqual('正在传输', fixture.text('mtaState'))
                        self.assertEqual('取消传输', fixture.text('mtaPrimary'))
                        fixture.capture(CAPTURES[0])
                    elif case == 'file_verification':
                        # ZIP bytes can exceed payload bytes: never divide the
                        # archive download counter by confirmed file size.
                        fixture.apply({'archiveBytes': 8388731, 'bytes': 4194304,
                                       'totalBytes': 8388608, 'totalFiles': 2, 'filesDone': 0})
                        fixture.receive_texts('归档已下载 8.0 MB',
                                              '解包校验 4.0 MB / 8.0 MB', 0.5)
                        self.assertEqual('正在传输', fixture.text('mtaState'))
                        fixture.capture(CAPTURES[1])
                    elif case == 'unknown_file_total':
                        fixture.apply({'archiveBytes': 4096, 'bytes': 1024})
                        fixture.receive_texts('归档已下载 4 KB', '解包校验 1 KB', 0.0)
                        self.assertNotIn('/ 0', fixture.text('mtaProgressDetails'))
                    elif case == 'legacy_receive_fallback':
                        fixture.apply({'bytes': 1024, 'totalBytes': 2048,
                                       'filesDone': 1, 'totalFiles': 2})
                        self.assertIs(fixture.page.property('archiveProgressKnown'), False)
                        self.assertEqual('1 KB / 2 KB', fixture.text('mtaProgressText'))
                        self.assertEqual('已完成 1 / 2 个文件', fixture.text('mtaProgressDetails'))
                        self.assertAlmostEqual(.5, fixture.page.property('progressRatio'))
                    elif case == 'sending_unchanged':
                        fixture.apply({'direction': 'send', 'archiveBytes': 9999999,
                                       'bytes': 3932160, 'totalBytes': 10485760,
                                       'totalFiles': 3}, state='connecting',
                                      send_stage='awaiting_result')
                        self.assertIs(fixture.page.property('archiveProgressKnown'), False)
                        self.assertEqual('3.8 MB / 10.0 MB · 37.5%', fixture.text('mtaProgressText'))
                        self.assertEqual('发送 3 个文件', fixture.text('mtaProgressDetails'))
                        self.assertEqual('等待完成结果', fixture.text('mtaState'))
                    elif case == 'commit_without_peer_ack':
                        fixture.apply({'archiveBytes': 4096, 'bytes': 2048,
                                       'totalBytes': 2048, 'totalFiles': 1, 'filesDone': 1,
                                       'localCommitVerified': True, 'peerAckVerified': False})
                        fixture.receive_texts('归档已下载 4 KB',
                                              '解包校验 2 KB / 2 KB', 1.0)
                        self.assertEqual('正在传输', fixture.text('mtaState'))
                        self.assertEqual('transferring', fixture.page.property('currentState'))
                        self.assertNotIn('传输完成', fixture.text('mtaState'))
                    elif case == 'restoring_and_unconfirmed_result':
                        counters = {'archiveBytes': 4096, 'bytes': 2048, 'totalBytes': 2048,
                                    'localCommitVerified': True, 'peerAckVerified': False}
                        fixture.apply(counters, state='restoring')
                        self.assertEqual('正在恢复网络', fixture.text('mtaState'))
                        self.assertEqual('网络恢复后即可继续使用', fixture.text('mtaProgressText'))
                        self.assertEqual('请勿关闭服务或再次开关无线功能',
                                         fixture.text('mtaProgressDetails'))
                        self.assertIs(fixture.item('mtaPrimary').property('enabled'), False)
                        reason = '文件已保存；未收到手机完成确认，请勿重复传输'
                        fixture.apply(counters, state='error', reason=reason)
                        self.assertEqual('传输未完成', fixture.text('mtaState'))
                        self.assertEqual(reason, fixture.text('mtaInfo'))
                        self.assertIs(fixture.item('mtaProgressTrack').property('visible'), False)
                    else:
                        fixture.apply({'archiveBytes': 4096, 'bytes': 0, 'totalBytes': 2048},
                                      state='awaiting_confirmation',
                                      request={'id': 'HOST-PROMPT', 'name': 'HOST',
                                               'fileCount': 1, 'totalBytes': 2048})
                        self.assertEqual('收到文件请求', fixture.text('mtaState'))
                        self.assertEqual('接受', fixture.text('mtaPrimary'))
                        self.assertEqual('拒绝', fixture.text('mtaSecondary'))
                        self.assertIs(fixture.item('mtaProgressTrack').property('visible'), False)
                    fixture.assert_no_io_or_admission()
                    completed.append(case)
                finally:
                    fixture.close()
        self.assertEqual(8, len(completed))
        self.assertEqual(set(CAPTURES), {path.name for path in CAPTURE_DIRECTORY.iterdir()})
        print(MARKER, end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--capture-dir', required=True)
    options, remaining = parser.parse_known_args()
    CAPTURE_DIRECTORY = Path(options.capture_dir).resolve()
    unittest.main(argv=[sys.argv[0]] + remaining)
