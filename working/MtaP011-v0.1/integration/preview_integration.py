"""HOST Qt integration QA: no device, no radio helper and no fake phone peers.

Starts copied toolbox HTTP and root MTA service against one private HOST user
directory. All helper paths are absent; real capability responses stay disabled.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

BASE = Path(__file__).resolve().parent
MTA = BASE.parent
COPY = BASE / 'ToolboxMta-v0.1'
sys.path.insert(0, str(COPY / 'runtime'))
sys.path.insert(0, str(MTA / 'runtime'))
from mta_toolbox_server import State as ToolboxState, BoundedServer
from mta_service import State as MtaState, Server as MtaServer


def main():
    output = MTA / 'results/toolbox-integration-ui'
    output.mkdir(parents=True, exist_ok=True)
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'
    os.environ['QT_QUICK_BACKEND'] = 'software'
    from PyQt5.QtCore import QUrl, QTimer, Qt, QMetaObject, Q_ARG, Q_RETURN_ARG, QObject, QPointF, QPoint
    from PyQt5.QtGui import QGuiApplication, QFont, QFontDatabase
    from PyQt5.QtQuick import QQuickView
    from PyQt5.QtTest import QTest, QSignalSpy
    from PyQt5 import QtMultimedia, QtMultimediaWidgets
    application = QGuiApplication(sys.argv[:1])
    if os.name == 'nt':
        path = Path('C:/Windows/Fonts/msyh.ttc')
        if path.is_file(): QFontDatabase.addApplicationFont(str(path))
        application.setFont(QFont('Microsoft YaHei', 12))
    user = tempfile.TemporaryDirectory(prefix='p011-mta-toolbox-host-')
    toolbox = ToolboxState(user.name, preview=True)
    incoming = Path(user.name) / 'Received' / 'HOST-text.txt'
    incoming.write_text('HOST 接入测试文件\n不代表手机传输成功。', encoding='utf-8')
    mta = MtaState(user.name, '', '', openssl='/HOST-absent-openssl')
    action_control = {'delay':False, 'entered':threading.Event(), 'release':threading.Event()}
    original_action = mta.action
    def delayed_action(value):
        # HOST transport timing only; capabilities remain the real disabled
        # service result. No radio fixture or fake transfer result is added.
        if value.get('action') == 'cancel' and action_control['delay']:
            action_control['entered'].set(); action_control['release'].wait(3)
        return original_action(value)
    mta.action = delayed_action
    old = BoundedServer(('127.0.0.1', 0), toolbox)
    new = MtaServer(mta)
    for server in (old, new):
        thread = threading.Thread(target=server.serve_forever); thread.daemon = True; thread.start()
    warnings = []
    checks = []
    view = QQuickView()
    view.engine().warnings.connect(lambda rows: warnings.extend(e.toString() for e in rows))
    context = view.rootContext()
    context.setContextProperty('nextEndpoint', 'http://' + old.expected_host)
    context.setContextProperty('nextToken', toolbox.token)
    context.setContextProperty('mtaEndpoint', 'http://' + new.expected_host)
    context.setContextProperty('mtaToken', mta.token)
    view.setResizeMode(QQuickView.SizeRootObjectToView)
    view.resize(800, 268)
    view.setSource(QUrl.fromLocalFile(str(COPY / 'device/ExtensionPage.qml')))
    view.show()

    def qa():
        try:
            root = view.rootObject()
            if root is None: raise AssertionError('QML root failed')
            root.setProperty('hostPreview', True)
            root.setProperty('biliAvailable', True)
            def check(name, value):
                if not value: raise AssertionError(name)
                checks.append(name)
            def capture(name):
                QTest.qWait(250)
                grab = root.grabToImage()
                if grab and grab.image().isNull(): QSignalSpy(grab.ready).wait(3000)
                if not grab or not grab.saveToFile(str(output / (name + '.png'))): raise AssertionError('Screenshot save')
            def find(name):
                item = root.findChild(QObject, name)
                if item is None:
                    stack = [root]
                    while stack:
                        node = stack.pop()
                        if node.objectName() == name:
                            item = node; break
                        if hasattr(node, 'childItems'): stack.extend(node.childItems())
                if item is None: raise AssertionError('Missing item ' + name)
                return item
            def click(name):
                item = find(name)
                point = item.mapToScene(QPointF(item.width()/2, item.height()/2)).toPoint()
                QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, point)
                QTest.qWait(400)
            def invoke(item, name, value=None):
                if value is None: QMetaObject.invokeMethod(item, name)
                else: QMetaObject.invokeMethod(item, name, Q_ARG('QVariant', value))
                QTest.qWait(500)
            def child(): return find('featureLoader').property('item')
            QTest.qWait(500)
            check('shared_user_root', toolbox.store.root == mta.registry.root)
            check('no_helpers_started', mta.helper is None and mta.worker is None)
            caps = mta.status()['capabilities']
            check('real_capabilities_disabled', all(value is False or (isinstance(value, dict) and not value.get('available')) for value in (caps['receive'],caps['send'])))
            check('home_scrollable', find('toolboxHomeScroller').property('contentWidth') > 768)
            check('home_title_explicit', find('toolboxHeaderTitle').property('text') == '工具箱 · HOST')
            capture('01-home')
            find('toolboxHomeScroller').setProperty('contentX', find('toolboxHomeScroller').property('contentWidth') - 768)
            capture('02-home-scrolled')
            find('toolboxHomeScroller').setProperty('contentX', 0)
            click('homeFiles')
            check('files_page_route', child().objectName() == 'filesPage')
            check('file_controls_large', find('fileFolderMta').width() >= 180 and find('fileFolderMta').height() >= 80)
            capture('03-files')
            click('fileFolderReceived')
            check('received_same_root_listing', child().property('directory') == 'Received' and len(child().property('entries').toVariant()) == 1)
            check('small_file_bytes_visible', find('fileEntrySize0').property('text') == '文本 · ' + str(incoming.stat().st_size) + ' B')
            check('file_size_boundaries', all(QMetaObject.invokeMethod(child(),'formatBytes',Q_RETURN_ARG('QVariant'),Q_ARG('QVariant',value)) == expected for value, expected in ((0,'0 B'),(16,'16 B'),(1023,'1023 B'),(1024,'1.0 KiB'),(1048576,'1.0 MiB'),(1073741824,'1.0 GiB'))))
            capture('04-received')
            invoke(root, 'open', 'Mta')
            check('mta_full_content', find('featureLoader').y() == 0 and child().height() == 268 and child().width() == 800)
            check('no_fake_peers', len(mta.status()['devices']) == 0)
            root.setProperty('pageName', '')
            check('home_title_ignores_retained_loader', child().property('headerTitle') == '手机互传' and find('toolboxHeaderTitle').property('text') == '工具箱 · HOST')
            root.setProperty('pageName', 'Mta')
            capture('05-mta-disabled')
            click('mtaFiles')
            check('opaque_picker_route', find('embeddedMtaHostLoader').property('item').property('stage') == 'files')
            capture('06-mta-received-picker')
            click('receivedOpenFileCenter')
            check('return_to_received_center', root.property('pageName') == 'Files' and child().property('directory') == 'Received')
            invoke(root, 'open', 'Mta')
            click('mtaSendTab')
            click('mtaFiles')
            host = find('embeddedMtaHostLoader').property('item')
            rows = host.property('fileRows').toVariant()
            check('opaque_file_ids', len(rows) == 1 and len(rows[0]['id']) == 32 and rows[0]['id'] != rows[0]['name'])
            capture('07-mta-selection')
            invoke(root, 'open', 'Games')
            check('game_full_content_preserved', find('featureLoader').y() == 0 and child().height() == 268)
            capture('08-games-preserved')
            invoke(root, 'open', 'Dashboard')
            check('dashboard_route_preserved', child().objectName() == 'dashboardPage')
            capture('09-dashboard-preserved')
            invoke(root, 'open', '')
            check('dashboard_return_home_title', find('toolboxHeaderTitle').property('text') == '工具箱 · HOST')
            invoke(root, 'open', 'Mta')
            invoke(child(), 'requestExit', '')
            check('mta_return_home_title', root.property('pageName') == '' and find('toolboxHeaderTitle').property('text') == '工具箱 · HOST')
            capture('10-home-returned')
            invoke(root, 'open', 'Mta')
            wrapper = child()
            action_control['delay'] = True
            invoke(root, 'open', 'Files')
            check('old_idle_cannot_leave_before_cancel_ack', action_control['entered'].is_set() and root.property('pageName') == 'Mta' and not wrapper.property('exitApproved'))
            root.setProperty('mtaAccessToken', 'HOST-invalid-token')
            action_control['delay'] = False; action_control['release'].set()
            QTest.qWait(500)
            check('credential_epoch_blocks_old_cancel_reply', root.property('pageName') == 'Mta' and not wrapper.property('knownStatus') and not wrapper.property('exitApproved'))
            root.setProperty('mtaAccessToken', mta.token)
            QTest.qWait(300)
            invoke(root, 'open', 'Files')
            check('fresh_cancel_and_get_allow_return', root.property('pageName') == 'Files')
            check('no_qml_runtime_errors', len(warnings) == 0)
            result = {'evidence_level':'HOST_QT', 'pass':True, 'checks':checks, 'screenshots':10,
                      'warnings':warnings, 'device_tested':False, 'phone_interop':'NOT_TESTED',
                      'radio_helpers_started':False, 'real_transfer_capabilities_disabled':True}
            (output / 'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
            print('HOST_TOOLBOX_INTEGRATION_QT_PASS checks=' + str(len(checks)) + ' screenshots=10 noRF=true')
            application.exit(0)
        except Exception:
            import traceback
            traceback.print_exc()
            print('QML_WARNINGS ' + repr(warnings))
            application.exit(1)
    QTimer.singleShot(100, qa)
    try:
        return application.exec_()
    finally:
        for server in (old,new): server.shutdown(); server.server_close()
        toolbox.close(); mta.close(); user.cleanup()


if __name__ == '__main__': sys.exit(main())
