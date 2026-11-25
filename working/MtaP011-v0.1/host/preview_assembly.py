"""HOST Qt QA of real loopback service + file picker + reused keyboard, no ADB."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/'runtime'))
from mta_service import State,Server


def main():
    os.environ['QT_QPA_PLATFORM']='offscreen';os.environ['QT_QUICK_BACKEND']='software'
    from PyQt5.QtCore import QUrl,QTimer,Qt,QMetaObject,Q_ARG,QObject
    from PyQt5.QtGui import QGuiApplication,QFont,QFontDatabase
    from PyQt5.QtQuick import QQuickView
    from PyQt5.QtTest import QTest,QSignalSpy
    temp=tempfile.TemporaryDirectory();rootdir=Path(temp.name)
    (rootdir/'Text').mkdir();(rootdir/'Text/HOST-界面测试.txt').write_bytes(b'HOST fixture only')
    state=State(str(rootdir),str(rootdir/'missing-bluez'),str(rootdir/'missing-network'))
    server=Server(state);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    app=QGuiApplication([])
    if os.name=='nt':
        font=Path('C:/Windows/Fonts/msyh.ttc')
        if font.exists():QFontDatabase.addApplicationFont(str(font))
        app.setFont(QFont('Microsoft YaHei',12))
    view=QQuickView();view.setResizeMode(QQuickView.SizeRootObjectToView)
    view.rootContext().setContextProperty('nativeFontFamily','Microsoft YaHei' if os.name=='nt' else 'sans-serif')
    warnings=[];view.engine().warnings.connect(lambda rows:warnings.extend(r.toString() for r in rows))
    view.setSource(QUrl.fromLocalFile(str(BASE/'device/MtaHost.qml')))
    if view.status()==QQuickView.Error:raise RuntimeError('Host assembly failed to load')
    root=view.rootObject();root.setProperty('endpoint','http://'+server.expected_host)
    root.setProperty('accessToken',state.token);root.setProperty('hostPreview',True)
    view.resize(800,268);view.show()
    out=BASE/'results/ui-assembly-host';out.mkdir(parents=True,exist_ok=True)
    def capture(name):
        QTest.qWait(250);grab=root.grabToImage();spy=QSignalSpy(grab.ready)
        if grab.image().isNull():spy.wait(3000)
        assert grab.saveToFile(str(out/(name+'.png')))
    def qa():
        try:
            QTest.qWait(700);page=root.findChild(QObject,'mtaPage')
            assert page.property('backendOnline');assert not page.property('status').toVariant()['discoverable']
            capture('01-main-no-radio')
            QMetaObject.invokeMethod(root,'fetchFiles',Q_ARG('QVariant','select'));QTest.qWait(500)
            assert len(root.property('fileRows').toVariant())==1;capture('02-file-picker')
            root.setProperty('stage','keyboard');board=root.findChild(QObject,'mtaKeyboard')
            QMetaObject.invokeMethod(board,'open',Q_ARG('QVariant','P011 HOST'),Q_ARG('QVariant',False))
            capture('03-reused-keyboard')
            if warnings:raise RuntimeError('\n'.join(warnings))
            report={'evidence_level':'HOST_QML_REAL_LOOPBACK','pass':True,'canvas':[800,268],
                    'checked':['no-radio-default','opaque-file-catalog','reused-keyboard'],'qml_warnings':warnings}
            (out/'result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps(report,indent=2));app.exit(0)
        except Exception:
            import traceback;traceback.print_exc();print('QML_WARNINGS='+repr(warnings));app.exit(1)
    QTimer.singleShot(50,qa)
    try:return app.exec_()
    finally:server.server_close();thread.join(3);state.close();temp.cleanup()


if __name__=='__main__':sys.exit(main())
