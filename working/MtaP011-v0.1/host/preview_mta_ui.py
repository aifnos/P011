"""HOST-only Qt UI QA with explicitly labelled fixtures; never touches P011.

Default run captures 800x268 pages and tests real QML pointer interactions.
--interactive opens a PC fixture preview. It is not an MTA interoperability test.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = Path(__file__).resolve().parents[1]


def idle_fixture():
    return {
        "state": "idle", "nickname": "P011 · HOST", "devices": [],
        "received": [], "request": None, "transfer": {},
        "capabilities": {"receive": True, "send": True, "scan": True, "rename": True},
        "reason": "", "discoverable": False, "scanning": False,
    }


class FixtureState:
    """Synthetic values are used only in this host QA process."""
    def __init__(self):
        self.status = idle_fixture()
        self.token = secrets.token_urlsafe(24)
        self.actions = []
        self.errors = []
        self.lock = threading.Lock()

    def set(self, **updates):
        with self.lock:
            self.status = dict(idle_fixture(), **updates)

    def act(self, value):
        allowed = {"discover_start", "discover_stop", "scan", "scan_stop", "accept", "reject", "cancel", "send", "rename"}
        if value.get("action") not in allowed:
            raise ValueError("Action is not whitelisted")
        with self.lock:
            self.actions.append(copy.deepcopy(value))
            action = value["action"]
            if action in ("discover_start", "discover_stop"):
                self.status.update(state="advertising" if action == "discover_start" else "idle", discoverable=action == "discover_start")
            elif action in ("scan", "scan_stop"):
                self.status.update(state="scanning" if action == "scan" else "idle", scanning=action == "scan")
                if action == "scan":
                    self.status["devices"] = [
                        {"id": "host-online", "name": "HOST 测试设备 · 不是真实手机", "available": True},
                        {"id": "host-offline", "name": "HOST 离线记录 · 禁止发送", "available": False},
                    ]
            elif action in ("accept", "reject"):
                request = self.status.get("request")
                if not request or request.get("id") != value.get("requestId"):
                    raise ValueError("Request ID is stale")
                self.status["request"] = None
                self.status["state"] = "transferring" if action == "accept" else "idle"
            elif action == "cancel":
                self.status["state"] = "restoring"
            elif action == "send":
                if value.get("deviceId") != "host-online" or value.get("fileIds") != ["host-file"]:
                    raise ValueError("Unexpected selection; fixture rejects paths")
                self.status["state"] = "connecting"
            elif action == "rename":
                self.status["nickname"] = value["nickname"]
            return copy.deepcopy(self.status)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Avoid logging headers or authentication tokens.

    def respond(self, code, value):
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def authorized(self):
        return self.headers.get("X-P011-MTA-Token") == self.server.fixture.token

    def do_GET(self):
        if not self.authorized():
            self.respond(403, {"ok": False, "reason": "HOST fixture requires a token"})
        elif self.path != "/v1/status":
            self.respond(404, {"ok": False, "reason": "Unknown path"})
        else:
            with self.server.fixture.lock:
                state = copy.deepcopy(self.server.fixture.status)
            self.respond(200, {"ok": True, "data": state})

    def do_POST(self):
        if not self.authorized():
            self.respond(403, {"ok": False, "reason": "HOST fixture requires a token"})
            return
        if self.path != "/v1/action":
            self.respond(404, {"ok": False, "reason": "Unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                raise ValueError("Body size")
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            result = self.server.fixture.act(value)
            self.respond(200, {"ok": True, "data": result})
        except Exception as exc:
            self.server.fixture.errors.append(str(exc))
            self.respond(400, {"ok": False, "reason": str(exc)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screenshots", type=Path)
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()
    if not args.interactive:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        os.environ["QT_QUICK_BACKEND"] = "software"
    from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, QPointF, QTimer, QUrl, Qt
    from PyQt5.QtGui import QFont, QFontDatabase
    from PyQt5.QtQuick import QQuickView
    from PyQt5.QtTest import QSignalSpy, QTest

    app = __import__("PyQt5.QtGui", fromlist=["QGuiApplication"]).QGuiApplication(sys.argv[:1])
    if os.name == "nt":
        existing_font = Path("C:/Windows/Fonts/msyh.ttc")
        if existing_font.is_file():
            QFontDatabase.addApplicationFont(str(existing_font))
        app.setFont(QFont("Microsoft YaHei", 12))
    fixture = FixtureState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    server.fixture = fixture
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    view = QQuickView()
    warnings = []
    view.engine().warnings.connect(lambda rows: warnings.extend(row.toString() for row in rows))
    view.setResizeMode(QQuickView.SizeRootObjectToView)
    if os.name == "nt":
        view.rootContext().setContextProperty("nativeFontFamily", "Microsoft YaHei")
    view.setSource(QUrl.fromLocalFile(str(BASE / "device" / "MtaPage.qml")))
    if view.status() == QQuickView.Error:
        print("HOST_UI_FAIL " + repr([row.toString() for row in view.errors()]))
        server.shutdown()
        server.server_close()
        return 1
    root = view.rootObject()
    root.setProperty("hostPreview", True)
    view.resize(800, 268)
    view.setTitle("P011 手机互传 — HOST fixture preview (not phone interoperability)")
    root.exitRequested.connect(app.quit)
    root.fileCenterRequested.connect(lambda mode: QMetaObject.invokeMethod(root, "toast", Q_ARG("QVariant", "HOST：文件中心信号 " + mode)))
    root.nicknameEditRequested.connect(lambda name: QMetaObject.invokeMethod(root, "applyNickname", Q_ARG("QVariant", "P011 HOST 改名")))
    view.show()
    output = args.screenshots or BASE / "results" / ("ui-host-" + time.strftime("%Y%m%d-%H%M%S"))
    captures = []
    checks = []

    def invoke(name, *values):
        return QMetaObject.invokeMethod(root, name, *[Q_ARG("QVariant", value) for value in values])

    def item(name):
        result = root.findChild(QObject, name)
        assert result is not None, "Missing control: " + name
        return result

    def click(name):
        control = item(name)
        assert control.property("enabled"), "Disabled control: " + name
        point = control.mapToScene(QPointF(control.width() / 2, control.height() / 2)).toPoint()
        QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, point)
        QTest.qWait(170)

    def capture(name):
        QTest.qWait(100)
        grab = root.grabToImage()
        assert grab, "Capture request failed"
        if grab.image().isNull():
            QSignalSpy(grab.ready).wait(3000)
        assert grab.saveToFile(str(output / (name + ".png")))
        assert grab.image().width() == 800 and grab.image().height() == 268
        captures.append(name)

    def status(**updates):
        fixture.set(**updates)
        invoke("refresh")
        QTest.qWait(170)

    def qa():
        try:
            output.mkdir(parents=True, exist_ok=True)
            QTest.qWait(120)
            assert not root.property("backendOnline")
            assert not item("mtaPrimary").property("enabled")
            assert not item("mtaSecondary").property("enabled")
            assert not fixture.actions
            capture("01-unavailable")
            checks.append("unavailable_fail_closed_no_auto_radio_action")

            root.setProperty("serviceUrl", "http://127.0.0.1:" + str(server.server_address[1]))
            root.setProperty("token", fixture.token)
            root.setProperty("nicknameEditorAvailable", True)
            invoke("refresh")
            QTest.qWait(170)
            assert root.property("backendOnline")
            assert not fixture.actions
            capture("02-receive-idle")
            click("mtaPrimary")
            assert fixture.actions[-1]["action"] == "discover_start"
            assert root.property("currentState") == "advertising"
            capture("03-receive-discoverable")
            click("mtaPrimary")
            assert fixture.actions[-1]["action"] == "discover_stop"
            checks.append("manual_discovery_start_stop")

            click("mtaRename")
            assert fixture.actions[-1] == {"action": "rename", "nickname": "P011 HOST 改名"}
            checks.append("nickname_host_signal_no_private_vendor_abi")
            click("mtaSendTab")
            root.setProperty("selectedFiles", [{"id": "host-file", "name": "HOST测试.txt", "size": 100}])
            assert not item("mtaSecondary").property("enabled")
            click("mtaPrimary")
            assert fixture.actions[-1]["action"] == "scan"
            assert root.property("selectedDeviceId") == ""
            capture("04-send-discovery")
            # List delegates are managed by ListView, not always QObject children.
            QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, __import__("PyQt5.QtCore", fromlist=["QPoint"]).QPoint(360, 167))
            QTest.qWait(100)
            assert root.property("selectedDeviceId") == "host-online"
            assert item("mtaSecondary").property("enabled")
            click("mtaSecondary")
            assert fixture.actions[-1] == {"action": "send", "deviceId": "host-online", "fileIds": ["host-file"]}
            checks.append("scan_then_select_online_id_only_send")

            status(state="transferring", transfer={"bytes": 3932160, "totalBytes": 10485760, "filesDone": 1, "totalFiles": 3})
            assert not item("mtaSendTab").property("enabled")
            assert not item("mtaFiles").property("enabled")
            assert abs(root.property("progressRatio") - 0.375) < 0.001
            capture("05-transfer-progress")
            click("mtaPrimary")
            assert fixture.actions[-1]["action"] == "cancel"
            assert root.property("currentState") == "restoring"
            assert not item("mtaPrimary").property("enabled")
            assert not item("mtaSecondary").property("enabled")
            capture("06-restoring")
            checks.append("cancel_then_wait_for_restore_no_false_completion")

            status(state="idle", devices=[{"id": "host-online", "name": "HOST离线设备", "available": False}])
            assert root.property("selectedDeviceId") == ""
            assert not item("mtaSecondary").property("enabled")
            checks.append("stale_device_selection_invalidated")
            click("mtaReceiveTab")
            incoming = {"id": "host-request", "name": "HOST发送方 · 合成数据", "fileCount": 3, "totalBytes": 10485760}
            status(state="awaiting_confirmation", request=incoming)
            capture("07-receive-confirm")
            click("mtaSecondary")
            assert fixture.actions[-1] == {"action": "reject", "requestId": "host-request"}
            status(state="awaiting_confirmation", request=incoming)
            click("mtaPrimary")
            assert fixture.actions[-1] == {"action": "accept", "requestId": "host-request"}
            checks.append("explicit_accept_and_reject_by_request_id")

            status(state="complete", received=[{"id": "host-received", "name": "HOST 已接收的很长文件名称用于截断检查.txt", "size": 100}])
            click("mtaSecondary")
            capture("08-received-files")
            invoke("handleBack")
            assert not root.property("showingReceived")
            status(state="error", reason="HOST：接收端拒绝请求，网络已恢复")
            capture("09-failure-reason")
            checks.append("received_list_and_truthful_failure_reason")

            # Loopback-only transport and missing capability fail closed.
            status(capabilities={})
            assert not item("mtaPrimary").property("enabled")
            root.setProperty("serviceUrl", "http://192.168.1.1:1234")
            invoke("refresh")
            QTest.qWait(100)
            assert not root.property("backendOnline")
            assert not item("mtaPrimary").property("enabled")
            checks.append("missing_capability_and_non_loopback_fail_closed")
            assert not fixture.errors, fixture.errors
            assert not warnings, warnings
            for name in ("mtaPrimary", "mtaSecondary", "mtaReceiveTab", "mtaSendTab", "mtaFiles"):
                control = item(name)
                assert control.width() >= 100 and control.height() >= 54
            checks.append("long_screen_primary_controls_min_100x54")
            result = {"evidence": "HOST_QML_QA_ONLY", "device_tested": False, "phone_interoperability_tested": False, "qt_version": __import__("PyQt5.QtCore", fromlist=["QT_VERSION_STR"]).QT_VERSION_STR, "canvas": [800, 268], "checks": checks, "screenshots": captures, "qml_warnings": warnings, "actions": fixture.actions}
            (output / "ui-result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            print("HOST_MTA_UI_QA_PASS checks=" + str(len(checks)) + " screenshots=" + str(len(captures)))
            print("EVIDENCE_DIR=" + str(output.resolve()))
            app.exit(0)
        except Exception:
            import traceback
            traceback.print_exc()
            print("HOST_MTA_UI_QA_FAIL warnings=" + repr(warnings))
            app.exit(1)

    if args.interactive:
        root.setProperty("serviceUrl", "http://127.0.0.1:" + str(server.server_address[1]))
        root.setProperty("token", fixture.token)
        root.setProperty("nicknameEditorAvailable", True)
        invoke("refresh")
    else:
        QTimer.singleShot(100, qa)
    try:
        return app.exec_()
    finally:
        invoke("prepareLeave")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
