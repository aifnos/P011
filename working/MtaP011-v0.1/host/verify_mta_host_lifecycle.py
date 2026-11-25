# -*- coding: utf-8 -*-
"""HOST_ONLY real-QML lifecycle QA with delayed loopback HTTP fixtures.

No ADB, Bluetooth, ConnMan or device files. All catalog rows, tokens and server
responses are synthetic HOST fixtures. Tests actual MtaHost.qml request epochs,
file-picker selection invalidation and keyboard visibility after open/cancel.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = Path(__file__).resolve().parents[1]


class Fixture:
    def __init__(self, label):
        self.label = label
        self.token = secrets.token_urlsafe(24)
        self.rows = [{"id": "host-" + label, "name": "Text/HOST_ONLY-" + label + ".txt", "size": 20}]
        self.catalog_started = threading.Event()
        self.catalog_release = threading.Event()
        self.catalog_release.set()
        self.bootstrap_started = threading.Event()
        self.bootstrap_release = threading.Event()
        self.bootstrap_release.set()
        self.actions = []
    def status(self):
        return {"state": "idle", "nickname": "HOST_ONLY " + self.label,
                "devices": [], "received": [], "request": None, "transfer": {},
                "discoverable": False, "scanning": False,
                "capabilities": {"receive": False, "send": False, "scan": False, "rename": True},
                "reason": "HOST_ONLY：模拟服务，无无线操作"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *unused):
        pass
    def reply(self, code, value):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Abort of a superseded request is expected and must be harmless.
            pass
    def do_GET(self):
        fixture = self.server.fixture
        if self.path == "/v1/bootstrap":
            token_at_request = fixture.token
            fixture.bootstrap_started.set()
            fixture.bootstrap_release.wait(6)
            self.reply(200, {"token": token_at_request})
            return
        if self.headers.get("X-P011-MTA-Token") != fixture.token:
            self.reply(403, {"error": "HOST fixture auth mismatch"})
            return
        if self.path == "/v1/status":
            self.reply(200, fixture.status())
        elif self.path == "/v1/files":
            rows_at_request = [dict(row) for row in fixture.rows]
            fixture.catalog_started.set()
            fixture.catalog_release.wait(6)
            self.reply(200, {"files": rows_at_request})
        else:
            self.reply(404, {"error": "Unknown fixture route"})
    def do_POST(self):
        fixture = self.server.fixture
        if self.headers.get("X-P011-MTA-Token") != fixture.token:
            self.reply(403, {"error": "HOST fixture auth mismatch"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 4096:
                raise ValueError("fixture body limit")
            action = json.loads(self.rfile.read(size).decode("utf-8"))
            if action.get("action") != "rename":
                raise ValueError("HOST lifecycle fixture does not accept radio actions")
            fixture.actions.append(action)
            self.reply(200, fixture.status())
        except (ValueError, UnicodeError):
            self.reply(409, {"error": "Unsupported fixture action"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=BASE / "results" / "ui-host-lifecycle")
    arguments = parser.parse_args()
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    os.environ["QT_QUICK_BACKEND"] = "software"
    from PyQt5.QtCore import Q_ARG, QMetaObject, QObject, QPoint, QTimer, QUrl, Qt, QT_VERSION_STR
    from PyQt5.QtGui import QFont, QFontDatabase, QGuiApplication
    from PyQt5.QtQuick import QQuickView
    from PyQt5.QtTest import QSignalSpy, QTest

    fixtures = [Fixture("A"), Fixture("B")]
    servers = []
    threads = []
    for fixture in fixtures:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.fixture = fixture
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)

    app = QGuiApplication(sys.argv[:1])
    if os.name == "nt":
        font = Path("C:/Windows/Fonts/msyh.ttc")
        if font.is_file():
            QFontDatabase.addApplicationFont(str(font))
        app.setFont(QFont("Microsoft YaHei", 12))
    view = QQuickView()
    warnings = []
    view.engine().warnings.connect(lambda rows: warnings.extend(row.toString() for row in rows))
    view.setResizeMode(QQuickView.SizeRootObjectToView)
    view.rootContext().setContextProperty("nativeFontFamily", "Microsoft YaHei" if os.name == "nt" else "sans-serif")
    view.setSource(QUrl.fromLocalFile(str(BASE / "device" / "MtaHost.qml")))
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"evidence": "HOST_ONLY_QML_LIFECYCLE", "device_tested": False,
              "phone_interoperability_tested": False, "radio_mutated": False,
              "qt_version": QT_VERSION_STR, "canvas": [800, 268], "checks": [],
              "screenshots": [], "qml_warnings": warnings, "pass": False}

    if view.status() == QQuickView.Error:
        report["failure"] = "QML load failed"
        report["qml_warnings"] += [row.toString() for row in view.errors()]
        (output / "HOST_ONLY-result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        for server in servers:
            server.shutdown()
            server.server_close()
        return 1

    root = view.rootObject()
    root.setProperty("hostPreview", True)
    view.resize(800, 268)
    view.setTitle("HOST_ONLY P011 MtaHost lifecycle fixture — not device or phone QA")
    view.show()
    a, b = fixtures
    endpoints = ["http://127.0.0.1:" + str(server.server_address[1]) for server in servers]
    page = root.findChild(QObject, "mtaPage")
    board = root.findChild(QObject, "mtaKeyboard")
    picker = root.findChild(QObject, "mtaFilePicker")

    def variant(value):
        return value.toVariant() if hasattr(value, "toVariant") else value
    def prop(name):
        return variant(root.property(name))
    def invoke(target, name, *values):
        return QMetaObject.invokeMethod(target, name, *[Q_ARG("QVariant", value) for value in values])
    def wait_for(predicate, reason, maximum=3000):
        deadline = time.monotonic() + maximum / 1000.0
        while not predicate() and time.monotonic() < deadline:
            QTest.qWait(10)
        assert predicate(), reason
    def capture(name):
        QTest.qWait(50)
        grab = root.grabToImage()
        assert grab, "HOST screenshot request failed"
        if grab.image().isNull():
            QSignalSpy(grab.ready).wait(3000)
        filename = "HOST_ONLY-" + name + ".png"
        assert grab.saveToFile(str(output / filename)), "HOST screenshot write failed"
        assert (grab.image().width(), grab.image().height()) == (800, 268)
        report["screenshots"].append(filename)
    def connect(index):
        root.setProperty("bootstrapAllowed", False)
        root.setProperty("endpoint", endpoints[index])
        root.setProperty("accessToken", fixtures[index].token)
        wait_for(lambda: page.property("backendOnline"), "New HOST service did not become online")

    def qa():
        try:
            assert page is not None and board is not None and picker is not None
            connect(0)
            assert not a.actions and not b.actions
            capture("01-no-radio-default")
            invoke(root, "fetchFiles", "select")
            wait_for(lambda: len(prop("fileRows")) == 1, "Initial HOST catalog missing")
            invoke(root, "choose", prop("fileRows")[0])
            assert len(prop("picked")) == 1
            capture("02-selected-host-file")

            # Old catalog response is held on the actual HTTP server. Switch
            # endpoint before releasing it; production QML must abort/ignore.
            a.catalog_started.clear()
            a.catalog_release.clear()
            invoke(root, "fetchFiles", "select")
            wait_for(a.catalog_started.is_set, "Delayed catalog request did not start")
            connect(1)
            assert prop("picked") == []
            assert variant(page.property("selectedFiles")) == []
            invoke(root, "fetchFiles", "select")
            wait_for(lambda: len(prop("fileRows")) == 1 and prop("fileRows")[0]["id"] == "host-B", "Current endpoint catalog missing")
            a.catalog_release.set()
            QTest.qWait(200)
            assert prop("fileRows")[0]["id"] == "host-B"
            assert prop("accessToken") == b.token
            assert prop("picked") == []
            report["checks"].append("delayed_old_endpoint_catalog_cannot_restore_rows_or_selection")
            capture("03-new-endpoint-no-stale-selection")

            # Same endpoint, different token: an old authorized response still
            # cannot repopulate files after the connection generation changes.
            b.catalog_started.clear()
            b.catalog_release.clear()
            invoke(root, "fetchFiles", "select")
            wait_for(b.catalog_started.is_set, "Delayed token catalog request did not start")
            b.token = secrets.token_urlsafe(24)
            root.setProperty("accessToken", b.token)
            assert prop("fileRows") == [] and prop("picked") == []
            b.catalog_release.set()
            QTest.qWait(200)
            assert prop("fileRows") == [] and prop("picked") == []
            assert prop("accessToken") == b.token
            report["checks"].append("delayed_old_token_catalog_cannot_restore_rows")
            capture("04-token-switch-clears-catalog")

            # Synthetic bootstrap A is delayed. B bootstrap must win even after
            # A returns its formerly valid token; no token values enter report.
            root.setProperty("bootstrapAllowed", False)
            root.setProperty("accessToken", "")
            root.setProperty("endpoint", endpoints[0])
            a.bootstrap_started.clear()
            a.bootstrap_release.clear()
            root.setProperty("bootstrapAllowed", True)
            invoke(root, "bootstrap")
            wait_for(a.bootstrap_started.is_set, "Delayed bootstrap did not start")
            root.setProperty("endpoint", endpoints[1])
            wait_for(lambda: prop("accessToken") == b.token, "Replacement bootstrap did not set current token")
            a.bootstrap_release.set()
            QTest.qWait(200)
            assert prop("accessToken") == b.token
            assert prop("fileRows") == [] and prop("picked") == []
            report["checks"].append("delayed_old_bootstrap_cannot_overwrite_current_token")
            root.setProperty("bootstrapAllowed", False)
            root.setProperty("stage", "mta")
            wait_for(lambda: page.property("backendOnline"), "HOST page did not recover after bootstrap")
            capture("05-current-bootstrap-main")

            # Actual pointer cancel exercises the keyboard signal and host
            # parent visibility binding, not a screenshot-only mock stage.
            root.setProperty("stage", "keyboard")
            invoke(board, "open", "HOST_ONLY name", False)
            QTest.qWait(70)
            assert board.property("visible") and not picker.property("visible")
            capture("06-keyboard-open")
            QTest.mouseClick(view, Qt.LeftButton, Qt.NoModifier, QPoint(670, 23))
            wait_for(lambda: prop("stage") == "mta", "Keyboard cancel did not return to main")
            assert not board.property("visible")
            invoke(root, "fetchFiles", "select")
            wait_for(lambda: len(prop("fileRows")) == 1, "Catalog after keyboard cancel missing")
            assert picker.property("visible")
            assert not board.property("visible")
            capture("07-file-page-after-keyboard-cancel")
            report["checks"].append("keyboard_open_cancel_does_not_overlay_file_page")

            root.setProperty("stage", "keyboard")
            invoke(board, "open", "HOST_ONLY name", False)
            invoke(board, "finish")
            wait_for(lambda: prop("stage") == "mta", "Keyboard finish did not return to main")
            invoke(root, "fetchFiles", "select")
            wait_for(lambda: len(prop("fileRows")) == 1, "Catalog after keyboard finish missing")
            assert picker.property("visible") and not board.property("visible")
            capture("08-file-page-after-keyboard-finish")
            report["checks"].append("keyboard_finish_does_not_overlay_file_page")
            assert all(action.get("action") == "rename" for action in a.actions + b.actions)
            report["checks"].append("no_discovery_scan_or_transfer_actions_in_fixture")
            assert not warnings, warnings
            report["pass"] = True
            print("HOST_ONLY_QML_LIFECYCLE_PASS checks=" + str(len(report["checks"])) + " screenshots=" + str(len(report["screenshots"])))
            app.exit(0)
        except Exception as error:
            import traceback
            traceback.print_exc()
            report["failure"] = type(error).__name__ + ": " + str(error)
            print("HOST_ONLY_QML_LIFECYCLE_FAIL")
            app.exit(1)
        finally:
            # Do not write fixture credentials, addresses or private key data.
            (output / "HOST_ONLY-result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
            print("HOST_ONLY_EVIDENCE_DIR=" + str(output))

    QTimer.singleShot(50, qa)
    try:
        return app.exec_()
    finally:
        for fixture in fixtures:
            fixture.catalog_release.set()
            fixture.bootstrap_release.set()
        invoke(page, "prepareLeave")
        view.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(3)


if __name__ == "__main__":
    sys.exit(main())
