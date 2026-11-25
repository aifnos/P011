"""HOST-only checks of the actual MtaPage.qml; no HTTP, process or device IO.

Use the same QQuickView/production component route as preview_mta_ui.py. Status
values below are explicit HOST fixtures injected into the page, not transfer
results or a new preview service. The endpoint/token stay empty throughout.
"""
import os
from pathlib import Path
import sys
import unittest

os.environ["QT_QPA_PLATFORM"] = "offscreen"
os.environ["QT_QUICK_BACKEND"] = "software"

from PyQt5.QtCore import QObject, QUrl, QT_VERSION_STR
from PyQt5.QtGui import QFont, QGuiApplication
from PyQt5.QtQuick import QQuickView

BASE = Path(__file__).resolve().parents[1]


class SendStageUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
        if os.name == "nt":
            cls.app.setFont(QFont("Microsoft YaHei", 12))
        print("HOST_ONLY_QML_SEND_STAGE qt=" + QT_VERSION_STR + " device=false phone=false network=false")

    def setUp(self):
        self.warnings = []
        self.view = QQuickView()
        self.view.engine().warnings.connect(lambda rows: self.warnings.extend(row.toString() for row in rows))
        self.view.setResizeMode(QQuickView.SizeRootObjectToView)
        self.view.rootContext().setContextProperty("nativeFontFamily", "Microsoft YaHei" if os.name == "nt" else "sans-serif")
        self.view.setSource(QUrl.fromLocalFile(str(BASE / "device" / "MtaPage.qml")))
        self.assertNotEqual(self.view.status(), QQuickView.Error, [row.toString() for row in self.view.errors()])
        self.page = self.view.rootObject()
        self.view.resize(800, 268)
        self.view.show()
        self.app.processEvents()

    def tearDown(self):
        self.assertEqual(self.page.property("serviceUrl"), "")
        self.assertEqual(self.page.property("token"), "")
        self.assertEqual(self.warnings, [])
        self.view.close()
        self.view.deleteLater()
        self.app.processEvents()

    def text(self, name):
        item = self.page.findChild(QObject, name)
        self.assertIsNotNone(item, name)
        return item.property("text")

    def state(self, stage="transferring", current="connecting", transfer=None, request=None, reason=""):
        self.page.setProperty("status", {
            "state": current, "nickname": "HOST", "devices": [], "received": [],
            "request": request, "transfer": transfer if transfer is not None else {
                "direction": "send", "bytes": 3932160, "totalBytes": 10485760, "totalFiles": 3},
            "sendLifecycle": {"stage": stage}, "reason": reason,
            "capabilities": {"send": {"available": False}, "receive": {"available": False}},
            "discoverable": False, "scanning": False,
        })
        self.page.setProperty("backendOnline", True)
        self.app.processEvents()

    def test_awaiting_confirmation_has_peer_confirmation_text_without_changing_gate(self):
        self.state("awaiting_confirmation")
        self.assertEqual(self.text("mtaState"), "等待对方确认")
        self.assertEqual(self.text("mtaInfo"), "请在对方设备上确认接收文件")
        self.assertEqual(self.page.property("currentState"), "connecting")
        self.assertFalse(self.page.findChild(QObject, "mtaSecondary").property("enabled"))
        self.assertEqual(self.text("mtaPrimary"), "取消传输")

    def test_all_bytes_sent_still_await_result_without_completion(self):
        self.state("awaiting_result", transfer={"direction": "send", "bytes": 1024,
                   "totalBytes": 1024, "totalFiles": 2, "localBytesVerified": True,
                   "peerCompletionVerified": False})
        self.assertEqual(self.text("mtaState"), "等待完成结果")
        self.assertIn("等待对方完成确认", self.text("mtaInfo"))
        self.assertEqual(self.text("mtaProgressText"), "1 KB / 1 KB · 100.0%")
        self.assertEqual(self.text("mtaProgressDetails"), "发送 2 个文件")
        self.assertNotIn("传输完成", self.text("mtaState"))

    def test_send_missing_files_done_uses_bytes_percent_and_total_only(self):
        self.state(current="transferring")
        self.assertEqual(self.text("mtaProgressText"), "3.8 MB / 10.0 MB · 37.5%")
        self.assertEqual(self.text("mtaProgressDetails"), "发送 3 个文件")
        self.assertNotIn("已完成", self.text("mtaProgressDetails"))
        self.assertAlmostEqual(self.page.property("progressRatio"), .375)

    def test_actual_files_done_is_displayed_including_real_zero(self):
        for done in (0, 1, 3):
            with self.subTest(done=done):
                self.state(transfer={"direction": "send", "bytes": 100, "totalBytes": 300,
                           "totalFiles": 3, "filesDone": done})
                self.assertEqual(self.text("mtaProgressDetails"), "已完成 " + str(done) + " / 3 个文件")

    def test_malformed_files_done_does_not_manufacture_file_completion(self):
        for done in (None, False, "1", -1, .5, 4):
            with self.subTest(done=done):
                self.state(transfer={"direction": "send", "bytes": 100, "totalBytes": 300,
                           "totalFiles": 3, "filesDone": done})
                self.assertEqual(self.text("mtaProgressDetails"), "发送 3 个文件")

    def test_missing_or_invalid_total_files_never_becomes_zero_of_zero(self):
        for total in (None, False, "3", -1, .5):
            with self.subTest(total=total):
                transfer = {"direction": "send", "bytes": 100, "totalBytes": 300, "filesDone": 0}
                if total is not None:
                    transfer["totalFiles"] = total
                self.state(transfer=transfer)
                self.assertEqual(self.text("mtaProgressDetails"), "发送字节不代表对方已保存")
                self.assertNotIn("已完成", self.text("mtaProgressDetails"))

    def test_receive_confirmation_overrides_stale_send_wait(self):
        self.state("awaiting_confirmation", request={"id": "HOST-REQUEST", "name": "HOST",
                   "fileCount": 1, "totalBytes": 10})
        self.assertEqual(self.text("mtaState"), "收到文件请求")
        self.assertEqual(self.text("mtaPrimary"), "接受")
        self.assertEqual(self.text("mtaSecondary"), "拒绝")
        self.assertIn("再选择接受或拒绝", self.text("mtaInfo"))

    def test_terminal_restoring_error_and_completed_ignore_stale_send_stage(self):
        for current, expected in (("restoring", "正在恢复网络"), ("error", "传输未完成"),
                                  ("completed", "传输完成")):
            with self.subTest(current=current):
                self.state("awaiting_result", current=current, reason="HOST terminal reason")
                self.assertEqual(self.text("mtaState"), expected)
                self.assertNotEqual(self.text("mtaInfo"), "字节已发送，正在等待对方完成确认；请勿重复发送")

    def test_send_tab_alone_cannot_relabel_receive_connection(self):
        self.page.setProperty("tab", "send")
        self.state("awaiting_confirmation", transfer={"bytes": 0, "totalBytes": 10, "totalFiles": 1})
        self.assertEqual(self.text("mtaState"), "正在连接")

    def test_receive_existing_file_progress_retains_real_count_without_percent(self):
        self.state(current="transferring", transfer={"bytes": 1024, "totalBytes": 2048,
                   "filesDone": 1, "totalFiles": 2})
        self.assertEqual(self.text("mtaState"), "正在传输")
        self.assertEqual(self.text("mtaProgressText"), "1 KB / 2 KB")
        self.assertEqual(self.text("mtaProgressDetails"), "已完成 1 / 2 个文件")


if __name__ == "__main__":
    unittest.main(verbosity=2)
