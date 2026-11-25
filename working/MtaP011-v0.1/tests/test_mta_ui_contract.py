"""Host-only static contract checks; no device or wireless control."""
from pathlib import Path
import re
import unittest

BASE = Path(__file__).resolve().parents[1]
QML = BASE / "device" / "MtaPage.qml"


class UiContractTests(unittest.TestCase):
    def test_canvas_and_qt510(self):
        text = QML.read_text(encoding="utf-8")
        self.assertIn("import QtQuick 2.10", text)
        self.assertIn("width: 800; height: 268", text)
        self.assertNotRegex(text, r"\brotation\s*:")
        self.assertNotRegex(text, r"\by\s*:\s*106\b")
        self.assertNotRegex(text, r"property\s+\w+\s+data\s*:")

    def test_ipc_has_no_shell_or_remote_endpoint(self):
        text = QML.read_text(encoding="utf-8")
        self.assertIn("127\\.0\\.0\\.1", text)
        self.assertIn('"X-P011-MTA-Token"', text)
        self.assertIn('request("/v1/status"', text)
        self.assertIn('request("/v1/action"', text)
        self.assertNotRegex(text, r"(?i)\b(killall|remount|adb|subprocess|webchannel)\b")
        self.assertIn("fileIds: ids", text)
        self.assertNotIn("filePaths:", text)

    def test_defaults_do_not_start_radio_or_show_fake_devices(self):
        text = QML.read_text(encoding="utf-8")
        self.assertIn('property bool hostPreview: false', text)
        self.assertIn('property string serviceUrl: ""', text)
        self.assertIn('devices: []', text)
        self.assertIn('Component.onCompleted: refresh()', text)
        self.assertNotRegex(text, r'Component\.onCompleted[^\n]*issue\(')
        self.assertIn('value === true || (value && value.available === true)', text)

    def test_no_bundled_fonts(self):
        for path in (BASE / "device").rglob("*"):
            self.assertNotIn(path.suffix.lower(), (".ttf", ".otf", ".ttc", ".woff", ".woff2"))
        self.assertNotIn("FontLoader", (BASE / "device" / "MtaLabel.qml").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
