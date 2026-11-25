"""HOST ONLY checks. Never creates an Adb instance or accesses a device."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import gui_trial as gui


def snapshot():
    rows = []
    for pid, name in enumerate(gui.CORE, 10):
        parent = {"pid": 1, "ppid": 0, "starttime": 1, "exe": "/sbin/init", "comm": "init"}
        rows.append({"pid": pid, "ppid": 1, "starttime": 100 + pid,
                     "exe": "/usr/bin/" + name, "comm": name, "parent": parent})
    return {"boot_id": "01234567-89ab-cdef-0123-456789abcdef", "hashes": {
        "/usr/bin/Z03": "a" * 64, "/usr/bin/control_engine": "b" * 64,
        "/usr/bin/zyb_z03_launch.sh": "c" * 64}, "processes": rows}


def events():
    return [{"event": "browser685.qt_gui", "qt_version": "6.8.5", "platform": "wayland", "surface_exposed": True},
            {"event": "browser685.qt_gles", "context_created": True, "make_current": True,
             "gl_error": 0, "swap_called": True, "vendor": "HOST_FIXTURE_ONLY"},
            {"event": "browser685.qt_gui_done", "rendered": True, "expose_attempted": True}]


def encoded(rows):
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


class GuiHostChecks(unittest.TestCase):
    def test_prepare_does_not_touch_adb(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            payload, out = base / "payload", base / "result"
            (payload / "bin").mkdir(parents=True)
            (payload / "lib").mkdir()
            (payload / gui.BINARY).write_bytes(b"HOST_ONLY_NOT_AN_ARM_ELF")
            (payload / "lib/libQt6Core.so.6").write_bytes(b"HOST_ONLY_NO_QT")
            out.mkdir()
            with patch.object(gui, "Adb", side_effect=AssertionError("ADB must not be touched")):
                manifest, state = gui.prepare_only(payload, out, snapshot(), 1)
            self.assertEqual(len(manifest["files"]), 2)
            self.assertTrue(gui.REMOTE_PATTERN.fullmatch(state["remote"]))
            self.assertEqual((out / "guardian.py").read_text(), gui.GUARDIAN)

    def test_sandboxed_user_must_not_be_root(self):
        with self.assertRaises(ValueError):
            gui.prepare_only(Path("unread"), Path("unwritten"), snapshot(), 1, uid=0)

    def test_baseline_detects_parent_restart(self):
        first, second = snapshot(), snapshot()
        second["processes"][0]["parent"]["starttime"] += 1
        self.assertNotEqual(gui.anchor(first), gui.anchor(second))

    def test_no_webengine_or_physical_claim_from_gl_fixture(self):
        result = gui.page_free_gui_events(encoded(events()))
        self.assertTrue(result["passed"])
        self.assertFalse(result["physical_display_verified"])
        self.assertFalse(result["webengine_tested"])
        self.assertFalse(result["swap_success_verified"])

    def test_makecurrent_failure_cannot_pass(self):
        rows = events()
        rows[1]["make_current"] = False
        self.assertFalse(gui.page_free_gui_events(encoded(rows))["passed"])

    def test_unexpected_or_corrupt_events_fail_without_host_exception(self):
        for value in (b"", b"not-json\n", b"[]\n", b"\xff", encoded(events() + [events()[0]])):
            with self.subTest(value=value[:20]):
                self.assertFalse(gui.page_free_gui_events(value)["passed"])

    def test_vendor_printf_is_counted_without_losing_fixed_events(self):
        raw = b"Mali diagnostic HOST_FIXTURE\n" + encoded(events()) + b"driver fini HOST_FIXTURE\n"
        result = gui.page_free_gui_events(raw)
        self.assertTrue(result["passed"])
        self.assertEqual(result["nonstructured_line_count"], 2)

    def test_event_reordering_cannot_pass(self):
        rows = events()
        rows[0], rows[1] = rows[1], rows[0]
        self.assertFalse(gui.page_free_gui_events(encoded(rows))["passed"])

    def test_wrong_qt_version_cannot_pass(self):
        rows = events()
        rows[0]["qt_version"] = "5.10.1"
        self.assertFalse(gui.page_free_gui_events(encoded(rows))["passed"])

    def test_all_remote_sources_are_python35_and_adb_bounded(self):
        remote = gui.AREA + "/gui/" + "a" * 16 + "-20261020-130000-123456"
        source_parts = [gui.DEVICE_COMMON + "REMOTE=" + repr(remote) + "\nEXPECTED="
                        + repr(gui.anchor(snapshot())) + "\nPAYLOAD_BYTES=50000000\n" + gui.PREPARE,
                        "REMOTE=" + repr(remote) + "\nDIRS=" + repr(["plugins/" + "x" * 32 for _ in range(40)])
                        + "\n" + gui.DEVICE_COMMON + gui.UPLOAD_DIRS,
                        "REMOTE=" + repr(remote) + "\n" + gui.DEVICE_COMMON + gui.VERIFY_START,
                        "REMOTE=" + repr(remote) + "\n" + gui.DEVICE_COMMON + gui.COLLECT_STATUS]
        for source in source_parts:
            ast.parse(source, feature_version=5)
            self.assertLess(len(gui.remote_command(source).encode()), 4096)
        ast.parse(gui.GUARDIAN, feature_version=5)

    def test_gui_payload_does_not_require_a_fake_webengine_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "bin").mkdir()
            (base / "lib").mkdir()
            (base / gui.BINARY).write_bytes(b"HOST_FIXTURE")
            (base / "lib/a.so").write_bytes(b"HOST_FIXTURE")
            manifest = gui.source_manifest(base)
            self.assertFalse(any("QtWebEngine" in row["path"] for row in manifest["files"]))
            (base / "lib/font.ttf").write_bytes(b"PROHIBITED")
            with self.assertRaises(ValueError):
                gui.source_manifest(base)

    def test_large_file_transfer_has_finite_scaled_timeout(self):
        self.assertEqual(gui.transfer_timeout(0), 30)
        self.assertGreater(gui.transfer_timeout(64 * 1024 * 1024), 30)
        self.assertEqual(gui.transfer_timeout(1024 * 1024 * 1024), 180)

    def test_collect_new_transport_requires_unchanged_device_and_preserves_origin(self):
        before = snapshot()
        state = {"transport": 1, "expected": gui.anchor(before)}
        selected = gui.bind_collect_target(state, 2, snapshot())
        self.assertEqual(selected["transport"], 2)
        self.assertEqual(selected["origin_transport"], 1)
        self.assertEqual(state["transport"], 1)
        for mutation in ("boot", "file", "parent"):
            changed = snapshot()
            if mutation == "boot":
                changed["boot_id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
            elif mutation == "file":
                changed["hashes"]["/usr/bin/Z03"] = "d" * 64
            else:
                changed["processes"][0]["parent"]["starttime"] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                gui.bind_collect_target(state, 2, changed)

    def collect_fixture(self, out, corrupt=False):
        # Fixed HOST bytes stand in for transport; no Adb construction, ELF or
        # Qt execution occurs. This checks evidence checksum enforcement only.
        payloads = {"app.stdout.raw": encoded(events()), "app.stderr.raw": b"HOST_FIXTURE_WARNING\n",
                    "result.literal": b"{'lifecycle_passed': True}\n", "COMPLETE": b""}
        class TransportFixture:
            def __init__(self):
                self.out = out
            def python(self, label, source):
                if label == "after":
                    return snapshot(), {}
                return {"available": list(payloads), "complete": True, "evidence": {
                    name: {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                    for name, body in payloads.items()}}, {}
            def run(self, label, args):
                name = args[1].rsplit("/", 1)[-1]
                body = payloads[name]
                if corrupt and name == "app.stderr.raw":
                    body += b"CORRUPTED_IN_TRANSIT"
                Path(args[2]).write_bytes(body)
                return "", {"host_exit": 0}
        state = {"remote": gui.AREA + "/gui/" + "a" * 16 + "-20261020-130000-123456",
                 "transport": 2, "manifest_sha256": "b" * 64, "expected": gui.anchor(snapshot())}
        return gui.collect(TransportFixture(), state, 0)

    def test_collect_binds_device_bytes_and_sha_for_all_fixed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.collect_fixture(Path(temp))
            self.assertTrue(result["passed"])
            self.assertTrue((Path(temp) / "evidence-bindings.json").is_file())

    def test_collect_adb_success_does_not_hide_changed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "size/checksum differs"):
                self.collect_fixture(Path(temp), corrupt=True)

    def test_resume_upload_binds_original_host_bytes_without_adb(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            saved, out, payload = base / "logs/original", base / "logs/resume", base / "source"
            saved.mkdir(parents=True)
            out.mkdir()
            (payload / "bin").mkdir(parents=True)
            (payload / "lib").mkdir()
            (payload / gui.BINARY).write_bytes(b"HOST_ONLY_NEVER_EXECUTED")
            (payload / "lib/a.so").write_bytes(b"HOST_ONLY_NO_QT")
            gui.prepare_only(payload, saved, snapshot(), 1)
            with patch.object(gui, "WORKSPACE", base), patch.object(gui, "Adb", side_effect=AssertionError("No ADB")):
                manifest, state = gui.load_resume_upload(saved, payload, snapshot(), 2, out, 65534, 65534)
                self.assertEqual(state["origin_transport"], 1)
                self.assertEqual(state["transport"], 2)
                self.assertTrue(state["resume_upload"])
                self.assertEqual((saved / "guardian.py").read_bytes(), (out / "guardian.py").read_bytes())
                self.assertEqual((saved / "config.literal").read_bytes(), (out / "config.literal").read_bytes())

    def test_resume_upload_refuses_changed_host_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            saved, out, payload = base / "logs/original", base / "logs/resume", base / "source"
            saved.mkdir(parents=True)
            out.mkdir()
            (payload / "bin").mkdir(parents=True)
            (payload / "lib").mkdir()
            (payload / gui.BINARY).write_bytes(b"HOST_ONLY_NEVER_EXECUTED")
            (payload / "lib/a.so").write_bytes(b"HOST_ONLY_NO_QT")
            gui.prepare_only(payload, saved, snapshot(), 1)
            (payload / "lib/a.so").write_bytes(b"HOST_ONLY_CHANGED")
            with patch.object(gui, "WORKSPACE", base), self.assertRaisesRegex(ValueError, "payload differs"):
                gui.load_resume_upload(saved, payload, snapshot(), 2, out, 65534, 65534)

    def test_staging_remote_and_unchanged_guardian_are_bound(self):
        self.assertEqual(hashlib.sha256(gui.GUARDIAN.encode()).hexdigest(),
                         "e98cf94bf1bc7fe61a77fcdde00f810b476dc271b233b28c7f940b4275352534")
        remote = gui.AREA + "/gui/" + "a" * 16 + "-20261020-130000-123456"
        bindings = {name: {"bytes": size, "sha256": checksum}
                    for name, size, checksum in [("guardian.py", 10812, "a" * 64),
                                                 ("config.literal", 10000, "b" * 64)]}
        for body in ("CONTROL_BINDINGS=" + repr(bindings) + "\n" + gui.STAGING_VERIFY, gui.VERIFY_START):
            source = "REMOTE=" + repr(remote) + "\n" + gui.DEVICE_COMMON + body
            ast.parse(source, feature_version=5)
            self.assertLess(len(gui.remote_command(source).encode()), 4096)


if __name__ == "__main__":
    unittest.main(verbosity=2)
