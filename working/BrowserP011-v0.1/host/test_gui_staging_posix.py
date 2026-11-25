"""HOST LINUX ONLY: real root/POSIX modes and hashes, no device/GUI execution.

Run in a new network-disabled read-only container with a private /mnt/data
tmpfs. Only the stock snapshot function is replaced by an explicit HOST
fixture; the actual uploaded-file staging verifier runs unchanged.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest

import gui_trial as gui
from test_gui_trial import snapshot


class PosixStagingChecks(unittest.TestCase):
    index = 0

    @classmethod
    def setUpClass(cls):
        if os.name != "posix" or os.getuid() != 0:
            raise unittest.SkipTest("Requires isolated Linux root HOST container")
        area = Path(gui.AREA)
        area.mkdir(mode=0o755)
        marker = area / ".area-owner"
        marker.write_bytes(b"p011.browser.area.v1\n")
        marker.chmod(0o600)
        (area / "gui").mkdir(mode=0o755)

    def staged(self):
        type(self).index += 1
        root = Path(gui.AREA) / "gui" / ("host-staging-" + str(self.index))
        root.mkdir(mode=0o755)
        control, payload = root / "control", root / "payload"
        control.mkdir(mode=0o700)
        payload.mkdir(mode=0o700)
        (payload / "bin").mkdir(mode=0o755)
        (payload / "lib").mkdir(mode=0o755)
        (payload / gui.BINARY).write_bytes(b"HOST_ONLY_NEVER_EXECUTED")
        (payload / "lib/a.so").write_bytes(b"HOST_ONLY_NOT_A_LIBRARY")
        manifest = gui.source_manifest(payload)
        config = {"expected": gui.anchor(snapshot()), "manifest": manifest, "uid": 65534, "gid": 65534,
                  "controls": {"guardian.py": hashlib.sha256(gui.GUARDIAN.encode()).hexdigest()}}
        (control / "guardian.py").write_bytes(gui.GUARDIAN.encode())
        (control / "config.literal").write_text(repr(config) + "\n")
        # Reproduce actual old Windows ADB push behavior exactly.
        for path in list(control.iterdir()) + [payload / gui.BINARY, payload / "lib/a.so"]:
            path.chmod(0o666)
        return root, gui.control_bindings(control)

    def verify(self, root, bindings):
        source = gui.DEVICE_COMMON + "\nsnapshot=lambda:HOST_SNAPSHOT\n" + gui.STAGING_VERIFY
        exec(compile(source, "HOST_ONLY_STAGING_VERIFIER", "exec"), {
            "REMOTE": str(root), "CONTROL_BINDINGS": bindings, "HOST_SNAPSHOT": snapshot()})

    def test_0666_upload_is_hashed_before_becoming_private_executable(self):
        root, bindings = self.staged()
        self.verify(root, bindings)
        self.assertEqual(stat.S_IMODE((root / "control/config.literal").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((root / "control/guardian.py").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((root / "payload" / gui.BINARY).stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((root / "payload/lib/a.so").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((root / "payload").stat().st_mode), 0o700)
        self.assertFalse((root / "app").exists())
        self.assertFalse((root / "control/LAUNCH_REQUESTED").exists())

    def test_changed_payload_refuses_all_permission_repairs(self):
        root, bindings = self.staged()
        (root / "payload/lib/a.so").write_bytes(b"HOST_ONLY_CORRUPTED")
        with self.assertRaisesRegex(ValueError, "owner/size|checksum"):
            self.verify(root, bindings)
        self.assertEqual(stat.S_IMODE((root / "control/guardian.py").stat().st_mode), 0o666)
        self.assertEqual(stat.S_IMODE((root / "payload" / gui.BINARY).stat().st_mode), 0o666)
        self.assertFalse((root / "control/STAGING_VERIFIED.literal").exists())

    def test_changed_control_refuses_mode_repair(self):
        root, bindings = self.staged()
        (root / "control/guardian.py").write_bytes(b"HOST_ONLY_CORRUPTED")
        with self.assertRaisesRegex(ValueError, "owner/size|checksum"):
            self.verify(root, bindings)
        self.assertEqual(stat.S_IMODE((root / "control/guardian.py").stat().st_mode), 0o666)

    def test_any_prior_launch_or_raw_record_refuses_resume(self):
        for name in ("LAUNCH_REQUESTED", "COMPLETE", "app.stdout.raw"):
            root, bindings = self.staged()
            (root / "control" / name).write_bytes(b"")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "already used"):
                self.verify(root, bindings)

    def test_public_payload_refuses_resume(self):
        root, bindings = self.staged()
        (root / "payload").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "no longer private"):
            self.verify(root, bindings)

    def test_extra_unmanifested_file_refuses_resume(self):
        root, bindings = self.staged()
        (root / "payload/lib/extra.so").write_bytes(b"HOST_ONLY_UNEXPECTED")
        with self.assertRaisesRegex(ValueError, "file set differs"):
            self.verify(root, bindings)

    def test_root_staging_does_not_execute_gui_or_guardian(self):
        root, bindings = self.staged()
        self.verify(root, bindings)
        self.assertEqual(set(path.name for path in root.iterdir()), {"control", "payload"})
        self.assertEqual(set(path.name for path in (root / "control").iterdir()),
                         {"config.literal", "guardian.py", "STAGING_VERIFIED.literal"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
