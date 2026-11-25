"""HOST-only V4 one-line compatibility tests; no native WPA/ADB/RF runs."""
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
V3_PATH = ROOT / "native/private-p2p-runtime-candidate-20261001-v3/runtime/mta_send_wifi.py"
V4_PATH = ROOT / "native/private-p2p-runtime-candidate-20261001-v4/runtime/mta_send_wifi.py"
V3_SHA = "eacc3a3a602f2ce047106920adaaa6c45a647e1de13a9ba4e90b5858303aff12"
V4_SHA = "ef2f087444c149a988b5b3895225960e85c03d702aa5a084cef62e6222ccf334"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v3 = load("mta_v3_host_config_test", V3_PATH)
v4 = load("mta_v4_host_config_test", V4_PATH)


class StopBeforeFork(Exception):pass


class V4ConfigTests(unittest.TestCase):
    def test_entire_runtime_has_exactly_one_byte_deletion(self):
        old = V3_PATH.read_bytes(); new = V4_PATH.read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(), V3_SHA)
        self.assertEqual(hashlib.sha256(new).hexdigest(), V4_SHA)
        self.assertEqual(old.count(b"\\nupdate_config=0"), 1)
        self.assertEqual(new, old.replace(b"\\nupdate_config=0", b""))
        self.assertEqual(len(old) - len(new), 17)
    def test_actual_generated_config_preserves_every_other_line(self):
        with tempfile.TemporaryDirectory(prefix="mta-host-v4-conf-") as directory:
            backend = object.__new__(v4.LinuxBackend)
            backend.directory = directory; backend.allow_rf = True
            # Exercise real configuration writer only, halt before any fork.
            # Windows has no fork; explicit created mock still never forks.
            with mock.patch.object(v4.os, "pipe", return_value=(101, 102)) as pipes, mock.patch.object(v4.os, "fork", side_effect=StopBeforeFork, create=True):
                with self.assertRaises(StopBeforeFork):backend.spawn_private("mta0123abcd", lambda record: None)
            self.assertEqual(pipes.call_count, 2)
            value = (Path(directory) / "private.conf").read_text(encoding="utf-8")
            self.assertEqual(value, "ctrl_interface=" + os.path.join(directory, "ctrl") + "\np2p_no_group_iface=1\nap_scan=2\n"
                             "device_name=P011\ndevice_type=1-0050F204-1\ndriver_param=mta_p2p_initial=1 control_port=0\n")
            self.assertNotIn("update_config", value)
    def test_invalid_interface_does_not_write_config_or_make_pipe(self):
        with tempfile.TemporaryDirectory(prefix="mta-host-v4-refuse-") as directory:
            backend = object.__new__(v4.LinuxBackend)
            backend.directory = directory; backend.allow_rf = True
            with mock.patch.object(v4.os, "pipe") as pipes:
                with self.assertRaises(v4.LeaseError):backend.spawn_private("wlan0", lambda record: None)
            pipes.assert_not_called(); self.assertEqual(os.listdir(directory), [])
    def test_native_build_keeps_no_write_and_required_feature_flags(self):
        path = ROOT / "native/private-p2p-candidate-20261001-v2/source/p2p-private-v2.config"
        rows = set(path.read_text(encoding="utf-8").splitlines())
        for flag in ("CONFIG_NO_CONFIG_WRITE=y", "CONFIG_WPS=y", "CONFIG_P2P=y", "CONFIG_CTRL_IFACE=y", "CONFIG_BACKEND=file"):
            self.assertIn(flag, rows)
    def test_fixed_upstream_parser_excludes_update_but_accepts_other_fields(self):
        path = ROOT / "native/private-p2p-candidate-20261001-v2/source/wpa_supplicant-2.12.tar.gz"
        with tarfile.open(str(path), "r:gz") as archive:
            config = archive.extractfile("wpa_supplicant-2.12/wpa_supplicant/config.c").read().decode("utf-8")
            make = archive.extractfile("wpa_supplicant-2.12/wpa_supplicant/Makefile").read().decode("utf-8")
        self.assertIn("#ifndef CONFIG_NO_CONFIG_WRITE\n\t{ INT(update_config), 0 },\n#endif", config)
        self.assertIn("ifdef CONFIG_NO_CONFIG_WRITE\nCFLAGS += -DCONFIG_NO_CONFIG_WRITE\nendif", make)
        for field in ("STR(ctrl_interface)", "INT(p2p_no_group_iface)", "INT(ap_scan)", "STR_RANGE(device_name", "FUNC(device_type)", "STR(driver_param)"):
            self.assertIn(field, config)
    def test_diagnostics_enums_and_unknown_errno_contract_unchanged(self):
        self.assertEqual(v3.FAILURE_PHASES, v4.FAILURE_PHASES)
        self.assertEqual(v3.NETLINK_COMMANDS, v4.NETLINK_COMMANDS)
        self.assertEqual(v3.DIAGNOSTIC_STAGES, v4.DIAGNOSTIC_STAGES)
        error = OSError(16, "HOST_PRIVATE_ERROR")
        self.assertEqual(v3.failure_diagnostic("private_spawn", error), v4.failure_diagnostic("private_spawn", error))
        self.assertEqual(v4.failure_diagnostic("private_spawn", RuntimeError("HOST_PRIVATE_ERROR"))["failure_errno"], 0)
    def test_runtime_still_go_only_default_disabled_and_python35(self):
        self.assertEqual(v3.WPA_SHA256, v4.WPA_SHA256)
        self.assertEqual(v3.DEVICE_PENDING, v4.DEVICE_PENDING)
        self.assertEqual(v3.DEVICE_LOCK, v4.DEVICE_LOCK)
        ast.parse(V4_PATH.read_text(encoding="utf-8"), feature_version=(3, 5))
        backend = object.__new__(v4.SendWifiBackend)
        backend.backend = mock.Mock()
        backend.backend.capabilities.return_value = {"phys": [{"iftypes": ["p2p_client", "p2p_go"], "combinations": [{"station_plus_go_same_channel": True}]}]}
        result = backend.capabilities()
        self.assertFalse(result["send"]["available"]); self.assertFalse(result["send"]["p2pVerified"])


if __name__ == "__main__":unittest.main()
