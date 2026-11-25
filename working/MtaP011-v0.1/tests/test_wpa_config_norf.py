"""HOST source/entry checks only; no ADB and no WPA process execution."""
import ast
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
import device_wpa_config_norf as trial
from device_p2p_v3 import probe_source


class WpaConfigNoRfTests(unittest.TestCase):
    def test_remote_python35_syntax(self):
        # No snapshot or device access: safety is deliberately inert here.
        source = probe_source("/mnt/data/p011-toolbox/candidates/mta-01-" + trial.CANDIDATE,
                              "def verify_candidate(path):pass\n", trial.BODY,
                              "RUN='fixture'\nTARGET='fixture'\n")
        ast.parse(source, feature_version=(3, 5))

    def test_only_reviewed_version_and_parse_arguments(self):
        tree = ast.parse(trial.BODY, feature_version=(3, 5))
        commands = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Attribute) and node.func.attr == "Popen"]
        self.assertEqual(len(commands), 2)
        arguments = [[ast.literal_eval(v) if isinstance(v, ast.Constant) else v.id
                      for v in node.args[0].elts] for node in commands]
        self.assertCountEqual(arguments, [["binary", "-c", "path"], ["binary", "-v"]])
        for command in commands:
            environment = next(v.value for v in command.keywords if v.arg == "env")
            self.assertEqual(set(ast.literal_eval(environment)), {"PATH", "LANG"})

    def test_import_does_not_invoke_adb_and_execution_is_explicit(self):
        with patch.object(trial, "Adb", side_effect=AssertionError("Must not contact ADB")), \
                patch.object(sys, "argv", ["device_wpa_config_norf.py"]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                trial.main()
            self.assertEqual(error.exception.code, 2)

    def test_no_runtime_backend_or_rf_methods_called(self):
        tree = ast.parse(trial.BODY, feature_version=(3, 5))
        forbidden = {"LinuxBackend", "GoLease", "DeviceGuard", "start_watchdog",
                     "spawn_private", "create", "group_add", "remove", "recover"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                self.assertNotIn(name, forbidden)
        self.assertIn("original.replace(b'update_config=0\\n',b'')", trial.BODY)
        self.assertIn("os.O_EXCL|os.O_NOFOLLOW,0o600", trial.BODY)


if __name__ == "__main__":
    unittest.main()
