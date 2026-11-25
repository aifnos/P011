"""HOST contracts for the explicit dump-only P011 checker; no ADB calls."""
import ast
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
import device_ip_readonly as checker


class IpReadOnlyTests(unittest.TestCase):
    def test_body_python35_and_no_write_backend(self):
        tree = ast.parse(checker.BODY, feature_version=(3, 5))
        forbidden = {"LinuxBackend", "GoLease", "DeviceGuard", "start_watchdog", "Popen",
                     "encode_new_address", "encode_del_address", "create", "remove", "recover"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                self.assertNotIn(name, forbidden)
        sockets = [v for v in ast.walk(tree) if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
                   and v.func.attr == "socket"]
        self.assertEqual(len(sockets), 1)
        self.assertEqual([v.attr for v in sockets[0].args], ["AF_NETLINK", "SOCK_RAW", "NETLINK_ROUTE"])
        sends = [v for v in ast.walk(tree) if isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
                 and v.func.attr == "sendto"]
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0].args[0].attr, "request")
        self.assertEqual(ast.literal_eval(sends[0].args[1]), (0, 0))
        self.assertFalse(any(isinstance(v, ast.Assert) for v in ast.walk(tree)))
        optimized = compile(checker.BODY, 'readonly-fixture', 'exec', optimize=1)
        self.assertIn('readonly_optimized_not_supported', optimized.co_consts)

    def test_explicit_execution_required(self):
        with patch.object(checker, "Adb", side_effect=AssertionError("No ADB")), \
                patch.object(sys, "argv", ["device_ip_readonly.py"]), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                checker.main()
            self.assertEqual(error.exception.code, 2)

    def test_public_result_rejects_extra_identifiers_and_invalid_types(self):
        value = {name: True for name in checker.BODY_FIELDS}
        value.update(complete_dump_sets=2, addresses_count=2, routes_count=9, rules_count=3)
        self.assertEqual(checker._public_fields(value), value)
        for replacement in ({"source_ip": "fixture"}, {"addresses_count": True},
                            {"complete_dump_sets": 1}, {"stable_complete_views": False},
                            {"routes_count": 4097}):
            invalid = dict(value);invalid.update(replacement)
            with self.assertRaises(ValueError):
                checker._public_fields(invalid)

    def test_freeze_has_only_three_sources_no_binary_and_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            frozen = Path(folder) / "snapshot"
            with patch.object(checker, "Adb", side_effect=AssertionError("No ADB")):
                identity = checker.freeze(frozen)
                self.assertEqual(checker.verify_frozen(frozen, identity), identity)
                self.assertEqual({v.relative_to(frozen).as_posix() for v in frozen.rglob("*") if v.is_file()},
                                 checker.EXPECTED_FILES)
                with self.assertRaises(ValueError):
                    checker.verify_frozen(frozen, "f" * 16)
                (frozen / "runtime/mta_ip.py").write_bytes(b"# changed\n")
                with self.assertRaises(ValueError):
                    checker.verify_frozen(frozen, identity)

    def test_kernel_origin_actual_socket_port_and_lifetime_gates_present(self):
        self.assertIn("port,groups=connection.getsockname()", checker.BODY)
        self.assertIn("peer!=(0,0)", checker.BODY)
        self.assertIn("socket.MSG_TRUNC|socket.MSG_CTRUNC", checker.BODY)
        self.assertIn("sequence+=1", checker.BODY)
        self.assertIn("row.cacheinfo[:2]==(ip.UINT_MAX,ip.UINT_MAX)", checker.BODY)
        self.assertIn("first.structural_key()==second.structural_key()", checker.BODY)
        self.assertNotIn("print(packet", checker.BODY)

    def test_one_click_uses_new_reviewed_freeze_not_archived_start(self):
        with patch.object(checker, "freeze", return_value="a" * 16) as freeze, \
                patch.object(checker, "run_reviewed", return_value=({"pass": True}, "fixture", "fixture.zip")) as run, \
                patch.object(Path, "mkdir"), patch.object(sys, "argv", ["device_ip_readonly.py", "--check-readonly"]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(checker.main(), 0)
            freeze.assert_called_once()
            run.assert_called_once_with(freeze.call_args.args[0], "a" * 16)


if __name__ == "__main__":
    unittest.main()
