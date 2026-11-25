"""Only v8 F budgets: candidate methods over existing HOST Fake fixtures.

Synthetic Actors/leases/receipts/frames are not actual P011, Store/Owner/
Provider, wait/FD, RF or restoration acceptance.
"""
import ast
import hashlib
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_executor as old

PATH = BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_executor.py'
spec = importlib.util.spec_from_file_location('client_recovery_budget_v8_f', str(PATH))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)

# Bind exact candidate LoadedDeployment without changing old fixture globals.
namespace = dict(old.deployment.__globals__)
namespace['f'] = f
deployment = types.FunctionType(old.deployment.__code__, namespace,
    old.deployment.__name__, old.deployment.__defaults__, old.deployment.__closure__)


class ExecutorRecoveryBudgetV8Tests(unittest.TestCase):
    def setUp(self):
        for name in ('validate', 'stat', 'open', 'read', 'write', 'fstat', 'close', 'ready', 'popen'):
            patcher = mock.patch.object(f._LinuxIo, name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.kill'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS/process forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def test_exact_two_replacements_other_functions_and_python35(self):
        original = (BASE / 'candidate/client-init-nlink2/runtime/mta_client_executor.py').read_bytes()
        revised = PATH.read_bytes()
        self.assertEqual('9cf0226e76254639c8fb7ab2638f6270ee0091b2485d49e00c0beff47d8f8602', hashlib.sha256(original).hexdigest())
        changes = (
            (b'restored = self.assembly[4].restore(timeout=20)', b'restored = self.assembly[4].restore(timeout=60)'),
            (b"if not _finite(timeout, 0.1, 60): _fail('invalid_input')", b"if not _finite(timeout, 0.1, 90): _fail('invalid_input')"))
        reverse = revised
        for before, after in changes:
            self.assertEqual(1, reverse.count(after)); reverse = reverse.replace(after, before, 1)
        self.assertEqual(original, reverse)
        def methods(source):
            return {(cls.name, node.name): ast.dump(node, include_attributes=False)
                for cls in ast.parse(source.decode('utf-8')).body if isinstance(cls, ast.ClassDef)
                for node in cls.body if isinstance(node, ast.FunctionDef)}
        before, after = methods(original), methods(revised)
        self.assertEqual(set(before), set(after))
        self.assertEqual({('ClientExecutor', 'run'), ('ParentExecutor', 'finish')},
            {key for key in before if before[key] != after[key]})
        self.assertEqual(old.f.MODULES, f.MODULES); self.assertEqual(19, len(f.MODULES))
        self.assertIs(old.f, old.deployment.__globals__['f'])
        for raw in (revised, Path(__file__).read_bytes()): ast.parse(raw.decode('utf-8'), feature_version=(3, 5))

    def test_child_restore60_same_lease_ttl20_and_real_receipt_gates(self):
        for failed_gate in (None, 'ticket_auth', 'bridge_closed', 'provider_closed', 'restored'):
            with self.subTest(failed_gate=failed_gate):
                clock = old.Clock(); io = old.FakeIo(clock); dep, state = deployment(io)
                if failed_gate is not None: setattr(state, failed_gate, False)
                issued, starts, restores, frames = [], [], [], []
                creator = dep.modules['mta_client_linux_provider'].assemble
                def capture(manifest):
                    value = creator(manifest); issued.append(value)
                    lease = value[4]; start, restore = lease.start, lease.restore
                    def capture_start(ttl, cancelled):
                        starts.append((lease, ttl)); return start(ttl, cancelled)
                    def capture_restore(timeout):
                        restores.append((lease, timeout)); return restore(timeout)
                    lease.start, lease.restore = capture_start, capture_restore
                    return value
                dep.modules['mta_client_linux_provider'].assemble = capture
                child = f.ClientExecutor(dep, io, clock, old.Control(), frames.append,
                    _environ={'P011_CLIENT_EXECUTABLE_FD': '60'})
                result = child.run(ttl=20)
                self.assertEqual(1, len(issued)); self.assertIs(issued[0], child.assembly)
                lease, store = issued[0][4], issued[0][1]
                self.assertEqual([(lease, 20)], starts); self.assertEqual([(lease, 60)], restores)
                self.assertEqual(20, lease.record.deadline - clock())
                self.assertIs(type(child.finish), old.core.FinishReceipt)
                self.assertIs(child.finish, lease.finish_receipt)
                self.assertIs(child.finish, store._finish_receipt); self.assertIs(child.finish.store, store)
                self.assertTrue(child.init_ready); self.assertEqual(1, state.stops)
                self.assertEqual(failed_gate is None, result['done'])
                self.assertEqual(failed_gate is not None, result['resource_pending'])
                self.assertEqual(result, frames[-1])
                for key in ('send_available', 'receive_available', 'association_verified', 'ip_ready', 'phone_tested'):
                    self.assertFalse(result[key])

    def test_parent_finish90_bounded_wait_invalid_values_and_no_child_pending(self):
        clock = old.Clock(); io = old.FakeIo(clock); dep, state = deployment(io)
        parent = f.ParentExecutor(dep, io, clock); parent.start(ttl=20)
        ready = f._public('not_started', True, True, False, True)
        final = f._public('restored', True, False, True, False)
        io.buffers[parent.pipes[1]['fd']] = [b''.join(f.PREFIX + old.json.dumps(v).encode('ascii') + b'\n'
            for v in (ready, final))]
        waits = []; original_wait = parent.process.wait
        def wait(timeout):
            waits.append(timeout); return original_wait(timeout)
        parent.process.wait = wait
        result = parent.finish(timeout=90)
        self.assertTrue(result['done']); self.assertFalse(result['resource_pending'])
        self.assertTrue(result['parent_waited']); self.assertTrue(result['parent_absence_verified'])
        self.assertTrue(result['parent_resources_closed'])
        self.assertTrue(result['stdout_eof_observed']); self.assertTrue(result['stderr_eof_observed'])
        self.assertEqual(1, parent.process.calls); self.assertTrue(waits)
        self.assertTrue(all(0 < value <= .05 for value in waits))
        self.assertEqual('20.0', io.argv[-1])
        self.assertTrue(all(io.closes.count(row['fd']) == 1 for row in parent.pipes))
        for bad in (90.0001, 91, True, False, float('nan'), float('inf'), float('-inf')):
            with self.subTest(timeout=bad):
                invalid = f.ParentExecutor(_io=old.FakeIo(old.Clock()))
                with self.assertRaises(f.ExecutorError) as error: invalid.finish(timeout=bad)
                self.assertEqual('invalid_input', error.exception.code); self.assertFalse(invalid.wait_attempted)
        unavailable = f.ParentExecutor(_io=old.FakeIo(old.Clock()))
        pending = unavailable.finish(timeout=90)
        self.assertTrue(pending['resource_pending']); self.assertFalse(pending['done'])
        self.assertEqual('wait_unknown', pending['reason'])
        self.assertFalse(pending['parent_waited']); self.assertFalse(pending['parent_absence_verified'])
        self.assertFalse(pending['parent_resources_closed'])


if __name__ == '__main__': unittest.main()
