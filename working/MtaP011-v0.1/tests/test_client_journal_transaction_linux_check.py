"""Only FakeIO / pinned-source AST; never actual Linux fixture or subprocess."""
import ast
import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from test_client_journal_transaction import CombinedIo
from test_client_files import TOKEN, RUN, PENDING

PATH = Path(__file__).absolute().parents[1] / 'host/client_journal_transaction_linux_check.py'
spec = importlib.util.spec_from_file_location('journal_linux_check', str(PATH))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)


class Reader(object):
    def __init__(self, modules):
        self.modules, self.calls, self.pending = modules, 0, False
        self.boot, self.bad_actor, self.task_count = '11111111-1111-1111-1111-111111111111', False, 1

    def read_self(self):
        self.calls += 1
        core, proc = self.modules['mta_p2p_client_init'], self.modules['mta_client_proc']
        actor = core.Actor(123, 301 if self.bad_actor and self.calls > 1 else 300, '/usr/bin/python3', 'b' * 64, ((123, 301 if self.bad_actor and self.calls > 1 else 300, 'R'),))
        return proc.ProcObservation('live_actor', 'synthetic', 'observed', self.boot, actor,
            False, (), True, 2, (), 12, 12, self.pending, self.task_count)


class Fixture(object):
    def __init__(self, modules):
        self.modules, self.io, self.reader = modules, CombinedIo(), Reader(modules)
        self.fixture, self.events = 'private-synthetic-fixture', []
        self.initialize_error, self.verify_error, self.retained_error = None, None, None
        self.closed, self.unknown = False, False

    def initialize(self):
        self.events.append('initialize')
        if self.initialize_error: raise self.initialize_error
        return TOKEN, (self.io, self.io, self.io), self.reader

    def verify(self, locks=False):
        self.events.append('verify')
        if self.verify_error: raise self.verify_error
        if locks:
            coord = self.modules['mta_client_coordination']
            for path in ('/tmp/p011-mta-p2p-device.lock', RUN + '/journal.lock'):
                coord._lock_identity(self.io.nodes[path].metadata())

    def retained(self, marker):
        self.events.append('retained')
        if self.retained_error: raise self.retained_error
        node = self.io.nodes[PENDING]
        if node.data != marker._data or self.modules['mta_client_files']._file_metadata(node.metadata()) != marker._metadata:
            check.fail('retained_marker_unknown')
        return True

    def finish(self):
        self.events.append('finish'); self.closed = not self.unknown
        return {'setup_closed': self.closed, 'setup_fd_count': 0, 'setup_ebadf_count': 0}


class OutputPath(object):
    def __init__(self, store, text='fixed'):
        self.store, self.text = store, text

    def __truediv__(self, name): return OutputPath(self.store, self.text + '/' + name)
    @property
    def parents(self): return ()
    def is_symlink(self): return False
    def mkdir(self, **kwargs):
        if self.text in self.store and not kwargs.get('exist_ok'): raise FileExistsError('synthetic')
        self.store[self.text] = 'directory'
    def open(self, mode):
        if mode != 'xb' or self.text in self.store: raise FileExistsError('synthetic')
        store, text = self.store, self.text
        class Handle(io.BytesIO):
            def close(self):
                if not self.closed: store[text] = self.getvalue()
                io.BytesIO.close(self)
        return Handle()


class CheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = tuple((name, (check.BASE / 'runtime' / (name + '.py')).read_bytes()) for name, _ in check.PINS)
        cls.modules = check._load(cls.sources)

    def setUp(self):
        # Read-only source inspection remains allowed, not actual fixture IO.
        for name in ('open', 'mkdir', 'close', 'read', 'write', 'fsync', 'lseek', 'kill', 'fork', 'waitpid'):
            if hasattr(os, name):
                patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
                patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'tempfile.mkdtemp'):
            patcher = mock.patch(target, side_effect=AssertionError('actual external resource forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        old = check._EXECUTIONS[:]; check._EXECUTIONS[:] = []
        self.addCleanup(lambda: check._EXECUTIONS.__setitem__(slice(None), old))

    def make(self):
        fixture = Fixture(self.modules)
        owner = check.LinuxTransactionCheck(self.modules, _fixture=fixture, _clock=fixture.io.clock)
        return owner, fixture

    def test_python35_ast_no_device_rf_spawn_or_cleanup(self):
        tree = ast.parse(PATH.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse({'socket', 'Popen', 'run', 'fork', 'execve', 'unlink', 'rmdir', 'rmtree', 'kill', 'chmod', 'chown'} & attrs)
        imports = {n.name for item in ast.walk(tree) if isinstance(item, ast.Import) for n in item.names}
        self.assertFalse({'subprocess', 'socket', 'shutil'} & imports)

    def test_exact_runtime_and_reference_whitelist(self):
        self.assertEqual(9, len(check.PINS)); self.assertEqual(2, len(check.REFERENCES))
        self.assertEqual('2783f66edbb545aff8adfaa2f80a77fd957c8ba5b365c90907474244b603dcaa', dict(check.PINS)['mta_client_journal_transaction'])
        self.assertEqual('7197c04cb96e4fce5c252664199668abe013489cbf3b247f521b3293a7d34d2c', dict(check.PINS)['mta_client_pending'])
        self.assertNotIn('mta_client_process_owner', dict(check.PINS))
        self.assertNotIn('test_', '\n'.join(name for name, _ in check.PINS))

    def test_source_pins_actual_and_python35(self):
        report, sources = check.source_check()
        self.assertTrue(report['source_check_pass']); self.assertFalse(report['p011_tested'])
        self.assertEqual(check.PINS, tuple((name, __import__('hashlib').sha256(data).hexdigest()) for name, data in sources))

    def test_source_pin_mismatch_fail_before_execution(self):
        original = check._source
        def altered(path, pin=None):
            if pin == check.PINS[0][1]: check.fail('source_pin')
            return original(path, pin)
        with mock.patch.object(check, '_source', side_effect=altered), mock.patch.object(check, 'LinuxTransactionCheck') as owner:
            with self.assertRaises(check.CheckError): check.execute_reviewed('1' * 64)
            owner.assert_not_called()

    def test_default_source_only_never_constructs_execute_owner(self):
        with mock.patch.object(check, 'LinuxTransactionCheck') as owner, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, check.main([])); self.assertEqual(0, check.main(['--source-check-only']))
            owner.assert_not_called()

    def test_execution_requires_exact_current_checker_pin(self):
        with mock.patch.object(check, 'LinuxTransactionCheck') as owner:
            with self.assertRaises(check.CheckError) as caught: check.execute_reviewed('0' * 64)
            self.assertEqual('reviewed_pin', caught.exception.code); owner.assert_not_called()

    def test_cli_no_arbitrary_fixture_or_implicit_execution(self):
        for args in (['--fixture', 'foreign'], ['--execute-reviewed'], ['--expected-checker-sha256', 'a' * 64]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): check.main(args)

    def test_constructor_pure_no_fixture_or_reader_call(self):
        owner, fixture = self.make()
        self.assertFalse(owner.attempted); self.assertIsNone(owner.resources)
        self.assertEqual([], fixture.events); self.assertEqual(0, fixture.reader.calls)
        self.assertEqual([], fixture.io.ops)

    def test_fake_whole_transaction_first_cas_stale_and_retained_marker(self):
        owner, fixture = self.make(); report = owner.execute()
        self.assertTrue(report['pass']); self.assertGreater(report['component_fd_count'], 7)
        self.assertEqual(report['component_fd_count'], report['component_ebadf_count'])
        self.assertTrue(report['new_inode_verified']); self.assertTrue(report['stale_receipt_rejected'])
        self.assertTrue(report['marker_retained_verified']); self.assertIn(PENDING, fixture.io.nodes)
        self.assertFalse(fixture.io.handles); self.assertIsNone(owner.resources)
        self.assertEqual(len(fixture.io.closed), len(set(fixture.io.closed)))

    def test_public_fixed_projection_does_not_leak_private_fields(self):
        owner, fixture = self.make(); report = owner.execute()
        text = json.dumps(report)
        for secret in (TOKEN, fixture.fixture, fixture.reader.boot, '/usr/bin/python3', 'wlan0', PENDING): self.assertNotIn(secret, text)
        self.assertFalse(report['p011_tested']); self.assertFalse(report['rf'])
        self.assertTrue(report['synthetic_stock_network_baseline']); self.assertFalse(report['network_baseline_authenticated'])

    def test_proc_unknown_blocks_before_transaction_open(self):
        owner, fixture = self.make(); fixture.reader.pending = True
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertEqual('proc', report['failure_stage'])
        self.assertEqual('proc_unknown', report['failure_reason']); self.assertFalse(fixture.io.opened)

    def test_multiple_actual_tasks_rejected_no_threads_started(self):
        owner, fixture = self.make(); fixture.reader.task_count = 2
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertEqual('proc_unknown', report['failure_reason'])

    def test_fresh_actor_change_failed_not_synthetic_authentication(self):
        owner, fixture = self.make(); fixture.reader.bad_actor = True
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertTrue(report['component_closed'])

    def test_fixture_foreign_permissions_or_identity_error_fixed(self):
        owner, fixture = self.make(); fixture.initialize_error = check.CheckError('unsafe_directory')
        report = owner.execute(); self.assertFalse(report['pass'])
        self.assertEqual('unsafe_directory', report['failure_reason']); self.assertEqual('fixture', report['failure_stage'])

    def test_actual_close_failure_sticky_strong_refs_and_no_second_execution(self):
        owner, fixture = self.make()
        def hook(io_, op, path, count):
            if op == 'fstat' and path == '/tmp/p011-mta-p2p-device.lock':
                for fd, row in io_.handles.items():
                    if row[0].path == path: io_.keep_open.add(fd)
        fixture.io.hook = hook
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertFalse(report['component_closed'])
        exact = owner.resources; self.assertIs(exact['fixture'], fixture)
        closed, events = list(fixture.io.closed), list(fixture.events)
        with self.assertRaises(check.CheckError): owner.execute()
        self.assertIs(owner.resources, exact); self.assertEqual(closed, fixture.io.closed); self.assertEqual(events, fixture.events)

    def test_baseexception_during_fixture_sticky_retained_once(self):
        owner, fixture = self.make(); fixture.initialize_error = KeyboardInterrupt('private secret')
        fixture.unknown = True
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertEqual('interrupted', report['failure_class'])
        self.assertIs(owner.resources['fixture'], fixture)
        self.assertNotIn('private secret', json.dumps(report))
        with self.assertRaises(check.CheckError): owner.execute()
        self.assertEqual(1, fixture.events.count('initialize'))

    def test_module_registry_holds_actual_instance_before_execute_and_output(self):
        owner, fixture = self.make(); fixture.initialize_error = KeyboardInterrupt(); fixture.unknown = True
        with mock.patch.object(check, 'LinuxTransactionCheck', return_value=owner), mock.patch.object(check, '_outputs') as output:
            pin = check.source_check()[0]['checker_sha256']
            report = check.execute_reviewed(pin)
            self.assertIs(check._EXECUTIONS[0], owner); self.assertFalse(report['pass']); output.assert_called_once()
            with self.assertRaises(check.CheckError): check.execute_reviewed(pin)
            self.assertEqual(1, fixture.events.count('initialize'))

    def test_retained_marker_mismatch_does_not_claim_cleanup_or_delete(self):
        owner, fixture = self.make(); fixture.retained_error = check.CheckError('retained_marker_unknown')
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertTrue(report['component_closed'])
        self.assertFalse(report['marker_retained_verified']); self.assertIn(PENDING, fixture.io.nodes)
        self.assertFalse(report['marker_unlinked'])

    def test_setup_close_unknown_retains_refs_even_component_success(self):
        owner, fixture = self.make(); fixture.unknown = True
        report = owner.execute()
        self.assertFalse(report['pass']); self.assertTrue(report['component_closed']); self.assertFalse(report['setup_closed'])
        self.assertIs(owner.resources['fixture'], fixture)

    def test_setup_open_epoch_interruption_and_close_once(self):
        fixture = check.LinuxFixture(self.modules)
        with self.assertRaises(KeyboardInterrupt): fixture._open(lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        self.assertTrue(fixture.rows[0]['unknown']); self.assertTrue(fixture.unknown)
        with mock.patch.object(os, 'fstat', side_effect=OSError(errno.EBADF, 'fake')):
            result = fixture.finish()
        self.assertFalse(result['setup_closed']); self.assertFalse(fixture.rows[0]['attempted'])

    def test_setup_close_failure_still_attempts_other_originals_and_never_reclose(self):
        fixture = check.LinuxFixture(self.modules)
        fixture._open(lambda: 41); fixture._open(lambda: 42)
        calls = []
        def close(fd):
            calls.append(fd)
            if fd == 42: raise OSError(errno.EIO, 'secret')
        with mock.patch.object(os, 'close', side_effect=close), mock.patch.object(os, 'fstat', side_effect=OSError(errno.EBADF, 'fake')):
            first = fixture.finish(); second = fixture.finish()
        self.assertFalse(first['setup_closed']); self.assertFalse(second['setup_closed'])
        self.assertEqual([42, 41], calls)

    def test_new_immutable_result_pair_and_private_raw_only(self):
        store = {}; path = OutputPath(store)
        private = {'fixture': 'secret-path', 'boot': 'secret-boot'}
        with mock.patch.object(check, 'BASE', path), mock.patch.object(os, 'urandom', return_value=b'1' * 8):
            check._outputs({'pass': False, 'p011_tested': False}, private)
            with self.assertRaises(FileExistsError): check._outputs({'pass': True}, private)
        public = [v for k, v in store.items() if k.endswith('/result.json')][0]
        raw = [v for k, v in store.items() if k.endswith('/observations.json')][0]
        self.assertFalse(json.loads(public)['pass']); self.assertNotIn(b'secret', public)
        self.assertIn(b'secret-path', raw); self.assertEqual(1, sum(k.endswith('/README.txt') for k in store))


if __name__ == '__main__': unittest.main()
