"""HOST FakeIO / source inspection only; no actual Linux or fixture creation."""
import ast
import contextlib
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from test_durable_client_store import StoreIo
from test_client_files import TOKEN, RUN, PENDING, TARGET

PATH = Path(__file__).absolute().parents[1] / 'host/client_durable_store_linux_check.py'
spec = importlib.util.spec_from_file_location('durable_linux_check', str(PATH))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)


class DistinctInodeIo(StoreIo):
    def __init__(self):
        self.next_inode = 1000
        StoreIo.__init__(self)

    def add(self, *args, **kwargs):
        node = StoreIo.add(self, *args, **kwargs)
        node.ino = self.next_inode; self.next_inode += 1
        return node


class Reader(object):
    def __init__(self, modules):
        self.modules, self.calls = modules, 0
        self.boot = '11111111-1111-1111-1111-111111111111'
        self.pending, self.changed, self.task_count, self.late = False, False, 1, False

    def read_self(self):
        self.calls += 1
        core, proc = self.modules['mta_p2p_client_init'], self.modules['mta_client_proc']
        start = 301 if self.changed and self.late else 300
        actor = core.Actor(123, start, '/HOST/python', 'b' * 64, ((123, start, 'R'),))
        return proc.ProcObservation('live_actor', 'synthetic', 'observed', self.boot, actor,
            False, (), True, 2, (), 12, 12, self.pending, self.task_count)


class Fixture(check.LinuxFixture):
    def __init__(self, modules):
        check.LinuxFixture.__init__(self, modules)
        self.io, self.reader = DistinctInodeIo(), Reader(modules)
        self.ios = (self.io, self.io, self.io)
        self.fixture, self.events = 'private-HOST-synthetic-fixture', []
        self.initialize_error, self.verify_error, self.readback_error, self.absence_error = None, None, None, None

    def initialize(self):
        self.events.append('initialize')
        if self.initialize_error: raise self.initialize_error
        return TOKEN, self.ios, self.reader

    def verify(self, locks=False):
        self.events.append('verify')
        if self.verify_error: raise self.verify_error
        if locks:
            for path in ('/tmp/p011-mta-p2p-device.lock', RUN + '/journal.lock'):
                self.modules['mta_client_coordination']._lock_identity(self.io.nodes[path].metadata())

    def terminal(self, canonical):
        self.events.append('terminal')
        if self.readback_error: raise self.readback_error
        node = self.io.nodes[TARGET]
        if self.modules['mta_client_files']._file_metadata(node.metadata()) != canonical.metadata or node.data != canonical.data:
            check.fail('readback_failed')
        self.reader.late = True
        return True

    def absent(self):
        self.events.append('absent')
        if self.absence_error: raise self.absence_error
        if PENDING in self.io.nodes: check.fail('marker_absence_unknown')
        return True

    def finish(self):
        self.events.append('setup_finish')
        return {'setup_closed': not self.unknown, 'setup_fd_count': 0, 'setup_ebadf_count': 0}


class OutputPath(object):
    def __init__(self, store, text='fixed'): self.store, self.text = store, text
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
        for name in ('open', 'mkdir', 'close', 'read', 'write', 'fsync', 'lseek', 'kill', 'fork', 'waitpid'):
            if hasattr(os, name):
                patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
                patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'tempfile.mkdtemp'):
            patcher = mock.patch(target, side_effect=AssertionError('actual resource forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        old = check._EXECUTIONS[:]; check._EXECUTIONS[:] = []
        self.addCleanup(lambda: check._EXECUTIONS.__setitem__(slice(None), old))

    def make(self):
        fixture = Fixture(self.modules)
        return check.LinuxDurableStoreCheck(self.modules, _fixture=fixture, _clock=fixture.io.clock), fixture

    def test_python35_ast_no_old_import_process_rf_or_unlink_command(self):
        tree = ast.parse(PATH.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse({'socket', 'Popen', 'run', 'fork', 'execve', 'unlink', 'rmdir', 'rmtree', 'kill', 'chmod', 'chown'} & attrs)
        imports = {n.name for x in ast.walk(tree) if isinstance(x, ast.Import) for n in x.names}
        self.assertFalse({'subprocess', 'socket', 'shutil', 'client_journal_transaction_linux_check'} & imports)

    def test_fixed_current_nine_runtime_and_two_references(self):
        self.assertEqual(9, len(check.PINS)); self.assertEqual(2, len(check.REFERENCES))
        self.assertEqual('c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd', dict(check.PINS)['mta_client_store'])
        self.assertEqual('edd6553b847db6dc8e5d2be48256b8e3ee706adca25cbda316bcf28f357ff7cf', dict(check.PINS)['mta_client_pending'])
        self.assertNotIn('mta_client_journal_transaction', dict(check.PINS))

    def test_current_exact_source_and_ast_not_actual_linux(self):
        report, sources = check.source_check()
        self.assertTrue(report['source_check_pass']); self.assertFalse(report['production_provider'])
        self.assertFalse(report['p011_tested']); self.assertFalse(report['phone_tested'])
        self.assertEqual(check.PINS, tuple((n, __import__('hashlib').sha256(b).hexdigest()) for n, b in sources))

    def test_pin_mismatch_blocks_owner_before_io(self):
        with mock.patch.object(check, '_source', side_effect=check.CheckError('source_pin')), mock.patch.object(check, 'LinuxDurableStoreCheck') as owner:
            with self.assertRaises(check.CheckError): check.execute_reviewed('a' * 64)
            owner.assert_not_called()

    def test_default_and_cli_source_only_no_fixture(self):
        with mock.patch.object(check, 'LinuxDurableStoreCheck') as owner, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, check.main([])); self.assertEqual(0, check.main(['--source-check-only']))
            owner.assert_not_called()
        for args in (['--fixture', 'foreign'], ['--execute-reviewed'], ['--expected-checker-sha256', 'a' * 64]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): check.main(args)

    def test_execution_requires_exact_checker_sha(self):
        with mock.patch.object(check, 'LinuxDurableStoreCheck') as owner:
            with self.assertRaises(check.CheckError): check.execute_reviewed('0' * 64)
            owner.assert_not_called()

    def test_pure_constructor_no_initialize_or_proc(self):
        owner, fixture = self.make()
        self.assertFalse(owner.attempted); self.assertIsNone(owner.resources)
        self.assertEqual([], fixture.events); self.assertEqual([], fixture.io.ops); self.assertEqual(0, fixture.reader.calls)

    def test_whole_fake_trace_actual_components_and_final_clear(self):
        owner, fixture = self.make(); report = owner.execute()
        self.assertTrue(report['pass']); self.assertIsNone(owner.resources)
        self.assertEqual(7, report['coord_history_count']); self.assertLess(report['files_history_count'], 256)
        self.assertGreater(report['component_fd_count'], 10)
        self.assertEqual(report['component_fd_count'], report['component_ebadf_count'])
        self.assertTrue(report['device_last_verified']); self.assertTrue(report['same_original_device_verified'])
        self.assertNotIn(PENDING, fixture.io.nodes); self.assertIn(TARGET, fixture.io.nodes)
        self.assertFalse(fixture.io.handles); self.assertEqual(1, fixture.io.counts[('unlink', PENDING)])
        self.assertEqual('reconciled', self.modules['mta_client_journal_codec'].decode_journal(fixture.io.nodes[TARGET].data).stage)

    def test_public_projection_private_identifiers_and_synthetic_boundary(self):
        owner, fixture = self.make(); report = owner.execute(); public = json.dumps(report)
        for value in (TOKEN, fixture.fixture, fixture.reader.boot, '/HOST/python', 'wlan0', PENDING): self.assertNotIn(value, public)
        for field in ('production_provider', 'p011_tested', 'phone_tested', 'rf', 'global_device_namespace_touched', 'network_baseline_authenticated', 'rf_ttl_expiry_actual_tested'):
            self.assertIs(report[field], False)
        self.assertTrue(report['synthetic_stock_network_baseline']); self.assertTrue(report['synthetic_restore_producer'])

    def test_unknown_or_multitask_proc_blocks_before_store(self):
        for kind in ('pending', 'tasks'):
            owner, fixture = self.make()
            if kind == 'pending': fixture.reader.pending = True
            else: fixture.reader.task_count = 2
            report = owner.execute(); self.assertFalse(report['pass'])
            self.assertEqual('proc', report['failure_stage']); self.assertFalse(fixture.io.opened)

    def test_after_process_identity_change_no_false_pass(self):
        owner, fixture = self.make(); fixture.reader.changed = True
        report = owner.execute(); self.assertFalse(report['pass'])
        self.assertTrue(report['component_closed']); self.assertEqual('actor_changed', report['failure_reason'])

    def test_initialization_interrupted_preserves_unknown_refs_once(self):
        owner, fixture = self.make(); fixture.initialize_error = KeyboardInterrupt('private'); fixture.unknown = True
        report = owner.execute(); self.assertFalse(report['pass'])
        self.assertIs(owner.resources['fixture'], fixture); self.assertEqual('interrupted', report['failure_class'])
        with self.assertRaises(check.CheckError): owner.execute()
        self.assertEqual(1, fixture.events.count('initialize'))

    def test_close_unknown_does_not_reclose_or_drop_store(self):
        owner, fixture = self.make()
        def fail_close(io_, operation, path, count):
            if operation == 'fstat' and path == '/tmp/p011-mta-p2p-device.lock':
                for fd, row in io_.handles.items():
                    if row[0].path == path: io_.keep_open.add(fd)
        fixture.io.hook = fail_close
        report = owner.execute(); self.assertFalse(report['pass']); self.assertFalse(report['component_closed'])
        refs, closed = owner.resources, list(fixture.io.closed)
        self.assertIs(refs['store'], fixture.store)
        with self.assertRaises(check.CheckError): owner.execute()
        self.assertIs(refs, owner.resources); self.assertEqual(closed, fixture.io.closed)

    def test_independent_marker_or_terminal_readback_failure_preserved(self):
        for kind in ('absence', 'terminal'):
            owner, fixture = self.make()
            if kind == 'absence': fixture.absence_error = check.CheckError('marker_absence_unknown')
            else: fixture.readback_error = check.CheckError('readback_failed')
            report = owner.execute(); self.assertFalse(report['pass']); self.assertTrue(report['component_closed'])
            self.assertEqual('readback', report['failure_stage'])

    def test_device_last_exact_ticket_not_numeric_slot(self):
        owner, fixture = self.make(); report = owner.execute(); self.assertTrue(report['pass'])
        original = fixture.close_events[-1]
        fixture.close_events[-1] = fixture.close_events[-2]
        with self.assertRaises(check.CheckError): fixture.component_closure(fixture.store)
        fixture.close_events[-1] = original
        self.assertEqual(report['component_fd_count'], fixture.component_closure(fixture.store)[0])

    def test_passive_close_observer_failure_never_skips_actual_close(self):
        owner, fixture = self.make()
        with mock.patch.object(check, '_rows', side_effect=MemoryError('private')):
            report = owner.execute()
        self.assertFalse(report['pass']); self.assertFalse(fixture.io.handles)
        self.assertTrue(fixture.close_observation_unknown); self.assertIsNotNone(owner.resources)

    def test_setup_unknown_or_close_failure_independently_once(self):
        fixture = check.LinuxFixture(self.modules)
        with self.assertRaises(KeyboardInterrupt): fixture._open(lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
        self.assertTrue(fixture.rows[0]['unknown'])
        with mock.patch.object(os, 'fstat', side_effect=OSError(errno.EBADF, 'fake')):
            self.assertFalse(fixture.finish()['setup_closed'])
        other = check.LinuxFixture(self.modules); other._open(lambda: 41); other._open(lambda: 42)
        calls = []
        def close(fd):
            calls.append(fd)
            if fd == 42: raise OSError(errno.EIO, 'private')
        with mock.patch.object(os, 'close', side_effect=close), mock.patch.object(os, 'fstat', side_effect=OSError(errno.EBADF, 'fake')):
            self.assertFalse(other.finish()['setup_closed']); self.assertFalse(other.finish()['setup_closed'])
        self.assertEqual([42, 41], calls)

    def test_setup_failure_after_component_success_prevents_pass(self):
        owner, fixture = self.make(); fixture.unknown = True
        report = owner.execute(); self.assertFalse(report['pass']); self.assertTrue(report['component_closed'])
        self.assertFalse(report['setup_closed']); self.assertIs(owner.resources['fixture'], fixture)

    def test_module_registry_issued_before_execute_output_unknown(self):
        owner, fixture = self.make(); fixture.initialize_error = KeyboardInterrupt(); fixture.unknown = True
        with mock.patch.object(check, 'LinuxDurableStoreCheck', return_value=owner), mock.patch.object(check, '_outputs') as output:
            report = check.execute_reviewed(check.source_check()[0]['checker_sha256'])
            self.assertIs(check._EXECUTIONS[0], owner); self.assertFalse(report['pass']); output.assert_called_once()
            with self.assertRaises(check.CheckError): check.execute_reviewed(check.source_check()[0]['checker_sha256'])

    def test_immutable_result_pair_and_private_observations(self):
        values = {}; base = OutputPath(values)
        with mock.patch.object(check, 'BASE', base), mock.patch.object(os, 'urandom', return_value=b'1' * 8):
            check._outputs({'pass': False, 'production_provider': False}, {'fixture': 'secret-private-fixture'})
            with self.assertRaises(FileExistsError): check._outputs({'pass': True}, {})
        public = [v for k, v in values.items() if k.endswith('/result.json')][0]
        raw = [v for k, v in values.items() if k.endswith('/observations.json')][0]
        self.assertFalse(json.loads(public)['pass']); self.assertNotIn(b'secret', public)
        self.assertIn(b'secret-private-fixture', raw)


if __name__ == '__main__': unittest.main()
