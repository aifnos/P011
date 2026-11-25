"""HOST FakeOS only; no actual Linux/fork/exec/WSL/device execution."""
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
from test_client_launch_registration import SidecarIo
from test_client_files import TOKEN, RUN, PENDING, TARGET
from test_client_process_owner import FakeKernel, metadata, ELF

PATH = Path(__file__).absolute().parents[1] / 'host/client_launch_registration_linux_check.py'
spec = importlib.util.spec_from_file_location('launch_linux_check', str(PATH))
check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)


class Reader(object):
    def __init__(self, modules):
        self.modules, self.owner, self.calls = modules, None, []
        self.boot = '11111111-1111-1111-1111-111111111111'
        self.pending, self.multi, self.post_fault, self.changed, self.late = False, False, None, False, False

    def value(self, actor=None, kind='live_actor', absent=False, pending=False):
        return self.modules['mta_client_proc'].ProcObservation(kind, '', 'HOST_FAKE_ONLY', self.boot,
            actor, absent, (), True, 2, (), 12, 12, pending, len(actor.tasks) if actor else 0)

    def read_self(self):
        self.calls.append('self')
        start = 301 if self.changed and self.late else 300
        rows = ((100, start, 'S'), (101, 301, 'S')) if self.multi else ((100, start, 'S'),)
        actor = self.modules['mta_p2p_client_init'].Actor(100, start, '/HOST/python', 'b' * 64, rows)
        return self.value(actor, pending=self.pending)

    def read_actor(self, pid, expected=None):
        self.calls.append(('actor', pid))
        child = next(t for t in self.owner._tickets if t.pid == pid)
        parent = child.parent
        if self.post_fault == 'exit' and child.released: return self.value(None, 'absence', True)
        exe, digest = (child.spec.exe, child.spec.argv_sha) if child.released else (parent.exe, parent.argv_sha)
        if self.post_fault == 'exec' and child.released: exe = '/HOST/unknown-exec'
        actor = self.modules['mta_p2p_client_init'].Actor(pid, 400 + pid, exe, digest, ((pid, 400 + pid, 'S'),))
        return self.value(actor, pending=self.post_fault == 'unknown' and child.released)

    def read_absence(self, target, boot):
        self.calls.append(('absence', target.pid))
        child = next(t for t in self.owner._tickets if t.pid == target.pid)
        return self.value(None, 'absence', True) if child.waited else self.value(None, 'unknown', pending=True)


class Kernel(FakeKernel):
    def __init__(self, clock):
        FakeKernel.__init__(self, clock)
        self.nextfd, self.owner, self.euid, self.wait_count = 1000, None, 0, {}
        self.image = metadata(800, self.binary_mode, self.binary)
        self.wait_fault, self.gate_delay = None, False

    def open(self, path, flags):
        if path == check.SLEEP_PATH:
            value = self.event('open', path, flags)
            return value if value is not None else self.alloc(self.image, self.binary)
        return FakeKernel.open(self, path, flags)

    def stat(self, path, follow_symlinks=False):
        self.event('stat', path)
        if path != check.SLEEP_PATH or follow_symlinks: raise AssertionError('HOST fixed path')
        return metadata(self.image.st_ino, self.image.st_mode, self.binary)

    def fork(self):
        value = self.event('fork')
        return value if value is not None else 200 + 100 * (len(self.owner._tickets) - 1)

    def waitpid(self, pid, flags):
        self.event('waitpid', pid, flags)
        self.wait_count[pid] = self.wait_count.get(pid, 0) + 1
        if self.wait_fault: raise self.wait_fault
        child = next(t for t in self.owner._tickets if t.pid == pid)
        gate = next(r for r in child.fds if r.role == 'gate_write')
        if child.released: return (pid, 0)
        if gate.closed: return (pid, 125 << 8)
        return (0, 0)

    def getpid(self): return 100
    def geteuid(self): return self.euid


class Fixture(check.LinuxFixture):
    def __init__(self, modules):
        check.LinuxFixture.__init__(self, modules)
        self.io, self.reader = SidecarIo(), Reader(modules)
        self.kernel = Kernel(self.io.clock)
        self.ios = (self.io, self.io, self.io)
        self.fixture, self.events = 'private-HOST-launch-fixture', []
        self.initialize_error, self.verify_error, self.absence_error, self.readback_error = None, None, None, None

    def initialize(self):
        self.events.append('initialize')
        if self.initialize_error: raise self.initialize_error
        return TOKEN, self.ios, self.reader

    def sleep_image(self): return check.SleepImage(_fs=self.kernel, _clock=self.io.clock)

    def child_owner(self, reader, clock):
        device = self.store._current_locks._device.fd
        value = self.io.fstat(device)
        self.kernel.live[device] = {'meta': metadata(value.st_ino, value.st_mode),
            'data': b'', 'pos': 0, 'inherit': False, 'block': True, 'ofd': object()}
        owner = self.modules['mta_client_process_owner'].DirectChildOwner(_os=self.kernel,
            _reader=reader, _clock=clock, _threads=lambda: 1, _flags=self.kernel.flags)
        self.reader.owner, self.kernel.owner = owner, owner
        return owner

    def verify(self, locks=False):
        self.events.append('verify')
        if self.verify_error: raise self.verify_error
        if locks:
            for path in ('/tmp/p011-mta-p2p-device.lock', RUN + '/journal.lock'):
                self.modules['mta_client_coordination']._lock_identity(self.io.nodes[path].metadata())

    def absent(self):
        self.events.append('absent')
        if self.absence_error: raise self.absence_error
        if PENDING in self.io.nodes: check.fail('marker_absence_unknown')
        return True

    def terminal(self, canonical):
        self.events.append('terminal')
        if self.readback_error: raise self.readback_error
        node = self.io.nodes[TARGET]
        if self.modules['mta_client_files']._file_metadata(node.metadata()) != canonical.metadata or node.data != canonical.data:
            check.fail('readback_failed')
        self.reader.late = True
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
        if self.text in self.store and not kwargs.get('exist_ok'): raise FileExistsError('HOST')
        self.store[self.text] = 'directory'
    def open(self, mode):
        if mode != 'xb' or self.text in self.store: raise FileExistsError('HOST')
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
        for name in ('open', 'mkdir', 'close', 'read', 'write', 'fsync', 'lseek', 'kill', 'fork', 'waitpid', 'execve'):
            if hasattr(os, name):
                patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
                patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'tempfile.mkdtemp'):
            patcher = mock.patch(target, side_effect=AssertionError('actual resources forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        old = check._EXECUTIONS[:]; check._EXECUTIONS[:] = []
        self.addCleanup(lambda: check._EXECUTIONS.__setitem__(slice(None), old))

    def make(self):
        fixture = Fixture(self.modules)
        return check.LinuxLaunchCheck(self.modules, _fixture=fixture, _clock=fixture.io.clock), fixture

    def test_fixed_eleven_pins_and_c_references_default_source_only(self):
        self.assertEqual(11, len(check.PINS)); self.assertEqual(2, len(check.REFERENCES))
        self.assertEqual('833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0', dict(check.PINS)['mta_client_launch_registration'])
        self.assertEqual('0a9a02c79e7e6603f86a7d7618f0b030a3c81d3581423801f22790e923839165', dict(check.PINS)['mta_client_process_owner'])
        self.assertEqual((('watchdog', '4'), ('controller', '2')), check.SLEEP_ARGUMENTS)
        result, sources = check.source_check()
        self.assertTrue(result['source_check_pass']); self.assertFalse(result['production_provider'])
        self.assertEqual(self.sources, sources)

    def test_cli_no_actual_by_default_and_no_path_commands(self):
        with mock.patch.object(check, 'LinuxLaunchCheck') as owner, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, check.main([])); self.assertEqual(0, check.main(['--source-check-only']))
            owner.assert_not_called()
        for args in (['--sleep', '/foreign'], ['--execute-reviewed'], ['--expected-checker-sha256', 'a' * 64]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): check.main(args)

    def test_exact_self_sha_and_dependency_fail_before_any_owner(self):
        with mock.patch.object(check, 'LinuxLaunchCheck') as owner:
            with self.assertRaises(check.CheckError): check.execute_reviewed('0' * 64)
            owner.assert_not_called()
        with mock.patch.object(check, '_source', side_effect=check.CheckError('source_pin')), mock.patch.object(check, 'LinuxLaunchCheck') as owner:
            with self.assertRaises(check.CheckError): check.execute_reviewed('a' * 64)
            owner.assert_not_called()

    def test_ctor_pure_no_proc_or_fixture_initialization(self):
        owner, fixture = self.make()
        self.assertFalse(owner.attempted); self.assertIsNone(owner.resources)
        self.assertEqual([], fixture.events); self.assertEqual([], fixture.reader.calls); self.assertEqual([], fixture.kernel.calls)

    def test_complete_fake_trace_real_components_split_inventory_and_terminal(self):
        owner, fixture = self.make(); report = owner.execute()
        self.assertTrue(report['pass'], owner.private.get('failures'))
        self.assertIsNone(owner.resources)
        self.assertEqual(2, len(owner.owner._tickets))
        self.assertEqual({200: 1, 300: 1}, fixture.kernel.wait_count)
        self.assertEqual(report['child_fd_count'], report['child_ebadf_count'])
        self.assertEqual(report['sidecar_fd_count'], report['sidecar_ebadf_count'])
        self.assertEqual(report['component_fd_count'], report['component_ebadf_count'])
        self.assertEqual(12, report['sidecar_fd_count'])
        self.assertNotIn(PENDING, fixture.io.nodes)
        self.assertEqual('reconciled', self.modules['mta_client_journal_codec'].decode_journal(fixture.io.nodes[TARGET].data).stage)
        self.assertIn(RUN + '/launch-watchdog.json', fixture.io.nodes)
        self.assertIn(RUN + '/launch-controller.json', fixture.io.nodes)
        self.assertFalse(fixture.io.handles)

    def test_public_has_no_private_process_address_path_or_hash(self):
        owner, fixture = self.make(); report = owner.execute(); public = json.dumps(report)
        for value in (TOKEN, fixture.fixture, fixture.reader.boot, 'argv_sha', '/HOST/python', '/usr/bin/sleep', 'wlan0', PENDING):
            self.assertNotIn(value, public)
        for field in ('production_provider', 'p011_tested', 'phone_tested', 'rf', 'global_device_namespace_touched',
                'production_manifest_authenticated', 'network_baseline_authenticated', 'rf_ttl_expiry_actual_tested'):
            self.assertIs(report[field], False)
        self.assertTrue(report['synthetic_interface']); self.assertTrue(report['synthetic_restore_producer'])

    def test_sleep_pin_pure_full_elf_hash_metadata_and_once_close(self):
        clock = fixture_clock = SidecarIo().clock; kernel = Kernel(clock)
        image = check.SleepImage(_fs=kernel, _clock=fixture_clock)
        self.assertFalse(kernel.calls); image.open()
        self.assertEqual(__import__('hashlib').sha256(ELF).hexdigest(), image.sha)
        self.assertEqual(len(ELF), image.metadata[7])
        self.assertTrue(image.close()); self.assertTrue(image.close())
        self.assertEqual(1, kernel.closed.count(image.fd))
        with self.assertRaises(check.CheckError): image.open()

    def test_sleep_pin_rejects_non_root_writable_non_elf_and_changed_entry(self):
        for fault in ('uid', 'writable', 'elf', 'entry'):
            kernel = Kernel(SidecarIo().clock)
            if fault == 'uid': kernel.euid = 1
            elif fault == 'writable': kernel.image.st_mode |= 0o022
            elif fault == 'elf': kernel.binary = b'NOELF'; kernel.image.st_size = 5
            else:
                original = kernel.stat
                def changed(path, follow_symlinks=False):
                    value = original(path, follow_symlinks); value.st_ino += 1; return value
                kernel.stat = changed
            image = check.SleepImage(_fs=kernel, _clock=kernel.clock)
            with self.assertRaises(check.CheckError): image.open()
            image.close()
            self.assertIsNone(image.sha)

    def test_sleep_unknown_open_close_strongrefs_and_no_retry(self):
        kernel = Kernel(SidecarIo().clock)
        original = kernel.open
        def hidden(path, flags): original(path, flags); raise RuntimeError('private hidden descriptor')
        kernel.open = hidden
        image = check.SleepImage(_fs=kernel, _clock=kernel.clock)
        with self.assertRaises(RuntimeError): image.open()
        self.assertTrue(image.creation_unknown); self.assertFalse(image.close()); self.assertFalse(image.close_attempted)
        with self.assertRaises(check.CheckError): image.open()

    def test_single_thread_unknown_proc_blocks_before_image_or_store(self):
        for kind in ('pending', 'multi'):
            owner, fixture = self.make()
            if kind == 'pending': fixture.reader.pending = True
            else: fixture.reader.multi = True
            report = owner.execute(); self.assertFalse(report['pass'])
            self.assertEqual('proc', report['failure_stage']); self.assertFalse(fixture.io.opened)
            self.assertFalse(fixture.kernel.calls)

    def test_initialization_unknown_retains_owner_and_first_failure(self):
        owner, fixture = self.make(); fixture.initialize_error = KeyboardInterrupt('private'); fixture.unknown = True
        report = owner.execute(); self.assertFalse(report['pass'])
        self.assertEqual('fixture', report['failure_stage']); self.assertEqual('interrupted', report['failure_class'])
        self.assertIs(owner.resources['fixture'], fixture)
        with self.assertRaises(check.CheckError): owner.execute()
        self.assertEqual(1, fixture.events.count('initialize'))

    def test_postexec_unknown_business_failure_never_becomes_cleanup_pass(self):
        owner, fixture = self.make(); fixture.reader.post_fault = 'unknown'
        report = owner.execute(); self.assertFalse(report['pass'])
        self.assertEqual('postexec', report['failure_stage'])
        self.assertEqual(1, len(owner.owner._tickets))
        self.assertTrue(owner.owner._tickets[0].waited)
        self.assertFalse(report['all_stages_verified']); self.assertTrue(report['fixture_retained'])

    def test_child_wait_echild_not_reaped_and_no_store_finish(self):
        owner, fixture = self.make(); fixture.kernel.wait_fault = OSError(errno.ECHILD, 'private')
        report = owner.execute(); self.assertFalse(report['pass']); self.assertFalse(report['children_reaped'])
        self.assertFalse(report['terminal_durable']); self.assertIn(PENDING, fixture.io.nodes)
        self.assertTrue(any('wait_unknown' in e['traceback'] or e['stage'] == 'child_reap' for e in owner.private['failures']))
        self.assertIsNotNone(owner.resources)

    def test_pregate_closes_exact_gate_only_then_real_fake_wait_125(self):
        owner, fixture = self.make()
        captured = {}
        original = self.modules['mta_client_launch_registration'].DurableLaunchRegistry.release
        def fail_before(registry, record):
            captured['owner'], captured['child'] = registry._owner, record.child
            raise check.CheckError('sidecar_unknown')
        with mock.patch.object(self.modules['mta_client_launch_registration'].DurableLaunchRegistry, 'release', fail_before):
            report = owner.execute()
        child = captured['child']
        self.assertTrue(child.waited); self.assertEqual(125, child.exit_code)
        self.assertFalse(child.released); self.assertFalse(report['pass'])
        self.assertEqual('preexec', report['failure_stage']); self.assertEqual('sidecar_unknown', report['failure_reason'])
        self.assertEqual(1, fixture.kernel.wait_count[child.pid])
        self.assertFalse(report['children_exit_zero'])
        self.assertFalse(report['terminal_durable'])
        self.assertIs(original, self.modules['mta_client_launch_registration'].DurableLaunchRegistry.release)

    def test_gate_unknown_attempted_foreign_never_force_close_or_kill(self):
        owner, fixture = self.make(); captured = {}
        def unknown_gate(registry, record):
            child = record.child; captured['child'] = child
            gate = next(r for r in child.fds if r.role == 'gate_write'); gate.unknown = True
            raise check.CheckError('gate_unknown')
        with mock.patch.object(self.modules['mta_client_launch_registration'].DurableLaunchRegistry, 'release', unknown_gate):
            report = owner.execute()
        gate = next(r for r in captured['child'].fds if r.role == 'gate_write')
        self.assertFalse(gate.attempted); self.assertIn(gate.fd, fixture.kernel.live)
        self.assertFalse(report['children_reaped']); self.assertFalse(report['pass'])
        self.assertIsNotNone(owner.resources)

    def test_sidecar_observer_has_exact_registry_tickets_not_false_unknown(self):
        owner, fixture = self.make(); report = owner.execute(); self.assertTrue(report['pass'])
        self.assertFalse(fixture.close_observation_unknown)
        for row in owner.registry._inventory:
            self.assertEqual(1, sum(event[0] is row for event in fixture.close_events))
        self.assertIs(fixture.close_events[-1][0], fixture.store._current_locks._device)

    def test_default_owner_not_os_wrapper_or_global_close_patch(self):
        tree = ast.parse(PATH.read_text(encoding='utf-8'))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'DirectChildOwner']
        self.assertEqual(1, len(calls)); self.assertNotIn('_os', {k.arg for k in calls[0].keywords})
        self.assertNotIn('os.close =', PATH.read_text(encoding='utf-8'))

    def test_closure_unknown_retains_exact_refs_and_no_reclose(self):
        owner, fixture = self.make()
        original = fixture.kernel.close
        def keep(fd):
            child = next((t for t in fixture.kernel.owner._tickets if any(r.fd == fd and r.role == 'executable' for r in t.fds)), None) if fixture.kernel.owner else None
            if child is not None: fixture.kernel.closed.append(fd); return None
            return original(fd)
        fixture.kernel.close = keep
        report = owner.execute(); self.assertFalse(report['pass']); self.assertFalse(report['child_fds_closed'])
        before = list(fixture.kernel.closed)
        with self.assertRaises(check.CheckError): owner.execute()
        self.assertEqual(before, fixture.kernel.closed); self.assertIs(owner.resources['child_owner'], owner.owner)

    def test_child_passive_observer_error_does_not_skip_actual_close(self):
        kernel = Kernel(SidecarIo().clock)
        module = self.modules['mta_client_process_owner']
        class Dummy(object):
            def __init__(self): self._tickets, self.called = [], []
            def _close_fd(self, ticket, row): self.called.append((ticket, row)); return True
        dummy = Dummy(); observer = check.ChildObserver(dummy)
        class Broken(object):
            @property
            def closed(self): raise MemoryError()
        row = Broken(); ticket = object()
        self.assertTrue(dummy._close_fd(ticket, row)); self.assertEqual([(ticket, row)], dummy.called)
        self.assertTrue(observer.unknown)

    def test_two_registered_tickets_without_fork_are_not_reported_reaped_or_absent(self):
        owner, fixture = self.make()
        actual = self.modules['mta_client_process_owner']
        observer = type('Observer', (), {'closure': lambda self: (0, 0)})()
        owner.observer = observer
        owner.report = {'failure_stage': 'not_recorded'}
        owner.owner = actual.DirectChildOwner(_os=fixture.kernel, _reader=fixture.reader,
            _clock=fixture.io.clock, _threads=lambda: 1, _flags=fixture.kernel.flags)
        for role, seconds in check.SLEEP_ARGUMENTS:
            spec = actual.LaunchSpec(role, check.SLEEP_PATH, (check.SLEEP_PATH, seconds), (), 'a' * 64)
            owner.owner.register(spec, 3, fixture.io.clock() + 18)
        owner._children_cleanup()
        self.assertFalse(owner.report['children_reaped'])
        self.assertFalse(owner.report['children_absence_verified'])
        self.assertFalse(owner.report['children_exit_zero'])

    def test_marker_terminal_setup_failure_never_masks_first_or_proves_restore(self):
        for field in ('absence', 'terminal', 'setup'):
            owner, fixture = self.make()
            if field == 'absence': fixture.absence_error = check.CheckError('marker_absence_unknown')
            elif field == 'terminal': fixture.readback_error = check.CheckError('readback_failed')
            else: fixture.unknown = True
            report = owner.execute(); self.assertFalse(report['pass'])
            self.assertTrue(report['component_closed'])
            self.assertFalse(report['network_baseline_authenticated'])

    def test_exact_source_registry_once_and_first_private_record_preserved(self):
        owner, fixture = self.make(); fixture.initialize_error = KeyboardInterrupt('private'); fixture.unknown = True
        with mock.patch.object(check, 'LinuxLaunchCheck', return_value=owner), mock.patch.object(check, '_outputs') as output:
            result = check.execute_reviewed(check.source_check()[0]['checker_sha256'])
            self.assertFalse(result['pass']); self.assertIs(check._EXECUTIONS[0], owner); output.assert_called_once()
            with self.assertRaises(check.CheckError): check.execute_reviewed(check.source_check()[0]['checker_sha256'])

    def test_immutable_public_pair_and_private_raw_exclusion(self):
        values = {}
        with mock.patch.object(check, 'BASE', OutputPath(values)), mock.patch.object(os, 'urandom', return_value=b'2' * 8):
            check._outputs({'pass': False, 'rf': False}, {'fixture': 'private-secret-path', 'failures': ['first-original']})
            with self.assertRaises(FileExistsError): check._outputs({'pass': True}, {})
        public = next(v for k, v in values.items() if k.endswith('/result.json'))
        private = next(v for k, v in values.items() if k.endswith('/observations.json'))
        self.assertFalse(json.loads(public)['pass']); self.assertNotIn(b'private-secret-path', public)
        self.assertIn(b'first-original', private)

    def test_private_lists_keep_nested_actors_sidecars_exits_and_first_failure(self):
        actor = self.modules['mta_p2p_client_init'].Actor(200, 600, '/HOST/sleep', 'a' * 64, ((200, 600, 'S'),))
        value = {'launches': [{'preexec': actor, 'sidecar': b'original-sidecar'}],
            'child_exits': [{'actor': actor, 'exit_code': 125}],
            'failures': [{'traceback': 'first-original-trace'}]}
        decoded = json.loads(json.dumps(check._private_json(value)))
        self.assertEqual(200, decoded['launches'][0]['preexec']['pid'])
        self.assertEqual(b'original-sidecar'.hex(), decoded['launches'][0]['sidecar']['bytes_hex'])
        self.assertEqual(125, decoded['child_exits'][0]['exit_code'])
        self.assertEqual('first-original-trace', decoded['failures'][0]['traceback'])

    def test_python35_and_no_signal_network_old_checker_import(self):
        text = PATH.read_text(encoding='utf-8'); tree = ast.parse(text, feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        attrs = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertFalse({'kill', 'Popen', 'socket', 'chmod', 'chown', 'rmdir', 'rmtree'} & attrs)
        imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        self.assertFalse({'subprocess', 'socket', 'shutil', 'client_durable_store_linux_check', 'client_journal_transaction_linux_check'} & imports)
        self.assertIn('SLEEP_PATH = \'/usr/bin/sleep\'', text)


if __name__ == '__main__': unittest.main()
