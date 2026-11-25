"""Prepare v10: new fixed graph and HOST-only orchestration; never ADB/RF."""
import ast
import base64
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import types
import unittest
from unittest import mock

import test_client_init_p011_host as old

BASE = Path(__file__).absolute().parents[1]
HOST = BASE / 'host/client_init_prepare_v10_p011.py'
PHASE = BASE / 'candidate/client-prepare-v10/runtime/mta_client_two_phase_lease.py'
V9_SHA = '302cfa0d0ef395f45786da5e3c04ef6c4701d78b1aae8d9fd817d0e894f87161'
PHASE_SHA = 'cc402317c4d07a37d82f2209f32bc688a212d04a1a3ec8fccdc95aa6ce6209d1'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load('isolated_client_prepare_v10_host', HOST)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def clone(function, **bindings):
    namespace = dict(function.__globals__)
    namespace.update(bindings)
    return types.FunctionType(function.__code__, namespace, function.__name__,
        function.__defaults__, function.__closure__)


# Clone algorithms into a private namespace; old driver and fixtures are unchanged.
fixture_source = clone(old.fixture_source, driver=driver)
target_run = clone(old.TargetFixture.run, driver=driver, fixture_source=fixture_source)

HOST_CHANGES = (
    (
        "\"\"\"Integrated v9 fixed P011 CLIENT init/restore; default source-only, no RF.",
        "\"\"\"Prepare v10 fixed P011 CLIENT init/restore; default source-only, no RF."
    ),
    (
        "('mta_client_two_phase_lease', '402cf2decd35aa31b47c07828e5ee14b7dd06bb5429740736fd11a54dfd11005')",
        "('mta_client_two_phase_lease', 'cc402317c4d07a37d82f2209f32bc688a212d04a1a3ec8fccdc95aa6ce6209d1')"
    ),
    (
        "    'mta_client_linux_provider': BASE / 'candidate/client-integrated-v9/runtime/mta_client_linux_provider.py'}",
        "    'mta_client_linux_provider': BASE / 'candidate/client-integrated-v9/runtime/mta_client_linux_provider.py',\n    'mta_client_two_phase_lease': BASE / 'candidate/client-prepare-v10/runtime/mta_client_two_phase_lease.py'}"
    ),
    (
        "end=time.monotonic()+165",
        "end=time.monotonic()+195"
    ),
    (
        "if not end-time.monotonic()>=125:fail",
        "if not end-time.monotonic()>=155:fail"
    ),
    (
        "ready_end=time.monotonic()+22",
        "ready_end=time.monotonic()+52"
    ),
    (
        "'kind': 'client-init-integrated-v9'",
        "'kind': 'client-init-prepare-v10'"
    ),
    (
        "out, err = value.communicate(data, timeout=195)",
        "out, err = value.communicate(data, timeout=225)"
    ),
    (
        "'MtaP011-ClientInitIntegratedV9-'",
        "'MtaP011-ClientInitPrepareV10-'"
    ),
    (
        "'restoration_pending', 'os_error', 'unexpected', 'interrupted', 'transport_unknown')",
        "'restoration_pending', 'init_not_ready', 'os_error', 'unexpected', 'interrupted', 'transport_unknown')"
    ),
    (
        "public['stage']='complete';public['reason']='complete' if public['pass'] else 'restoration_pending'",
        "public['stage']='complete';public['reason']='complete' if public['pass'] else 'init_not_ready' if public['restoration_verified'] else 'restoration_pending'"
    )
)


def run_target(elapsed_at_final_pending=0.0, ready_delay=None, final_not_ready=False):
    fixture = old.TargetFixture()
    fixture.actor.live = lambda: True  # Synthetic only, not a kernel observation.
    original = fixture.os.lstat
    pending_count = [0]
    def lstat(path):
        if path == '/tmp/p011-mta-p2p-device.pending':
            pending_count[0] += 1
            if pending_count[0] == 4:
                fixture.clock = 100.0 + elapsed_at_final_pending
        return original(path)
    fixture.os.lstat = lstat
    if ready_delay is not None:
        base_parent = fixture.modules['mta_client_executor'].ParentExecutor
        class DelayedParent(base_parent):
            def __init__(self, loaded):
                base_parent.__init__(self, loaded)
                self.pipes = [{'fd': 70}, {'fd': 71}, {'fd': 72}]
                self.io = types.SimpleNamespace(ready=self.advance)
                self.began = None
            def start(self, ttl):
                result = base_parent.start(self, ttl)
                self.frames = []; self.began = fixture.clock
                return result
            def poll(self):
                fixture.calls.append(('poll', fixture.clock - self.began))
                if fixture.clock >= self.began + ready_delay:
                    self.frames = [{'client_init_ready': True, 'done': fixture.done}]
            def advance(self, fds, timeout):
                fixture.calls.append(('ready_wait', tuple(fds), timeout))
                event_time = self.began + ready_delay
                fixture.clock = min(fixture.clock + timeout, event_time) if fixture.clock < event_time else fixture.clock + timeout
        fixture.modules['mta_client_executor'].ParentExecutor = DelayedParent
    elif final_not_ready:
        base_parent = fixture.modules['mta_client_executor'].ParentExecutor
        class NoInitParent(base_parent):
            def start(self, ttl):
                result = base_parent.start(self, ttl)
                self.frames = [{'client_init_ready': False, 'done': True}]
                return result
        fixture.modules['mta_client_executor'].ParentExecutor = NoInitParent
    result = target_run(fixture)
    return result, fixture, pending_count[0]


class PrepareV10HostTests(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'socket.socket', 'os.kill', 'os.fork'):
            patcher = mock.patch(name, side_effect=AssertionError('actual process/socket/RF forbidden'),
                create=True)
            patcher.start(); self.addCleanup(patcher.stop)

    def test_exact_v9_inverse_and_new_phase_only_graph_change_python35(self):
        original = (BASE / 'host/client_init_integrated_v9_p011.py').read_bytes()
        self.assertEqual(V9_SHA, digest(original))
        revised = HOST.read_bytes().decode('utf-8')
        for before, after in HOST_CHANGES:
            self.assertEqual(1, revised.count(after), after)
            revised = revised.replace(after, before, 1)
        self.assertEqual(original, revised.encode('utf-8'))
        self.assertEqual(19, len(driver.PINS))
        self.assertEqual(8, len(driver.SOURCE_LOCATIONS))
        self.assertEqual(PHASE, driver.SOURCE_LOCATIONS['mta_client_two_phase_lease'])
        self.assertEqual(PHASE_SHA, dict(driver.PINS)['mta_client_two_phase_lease'])
        self.assertEqual(PHASE_SHA, digest(PHASE.read_bytes()))
        for raw in (HOST.read_bytes(), Path(__file__).read_bytes(), PHASE.read_bytes()):
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))

    def test_new_actual_pc_nineteen_graph_loader_has_real_provider_restore_override(self):
        # One new graph check only: PC fixed source reads, never target or default IO.
        report, rows, native, manifest, unused = driver.source_check()
        self.assertTrue(report['source_check_pass']); self.assertEqual(19, report['source_count'])
        self.assertEqual(digest(HOST.read_bytes()), report['driver_sha256'])
        self.assertEqual(driver.PINS, tuple((name, pin) for name, pin, raw in rows))
        for name, pin, raw in rows: self.assertEqual(pin, digest(raw))
        source, identity = driver.build_source(rows, native, manifest, 'c' * 32, report['driver_sha256'])
        tree = ast.parse(source, feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertLessEqual(len(source.encode('utf-8')), driver.MAX_SOURCE)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()), 2048)
        self.assertEqual(64, len(identity))
        namespace = {'PINS': driver.PINS,
            'ENCODED': tuple((name, pin, base64.b64encode(raw).decode('ascii')) for name, pin, raw in rows)}
        with mock.patch('os.open', side_effect=AssertionError('default IO forbidden')), \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('libc construction forbidden')):
            exec(driver.LOADER, namespace)
        modules = namespace['modules']
        phase = modules['mta_client_two_phase_lease'].TwoPhaseClientInitLease
        provider = modules['mta_client_linux_provider']
        lease = provider.LinuxClientInitLease
        self.assertEqual((phase,), lease.__bases__)
        self.assertIs(phase.start, lease.start)
        self.assertIs(lease.restore, lease.__dict__['restore'])
        self.assertIsNot(phase.restore, lease.restore)
        self.assertEqual((60, None), lease.restore.__defaults__)
        self.assertEqual((20, None), phase.restore.__defaults__)
        self.assertEqual(tuple(name for name, pin in driver.PINS),
            modules['mta_client_executor'].MODULES)
        self.assertEqual((modules['mta_client_two_phase_lease'].DirectChildLaunchBridge,),
            provider.LinuxDirectChildLaunchBridge.__bases__)
        for key in ('send_available', 'receive_available', 'phone_tested'):
            self.assertFalse(report[key])

    def test_default_source_only_still_has_no_transport_or_execution(self):
        with mock.patch.object(driver, 'source_check', return_value=({'source_check_pass': True}, None, None, None, None)), \
                mock.patch.object(driver, 'execute', side_effect=AssertionError('no execute')), \
                mock.patch.object(driver, 'HostAdbCall', side_effect=AssertionError('no ADB')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, driver.main([]))

    def test_less_than155_margin_blocks_before_parent_and_rf(self):
        for elapsed in (40.001, 41.0):
            with self.subTest(elapsed=elapsed):
                result, fixture, count = run_target(elapsed)
                public = result['public']
                self.assertEqual(4, count); self.assertEqual('budget_before_rf', public['reason'])
                self.assertEqual('pending_before_rf', public['stage'])
                self.assertTrue(public['staging_verified'])
                self.assertFalse(public['rf_requested']); self.assertFalse(public['pass'])
                self.assertTrue(public['resource_pending']); self.assertIsNone(fixture.values['parent'])
                self.assertEqual(295.0, fixture.values['end'])
                self.assertFalse(any(type(row) is tuple and row[0] in ('start', 'finish') for row in fixture.calls))

    def test_exact155_after40_seconds_and_sufficient_margin_keep_ttl20_finish90(self):
        for elapsed in (40.0, 39.999, 0.0):
            with self.subTest(elapsed=elapsed):
                result, fixture, unused = run_target(elapsed)
                self.assertTrue(result['public']['pass'])  # HOST Fake orchestration, not P011.
                self.assertEqual(295.0, fixture.values['end'])
                self.assertIn(('start', 20), fixture.calls); self.assertIn(('finish', 90), fixture.calls)
                self.assertEqual(len(fixture.os.fds), len(fixture.os.closed))
                for key in ('send_available', 'receive_available', 'phone_tested'):
                    self.assertFalse(result['public'][key])

    def test_actual_target_ready_window52_observes40_and51_999_not_later(self):
        for delay, expected in ((40.0, True), (51.999, True), (52.05, False)):
            with self.subTest(delay=delay):
                result, fixture, unused = run_target(ready_delay=delay)
                self.assertEqual(expected, result['public']['client_init_observed'])
                self.assertEqual(expected, result['public']['pass'])
                self.assertIn(('start', 20), fixture.calls); self.assertIn(('finish', 90), fixture.calls)
                waits = [row for row in fixture.calls if type(row) is tuple and row[0] == 'ready_wait']
                self.assertTrue(waits); self.assertLessEqual(len(waits), 1041)
                self.assertTrue(all(row[1:] == ((71, 72), .05) for row in waits))

    def test_final_done_without_init_ready_reports_init_not_ready_not_restore_failure(self):
        result, fixture, unused = run_target(final_not_ready=True)
        public = result['public']
        self.assertTrue(public['restoration_verified'])
        self.assertFalse(public['client_init_observed']); self.assertFalse(public['pass'])
        self.assertFalse(public['resource_pending']); self.assertEqual('init_not_ready', public['reason'])
        self.assertEqual([{'client_init_ready': False, 'done': True}], fixture.values['parent'].frames)
        raw = {'stdout': ('RESULT=' + repr(result) + '\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode('utf-8'),
            'stderr': b'', 'host_exit': 0}
        parsed = driver.parse(raw)
        self.assertTrue(parsed['public']['restoration_verified'])
        self.assertEqual('init_not_ready', parsed['public']['reason']); self.assertFalse(parsed['public']['pass'])

    def test_host_transport225_once_timeout_retains_original_without_kill_or_retry(self):
        for error in (None, subprocess.TimeoutExpired('private fixture', 225,
                output=b'partial', stderr=b'failure')):
            with self.subTest(timeout=error is not None):
                process = old.Process(error=error)
                creator = mock.Mock(return_value=process)
                call = driver.HostAdbCall(types.SimpleNamespace(ADB='fixed-fake', select_target=lambda: '8'),
                    'FAKE_NO_FILESYSTEM', _popen=creator, _process_type=old.Process,
                    _fstat=lambda fd: (_ for _ in ()).throw(OSError(9, 'fixture closed')))
                call.select()
                if error is None:
                    raw, unused = call.run('print(1)')
                    self.assertEqual(0, raw['host_exit']); self.assertTrue(call.ticket['pipes_closed'])
                else:
                    with self.assertRaises(subprocess.TimeoutExpired): call.run('print(1)')
                    self.assertIs(error, call.failure); self.assertIs(process, call.process)
                    self.assertEqual('UNKNOWN', call.raw['host_exit'])
                    with self.assertRaisesRegex(ValueError, 'once_or_target'): call.run('second')
                self.assertEqual(225, process.calls[0][1]); self.assertEqual(1, creator.call_count)
                self.assertFalse(process.forbidden)


if __name__ == '__main__': unittest.main()
