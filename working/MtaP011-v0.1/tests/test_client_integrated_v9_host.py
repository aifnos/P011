"""Integrated v9 SOURCE/HOST Fake only; never ADB, target staging or RF."""
import ast
import base64
import builtins
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock

import test_client_init_p011_host as old

BASE = Path(__file__).absolute().parents[1]
HOST = BASE / 'host/client_init_integrated_v9_p011.py'
PROVIDER = BASE / 'candidate/client-integrated-v9/runtime/mta_client_linux_provider.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


driver = load('isolated_client_integrated_v9', HOST)
sys.path.insert(0, str(BASE / 'runtime'))
core = load('isolated_caps_v7_core_for_v9',
    BASE / 'candidate/client-caps-v7/runtime/mta_p2p_client_init.py')


def digest(raw): return hashlib.sha256(raw).hexdigest()


def clone(function, **bindings):
    namespace = dict(function.__globals__)
    namespace.update(bindings)
    return types.FunctionType(function.__code__, namespace, function.__name__,
        function.__defaults__, function.__closure__)


# Reuse old fixture source/target algorithms without modifying old globals.
fixture_source = clone(old.fixture_source, driver=driver)
target_run = clone(old.TargetFixture.run, driver=driver, fixture_source=fixture_source)


def caps_function(source):
    tree = ast.parse(source.decode('utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_caps_core')
    return ''.join(source.decode('utf-8').splitlines(True)[node.lineno - 1:node.end_lineno]).encode('utf-8')


HOST_CHANGES = (
    ('"""One fixed P011 CLIENT init/restore round; default source-only, no RF.',
     '"""Integrated v9 fixed P011 CLIENT init/restore; default source-only, no RF.'),
    ("EXECUTOR_SHA = '9cf0226e76254639c8fb7ab2638f6270ee0091b2485d49e00c0beff47d8f8602'",
     "EXECUTOR_SHA = '1b2b07f45d3564b743dfa66921bf831962ec6c3754b25e35c384ab699de362a3'"),
    ("PROVIDER_SHA = '8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544'",
     "PROVIDER_SHA = '8bb5dfae34ab7cc4db772957781c8c9385bf6285250137351bac70de685798d6'"),
    ("('mta_p2p_client_init', 'f5ebf037743f9fc910a7107425119576acdea649e16cf9e0660c0e9e257a607e')",
     "('mta_p2p_client_init', 'bb22e43ec191c04624e009539f954a9bcbb7b98520fb32adf6fd4f18f4e8139a')"),
    ("('mta_client_baseline', 'ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a')",
     "('mta_client_baseline', '1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1')"),
    ("('mta_client_pending', 'edd6553b847db6dc8e5d2be48256b8e3ee706adca25cbda316bcf28f357ff7cf')",
     "('mta_client_pending', 'cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af')"),
    ("('mta_client_store', 'c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd')",
     "('mta_client_store', '2c1bcd60013e416fe4d0ef961ceef3bc700ceae6bc40c4c079bab0a663b411cb')"),
    ("SOURCE_LOCATIONS = {\n    'mta_client_executor': BASE / 'candidate/client-init-nlink2/runtime/mta_client_executor.py',\n    'mta_client_process_owner': BASE / 'candidate/client-init-nlink2/runtime/mta_client_process_owner.py',\n    'mta_client_baseline': BASE / 'candidate/client-baseline-v3/runtime/mta_client_baseline.py',\n    'mta_p2p_client_init': BASE / 'candidate/client-baseline-v3/runtime/mta_p2p_client_init.py'}",
     "SOURCE_LOCATIONS = {\n    'mta_client_executor': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_executor.py',\n    'mta_client_process_owner': BASE / 'candidate/client-init-nlink2/runtime/mta_client_process_owner.py',\n    'mta_client_baseline': BASE / 'candidate/client-readparts-v6/runtime/mta_client_baseline.py',\n    'mta_p2p_client_init': BASE / 'candidate/client-caps-v7/runtime/mta_p2p_client_init.py',\n    'mta_client_pending': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_pending.py',\n    'mta_client_store': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_store.py',\n    'mta_client_linux_provider': BASE / 'candidate/client-integrated-v9/runtime/mta_client_linux_provider.py'}"),
    ("'python_invalid', 'baseline_invalid', 'stage_exists', 'stage_unknown', 'parent_pending',",
     "'python_invalid', 'baseline_invalid', 'stage_exists', 'stage_unknown', 'parent_pending', 'budget_before_rf',"),
    ('end=time.monotonic()+120', 'end=time.monotonic()+165'),
    (' return a.key()==b.key() and tuple((x.pid,x.tasks) for x in a.stock_actors)==tuple((x.pid,x.tasks) for x in b.stock_actors)',
     ' return a.key()==b.key() and all(x.live() for x in a.stock_actors) and all(x.live() for x in b.stock_actors)'),
    (" pending_absent();public['stage']='parent';parent=f.ParentExecutor(loaded);private['owners'].append(parent)",
     " pending_absent()\n if not end-time.monotonic()>=125:fail('budget_before_rf')\n public['stage']='parent';parent=f.ParentExecutor(loaded);private['owners'].append(parent)"),
    ('result=parent.finish(timeout=45)', 'result=parent.finish(timeout=90)'),
    ("'kind': 'client-init-baseline-v3-route-multiplicity'", "'kind': 'client-init-integrated-v9'"),
    ('out, err = value.communicate(data, timeout=150)', 'out, err = value.communicate(data, timeout=195)'),
    ("'MtaP011-ClientInitBaselineV3-'", "'MtaP011-ClientInitIntegratedV9-'"),
)


def run_target(elapsed_at_final_pending=0.0, pending=False, done=True):
    fixture = old.TargetFixture(pending=pending, done=done)
    fixture.actor.live = lambda: True  # Explicit synthetic fixture, not real actor proof.
    original = fixture.os.lstat
    count = [0]
    def lstat(path):
        if path == '/tmp/p011-mta-p2p-device.pending':
            count[0] += 1
            if count[0] == 4: fixture.clock = 100.0 + elapsed_at_final_pending
        return original(path)
    fixture.os.lstat = lstat
    value = target_run(fixture)
    return value, fixture, count[0]


class IntegratedV9HostTests(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'socket.socket', 'os.kill'):
            patcher = mock.patch(name, side_effect=AssertionError('actual process/socket/RF forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def test_provider_only_exact_caps_function_new_whole_sha(self):
        original = (BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_linux_provider.py').read_bytes()
        cap = (BASE / 'candidate/client-caps-v7/runtime/mta_client_linux_provider.py').read_bytes()
        merged = PROVIDER.read_bytes()
        self.assertEqual(digest(original), 'ae4bb7fa9dc9d030a35388f74325c0d2356b48bd62af344221cd26a29ebbf2ee')
        self.assertEqual(digest(cap), 'a49ce9bc6766d6b0182b45c833a3edaad307e4c27c45069871042ae49282f7c6')
        self.assertEqual(digest(merged), driver.PROVIDER_SHA)
        old_function, new_function = caps_function(original), caps_function(cap)
        self.assertEqual(caps_function(merged), new_function)
        self.assertEqual(1, merged.count(new_function))
        self.assertEqual(original, merged.replace(new_function, old_function, 1))

    def test_host_only_exact_fixed_pins_identity_budgets_same_diff(self):
        original = (BASE / 'host/client_init_baseline_v3_p011.py').read_bytes()
        self.assertEqual(digest(original), '518617174571a7f9b8b295083054a44212d67cac0e173340fa4bb4e47b647122')
        revised = HOST.read_bytes().decode('utf-8')
        for before, after in HOST_CHANGES:
            self.assertEqual(1, revised.count(after), after)
            revised = revised.replace(after, before, 1)
        self.assertEqual(original, revised.encode('utf-8'))
        self.assertEqual(19, len(driver.PINS)); self.assertEqual(7, len(driver.SOURCE_LOCATIONS))
        self.assertEqual(old.driver.STATUS_DRIVER_SHA, driver.STATUS_DRIVER_SHA)
        self.assertEqual(old.driver.ADB_PIN, driver.ADB_PIN)
        for source in (HOST.read_bytes(), PROVIDER.read_bytes(), Path(__file__).read_bytes()):
            ast.parse(source.decode('utf-8'), feature_version=(3, 5))

    def test_actual_pc_nineteen_graph_and_generated_source_pins_python35(self):
        report, rows, native, manifest, unused = driver.source_check()
        self.assertTrue(report['source_check_pass']); self.assertEqual(19, report['source_count'])
        self.assertEqual(digest(HOST.read_bytes()), report['driver_sha256'])
        self.assertEqual(tuple((name, pin) for name, pin, raw in rows), driver.PINS)
        for name, pin, raw in rows: self.assertEqual(digest(raw), pin)
        self.assertEqual({'mta_client_executor', 'mta_client_process_owner', 'mta_client_baseline',
            'mta_p2p_client_init', 'mta_client_pending', 'mta_client_store', 'mta_client_linux_provider'},
            set(driver.SOURCE_LOCATIONS))
        source, identity = driver.build_source(rows, native, manifest, 'c' * 32, report['driver_sha256'])
        tree = ast.parse(source, feature_version=(3, 5))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        self.assertLessEqual(len(source.encode('utf-8')), driver.MAX_SOURCE)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()), 2048)
        self.assertEqual(64, len(identity))
        for key in ('send_available', 'receive_available', 'phone_tested'): self.assertFalse(report[key])

    def test_same_real_actor_identity_ignores_raw_rs_but_keeps_live_and_keys(self):
        node = next(n for n in ast.parse(driver.TARGET).body if isinstance(n, ast.FunctionDef) and n.name == 'same')
        namespace = {}; exec(ast.get_source_segment(driver.TARGET, node), namespace)
        class Snapshot(object):
            def __init__(self, actor): self.stock_actors = (actor,)
            def key(self): return tuple(a.key() for a in self.stock_actors)
        a = core.Actor(100, 7, '/original', 'a' * 64, ((100, 7, 'R'),))
        b = core.Actor(100, 7, '/original', 'a' * 64, ((100, 7, 'S'),))
        self.assertNotEqual(a.tasks, b.tasks); self.assertTrue(namespace['same'](Snapshot(a), Snapshot(b)))
        for changed in (
                core.Actor(100, 7, '/original', 'a' * 64, ((100, 7, 'Z'),)),
                core.Actor(100, 8, '/original', 'a' * 64, ((100, 8, 'S'),)),
                core.Actor(100, 7, '/replaced', 'a' * 64, ((100, 7, 'S'),)),
                core.Actor(100, 7, '/original', 'b' * 64, ((100, 7, 'S'),)),
                core.Actor(100, 7, '/original', 'a' * 64, ((100, 7, 'S'), (101, 8, 'S')))):
            self.assertFalse(namespace['same'](Snapshot(a), Snapshot(changed)))
            self.assertFalse(namespace['same'](Snapshot(changed), Snapshot(a)))

    def test_default_source_only_never_execute_or_create_transport(self):
        with mock.patch.object(driver, 'source_check', return_value=({'source_check_pass': True}, None, None, None, None)), \
                mock.patch.object(driver, 'execute', side_effect=AssertionError('no execute')), \
                mock.patch.object(driver, 'HostAdbCall', side_effect=AssertionError('no ADB')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, driver.main([]))

    def test_less_than125_after_final_pending_fails_before_parent_rf(self):
        for elapsed in (40.001, 41.0):
            with self.subTest(elapsed=elapsed):
                result, fixture, pending_calls = run_target(elapsed)
                public = result['public']
                self.assertEqual(4, pending_calls)
                self.assertEqual('budget_before_rf', public['reason'])
                self.assertEqual('pending_before_rf', public['stage'])
                self.assertTrue(public['staging_verified']); self.assertFalse(public['rf_requested'])
                self.assertFalse(public['pass']); self.assertTrue(public['resource_pending'])
                self.assertIsNone(fixture.values['parent'])
                self.assertFalse(any(type(row) is tuple and row[0] in ('start', 'finish') for row in fixture.calls))
                self.assertEqual(265.0, fixture.values['end'])
                raw = {'stdout': ('RESULT=' + repr(result) + '\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode('utf-8'),
                    'stderr': b'', 'host_exit': 0}
                self.assertEqual('budget_before_rf', driver.parse(raw)['public']['reason'])

    def test_exact125_and_sufficient_fake_margin_keep_ttl20_finish90(self):
        for elapsed in (40.0, 39.999, 0.0):
            with self.subTest(elapsed=elapsed):
                result, fixture, unused = run_target(elapsed)
                self.assertTrue(result['public']['pass'])  # Explicit HOST orchestration fixture only.
                self.assertIn(('start', 20), fixture.calls); self.assertIn(('finish', 90), fixture.calls)
                self.assertEqual(265.0, fixture.values['end'])
                self.assertEqual(set(result['public']), set(driver._BOOLS) | {'stage', 'reason'})
                self.assertEqual(len(fixture.os.fds), len(fixture.os.closed))
                for key in ('send_available', 'receive_available', 'phone_tested'): self.assertFalse(result['public'][key])

    def test_existing_pending_and_ready_without_restore_still_not_success(self):
        result, fixture, unused = run_target(pending=True)
        self.assertEqual('pending_blocked', result['public']['reason'])
        self.assertFalse(result['public']['staging_attempted']); self.assertFalse(result['public']['rf_requested'])
        self.assertNotIn('executor', fixture.calls)
        result, fixture, unused = run_target(done=False)
        self.assertTrue(result['public']['client_init_observed']); self.assertFalse(result['public']['pass'])
        self.assertFalse(result['public']['restoration_verified']); self.assertTrue(result['public']['resource_pending'])

    def test_actual_host_transport_method195_once_no_timeout_kill_or_retry(self):
        for error in (None, subprocess.TimeoutExpired('private fixture', 195, output=b'partial', stderr=b'failure')):
            with self.subTest(timeout=error is not None):
                process = old.Process(error=error)
                creator = mock.Mock(return_value=process)
                call = driver.HostAdbCall(types.SimpleNamespace(ADB='fixed-fake', select_target=lambda: '8'),
                    'FAKE_NO_FILESYSTEM', _popen=creator, _process_type=old.Process,
                    _fstat=lambda fd: (_ for _ in ()).throw(OSError(9, 'fixture closed')))
                call.select()
                if error is None:
                    result, unused = call.run('print(1)')
                    self.assertEqual(0, result['host_exit']); self.assertTrue(call.ticket['pipes_closed'])
                else:
                    with self.assertRaises(subprocess.TimeoutExpired): call.run('print(1)')
                    self.assertIs(error, call.failure); self.assertIs(process, call.process)
                    self.assertEqual('UNKNOWN', call.raw['host_exit'])
                    with self.assertRaisesRegex(ValueError, 'once_or_target'): call.run('second')
                self.assertEqual(195, process.calls[0][1]); self.assertEqual(1, creator.call_count)
                self.assertFalse(process.forbidden)


if __name__ == '__main__': unittest.main()
