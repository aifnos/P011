"""v12 HOST Fake only; old suites/actual OS and the formal source graph are not run."""
import ast
import errno
import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'tests'))
NEW = BASE / 'candidate/client-diagnostic-v12/runtime'
OLD_F = BASE / 'candidate/client-tmp-alias-v11/runtime/mta_client_executor.py'
OLD_PHASE = BASE / 'candidate/client-prepare-v10/runtime/mta_client_two_phase_lease.py'
BUDGET = BASE / 'candidate/client-recovery-budget-v8/runtime'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


with mock.patch.dict(sys.modules):
    f = load('diagnostic_v12_f', NEW / 'mta_client_executor.py')
    old_f = load('diagnostic_v11_f', OLD_F)
    sys.modules['mta_client_executor'] = f
    ff = load('diagnostic_v12_f_fixture', BASE / 'tests/test_client_executor.py')
    pending = load('mta_client_pending', BUDGET / 'mta_client_pending.py')
    store = load('mta_client_store', BUDGET / 'mta_client_store.py')
    phase = load('mta_client_two_phase_lease', NEW / 'mta_client_two_phase_lease.py')
    pf = load('diagnostic_v12_phase_fixture', BASE / 'tests/test_client_two_phase_lease.py')


GROUP_CODES = {'none': frozenset(('not_recorded',)), 'not_recorded': frozenset(('not_recorded',)),
    'other': frozenset(('not_recorded',)), 'core': ff.core._CODES,
    'os': frozenset(('io_error',)), 'interrupt': frozenset(('interrupted',))}


def classify(error):
    # Explicit HOST producer seam, not the actual Linux Provider or source graph.
    if type(error) is ff.core.ClientInitError:
        return ('core', error.code if error.code in ff.core._CODES else 'not_recorded')
    if type(error) is OSError: return ('os', 'io_error')
    if type(error) in (KeyboardInterrupt, SystemExit, GeneratorExit): return ('interrupt', 'interrupted')
    return ('other', 'not_recorded')


class CountingClock(ff.Clock):
    def __init__(self): ff.Clock.__init__(self); self.calls = 0
    def __call__(self): self.calls += 1; return ff.Clock.__call__(self)


class Diagnostics(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen', 'socket.socket', 'ctypes.CDLL'):
            patcher = mock.patch(target, side_effect=AssertionError('actual platform forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('fork', 'kill', 'execve', 'waitpid'):
            patcher = mock.patch('os.' + name, side_effect=AssertionError('actual process forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for module in (f, old_f):
            for name in ('validate', 'open', 'read', 'write', 'close', 'popen', 'ready', 'fstat', 'stat'):
                patcher = mock.patch.object(module._LinuxIo, name, side_effect=AssertionError('actual IO forbidden'))
                patcher.start(); self.addCleanup(patcher.stop)

    def child(self, module=f):
        clock = CountingClock(); io = ff.FakeIo(clock)
        issuer = types.FunctionType(ff.deployment.__code__, dict(ff.deployment.__globals__, f=module),
            argdefs=ff.deployment.__defaults__)
        dep, state = issuer(io)
        provider_module = dep.modules['mta_client_linux_provider']
        provider_module._DIAGNOSTIC_GROUP_CODES = GROUP_CODES
        provider_module._diagnostic_error = classify
        child = module.ClientExecutor(dep, io, clock, ff.Control(), _environ={'P011_CLIENT_EXECUTABLE_FD': '60'})
        return child, dep, state, io, clock

    def lines(self, io):
        writes = [data for fd, data in io.writes if fd == 2]
        self.assertEqual(1, len(writes))
        self.assertLessEqual(len(writes[0]), 1536)
        writes[0].decode('ascii')
        lines = writes[0].splitlines(keepends=True)
        self.assertLessEqual(len(lines), 4)
        self.assertTrue(all(len(line) <= 384 and line.endswith(b'\n') for line in lines))
        return writes[0]

    def test_positive_same_stdout_clock_auth_and_closure_as_v11(self):
        traces = []
        for module in (old_f, f):
            child, dep, state, io, clock = self.child(module)
            frames, calls = [], []
            child.emit = frames.append
            original = dep.modules['mta_client_linux_provider'].assemble
            def assemble(manifest):
                values = original(manifest)
                for obj, name in ((values[1], 'authenticate_finish'), (values[3], 'verify_closed'),
                                  (values[0], 'closed_resources'), (values[2], 'status')):
                    fn = getattr(obj, name)
                    def traced(*args, _fn=fn, _name=name): calls.append(_name); return _fn(*args)
                    setattr(obj, name, traced)
                return values
            dep.modules['mta_client_linux_provider'].assemble = assemble
            result = child.run(); traces.append((result, frames, calls, clock.calls, io.closes))
            if module is f: self.assertIn(b'event=complete site=complete', self.lines(io))
        self.assertEqual(traces[0], traces[1])

    def test_start_failure_reason_is_frozen_before_restore_mutates_phase(self):
        child, dep, state, io, clock = self.child(); state.ready = False
        lease = dep.modules['mta_client_linux_provider'].assemble(dep.manifest)[4]
        lease.reason = 'expired'
        lease._diagnostic_start = {'site': 'initial_snapshot', 'stage': 'none', 'error_group': 'core',
            'error_code': 'expired', 'result': 'raised'}
        restore = lease.restore
        def changed(timeout):
            self.assertEqual('expired', child._diagnostic_start_reason)
            lease.reason = 'unexpected_provider_error'; lease._diagnostic_start['error_code'] = 'invalid_actor'
            return restore(timeout)
        lease.restore = changed
        result = child.run(); raw = self.lines(io)
        self.assertTrue(result['done']); self.assertFalse(child.init_ready)
        self.assertIn(b'error_code=expired', raw); self.assertIn(b'reason=expired', raw)
        self.assertNotIn(b'error_code=invalid_actor', raw)

    def test_restore_first_exception_separate_from_start_no_exception_text(self):
        child, dep, state, io, clock = self.child()
        error = ff.core.ClientInitError('origin_changed'); state.restore_error = error
        result = child.run(); raw = self.lines(io)
        self.assertFalse(result['done']); self.assertIs(child.failures[0], error)
        self.assertIn(b'event=restore site=restore', raw)
        self.assertIn(b'error_group=core error_code=origin_changed result=raised', raw)
        self.assertNotIn(b'event=complete', raw)

    def test_returned_restore_does_not_hide_first_complete_predicate(self):
        child, dep, state, io, clock = self.child(); state.ticket_auth = False
        self.assertFalse(child.run()['done'])
        self.assertIn(b'event=restore', self.lines(io))
        self.assertEqual('finish_auth', child._diagnostic_complete['site'])
        self.assertEqual('rejected', child._diagnostic_complete['result'])

    def test_complete_shortcircuit_calls_remain_once(self):
        child, dep, state, io, clock = self.child(); state.bridge_closed = False
        provider, store_value, owner, bridge, lease = dep.modules['mta_client_linux_provider'].assemble(dep.manifest)
        calls = []
        store_value.authenticate_finish = lambda *args: calls.append('auth') or True
        bridge.verify_closed = lambda: calls.append('bridge') or False
        provider.closed_resources = lambda *args: self.fail('late provider proof forbidden')
        self.assertFalse(child.run()['done']); self.assertEqual(['auth', 'bridge'], calls)
        self.assertEqual('bridge_closed', child._diagnostic_complete['site'])

    def test_complete_exception_keeps_exact_error_and_site(self):
        child, dep, state, io, clock = self.child()
        store_value = dep.modules['mta_client_linux_provider'].assemble(dep.manifest)[1]
        error = OSError(errno.EIO, 'PRIVATE-SECRET-FIXTURE')
        def failed(*args): raise error
        store_value.authenticate_finish = failed
        self.assertFalse(child.run()['done']); self.assertIs(child.failures[0], error)
        raw = self.lines(io); self.assertIn(b'event=complete site=finish_auth', raw)
        self.assertIn(b'error_group=os error_code=io_error result=raised', raw)
        self.assertNotIn(b'PRIVATE', raw)

    def test_unknown_factory_preserves_pending_without_restore(self):
        child, dep, state, io, clock = self.child(); state.factory_error = RuntimeError('PRIVATE-SECRET-FIXTURE')
        self.assertTrue(child.run()['resource_pending'])
        raw = self.lines(io); self.assertIn(b'event=start site=assembly', raw)
        self.assertNotIn(b'event=restore', raw); self.assertNotIn(b'PRIVATE', raw)

    def test_bad_diagnostic_property_cannot_block_complete_or_restore(self):
        child, dep, state, io, clock = self.child()
        lease_cls = dep.modules['mta_client_linux_provider'].LinuxClientInitLease
        def failed(obj): raise MemoryError()
        lease_cls._diagnostic_restore = property(failed)
        result = child.run(); self.assertTrue(result['done']); self.assertEqual([], child.failures)
        self.assertIsNone(child._diagnostic_restore); self.lines(io)

    def test_diagnostic_write_failure_occurs_after_restore_and_no_retry(self):
        child, dep, state, io, clock = self.child(); calls = []
        lease = dep.modules['mta_client_linux_provider'].assemble(dep.manifest)[4]
        real_restore = lease.restore
        def restore(timeout): calls.append('restore'); return real_restore(timeout)
        lease.restore = restore
        def write(fd, data): calls.append(('write', fd)); raise KeyboardInterrupt()
        io.write = write
        self.assertTrue(child.run()['done']); self.assertEqual(['restore', ('write', 2)], calls)
        child._write_diagnostics(); self.assertEqual(2, len(calls)); self.assertEqual([], child.failures)

    def test_short_write_no_retry_or_success_change(self):
        child, dep, state, io, clock = self.child(); calls = []
        def write(fd, data): calls.append((fd, data)); return 1
        io.write = write
        self.assertTrue(child.run()['done']); child._write_diagnostics()
        self.assertEqual(1, len(calls)); self.assertEqual(2, calls[0][0])

    def test_arbitrary_schema_codes_and_non_ascii_fields_are_not_emitted(self):
        child, dep, state, io, clock = self.child()
        lease = dep.modules['mta_client_linux_provider'].assemble(dep.manifest)[4]
        lease._diagnostic_start = {'site': '/PRIVATE', 'stage': '凭据', 'error_group': 'core',
            'error_code': 'PRIVATE-SECRET-FIXTURE', 'result': 'free_text'}
        self.assertTrue(child.run()['done']); raw = self.lines(io)
        self.assertNotIn(b'PRIVATE', raw); self.assertEqual('start', child._diagnostic_start['site'])
        self.assertEqual('not_recorded', child._diagnostic_start['error_code'])
        self.assertEqual('not_recorded', child._diagnostic_start['error_group'])

    def test_error_subclass_cannot_smuggle_code_or_stringification(self):
        child, dep, state, io, clock = self.child()
        class Foreign(ff.core.ClientInitError):
            def __str__(self): raise AssertionError('no exception formatting')
        error = Foreign('origin_changed'); error.code = 'PRIVATE-SECRET-FIXTURE'; state.restore_error = error
        self.assertFalse(child.run()['done']); raw = self.lines(io)
        self.assertIn(b'error_group=other error_code=not_recorded', raw)
        self.assertNotIn(b'PRIVATE', raw)

    def test_default_unavailable_creates_no_diagnostic_write(self):
        io = ff.FakeIo(); child = f.ClientExecutor(_io=io)
        self.assertEqual('unavailable', child.run()['reason']); self.assertEqual([], io.writes)


class PhaseDiagnostics(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(sys.modules, {'mta_client_store': store,
            'mta_client_pending': pending, 'mta_client_two_phase_lease': phase})
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(phase.launches, 'store_module', store)
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self):
        case = pf.TwoPhaseLeaseTests(methodName='runTest'); case.setUp(); self.addCleanup(case.doCleanups)
        values = case.make(); self.assertIs(type(values[0]), phase.TwoPhaseClientInitLease)
        values[1]._diagnostic_error = classify
        return values

    def test_success_is_actual_new_start_over_existing_fake_components(self):
        values = self.make(); result = values[0].start()
        self.assertTrue(result['client_init_ready']); self.assertEqual(2, len(values[0].launches))
        self.assertEqual({'site': 'complete', 'stage': 'client_init_ready', 'error_group': 'none',
            'error_code': 'not_recorded', 'result': 'returned'}, values[0]._diagnostic_start)
        self.assertNotIn('_diagnostic_start', result)

    def test_initial_snapshot_exception_is_fixed_and_pre_resource(self):
        values = self.make(); error = OSError(errno.EIO, 'PRIVATE-SECRET-FIXTURE')
        def failed(deadline): raise error
        values[1].snapshot = failed
        result = values[0].start(); diagnostic = values[0]._diagnostic_start
        self.assertEqual('unexpected_provider_error', result['reason'])
        self.assertEqual('initial_snapshot', diagnostic['site']); self.assertEqual('none', diagnostic['stage'])
        self.assertEqual(('os', 'io_error', 'raised'), tuple(diagnostic[k] for k in ('error_group', 'error_code', 'result')))
        self.assertEqual([], values[4]._tickets); self.assertNotIn('create_client', values[1].calls)

    def test_cancelled_watchdog_records_real_durable_stage_without_fake_handle(self):
        values = self.make(); cancelled = [False]
        values[1].extra_hook = lambda name, args: cancelled.__setitem__(0, True) if name == 'fork' else None
        result = values[0].start(cancelled=lambda: cancelled[0])
        diagnostic = values[0]._diagnostic_start
        self.assertEqual('cancelled', result['reason']); self.assertEqual('watchdog_role', diagnostic['site'])
        self.assertEqual('watchdog_intent', diagnostic['stage']); self.assertEqual('cancelled', diagnostic['error_code'])
        self.assertEqual({}, values[0].handles); self.assertTrue(values[0].launches)

    def test_diagnostic_classifier_error_cannot_change_original_catch(self):
        values = self.make()
        def failed(deadline): raise ValueError('PRIVATE')
        def failed_classifier(error): raise KeyboardInterrupt()
        values[1].snapshot = failed; values[1]._diagnostic_error = failed_classifier
        result = values[0].start()
        self.assertEqual('unexpected_provider_error', result['reason']); self.assertFalse(result['client_init_ready'])
        self.assertEqual('not_recorded', values[0]._diagnostic_start['result'])

    def test_start_failure_stays_frozen_when_existing_restore_runs(self):
        values = self.make(); cancelled = [False]
        values[1].extra_hook = lambda name, args: cancelled.__setitem__(0, True) if name == 'fork' else None
        values[0].start(cancelled=lambda: cancelled[0]); exact = values[0]._diagnostic_start
        self.assertTrue(values[0].restore()['cleanup_complete'])
        self.assertIs(exact, values[0]._diagnostic_start); self.assertEqual('cancelled', exact['error_code'])


class SourceScope(unittest.TestCase):
    def test_python35_and_frozen_origins_unchanged(self):
        for name in ('mta_client_executor.py', 'mta_client_two_phase_lease.py'):
            ast.parse((NEW / name).read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertEqual('1e8e1632b9170964f8471f106a50988e2d75ccfba7b1c5ed49a604323d481e43',
            hashlib.sha256(OLD_F.read_bytes()).hexdigest())
        self.assertEqual('cc402317c4d07a37d82f2209f32bc688a212d04a1a3ec8fccdc95aa6ce6209d1',
            hashlib.sha256(OLD_PHASE.read_bytes()).hexdigest())

    def test_phase_restore_bridge_and_nonstart_methods_are_byte_identical(self):
        old, new = OLD_PHASE.read_text(), (NEW / 'mta_client_two_phase_lease.py').read_text()
        self.assertEqual(old[old.index('    def restore(self, timeout=20'):], new[new.index('    def restore(self, timeout=20'):])
        self.assertEqual(old[:old.index('class TwoPhaseClientInitLease')], new[:new.index('class TwoPhaseClientInitLease')])
        for key in ('_role',):
            old_tree, new_tree = ast.parse(old), ast.parse(new)
            defs = [next(n for n in ast.walk(t) if isinstance(n, ast.FunctionDef) and n.name == key) for t in (old_tree, new_tree)]
            self.assertEqual(ast.dump(defs[0]), ast.dump(defs[1]))

    def test_parent_loader_watchdog_and_public_schema_ast_unchanged(self):
        old, new = ast.parse(OLD_F.read_text()), ast.parse((NEW / 'mta_client_executor.py').read_text())
        for key in ('ParentExecutor', 'DeploymentLoader', '_ReadOwner', 'watchdog', 'main', '_public', '_actor', '_reader_closed'):
            nodes = [next(n for n in t.body if getattr(n, 'name', None) == key) for t in (old, new)]
            self.assertEqual(ast.dump(nodes[0]), ast.dump(nodes[1]), key)

    def test_start_only_diagnostic_assignments_and_calls_preserve_original_algorithm(self):
        class Strip(ast.NodeTransformer):
            def visit_Assign(self, node):
                if any(isinstance(t, ast.Name) and t.id == 'site' for t in node.targets): return None
                return self.generic_visit(node)
            def visit_Expr(self, node):
                call = node.value
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == '_start_diagnostic': return None
                return self.generic_visit(node)
        defs = []
        for path in (OLD_PHASE, NEW / 'mta_client_two_phase_lease.py'):
            tree = ast.parse(path.read_text()); cls = next(n for n in tree.body if getattr(n, 'name', '') == 'TwoPhaseClientInitLease')
            defs.append(next(n for n in cls.body if getattr(n, 'name', '') == 'start'))
        self.assertEqual(ast.dump(defs[0]), ast.dump(Strip().visit(defs[1])))


if __name__ == '__main__': unittest.main()
