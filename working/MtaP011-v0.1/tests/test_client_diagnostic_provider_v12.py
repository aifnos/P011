"""v12 passive SOURCE/Fake diagnostics only; no OS, RF or restore proof."""
import ast
import copy
import hashlib
from pathlib import Path
import types
import unittest
from unittest import mock

import test_client_tmp_alias_provider_v11 as old
from test_p2p_client_init import snapshot, actor

BASE = old.BASE
PATH = BASE / 'candidate/client-diagnostic-v12/runtime/mta_client_linux_provider.py'
ORIGINAL = old.CANDIDATE / 'mta_client_linux_provider.py'
ORIGINAL_SHA = '4f4cec03ddec5ec8e91f9f04ccdc91beb7e54a725a1481ba73c7045338883df6'
p = old.load('v12_private_provider_diagnostic', PATH, old.alias)


def manifest(module):
    value = old.manifest()
    fields = dict((key, getattr(value, key)) for key in module._KEYS)
    fields['status_manifest'] = dict(value.status_manifest)
    return module.ProviderManifest(fields, _manifest_sha256=value.manifest_sha256)


class RestoreRun(object):
    """Callbacks are explicit Fake control-flow seams, never authentic producers."""
    def __init__(self, module=p, failure=None, error=None, stage='cleanup_intent'):
        self.module, self.calls, self.clocks = module, [], 0
        self.failure, self.error = failure, error
        self.provider, self.store, self.owner, self.bridge, self.lease = module.assemble(manifest(module))
        self.lease.clock = self.clock
        self.record = module.core.Journal(self.lease.identity, stage, snapshot(), 20.)
        self.lock = object()
        self.store._recovery_deadline = None  # Fixed v8 control-flow field in this old Fake Store seam.
        self.store._restore_reader = object()  # Fake branch, not a trusted reader.
        self.provider.close_resources = lambda *args: self.call('close_resources', module.core.CloseProof(0, (), ()))
        self.store.acquire = lambda *args: self.call('acquire', self.lock)
        self.store.current = lambda *args: self.call('current', self.record)
        self.lease._known_locks_before_acquire = lambda *args: self.call('known_locks')
        self.lease._executor = lambda *args, **kwargs: self.call('executor', types.SimpleNamespace(role='owner', actor=actor(100)))
        self.lease._pending_admission = lambda *args: self.call('current_admission', True)
        self.lease._save = self.save
        self.lease._baseline = self.baseline
        self.bridge.cleanup = lambda *args: self.call('bridge_cleanup', True)
        self.bridge.verify_closed = lambda: self.call('close_proof', True)
        self.lease._finish_receipt = lambda *args: self.call('finish_receipt')
        self.baseline_count = 0

    def clock(self):
        self.clocks += 1
        return 1.

    def call(self, site, result=None):
        self.calls.append(site)
        if self.failure == site: raise self.error
        return result

    def baseline(self, *args):
        names = ('baseline_before_children', 'baseline_after_children', 'baseline_after_delete', 'baseline_terminal')
        name = names[self.baseline_count % 4]
        self.baseline_count += 1
        return self.call(name)

    def save(self, record):
        self.call('save_cleanup_intent' if record.stage == 'cleanup_intent' else 'save_cleanup_verified')
        self.record = self.lease.record = record


def function(tree, cls, name):
    body = tree.body if cls is None else next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls).body
    return next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)


class StripDiagnostics(ast.NodeTransformer):
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == 'diagnostic_site': return None
            if isinstance(target, ast.Attribute) and target.attr == '_diagnostic_restore': return None
        return self.generic_visit(node)
    def visit_Expr(self, node):
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == '_note_restore_diagnostic':
            return None
        return self.generic_visit(node)


class DiagnosticProviderV12Tests(unittest.TestCase):
    def setUp(self):
        for name in ('os.open', 'os.close', 'os.readlink', 'os.kill', 'os.fork',
                'socket.socket', 'subprocess.Popen', 'ctypes.CDLL'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS/RF forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for module in (p, old.p):
            module._OWNERS[:] = []
            self.addCleanup(lambda module=module: module._OWNERS.__setitem__(slice(None), []))

    def test_exact_original_methods_and_restore_ast_python35(self):
        original, candidate = ORIGINAL.read_bytes(), PATH.read_bytes()
        self.assertEqual(ORIGINAL_SHA, hashlib.sha256(original).hexdigest())
        old_methods, new_methods = old.method_sources(original), old.method_sources(candidate)
        changed = {'LinuxClientInitLease.__init__', 'LinuxClientInitLease.restore'}
        added = {'_diagnostic_error', 'LinuxClientInitLease._note_restore_diagnostic'}
        self.assertEqual(added, set(new_methods) - set(old_methods))
        for name, raw in old_methods.items():
            if name not in changed: self.assertEqual(raw, new_methods[name], name)
        a, b = ast.parse(original.decode('utf-8')), ast.parse(candidate.decode('utf-8'))
        for name in ('__init__', 'restore'):
            before = function(a, 'LinuxClientInitLease', name)
            after = StripDiagnostics().visit(copy.deepcopy(function(b, 'LinuxClientInitLease', name)))
            self.assertEqual(ast.dump(before, include_attributes=False), ast.dump(after, include_attributes=False))
        for name in ('_diagnostic_error', '_note_restore_diagnostic'):
            node = function(b, None if name == '_diagnostic_error' else 'LinuxClientInitLease', name)
            for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
                if isinstance(call.func, ast.Attribute):
                    self.assertNotIn(call.func.attr, ('_now', 'monotonic', 'snapshot', 'open', 'close', 'authenticate', 'read', 'write'))
                elif isinstance(call.func, ast.Name):
                    self.assertNotIn(call.func.id, ('str', 'repr', 'print', 'open'))
        ast.parse(candidate.decode('utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_caps_fixed_literal_table_and_exact_domain_classes(self):
        transport = BASE / 'runtime/mta_client_caps_transport.py'
        raw = transport.read_bytes()
        self.assertEqual('df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420', hashlib.sha256(raw).hexdigest())
        literals = set()
        for n in ast.walk(ast.parse(raw.decode('utf-8'))):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ('_fail', 'CapsTransportError') and n.args and isinstance(n.args[0], ast.Constant) and type(n.args[0].value) is str:
                literals.add(n.args[0].value)
        self.assertEqual(60, len(literals)); self.assertEqual(literals, p._DIAGNOSTIC_CAPS_CODES)
        rows = ((p.core.ClientInitError, 'core', 'current_blocked'),
            (p.LinuxProviderError, 'provider', 'ctrl_invalid'),
            (p.stores.PreparationError, 'store', 'component_error'),
            (p.stores.DurableStoreError, 'store', 'component_error'),
            (p.proc.ProcReadError, 'proc', 'unexpected_read_error'),
            (p.coordination.CoordinationError, 'coord', 'io_error'),
            (p.files.ClientFileError, 'files', 'io_error'),
            (p.pending.PendingError, 'pending', 'io_unknown'),
            (p.launches.LaunchRegistrationError, 'launch', 'component_error'),
            (p.tmp_alias.TmpAliasError, 'alias', 'io_error'),
            (p.baseline.BaselineError, 'baseline', 'actor_changed'),
            (p.caps_transport.CapsTransportError, 'caps', 'caps_schema'),
            (p.original_status.WpaStatusError, 'status', 'io_error'))
        for cls, group, code in rows:
            with self.subTest(group=group, cls=cls.__name__):
                self.assertEqual((group, code), p._diagnostic_error(cls(code)))
        # Frozen Owner has no .code; do not read its exception args as code.
        self.assertEqual(('other', 'not_recorded'), p._diagnostic_error(p.processes.ProcessOwnerError('wait_unknown')))

    def test_unknown_sensitive_invalid_and_interrupt_codes_are_fixed(self):
        secret = 'SECRET_PATH_IP_PSK_ACTOR'
        class ForeignOsError(OSError):
            def __str__(self): raise AssertionError('no exception formatting')
        for error, expected in ((ValueError(secret), ('other', 'not_recorded')),
                (OSError(5, secret), ('os', 'io_error')),
                (PermissionError(13, secret), ('os', 'io_error')),
                (ForeignOsError(5, secret), ('other', 'not_recorded')),
                (KeyboardInterrupt(secret), ('interrupt', 'interrupted')),
                (SystemExit(secret), ('interrupt', 'interrupted')),
                (GeneratorExit(secret), ('interrupt', 'interrupted')),
                (None, ('none', 'not_recorded'))):
            result = p._diagnostic_error(error)
            self.assertIs(type(result), tuple); self.assertEqual(expected, result)
            self.assertNotIn(secret, repr(result))
        error = p.core.ClientInitError('current_blocked'); error.code = secret
        self.assertEqual(('other', 'not_recorded'), p._diagnostic_error(error))
        error.code = True
        self.assertEqual(('other', 'not_recorded'), p._diagnostic_error(error))
        del error.code
        self.assertEqual(('other', 'not_recorded'), p._diagnostic_error(error))
        with mock.patch.object(p, '_DIAGNOSTIC_GROUP_CODES', {}):
            self.assertEqual(('other', 'not_recorded'), p._diagnostic_error(p.core.ClientInitError('current_blocked')))
        ast.parse(PATH.read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_pure_assembly_initial_diagnostics_and_default_unavailable(self):
        default = p.LinuxClientInitProvider()
        self.assertIsNone(default.manifest)
        self.assertEqual(('none', 'not_recorded'), default._diagnostic_error(None))
        provider, store, owner, bridge, lease = p.assemble(manifest(p))
        self.assertEqual(dict((k, 'not_recorded') for k in ('site', 'stage', 'error_group', 'error_code', 'result')), lease._diagnostic_restore)
        self.assertEqual([], provider._ledger.rows)
        self.assertFalse(lease.status()['send_available']); self.assertFalse(lease.status()['receive_available'])

    def test_actual_restore_first_sites_fixed_and_aggregation_unchanged(self):
        rows = (('known_locks', p.core.ClientInitError('locks_close_unverified'), 'core', 'locks_close_unverified'),
            ('executor', p.LinuxProviderError('actor_unknown'), 'provider', 'actor_unknown'),
            ('acquire', p.stores.DurableStoreError('component_error'), 'store', 'component_error'),
            ('current', p.core.ClientInitError('current_blocked'), 'core', 'current_blocked'),
            ('baseline_before_children', p.baseline.BaselineError('actor_changed'), 'baseline', 'actor_changed'),
            ('bridge_cleanup', p.core.ClientInitError('resource_close_unknown'), 'core', 'resource_close_unknown'),
            ('baseline_after_children', p.proc.ProcReadError('unexpected_read_error'), 'proc', 'unexpected_read_error'),
            ('baseline_after_delete', p.caps_transport.CapsTransportError('caps_schema'), 'caps', 'caps_schema'),
            ('close_resources', OSError(5, 'SECRET'), 'os', 'io_error'),
            ('close_proof', p.core.ClientInitError('resource_close_unknown'), 'core', 'resource_close_unknown'),
            ('baseline_terminal', p.original_status.WpaStatusError('io_error'), 'status', 'io_error'),
            ('save_cleanup_verified', p.core.ClientInitError('durability_unknown'), 'core', 'durability_unknown'),
            ('finish_receipt', ValueError('SECRET'), 'other', 'not_recorded'))
        for site, error, group, code in rows:
            with self.subTest(site=site):
                run = RestoreRun(failure=site, error=error)
                result = run.lease.restore()
                self.assertEqual({'site': site, 'stage': 'none' if site in ('known_locks', 'executor', 'acquire', 'current') else 'cleanup_verified' if site == 'finish_receipt' else 'cleanup_intent',
                    'error_group': group, 'error_code': code, 'result': 'raised'}, run.lease._diagnostic_restore)
                self.assertFalse(result['cleanup_complete']); self.assertTrue(result['cleanup_unresolved'])
                self.assertEqual(error.code if type(error) is p.core.ClientInitError else 'unexpected_provider_error', result['reason'])
                self.assertIsNone(run.store._recovery_deadline)

    def test_real_restore_fake_call_clock_parity_and_return_not_proof(self):
        before, after = RestoreRun(old.p), RestoreRun(p)
        old_result, new_result = before.lease.restore(), after.lease.restore()
        self.assertEqual(before.calls, after.calls); self.assertEqual(before.clocks, after.clocks)
        self.assertEqual(old_result, new_result)
        self.assertFalse(new_result['cleanup_complete']); self.assertTrue(new_result['cleanup_unresolved'])
        self.assertEqual({'site': 'complete', 'stage': 'cleanup_verified', 'error_group': 'none',
            'error_code': 'not_recorded', 'result': 'returned'}, after.lease._diagnostic_restore)
        for site, error in (('baseline_before_children', p.core.ClientInitError('baseline_changed')),
                ('close_resources', OSError(5, 'SECRET'))):
            a, b = RestoreRun(old.p, site, error), RestoreRun(p, site, error)
            self.assertEqual(a.lease.restore(), b.lease.restore())
            self.assertEqual(a.calls, b.calls); self.assertEqual(a.clocks, b.clocks)

    def test_sticky_first_raised_survives_retry_and_normal_return(self):
        run = RestoreRun(failure='bridge_cleanup', error=p.core.ClientInitError('resource_close_unknown'))
        run.lease.restore(); first = dict(run.lease._diagnostic_restore)
        run.failure = None; run.baseline_count = 0
        run.lease.restore()
        self.assertEqual(first, run.lease._diagnostic_restore)
        run.lease._note_restore_diagnostic('complete', 'returned')
        self.assertEqual(first, run.lease._diagnostic_restore)

    def test_interrupt_rethrows_after_diagnostic_and_budget_restored(self):
        for site in ('known_locks', 'close_resources', 'finish_receipt'):
            with self.subTest(site=site):
                run = RestoreRun(failure=site, error=KeyboardInterrupt('SECRET'))
                with self.assertRaises(KeyboardInterrupt): run.lease.restore()
                self.assertEqual(site, run.lease._diagnostic_restore['site'])
                self.assertEqual('interrupt', run.lease._diagnostic_restore['error_group'])
                self.assertEqual('raised', run.lease._diagnostic_restore['result'])
                self.assertIsNone(run.store._recovery_deadline)
                self.assertTrue(run.lease.pending); self.assertFalse(run.lease.cleanup_complete)

    def test_try_external_failure_and_early_return_remain_not_recorded(self):
        run = RestoreRun()
        with self.assertRaises(p.core.ClientInitError): run.lease.restore(timeout=61)
        self.assertTrue(all(v == 'not_recorded' for v in run.lease._diagnostic_restore.values()))
        run.store._recovery_deadline = 9.
        with self.assertRaises(p.core.ClientInitError): run.lease.restore()
        self.assertEqual(9., run.store._recovery_deadline)
        self.assertTrue(all(v == 'not_recorded' for v in run.lease._diagnostic_restore.values()))
        run = RestoreRun(); run.lease.bridge = None
        self.assertEqual('provider_unavailable', run.lease.restore()['reason'])
        self.assertTrue(all(v == 'not_recorded' for v in run.lease._diagnostic_restore.values()))

    def test_stage_is_fixed_and_diagnostic_errors_never_replace_original(self):
        run = RestoreRun()
        run.lease.record = types.SimpleNamespace(stage='SECRET')
        run.lease._note_restore_diagnostic('current', 'raised', ValueError('SECRET'))
        self.assertEqual('other', run.lease._diagnostic_restore['stage'])
        self.assertNotIn('SECRET', repr(run.lease._diagnostic_restore))
        run = RestoreRun(failure='known_locks', error=p.core.ClientInitError('current_blocked'))
        run.lease._diagnostic_restore = None
        self.assertEqual('current_blocked', run.lease.restore()['reason'])
        self.assertIsNone(run.store._recovery_deadline)
        run = RestoreRun(); before = dict(run.lease._diagnostic_restore)
        run.lease._note_restore_diagnostic('SECRET', 'raised', ValueError('SECRET'))
        self.assertEqual(before, run.lease._diagnostic_restore)
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))


if __name__ == '__main__': unittest.main()
