"""One retained V2 method with actual Baseline.collect AST and explicit models.

No syscall, clock, owner lifecycle or actual close is performed. The modeled
_now raises before IO in the original body; modeled close only records ended.
Private Factory/Startup/Proc type and module fixtures never grant admission.
"""
import ast
import math
from pathlib import Path
import sys
import types
import unittest

HELPER = 'host/receive_startup_retained_v2_projection.py'
FACTORY = 'candidate/receive-publication-progress-graph-v1/runtime/mta_client_receive_factory.py'
BASELINE = 'candidate/client-proc-deadline-v25/runtime/mta_client_baseline.py'
PROC = 'candidate/receive-proc-freezer-v1/runtime/mta_client_proc.py'
STARTUP = 'candidate/receive-startup-readonly-v3/runtime/mta_client_startup_readonly.py'
SELECTOR = 'ReceiveStartupRetainedV2Contract.test_direct_cache_and_retained_collect_error'
INPUTS = None
SCENARIOS = 0


def declarations(path, module, names, method=None):
    tree = ast.parse((INPUTS / path).read_bytes(), feature_version=(3, 5))
    selected = []
    for row in tree.body:
        if isinstance(row, ast.Assign) and len(row.targets) == 1 and isinstance(row.targets[0], ast.Name):
            if row.targets[0].id in names:
                selected.append(row)
        elif isinstance(row, (ast.ClassDef, ast.FunctionDef)) and row.name in names:
            selected.append(row)
        elif isinstance(row, ast.ClassDef) and method and row.name == method[0]:
            methods = [n for n in row.body if isinstance(n, ast.FunctionDef) and n.name == method[1]]
            if len(methods) != 1:
                raise ValueError('one_actual_method')
            selected.append(ast.ClassDef(name=row.name, bases=[], keywords=[], body=methods, decorator_list=[]))
    value = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(value)
    module.__dict__['math'] = math
    exec(compile(value, path, 'exec'), module.__dict__)


def fixture(kind='value', success=False):
    fm = types.ModuleType('mta_client_receive_factory')
    declarations(FACTORY, fm, ('ReceivePublicationError', '_fail', '_number'), ('_StartupReadScope', 'check_active'))
    fm.FixedReceiveDeploymentFactory = type('FixedReceiveDeploymentFactory', (), {})
    check = fm._StartupReadScope.check_active
    fm._STARTUP_ALIAS_ORIGINALS = (None, None, check, None, None, None)
    fm._STARTUP_ALIAS_CODES = (None, None, check.__code__, None, None, None)
    bm = types.ModuleType('mta_client_baseline')
    declarations(BASELINE, bm, ('_CODES', 'BaselineError', '_fail'), ('BaselineCollector', 'collect'))
    pm = types.ModuleType('mta_client_proc')
    declarations(PROC, pm, ('_CODES', 'ProcReadError'))
    sm = types.ModuleType('mta_client_startup_readonly')
    declarations(STARTUP, sm, ('_CODES', 'StartupReadError'))
    sm.StartupCollection = type('StartupCollection', (), {})
    own_module = types.ModuleType('model_retained_owner')
    own_module.FixedStateServiceOwner = type('FixedStateServiceOwner', (), {})
    owner = own_module.FixedStateServiceOwner()
    loader = types.SimpleNamespace(modules={fm.__name__: fm, sm.__name__: sm})
    owner.loader = loader
    owner._startup_namespace_original = own_module.__dict__
    owner._startup_owner_type_original = type(owner)
    factory = fm.FixedReceiveDeploymentFactory()
    scope = fm._StartupReadScope()
    owner.factory = owner._startup_factory_original = factory
    owner.startup_scope = owner._startup_scope_original = factory._startup_scope = scope
    scope.owner, scope.factory = owner, factory
    scope._alias_functions, scope._alias_codes = fm._STARTUP_ALIAS_ORIGINALS, fm._STARTUP_ALIAS_CODES
    scope.startup_boundary_init, scope.startup_boundary_private_sources = 1.0, 3.0
    scope.startup_boundary_wpa, scope.startup_boundary_profile = 4.0, 5.0
    scope.startup_boundary_postimport = 8.0
    scope.last, scope.original_until = 12.0, 61.0
    scope.prepare_until = scope.original_prepare_until = 11.0
    scope.failure = None  # Factory has returned before later collection failure.
    private = {m.__name__: m for m in (bm, pm)}
    for name in ('mta_client_wpa_status', 'mta_client_files'):
        private[name] = types.ModuleType(name)
    scope.private_modules = private
    rows = tuple((name, module, module.__dict__) for name, module in private.items())
    scope.module_originals = rows + tuple(('inert_' + str(i), None, None) for i in range(31))
    value = sm.StartupCollection()
    value.scope = value._scope_original = scope
    value.modules = value._modules_original = private
    native = type('NativeCollector', (bm.BaselineCollector,), {})
    collector = native()
    collector._attempted = collector._ended = collector._pending = False
    collector._timeout = 10.0
    inner = (pm.ProcReadError('invalid_stat') if kind == 'proc' else
             sm.StartupReadError('startup_originals') if kind == 'startup' else
             FileNotFoundError(2, 'PRIVATE TEXT NEVER EXPORTED') if kind == 'errno' else ValueError('PRIVATE TEXT NEVER EXPORTED'))

    def model_now():
        raise inner

    def model_close():
        collector._ended = True
        return True

    collector._now, collector.close = model_now, model_close
    try:
        collector.collect(61.0)
    except bm.BaselineError as error:
        outer = error
    else:
        raise ValueError('actual_baseline_error_seed')
    value._native_class = native
    value.collector = value._collector_original = collector
    value._definitions = (bm.BaselineCollector, bm.BaselineCollector.collect) + (None,) * 21
    value.failure = None if success else outer
    owner.startup_failure = None if success else outer
    owner.startup_result = None  # collect failure precedes the original assignment.
    owner._startup_module_original = sm
    owner._startup_collection_type_original = sm.StartupCollection
    scope.collector_ticket = dict(creator=sm.StartupCollection, returned=value, started=True, ended=True,
                                  failure=None if success else outer)
    session = types.ModuleType('model_retained_session')
    session.FixedSession = type('FixedSession', (), {})
    session.sys = sys
    retained = session.FixedSession()
    session._RETAINED = retained
    retained.owner, retained.loader, retained.owner_module = owner, loader, own_module
    retained.startup_scope, retained.startup_collection = scope, value
    retained.first_error = None if success else outer
    calls = []

    def forbidden(*args, **kwargs):
        calls.append('forbidden_lifecycle')
        raise AssertionError('passive_projection_only')

    owner._now = owner.close = owner.status = owner._context = forbidden
    scope.close = scope.closed = scope._originals = scope.alias_now = forbidden
    collector._now = collector.close = collector.status = forbidden
    value._now = value._originals = value.resources_closed = forbidden
    return dict(fm=fm, sm=sm, bm=bm, pm=pm, retained=retained, session=session, owner=owner,
                scope=scope, collection=value, collector=collector, outer=outer, inner=inner, calls=calls)


class ReceiveStartupRetainedV2Contract(unittest.TestCase):
    def test_direct_cache_and_retained_collect_error(self):
        global SCENARIOS
        helper = types.ModuleType('fixed_v2_projection_contract')
        raw = (INPUTS / HELPER).read_bytes()
        exec(compile(raw, HELPER, 'exec'), helper.__dict__)
        saved = {name: sys.modules.get(name) for name in ('mta_client_receive_factory', 'mta_client_startup_readonly')}

        def observe(change=None, numeric=True, leaf=True, kind='value', success=False):
            global SCENARIOS
            value = fixture(kind, success)
            sys.modules['mta_client_receive_factory'] = value['fm']
            sys.modules['mta_client_startup_readonly'] = value['sm']
            if change:
                change(value)
            snapshot = dict(value['scope'].__dict__)
            cache = helper._private_startup_retained_cache_v2(value['retained'], value['session'])
            error = helper._private_startup_retained_collect_error_v2(value['retained'], value['session'])
            self.assertEqual(value['calls'], [])
            self.assertEqual(value['scope'].__dict__, snapshot)
            self.assertIs(cache['available'], numeric)
            self.assertIs(error['available'], leaf)
            self.assertIs(cache['unknown'], not numeric)
            self.assertIs(error['unknown'], not leaf)
            if leaf:
                self.assertNotIn('PRIVATE TEXT', repr(error))
                self.assertTrue(any(row[:2] == ('mta_client_baseline', 'collect') for row in error['trace']))
            SCENARIOS += 1
            return cache, error

        try:
            cache, error = observe()
            self.assertEqual(cache['values'], (1.0, 3.0, 4.0, 5.0, 8.0, 12.0, 11.0, 11.0, 61.0))
            self.assertIs(cache['postimport_is_last'], False)
            self.assertEqual(error['kind'], 'ValueError')
            observe(success=True, leaf=False)
            observe(lambda v: setattr(v['scope'], 'last', float('nan')), numeric=False)
            observe(lambda v: v['scope'].__dict__.pop('last'), numeric=False)
            observe(lambda v: setattr(v['retained'], 'startup_scope', None), numeric=False, leaf=False)
            observe(lambda v: setattr(v['owner'], 'startup_scope', object()), numeric=False, leaf=False)
            observe(lambda v: setattr(v['scope'], '_alias_codes', (None,) * 6), numeric=False, leaf=False)
            observe(lambda v: sys.modules.__setitem__('mta_client_receive_factory', object()), numeric=False, leaf=False)
            observe(lambda v: setattr(v['scope'], 'module_originals', ()), leaf=False)
            observe(lambda v: setattr(v['collection'], '_collector_original', object()), leaf=False)
            observe(lambda v: setattr(v['collection'], '_native_class', object()), leaf=False)
            observe(lambda v: setattr(v['collection'], '_definitions', (None,) * 23), leaf=False)

            def foreign_error(value):
                error = value['bm'].BaselineError('io_error')
                value['retained'].first_error = value['owner'].startup_failure = value['collection'].failure = error
                value['scope'].collector_ticket['failure'] = error

            observe(foreign_error, leaf=False)
            observe(lambda v: setattr(v['outer'], 'code', 'close_unknown'), leaf=False)
            observe(lambda v: setattr(v['collector'], '_reason', 'close_unknown'), leaf=False)
            observe(lambda v: setattr(v['collector'], '_ended', False), leaf=False)
            observe(lambda v: v['scope'].collector_ticket.__setitem__('failure', None), leaf=False)
            observe(lambda v: setattr(v['inner'], 'errno', False), kind='errno', leaf=False)
            unused, error = observe(kind='errno')
            self.assertEqual((error['kind'], error['errno']), ('FileNotFoundError', 2))
            unused, error = observe(kind='proc')
            self.assertEqual((error['kind'], error['code']), ('ProcReadError', 'invalid_stat'))
            unused, error = observe(kind='startup')
            self.assertEqual((error['kind'], error['code']), ('StartupReadError', 'startup_originals'))
            fragment = helper.target_fragment(raw)
            self.assertLessEqual(len(fragment), 16384)
            carrier = b'import types\ncomponent=session.run_fixed(artifacts,False,receive_trial_requested=False)\nretained=session._RETAINED\nprint("RESULT="+repr(component))\n'
            current = helper.inject(carrier, raw)
            self.assertEqual(current.replace(b'retained=session._RETAINED\n' + fragment,
                                             b'retained=session._RETAINED\n'), carrier)
            self.assertLess(current.index(b'component=session.run_fixed'), current.index(fragment))
            SCENARIOS += 1
        finally:
            for name, module in saved.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != SELECTOR:
        raise SystemExit('fixed_selector_and_private_inputs_required')
    INPUTS = Path(sys.argv[2])
    result = unittest.TextTestRunner().run(unittest.TestSuite((
        ReceiveStartupRetainedV2Contract('test_direct_cache_and_retained_collect_error'),)))
    if result.wasSuccessful():
        print('PRIVATE_RETAINED_V2_SCENARIOS=' + str(SCENARIOS))
    raise SystemExit(0 if result.wasSuccessful() else 1)
