"""One affected pure cache projection method; no runtime or physical IO fixture.

The traceback check_active body is selected from the actual frozen Factory.
Owner/Session/Loader/Factory and clock/_originals are explicit narrow models.
The clock model is used only to seed an original exception before observation;
all lifecycle seams are then traps. This is not hardware or close acceptance.
"""
import ast
import math
from pathlib import Path
import sys
import types
import unittest

HELPER = 'host/receive_startup_cached_boundaries_v1_projection.py'
FACTORY = 'candidate/receive-publication-progress-graph-v1/runtime/mta_client_receive_factory.py'
SELECTOR = 'ReceiveStartupCachedBoundariesV1Contract.test_original_check_trace_and_passive_cache'
INPUTS = None
SCENARIOS = 0


def load_fixture_sources():
    projection_raw = (INPUTS / HELPER).read_bytes()
    projection = types.ModuleType('fixed_private_cache_projection_contract')
    exec(compile(projection_raw, HELPER, 'exec'), projection.__dict__)
    tree = ast.parse((INPUTS / FACTORY).read_bytes(), feature_version=(3, 5))
    names = ('ReceivePublicationError', '_fail', '_number')
    selected = [row for row in tree.body if isinstance(row, (ast.ClassDef, ast.FunctionDef)) and row.name in names]
    if tuple(row.name for row in selected) != names:
        raise ValueError('actual_factory_pure_selection')
    scope = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == '_StartupReadScope')
    check = [row for row in scope.body if isinstance(row, ast.FunctionDef) and row.name == 'check_active']
    if len(check) != 1:
        raise ValueError('actual_check_active_selection')
    model = ast.ClassDef(name='_StartupReadScope', bases=[], keywords=[], body=check, decorator_list=[])
    selected.append(model)
    actual = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(actual)
    return projection, actual, check[0]


def fixture(actual, depth=0):
    module = types.ModuleType('mta_client_receive_factory')
    module.__dict__['math'] = math
    exec(compile(actual, FACTORY, 'exec'), module.__dict__)
    scope_type = module._StartupReadScope
    factory_type = type('FixedReceiveDeploymentFactory', (), {})
    module.FixedReceiveDeploymentFactory = factory_type
    check = scope_type.check_active
    module._STARTUP_ALIAS_ORIGINALS = (None, None, check, None, None, None)
    module._STARTUP_ALIAS_CODES = (None, None, check.__code__, None, None, None)
    owner_module = types.ModuleType('private_model_owner')
    owner_type = type('FixedStateServiceOwner', (), {})
    owner_module.FixedStateServiceOwner = owner_type
    owner, factory = owner_type(), factory_type()
    loader = types.SimpleNamespace(modules={module.__name__: module})
    owner.loader = loader
    owner._startup_namespace_original = owner_module.__dict__
    owner._startup_owner_type_original = owner_type
    owner.factory = factory
    scope = scope_type()
    scope.owner, scope.factory = owner, factory
    scope.last = 5.0
    scope.original_until = 61.0
    scope.prepare_until = scope.original_prepare_until = 11.0
    scope.phase = 'importing'
    owner._now = lambda: 12.0
    scope._originals = lambda active: None
    owner.startup_scope = owner._startup_scope_original = factory._startup_scope = scope

    def enter(remaining):
        if remaining:
            return enter(remaining - 1)
        return scope.check_active()

    try:
        enter(depth)
    except module.ReceivePublicationError as error:
        if error.args != ('startup_expired',):
            raise ValueError('original_expired_seed')
        scope.failure = owner.startup_failure = error
        failure = error
    else:
        raise ValueError('original_seed_required')
    scope.startup_boundary_init = 1.0
    scope.startup_boundary_private_sources = 3.0
    scope.startup_boundary_wpa = 4.0
    scope.startup_boundary_profile = 5.0
    scope.startup_boundary_postimport = scope.last
    session = types.ModuleType('fixed_model_session')
    session.FixedSession = type('FixedSession', (), {})
    retained = session.FixedSession()
    session._RETAINED = retained
    session.sys = sys
    retained.owner, retained.loader, retained.owner_module = owner, loader, owner_module
    retained.first_error, retained.startup_scope = failure, scope
    calls = []

    def forbidden(*args, **kwargs):
        calls.append('forbidden_lifecycle')
        raise AssertionError('observation_must_not_call_lifecycle')

    owner._now = owner.close = owner.closed = owner.status = owner._context = forbidden
    scope._originals = scope.close = scope.closed = scope.alias_now = forbidden
    factory.startup_readonly = loader.load = forbidden
    return dict(module=module, session=session, retained=retained, owner=owner,
                loader=loader, scope=scope, factory=factory, calls=calls)


class ReceiveStartupCachedBoundariesV1Contract(unittest.TestCase):
    def test_original_check_trace_and_passive_cache(self):
        global SCENARIOS
        projection, actual, check_ast = load_fixture_sources()
        self.assertEqual(check_ast.name, 'check_active')
        old_module = sys.modules.get('mta_client_receive_factory')

        def observe(change=None, expected=True, depth=0):
            global SCENARIOS
            value = fixture(actual, depth)
            sys.modules['mta_client_receive_factory'] = value['module']
            if change is not None:
                change(value)
            before = dict(value['scope'].__dict__)
            result = projection._private_startup_cached_boundaries_v1(value['retained'], value['session'])
            self.assertEqual(value['calls'], [])
            self.assertEqual(value['scope'].__dict__, before)
            self.assertIs(result['available'], expected)
            self.assertIs(result['unknown'], not expected)
            if not expected:
                self.assertEqual(result, dict(available=False, unknown=True, values=None,
                                             prepare_same_object=None, postimport_is_last=None))
            SCENARIOS += 1
            return result, value

        try:
            result, value = observe()
            self.assertEqual(result['values'], (1.0, 3.0, 4.0, 5.0, 12.0, 12.0, 11.0, 11.0, 61.0))
            self.assertIs(result['prepare_same_object'], True)
            self.assertIs(result['postimport_is_last'], True)
            self.assertGreaterEqual(result['values'][4], result['values'][6])
            result, unused = observe(lambda v: setattr(v['scope'], 'startup_boundary_profile', None))
            self.assertIs(result['values'][3], None)
            result, unused = observe(lambda v: setattr(v['scope'], 'startup_boundary_postimport', None))
            self.assertIs(result['postimport_is_last'], None)
            result, unused = observe(lambda v: setattr(v['scope'], 'prepare_until', float('11.0')))
            self.assertIs(result['prepare_same_object'], False)
            observe(depth=33, expected=False)

            mutations = (
                lambda v: setattr(v['session'], '_RETAINED', object()),
                lambda v: setattr(v['retained'], 'owner_module', object()),
                lambda v: setattr(v['owner'], '_startup_namespace_original', {}),
                lambda v: setattr(v['owner'], '_startup_owner_type_original', object()),
                lambda v: setattr(v['owner'], 'loader', object()),
                lambda v: v['loader'].modules.clear(),
                lambda v: sys.modules.__setitem__('mta_client_receive_factory', types.ModuleType('foreign')),
                lambda v: setattr(v['module'], '_STARTUP_ALIAS_ORIGINALS', (None,) * 6),
                lambda v: setattr(v['module'], '_STARTUP_ALIAS_CODES', (None,) * 6),
                lambda v: setattr(v['module']._StartupReadScope, 'check_active', lambda self: None),
                lambda v: setattr(v['retained'], 'first_error', ValueError('not_original')),
                lambda v: setattr(v['retained'], 'startup_scope', None),
                lambda v: setattr(v['owner'], 'startup_scope', object()),
                lambda v: setattr(v['owner'], '_startup_scope_original', object()),
                lambda v: setattr(v['factory'], '_startup_scope', object()),
                lambda v: setattr(v['scope'], 'owner', object()),
                lambda v: setattr(v['scope'], 'factory', object()),
                lambda v: setattr(v['scope'], 'failure', ValueError('different')),
                lambda v: setattr(v['owner'], 'startup_failure', ValueError('different')),
                lambda v: v['scope'].__dict__.pop('last'))
            for change in mutations:
                observe(change, False)
            for bad in (False, 1, '1.0', -1.0, 1e12, float('nan'), float('inf')):
                observe(lambda v, bad=bad: setattr(v['scope'], 'startup_boundary_profile', bad), False)

            known = result = dict(available=True, unknown=False,
                values=(1.0, 3.0, 4.0, None, 12.0, 12.0, 11.0, 11.0, 61.0),
                prepare_same_object=True, postimport_is_last=True)
            unknown = dict(available=False, unknown=True, values=None,
                           prepare_same_object=None, postimport_is_last=None)
            for result in (known, unknown):
                wire = (projection.PREFIX + repr(result) + '\n').encode('ascii')
                self.assertEqual(projection.parse_private(wire), result)
                SCENARIOS += 1
            bad_rows = (
                b'', (projection.PREFIX + repr(known) + '\n') .encode('ascii') * 2,
                (projection.PREFIX + repr(dict(known, extra=1)) + '\n').encode('ascii'),
                (projection.PREFIX + repr(dict(known, unknown=True)) + '\n').encode('ascii'),
                (projection.PREFIX + repr(dict(known, values=(1.0,) * 8)) + '\n').encode('ascii'),
                (projection.PREFIX + repr(dict(known, values=(1,) * 9)) + '\n').encode('ascii'),
                (projection.PREFIX + repr(dict(known, postimport_is_last=None)) + '\n').encode('ascii'),
                (projection.PREFIX + repr(dict(unknown, values=(1.0,) * 9)) + '\n').encode('ascii'),
                (projection.PREFIX + repr(dict(known, values=(float('inf'),) * 9)) + '\n').encode('ascii'))
            for wire in bad_rows:
                with self.assertRaises((ValueError, SyntaxError)):
                    projection.parse_private(wire)
                SCENARIOS += 1
            raw = (INPUTS / HELPER).read_bytes()
            fragment = projection.target_fragment(raw)
            self.assertLessEqual(len(fragment), 16384)
            self.assertNotIn(b'parse_private', fragment)
            program = b'import types\ncomponent=session.run_fixed(artifacts,False,receive_trial_requested=False)\nretained=session._RETAINED\nprint("RESULT="+repr(component))\n'
            added = projection.inject(program, raw)
            self.assertEqual(added.replace(b'retained=session._RETAINED\n' + fragment,
                                          b'retained=session._RETAINED\n'), program)
            self.assertLess(added.index(b'component=session.run_fixed'), added.index(fragment))
            self.assertLess(added.index(fragment), added.index(b'print("RESULT="'))
            for bad in (b'no_anchor\n', program + b'retained=session._RETAINED\n', added):
                with self.assertRaises(ValueError):
                    projection.inject(bad, raw)
                SCENARIOS += 1
            SCENARIOS += 1
        finally:
            if old_module is None:
                sys.modules.pop('mta_client_receive_factory', None)
            else:
                sys.modules['mta_client_receive_factory'] = old_module


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != SELECTOR:
        raise SystemExit('fixed_selector_and_private_inputs_required')
    INPUTS = Path(sys.argv[2])
    result = unittest.TextTestRunner().run(unittest.TestSuite((
        ReceiveStartupCachedBoundariesV1Contract('test_original_check_trace_and_passive_cache'),)))
    if result.wasSuccessful():
        print('PRIVATE_CACHE_CONTRACT_SCENARIOS=' + str(SCENARIOS))
    raise SystemExit(0 if result.wasSuccessful() else 1)
