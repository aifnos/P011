"""New HOST-only coordination method, selected real frozen helper AST.

Owner/State/Gate/clock/Companion/guardian/FD/native inventories and original
closure callbacks are explicit HOST models. No full worker, Boot, GUI, actual
Owner/State/Session constructor, thread start, Popen, network, archive consumer,
Native, target or phone runs. Old audio13/send26 methods are not replayed.
The production run_fixed body is only parsed for the real recipe/call order.
"""
import ast
import hashlib
import math
from pathlib import Path
import threading
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
WORKER = 'candidate/receive-filecenter-archive-v1/runtime/ui_session.py'
WORKER_PIN = (104680, '04d3bbbbda2bccf67b29154a5b481d70cecb17647dc8cec51eb045c679d24a7c')
HELPERS = ('need', '_filecenter_current', '_receive_interactive_window',
    '_receive_interactive_originals', '_receive_interactive_expired',
    '_retain_completed_archive_projection', '_archive_refusal_cleanup_originals',
    '_reject_archive_cleanup', '_finish_owner_after_filecenter', '_copy_completed_archive_facts')
CONSTANTS = ('STATE_ROOT', 'STATE_ALIAS', 'INTERACTIVE_PROFILE', 'INTERACTIVE_SECONDS',
             'EXIT_MARGIN_SECONDS', 'COMPLETED_ARCHIVE_BOOL_FIELDS',
             'COMPLETED_ARCHIVE_REASONS', 'FILECENTER_PINS', 'RUNNER_PIN')
CASES = (
    'static_actual_recipe_and_finally_order', 'window_600_and_original_caps',
    'window_original_archive_policy_required', 'window_cap_substitution_refused',
    'window_expiry_uses_original_cutoff', 'closed_original_allows_finish',
    'no_filecenter_constructor_allows_finish', 'unknown_close_cancels_without_finish',
    'cached_true_actual_closed_false_cancels', 'cached_true_guardian_unsettled_cancels',
    'changed_companion_creator_not_invoked', 'passive_error_retained_before_cancel',
    'abort_remaining_wait_clipped', 'abort_expiry_zero_wait_no_renewal',
    'abort_once_keeps_original_inventory', 'revoke_error_still_stops_and_closes_state',
    'stop_error_still_closes_state', 'state_close_unknown_never_closes_owner',
    'changed_owner_refuses_all_actor_calls', 'changed_original_state_cap_refuses_calls',
    'invalid_clock_retains_refusal_without_state_wait', 'noop_projection_strict_scalar_scope',
    'archived_projection_never_calls_getter', 'extra_projection_field_refused_raw_retained',
    'unknown_projection_reason_refused', 'missing_original_projection_refused',
    'native_grant_true_refused', 'receive_grant_true_refused',
    'boolean_history_count_refused', 'owner_not_closed_projection_refused',
    'changed_projection_namespace_refused', 'contradictory_rename_projection_refused',
)


class InjectedFailure(RuntimeError):
    pass


class ClockModel:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class GuardianModel:
    """Not the original audio guardian; passive inventories are assumptions."""
    def __init__(self, audio, calls):
        self.audio, self.calls = audio, calls
        self.current_value = self.settled_value = True
    def current(self):
        self.calls.append('guardian_current')
        return self.current_value
    def settled(self):
        self.calls.append('guardian_settled')
        return self.settled_value


OWNER_MODEL = '''
class FixedStateServiceOwner:
 def completed_archive_facts(self):
  self.projector_calls += 1
  raise AssertionError('HOST_model_getter_must_not_run')
 def _revoke_receive_trial(self, reason):
  self.calls.append(('revoke_trial', reason))
  if self.revoke_error is not None: raise self.revoke_error
  self.receive_trial.revoked = True
  return True
 def _stop_server(self):
  self.calls.append(('stop_http',))
  if self.stop_error is not None: raise self.stop_error
  self.stop_called = True
 def close(self):
  raise AssertionError('HOST_model_direct_Owner_close_forbidden')
'''
STATE_MODEL = '''
class State:
 def close(self, timeout=30):
  self.calls.append(('close_state', timeout))
  if self.close_error is not None: raise self.close_error
  self.cancel_requested = True
  return self.close_return
'''
COMPANION_MODEL = '''
def create(*unused):
 raise AssertionError('HOST_model_Companion_create_must_not_run')
class _Companion:
 def close(self):
  raise AssertionError('HOST_model_additional_Companion_close_forbidden')
 def closed(self):
  self.calls.append('companion_closed')
  if self.closed_error is not None: raise self.closed_error
  return self.closed_value
 def check(self):
  raise AssertionError('HOST_model_Companion_check_must_not_run')
 def credentials(self):
  raise AssertionError('HOST_model_credentials_must_not_run')
'''


def frozen_tree():
    raw = (BASE / WORKER).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != WORKER_PIN:
        raise ValueError('frozen_archive_worker_changed')
    return ast.parse(raw, feature_version=(3, 5))


def helper_namespace(clock, module_inventory):
    tree = frozen_tree()
    body = []
    found_functions, found_constants, found_classes = set(), set(), set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in HELPERS:
            body.append(node); found_functions.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name == 'UiSessionError':
            body.append(node); found_classes.add(node.name)
        elif isinstance(node, ast.Assign):
            names = {target.id for target in node.targets if isinstance(target, ast.Name)}
            if names & set(CONSTANTS):
                body.append(node); found_constants.update(names)
    if (found_functions != set(HELPERS) or found_constants != set(CONSTANTS) or
            found_classes != {'UiSessionError'}):
        raise ValueError('selected_helper_shape_changed')
    namespace = dict(types=types, math=math, threading=threading,
        time=types.SimpleNamespace(monotonic=clock),
        sys=types.SimpleNamespace(modules=module_inventory), _RETAINED=None)
    unit = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
    exec(compile(unit, WORKER, 'exec'), namespace)
    return namespace


class Fixture:
    """Original identities are modeled; actual selected helper guards run."""
    def __init__(self):
        self.clock, self.calls, self.passive_calls = ClockModel(), [], []
        self.modules = {}
        self.ns = helper_namespace(self.clock, self.modules)
        owner_module = types.ModuleType('startup_readonly_private_owner')
        service_module = types.ModuleType('mta_service')
        archive_module = types.ModuleType('mta_receive_completed_archive')
        exec(OWNER_MODEL, owner_module.__dict__)
        exec(STATE_MODEL, service_module.__dict__)
        self.owner_module, self.service_module, self.archive_module = owner_module, service_module, archive_module
        self.modules.update(startup_readonly_private_owner=owner_module,
                            mta_service=service_module, mta_receive_completed_archive=archive_module)
        archive_module.__file__ = self.ns['STATE_ALIAS'] + '/runtime/mta_receive_completed_archive.py'
        archive_module.REASONS = self.ns['COMPLETED_ARCHIVE_REASONS']
        c = self.component = types.SimpleNamespace()
        c.profile = self.ns['INTERACTIVE_PROFILE']
        c.window_started_at = 100.0
        c.until, c.cleanup_until = c.window_started_at + 600.0, c.window_started_at + 660.0
        c._window_original = c._window_retained = (c.profile, c.window_started_at, c.until, c.cleanup_until)
        c.receive_trial_requested = c._receive_trial_requested_original = True
        c.archive_completed_receives = c._archive_completed_receives_original = True
        c.preflight_only = False
        c.owner_module = c._owner_module_original = owner_module
        o = self.owner = owner_module.FixedStateServiceOwner()
        c.owner = o
        o._startup_namespace_original = owner_module.__dict__
        o.worker = threading.current_thread()
        o.close_called = o.close_complete = o.directory_close_called = o.stop_called = False
        o.archive_completed_receives = o._archive_completed_receives_original = True
        o.until = o.original_until = c.until
        o.clock = self.clock
        o.calls, o.projector_calls = self.calls, 0
        o.revoke_error = o.stop_error = None
        o.received_directory = o._received_directory_original = types.SimpleNamespace(absolute_until=c.until)
        o.receive_trial = o._receive_trial_original = types.SimpleNamespace(until=c.until, _until_original=c.until, revoked=False)
        s = self.state = service_module.State()
        o.state = o._state_original = s
        o.service = service_module
        s._original_service_until = s._service_until_original = c.until
        s._original_service_cleanup_until = s._service_cleanup_until_original = c.cleanup_until
        s._original_received_binding = s._received_binding_original = o.received_directory
        s.calls, s.close_error, s.close_return, s.cancel_requested = self.calls, None, True, False
        c.loader = types.SimpleNamespace(_original_until=c.until, clock=self.clock,
            modules={'mta_service':service_module, 'mta_receive_completed_archive':archive_module})
        c.result = dict(owner_close_called=False, owner_resources_closed=False)
        c.archive_end_facts = None
        c.finish_calls = 0
        def modeled_finish_owner():
            self.calls.append(('finish_owner',))
            c.finish_calls += 1
            o.close_called = o.close_complete = True
            c.result.update(owner_close_called=True, owner_resources_closed=True)
        c.finish_owner = modeled_finish_owner  # No production Owner/consumer runs.
        self.window = self.ns['_receive_interactive_window'](c)
        self.retained = dict(receive_window=self.window, completed_archive_projection=None,
            completed_archive_raw=None, archive_refusal_cleanup_originals=None,
            archive_refusal_cleanup=None, filecenter=None, filecenter_close_result=None, failures=[])
        self.ns['_RETAINED'] = self.retained
        self.ns['_retain_completed_archive_projection'](c)

    def filecenter(self):
        entries = []
        for name, unused_bytes, unused_sha in self.ns['FILECENTER_PINS']:
            module = types.ModuleType(name)
            entries.append(dict(name=name, module=module, namespace=module.__dict__, complete=True))
            self.modules[name] = module
        module = entries[-1]['module']
        exec(COMPANION_MODEL, module.__dict__)
        companion = self.companion = module._Companion()
        companion.worker, companion.until, companion.owner = threading.current_thread(), self.component.until, self.owner
        companion.audio = object()
        companion.calls = self.passive_calls
        companion.closed_value, companion.closed_error = True, None
        self.guardian = GuardianModel(companion.audio, self.passive_calls)
        ticket = dict(component=self.component, owner=self.owner, owner_module=self.owner_module,
            worker=threading.current_thread(), until=self.component.until, create_returned=True,
            modules=entries, module=module, creator=module.create, companion_type=module._Companion,
            companion=companion, close_creator=module._Companion.close,
            closed_creator=module._Companion.closed, check_creator=module._Companion.check,
            credentials_creator=module._Companion.credentials,
            audio_guardian=self.guardian, close_called=True, closed=True)
        self.retained['filecenter'] = ticket
        self.retained['filecenter_close_result'] = True
        return ticket

    def close_owner_projection(self, archived=False):
        self.owner.close_called = self.owner.close_complete = True
        self.component.result.update(owner_close_called=True, owner_resources_closed=True)
        raw = dict((name, False) for name in self.ns['COMPLETED_ARCHIVE_BOOL_FIELDS'])
        raw.update(requested=True, resources_closed=True, reason='not_attempted', historical_entries_examined=0)
        if archived:
            raw.update(attempted=True, archived=True, rename_called=True,
                       rename_outcome_known=True, reason='archived')
        self.component.archive_end_facts = raw
        facts = {'owner_close_verified':True}
        return raw, facts

    def reject_coordinator(self, test, ticket):
        with test.assertRaisesRegex(ValueError, 'filecenter_before_owner_close'):
            self.ns['_finish_owner_after_filecenter'](self.component, ticket)
        test.assertEqual(self.component.finish_calls, 0)
        test.assertFalse(self.owner.close_called)
        test.assertFalse(self.owner.directory_close_called)


class CoordinationTests(unittest.TestCase):
    def test_new_coordination_contracts(self):
        seen = []
        def case(name, callback):
            with self.subTest(contract=name): callback()
            seen.append(name)
            print('HOST_RECEIVE_ARCHIVE_COORD_CASE=' + name)

        def static_recipe():
            tree = frozen_tree()
            main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_fixed')
            self.assertEqual([a.arg for a in main.args.args], ['runner_raw','artifacts','validator_raw','filecenter_sources'])
            constructors = [n for n in ast.walk(main) if isinstance(n, ast.Call) and
                isinstance(n.func, ast.Attribute) and n.func.attr == 'FixedSession']
            self.assertEqual(len(constructors), 1)
            values = {k.arg:k.value for k in constructors[0].keywords}
            self.assertIs(ast.literal_eval(values['receive_trial_requested']), True)
            self.assertIs(ast.literal_eval(values['archive_completed_receives']), True)
            self.assertIsInstance(values['profile'], ast.Name)
            self.assertEqual(values['profile'].id, 'INTERACTIVE_PROFILE')
            calls = {name:[n for n in ast.walk(main) if isinstance(n, ast.Call) and
                isinstance(n.func, ast.Name) and n.func.id == name] for name in
                ('_close_filecenter','_finish_owner_after_filecenter','_copy_completed_archive_facts')}
            self.assertTrue(all(len(rows) == 1 for rows in calls.values()))
            self.assertLess(calls['_close_filecenter'][0].lineno, calls['_finish_owner_after_filecenter'][0].lineno)
            self.assertLess(calls['_finish_owner_after_filecenter'][0].lineno, calls['_copy_completed_archive_facts'][0].lineno)
            self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and
                n.func.attr == 'finish_owner' for n in ast.walk(main)))
            copied = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_copy_completed_archive_facts')
            self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'projector'
                                 for n in ast.walk(copied)))
        case(CASES[0], static_recipe)

        def fixed_window():
            f = Fixture(); originals = f.component._window_original
            self.assertEqual(f.window[3] - f.window[2][1], 600.0)
            self.assertEqual(f.window[4] - f.window[3], 60.0)
            self.assertTrue(f.ns['_receive_interactive_originals'](f.component, f.window))
            self.assertIs(f.component._window_original, originals)
        case(CASES[1], fixed_window)

        def policy_required():
            f = Fixture(); f.component.archive_completed_receives = False
            with self.assertRaisesRegex(ValueError, 'interactive_window_changed'):
                f.ns['_receive_interactive_window'](f.component)
        case(CASES[2], policy_required)

        def cap_changed():
            f = Fixture(); original = f.component.until
            f.component.until = float(str(original)); self.assertIsNot(f.component.until, original)
            with self.assertRaisesRegex(ValueError, 'interactive_window_changed'):
                f.ns['_receive_interactive_originals'](f.component, f.window)
        case(CASES[3], cap_changed)

        def expiry():
            f = Fixture(); original = f.component.cleanup_until
            self.assertFalse(f.ns['_receive_interactive_expired'](f.component, f.window, 698.0))
            self.assertTrue(f.ns['_receive_interactive_expired'](f.component, f.window, 699.0))
            self.assertIs(f.component.cleanup_until, original)
        case(CASES[4], expiry)

        def closed_finish():
            f = Fixture(); ticket = f.filecenter()
            f.ns['_finish_owner_after_filecenter'](f.component, ticket)
            self.assertEqual(f.calls, [('finish_owner',)])
            self.assertIn('companion_closed', f.passive_calls)
            self.assertIn('guardian_settled', f.passive_calls)
        case(CASES[5], closed_finish)

        def no_constructor():
            f = Fixture(); f.ns['_finish_owner_after_filecenter'](f.component, None)
            self.assertEqual(f.calls, [('finish_owner',)])
        case(CASES[6], no_constructor)

        def unknown_close():
            f = Fixture(); ticket = f.filecenter(); f.retained['filecenter_close_result'] = False
            f.reject_coordinator(self, ticket)
            self.assertEqual([r[0] for r in f.calls], ['revoke_trial','stop_http','close_state'])
        case(CASES[7], unknown_close)

        def stale_closed_cache():
            f = Fixture(); ticket = f.filecenter(); f.companion.closed_value = False
            f.reject_coordinator(self, ticket)
            self.assertTrue(ticket['closed']); self.assertTrue(f.retained['filecenter_close_result'])
            self.assertTrue(f.state.cancel_requested)
        case(CASES[8], stale_closed_cache)

        def guardian_unsettled():
            f = Fixture(); ticket = f.filecenter(); f.guardian.settled_value = False
            f.reject_coordinator(self, ticket)
            self.assertIn('guardian_settled', f.passive_calls)
            self.assertTrue(f.state.cancel_requested)
        case(CASES[9], guardian_unsettled)

        def creator_changed():
            f = Fixture(); ticket = f.filecenter()
            foreign_calls = []
            def foreign_closed(unused): foreign_calls.append(True); return True
            ticket['companion_type'].closed = foreign_closed
            f.reject_coordinator(self, ticket)
            self.assertEqual(foreign_calls, [])
            self.assertNotIn('companion_closed', f.passive_calls)
        case(CASES[10], creator_changed)

        def passive_failure():
            f = Fixture(); ticket = f.filecenter()
            original = InjectedFailure('HOST_existing_failure'); f.retained['failures'].append(original)
            failure = f.companion.closed_error = InjectedFailure('HOST_passive_error')
            f.reject_coordinator(self, ticket)
            self.assertIs(f.retained['failures'][0], original)
            self.assertIn(failure, f.retained['failures'])
            self.assertTrue(f.state.cancel_requested)
        case(CASES[11], passive_failure)

        def remaining_clip():
            f = Fixture(); f.clock.now = 758.0
            f.ns['_reject_archive_cleanup'](f.component)
            self.assertEqual(f.calls[-1], ('close_state', 2.0))
        case(CASES[12], remaining_clip)

        def zero_wait():
            f = Fixture(); cap = f.component.cleanup_until; f.clock.now = 800.0
            f.ns['_reject_archive_cleanup'](f.component)
            self.assertEqual(f.calls[-1], ('close_state', 0.0))
            self.assertIs(f.component.cleanup_until, cap)
            self.assertFalse(f.owner.close_called); self.assertFalse(f.owner.directory_close_called)
        case(CASES[13], zero_wait)

        def once():
            f = Fixture(); f.ns['_reject_archive_cleanup'](f.component)
            original = f.retained['archive_refusal_cleanup']; calls = list(f.calls)
            with self.assertRaisesRegex(ValueError, 'archive_refusal_cleanup_originals'):
                f.ns['_reject_archive_cleanup'](f.component)
            self.assertIs(f.retained['archive_refusal_cleanup'], original)
            self.assertEqual(f.calls, calls)
            self.assertTrue(original['ended'])
        case(CASES[14], once)

        def revoke_error():
            f = Fixture(); failure = f.owner.revoke_error = InjectedFailure('HOST_revoke_error')
            f.ns['_reject_archive_cleanup'](f.component)
            rows = f.retained['archive_refusal_cleanup']['calls']
            self.assertIs(rows[0]['failure'], failure)
            self.assertEqual([r[0] for r in f.calls], ['revoke_trial','stop_http','close_state'])
            self.assertTrue(all(row['ended'] for row in rows))
        case(CASES[15], revoke_error)

        def stop_error():
            f = Fixture(); failure = f.owner.stop_error = InjectedFailure('HOST_stop_error')
            f.ns['_reject_archive_cleanup'](f.component)
            self.assertIs(f.retained['archive_refusal_cleanup']['calls'][1]['failure'], failure)
            self.assertTrue(f.state.cancel_requested)
        case(CASES[16], stop_error)

        def state_unknown():
            f = Fixture(); f.state.close_return = False
            f.ns['_reject_archive_cleanup'](f.component)
            self.assertIs(f.retained['archive_refusal_cleanup']['calls'][2]['returned'], False)
            self.assertFalse(f.owner.close_complete)
            self.assertFalse(f.component.result['owner_resources_closed'])
        case(CASES[17], state_unknown)

        def owner_changed():
            f = Fixture(); original = f.owner
            # Preserve the accessed data shape, not the original creator or
            # identity. The selected guard must reject before actor callbacks.
            f.component.owner = types.SimpleNamespace(state=f.state,
                receive_trial=f.owner.receive_trial, received_directory=f.owner.received_directory)
            with self.assertRaisesRegex(ValueError, 'archive_refusal_cleanup_originals'):
                f.ns['_reject_archive_cleanup'](f.component)
            self.assertEqual(f.calls, [])
            self.assertIs(f.retained['archive_refusal_cleanup_originals'][0], original)
        case(CASES[18], owner_changed)

        def state_cap_changed():
            f = Fixture(); f.state._service_cleanup_until_original = float('760')
            with self.assertRaisesRegex(ValueError, 'archive_refusal_cleanup_originals'):
                f.ns['_reject_archive_cleanup'](f.component)
            self.assertEqual(f.calls, [])
        case(CASES[19], state_cap_changed)

        def invalid_clock():
            f = Fixture(); f.clock.now = float('nan')
            f.ns['_reject_archive_cleanup'](f.component)
            self.assertEqual([r[0] for r in f.calls], ['revoke_trial','stop_http'])
            row = f.retained['archive_refusal_cleanup']['calls'][2]
            self.assertFalse(row['called']); self.assertTrue(row['ended'])
            self.assertEqual(row['failure'].code, 'interactive_clock_unknown')
        case(CASES[20], invalid_clock)

        def noop_projection():
            f = Fixture(); raw, facts = f.close_owner_projection()
            f.ns['_copy_completed_archive_facts'](f.component, facts)
            expected = {'owner_close_verified','completed_archive_observed','completed_archive_reason',
                        'completed_archive_historical_entries_examined'} | {
                        'completed_archive_' + name for name in f.ns['COMPLETED_ARCHIVE_BOOL_FIELDS']}
            self.assertEqual(set(facts), expected)
            self.assertIs(f.retained['completed_archive_raw'], raw)
            self.assertFalse(facts['completed_archive_archived'])
            self.assertFalse(facts['completed_archive_native_restore_grant'])
            self.assertFalse(facts['completed_archive_receive_admission'])
        case(CASES[21], noop_projection)

        def archived_projection():
            f = Fixture(); raw, facts = f.close_owner_projection(archived=True)
            f.ns['_copy_completed_archive_facts'](f.component, facts)
            self.assertTrue(facts['completed_archive_archived'])
            self.assertEqual(f.owner.projector_calls, 0)
            self.assertEqual(f.calls, [])
            self.assertFalse(facts['completed_archive_native_restore_grant'])
        case(CASES[22], archived_projection)

        def projection_rejected(change):
            f = Fixture(); raw, facts = f.close_owner_projection()
            change(f, raw, facts)
            with self.assertRaisesRegex(ValueError, 'completed_archive_observation'):
                f.ns['_copy_completed_archive_facts'](f.component, facts)
            self.assertEqual(set(facts), {'owner_close_verified'})
            self.assertEqual(f.owner.projector_calls, 0)
            self.assertEqual(f.calls, [])
            return f, raw

        def extra_field():
            f, raw = projection_rejected(lambda f,r,v:r.update(extra_untrusted=True))
            self.assertIs(f.retained['completed_archive_raw'], raw)
        case(CASES[23], extra_field)
        case(CASES[24], lambda:projection_rejected(lambda f,r,v:r.update(reason='UNKNOWN_HOST_DATA')))
        case(CASES[25], lambda:projection_rejected(lambda f,r,v:setattr(f.component,'archive_end_facts',None)))
        case(CASES[26], lambda:projection_rejected(lambda f,r,v:r.update(native_restore_grant=True)))
        case(CASES[27], lambda:projection_rejected(lambda f,r,v:r.update(receive_admission=True)))
        case(CASES[28], lambda:projection_rejected(lambda f,r,v:r.update(historical_entries_examined=False)))
        case(CASES[29], lambda:projection_rejected(lambda f,r,v:setattr(f.owner,'close_complete',False)))
        case(CASES[30], lambda:projection_rejected(lambda f,r,v:f.modules.update(
            startup_readonly_private_owner=types.ModuleType('HOST_changed_owner_namespace'))))
        case(CASES[31], lambda:projection_rejected(lambda f,r,v:r.update(rename_outcome_known=True)))
        self.assertEqual(tuple(seen), CASES)
        print('RECEIVE_ARCHIVE_COORD_CONTRACTS=' + str(len(seen)))


if __name__ == '__main__':
    unittest.main()
