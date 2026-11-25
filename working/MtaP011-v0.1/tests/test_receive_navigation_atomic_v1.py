"""One affected HOST method: selected actual predicates, guard and cancel.

Canonical Owner/State/Trial binding, HTTP and peripheral calls remain models.
Only the two actual predicates, actual Worker helper/navigation block, actual
State.action/_revoke_receive_trial and actual Trial.revoke are executed. Real
HOST RLocks/Events/threads test the affected interleaving; no full graph runs.
"""
import _thread
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
PREFIX = 'candidate/receive-navigation-atomic-v1/'
FIXTURE = ('tests/test_receive_navigation_refusal_projection_v1.py', 23140,
           '99bcdb66b0b6d0875ddd57114ac7c8273d8cfe5b47a7fab81bb88b8661e7d3be')
RUNNER = ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_navigation_session.py', 88850,
          '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48')
SERVICE = ('candidate/formal-receive-v3/runtime/mta_service.py', 155732,
           '76f48871bb4c2a3b72bb308e9bef56b3d509f01ef45c7ac2808d210acedd6960')
TRIAL = ('candidate/formal-receive-v3/runtime/mta_receive_trial.py', 64493,
         'b3ffef7c593d254c375f8f4f0f97aa97cb7027db03e88861db639294dd1de13a')
OLD_WORKER = ('candidate/receive-navigation-frame-v2/runtime/ui_session.py', 95351,
              '0c53b23051e5d79cdc392b2f89d3d21de2425028ff4f76292284a72f631cb4fe')
# ROOT fills only these source DATA pins after its unique explicit --write.
GENERATOR = (PREFIX + 'generate.py', 11019,
             '7a2cbc24c19c850c17244162ca033bf83e8b39246e901becc418fbe265e1f12d')
WORKER = (PREFIX + 'runtime/ui_session.py', 100162,
          'cde8ae626632e5d86acb2cc741b7d22eb18582b58ed6d6fd48160c008b62225e')
DELTA = (PREFIX + 'exactsource-delta.json', 7470,
         '9af5097dda522efa3bd9b5f406308f3c43123e7159a1ef78251d835b8dd35613')


def pinned(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('atomic_contract_source_pin:' + pin[0])
    return raw


def selected_fixture(raw):
    tree = ast.parse(raw, feature_version=(3, 5))
    names = {'method', 'selected_runner', 'fixture', 'cached_trial', 'facts', 'Tracked'}
    nodes = [copy.deepcopy(row) for row in tree.body
             if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name in names]
    if len(nodes) != len(names):
        raise ValueError('exact_reused_fixture_subset')
    module = types.ModuleType('atomic_reused_fixture')
    module.__dict__.update(ast=ast, copy=copy, types=types)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 '<reused-selected-canonical-fixtures>', 'exec'), module.__dict__)
    return module


def function(tree, name, cls=None):
    body = tree.body if cls is None else next(row.body for row in tree.body
        if isinstance(row, ast.ClassDef) and row.name == cls)
    return next(row for row in body if isinstance(row, ast.FunctionDef) and row.name == name)


def selected_worker(raw, label):
    tree = ast.parse(raw, feature_version=(3, 5))
    names = {'need', '_receive_ui_cancelled_empty', '_receive_ui_empty_pair', 'UiSessionError'}
    nodes = [copy.deepcopy(row) for row in tree.body
             if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name in names]
    run = copy.deepcopy(function(tree, 'run_fixed'))
    block = next(row for row in ast.walk(run) if isinstance(row, ast.If) and
                 isinstance(row.test, ast.Name) and row.test.id == 'navigation_test' and row.lineno == 1552)
    run.args = ast.parse('def guard(component,runner,facts,trial_observed,navigation_test=True): pass').body[0].args
    run.body = [block]
    nodes.append(run)
    original_run = function(tree, 'run_fixed')
    retain = [copy.deepcopy(row) for row in ast.walk(original_run) if isinstance(row, ast.Expr)
              and row.lineno == 1461 and isinstance(row.value, ast.IfExp)]
    if retain:
        if len(retain) != 1:
            raise ValueError('single_actual_navigation_retain')
        adapter = ast.parse('def selected_retain(component,navigation_test): pass').body[0]
        adapter.body = retain
        adapter.end_lineno = 1461
        nodes.append(adapter)
    module = types.ModuleType(label)
    module.__dict__.update(types=types, sys=sys)
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 '<actual-selected-atomic-worker>', 'exec'), module.__dict__)
    return module, tree


def bind_cancel(raw_service, raw_trial, case):
    """Actual cancel transition; original binding and no-actor helpers modeled."""
    service_tree, trial_tree = (ast.parse(raw, feature_version=(3, 5))
                                for raw in (raw_service, raw_trial))
    service = types.ModuleType('atomic_selected_cancel_service')
    gate_module = case.component.loader.modules['mta_receive_trial']
    service.__dict__.update(receive_trial=gate_module)
    for name in ('action', '_revoke_receive_trial'):
        node = copy.deepcopy(function(service_tree, name, 'State'))
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                     '<actual-state-cancel-methods>', 'exec'), service.__dict__)
        setattr(type(case.state), name, service.__dict__[name])
    trial_namespace = types.ModuleType('atomic_selected_trial_revoke')
    reasons = next(row.value for row in trial_tree.body if isinstance(row, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'REVOKE_REASONS'
                           for target in row.targets))
    if (not isinstance(reasons, ast.Call) or not isinstance(reasons.func, ast.Name) or
            reasons.func.id != 'frozenset' or len(reasons.args) != 1 or reasons.keywords):
        raise ValueError('actual_revoke_reasons_literal')
    trial_namespace.__dict__['REVOKE_REASONS'] = frozenset(ast.literal_eval(reasons.args[0]))
    node = copy.deepcopy(function(trial_tree, 'revoke', 'FixedReceiveTrial'))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                 '<actual-trial-revoke>', 'exec'), trial_namespace.__dict__)
    type(case.trial).revoke = trial_namespace.revoke
    type(case.trial)._originals = lambda self, state, bound: state is case.state and bound is True
    type(case.state)._receive_constructor_pending = lambda self: False
    type(case.state)._probes_closed = lambda self: True
    type(case.state)._cleanup_session_locked = lambda self: None
    type(case.state).status = lambda self: {'fixture_status': True}
    case.state._receive_trial = case.trial
    case.state._receive_trial_error = None


class NavigationAtomicV1Contract(unittest.TestCase):
    def test_actual_empty_pair_cancel_transition_and_retained_guards(self):
        pins = (FIXTURE, RUNNER, SERVICE, TRIAL, OLD_WORKER, GENERATOR, WORKER, DELTA)
        raw = {pin[0]: pinned(pin) for pin in pins}
        delta = json.loads(raw[DELTA[0]].decode('ascii'))
        self.assertEqual(delta['schema'], 'p011-receive-navigation-atomic-v1-worker-delta')
        self.assertEqual(delta['source'], list(OLD_WORKER))
        self.assertEqual(delta['candidate'], list(WORKER))
        self.assertEqual(delta['generator'], list(GENERATOR))
        current = raw[OLD_WORKER[0]]
        self.assertEqual(len(delta['replacements']), 4)
        for row in delta['replacements']:
            before, after = (row[name].encode('ascii') for name in ('before', 'after'))
            self.assertEqual(current.count(before), row['count'])
            current = current.replace(before, after, row['count'])
        self.assertEqual(current, raw[WORKER[0]])
        for row in reversed(delta['replacements']):
            before, after = (row[name].encode('ascii') for name in ('before', 'after'))
            self.assertEqual(current.count(after), row['count'])
            current = current.replace(after, before, row['count'])
        self.assertEqual(current, raw[OLD_WORKER[0]])
        reused = selected_fixture(raw[FIXTURE[0]])
        old, old_tree = selected_worker(raw[OLD_WORKER[0]], 'atomic_old_worker')
        new, new_tree = selected_worker(raw[WORKER[0]], 'atomic_new_worker')
        self.assertEqual(old.run_fixed.__code__.co_firstlineno, 1246)
        self.assertEqual(new.run_fixed.__code__.co_firstlineno, 1246)
        for tree in (old_tree, new_tree):
            needs = [row for row in ast.walk(function(tree, 'run_fixed')) if isinstance(row, ast.Call)
                     and isinstance(row.func, ast.Name) and row.func.id == 'need' and len(row.args) == 2
                     and isinstance(row.args[1], ast.Constant) and row.args[1].value == 'navigation_receive_activity']
            self.assertEqual(len(needs), 1)
            self.assertEqual(needs[0].end_lineno, 1560)
        old_need, new_need = [next(row for row in ast.walk(function(tree, 'run_fixed'))
            if isinstance(row, ast.Call) and isinstance(row.func, ast.Name) and row.func.id == 'need'
            and len(row.args) == 2 and isinstance(row.args[1], ast.Constant)
            and row.args[1].value == 'navigation_receive_activity') for tree in (old_tree, new_tree)]
        self.assertEqual(ast.dump(old_need), ast.dump(new_need))
        helper = function(new_tree, '_receive_ui_empty_pair')
        locks = [row for row in ast.walk(helper) if isinstance(row, ast.With)]
        self.assertEqual([ast.unparse(row.items[0].context_expr) for row in locks], ['state_lock', 'trial_lock'])
        calls = [row for row in ast.walk(helper) if isinstance(row, ast.Call)]
        forbidden = {'available', 'public_facts', '_live', 'monotonic', 'sleep', 'close',
                     'revoke', 'claim', 'action', 'open', 'poll', 'check', 'acquire', 'release'}
        self.assertFalse(any(isinstance(row.func, ast.Name) and row.func.id in forbidden or
                             isinstance(row.func, ast.Attribute) and row.func.attr in forbidden for row in calls))

        def make(worker, cancelled=False):
            runner = reused.selected_runner(ast.parse(raw[RUNNER[0]], feature_version=(3, 5)), 'atomic_actual_predicates')
            self.assertEqual(runner.FixedSession.original_receive_ui_cancelled_empty.__code__.co_firstlineno, 817)
            case = reused.fixture(runner)
            case.state_lock, case.trial_lock = _thread.RLock(), _thread.RLock()
            case.state.lock = case.state_lock
            case.trial._lock = case.trial._lock_original = case.trial_lock
            case.trial.state = case.state
            case.state.cancelled, case.state.decision = threading.Event(), threading.Event()
            runner.threading.Event = threading.Event
            case.trial.revoked = cancelled
            case.trial.revoke_reason = 'cancelled' if cancelled else None
            case.trial.reason = 'cancelled' if cancelled else 'client_root_missing'
            if cancelled:
                case.state.cancelled.set(); case.state.decision.set()
            bind_cancel(raw[SERVICE[0]], raw[TRIAL[0]], case)
            observer = runner.FixedSession.original_receive_ui_cancelled_empty
            worker._RETAINED = dict(component=case.component,
                navigation_observer=(runner.FixedSession, observer, observer.__code__), failures=[])
            worker.sys = types.SimpleNamespace(modules=dict(case.component.loader.modules, _thread=_thread))
            if hasattr(worker, 'selected_retain'):
                worker.selected_retain(case.component, True)
            return case, runner

        class Untouchable:
            def __getattribute__(self, name):
                raise AssertionError('non-navigation must not read or update retain: ' + name)
        new._RETAINED = Untouchable()
        new.selected_retain(Untouchable(), False)
        case, runner = make(new)
        original_refs = new._RETAINED['navigation_empty_originals']
        self.assertEqual(len(original_refs), 6)
        self.assertTrue(all(a is b for a, b in zip(original_refs,
            (case.component, case.owner, case.state, case.state_lock, case.trial, case.trial_lock))))

        # A real refusal remains displayable; no CLIENT special case or admission.
        self.assertEqual(new._receive_ui_empty_pair(case.component), (False, True))
        case, runner = make(new, True)
        self.assertEqual(new._receive_ui_empty_pair(case.component), (True, False))

        for worker, atomic in ((old, False), (new, True)):
            with self.subTest(interleaving='new_atomic' if atomic else 'old_split'):
                case, runner = make(worker)
                requested, attempted, done = threading.Event(), threading.Event(), threading.Event()
                errors, acquired = [], []
                def cancel():
                    try:
                        if not requested.wait(2): raise AssertionError('cancel_request_timeout')
                        for lock in (case.state_lock, case.trial_lock):
                            ok = lock.acquire(False)
                            acquired.append(ok)
                            if ok: lock.release()
                        attempted.set()
                        type(case.state).action(case.state, {'action': 'cancel'})
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        attempted.set(); done.set()
                wrapper = worker._receive_ui_cancelled_empty
                def between(component):
                    result = wrapper(component)
                    self.assertIs(result, False)
                    requested.set()
                    self.assertTrue(attempted.wait(2), 'cancel_attempt_timeout')
                    if not atomic: self.assertTrue(done.wait(2), 'old_cancel_return_timeout')
                    return result
                worker._receive_ui_cancelled_empty = between
                actor = threading.Thread(target=cancel, daemon=True)
                actor.start()
                observed = reused.facts()
                try:
                    if atomic:
                        worker.run_fixed(case.component, runner, observed, reused.cached_trial(revoked=False))
                    else:
                        with self.assertRaises(worker.UiSessionError) as caught:
                            worker.run_fixed(case.component, runner, observed, reused.cached_trial(revoked=False))
                        self.assertEqual(caught.exception.code, 'navigation_receive_activity')
                finally:
                    worker._receive_ui_cancelled_empty = wrapper
                    requested.set()
                    actor.join(2)
                self.assertFalse(actor.is_alive(), 'cancel_thread_must_exit')
                self.assertEqual(errors, [])
                self.assertEqual(acquired, [False, False] if atomic else [True, True])
                self.assertEqual(observed['navigation_receive_activity_free'], atomic)
                self.assertEqual(case.trial.claim_count, 0)
                self.assertIsNone(case.state.operation)
                self.assertIsNone(case.state.session)
                if atomic:
                    self.assertEqual(worker._receive_ui_empty_pair(case.component), (True, False))
                    worker.run_fixed(case.component, runner, observed, reused.cached_trial())
                    self.assertIs(observed['navigation_cancelled_empty_observed'], True)

        # Only new helper/call-site integration cases are executed; old suites stay reused.
        changes = (
            ('state_lock_replaced', lambda f: setattr(f.state, 'lock', _thread.RLock())),
            ('trial_lock_replaced', lambda f: setattr(f.trial, '_lock', _thread.RLock())),
            ('foreign_owner', lambda f: setattr(f.component, 'owner', object())),
            ('foreign_state', lambda f: setattr(f.owner, 'state', object())),
            ('foreign_trial', lambda f: setattr(f.owner, 'receive_trial', object())),
            ('closing', lambda f: setattr(f.state, 'closing', True)),
            ('expired', lambda f: setattr(f.trial, 'expired', True)),
            ('claimed', lambda f: setattr(f.trial, 'claim_count', 1)),
            ('attached', lambda f: setattr(f.trial, 'session', object())),
            ('pending', lambda f: setattr(f.state, 'radio_restore_pending', True)),
            ('rf_sentinel', lambda f: setattr(f.state, 'receive_available', True)),
            ('observer_code', lambda f: new._RETAINED.update(navigation_observer=(
                runner.FixedSession, runner.FixedSession.original_receive_ui_cancelled_empty, object()))),
        )
        for name, mutate in changes:
            with self.subTest(new_integration_refusal=name):
                case, runner = make(new, True)
                mutate(case)
                self.assertEqual(new._receive_ui_empty_pair(case.component), (False, False))
        for field in ('state', 'trial'):
            with self.subTest(non_rlock_retention=field):
                case, runner = make(new, True)
                foreign = threading.Lock()
                if field == 'state':
                    case.state.lock = foreign
                    values = (case.component, case.owner, case.state, foreign, case.trial, case.trial_lock)
                else:
                    case.trial._lock = case.trial._lock_original = foreign
                    values = (case.component, case.owner, case.state, case.state_lock, case.trial, foreign)
                new._RETAINED['navigation_empty_originals'] = values
                self.assertEqual(new._receive_ui_empty_pair(case.component), (False, False))
        for cached in (dict(claimed=True), dict(claim_count=1), dict(session_attached=True), dict(expired=True)):
            with self.subTest(original_cached_guard=cached):
                case, runner = make(new, True)
                observed = reused.facts()
                with self.assertRaises(new.UiSessionError) as caught:
                    new.run_fixed(case.component, runner, observed, reused.cached_trial(**cached))
                self.assertEqual(caught.exception.code, 'navigation_receive_activity')
                self.assertIs(observed['navigation_receive_activity_free'], False)
        # Recheck canonical fields after waiting for the retained State lock.
        case, runner = make(new, True)
        helper_line = next(row.lineno for row in ast.walk(helper) if isinstance(row, ast.With)
                           and isinstance(row.items[0].context_expr, ast.Name)
                           and row.items[0].context_expr.id == 'state_lock')
        locking, outcome, errors = threading.Event(), [], []
        def observe_after_wait():
            def trace(frame, event, arg):
                if frame.f_code is new._receive_ui_empty_pair.__code__ and event == 'line' and frame.f_lineno == helper_line:
                    locking.set()
                return trace
            sys.settrace(trace)
            try: outcome.append(new._receive_ui_empty_pair(case.component))
            except BaseException as error: errors.append(error)
            finally: sys.settrace(None)
        case.state_lock.acquire()
        actor = threading.Thread(target=observe_after_wait, daemon=True)
        actor.start()
        try:
            self.assertTrue(locking.wait(2), 'helper_prelock_timeout')
            case.state.lock = _thread.RLock()
        finally:
            case.state_lock.release()
            actor.join(2)
        self.assertFalse(actor.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(outcome, [(False, False)])
        self.assertTrue(all((BASE / pin[0]).read_bytes() == raw[pin[0]] for pin in pins))
        print('RECEIVE_NAVIGATION_ATOMIC_V1_HOST_PASS methods=1 old_methods=0 real_rlocks=true actual_cancel=true', flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
