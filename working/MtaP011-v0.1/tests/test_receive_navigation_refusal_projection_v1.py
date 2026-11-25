"""One HOST method for selected actual observer/guard AST and projection binding.

Owner/State/Trial/HTTP, locks, Events and canonical binding are narrow fixtures.
The guard function contains only the actual navigation block, retaining its
original function/statement line numbers. Its traceback tests the actual
projection fragment's selected-code bindings, not a complete Worker/Owner run.
No runtime main, device, RF, network, GUI or resource closer is executed.
"""
import ast
import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
OLD_RUNNER = ('candidate/formal-receive-filecenter-navigation-publication-v1/runtime/mta_formal_receive_session.py',
              85546, '521f5110bafdbde3a3539fff5f2b2a53a911a8e1008597ca646e3b0acff8ca8b')
OLD_WORKER = ('candidate/formal-receive-filecenter-navigation-publication-v2/runtime/ui_session.py',
              95260, '68aa90855e6109714c9e8e091d266eb7900dba5a4129d75a3fc943543e3ed19a')
RUNNER = ('candidate/formal-receive-filecenter-navigation-publication-v3/runtime/mta_formal_receive_session.py',
          88817, 'a54c40de4ad1b0a59ed81191ad7768d6d0783d2acb4b7aa58a84d010bd3b812f')
WORKER = ('candidate/formal-receive-filecenter-navigation-publication-v3/runtime/ui_session.py',
          95419, '2661710612069f9381dea2049721147cab01f2b1ac67e3d22628fa609b90d80c')
HELPER = ('host/receive_navigation_refusal_projection_v1.py',
          7474, 'c48192bd978e0bb056f5ea0c74617628b6d9e27936ca9e5697310e39b7bb1bb4')
DELTA = ('candidate/formal-receive-filecenter-navigation-publication-v3/exactsource-delta.json',
         19340, '2b1a84e35fa27a546248d70d4780d73e37622eb4b37ec6f453d942278261e812')
GROUPS = ('owner', 'http', 'types', 'bound_trial', 'trial_cancel', 'trial_empty',
          'epochs', 'inventory', 'resources', 'collections', 'probes', 'events')


def pinned(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('navigation_contract_source_pin')
    return raw


def method(tree, name):
    cls = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedSession')
    return next(row for row in cls.body if isinstance(row, ast.FunctionDef) and row.name == name)


def selected_runner(tree, label):
    cls = copy.deepcopy(next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedSession'))
    cls.body = [copy.deepcopy(method(tree, name)) for name in
                ('original_receive_ui_idle', 'original_receive_ui_cancelled_empty')]
    module = types.ModuleType(label)
    module.__dict__.update(types=types)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])),
                 '<actual-selected-receive-observer>', 'exec'), module.__dict__)
    return module


def selected_worker(tree, label):
    selected = [copy.deepcopy(row) for row in tree.body if
                isinstance(row, ast.FunctionDef) and row.name in ('need', '_receive_ui_cancelled_empty') or
                isinstance(row, ast.ClassDef) and row.name == 'UiSessionError']
    run = copy.deepcopy(next(row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == 'run_fixed'))
    block = next(row for row in ast.walk(run) if isinstance(row, ast.If) and
                 isinstance(row.test, ast.Name) and row.test.id == 'navigation_test' and row.lineno == 1552)
    # Only the surrounding HOST-fixture signature/return are supplied. Every
    # navigation block statement and its original line number are unchanged.
    run.args = ast.parse('def guard(component,runner,facts,trial_observed,navigation_test=True,smoke_only=False): pass').body[0].args
    run.body = [block, ast.Return(value=ast.Call(func=ast.Name(id='locals', ctx=ast.Load()), args=[], keywords=[]),
                                 lineno=1564, col_offset=4, end_lineno=1564, end_col_offset=20)]
    selected.append(run)
    module = types.ModuleType(label)
    module.__dict__.update(types=types)
    exec(compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                 '<actual-selected-navigation-guard>', 'exec'), module.__dict__)
    return module


class Tracked:
    def __getattribute__(self, name):
        if not name.startswith('__') and name not in ('_trace', '_kind'):
            trace = object.__getattribute__(self, '_trace')
            trace.append(('read', object.__getattribute__(self, '_kind'), name))
        return object.__getattribute__(self, name)


def fixture(runner):
    trace = []

    def fields(obj, kind, **values):
        object.__setattr__(obj, '_trace', trace)
        object.__setattr__(obj, '_kind', kind)
        for name, value in values.items():
            setattr(obj, name, value)
        return obj

    class Lock:
        def __init__(self, label): self.label, self.exit_error = label, None
        def __enter__(self): trace.append(('enter', self.label)); return self
        def __exit__(self, *unused):
            trace.append(('exit', self.label))
            if self.exit_error is not None: raise self.exit_error
            return False

    class HttpThread:
        def is_alive(self): trace.append(('alive',)); return True

    class Event:
        def __init__(self, label): self.label = label
        def is_set(self): trace.append(('event', self.label)); return True

    class State(Tracked):
        def _receive_trial_exact(self):
            trace.append(('exact',))
            error = object.__getattribute__(self, 'exact_error')
            if error is not None: raise error
            return object.__getattribute__(self, 'exact_return')

    class Gate(Tracked): pass

    owner_module = types.ModuleType('fixture_canonical_owner')
    owner_module.__dict__['Tracked'] = Tracked
    exec('class FixedStateServiceOwner(Tracked):\n def __init__(self): pass\n', owner_module.__dict__)
    service, gate_module = types.ModuleType('mta_service'), types.ModuleType('mta_receive_trial')
    service.State, gate_module.FixedReceiveTrial = State, Gate
    loader = types.SimpleNamespace(modules={'mta_service': service, 'mta_receive_trial': gate_module})
    cap, worker, thread = 123.5, object(), HttpThread()
    loader._original_until = cap
    state_lock, trial_lock = Lock('state'), Lock('trial')
    probes, restore = [{'closed': True}, {'closed': True}], []
    trial = fields(Gate(), 'trial', _lock=trial_lock, _lock_original=trial_lock,
                   requested=True, revoked=True, revoke_reason='cancelled', reason='cancelled',
                   expired=False, failure=None, claim_count=0, claimed_operation=None,
                   _claimed_operation_original=None, session=None, _session_original=None,
                   _epoch=0, _restore_probes=restore, probes=probes, _probe_prefix=tuple(probes))
    state = fields(State(), 'state', lock=state_lock, _receive_trial_original=trial,
                   exact_return=True, exact_error=None, native_epoch=0, state='idle', closing=False,
                   receive_available=False, send_available=False, scan_available=False,
                   operation=None, session=None, discoverable=False, scanning=False,
                   wifi_restore_pending=False, radio_restore_pending=False, accepted=False,
                   history=[], received=[], devices={}, peer_seen={}, transfer={}, event_counts={},
                   radio_restore_probes=restore, probe_actors=probes,
                   cancelled=Event('cancelled'), decision=Event('decision'))
    for name in ('helper', 'key', 'crypto', 'lease', 'transport', 'worker', 'request'):
        setattr(state, name, None)
    ticket = dict(thread=thread, thread_original=thread, initialized=True, called=True,
                  returned=True, unknown=False, failure=None)
    threads = [ticket]
    owner = fields(owner_module.FixedStateServiceOwner.__new__(owner_module.FixedStateServiceOwner), 'owner',
                   _startup_owner_type_original=owner_module.FixedStateServiceOwner,
                   _startup_namespace_original=owner_module.__dict__, loader=loader, worker=worker,
                   pid=321, until=cap, original_until=cap, receive_trial_requested=True,
                   _receive_trial_requested_original=True, start_complete=True, stop_called=False,
                   close_called=False, threads=threads, _threads_original=threads, thread=thread,
                   service=service, state=state, _state_original=state,
                   receive_trial=trial, _receive_trial_original=trial, probe_rows=probes)
    component = runner.FixedSession.__new__(runner.FixedSession)
    component.__dict__.update(owner=owner, loader=loader, owner_module=owner_module,
                              worker=worker, pid=321, until=cap, receive_trial_requested=True,
                              _receive_trial_requested_original=True)
    runner.__dict__.update(sys=types.SimpleNamespace(modules=loader.modules),
                           threading=types.SimpleNamespace(Thread=HttpThread, Event=Event))
    return types.SimpleNamespace(component=component, owner=owner, state=state, trial=trial,
                                 ticket=ticket, trace=trace, state_lock=state_lock, trial_lock=trial_lock)


def cached_trial(**changes):
    result = dict(requested=True, available=False, claimed=False, claim_count=0,
                  session_attached=False, revoked=True, expired=False, reason='cancelled',
                  startup_verified=True, probe_verified=True, radio_known=True,
                  barrier_clear=True, network_spec_verified=True,
                  restoration_verified=False, phone_verified=False)
    result.update(changes)
    return result


def facts():
    return dict(navigation_receive_activity_free=False, navigation_cancelled_empty_observed=False)


class NavigationRefusalProjectionV1Contract(unittest.TestCase):
    def test_actual_guard_short_circuit_and_cached_data(self):
        raw = {pin[0]: pinned(pin) for pin in (OLD_RUNNER, OLD_WORKER, RUNNER, WORKER, HELPER, DELTA)}
        spec = json.loads(raw[DELTA[0]].decode('ascii'))
        self.assertEqual(spec['evidence'], 'source_data_only_not_executed')
        self.assertEqual([(row['path'], row['bytes'], row['sha256']) for row in spec['sources']],
                         [(pin[0], pin[1], pin[2]) for pin in (OLD_RUNNER, OLD_WORKER)])
        self.assertEqual([(row['path'], row['bytes'], row['sha256']) for row in spec['candidates']],
                         [(pin[0], pin[1], pin[2]) for pin in (RUNNER, WORKER)])
        original = {'runtime/mta_formal_receive_session.py': raw[OLD_RUNNER[0]], 'runtime/ui_session.py': raw[OLD_WORKER[0]]}
        current = dict(original)
        self.assertEqual(len(spec['replacements']), 4)
        for row in spec['replacements']:
            before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
            self.assertEqual(current[row['file']].count(before), row['count'])
            current[row['file']] = current[row['file']].replace(before, after)
        self.assertEqual(current, {'runtime/mta_formal_receive_session.py': raw[RUNNER[0]], 'runtime/ui_session.py': raw[WORKER[0]]})
        for row in reversed(spec['replacements']):
            before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
            self.assertEqual(current[row['file']].count(after), row['count'])
            current[row['file']] = current[row['file']].replace(after, before)
        self.assertEqual(current, original)

        trees = [ast.parse(raw[pin[0]].decode('ascii'), feature_version=(3, 5)) for pin in (OLD_RUNNER, RUNNER)]
        observers = [method(tree, 'original_receive_ui_cancelled_empty') for tree in trees]
        tries = [next(node for node in fn.body if isinstance(node, ast.Try)) for fn in observers]
        old_ifs, new_ifs = [[node for node in tr.body if isinstance(node, ast.If)] for tr in tries]
        self.assertEqual([ast.dump(n.test) for n in old_ifs], [ast.dump(n.test) for n in new_ifs])
        self.assertEqual(ast.dump(tries[0].handlers[0].type), ast.dump(tries[1].handlers[0].type))
        old_with, new_with = [next(node for node in tr.body if isinstance(node, ast.With)) for tr in tries]
        old_inner, new_inner = old_with.body[0], new_with.body[0]
        self.assertEqual(ast.dump(old_with.items[0]), ast.dump(new_with.items[0]))
        self.assertEqual(ast.dump(old_inner.items[0]), ast.dump(new_inner.items[0]))

        def terms(value):
            return [part for node in value.values for part in terms(node)] if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.And) else [ast.dump(value)]

        old_terms = terms(old_inner.body[0].value)
        new_terms = [part for node in new_inner.body if isinstance(node, ast.If)
                     for part in terms(node.test.operand)]
        self.assertEqual(new_terms, old_terms)
        runners = [selected_runner(tree, 'selected_original' if i == 0 else 'selected_candidate') for i, tree in enumerate(trees)]
        mutations = (
            lambda f: setattr(f.owner, 'start_complete', False),
            lambda f: f.ticket.update(initialized=False),
            lambda f: setattr(f.owner, 'service', object()),
            lambda f: setattr(f.state, 'exact_return', False),
            lambda f: setattr(f.trial, 'revoked', False),
            lambda f: setattr(f.trial, 'claim_count', True),
            lambda f: setattr(f.state, 'native_epoch', True),
            lambda f: setattr(f.state, 'state', 'busy'),
            lambda f: setattr(f.state, 'helper', object()),
            lambda f: setattr(f.state, 'history', [object()]),
            lambda f: setattr(f.state, 'radio_restore_probes', []),
            lambda f: setattr(f.state, 'cancelled', object()),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(group=GROUPS[index]):
                cases = [fixture(runner) for runner in runners]
                for case in cases: mutate(case)
                self.assertIs(cases[0].component.original_receive_ui_cancelled_empty(), False)
                self.assertIs(cases[1].component.original_receive_ui_cancelled_empty(), False)
                self.assertEqual(cases[1].trace, cases[0].trace)
                self.assertEqual(cases[1].component._navigation_cancelled_diagnostic,
                                 (GROUPS[index], GROUPS[:index], 'false'))
                # No skipped group may acquire a lock or observe an Event.
                if index < 3: self.assertNotIn(('enter', 'state'), cases[1].trace)
                if index < 11: self.assertFalse(any(row[0] == 'event' for row in cases[1].trace))
        success = [fixture(runner) for runner in runners]
        self.assertTrue(all(case.component.original_receive_ui_cancelled_empty() is True for case in success))
        self.assertEqual(success[1].trace, success[0].trace)
        self.assertEqual(success[1].component._navigation_cancelled_diagnostic, ('none', GROUPS, 'true'))
        # Diagnostics belong to this call, not an earlier successful observation.
        success[1].trial.revoked = False
        self.assertIs(success[1].component.original_receive_ui_cancelled_empty(), False)
        self.assertEqual(success[1].component._navigation_cancelled_diagnostic, ('trial_cancel', GROUPS[:4], 'false'))
        for error_class, kind in ((AttributeError, 'attribute'), (KeyError, 'key'),
                                  (TypeError, 'type'), (ValueError, 'value'), (RuntimeError, 'runtime')):
            with self.subTest(exception=kind):
                cases = [fixture(runner) for runner in runners]
                for case in cases: case.state.exact_error = error_class('private-sensitive-detail')
                self.assertTrue(all(case.component.original_receive_ui_cancelled_empty() is False for case in cases))
                self.assertEqual(cases[1].trace, cases[0].trace)
                self.assertEqual(cases[1].component._navigation_cancelled_diagnostic, ('bound_trial', GROUPS[:3], kind))
        for runner in runners:
            case = fixture(runner); case.state.exact_error = OSError('private-sensitive-detail')
            with self.assertRaises(OSError): case.component.original_receive_ui_cancelled_empty()
            self.assertEqual(case.trace[-2:], [('exit', 'trial'), ('exit', 'state')])
        for runner in runners:
            case = fixture(runner); case.trial_lock.exit_error = RuntimeError('private-sensitive-detail')
            self.assertIs(case.component.original_receive_ui_cancelled_empty(), False)
        self.assertEqual(case.component._navigation_cancelled_diagnostic, ('lock_exit', GROUPS, 'runtime'))

        worker_trees = [ast.parse(raw[pin[0]].decode('ascii'), feature_version=(3, 5)) for pin in (OLD_WORKER, WORKER)]
        workers = [selected_worker(tree, 'selected_old_worker' if i == 0 else 'selected_new_worker') for i, tree in enumerate(worker_trees)]

        def attach(worker, runner, case):
            observer = runner.FixedSession.original_receive_ui_cancelled_empty
            worker._RETAINED = dict(component=case.component, failures=[],
                                    navigation_observer=(runner.FixedSession, observer, observer.__code__))
            calls = []
            retained_wrapper = worker._receive_ui_cancelled_empty
            def cancelled(component): calls.append('cancelled'); return retained_wrapper(component)
            worker._receive_ui_cancelled_empty = cancelled
            original_idle = runner.FixedSession.original_receive_ui_idle
            def idle(component): calls.append('idle'); return original_idle(component)
            # This counter fixture returns the actual selected idle result.
            runner.FixedSession.original_receive_ui_idle = idle
            return calls

        class ReadTraceDict(dict):
            def __getitem__(self, key): reads.append(key); return dict.__getitem__(self, key)

        scenarios = (
            ('ready', {}, lambda f: setattr(f.trial, 'revoked', False), False),
            ('cancelled', {}, lambda f: None, False),
            ('neither', {}, lambda f: setattr(f.state, 'state', 'busy'), True),
            ('claimed', dict(claimed=True, claim_count=1), lambda f: None, True),
            ('count', dict(claim_count=1), lambda f: None, True),
            ('attached', dict(session_attached=True), lambda f: None, True),
            ('expired', dict(expired=True), lambda f: None, True),
        )
        for name, changes, mutate, refused in scenarios:
            results = []
            for i, worker_tree in enumerate(worker_trees):
                runner = selected_runner(trees[1], 'worker_case_runner_' + str(i))
                worker = selected_worker(worker_tree, 'worker_case_' + str(i))
                case = fixture(runner); mutate(case)
                calls = attach(worker, runner, case)
                reads = []
                cached = ReadTraceDict(cached_trial(**changes))
                observed = facts()
                try: worker.run_fixed(case.component, runner, observed, cached)
                except worker.UiSessionError as error:
                    self.assertTrue(refused); self.assertEqual(error.code, 'navigation_receive_activity')
                else: self.assertFalse(refused)
                self.assertEqual(calls, ['cancelled', 'idle'])
                if name == 'neither': self.assertEqual(reads, [])
                results.append((observed, reads))
            self.assertEqual(results[0], results[1])

        helper_tree = ast.parse(raw[HELPER[0]].decode('ascii'), feature_version=(3, 5))
        fragment = ast.literal_eval(next(row.value for row in helper_tree.body if isinstance(row, ast.Assign)
                                       and any(isinstance(t, ast.Name) and t.id == 'TARGET_FRAGMENT' for t in row.targets)))
        fragment_tree = ast.parse(fragment.decode('ascii'), feature_version=(3, 5))
        forbidden = {'os', 'time', 'subprocess', 'socket', 'threading', 'open', 'eval', 'exec',
                     'getattr', 'setattr', 'original_receive_ui_idle', 'original_receive_ui_cancelled_empty',
                     'public_facts', 'finish_owner', 'close', 'monotonic', 'sleep', 'available'}
        self.assertFalse(any(isinstance(row, ast.Name) and row.id in forbidden or
                             isinstance(row, ast.Attribute) and row.attr in forbidden for row in ast.walk(fragment_tree)))
        imports = [alias.name for row in ast.walk(fragment_tree) if isinstance(row, ast.Import) for alias in row.names]
        self.assertEqual(imports, ['sys', 'types'])
        target_code = compile(fragment_tree, '<actual-refusal-projection-fragment>', 'exec')
        runner = selected_runner(trees[1], 'projection_fixture_runner')
        worker = selected_worker(worker_trees[1], 'projection_fixture_worker')
        case = fixture(runner); calls = attach(worker, runner, case)
        cached = cached_trial(expired=True)
        try: worker.run_fixed(case.component, runner, facts(), cached)
        except worker.UiSessionError as error: worker._RETAINED['failures'].append(error)
        else: self.fail('original selected navigation refusal required')
        self.assertEqual(calls, ['cancelled', 'idle'])
        self.assertEqual(worker.run_fixed.__code__.co_firstlineno, 1246)
        self.assertEqual(runner.FixedSession.original_receive_ui_cancelled_empty.__code__.co_firstlineno, 816)
        # Mutate live objects/sidecar after the refusal. The projection must use
        # the independent earlier cached dict/tuple and never observe them again.
        case.trial.expired = False
        case.component._navigation_cancelled_diagnostic = ('invented-live-value', (), 'false')
        case.trace.clear(); calls.clear()

        def project(value=worker):
            output = io.StringIO()
            with redirect_stderr(output): exec(target_code, {'worker': value})
            self.assertEqual(case.trace, []); self.assertEqual(calls, [])
            self.assertNotIn('private-sensitive-detail', output.getvalue())
            return output.getvalue()

        output = project()
        self.assertTrue(output.startswith('PRIVATE_RECEIVE_NAVIGATION_REFUSAL='), output)
        row = ast.literal_eval(output.partition('=')[2].strip().removesuffix('\\n'))
        self.assertEqual(row[1], (False, True))
        self.assertEqual(dict(row[2])['expired'], True)
        self.assertEqual(row[-1], ('none', GROUPS, 'true'))
        self.assertIn('PRIVATE_RECEIVE_NAVIGATION_REFUSAL_UNKNOWN=', project(object()))
        cached['claim_count'] = True
        self.assertIn('finite_cached_data', project())
        cached['claim_count'] = 0
        worker._RETAINED['failures'] *= 2
        self.assertIn('navigation_traceback', project())
        worker._RETAINED['failures'] = []
        self.assertIn('PRIVATE_RECEIVE_NAVIGATION_REFUSAL_NOT_APPLICABLE=', project())


if __name__ == '__main__':
    unittest.main(verbosity=2)
