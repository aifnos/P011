"""New HOST constructor-retention checks, not a deployed sender graph.

Execute the saved State's actual selected methods and Operation constructor,
plus the original unstarted Session78 constructor. Trial decisions, callbacks,
prior-session closure and worker-start resolution are explicit HOST models.
No Session worker/finalizer, Native, original Owner/Parent or target IO runs.
"""
import ast
import hashlib
from pathlib import Path
import threading
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
STATE = 'candidate/formal-send-v1/runtime/mta_service.py'
SESSION = 'candidate/go-send-state-v78/runtime/mta_transfer_session.py'
STATE_PIN = (145518, '4c580381a6ed2988ea6fa8f968e8145d3ac21748b49e7e5e9eff7809c55b8c43')
SESSION_PIN = (20633, 'e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859')
METHODS = ('_new_operation_locked', '_verify_go_terminal_restoration',
           '_go_freeze', '_go_restoration_current', '_go_zero_closed')


def source(name, pin):
    raw = (ROOT / name).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
        raise ValueError('fixed_source_changed')
    ast.parse(raw, feature_version=(3, 5))
    return raw


class InjectedFailure(RuntimeError):
    pass


class TrialModel:
    """Explicit transition model; actual SendTrial was tested separately."""
    def __init__(self):
        self.claimed_original = self.session_original = None
        self.claim_count = 0
        self.rows = []
        self.fail_claim = self.fail_attach = False

    @staticmethod
    def claim(gate, state, operation):
        gate.rows.append(('claim', state, operation))
        if gate.fail_claim:
            raise InjectedFailure('claim_model')
        gate.claimed_original = operation
        gate.claim_count += 1
        return operation

    @staticmethod
    def attach_session(gate, state, operation, session):
        gate.rows.append(('attach', state, operation, session))
        if gate.fail_attach:
            raise InjectedFailure('attach_model')
        gate.session_original = session
        return session

    @staticmethod
    def revoke(gate, state, reason):
        gate.rows.append(('revoke', state, reason))
        return True


class Fixture:
    def __init__(self):
        self.session_module = types.ModuleType('HOST_actual_unstarted_session78')
        exec(compile(source(SESSION, SESSION_PIN), SESSION, 'exec'), self.session_module.__dict__)
        self.namespace = dict(threading=threading, time=time,
            TransferSession=self.session_module.TransferSession,
            send_trial=types.SimpleNamespace(FixedSendTrial=TrialModel))
        tree = ast.parse(source(STATE, STATE_PIN))
        operation = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Operation')
        state = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'State')
        selected = [node for node in state.body if isinstance(node, ast.FunctionDef) and node.name in METHODS]
        if set(node.name for node in selected) != set(METHODS) or len(selected) != len(METHODS):
            raise ValueError('selected_methods_changed')
        body = [operation, ast.ClassDef(name='State', bases=[ast.Name(id='object', ctx=ast.Load())],
            keywords=[], body=selected, decorator_list=[])]
        unit = ast.fix_missing_locations(ast.Module(body=body, type_ignores=[]))
        exec(compile(unit, STATE, 'exec'), self.namespace)
        self.State, self.Operation = self.namespace['State'], self.namespace['Operation']
        self.state = self.State()
        s = self.state
        s.session = s.operation = s.worker = None
        s.history = []
        s.native_epoch = 0
        s._service_until_original = time.monotonic() + 30.0
        s._send_trial = TrialModel()
        s._probes_closed = lambda: True  # Model, not an actual capability actor.
        self.callbacks = []

        def forbidden(*args):
            self.callbacks.append(args)
            raise AssertionError('HOST_callbacks_must_not_run')
        s._run_operation = s._restore_owner = s._close_extra = forbidden

    def new(self):
        return self.state._new_operation_locked('go_send')

    def threads_unstarted(self, session):
        threads = [session._worker] + [row['thread'] for row in session._attempts]
        return all(type(value) is threading.Thread and value.ident is None and not value.is_alive()
                   for value in threads)

    def resolved_before_go_model(self, session):
        # Only exercise the passive predicate. No actual Session.close/start.
        session._worker_start_resolved = True
        session._worker_skipped = True

    def terminal_dependency_model(self, op):
        """Explicit original-proof models; not actual terminal/native owners."""
        s = self.state
        s.probe_actors = []
        s.bluez_path = 'HOST_MODEL_HELPER_NOT_EXECUTED'
        before_actor, current_actor = {}, {}
        caps = {'HOST_MODEL_CAPS': True}
        radio = dict(before_actor=before_actor, current_actor=current_actor,
            before=caps, current=caps, call_returned=True, error=None)
        s.radio_restore_probes = [radio]
        s._bluetooth_probe_actor_original = before_actor
        s._bluetooth_caps_original = caps
        op.go_radio_probe_original = radio
        op.go_radio_verified = op.go_helper_closed = True
        parent = types.SimpleNamespace(rows=[])
        process = dict(pipes=[])
        preflight = (object(), parent, types.SimpleNamespace(
            snapshot=types.SimpleNamespace(stable_key=('HOST_MODEL_KEY',), key_sha='HOST_MODEL_SHA')),
            object(), object(), process, object())
        terminal_parent = types.SimpleNamespace(write_ticket={}, input_close_ticket=(), input_row={})
        data = types.SimpleNamespace(snapshot=preflight[2].snapshot,
            stable_key_sha256=preflight[2].snapshot.key_sha, finish_data=())

        class ConsumptionModel:
            pass
        consumed = ConsumptionModel()
        consumed.state, consumed.operation = s, op
        consumed.bridge, consumed.parent = object(), terminal_parent
        consumed.terminal = data
        consumed.finish = types.SimpleNamespace(data=())
        op.send_bridge, op.go_terminal_parent = consumed.bridge, terminal_parent
        op.go_terminal_result = data
        op.go_terminal_facts, op.go_network_refs = (), ()
        # Deliberate HOST worker-identity model for the same-worker method.
        # It does not start or replace the actual Session78 thread in any run.
        op.session = types.SimpleNamespace(_worker=threading.current_thread())
        op.go_worker = op.session._worker
        s._go_network_source_current = lambda: True
        s._go_private_definitions_current = lambda *unused: True
        s._go_pub_preflight_current = lambda unused: preflight
        s._go_network_closed_current = s._go_terminal_closed = lambda unused: True
        self.namespace['_probe_result'] = lambda *unused: True
        self.namespace['_GO_CONSUMER_DEFINITIONS'] = (None, None, lambda *unused: consumed, ConsumptionModel)
        self.namespace['radio_baseline'] = types.SimpleNamespace(
            matches=lambda *unused: True, normalize=lambda value: tuple(sorted(value.items())))
        return consumed


class StateConstructorTests(unittest.TestCase):
    def test_new_constructor_retention_contracts(self):
        cases = []

        def case(name, callback):
            with self.subTest(contract=name):
                callback()
            cases.append(name)
            print('HOST_SEND_STATE_CONSTRUCTOR_CASE=' + name)

        def positive():
            f = Fixture(); op = f.new(); s = f.state
            self.assertIs(type(op), f.Operation)
            self.assertIs(op, s.operation)
            self.assertEqual((op.kind, op.epoch, s.native_epoch), ('go_send', 1, 1))
            self.assertIs(op.session, s.session)
            self.assertIs(op.session._lease_owner, op)
            self.assertIs(op.session.cancelled, op.cancelled)
            self.assertEqual(op.session._direction, 'send')
            self.assertEqual(op.session._absolute_until_original, s._service_until_original)
            self.assertIs(s.worker, op.session._worker)
            self.assertIs(op.go_session_ctor_ticket['partial'], op.session)
            self.assertTrue(op.go_session_ctor_ticket['returned'])
            self.assertFalse(op.go_session_ctor_ticket['unknown'])
            self.assertIsNone(op.go_session_ctor_ticket['error'])
            self.assertEqual([row[0] for row in s._send_trial.rows], ['claim', 'attach'])
            self.assertTrue(f.threads_unstarted(op.session))
            self.assertEqual(f.callbacks, [])
        case('actual_operation_session_and_original_cap', positive)

        def partial_failure():
            f = Fixture(); original = f.session_module.TransferSession.__init__
            error = InjectedFailure('after_actual_constructor')

            def fail(value, *args, **kwargs):
                original(value, *args, **kwargs)
                raise error
            with patch.object(f.session_module.TransferSession, '__init__', fail):
                with self.assertRaises(InjectedFailure) as caught:
                    f.new()
            op, s = f.state.operation, f.state
            self.assertIs(caught.exception, error)
            self.assertIs(op.go_session_ctor_ticket['error'], error)
            self.assertIs(op.go_session_ctor_ticket['partial'], op.session)
            self.assertIs(op.session, s.session)
            self.assertTrue(op.go_session_ctor_ticket['unknown'])
            self.assertFalse(op.go_session_ctor_ticket['returned'])
            self.assertTrue(op.actor_unknown)
            self.assertTrue(op.cancelled.is_set())
            self.assertIsNone(s.worker)
            self.assertTrue(f.threads_unstarted(op.session))
            self.assertIsNone(s._send_trial.session_original)
            self.assertEqual([row[0] for row in s._send_trial.rows], ['claim', 'revoke'])
            self.assertFalse(s._go_zero_closed(op))
            self.assertEqual(f.callbacks, [])
        case('partial_constructor_object_threads_and_error_retained', partial_failure)

        def allocation_failure():
            f = Fixture(); error = InjectedFailure('allocation_model')

            class ObjectAllocationModel:
                @staticmethod
                def __new__(creator):
                    raise error
            f.namespace['object'] = ObjectAllocationModel
            with self.assertRaises(InjectedFailure) as caught:
                f.new()
            s, op = f.state, f.state.operation
            self.assertIs(caught.exception, error)
            self.assertIs(op.go_session_ctor_ticket['error'], error)
            self.assertIsNone(op.go_session_ctor_ticket['partial'])
            self.assertIsNone(op.session)
            self.assertIsNone(s.session)
            self.assertTrue(op.actor_unknown)
            self.assertTrue(op.cancelled.is_set())
            self.assertEqual([row[0] for row in s._send_trial.rows], ['claim', 'revoke'])
            self.assertFalse(s._go_zero_closed(op))
        case('ticket_and_operation_retained_before_allocation', allocation_failure)

        def attach_failure():
            f = Fixture(); f.state._send_trial.fail_attach = True
            with self.assertRaises(InjectedFailure): f.new()
            s, op = f.state, f.state.operation
            self.assertIs(op.session, s.session)
            self.assertIs(op.go_session_ctor_ticket['partial'], op.session)
            self.assertTrue(op.go_session_ctor_ticket['returned'])
            self.assertFalse(op.go_session_ctor_ticket['unknown'])
            self.assertTrue(op.cancelled.is_set())
            self.assertTrue(f.threads_unstarted(op.session))
            self.assertEqual([row[0] for row in s._send_trial.rows], ['claim', 'attach', 'revoke'])
            self.assertFalse(s._go_zero_closed(op))
        case('attach_failure_keeps_complete_unstarted_session', attach_failure)

        def claim_failure():
            f = Fixture(); f.state._send_trial.fail_claim = True
            with self.assertRaises(InjectedFailure): f.new()
            s, op = f.state, f.state.operation
            self.assertIs(type(op), f.Operation)
            self.assertIsNone(op.go_session_ctor_ticket)
            self.assertIsNone(op.session)
            self.assertIsNone(s.session)
            self.assertFalse(s._go_zero_closed(op))
        case('claim_failure_has_no_session_creator', claim_failure)

        def history():
            f = Fixture(); old = object()
            f.state.operation = old
            f.state.session = types.SimpleNamespace(closed=lambda: True)
            op = f.new()
            self.assertEqual(len(f.state.history), 1)
            self.assertIs(f.state.history[0], old)
            self.assertIsNot(op, old)
        case('previous_owner_history_is_not_erased', history)

        def pending():
            f = Fixture(); old = object(); session = types.SimpleNamespace(closed=lambda: False)
            f.state.operation, f.state.session = old, session
            with self.assertRaises(ValueError): f.new()
            self.assertIs(f.state.operation, old)
            self.assertIs(f.state.session, session)
            self.assertEqual(f.state.native_epoch, 0)
            self.assertEqual(f.state._send_trial.rows, [])
        case('pending_original_session_blocks_before_new_claim', pending)

        def unresolved():
            f = Fixture(); op = f.new()
            self.assertFalse(op.session._worker_start_resolved)
            self.assertFalse(f.state._go_zero_closed(op))
        case('unresolved_start_is_not_zero_creator_closure', unresolved)

        def zero():
            f = Fixture(); op = f.new(); f.resolved_before_go_model(op.session)
            self.assertTrue(f.state._go_zero_closed(op))
            self.assertFalse(op.go_child_called)
            self.assertFalse(op.go_native_restore_verified)
            self.assertIsNone(op.go_restoration_consumption)
            self.assertTrue(f.threads_unstarted(op.session))
        case('resolved_pre_go_model_only_local_inventory', zero)

        def unknown_ticket():
            f = Fixture(); op = f.new(); f.resolved_before_go_model(op.session)
            op.go_session_ctor_ticket['unknown'] = True
            self.assertFalse(f.state._go_zero_closed(op))
        case('unknown_constructor_ticket_refuses_local_closure', unknown_ticket)

        def changed_partial():
            f = Fixture(); op = f.new(); f.resolved_before_go_model(op.session)
            op.go_session_ctor_ticket['partial'] = object()
            self.assertFalse(f.state._go_zero_closed(op))
        case('changed_partial_reference_refuses_local_closure', changed_partial)

        def changed_operation():
            f = Fixture(); op = f.new(); f.resolved_before_go_model(op.session)
            f.state._send_trial.claimed_original = object()
            self.assertFalse(f.state._go_zero_closed(op))
        case('foreign_claim_reference_refuses_local_closure', changed_operation)

        def deadline_failure():
            f = Fixture(); op = f.new(); f.terminal_dependency_model(op)
            op.go_cleanup_until = time.monotonic() - 1.0
            with self.assertRaisesRegex(ValueError, 'send_terminal_original_cleanup_expired') as caught:
                f.state._verify_go_terminal_restoration(op)
            self.assertEqual(len(op.go_restoration_refs), 28)
            self.assertIsNotNone(op.go_restoration_consumption)
            self.assertIsNone(op.go_restoration_completion)
            # Mirror the original caller's failure retention; do not clear refs.
            original_refs = op.go_restoration_refs
            op.go_restoration_error = caught.exception
            op.go_cleanup_unknown = True
            self.assertFalse(f.state._go_restoration_current(op))
            self.assertIs(op.go_restoration_refs, original_refs)
            self.assertIs(op.go_restoration_error, caught.exception)
        case('actual_final_deadline_failure_keeps_refs_without_success', deadline_failure)

        def terminal_return():
            f = Fixture(); op = f.new(); f.terminal_dependency_model(op)
            op.go_cleanup_until = time.monotonic() + 5.0
            self.assertTrue(f.state._verify_go_terminal_restoration(op))
            self.assertEqual(len(op.go_restoration_refs), 28)
            self.assertIs(op.go_restoration_completion[3], op.go_restoration_refs)
            self.assertTrue(f.state._go_restoration_current(op))
            self.assertFalse(op.go_native_restore_verified)
        case('completion_issued_only_after_actual_deadline_check', terminal_return)

        def retained_failure():
            f = Fixture(); op = f.new(); f.terminal_dependency_model(op)
            op.go_cleanup_until = time.monotonic() + 5.0
            self.assertTrue(f.state._verify_go_terminal_restoration(op))
            original_refs = op.go_restoration_refs
            op.go_restoration_error = InjectedFailure('retained_failure_model')
            self.assertFalse(f.state._go_restoration_current(op))
            self.assertIs(op.go_restoration_refs, original_refs)
            other = Fixture(); other_op = other.new(); other.terminal_dependency_model(other_op)
            other_op.go_cleanup_until = time.monotonic() + 5.0
            self.assertTrue(other.state._verify_go_terminal_restoration(other_op))
            other_op.go_cleanup_unknown = True
            self.assertFalse(other.state._go_restoration_current(other_op))
        case('retained_failure_or_unknown_refuses_even_with_completion', retained_failure)

        def changed_completion():
            f = Fixture(); op = f.new(); f.terminal_dependency_model(op)
            op.go_cleanup_until = time.monotonic() + 5.0
            self.assertTrue(f.state._verify_go_terminal_restoration(op))
            original = op.go_restoration_completion
            op.go_restoration_completion = (original[0], original[1], object(), original[3])
            self.assertFalse(f.state._go_restoration_current(op))
        case('foreign_completion_worker_refuses_passive_status', changed_completion)
        print('FORMAL_SEND_STATE_CONSTRUCTOR_CONTRACTS=' + str(len(cases)))


if __name__ == '__main__':
    unittest.main()
