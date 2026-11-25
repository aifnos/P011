"""New HOST-only contract for the actual V3 original empty UI inventory.

The runner method is extracted without running the Linux FixedSession. State,
Gate binding and Owner are explicit models; no FD, Qt, RF or phone is tested.
This tests the separation between inventory idle and closed-policy admission,
not the original Gate's source authentication or actual receive restoration.
"""
import ast
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/formal-receive-v3/runtime/mta_formal_receive_session.py'


def original_methods():
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'), feature_version=(3, 5))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'FixedSession')
    methods = [node for node in cls.body if isinstance(node, ast.FunctionDef) and
               node.name in ('idle', 'original_receive_ui_idle')]
    if len(methods) != 2:
        raise AssertionError('two actual methods required')
    subset = ast.Module(body=[ast.ClassDef(name='ActualRunnerMethods', bases=[], keywords=[],
        body=methods, decorator_list=[])], type_ignores=[])
    scope = dict(types=types, sys=sys)
    exec(compile(ast.fix_missing_locations(subset), str(SOURCE), 'exec'), scope)
    return scope['ActualRunnerMethods'], cls


class UiInventoryTest(unittest.TestCase):
    def test_new_original_receive_ui_inventory(self):
        runner_type, original_class = original_methods()
        completed = 0

        def fixture(ready):
            service = types.ModuleType('mta_service')
            gate_module = types.ModuleType('mta_receive_trial')
            # Binding is a model here. The actual Gate is separately tested.
            class StateModel(object):
                def _receive_trial_exact(self):
                    return self.fixture_binding
                def _receive_trial_available(self):
                    return self.fixture_ready
            class GateModel(object):
                pass
            service.State = StateModel
            gate_module.FixedReceiveTrial = GateModel
            state, gate = StateModel(), GateModel()
            state.fixture_binding, state.fixture_ready = True, ready
            state.lock = threading.RLock()
            state.state, state.closing = 'idle', False
            state.receive_available = state.send_available = state.scan_available = False
            state.discoverable = state.scanning = False
            state.wifi_restore_pending = state.radio_restore_pending = False
            for name in ('operation', 'session', 'helper', 'key', 'crypto', 'lease', 'transport', 'worker'):
                setattr(state, name, None)
            gate.requested, gate.revoked, gate.expired = True, False, False
            gate.failure = None
            gate.claim_count = 0
            gate.claimed_operation = gate._claimed_operation_original = None
            gate.session = gate._session_original = None
            state._receive_trial_original = gate
            owner = types.SimpleNamespace(state=state, _state_original=state,
                service=service, receive_trial=gate, _receive_trial_original=gate,
                receive_trial_requested=True, _receive_trial_requested_original=True,
                start_complete=True, stop_called=False, close_called=False)
            runner = runner_type()
            runner.owner = owner
            runner.loader = types.SimpleNamespace(modules={'mta_service': service,
                'mta_receive_trial': gate_module})
            runner.receive_trial_requested = runner._receive_trial_requested_original = True
            return runner, state, gate, owner, service, gate_module

        def run_case(name, change=None, ready=True, expect=True, closed=False):
            nonlocal completed
            with self.subTest(name=name):
                runner, state, gate, owner, service, gate_module = fixture(ready)
                with mock.patch.dict(sys.modules, {'mta_service': service, 'mta_receive_trial': gate_module}):
                    if change is not None:
                        change(runner, state, gate, owner)
                    self.assertIs(runner.original_receive_ui_idle(), expect)
                    if expect:
                        self.assertIs(runner.idle(), closed)
                    self.assertIsNone(state.operation)
                    self.assertIsNone(state.session)
                completed += 1

        run_case('ready gate is empty but not closed')
        run_case('real refusal can remain visible', ready=False, closed=True)
        changes = (
            ('request not explicit', lambda r,s,g,o: setattr(r, 'receive_trial_requested', False)),
            ('owner request changed', lambda r,s,g,o: setattr(o, 'receive_trial_requested', False)),
            ('owner stopped', lambda r,s,g,o: setattr(o, 'stop_called', True)),
            ('owner closed', lambda r,s,g,o: setattr(o, 'close_called', True)),
            ('owner not started', lambda r,s,g,o: setattr(o, 'start_complete', False)),
            ('binding unknown', lambda r,s,g,o: setattr(s, 'fixture_binding', False)),
            ('claim consumed', lambda r,s,g,o: setattr(g, 'claim_count', 1)),
            ('malformed count', lambda r,s,g,o: setattr(g, 'claim_count', False)),
            ('revoked', lambda r,s,g,o: setattr(g, 'revoked', True)),
            ('expired', lambda r,s,g,o: setattr(g, 'expired', True)),
            ('construction unknown', lambda r,s,g,o: setattr(g, 'failure', RuntimeError('fixture'))),
            ('radio pending', lambda r,s,g,o: setattr(s, 'radio_restore_pending', True)),
            ('wifi pending', lambda r,s,g,o: setattr(s, 'wifi_restore_pending', True)),
            ('foreign helper', lambda r,s,g,o: setattr(s, 'helper', object())),
            ('scanning', lambda r,s,g,o: setattr(s, 'scanning', True)),
            ('advertising', lambda r,s,g,o: setattr(s, 'discoverable', True)),
            ('foreign gate', lambda r,s,g,o: setattr(o, 'receive_trial', object())),
            ('foreign state', lambda r,s,g,o: setattr(o, '_state_original', object())),
        )
        for name, change in changes:
            run_case(name, change=change, expect=False)
        with self.subTest(name='load_owner does not mislabel an open gate'):
            method = next(node for node in original_class.body if isinstance(node, ast.FunctionDef)
                          and node.name == 'load_owner')
            text = ast.unparse(method)
            self.assertIn('self.original_receive_ui_idle()', text)
            assignments = [node for node in ast.walk(method) if isinstance(node, ast.Assign) and
                any(isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute)
                    and target.value.attr == 'result' and isinstance(target.slice, ast.Constant)
                    and target.slice.value == 'gates_remained_closed' for target in node.targets)]
            self.assertEqual(len(assignments), 1)
            self.assertEqual(ast.unparse(assignments[0].value), 'self.idle()')
            completed += 1
        self.assertEqual(completed, 21)
        print('RECEIVE_UI_INVENTORY_CONTRACTS=' + str(completed), flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
