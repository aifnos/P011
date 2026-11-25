"""One new focused HOST method for the actual V3 UI policy/guard wiring.

Only two pinned pure UI helper definitions are extracted; the entire run_fixed
function is inspected as AST, never executed. Owner, Gate, thread liveness and
runner inventory below are explicit in-memory HOST control models, not source
authentication, RF, original FD/resource closure, phone or P011 evidence. No
production constructor, Qt application, HTTP action or old test is invoked.
The ROOT-sealed runner pin is outside the helper AST pins so sealing the final
immutable graph cannot silently alter these tested helper definitions.
"""
import ast
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/formal-receive-v3/runtime/ui_session.py'
HELPER_PINS = {
    '_receive_ui_display_allowed': '74289ea091e096dada2cb61461d08bb2263af1b57333077f6029fd0f73c1d7c8',
    '_copy_receive_ui_trial': 'edd5a55e39aef274d63ca9e150c15f5962352d4e0e42eb876a5487125fc3e555',
}


class GateScopeModel(object):
    """An observation data model, never an actual receive qualification."""
    def __init__(self, state):
        self.state = state
        self.calls = 0
        self.observed = {'requested': True, 'available': True, 'claimed': False,
            'claim_count': 0, 'session_attached': False, 'revoked': False,
            'expired': False, 'reason': 'ready', 'startup_verified': True,
            'probe_verified': True, 'radio_known': True, 'barrier_clear': True,
            'network_spec_verified': True, 'restoration_verified': False,
            'phone_verified': False}

    def public_facts(self):
        self.calls += 1
        return dict(self.observed)


class ThreadLivenessModel(object):
    def __init__(self, value=True):
        self.value = value
        self.calls = 0

    def is_alive(self):
        self.calls += 1
        return self.value


class InventoryModel(object):
    """Returns explicit control data; cannot certify original resource state."""
    def __init__(self, idle=True, alive=True):
        self.idle = idle
        self.idle_calls = 0
        self.owner = types.SimpleNamespace(thread=ThreadLivenessModel(alive))

    def original_receive_ui_idle(self):
        self.idle_calls += 1
        return self.idle


def fresh_facts():
    return dict(radio_admission=False, receive_trial_policy_requested=True,
        auto_receive_action_issued=False, receive_trial_initial_observed=False,
        receive_trial_initial_available=False, receive_trial_initial_reason='not_started',
        receive_trial_claimed=False, receive_trial_claim_count=0,
        receive_trial_session_attached=False, receive_trial_terminal_observed=False,
        receive_trial_terminal_revoked=False, receive_trial_terminal_reason='not_started')


def model_component():
    module = types.ModuleType('private_ui_gate_scope_model')
    module.FixedReceiveTrial = GateScopeModel
    module.REASONS = frozenset(('ready', 'claimed', 'pending_exists', 'owner_closed', 'cancelled'))
    state = object()
    gate = GateScopeModel(state)
    owner = types.SimpleNamespace(receive_trial=gate, _receive_trial_original=gate,
                                  state=state, _state_original=state)
    loader = types.SimpleNamespace(modules={'mta_receive_trial': module})
    return types.SimpleNamespace(owner=owner, loader=loader), gate


class ReceiveUiPolicyTests(unittest.TestCase):
    def test_receive_ui_fixed_policy_and_original_guard(self):
        raw = SOURCE.read_bytes()
        tree = ast.parse(raw, str(SOURCE))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertTrue(set(HELPER_PINS) <= set(functions))
        for name, pin in HELPER_PINS.items():
            self.assertEqual(hashlib.sha256(ast.dump(functions[name], include_attributes=False).encode('utf-8')).hexdigest(), pin)
        selected = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'UiSessionError' or
                    isinstance(node, ast.FunctionDef) and node.name in set(HELPER_PINS) | {'need'} or
                    isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'TRIAL_BOOL_FIELDS' for target in node.targets)]
        realm = {'types': types, '__name__': 'private_ui_policy_helpers'}
        helper_tree = ast.Module(body=selected, type_ignores=[])
        exec(compile(ast.fix_missing_locations(helper_tree), '<new-ui-policy-helpers>', 'exec'), realm)
        guard, project = realm['_receive_ui_display_allowed'], realm['_copy_receive_ui_trial']
        ui_error = realm['UiSessionError']
        domains = 0
        with mock.patch.object(os, 'open', side_effect=AssertionError('HOST scope opened an OS descriptor')), \
             mock.patch.object(socket, 'socket', side_effect=AssertionError('HOST scope opened a socket')), \
             mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('HOST scope spawned a process')), \
             mock.patch.object(threading.Thread, 'start', side_effect=AssertionError('HOST scope started a thread')), \
             mock.patch.object(time, 'monotonic', side_effect=AssertionError('HOST model requested a new deadline')):
            with self.subTest(domain='fixed_entry_ast'):
                run = functions['run_fixed']
                constructors = [node for node in ast.walk(run) if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and
                    node.func.value.id == 'runner' and node.func.attr == 'FixedSession']
                self.assertEqual(len(constructors), 1)
                call = constructors[0]
                self.assertEqual(len(call.args), 2)
                self.assertEqual(ast.dump(call.args[0]), "Name(id='artifacts', ctx=Load())")
                self.assertIsInstance(call.args[1], ast.Constant)
                self.assertIs(call.args[1].value, False)
                self.assertEqual([(row.arg, row.value.value) for row in call.keywords], [('receive_trial_requested', True)])
                calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)]
                self.assertFalse(any(isinstance(node.func, ast.Attribute) and node.func.attr in
                    ('action', 'start_receive', 'smoke', 'request', 'idle') for node in calls))
                self.assertFalse(any(isinstance(node, ast.Constant) and node.value in
                    ('discover_start', 'scan', 'send', 'send_prepare') for node in ast.walk(run)))
                self.assertEqual(sum(isinstance(node.func, ast.Name) and node.func.id == '_receive_ui_display_allowed' for node in calls), 1)
                self.assertEqual(sum(isinstance(node.func, ast.Attribute) and node.func.attr == 'original_receive_ui_idle' for node in calls), 1)
                copy_calls = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == '_copy_receive_ui_trial']
                self.assertEqual(len(copy_calls), 3)
                self.assertEqual(sorted(tuple((row.arg, row.value.value) for row in node.keywords) for node in copy_calls), [(), (('initial', True),), (('terminal', True),)])
                assignments = [node for node in ast.walk(run) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'update' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'facts']
                fixed = next(node for node in assignments if any(row.arg == 'auto_receive_action_issued' for row in node.keywords))
                self.assertIs(next(row.value.value for row in fixed.keywords if row.arg == 'auto_receive_action_issued'), False)
                self.assertIs(next(row.value.value for row in fixed.keywords if row.arg == 'receive_trial_policy_requested'), True)
                domains += 1
            with self.subTest(domain='ready_refusal_inventory_skips_monitor'):
                for initial_reason in ('ready', 'pending_exists'):
                    component = InventoryModel(idle=True)
                    monitor_calls = []
                    self.assertIs(guard(component, lambda value: monitor_calls.append(value)), True)
                    self.assertEqual(monitor_calls, [])
                    self.assertEqual(component.idle_calls, 1)
                    self.assertEqual(component.owner.thread.calls, 1)
                domains += 1
            with self.subTest(domain='actual_guard_requires_owned_monitor_or_empty_and_live_thread'):
                for idle, monitored, alive, expected in ((False, True, True, True),
                        (False, False, True, False), (False, True, False, False),
                        (True, False, False, False), (1, 1, True, False),
                        (False, True, 1, False)):
                    component = InventoryModel(idle=idle, alive=alive)
                    seen = []
                    def monitor(value):
                        seen.append(value)
                        return monitored
                    self.assertIs(guard(component, monitor), expected)
                    self.assertEqual(len(seen), 0 if idle is True else 1)
                    if seen:
                        self.assertIs(seen[0], component)
                domains += 1
            with self.subTest(domain='ready_claim_close_projection_does_not_fake_rf_restore'):
                component, gate = model_component()
                facts = fresh_facts()
                self.assertEqual(project(component, facts, initial=True), gate.observed)
                self.assertTrue(facts['receive_trial_initial_available'])
                self.assertEqual(facts['receive_trial_initial_reason'], 'ready')
                self.assertTrue(facts['radio_admission'])
                gate.observed.update(available=False, claimed=True, claim_count=1, session_attached=True, reason='claimed')
                project(component, facts)
                self.assertTrue(facts['receive_trial_claimed'])
                self.assertEqual(facts['receive_trial_claim_count'], 1)
                gate.observed.update(revoked=True, reason='owner_closed')
                observed = project(component, facts, terminal=True)
                self.assertTrue(facts['receive_trial_terminal_observed'])
                self.assertTrue(facts['receive_trial_terminal_revoked'])
                self.assertEqual(facts['receive_trial_terminal_reason'], 'owner_closed')
                self.assertTrue(facts['radio_admission'])
                self.assertFalse(observed['restoration_verified'])
                self.assertFalse(observed['phone_verified'])
                self.assertFalse(facts['auto_receive_action_issued'])
                self.assertEqual(gate.calls, 3)
                domains += 1
            with self.subTest(domain='refusal_projection_never_qualifies'):
                component, gate = model_component()
                gate.observed.update(available=False, reason='pending_exists', barrier_clear=False)
                facts = fresh_facts()
                project(component, facts, initial=True)
                gate.observed.update(revoked=True, reason='owner_closed')
                project(component, facts, terminal=True)
                self.assertFalse(facts['radio_admission'])
                self.assertEqual(facts['receive_trial_initial_reason'], 'pending_exists')
                self.assertEqual(facts['receive_trial_claim_count'], 0)
                self.assertFalse(facts['receive_trial_session_attached'])
                self.assertTrue(facts['receive_trial_terminal_revoked'])
                domains += 1
            with self.subTest(domain='foreign_malformed_and_regression_refused'):
                mutations = (
                    lambda c, g, f: setattr(c.owner, '_receive_trial_original', object()),
                    lambda c, g, f: setattr(c.owner, '_state_original', object()),
                    lambda c, g, f: setattr(g, 'state', object()),
                    lambda c, g, f: c.loader.modules.__setitem__('mta_receive_trial', object()),
                    lambda c, g, f: g.observed.__setitem__('extra', True),
                    lambda c, g, f: g.observed.__setitem__('claim_count', True),
                    lambda c, g, f: g.observed.__setitem__('claimed', 1),
                    lambda c, g, f: g.observed.__setitem__('reason', 'unrecognised'),
                    lambda c, g, f: g.observed.__setitem__('requested', False),
                    lambda c, g, f: g.observed.__setitem__('phone_verified', True),
                    lambda c, g, f: g.observed.__setitem__('restoration_verified', True),
                    lambda c, g, f: f.__setitem__('receive_trial_claim_count', 1),
                    lambda c, g, f: f.__setitem__('receive_trial_session_attached', True),
                )
                for mutate in mutations:
                    component, gate = model_component()
                    facts = fresh_facts()
                    mutate(component, gate, facts)
                    with self.assertRaises(ui_error):
                        project(component, facts)
                component, gate = model_component()
                with self.assertRaises(ui_error):
                    project(component, fresh_facts(), initial=True, terminal=True)
                domains += 1
        self.assertEqual(domains, 6)
        print('RECEIVE_UI_POLICY_SUBDOMAINS=' + str(domains))


if __name__ == '__main__':
    unittest.main()
