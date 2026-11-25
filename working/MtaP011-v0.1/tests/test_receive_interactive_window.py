"""One new HOST method for the fixed original receive-window contract.

Actual new runner constructor/window/check and new UI pure guards are extracted.
Clock and Owner/Loader/Gate/State/Directory are explicit HOST models. No full
platform module graph, resource closure, Qt, radio or phone is executed.
"""
import ast
import hashlib
import math
import os
from pathlib import Path
import sys
import threading
import types
import unittest


BASE = Path(__file__).resolve().parents[1]
RUNNER = 'candidate/receive-interactive-v1/runtime/mta_formal_receive_session.py'
UI = 'candidate/receive-interactive-v1/runtime/ui_session.py'
V3_UI = 'candidate/formal-receive-v3/runtime/ui_session.py'
OWNER = 'candidate/formal-receive-v3/runtime/mta_client_service_owner.py'
STATE = 'candidate/formal-receive-v3/runtime/mta_service.py'
FACTORY = 'candidate/formal-receive-v3/runtime/mta_client_receive_factory.py'
SESSION = 'candidate/go-send-state-v78/runtime/mta_transfer_session.py'


def parse(name):
    return ast.parse((BASE / name).read_text(encoding='utf-8'), feature_version=(3, 5))


def named(tree, name, kind=ast.FunctionDef):
    return next(node for node in tree.body if isinstance(node, kind) and node.name == name)


def constants(tree, wanted):
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    result[target.id] = ast.literal_eval(node.value)
    if set(result) != set(wanted):
        raise AssertionError('actual fixed constants missing')
    return result


def actual_logic(clock):
    runner, ui = parse(RUNNER), parse(UI)
    cls = named(runner, 'FixedSession', ast.ClassDef)
    method_names = ('__init__', 'window_current', 'check')
    methods = [named(cls, name) for name in method_names]
    actual_class = ast.ClassDef(name='ActualRunner', bases=[], keywords=[], body=methods, decorator_list=[])
    scope = dict(os=os, threading=threading, time=clock)
    scope.update(constants(runner, ('BOOL_FIELDS', 'COUNT_FIELDS')))
    subset = [named(runner, 'ClosedServiceError', ast.ClassDef), named(runner, 'fail'), actual_class]
    exec(compile(ast.fix_missing_locations(ast.Module(body=subset, type_ignores=[])), RUNNER, 'exec'), scope)
    guards = ('_receive_interactive_window', '_receive_interactive_originals', '_receive_interactive_expired')
    ui_scope = dict(math=math)
    ui_scope.update(constants(ui, ('INTERACTIVE_PROFILE', 'INTERACTIVE_SECONDS', 'EXIT_MARGIN_SECONDS')))
    subset = [named(ui, 'UiSessionError', ast.ClassDef), named(ui, 'need')] + [named(ui, name) for name in guards]
    exec(compile(ast.fix_missing_locations(ast.Module(body=subset, type_ignores=[])), UI, 'exec'), ui_scope)
    hashes = {}
    for prefix, source_nodes in (('runner.', methods), ('ui.', [named(ui, name) for name in guards])):
        for node in source_nodes:
            hashes[prefix + node.name] = hashlib.sha256(ast.dump(node, include_attributes=False).encode('utf-8')).hexdigest()
    return scope, ui_scope, runner, ui, hashes


class ReceiveInteractiveWindowTest(unittest.TestCase):
    def test_new_fixed_original_receive_window(self):
        clock = types.SimpleNamespace(value=100.0, calls=0)
        def tick():
            clock.calls += 1
            return clock.value
        clock.monotonic = tick
        scope, guards, runner_tree, ui_tree, hashes = actual_logic(clock)
        runner_type, runner_error = scope['ActualRunner'], scope['ClosedServiceError']
        ui_error = guards['UiSessionError']
        open_window = guards['_receive_interactive_window']
        bound = guards['_receive_interactive_originals']
        expired = guards['_receive_interactive_expired']
        domains = 0

        def new():
            clock.value = 100.0
            value = runner_type((), False, receive_trial_requested=True, profile='receive-interactive-v1')
            self.assertIs(value.window_current(), True)
            return value

        def bind_models(value):
            cap = value.until
            gate = types.SimpleNamespace(until=cap, _until_original=cap)
            state = types.SimpleNamespace(_original_service_until=cap, _service_until_original=cap)
            directory = types.SimpleNamespace(absolute_until=cap)
            owner = types.SimpleNamespace(until=cap, original_until=cap, state=state, _state_original=state,
                receive_trial=gate, _receive_trial_original=gate, received_directory=directory,
                _received_directory_original=directory)
            value.loader = types.SimpleNamespace(_original_until=cap)
            value.owner = owner
            return owner, state, gate, directory

        with self.subTest(domain='single constructor period'):
            before = clock.calls
            value = new()
            self.assertEqual(clock.calls - before, 1)
            self.assertEqual((value.window_started_at, value.until, value.cleanup_until), (100.0, 700.0, 760.0))
            self.assertIs(value._window_original, value._window_retained)
            self.assertIs(value.result['interactive_window_requested'], True)
            self.assertIsNone(value.owner)
            self.assertIsNone(value.loader)
            domains += 1

        with self.subTest(domain='diagnostic remains sixty seconds'):
            value = runner_type((), False)
            self.assertEqual(value.until - value.window_started_at, 60.0)
            self.assertEqual(value.cleanup_until - value.until, 60.0)
            self.assertIs(value.result['interactive_window_requested'], False)
            with self.assertRaises(ui_error): open_window(value)
            domains += 1

        with self.subTest(domain='fixed profile cannot be user duration or preflight'):
            for preflight, requested, profile in ((False, False, 'receive-interactive-v1'),
                    (True, True, 'receive-interactive-v1'), (False, True, 'arbitrary'), (False, True, 600)):
                with self.assertRaises(runner_error):
                    runner_type((), preflight, receive_trial_requested=requested, profile=profile)
            domains += 1

        with self.subTest(domain='component copies cannot renew original cap'):
            for name in ('window_started_at', 'until', 'cleanup_until'):
                value = new()
                replacement = float(str(getattr(value, name)))
                self.assertIsNot(replacement, getattr(value, name))
                setattr(value, name, replacement)
                self.assertIs(value.window_current(), False)
                with self.assertRaises(runner_error): value.check()
            domains += 1

        with self.subTest(domain='original period tuple cannot be replaced'):
            value = new()
            value._window_original = tuple(list(value._window_original))
            self.assertIs(value.window_current(), False)
            with self.assertRaises(ui_error): open_window(value)
            domains += 1

        with self.subTest(domain='active cap expires without renewal'):
            value = new()
            original = value.until
            clock.value = 700.0
            with self.assertRaises(runner_error) as result: value.check()
            self.assertEqual(result.exception.code, 'deadline')
            self.assertIs(value.until, original)
            domains += 1

        with self.subTest(domain='cleanup is original plus sixty only'):
            value = new()
            clock.value = 759.0
            value.check(cleanup=True)
            clock.value = 760.0
            with self.assertRaises(runner_error): value.check(cleanup=True)
            domains += 1

        with self.subTest(domain='pure guard does not call clock'):
            value = new()
            before = clock.calls
            window = open_window(value)
            self.assertEqual(clock.calls, before)
            self.assertEqual(window[5], 699.0)
            self.assertIs(bound(value, window), False)
            domains += 1

        with self.subTest(domain='original owner gate state directory cap'):
            value = new()
            window = open_window(value)
            bind_models(value)
            self.assertIs(bound(value, window), True)
            self.assertIs(expired(value, window, 150.0), False)
            self.assertIs(expired(value, window, 698.99), False)
            self.assertIs(expired(value, window, 699.0), True)
            self.assertIs(expired(value, window, 700.0), True)
            domains += 1

        with self.subTest(domain='startup spends original window'):
            value = new()
            window = open_window(value)
            bind_models(value)
            self.assertIs(expired(value, window, 690.0), False)
            self.assertIs(expired(value, window, 699.0), True)
            self.assertEqual(value.until, 700.0)  # Never READY + 600.
            domains += 1

        with self.subTest(domain='late or foreign owner binding fails closed'):
            replacements = (('owner', 'until'), ('owner', 'original_until'), ('loader', '_original_until'),
                ('state', '_original_service_until'), ('state', '_service_until_original'),
                ('gate', 'until'), ('gate', '_until_original'), ('directory', 'absolute_until'))
            for who, name in replacements:
                value = new()
                window = open_window(value)
                owner, state, gate, directory = bind_models(value)
                target = dict(owner=owner, loader=value.loader, state=state, gate=gate, directory=directory)[who]
                setattr(target, name, float(str(value.until)))
                self.assertIs(bound(value, window), False)
                with self.assertRaises(ui_error): expired(value, window, 150.0)
            domains += 1

        with self.subTest(domain='window original references retained'):
            for name in ('until', 'cleanup_until', 'window_started_at'):
                value = new()
                window = open_window(value)
                bind_models(value)
                setattr(value, name, float(str(getattr(value, name))))
                with self.assertRaises(ui_error): expired(value, window, 150.0)
            domains += 1

        with self.subTest(domain='invalid clock cannot authorize time'):
            value = new()
            window = open_window(value)
            bind_models(value)
            for now in (True, 150, float('nan'), float('inf'), 99.0):
                with self.assertRaises(ui_error): expired(value, window, now)
            domains += 1

        with self.subTest(domain='UI fixed profile and original expiry are wired'):
            run = named(ui_tree, 'run_fixed')
            text = ast.unparse(run)
            self.assertIn('profile=INTERACTIVE_PROFILE', text)
            self.assertIn('_receive_interactive_window(component)', text)
            self.assertIn('_receive_interactive_originals(component, window)', text)
            self.assertIn('_receive_interactive_expired(component, window, time.monotonic())', text)
            self.assertNotIn('DISPLAY_SECONDS', text)
            self.assertNotIn("component.until =", text)
            self.assertIn('component.finish_owner()', text)
            self.assertIn("facts['interactive_window_bound']", text)
            domains += 1

        with self.subTest(domain='guardian original recovery unchanged'):
            self.assertEqual(ast.dump(named(ui_tree, '_guardian'), include_attributes=False),
                             ast.dump(named(parse(V3_UI), '_guardian'), include_attributes=False))
            domains += 1

        with self.subTest(domain='task publication cleanup original maxima retained'):
            state = named(parse(STATE), 'State', ast.ClassDef)
            task_text = ast.unparse(named(state, '_new_operation_locked'))
            self.assertIn('task_timeout=300', task_text)
            self.assertIn('finalize_timeout=120', task_text)
            self.assertIn('absolute_until=self._service_until_original', task_text)
            self.assertEqual(constants(parse(FACTORY), ('PREPARE_SECONDS',))['PREPARE_SECONDS'], 120.0)
            self.assertEqual(constants(parse(OWNER), ('CLEANUP_SECONDS',))['CLEANUP_SECONDS'], 60.0)
            session = named(parse(SESSION), 'TransferSession', ast.ClassDef)
            self.assertIn('min(start + self.task_timeout, self._absolute_until)', ast.unparse(named(session, 'start')))
            domains += 1

        self.assertEqual(domains, 16)
        print('RECEIVE_INTERACTIVE_WINDOW_DOMAINS=' + str(domains), flush=True)
        print('NEW_METHODS_EXECUTED=1', flush=True)
        for name in sorted(hashes):
            print('TESTED_AST ' + name + '=' + hashes[name], flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
