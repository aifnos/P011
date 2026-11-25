"""One HOST DATA-only changed observer contract, never native/phone proof.

Actual new progress_decision and actual deadline expression are exercised.
No Owner, production graph, crypto, RF, process spawn or old suite runs.
"""
import ast
import importlib.util
from pathlib import Path
import unittest


BASE = Path(__file__).resolve().parents[1]


def load_definition(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProgressContractTest(unittest.TestCase):
    def test_actual_peer_progress_deadline_unknown_and_strict_parser(self):
        host = load_definition('host_progress_actual_entry',
            BASE / 'host/device_receive_handoff_progress_120s_v1_check.py')
        runtime = load_definition('host_progress_actual_runtime', BASE / host.RUNTIME_V2[0])
        source = ast.parse((BASE / host.RUNTIME_V2[0]).read_text(encoding='ascii'))
        observe = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                       and node.name == 'observe_window')
        loop = next(node for node in observe.body if isinstance(node, ast.While))
        peer = next(node for node in loop.body if isinstance(node, ast.If) and
                    ast.unparse(node.test) == "row['peer_activity']")
        initial = next(node for node in peer.body if isinstance(node, ast.If)
                       and ast.unparse(node.test) == 'peer_at is None')
        bound = next(node.value for node in initial.body if isinstance(node, ast.Assign)
                     and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'until')
        expression = compile(ast.Expression(body=bound), '<actual-progress-bound>', 'eval')
        def deadline(until, peer_at):
            return eval(expression, {'HANDSHAKE_SECONDS': runtime.HANDSHAKE_SECONDS},
                        {'until': until, 'peer_at': peer_at})
        self.assertEqual(runtime.PHONE_SECONDS, 120.0)
        self.assertEqual(runtime.PREPARE_SECONDS, 15.0)
        self.assertEqual(runtime.HANDSHAKE_SECONDS, 15.0)
        self.assertEqual(deadline(120.0, 5.0), 20.0)
        self.assertEqual(deadline(120.0, 119.0), 120.0)  # Late peer cannot renew.
        self.assertEqual(deadline(15.0, 3.0), 15.0)  # Before READY stays capped.
        self.assertFalse(any(isinstance(node, ast.Break) for node in initial.body))
        self.assertFalse(any(isinstance(node, ast.Break) for node in peer.body))
        checks = [node for node in peer.body if isinstance(node, ast.If)
                  and any(isinstance(child, ast.Break) for child in node.body)]
        self.assertEqual(len(checks), 1)
        self.assertEqual(ast.unparse(checks[0].test), 'decision is not None')
        row = dict((name, False) for name in host.OBS_BOOL + host.PROGRESS_BOOL)
        row.update(worker_alive=True, handoff_received=True, peer_activity=True,
                   f_process_retained=False, stage='connecting', state='connecting',
                   event_counts=(1, 1, 1, 0, 0, 0), elapsed_seconds=25.0)
        self.assertIsNone(runtime.progress_decision(row))
        self.assertIsNone(runtime.progress_decision(dict(row, decrypt_attempted=True)))
        unknown = dict(row, decrypt_attempted=True, f_process_retained=None, progress_unknown=True)
        self.assertIsNone(runtime.progress_decision(unknown))
        self.assertEqual(runtime.progress_decision(dict(row, handoff_failed=True)), 'handoff_failed')
        self.assertEqual(runtime.progress_decision(dict(row, native_failure=True)), 'native_failure')
        # Execute the actual peer branch inside a one-iteration DATA loop so
        # its own break is preserved. No observe/native producer is called.
        peer_function = ast.FunctionDef(name='actual_peer_branch',
            args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=name) for name in
                ('row', 'flags', 'now', 'started', 'peer_at', 'until')],
                vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
            body=[ast.For(target=ast.Name(id='ordinal', ctx=ast.Store()),
                iter=ast.Tuple(elts=[ast.Constant(value=0)], ctx=ast.Load()), body=[peer], orelse=[]),
                ast.Return(value=ast.Name(id='flags', ctx=ast.Load()))], decorator_list=[])
        namespace = dict(progress_decision=runtime.progress_decision,
            HANDSHAKE_SECONDS=runtime.HANDSHAKE_SECONDS, _HANDSHAKE_WINDOW={})
        fragment = ast.fix_missing_locations(ast.Module(body=[peer_function], type_ignores=[]))
        exec(compile(fragment, '<actual-progress-peer-branch>', 'exec'), namespace)
        flags = namespace['actual_peer_branch'](dict(row, native_failure=True),
            dict(peer_activity_seen=False, native_failure_seen=False), 10.0, 0.0, None, 120.0)
        self.assertTrue(flags['peer_activity_seen'])
        self.assertTrue(flags['native_failure_seen'])
        self.assertEqual(runtime.progress_decision(dict(row, worker_alive=False)), 'worker_ended')
        self.assertEqual(runtime.progress_decision(dict(row, request_present=True)), 'request_seen')
        claimed = dict(row, frame_claimed=True, f_process_retained=True)
        self.assertEqual(runtime.progress_decision(claimed), 'claimed_with_f')
        component, trials = {'complete': False}, {'start': None, 'end': None}
        data = dict(scope='receive-advertise-cancel-only-v1', complete=False, reason='peer_activity_cancelled',
            flags=dict((name, name == 'peer_activity_seen') for name in host.FLAGS),
            observations=(unknown,), terminal=None, trials=trials, component=component)
        def smoke_parse(value):
            raw = ('SMOKE_RESULT=' + repr(value) + '\r\r\n').encode('ascii')
            return host.parse_smoke(raw, component, 1, trials)
        parsed = smoke_parse(data)
        self.assertIsNone(parsed['observations'][0]['f_process_retained'])
        self.assertTrue(parsed['observations'][0]['progress_unknown'])
        for changed in (dict(unknown, f_process_retained=False),
                        dict(unknown, progress_unknown=False),
                        dict(unknown, frame_claimed=1),
                        dict(unknown, f_process_retained='unknown')):
            with self.assertRaises(ValueError):
                smoke_parse(dict(data, observations=(changed,)))
        diagnostic = load_definition('host_progress_actual_diagnostic', BASE / host.DIAGNOSTIC[0])
        progress = dict(peer_seen=True, phase_seconds=15.0, started_elapsed=10.0,
                        elapsed=15.01, outcome='phase_deadline')
        def progress_parse(value, observed=parsed):
            return host.parse_progress(diagnostic,
                ('HANDSHAKE_PROGRESS_RESULT=' + repr(value) + '\r\r\n').encode('ascii'), observed)
        self.assertEqual(progress_parse(progress), progress)
        for changed in (dict(progress, phase_seconds=20.0), dict(progress, elapsed=20.01),
                        dict(progress, peer_seen=1), dict(progress, outcome='claimed_with_f')):
            with self.assertRaises(ValueError):
                progress_parse(changed)
        self.assertEqual(progress_parse(dict(progress, outcome='claimed_with_f'),
            dict(parsed, observations=(claimed,)))['outcome'], 'claimed_with_f')
        # No False replaces unknown; no DATA frame or assertion grants closure.


if __name__ == '__main__':
    unittest.main(verbosity=2)
