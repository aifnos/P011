"""HOST DATA-only duration contract, not native/phone/Owner evidence.

Uses the new actual READY/smoke parser and its exact window-check AST segment.
No old capture test, production graph, device, radio or closure fixture runs.
"""
import ast
import importlib.util
from pathlib import Path
import re
import unittest


BASE = Path(__file__).resolve().parents[1]
HOST = BASE / 'host/device_receive_phone_discovery_120s_v1_check.py'


def load_definition(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def window_segment(host):
    source = ast.parse(HOST.read_text(encoding='ascii'), filename=str(HOST))
    original = next(node for node in source.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'parse_observation')
    first = next(index for index, node in enumerate(original.body) if isinstance(node, ast.Assign)
                 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'busy')
    function = ast.FunctionDef(name='actual_window_checks',
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg='raw'), ast.arg(arg='smoke')],
            vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=original.body[first:-1] + [ast.Return(value=ast.Tuple(elts=[
            ast.Name(id='busy', ctx=ast.Load()), ast.Name(id='window', ctx=ast.Load())], ctx=ast.Load()))],
        decorator_list=[])
    diagnostic = load_definition('host_120s_actual_diagnostic', BASE / host.DIAGNOSTIC[0])
    namespace = dict(diagnostic=diagnostic, re=re, parse_ready=host.parse_ready, READY_VALUE=host.READY_VALUE)
    program = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(program, str(HOST), 'exec'), namespace)
    return namespace['actual_window_checks']


class DurationContractTest(unittest.TestCase):
    def test_actual_duration_runtime_and_parser_boundaries(self):
        host = load_definition('host_120s_actual_entry', HOST)
        old = (BASE / host.OLD_RUNTIME[0]).read_bytes()
        actual = (BASE / host.RUNTIME_V2[0]).read_bytes()
        expected = old.replace(b'45-second phone discovery window', b'120-second phone discovery window').replace(
            b'PHONE_SECONDS = 45.0', b'PHONE_SECONDS = 120.0').replace(b'len(rows) < 160', b'len(rows) < 320')
        self.assertEqual(actual, expected)
        self.assertIn(b"profile='receive-interactive-v1'", actual)
        self.assertIn(b'OBSERVE_SECONDS = PREPARE_SECONDS + PHONE_SECONDS', actual)
        self.assertIn(b'PREPARE_SECONDS = 15.0', actual)
        ready = dict(host.READY_VALUE)
        self.assertEqual(host.parse_ready(repr(ready).encode('ascii')), ready)
        for mutate in (lambda row: row.update(opportunity_seconds=45.0),
                       lambda row: row.update(opportunity_seconds=120),
                       lambda row: row.update(send_allowed=True),
                       lambda row: row.update(accept_allowed=True),
                       lambda row: row.update(ready=1),
                       lambda row: row.update(extra=False)):
            value = dict(ready); mutate(value)
            with self.assertRaises(ValueError):
                host.parse_ready(repr(value).encode('ascii'))
        # These are parser inputs only: complete=False/remote1 and no terminal.
        # They do not claim native advertising, real peer input or cleanup.
        row = dict((name, False) for name in host.OBS_BOOL)
        row.update(stage='advertising', state='advertising', event_counts=(0, 0, 0, 0, 0, 0),
                   elapsed_seconds=135.0, advertising=True)
        component, trials = {'complete': False}, {'start': None, 'end': None}
        value = dict(scope='receive-advertise-cancel-only-v1', complete=False, reason='advert_not_observed',
            flags=dict((name, False) for name in host.FLAGS), observations=(row,) * 320,
            terminal=None, trials=trials, component=component)
        def smoke_parse(value):
            return host.parse_smoke(('SMOKE_RESULT=' + repr(value) + '\r\r\n').encode('ascii'),
                                    component, 1, trials)
        parsed = smoke_parse(value)
        self.assertEqual(len(parsed['observations']), 320)
        for observations in ((row,) * 321, (dict(row, elapsed_seconds=135.001),),
                             (dict(row, elapsed_seconds=True),),
                             (dict(row, worker_alive=1),),
                             (dict(row, event_counts=(False, 0, 0, 0, 0, 0)),)):
            with self.assertRaises(ValueError):
                smoke_parse(dict(value, observations=observations))
        fields = window_segment(host)
        window = dict(ready=True, completed=True, ready_elapsed=15.0,
                      opportunity_seconds=120.0, elapsed=120.0)
        def frame(window, busy=2000, ready_frame=ready):
            text = 'OBSERVATION_LOCK_BUSY_COUNT=' + repr(busy) + '\r\r\n'
            text += 'PHONE_WINDOW_RESULT=' + repr(window) + '\r\r\n'
            if ready_frame is not None:
                text += 'PHONE_DISCOVERY_READY=' + repr(ready_frame) + '\r\r\n'
            return text.encode('ascii')
        self.assertEqual(fields(frame(window), parsed), (2000, window))
        late = dict(window, completed=False, elapsed=135.0)
        self.assertEqual(fields(frame(late), parsed), (2000, late))
        for changed in (dict(window, opportunity_seconds=45.0),
                        dict(window, opportunity_seconds=120),
                        dict(window, ready_elapsed=15.001),
                        dict(window, elapsed=119.99),
                        dict(window, elapsed=135.001),
                        dict(window, elapsed=True),
                        dict(window, extra=False)):
            with self.assertRaises(ValueError):
                fields(frame(changed), parsed)
        for busy in (2001, -1, True):
            with self.assertRaises(ValueError):
                fields(frame(window, busy=busy), parsed)
        with self.assertRaises(ValueError):
            fields(frame(window, ready_frame=dict(ready, opportunity_seconds=45.0)), parsed)
        with self.assertRaises(ValueError):
            fields(frame(window, ready_frame=None), parsed)
        self.assertEqual(fields(frame(None, busy=0, ready_frame=None),
                                dict(parsed, observations=())), (0, None))


if __name__ == '__main__':
    unittest.main(verbosity=2)
