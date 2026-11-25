"""One narrow v37 native STATUS pre-dispatch rejection HOST method.

The 35 fixed modules are definitions only: no old tests/fixtures/F lifecycle
are imported or run. Actual Provider(None) pure construction and native STATUS
receive/channel/current preconditions execute. Every OS/IO operation is a
tripwire. MODEL invalid-active dictionaries are denial inputs only: they have
no native issuer/history/context/Store/Journal/FD, and grant no permission.
No valid ticket, active expiry, held-mutex continuity, recv fault, restore,
physical close, production admission, RF, device or phone is certified.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/client_integrated_v37_source_manifest.json'
PLAN_SHA = '4b9ea54997194ca895a3459cf88cd715b2ccc05e46c55b533920f8182314d07a'
PLAN_BYTES = 8077
PREVIOUS_PLAN_SHA = '2b13ba05acb3dd4984f7d2c5740349f4d90f1980ebde4014aa63f62a515f721a'


def fixed(relative, digest, size):
    raw = (BASE / relative).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('HOST fixed source changed')
    return raw


def source_inputs():
    plan = json.loads(fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    if (set(plan) != {'schema', 'previous_manifest_sha256', 'sources'} or
            plan['schema'] != 'client-integrated-v37-host' or
            plan['previous_manifest_sha256'] != PREVIOUS_PLAN_SHA):
        raise ValueError('HOST source graph changed')
    rows = plan['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST source graph changed')
    return [(row['module'], fixed(row['path'], row['sha256'], row['bytes'])) for row in rows]


def definitions(inputs):
    modules, original_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('HOST unplanned private source')
            return modules[name]
        return original_import(name, *args, **kwargs)
    for name, raw in inputs:
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('HOST target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-status-rejection-v37/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(modules) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST source order changed')
    return modules


def platform_tripwires(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
            'os.stat', 'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'os.system', 'os.urandom',
            'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name,
            side_effect=AssertionError('HOST actual platform forbidden'), create=True))


class TripwireIo:
    def __init__(self): self.calls = []
    def __getattr__(self, name):
        self.calls.append(name)
        raise AssertionError('HOST native IO forbidden')


class ClientStatusRejectionV37Tests(unittest.TestCase):
    def test_native_status_predispatch_rejections_and_failed_claim_are_io_free(self):
        inputs = source_inputs()  # Only fixed private source reads precede tripwires.
        with ExitStack() as stack:
            platform_tripwires(stack)
            modules = definitions(inputs)
            provider_module = modules['mta_client_linux_provider']
            provider_type = provider_module.LinuxClientInitProvider
            calls = {'current': [], 'context': [], 'anchors': [], 'timeout': []}
            for name, label in (('_status_exchange_current_v35', 'current'),
                    ('_connection_context', 'context'), ('_verify_anchors', 'anchors'),
                    ('_connection_timeout', 'timeout')):
                original = getattr(provider_type, name)
                def observe(instance, *args, _original=original, _label=label, **kwargs):
                    calls[_label].append(instance)
                    return _original(instance, *args, **kwargs)  # Never substitute a gate/exception.
                stack.enter_context(mock.patch.object(provider_type, name, observe))

            def producer():
                io, clock_calls = TripwireIo(), []
                def clock():
                    clock_calls.append(True)
                    return 1.0
                native = provider_type(None, _io=io, _clock=clock)
                self.assertIsNone(native.manifest)
                self.assertIs(native._io, io)
                self.assertIsNone(native._store)
                self.assertIsNone(native._lease)
                self.assertIsNone(native._owner)
                self.assertIsNone(native._connection)
                self.assertFalse(native._started)
                self.assertFalse(native._unknown)
                self.assertIsNone(native._status_exchange_v35)
                self.assertEqual([], native._status_exchanges_v35)
                self.assertEqual([], io.calls)
                self.assertEqual([], clock_calls)
                return native, io, clock_calls

            def invalid_active(native, **changes):
                # Explicit INVALID denial input only. No native issue() call,
                # producer-history membership, context, ready, Journal or FD.
                row = dict(claimed=False, send_attempted=True, send_return=6, wire=b'STATUS')
                row.update(changes)
                native._status_exchange_v35 = row
                self.assertEqual([], native._status_exchanges_v35)
                return row

            def denied(callback):
                with self.assertRaises(provider_module.LinuxProviderError) as caught:
                    callback()
                self.assertIs(type(caught.exception), provider_module.LinuxProviderError)
                self.assertEqual('wrong_owner', caught.exception.code)

            operation, until = object(), 2.0  # No actual Connection/ticket/network authority.
            cases = ('nonactive', 'copied', 'claimed', 'bool_send', 'short_send',
                'event', 'poll', 'reply', 'command_event', 'integer_poll', 'integer_reply', 'integer_event')
            for case in cases:
                with self.subTest(case=case):
                    native, io, clock_calls = producer()
                    before = {label: len(values) for label, values in calls.items()}
                    if case == 'nonactive':
                        row = dict(claimed=False, send_attempted=True, send_return=6, wire=b'STATUS')
                    else:
                        row = invalid_active(native,
                            **({'claimed': True} if case == 'claimed' else
                               {'send_return': True} if case == 'bool_send' else
                               {'send_return': 5} if case == 'short_send' else {}))
                    candidate = dict(row) if case == 'copied' else row
                    original_claimed = row['claimed']
                    if case in ('poll', 'reply', 'command_event', 'integer_poll', 'integer_reply', 'integer_event'):
                        kwargs = {'poll': False, 'reply': True, 'command_event': False}
                        kwargs[{'poll': 'poll', 'reply': 'reply', 'command_event': 'command_event',
                            'integer_poll': 'poll', 'integer_reply': 'reply', 'integer_event': 'command_event'}[case]] = (
                                True if case in ('poll', 'command_event') else
                                False if case == 'reply' else 1 if case == 'integer_reply' else 0)
                        denied(lambda: native._connection_receive(operation, until,
                            _status_ticket=candidate, **kwargs))
                    else:
                        denied(lambda: native._connection_channel_gate(operation, until,
                            case == 'event', _status_ticket=candidate))
                    self.assertIs(row['claimed'], original_claimed)
                    self.assertEqual(before, {label: len(values) for label, values in calls.items()})
                    self.assertEqual([], native._status_exchanges_v35)
                    self.assertIsNone(native._store)
                    self.assertFalse(native._ctrl_receive_unknown)
                    self.assertEqual([], io.calls)
                    self.assertEqual([], clock_calls)

            # Valid PRE-DISPATCH fields only. The native once-claim is followed
            # by actual current() rejecting absent issuer-history membership;
            # this is not a fabricated valid ticket or active context.
            native, io, clock_calls = producer()
            row = invalid_active(native)
            before = len(calls['current'])
            denied(lambda: native._connection_channel_gate(operation, until, False, _status_ticket=row))
            self.assertTrue(row['claimed'])
            self.assertEqual(before + 1, len(calls['current']))
            self.assertIs(calls['current'][-1], native)
            self.assertIs(native._status_exchange_v35, row)
            self.assertEqual([], native._status_exchanges_v35)
            denied(lambda: native._connection_channel_gate(operation, until, False, _status_ticket=row))
            self.assertTrue(row['claimed'])
            self.assertEqual(before + 1, len(calls['current']))  # No second current/claim attempt.
            self.assertEqual([], calls['context'])
            self.assertEqual([], calls['anchors'])
            self.assertEqual([], calls['timeout'])
            self.assertEqual([], io.calls)
            self.assertEqual([], clock_calls)
            self.assertIsNone(native._store)
            self.assertFalse(native._ctrl_receive_unknown)


if __name__ == '__main__': unittest.main()
