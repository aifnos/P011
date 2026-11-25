"""One new HOST unit boundary for native F completion, not restoration.

Both private 29-source graphs are exact fixed inputs. Finish/Store/Bridge/
Provider/Owner closure is an explicit synthetic precondition, not a native
restore or RF result. Native _observe creates the original ProcReader history
over pinned FakeFs definitions; no target definition or boolean is rewritten.
Only an instance return-boundary timing hook advances the synthetic clock
after the native history check. No old methods, device or real OS IO run.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import hashlib
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
MANIFESTS = (
    ('host/client_formal_v26_source_manifest.json',
     '1dbfc59425315d8ab2bcc3bf4a60aaa551fdb36d8707d884d5f9a512a694d586'),
    ('host/client_completion_v27_source_manifest.json',
     'd1a3435c3f021a10c618d2967e2682791832f9f024902df71a05ce058e1b1213'),
)
EXECUTOR_PINS = (
    ('11b17396c8ff825069d4c32c9beec05983558bc2a3ca54ad03d7a69278d70ff5', 75539),
    ('0c6bb9c96e9d79e828f2a9482926868865914e14a3432419ebf48813cde7fdca', 75843),
)
FIXTURE = 'tests/test_client_proc.py'
FIXTURE_SHA = 'fad1f4e86dd7cb6f17f8254865b75cc9389d19f89aefd8332de9ccc8d1c9c6bc'


def fixed(relative, digest, count=None):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest or count is not None and len(raw) != count:
        raise ValueError('HOST fixed source changed')
    return raw


def source_inputs():
    graphs, manifests = [], []
    for index, (relative, digest) in enumerate(MANIFESTS):
        manifest = json.loads(fixed(relative, digest).decode('utf-8'))
        rows = manifest['sources']
        if len(rows) != 29 or len({row['module'] for row in rows}) != 29:
            raise ValueError('HOST source graph shape changed')
        manifests.append(rows)
        graph = []
        for row in rows:
            raw = fixed(row['path'], row['sha256'], row['bytes'])
            if row['module'] == 'mta_client_executor' and \
                    (row['sha256'], row['bytes']) != EXECUTOR_PINS[index]:
                raise ValueError('HOST executor pin changed')
            graph.append((row['module'], raw))
        graphs.append(graph)
    if [row['module'] for row in manifests[0]] != [row['module'] for row in manifests[1]]:
        raise ValueError('HOST graph order changed')
    if any(old != new for old, new in zip(manifests[0], manifests[1])
            if old['module'] != 'mta_client_executor'):
        raise ValueError('HOST unchanged dependency changed')
    return graphs, fixed(FIXTURE, FIXTURE_SHA)


def private_domain(inputs):
    modules, imported = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private dependency unavailable')
            return modules[name]
        return imported(name, *args, **kwargs)
    for name, raw in inputs:
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('HOST target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-completion-unit/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(modules) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST exact module order changed')
    return modules


def fixture_definitions(raw):
    # Original definitions only, not the fixture's runtime imports/tests.
    tree = ast.parse(raw.decode('utf-8'))
    names = {'BOOT', 'BOOT_PATH', 'stat_data', 'meta', 'FakeFs'}
    body = [node for node in tree.body if
        isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names or
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
            target.id in names for target in node.targets)]
    selected = ast.Module(body=body, type_ignores=[])
    module = types.ModuleType('HOST_fixed_proc_fixture_definitions')
    module.__dict__.update(errno=errno, stat=stat, types=types)
    exec(compile(selected, 'HOST-fixed-proc-fixture', 'exec'), module.__dict__)
    return module


def tripwires(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
            'os.stat', 'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'os.system', 'os.urandom',
            'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name,
            side_effect=AssertionError('actual OS forbidden'), create=True))


class Clock(object):
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


def completion_unit(modules, fixture, stage=None, value=None, until=101.0):
    """Native F/Proc checks; collaborator closure is a stated unit premise."""
    f, core, proc = (modules[name] for name in
        ('mta_client_executor', 'mta_p2p_client_init', 'mta_client_proc'))
    clock, events = Clock(), []
    identity = core.Identity('a' * 64)
    pm = types.SimpleNamespace(run_token='a' * 32, identity=identity)
    dep = f.LoadedDeployment(None, modules, pm, 'b' * 64, '/HOST/unit', None)
    executor = f.ClientExecutor(dep, _io=object(), _clock=clock,
        _proc_fs=fixture.FakeFs(), _environ={})
    executor._proc_deadline = 110.0
    # Real pure Store budget, original RLock and native observed close history.
    f._pure_proc_store(executor)
    observed = f._observe(executor, proc, 'read_self')
    if observed.kind != 'live_actor' or not executor.reader.history_closed():
        raise AssertionError('HOST native Proc precondition failed')
    if executor._proc_fs.live: raise AssertionError('HOST native Proc descriptors remain')
    original_history = executor.reader.history_closed
    original_rows = executor.reader.operation_history
    def history_boundary():
        closed = original_history()
        events.append(('history', closed, clock.value))
        if stage == 'history': clock.value = value
        return closed
    # This instance hook only controls elapsed time at the native return
    # boundary. It cannot fabricate a history result or an open-ticket fact.
    executor.reader.history_closed = history_boundary

    class ClosedStoreAssumption(core.ClientInitStore):
        def __init__(self):
            self.locks = object()
            self._finish_receipt = core.FinishReceipt(self, self.locks, identity,
                None, None, True, True, 'absent_observed', 'verified', True, False, True)
        def authenticate_finish(self, locks, record, receipt, deadline):
            events.append(('authenticate', deadline))
            return (locks is self.locks and record is None and
                receipt is self._finish_receipt and deadline == until)
    store = ClosedStoreAssumption()
    class ClosedBridgeAssumption(object):
        def verify_closed(self, _absolute_deadline=None):
            events.append(('bridge', _absolute_deadline))
            return _absolute_deadline == until
    class ClosedProviderAssumption(object):
        def closed_resources(self, handles, deadline):
            events.append(('provider', deadline))
            if handles != () or not clock.value < deadline <= until:
                raise AssertionError('HOST provider local cap changed')
            return core.CloseProof(0, (), ())
    class ClosedOwnerAssumption(object):
        def status(self):
            events.append(('owner', clock.value))
            result = {'unknown_count': 0}
            if stage == 'owner': clock.value = value
            return result
    lease = types.SimpleNamespace(finish_receipt=store._finish_receipt,
        cleanup_complete=True, pending=False, handles={})
    executor.assembly = (ClosedProviderAssumption(), store,
        ClosedOwnerAssumption(), ClosedBridgeAssumption(), lease)
    # Original immediate-close premise, not a real inherited ELF/readback.
    executor.inherited_elf = {'closed': True, 'unknown': False, 'attempted': True,
        'close_returned': True, 'close_result': None,
        'ebadf_error': OSError(errno.EBADF, 'HOST synthetic closed ELF')}
    executor.recovery_until = until
    return executor, clock, events, original_rows


class FormalCompletionDeadlineV27Tests(unittest.TestCase):
    def test_native_completion_final_cap_owner_history_early_and_expired(self):
        inputs, fixture_raw = source_inputs()  # PC source reads, no target IO.
        with ExitStack() as stack:
            tripwires(stack)
            fixture = fixture_definitions(fixture_raw)
            graphs = [private_domain(graph) for graph in inputs]
            results = []
            for version, modules in zip(('v26', 'v27'), graphs):
                for stage, moment in (('owner', 101.0), ('owner', 101.001),
                        ('history', 101.0), ('history', 101.001),
                        ('history', 100.999), (None, None)):
                    with self.subTest(version=version, stage=stage, moment=moment):
                        executor, clock, events, original = completion_unit(
                            modules, fixture, stage, moment)
                        result = executor._complete()
                        expected = version == 'v26' or moment is None or moment < 101.0
                        self.assertIs(result, expected)
                        self.assertEqual(101.0, executor.recovery_until)
                        self.assertIs(type(executor.recovery_until), float)
                        self.assertIs(executor.finish, executor.assembly[1]._finish_receipt)
                        self.assertIs(executor.reader.operation_history[0], original[0])
                        self.assertTrue(original[0].ended)
                        self.assertFalse(original[0].unknown)
                        self.assertTrue(all(executor.reader.closed_open_ticket(ticket)
                            for ticket in original[0].tickets))
                        self.assertEqual(110.0, original[0].absolute_deadline)
                        self.assertEqual([101.0], [event[1] for event in events
                            if event[0] == 'authenticate'])
                        self.assertEqual([101.0], [event[1] for event in events
                            if event[0] == 'bridge'])
                        self.assertEqual([101.0], [event[1] for event in events
                            if event[0] == 'provider'])
                        self.assertEqual(1, len([event for event in events if event[0] == 'owner']))
                        self.assertEqual(1, len([event for event in events if event[0] == 'history']))
                        self.assertEqual('complete' if expected else 'finish_deadline',
                            executor._complete_site)
                        results.append((version, stage, moment, result))
                # An already-expired original cap cannot be replaced or grant
                # a later producer call. It is retained exactly as supplied.
                executor, clock, events, unused = completion_unit(modules, fixture, until=100.0)
                self.assertIs(executor._complete(), False)
                self.assertEqual(100.0, executor.recovery_until)
                self.assertIs(type(executor.recovery_until), float)
                self.assertEqual([], events)
                self.assertEqual('finish_auth', executor._complete_site)
            self.assertEqual(12, len(results))


if __name__ == '__main__': unittest.main()
