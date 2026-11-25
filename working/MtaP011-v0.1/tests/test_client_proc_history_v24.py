"""Only new v24 HOST methods; actual ProcReader over pinned FakeFS definitions.

No old TestCase/method is imported or executed. Frozen v23 29-source pins are
read, 28 definition modules (no Executor entry) load with only Proc/broker
replaced. This is not a P011, network, full namespace or Python heap proof.
"""
import ast
import builtins
import errno
import hashlib
import json
from pathlib import Path
import stat
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
PROC_SOURCE = BASE / 'candidate/client-proc-history-v24/runtime/mta_client_proc.py'
BUDGET_SOURCE = BASE / 'candidate/client-proc-history-v24/runtime/mta_client_resource_budget.py'
ORIGINAL_PROC_SHA = '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591'
V23_BUDGET_SHA = 'b7bcca034c77dffa8ffc6e24a20ac19a81ae8981702c6f70f87acde1f6252f3c'
MANIFEST_SHA = '54636ca4449a334abeef54be3de57ad4d6c096c06de7feb45172590dd2338a27'


def pinned(relative, sha):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('HOST whole source pin mismatch')
    return raw


manifest = json.loads(pinned('host/client_resource_v23_source_manifest.json', MANIFEST_SHA).decode('utf-8'))
raws = {row['module']: pinned(row['path'], row['sha256']) for row in manifest['sources']}
if len(raws) != 29: raise ValueError('HOST frozen graph must remain 29')
order = [row['module'] for row in manifest['sources'] if row['module'] != 'mta_client_executor']
order.remove('mta_client_resource_budget'); order.insert(order.index('mta_client_proc'), 'mta_client_resource_budget')
M = {}
original_import = builtins.__import__
def private_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name.startswith(('mta_', 'p011_')):
        if level or name not in M: raise ImportError('unloaded private graph dependency')
        return M[name]
    if level: raise ImportError('relative private dependency')
    return original_import(name, globals, locals, fromlist, level)
for name in order:
    path = PROC_SOURCE if name == 'mta_client_proc' else BUDGET_SOURCE if name == 'mta_client_resource_budget' else \
        BASE / next(row['path'] for row in manifest['sources'] if row['module'] == name)
    raw = path.read_bytes() if name in ('mta_client_proc', 'mta_client_resource_budget') else raws[name]
    module = types.ModuleType(name); module.__file__ = str(path)
    module.__builtins__ = dict(vars(builtins), __import__=private_import)
    M[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
p, b, s, core = (M[name] for name in ('mta_client_proc', 'mta_client_resource_budget',
    'mta_client_store', 'mta_p2p_client_init'))
N, C = b.PREPARATION_NETWORK, b.CLEANUP

# Only these source definitions, not old TestCase or runtime imports.
fixture_raw = pinned('tests/test_client_proc.py',
    'fad1f4e86dd7cb6f17f8254865b75cc9389d19f89aefd8332de9ccc8d1c9c6bc')
fixture_tree = ast.parse(fixture_raw.decode('utf-8'))
fixture_names = frozenset(('BOOT', 'BOOT_PATH', 'stat_data', 'meta', 'FakeFs', 'expected'))
selected = [node for node in fixture_tree.body if
    isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in fixture_names or
    isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in fixture_names for t in node.targets)]
fixture = dict(errno=errno, hashlib=hashlib, stat=stat, types=types, p=p, c=core)
exec(compile(ast.Module(body=selected, type_ignores=[]), '<pinned FakeFS definitions>', 'exec'), fixture)
FakeFs, BOOT_PATH = fixture['FakeFs'], fixture['BOOT_PATH']


class ReusingFs(FakeFs):
    def open(self, path, flags):
        if self.live: raise AssertionError('HOST fixture permits only one live proc FD')
        self.fd = 10
        return FakeFs.open(self, path, flags)


class ProcHistoryV24Tests(unittest.TestCase):
    def setUp(self):
        for target in ('os.open', 'os.read', 'os.close', 'os.fstat', 'os.lstat', 'os.listdir', 'os.readlink',
                'os.getpid', 'os.kill', 'os.waitpid', 'os.fork', 'ctypes.CDLL', 'socket.socket',
                'subprocess.Popen', 'threading.Thread.start', 'time.sleep'):
            if target == 'os.fork' and not hasattr(__import__('os'), 'fork'): continue
            patcher = mock.patch(target, side_effect=AssertionError('actual OS/IO forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)

    def make(self, fs=None):
        store = s.DurableClientInitStore('1' * 32, core.Identity('a' * 64), _clock=lambda: 1.0)
        budget = store._resource_budget_v23
        fs = ReusingFs() if fs is None else fs
        reader = p.ProcReader(_fs=fs, _clock=lambda: 1.0)
        self.assertIs(budget.bind_reader(reader), reader)
        return store, budget, reader, fs

    def budget_error(self, code, function, *args):
        with self.assertRaises(b.ResourceBudgetError) as caught: function(*args)
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def test_repeated_actual_generations_keep_full_raw_distinct_open_originals_and_public_schema(self):
        store, budget, reader, fs = self.make()
        locked = []
        fs.hook = lambda unused, operation, path, count: locked.append(store._mutex._is_owned())
        observations = [reader.read_self() for unused in range(3)]
        histories = reader.operation_history
        self.assertEqual(3, len(histories)); self.assertTrue(all(locked))
        self.assertTrue(reader.history_closed()); self.assertFalse(reader._pending)
        self.assertTrue(all(type(value) is p.ProcObservation and value.kind == 'live_actor' for value in observations))
        self.assertTrue(all(type(value.actor) is core.Actor for value in observations))
        self.assertEqual({'kind', 'reason', 'stage', 'actor_available', 'pid_path_absent', 'same_boot',
            'observation_count', 'task_count', 'remaining_task_count', 'file_count', 'files_closed',
            'resource_pending', 'reap_complete'}, set(observations[-1].public_status()))
        self.assertTrue(all(not value.reap_complete for value in observations))
        self.assertEqual(observations[-1].file_count, len(reader._fd_refs))
        self.assertEqual(observations[-1].file_count, reader._files)
        all_tickets = [ticket for generation in histories for ticket in generation.tickets]
        self.assertEqual({11}, {ticket.fd for ticket in all_tickets})
        self.assertEqual(len(all_tickets), len({id(ticket) for ticket in all_tickets}))
        self.assertEqual(len(all_tickets), len(fs.closed)); self.assertFalse(fs.live)
        for generation, observation in zip(histories, observations):
            self.assertTrue(reader.owns_generation(generation)); self.assertTrue(generation.ended)
            self.assertFalse(generation.active); self.assertIs(generation.observation, observation)
            self.assertEqual(tuple(generation.raw), observation.raw)
            self.assertTrue(generation.returned_raw)
            self.assertTrue(any(type(value) is list for value in generation.returned_raw))
            self.assertTrue(any(type(value) is str for value in generation.returned_raw))
            self.assertTrue(any(value == 42 for value in generation.returned_raw if type(value) is int))
            self.assertTrue(any(row.data == b'/private/fixture\0argument\0' for row in generation.raw))
            for ticket in generation.tickets:
                self.assertTrue(reader.owns_open_ticket(ticket)); self.assertTrue(reader.closed_open_ticket(ticket))
                self.assertIs(ticket.fs, fs); self.assertIs(ticket.generation, generation)
                self.assertTrue(ticket.close_attempted and ticket.close_returned and ticket.ebadf_observed)
                self.assertEqual(errno.EBADF, ticket.ebadf_errno); self.assertIsNone(ticket.close_result)
                self.assertIs(ticket.data, ticket.raw.data)
        used = budget.status()['counts'][0]
        self.assertEqual(3, used[b.KINDS.index('PROC_GENERATION')])
        self.assertEqual(len(all_tickets), used[b.KINDS.index('PROC_OPEN')])
        self.assertEqual(0, budget.status()['active_producers'])
        self.assertEqual(0, budget.status()['inflight_payload_bytes'][0])
        self.assertGreater(budget.status()['retained_payload_bytes'][0], 0)
        for key in ('network_authorized', 'resources_closed', 'restoration_verified', 'send_available', 'receive_available'):
            self.assertIs(False, budget.status()[key])

    def test_unknown_bad_chunk_unreturned_creation_raw_failure_and_close_contract_remain_sticky(self):
        for mode in ('bad_chunk', 'large_chunk', 'unreturned_open', 'raw_append', 'close_result', 'bad_errno'):
            with self.subTest(mode=mode):
                store, budget, reader, fs = self.make()
                if mode == 'bad_chunk': fs.read_result = {'private actual': b'payload'}
                elif mode == 'large_chunk': fs.read_result = b'x' * 4097
                elif mode == 'unreturned_open':
                    actual_open = fs.open
                    def interrupted(path, flags):
                        actual_open(path, flags); raise MemoryError('HOST original creation signal')
                    fs.open = interrupted
                elif mode == 'raw_append':
                    actual_record = reader._record
                    def interrupted_record(path, data, metadata=()):
                        if path == BOOT_PATH and type(data) is bytes: raise MemoryError('HOST original raw signal')
                        return actual_record(path, data, metadata)
                    reader._record = interrupted_record
                elif mode == 'close_result':
                    actual_close = fs.close
                    def wrong_close(fd): actual_close(fd); return True
                    fs.close = wrong_close
                elif mode == 'bad_errno':
                    actual_fstat = fs.fstat
                    def wrong_errno(fd):
                        if fd not in fs.live:
                            error = OSError(errno.EBADF, 'HOST readback'); error.errno = float(errno.EBADF); raise error
                        return actual_fstat(fd)
                    fs.fstat = wrong_errno
                value = reader.read_actor(42)
                generation = reader.operation_history[0]; ticket = generation.tickets[0]
                self.assertTrue(value.resource_pending); self.assertTrue(generation.unknown)
                self.assertFalse(reader.history_closed()); self.assertFalse(reader.closed_open_ticket(ticket))
                self.assertEqual(0, budget.status()['active_producers'])
                self.assertGreaterEqual(budget.status()['inflight_payload_bytes'][0], p.MAX_GENERATION_PAYLOAD)
                if mode == 'bad_chunk': self.assertIs(fs.read_result, ticket.incoming)
                if mode == 'large_chunk': self.assertIs(fs.read_result, ticket.chunks[0])
                if mode == 'raw_append': self.assertEqual(fixture['BOOT'].encode('ascii') + b'\n', ticket.data)
                if mode == 'unreturned_open':
                    self.assertIsNone(ticket.descriptor); self.assertFalse(ticket.returned)
                    self.assertEqual([], fs.closed); self.assertTrue(fs.live)
                else: self.assertEqual([11], fs.closed)
                before = tuple(fs.operations), tuple(fs.closed), len(reader.operation_history)
                with self.assertRaises(p.ProcReadError): reader.read_actor(42)
                self.assertEqual(before, (tuple(fs.operations), tuple(fs.closed), len(reader.operation_history)))

    def test_owner_cancel_epoch_and_binding_none_late_returns_retain_originals_and_end_actor(self):
        for mode in ('cancel', 'epoch', 'reader_none'):
            with self.subTest(mode=mode):
                store, budget, reader, fs = self.make()
                def drift(unused, operation, path, count):
                    if operation == 'read' and path == BOOT_PATH and count == 1:
                        if mode == 'cancel': budget.cancel()
                        elif mode == 'epoch': store._epoch = object()
                        else: reader._resource_budget_v24 = None
                fs.hook = drift
                with self.assertRaises(b.ResourceBudgetError):
                    reader.read_actor(42)
                generation = reader.operation_history[0]; ticket = generation.tickets[0]
                self.assertTrue(generation.ended); self.assertFalse(generation.active)
                self.assertTrue(generation.late); self.assertTrue(generation.unknown)
                self.assertFalse(reader._active); self.assertFalse(reader._history_active)
                self.assertIs(ticket.fs, fs); self.assertTrue(ticket.chunks)
                self.assertIs(generation, budget._rows[0]['original'])
                self.assertEqual(0, budget.status()['active_producers']); self.assertTrue(budget.status()['resource_pending'])
                self.assertEqual([11], fs.closed); self.assertFalse(fs.live)
                self.assertFalse(reader.history_closed()); self.assertTrue(budget.status()['network_cancelled'])

    def test_generation_open_exhaustion_and_known_prefix_negative_oserror_subclasses_preserve_closed_facts(self):
        for kind in ('PROC_GENERATION', 'PROC_OPEN', 'prefix'):
            with self.subTest(kind=kind):
                store, budget, reader, fs = self.make()
                column = b.KINDS.index('PROC_OPEN' if kind == 'prefix' else kind)
                if kind == 'prefix':
                    def exhaust(unused, operation, path, count):
                        if operation == 'read' and path == BOOT_PATH and count == 2:
                            budget._used[0][column] = b.SOURCE_PROFILE.count_limit(N, 'PROC_OPEN')
                    fs.hook = exhaust
                else: budget._used[0][column] = b.SOURCE_PROFILE.count_limit(N, kind)
                self.budget_error('safe_exhaustion', reader.read_self)
                self.assertFalse(reader._pending); self.assertFalse(reader._history_active)
                self.assertTrue(reader.history_closed()); self.assertEqual(0, budget.status()['active_producers'])
                self.assertFalse(budget.status()['resource_pending'])
                if kind == 'PROC_GENERATION': self.assertEqual([], fs.operations); self.assertEqual((), reader.operation_history)
                elif kind == 'PROC_OPEN': self.assertEqual([], fs.opens); self.assertEqual([], reader.operation_history[0].tickets)
                else:
                    self.assertEqual(1, len(fs.opens)); self.assertEqual([11], fs.closed)
                    self.assertTrue(reader.closed_open_ticket(reader.operation_history[0].tickets[0]))
                store._resource_lane_v23 = C
                fs.hook = None
                self.assertEqual('live_actor', reader.read_actor(42).kind)
        for error in (FileNotFoundError(errno.ENOENT, 'HOST negative'), PermissionError(errno.EACCES, 'HOST negative')):
            store, budget, reader, fs = self.make()
            fs.fail[('open', BOOT_PATH)] = error
            value = reader.read_actor(42); ticket = reader.operation_history[0].tickets[0]
            self.assertEqual('unknown', value.kind); self.assertFalse(value.resource_pending)
            self.assertIs(error, ticket.open_error); self.assertTrue(reader.closed_open_ticket(ticket))
            self.assertTrue(reader.history_closed()); self.assertFalse(ticket.close_attempted); self.assertFalse(fs.closed)

    def test_started_partial_failure_true_finally_and_exact_bind_rejects_unbound_or_foreign_reader(self):
        for kind, activated in (('PROC_GENERATION', True), ('PROC_OPEN', True), ('PROC_OPEN', False)):
            with self.subTest(kind=kind, activated=activated):
                store, budget, reader, fs = self.make(); original = budget.started
                signal = MemoryError('HOST first producer accounting signal')
                def started(credit):
                    if credit.kind == kind:
                        if activated: original(credit)
                        raise signal
                    return original(credit)
                with mock.patch.object(budget, 'started', side_effect=started):
                    with self.assertRaises(MemoryError) as caught: reader.read_actor(42)
                self.assertIs(signal, caught.exception)
                self.assertFalse(reader._active); self.assertFalse(reader._history_active)
                self.assertEqual(0, budget.status()['active_producers']); self.assertFalse(fs.opens)
                self.assertTrue(reader._pending); self.assertFalse(reader.history_closed())
                if kind == 'PROC_OPEN': self.assertIs(signal, reader.operation_history[0].tickets[0].error)
        store, budget, reader, fs = self.make()
        self.budget_error('already_bound', budget.bind_reader, reader)
        self.budget_error('invalid_reader', budget.bind_reader, types.SimpleNamespace())
        class Subclass(p.ProcReader): pass
        self.budget_error('invalid_reader', budget.bind_reader, Subclass(_fs=fs, _clock=lambda: 1.0))
        unbound = p.ProcReader(_fs=ReusingFs(), _clock=lambda: 1.0)
        with self.assertRaises(p.ProcReadError) as caught: unbound.read_self()
        self.assertEqual('reader_unbound', caught.exception.code); self.assertEqual([], unbound._fs.operations)
        class DeniedLock(object):
            def acquire(self, timeout): self.timeout = timeout; return False
        denied = DeniedLock()
        with mock.patch.object(budget, '_mutex', denied):
            with self.assertRaises(p.ProcReadError): reader.read_actor(42)
        self.assertEqual(0.2, denied.timeout); self.assertEqual([], fs.operations)

    def test_python35_exact_domain_unchanged_schema_mutating_gates_and_fixed_source_profile(self):
        original_tree = ast.parse(raws['mta_client_proc'].decode('utf-8'), feature_version=(3, 5))
        tree = ast.parse(PROC_SOURCE.read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(BUDGET_SOURCE.read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
        def definition(parsed, name): return next(node for node in parsed.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name)
        for name in ('ProcObservation', 'RawRecord', 'StatIdentity', 'parse_stat'):
            self.assertEqual(ast.dump(definition(original_tree, name)), ast.dump(definition(tree, name)))
        original_reader, changed_reader = definition(original_tree, 'ProcReader'), definition(tree, 'ProcReader')
        for name in ('_actor_pass', '_absence_pass', 'read_actor', 'read_absence'):
            self.assertEqual(ast.dump(next(node for node in original_reader.body if isinstance(node, ast.FunctionDef) and node.name == name)),
                ast.dump(next(node for node in changed_reader.body if isinstance(node, ast.FunctionDef) and node.name == name)))
        attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse({'kill', 'waitpid', 'fork', 'socket', 'unlink', 'mkdir', 'flock'} & attrs)
        self.assertEqual((16384, 262144), b.SOURCE_PROFILE.counts[0][-2:])
        self.assertEqual((2048, 65536), b.SOURCE_PROFILE.counts[1][-2:])
        self.assertEqual((64 * 1024 * 1024, 32 * 1024 * 1024), b.SOURCE_PROFILE.payload_bytes)
        self.assertEqual(4259842, p.MAX_GENERATION_PAYLOAD)
        self.assertIs(M['mta_client_pending'].proc, p); self.assertIs(M['mta_client_wpa_status'].proc, p)
        self.assertIs(M['mta_client_process_owner'].ProcReader, p.ProcReader)
        self.assertIs(M['mta_client_linux_provider'].proc, p)
        self.assertNotIn('mta_client_executor', M)
        self.assertEqual(ORIGINAL_PROC_SHA, hashlib.sha256(raws['mta_client_proc']).hexdigest())
        self.assertEqual(V23_BUDGET_SHA, hashlib.sha256(raws['mta_client_resource_budget']).hexdigest())
        self.assertFalse(any(isinstance(node, ast.ClassDef) and node.name == 'ProcTests' for node in selected))

    def test_malformed_nonbyte_getpid_lstat_listdir_readlink_fstat_returns_retained_before_validation(self):
        for method in ('getpid', 'lstat', 'listdir', 'readlink', 'fstat'):
            with self.subTest(method=method):
                store, budget, reader, fs = self.make()
                original = getattr(fs, method)
                bad = {'HOST exact nonbyte original': method}
                if method == 'fstat':
                    def malformed_stat(fd):
                        if fd in fs.live: return bad
                        return original(fd)
                    fs.fstat = malformed_stat
                else: setattr(fs, method, lambda *args: bad)
                observation = reader.read_self()
                generation = reader.operation_history[0]
                self.assertEqual('unknown', observation.kind); self.assertIsNone(observation.actor)
                self.assertTrue(any(value is bad for value in generation.returned_raw))
                self.assertEqual(0, budget.status()['active_producers'])
                self.assertFalse(budget.status()['resources_closed'])  # Strong refs are not a heap/close grant.
                self.assertFalse(observation.reap_complete)


if __name__ == '__main__': unittest.main()
