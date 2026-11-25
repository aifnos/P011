"""New v23 HOST accounting methods only; actual Store originals over FakeIO.

The frozen v22 fixture is read as selected definitions, never imported or run.
No real IO/network/thread, fake FD proof, old test or production admission.
"""
import ast
import builtins
from contextlib import ExitStack
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
BUDGET_SOURCE = BASE / 'candidate/client-resource-v23/runtime/mta_client_resource_budget.py'
V22_SOURCE = BASE / 'candidate/client-store-close-v22/runtime/mta_client_store.py'
V22_TEST = BASE / 'tests/test_client_store_close_v22.py'
V22_SOURCE_SHA = 'a829dfd10ed00ce4ea3fc8b4e850b917cb2e79d609de8dfa9ea096e33c2c97ab'
V22_TEST_SHA = '0eb618268144848b0e719bee6e67367d32f12e99f9f84356a53d0fa8175196e0'


def pinned(path, sha):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha: raise ValueError('HOST source pin mismatch')
    return raw


# Reuse definitions, not old TestCase classes or methods. All actual source
# graph/fixture pins inside these selected functions remain effective.
pinned(V22_SOURCE, V22_SOURCE_SHA)
v22_tree = ast.parse(pinned(V22_TEST, V22_TEST_SHA).decode('utf-8'))
setup_names = frozenset(('BASE', 'SOURCE', 'ORIGINAL', 'ORIGINAL_SHA', 'OLD_GATE',
    'NEW_GATE', 'NAMES', 'checked', 'private_graph', 'definitions'))
selected = [node for node in v22_tree.body if
    isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in setup_names or
    isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in setup_names for t in node.targets)]
scope = dict(globals())
exec(compile(ast.Module(body=selected, type_ignores=[]), '<pinned v22 definitions>', 'exec'), scope)
manifest = json.loads(pinned(BASE / 'host/client_durable_connect_v19_source_manifest.json',
    '9c547fe0b30b899dc1b11beeb67d8815c4e98bd7db8da8c12a2d12cf775beec5').decode('utf-8'))
scope['NAMES'] = tuple(row['module'] for row in manifest['sources'] if row['module'] != 'mta_client_executor')
M, OLD_RAW = scope['private_graph']()
s, c, f, p, a, core = (M[name] for name in ('mta_client_store', 'mta_client_coordination',
    'mta_client_files', 'mta_client_pending', 'mta_client_tmp_alias', 'mta_p2p_client_init'))
scope['FIXTURE'] = dict(errno=errno, stat=stat, types=types, core=core, ip=M['mta_ip'],
    f=f, a=a, proc=M['mta_client_proc'], __builtins__=vars(builtins))
for node in v22_tree.body:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and \
            isinstance(node.value.func, ast.Name) and node.value.func.id == 'definitions':
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<pinned fixture selection>', 'exec'), scope)
FIXTURE = scope['FIXTURE']
b = types.ModuleType('mta_client_resource_budget'); b.__file__ = str(BUDGET_SOURCE)
b.__builtins__ = s.__builtins__
M[b.__name__] = b
exec(compile(BUDGET_SOURCE.read_bytes(), str(BUDGET_SOURCE), 'exec'), b.__dict__)
N, C = b.PREPARATION_NETWORK, b.CLEANUP


class ClientResourceBudgetV23Tests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'stat_root',
                    'readlink_at', 'close', 'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual IO forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'subprocess.Popen', 'os.open', 'os.kill',
                'os.waitpid', 'threading.Thread.start', 'time.sleep'):
            patcher = mock.patch(target, side_effect=AssertionError('actual IO forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(M['mta_client_proc'].ProcReader, 'read_self',
            side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self):
        io, reader = FIXTURE['AliasIo'](True), FIXTURE['Reader']()
        baseline = FIXTURE['baseline'](); reader.boot = baseline.boot
        store = s.DurableClientInitStore(FIXTURE['TOKEN'], FIXTURE['IDENTITY'],
            _coordination_io=io, _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock)
        self.addCleanup(store.close)
        return store, io, b.ResourceBudget(store)

    def error(self, code, callback, *args):
        with self.assertRaises(b.ResourceBudgetError) as caught: callback(*args)
        self.assertEqual(code, caught.exception.code)

    def test_fixed_profile_shared_byte_headroom_count_exhaustion_before_creation(self):
        store, io, budget = self.make()
        self.assertIs(budget._mutex, store._mutex); self.assertIs(budget._epoch, store._epoch)
        self.assertEqual((64 * 1024 * 1024, 32 * 1024 * 1024), b.SOURCE_PROFILE.payload_bytes)
        self.assertEqual(('FILES_OPEN', 'CANONICAL', 'PROC_CALL', 'COLLECTOR', 'KERNEL_READER',
            'CAPS_READER', 'FD_RECEIPT', 'LEGACY_REQUEST', 'LEGACY_PACKET'), b.KINDS)
        for bad in ({'counts': 999999}, b._Profile(), None):
            other, other_io, ignored = self.make()
            delattr(other, '_resource_budget_v23')
            self.error('invalid_profile', b.ResourceBudget, other, bad)
        self.error('already_bound', b.ResourceBudget, store)
        self.error('invalid_owner', b.ResourceBudget, types.SimpleNamespace(_mutex=threading.RLock(), _epoch=object()))
        for lane, kind, size, code in ((True, 'FILES_OPEN', 0, 'invalid_lane'),
                (N, 'any', 0, 'invalid_kind'), (N, 'PROC_CALL', True, 'invalid_payload_budget'),
                (N, 'PROC_CALL', -1, 'invalid_payload_budget'), (N, 'PROC_CALL', float('nan'), 'invalid_payload_budget')):
            self.error(code, budget.reserve, lane, kind, size)
        # One shared lane ceiling across different kinds, not 64MiB per kind.
        maximum = b.SOURCE_PROFILE.payload_limit(N)
        first = budget.reserve(N, 'PROC_CALL', maximum // 4)
        second = budget.reserve(N, 'COLLECTOR', 3 * maximum // 4)
        before = len(budget._rows), tuple(io.opened), tuple(io.closed)
        self.error('safe_exhaustion', budget.reserve, N, 'FILES_OPEN', 1)
        self.assertEqual(before, (len(budget._rows), tuple(io.opened), tuple(io.closed)))
        self.assertFalse(budget.status()['resource_pending']); self.assertFalse(store._unknown)
        cleanup = budget.reserve(C, 'FILES_OPEN', b.SOURCE_PROFILE.payload_limit(C))
        self.assertEqual((maximum, 32 * 1024 * 1024), budget.status()['inflight_payload_bytes'])
        self.assertIs(first._store, store); self.assertIs(second._mutex, store._mutex)
        self.assertEqual(C, cleanup.lane)
        # Count exhaustion is independent of zero payload and remains known.
        other, other_io, count = self.make()
        originals = []
        for unused in range(b.SOURCE_PROFILE.count_limit(N, 'KERNEL_READER')):
            ticket = count.reserve(N, 'KERNEL_READER'); count.started(ticket)
            original = object(); originals.append(original); count.returned(ticket, original)
            self.assertTrue(count.settle(ticket))
        self.error('safe_exhaustion', count.reserve, N, 'KERNEL_READER')
        self.assertEqual(64, len(count._rows)); self.assertFalse(count.status()['resource_pending'])
        self.assertFalse(other._unknown); self.assertFalse(other_io.opened)
        self.assertTrue(all(row['original'] is original for row, original in zip(count._rows, originals)))
        count.reserve(C, 'KERNEL_READER')  # Cannot borrow cleanup, cannot consume it from network.

    def test_ten_large_max_small_actual_returns_release_only_unused_inflight(self):
        store, io, budget = self.make(); maximum = 8 * 1024 * 1024
        originals, total = [], 0
        for index in range(10):
            ticket = budget.reserve(N, 'COLLECTOR', maximum); budget.started(ticket)
            original, payload = object(), bytes([index]) * (index + 1)
            originals.append(original); total += len(payload)
            budget.returned(ticket, original, (payload,))
            state = budget.status()
            self.assertEqual(total, state['retained_payload_bytes'][0])
            self.assertEqual(maximum - len(payload), state['inflight_payload_bytes'][0])
            self.assertEqual(1, state['active_producers']); self.assertTrue(state['resource_pending'])
            self.assertTrue(budget.settle(ticket))
            self.assertEqual(0, budget.status()['inflight_payload_bytes'][0])
        self.assertEqual(55, budget.status()['retained_payload_bytes'][0])
        self.assertEqual(10, budget.status()['counts'][0][b.KINDS.index('COLLECTOR')])
        self.assertFalse(budget.status()['resource_pending'])
        self.assertTrue(all(row['original'] is original for row, original in zip(budget._rows, originals)))
        self.assertFalse(io.opened); self.assertFalse(store._unknown)
        for name in ('refund', 'retire', 'observe_closed', 'authenticate_restore', 'close'):
            self.assertFalse(hasattr(budget, name))
        self.assertTrue(all(budget.status()[key] is False for key in ('network_authorized',
            'resources_closed', 'restoration_verified', 'send_available', 'receive_available')))

    def test_actual_provider_optional_two_stage_exact_binding_without_authority(self):
        store, io, budget = self.make(); linux = M['mta_client_linux_provider']
        provider = linux.LinuxClientInitProvider()
        self.assertIsNone(provider._store); budget.bind_provider(provider)
        self.assertIs(provider._resource_budget_v23, budget)
        self.assertIs(budget._provider, provider)
        budget.reserve(N, 'PROC_CALL')  # Prepare accounting before actual Provider.attach.
        provider._store = store  # Pure accounting seam, NOT actual attach/admission proof.
        budget.reserve(N, 'PROC_CALL')
        self.error('already_bound', budget.bind_provider, provider)
        other, other_io, ignored = self.make()
        provider._store = other
        self.error('owner_changed', budget.reserve, N, 'PROC_CALL')
        self.assertTrue(budget.status()['owner_changed'])
        self.assertFalse(provider._started); self.assertIsNone(provider.manifest)
        self.assertFalse(provider.status()['send_available'])
        self.assertFalse(provider.status()['receive_available'])
        self.assertFalse(io.opened)

    def test_actual_files_canonical_and_per_fd_evidence_remain_originals_after_close(self):
        store, io, budget = self.make(); journal_files = store._files
        old_open, old_read, old_commit = journal_files._open_fd, journal_files.read_current, journal_files.commit
        def charged_open(*args, **kwargs):
            ticket = budget.reserve(N, 'FILES_OPEN'); budget.started(ticket)
            try:
                original = old_open(*args, **kwargs)
                budget.returned(ticket, original); return original
            finally: budget.settle(ticket)
        def canonical(producer, *args):
            ticket = budget.reserve(N, 'CANONICAL', s.codec.MAX_BYTES); budget.started(ticket)
            try:
                original = producer(*args)
                budget.returned(ticket, original, () if original is None else (original.data,))
                return original
            finally: budget.settle(ticket)
        journal_files._open_fd = charged_open
        journal_files.read_current = lambda: canonical(old_read)
        journal_files.commit = lambda expected, record: canonical(old_commit, expected, record)
        locks = store.acquire(FIXTURE['IDENTITY'], 3.0)
        record = store.commit(locks, core.Journal(FIXTURE['IDENTITY'], 'prepared', FIXTURE['baseline'](), 10.0))
        self.assertIs(store._canonical.journal, record)
        self.assertGreater(budget.status()['retained_payload_bytes'][0], 0)
        issued = tuple(budget._rows); before = budget.status()['counts']
        store.close(); store._begin_io(3.0)
        self.assertTrue(store._inventory_closed())  # Actual issuer's existing per-FD interface only.
        for row in issued:
            original = row['original']
            if row['credit'].kind == 'FILES_OPEN':
                self.assertIs(type(original), f._Fd)
                self.assertTrue(any(original is t for t in journal_files._inventory))
                self.assertTrue(store._fd_closed(original))
                credit = budget.reserve(C, 'FD_RECEIPT'); budget.started(credit)
                evidence = (original.io, original.fd, original)
                budget.returned(credit, evidence); self.assertTrue(budget.settle(credit))
                self.assertIs(budget._rows[-1]['original'], evidence)
            elif original is not None:
                self.assertIs(type(original), f.CanonicalRecord)
                self.assertIs(original._issuer, journal_files._issuer)
                self.assertTrue(any(original is v for v in journal_files._issued_canonicals))
                self.assertIs(row['payloads'][0], original.data)
        self.assertEqual(before[0], budget.status()['counts'][0])
        self.assertTrue(all(row['original'] is saved['original'] for row, saved in zip(budget._rows, issued)))
        self.assertFalse(io.handles); self.assertFalse(budget.status()['resources_closed'])
        self.assertFalse(store._restore_verified); self.assertIsNone(store._restore_reader)

    def test_provider_original_store_single_latch_rejects_none_after_attach_and_retains_return(self):
        ast.parse(BUDGET_SOURCE.read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
        for attached_at_bind in (False, True):
            with self.subTest(attached_at_bind=attached_at_bind):
                store, io, budget = self.make()
                provider = M['mta_client_linux_provider'].LinuxClientInitProvider()
                if attached_at_bind: provider._store = store
                budget.bind_provider(provider)
                self.assertEqual(attached_at_bind, budget._provider_store_seen)
                if not attached_at_bind:
                    ticket = budget.reserve(N, 'PROC_CALL', 8); budget.started(ticket)
                    budget.returned(ticket, object(), (b'pre',)); self.assertTrue(budget.settle(ticket))
                    self.assertFalse(budget._provider_store_seen)  # Pre-attach None remains valid once.
                    provider._store = store
                ticket = budget.reserve(N, 'PROC_CALL', 16); budget.started(ticket)
                self.assertTrue(budget._provider_store_seen)
                original, payload = object(), b'actual'
                provider._store = None  # Accounting drift, NOT actual attach/FD or permission proof.
                budget.returned(ticket, original, (payload,))
                row = budget._rows[-1]
                self.assertIs(original, row['original']); self.assertIs(payload, row['payloads'][0])
                self.assertTrue(row['late']); self.assertTrue(row['sticky']); self.assertTrue(row['unknown'])
                self.assertFalse(budget.settle(ticket))
                self.assertEqual(16, budget.status()['inflight_payload_bytes'][0])
                self.assertEqual(0, budget.status()['active_producers'])
                self.assertTrue(budget.status()['owner_changed']); self.assertTrue(budget.status()['resource_pending'])
                self.error('owner_changed', budget.reserve, C, 'FILES_OPEN')
                self.assertFalse(io.opened); self.assertFalse(store._unknown)
                self.assertFalse(budget.status()['network_authorized'])

    def test_unknown_active_late_overrun_and_owner_drift_never_release_or_replace_originals(self):
        for mode in ('unknown', 'missing_return', 'late', 'epoch', 'mutex', 'malformed', 'overrun'):
            with self.subTest(mode=mode):
                store, io, budget = self.make(); original = object(); maximum = 1024
                ticket = budget.reserve(N, 'PROC_CALL', maximum); budget.started(ticket)
                self.assertEqual(maximum, budget.status()['inflight_payload_bytes'][0])
                if mode == 'unknown': budget.mark_unknown(ticket)
                elif mode == 'late': budget.cancel()
                elif mode == 'epoch': store._epoch = object()
                elif mode == 'mutex': store._mutex = threading.RLock()
                if mode != 'missing_return':
                    if mode == 'malformed': self.error('invalid_payload', budget.returned, ticket, original, [b'a'])
                    elif mode == 'overrun': self.error('payload_overrun', budget.returned, ticket, original, (b'x' * 1025,))
                    else: budget.returned(ticket, original, (b'a',))
                    self.assertIs(original, budget._rows[0]['original'])
                self.assertFalse(budget.settle(ticket))
                self.assertEqual(maximum, budget.status()['inflight_payload_bytes'][0])
                self.assertTrue(budget.status()['resource_pending'])
                self.assertEqual(1, len(budget._rows)); self.assertEqual(0, budget.status()['active_producers'])
                self.error('invalid_state', budget.settle, ticket)
                if mode in ('epoch', 'mutex'):
                    self.error('owner_changed', budget.reserve, C, 'FILES_OPEN')
                    self.assertIs(ticket._mutex, budget._mutex); self.assertIs(ticket._epoch, budget._epoch)
                else:
                    self.error('network_cancelled', budget.reserve, N, 'FILES_OPEN')
                    budget.reserve(C, 'FILES_OPEN', 16)  # Independent cleanup headroom remains usable.
                self.assertFalse(io.opened); self.assertFalse(store._unknown)
        # Normal CAS/epoch/current pointer advance does not become owner drift.
        store, io, budget = self.make(); first = budget.reserve(N, 'CANONICAL', 8)
        store._canonical, store._journal_epoch, store._current_locks = object(), object(), object()
        budget.started(first); budget.returned(first, object(), (b'abc',)); self.assertTrue(budget.settle(first))
        budget.reserve(N, 'CANONICAL', 8); self.assertFalse(budget.status()['owner_changed'])
        other, other_io, foreign = self.make()
        ticket = foreign.reserve(N, 'FILES_OPEN')
        self.error('invalid_credit', budget.started, ticket)
        clone = object.__new__(b.Credit)
        for name in b.Credit.__slots__: object.__setattr__(clone, name, getattr(first, name))
        self.error('invalid_credit', budget.started, clone)

    def test_cleanup_nested_collector_proc_headroom_with_retained_history_and_cancelled_network(self):
        store, io, budget = self.make()
        self.assertEqual((64 * 1024 * 1024, 32 * 1024 * 1024), b.SOURCE_PROFILE.payload_bytes)
        budget.cancel()
        self.error('network_cancelled', budget.reserve, N, 'COLLECTOR')
        canonical = budget.reserve(C, 'CANONICAL', 4096); budget.started(canonical)
        saved, prior = object(), b'actual prior canonical'
        budget.returned(canonical, saved, (prior,)); self.assertTrue(budget.settle(canonical))
        collector = budget.reserve(C, 'COLLECTOR', 16 * 1024 * 1024); budget.started(collector)
        proc_credit = budget.reserve(C, 'PROC_CALL', 2 * 1024 * 1024); budget.started(proc_credit)
        self.assertEqual(18 * 1024 * 1024, budget.status()['inflight_payload_bytes'][1])
        self.assertEqual(2, budget.status()['active_producers'])
        proc_original, proc_raw = object(), b'actual proc'
        budget.returned(proc_credit, proc_original, (proc_raw,)); self.assertTrue(budget.settle(proc_credit))
        self.assertEqual(16 * 1024 * 1024, budget.status()['inflight_payload_bytes'][1])
        collector_original, collector_raw = object(), b'actual collector'
        budget.returned(collector, collector_original, (collector_raw,)); self.assertTrue(budget.settle(collector))
        state = budget.status()
        self.assertEqual(len(prior) + len(proc_raw) + len(collector_raw), state['retained_payload_bytes'][1])
        self.assertEqual(0, state['inflight_payload_bytes'][1]); self.assertEqual(0, state['active_producers'])
        self.assertFalse(state['resource_pending']); self.assertFalse(store._unknown); self.assertFalse(io.opened)
        for kind in ('CANONICAL', 'COLLECTOR', 'PROC_CALL'):
            self.assertEqual(1, state['counts'][1][b.KINDS.index(kind)])
        self.assertTrue(all(count == 0 for count in state['counts'][0]))
        self.assertIs(saved, budget._rows[0]['original'])
        self.assertIs(collector_original, budget._rows[1]['original'])
        self.assertIs(proc_original, budget._rows[2]['original'])
        self.error('network_cancelled', budget.reserve, N, 'FILES_OPEN', 1)
        before = len(budget._rows), state['retained_payload_bytes'], state['counts']
        self.error('safe_exhaustion', budget.reserve, C, 'COLLECTOR', b.SOURCE_PROFILE.payload_limit(C))
        self.assertEqual(before, (len(budget._rows), budget.status()['retained_payload_bytes'], budget.status()['counts']))
        self.assertFalse(budget.status()['resource_pending'])
        self.assertFalse(budget.status()['resources_closed']); self.assertFalse(budget.status()['restoration_verified'])
        ast.parse(BUDGET_SOURCE.read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_python35_source_no_io_no_resource_proof_and_lazy_definition_graph(self):
        source = BUDGET_SOURCE.read_text(encoding='utf-8'); tree = ast.parse(source, feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        eager = [alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names]
        self.assertEqual([], eager)
        attrs = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertFalse({'close', 'fstat', 'socket', 'open', 'kill', 'join', 'start', 'Thread',
            'CloseProof', 'FinishReceipt', 'authenticate', 'validate'} & attrs)
        self.assertIs(s.files, f); self.assertIs(f.codec.core, core); self.assertIs(p.files, f)
        self.assertIs(M['mta_client_linux_provider'].stores, s)
        self.assertIs(M['mta_client_linux_provider'].proc, M['mta_client_proc'])
        self.assertEqual(V22_SOURCE_SHA, hashlib.sha256(V22_SOURCE.read_bytes()).hexdigest())
        self.assertEqual(V22_TEST_SHA, hashlib.sha256(V22_TEST.read_bytes()).hexdigest())
        self.assertFalse(any(isinstance(node, ast.ClassDef) and node.name == 'ClientStoreCloseV22Tests'
            for node in selected))


if __name__ == '__main__': unittest.main()
