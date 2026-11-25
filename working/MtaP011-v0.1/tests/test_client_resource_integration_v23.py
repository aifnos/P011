"""New v23 integration methods only. Actual private source over FakeIO.

INIT, actors, interface and packet ingress are synthetic HOST assumptions.
No OS, ADB, RF, address, endpoint or phone acceptance is performed here.
The new accounting is partial (nested proc/heap coverage still unknown).
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import importlib.util
from pathlib import Path
import socket
import struct
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
NEW = BASE / 'candidate/client-resource-v23/runtime'
sys.path.insert(0, str(BASE / 'tests'))


def checked(relative, pin):
    value = (BASE / relative).read_bytes()
    if hashlib.sha256(value).hexdigest() != pin: raise ValueError('HOST fixture source drift')
    return value


def blocked(stack):
    for name in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open',
            'os.kill', 'os.waitpid', 'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))


def domain():
    spec = importlib.util.spec_from_file_location('private_v23_previous_checker',
        str(BASE / 'host/client_store_close_v22_source_check.py'))
    check = importlib.util.module_from_spec(spec); spec.loader.exec_module(check)
    rows = check.verify()
    result, imported = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name in result: return result[name]
        if name.startswith(('mta_', 'p011_')): raise ImportError('private v23 graph only')
        return imported(name, *args, **kwargs)
    names = {'mta_client_files', 'mta_client_store', 'mta_client_linux_provider', 'mta_client_dora'}
    with ExitStack() as stack:
        blocked(stack)
        for row in rows:
            if row['module'] == 'mta_client_files':
                raw = (NEW / 'mta_client_resource_budget.py').read_bytes()
                module = types.ModuleType('mta_client_resource_budget')
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
                exec(compile(raw, str(NEW / 'mta_client_resource_budget.py'), 'exec'), module.__dict__)
                result[module.__name__] = module
            path = NEW / (row['module'] + '.py') if row['module'] in names else BASE / row['path']
            raw = path.read_bytes()
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if row['module'] not in names and hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('HOST untouched graph source drift')
            module = types.ModuleType(row['module']); module.__file__ = str(path)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            exec(compile(raw, str(path), 'exec'), module.__dict__); result[row['module']] = module
    return result


M = domain()
# Reuse setup definitions, not old tests. New private objects share one domain.
raw = checked('tests/test_client_durable_connect_v19.py',
    'f92ab1be262d6da641e4cc3306f218f44d1c500f70c35d0352017cbae396bab1').decode('utf-8')
if raw.count('M = graph()') != 1: raise ValueError('fixture scope drift')
v19 = types.ModuleType('HOST_v23_fixture'); v19.__file__ = str(BASE / 'tests/test_client_durable_connect_v19.py')
v19.HOST_GRAPH = M
with ExitStack() as stack:
    blocked(stack)
    exec(compile(raw.replace('M = graph()', 'M = HOST_GRAPH'), v19.__file__, 'exec'), v19.__dict__)
raw = checked('tests/test_client_dora_v21.py',
    'f21fe1628b4b1545cce8340bbe6985cd346a7711158677748ae25904d5d03aab').decode('utf-8')
if raw.count('import test_client_durable_connect_v19 as v19') != 1 or raw.count('M = graph(); dora') != 1:
    raise ValueError('v21 fixture scope drift')
raw = raw.replace('import test_client_durable_connect_v19 as v19', 'v19 = HOST_FIXTURE')
raw = raw.replace('M = graph(); dora', 'M = HOST_GRAPH; dora')
v21 = types.ModuleType('HOST_v23_dora_fixture'); v21.__file__ = str(BASE / 'tests/test_client_dora_v21.py')
v21.HOST_FIXTURE, v21.HOST_GRAPH = v19, M
with ExitStack() as stack:
    blocked(stack); exec(compile(raw, v21.__file__, 'exec'), v21.__dict__)
dora, dhcp, wire, resources = (M[n] for n in
    ('mta_client_dora', 'mta_dhcp_client', 'mta_dhcp', 'mta_client_resource_budget'))


class ClientResourceIntegrationV23Tests(unittest.TestCase):
    make = v19.DurableConnectV19Tests.make
    connected = v21.ClientDoraV21Tests.connected
    setUp = v21.ClientDoraV21Tests.setUp

    def reply(self, capsule, kind):
        server = wire.ipv4('192.168.49.7')
        packet = wire.encode(2, capsule._core._xid, capsule.context.mac,
            {53: bytes(bytearray((kind,))), 54: server,
             1: wire.ipv4('255.255.255.0'), 51: struct.pack('!I', 60)},
            yiaddr=wire.ipv4('192.168.49.123'))
        controls = [(socket.IPPROTO_IP, dhcp.IP_PKTINFO,
            dhcp.PKTINFO.pack(capsule.context.ifindex, wire.ZERO, b'\xff' * 4))]
        return packet, controls, 0, ('192.168.49.7', 67)

    def test_full_active_dora_and_repeat_live_pass_previous_files_256_limit(self):
        capsule, lease, provider, store, io, raw = self.connected()
        budget = store._resource_budget_v23
        self.assertIs(provider._resource_budget_v23, budget)
        self.assertIs(store._files._resource_budget_v23, budget)
        self.assertIs(capsule.open(), capsule)
        self.assertEqual(1, len(raw.sent))
        raw.queue.append(self.reply(capsule, wire.OFFER))
        self.assertEqual('waiting', capsule.poll()['event'])
        self.assertEqual(2, len(raw.sent))
        raw.queue.append(self.reply(capsule, wire.ACK))
        self.assertEqual('candidate_received', capsule.poll()['event'])
        allocation = capsule.candidate()
        self.assertIs(type(allocation), dora.LiveAllocation)
        self.assertTrue(capsule.validate_live(allocation))
        self.assertGreater(len(store._files._inventory), 256)
        self.assertEqual(10, len(capsule._proof_calls))
        self.assertEqual((22, 22, 11), (len(provider._kernel_readers),
            len(provider._caps_readers), len(provider._association_receipts)))
        self.assertTrue(all(row['unknown'] is False for row in provider._kernel_readers + provider._caps_readers))
        state = budget.status()
        self.assertEqual(0, state['active_producers']); self.assertFalse(state['resource_pending'])
        self.assertFalse(state['network_authorized']); self.assertFalse(state['restoration_verified'])
        # F still has its old 24-source loader and TTL=20. This is not deployment.
        self.assertEqual(24, len(M['mta_client_executor'].MODULES))
        self.assertEqual(29, len(M))
        print('HOST_V23_DORA_COUNTS', len(store._files._inventory),
            len(store._files._issued_canonicals), len(provider._collectors),
            len(provider._proc_calls), len(provider._fd_receipts), state['retained_payload_bytes'])
        self.assertTrue(capsule.close())

    def test_known_before_open_exhaustion_keeps_store_known_and_cleanup_credit_independent(self):
        capsule, lease, provider, store, io, raw = self.connected()
        budget = store._resource_budget_v23
        limit = resources.SOURCE_PROFILE.count_limit(resources.PREPARATION_NETWORK, 'FILES_OPEN')
        used = budget.status()['counts'][0][resources.KINDS.index('FILES_OPEN')]
        for unused in range(limit - used):
            credit = budget.reserve(resources.PREPARATION_NETWORK, 'FILES_OPEN')
            budget.started(credit); budget.returned(credit, ('HOST known-no-IO fixture',)); budget.settle(credit)
        before = tuple(store._files._inventory)
        with self.assertRaisesRegex(resources.ResourceBudgetError, 'safe_exhaustion'):
            store.current(lease.locks)
        self.assertEqual(before, tuple(store._files._inventory))
        self.assertFalse(store._unknown); self.assertFalse(store._files._resource_pending)
        self.assertTrue(budget.status()['safe_exhaustion'][0])
        # Trusted HOST seam changes only accounting lane, not locks or authority.
        store._resource_lane_v23 = resources.CLEANUP; budget.cancel()
        self.assertIs(type(store.current(lease.locks)), M['mta_p2p_client_init'].Journal)
        self.assertEqual(limit, budget.status()['counts'][0][resources.KINDS.index('FILES_OPEN')])
        self.assertEqual(1, budget.status()['counts'][1][resources.KINDS.index('FILES_OPEN')])
        self.assertEqual(before, tuple(store._files._inventory[:-1]))
        self.assertFalse(store._unknown)

    def test_grouped_roots_recheck_each_original_fd_and_proof_count_refuses_before_new_reader(self):
        capsule, lease, provider, store, io, raw = self.connected()
        groups = provider._closed_objects()
        self.assertLessEqual(len(groups), 4); self.assertTrue(all(a and c for a, c in groups))
        original = provider._kernel_readers[0]['resources'][0]
        saved = original['closed']; original['closed'] = False
        try: self.assertFalse(all(c for a, c in provider._closed_objects()))
        finally: original['closed'] = saved
        # Synthetic history fills only count, not successful producer evidence.
        capsule._proof_calls[:] = [object() for unused in range(26)]
        before = (tuple(store._files._inventory), tuple(provider._kernel_readers), tuple(provider._caps_readers))
        with self.assertRaisesRegex(dora.DoraError, 'proof_budget'):
            capsule.proof(capsule.context, 5)
        self.assertEqual(before, (tuple(store._files._inventory), tuple(provider._kernel_readers), tuple(provider._caps_readers)))
        self.assertTrue(capsule._revoked)
        self.assertFalse(capsule._unknown)

    def test_journal_growth_preserves_first_failure_and_ends_both_actual_producers(self):
        capsule, lease, provider, store, io, raw = self.connected()
        budget, data, read = store._resource_budget_v23, store._canonical.data, io.read
        def growing(fd, count):
            value = read(fd, count)
            # Inject only into the final short Journal chunk; size is not
            # assumed below 4096. Marker/earlier chunks are unchanged.
            return value + b'!' if value and len(value) < count and data.endswith(value) else value
        before = len(budget._rows)
        with mock.patch.object(io, 'read', side_effect=growing):
            with self.assertRaisesRegex(M['mta_client_files'].ClientFileError, 'file_changed'):
                store._files.read_current()
        new = budget._rows[before:]
        self.assertEqual({'FILES_OPEN', 'CANONICAL'}, {r['credit'].kind for r in new})
        self.assertTrue(all(r['active'] is False and r['settled'] is True for r in new))
        self.assertTrue(budget.status()['payload_overrun']); self.assertTrue(budget.status()['resource_pending'])
        canonical = next(r for r in new if r['credit'].kind == 'CANONICAL')
        self.assertEqual((data + b'!',), canonical['payloads'])
        self.assertGreater(canonical['reserved'], 0)
        self.assertTrue(store._files._inventory[-1].closed)

    def test_legacy_malformed_return_preserved_before_unpack_and_unknown_max_retained(self):
        capsule, lease, provider, store, io, raw = self.connected()
        malformed = (b'HOST-malformed-recv',)
        class KernelSocket:
            def sendto(self, packet, endpoint): return len(packet)
            def settimeout(self, value): self.timeout = value
            def gettimeout(self): return self.timeout
            def recvmsg(self, count): return malformed
        kernel = provider._kernel
        kernel.row, kernel.port = types.SimpleNamespace(value=KernelSocket()), 321
        budget = store._resource_budget_v23
        before = len(budget._rows)
        with self.assertRaises(ValueError): kernel.request(32, 5, b'', 0, lease.record.deadline)
        packet_row = next(r for r in budget._rows[before:] if r['credit'].kind == 'LEGACY_PACKET')
        self.assertIs(packet_row['original'], malformed)
        self.assertFalse(packet_row['active']); self.assertTrue(packet_row['settled'])
        self.assertTrue(packet_row['unknown']); self.assertEqual(262144, packet_row['reserved'])

    def test_projection_failure_retains_actual_registered_rows_and_settles_under_original_lock(self):
        capsule, lease, provider, store, io, raw = self.connected()
        budget = store._resource_budget_v23
        before = len(budget._rows)
        held = []
        def failure(rows):
            held.append(budget._mutex._is_owned())
            raise RuntimeError('HOST projection failure')
        with mock.patch.object(M['mta_client_linux_provider'], '_payload_subset_v23', side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, 'HOST projection failure'):
                provider.executor(lease.record.deadline)
        row = next(r for r in budget._rows[before:] if r['credit'].kind == 'PROC_CALL')
        self.assertEqual([True], held)
        self.assertIs(row['original'][0], provider._proc_calls[-1])
        self.assertFalse(row['active']); self.assertTrue(row['settled']); self.assertTrue(row['unknown'])
        self.assertEqual(M['mta_client_proc'].MAX_TOTAL, row['reserved'])
        self.assertTrue(provider._proc_calls[-1]['unknown'] is False)


if __name__ == '__main__': unittest.main()
