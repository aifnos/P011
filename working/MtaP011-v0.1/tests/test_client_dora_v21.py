"""Only new v21 methods. Actual v19 private graph/Store/readers over FakeIO.

Init actors/baseline/connection events are synthetic fixture assumptions. A
synthetic bound-ACK precondition tests live allocation identity, not full DORA.
No old test methods are run, no actual OS/socket/ADB/network is permitted.
"""
import ast
import builtins
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
NEW = BASE / 'candidate/client-dhcp-v21/runtime'
sys.path.insert(0, str(BASE / 'tests'))


def checked(path, pin):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin: raise ValueError('HOST source pin mismatch')
    return raw


# Gate the whole original 24-source graph before importing fixture definitions.
manifest = checked(BASE / 'host/client_durable_connect_v19_source_manifest.json',
    '9c547fe0b30b899dc1b11beeb67d8815c4e98bd7db8da8c12a2d12cf775beec5')
for row in json.loads(manifest.decode('utf-8'))['sources']:
    checked(BASE / row['path'], row['sha256'])
checked(BASE / 'tests/test_client_durable_connect_v19.py',
    'f92ab1be262d6da641e4cc3306f218f44d1c500f70c35d0352017cbae396bab1')
import test_client_durable_connect_v19 as v19


def graph():
    modules, real_import = dict(v19.M), builtins.__import__
    def private_import(name, *args, **kwargs):
        if name in modules: return modules[name]
        if name.startswith('mta_') or name == 'p011_json': raise ImportError('private graph only')
        return real_import(name, *args, **kwargs)
    sources = (
        ('mta_dhcp', BASE / 'runtime/mta_dhcp.py', '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
        ('mta_dhcp_client_core', BASE / 'runtime/mta_dhcp_client_core.py', '13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa'),
        ('mta_dhcp_client', NEW / 'mta_dhcp_client.py', None),
        ('mta_client_dora', NEW / 'mta_client_dora.py', None))
    for name, path, pin in sources:
        raw = checked(path, pin) if pin else path.read_bytes()
        namespace = dict(vars(builtins)); namespace['__import__'] = private_import
        module = types.ModuleType(name); module.__file__ = str(path); module.__builtins__ = namespace
        exec(compile(raw, str(path), 'exec'), module.__dict__); modules[name] = module
    return modules


M = graph(); dora, dhcp, wire = (M[n] for n in ('mta_client_dora', 'mta_dhcp_client', 'mta_dhcp'))


class HostDatagram:
    def __init__(self):
        self.family, self.fd = socket.AF_INET, 800
        self.options, self.sent, self.queue = {}, [], []
        self.inheritable, self.timeout, self.address = True, None, None
    def fileno(self): return self.fd
    def close(self): self.fd = -1
    def set_inheritable(self, value): self.inheritable = value
    def get_inheritable(self): return self.inheritable
    def setsockopt(self, level, option, value): self.options[level, option] = value
    def getsockopt(self, level, option, *unused):
        if option == socket.SO_TYPE: return int(socket.SOCK_DGRAM)
        if option in (socket.SO_REUSEADDR, dhcp.SO_REUSEPORT): return 0
        return self.options.get((level, option))
    def bind(self, address): self.address = address
    def getsockname(self): return self.address
    def settimeout(self, value): self.timeout = value
    def gettimeout(self): return self.timeout
    def sendmsg(self, buffers, ancillary, flags, target):
        self.sent.append((buffers, ancillary, flags, target)); return len(buffers[0])
    def recvmsg(self, *arguments):
        if self.queue: return self.queue.pop(0)
        raise socket.timeout()


class ClientDoraV21Tests(unittest.TestCase):
    make = v19.DurableConnectV19Tests.make  # Fixture setup only, not an old test.
    def setUp(self):
        v19.p._OWNERS[:] = []
        self.addCleanup(lambda: v19.p._OWNERS.__setitem__(slice(None), []))
        for target in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('mta_client_coordination', 'mta_client_files', 'mta_client_pending'):
            patcher = mock.patch.object(M[name]._LinuxIo, 'open_root', side_effect=AssertionError('actual root forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(socket, 'CMSG_SPACE', lambda size: 16 + ((size + 7) // 8) * 8, create=True)
        patcher.start(); self.addCleanup(patcher.stop)
    def connected(self):
        lease, provider, store, io, request, kernels, caps = self.make()
        lease.connect_p2p(request, _checkpoint=lambda: False)
        current = provider._connection.receipt
        capsule = dora.PrivateClientDora(lease, current)
        raw = HostDatagram()
        # Existing private HOST seams only; no caller-supplied proof/context.
        capsule._client._factory = lambda *args: raw; capsule._client._real_factory = False
        capsule._client._index_reader = lambda name: capsule.context.ifindex
        self.addCleanup(capsule.close)
        return capsule, lease, provider, store, io, raw
    def seed_ack(self, capsule, raw):
        """Synthetic already-active socket/Offer/ACK, not full transport success."""
        client, core = capsule._client, capsule._core
        raw.address = ('0.0.0.0', 68); client._socket, client._stage = raw, 'bound'
        now = capsule._now(); core.start(now)
        server, assigned, mask = (wire.ipv4(x) for x in ('192.168.49.7', '192.168.49.123', '255.255.255.0'))
        def packet(kind):
            return wire.encode(2, core._xid, capsule.context.mac,
                {53: bytes(bytearray((kind,))), 54: server, 1: mask, 51: struct.pack('!I', 60)}, yiaddr=assigned)
        core.accept_offer(packet(wire.OFFER), now)
        token = object(); capsule._poll_token = token
        ack = packet(wire.ACK)
        ancillary = [(socket.IPPROTO_IP, dhcp.IP_PKTINFO,
            dhcp.PKTINFO.pack(capsule.context.ifindex, wire.ZERO, b'\xff' * 4))]
        self.assertIsNone(capsule._client._envelope(ack, ancillary, 0, ('192.168.49.7', 67)))
        actual = core.accept_ack(ack, now)
        capsule._accept_ack(token); capsule._poll_token = None
        self.assertIs(capsule._acks[-1]['packet'], ack)
        self.assertIs(capsule._acks[-1]['configuration'], actual)
        return actual
    def test_exact_constructor_and_flags_from_new_original_fresh_receipt(self):
        capsule, lease, provider, store, io, raw = self.connected(); first = capsule._receipt
        original_record, original_baseline, original_canonical = lease.record, lease.record.baseline, store._canonical
        ctx = capsule.context
        self.assertEqual((100000001, 8, v19.LOCAL, lease.record.deadline),
            (ctx.task_epoch, ctx.native_epoch, ctx.mac, ctx.deadline))
        with self.assertRaises(dora.DoraError): dora.PrivateClientDora({}, first)
        fake = v19.c.AssociationReceipt(provider, provider._connection,
            provider._connection.result, store._canonical, first._generation)
        with self.assertRaises(Exception): dora.PrivateClientDora(lease, fake)
        value = capsule.proof(ctx, 5)
        self.assertIs(type(value), dhcp.AssociationProof); self.assertIs(value.context, ctx)
        self.assertTrue(all(x is True for x in value[9:])); self.assertEqual(8, value.iftype)
        self.assertIsNot(capsule._receipt, first)
        self.assertIsNot(store._canonical, original_canonical)
        self.assertIs(capsule._registration['canonical'], store._canonical)
        self.assertIs(lease.record, original_record); self.assertIs(lease.record.baseline, original_baseline)
        self.assertIs(capsule._receipt._record, original_record)
        self.assertIs(capsule._proof_calls[0]['returned'], capsule._receipt)
        self.assertIs(provider._active_association_receipt, capsule._receipt)
        self.assertEqual(4, len(provider._kernel_readers)); self.assertEqual(4, len(provider._caps_readers))
        self.assertFalse(capsule._proof_calls[0]['unknown']); self.assertFalse(raw.sent)
        self.assertEqual(5, capsule._client._proof_seconds); self.assertEqual(.2, capsule._client._lock_seconds)
        self.assertIs(provider._dora_v21_registration, provider._connection._dora_v21_registration)
    def test_budget_retains_returned_original_and_revokes_pending(self):
        capsule, lease, provider, _, io, _ = self.connected(); initial = capsule._receipt
        original = lease.read_association_receipt
        def delayed(receipt):
            value = original(receipt); io.clock.value += 5.01; return value
        lease.read_association_receipt = delayed
        with self.assertRaises(dora.DoraError): capsule.proof(capsule.context, 5)
        self.assertIsNot(capsule._receipt, initial)
        self.assertIs(capsule._receipt, capsule._proof_calls[0]['returned'])
        self.assertIsNone(provider._active_association_receipt)
        self.assertTrue(capsule._proof_calls[0]['unknown']); self.assertTrue(capsule.status()['resource_pending'])
        self.assertTrue(lease.pending); self.assertEqual(10, lease.record.deadline)
    def test_changed_epoch_cancel_owned_ipv4_and_local_mac_fail_closed(self):
        for mode in ('epoch', 'cancel', 'ipv4', 'local_mac'):
            with self.subTest(mode=mode):
                capsule, lease, provider, store, io, _ = self.connected()
                try:
                    if mode == 'epoch': store._journal_epoch = object()
                    elif mode == 'cancel': provider.request_stop()
                    elif mode == 'ipv4':
                        snap = provider.fake_snapshot
                        record = M['mta_ip'].AddressRecord(capsule.context.ifindex, 0xc0a8317b, 0xc0a8317b,
                            24, 128, 0, b'HOST\0', 0xc0a831ff, (0xffffffff, 0xffffffff, 0, 0))
                        provider.fake_snapshot = v19.core.Snapshot(snap.boot, snap.stock_hashes, snap.stock_actors,
                            snap.station, snap.station_state_sha, snap.station_frequency, snap.interfaces,
                            M['mta_ip'].IpSnapshot(snap.ipv4.addresses + (record,), snap.ipv4.routes, snap.ipv4.rules),
                            snap.ipv6_addresses, snap.ipv6_routes, snap.station_completed)
                    else: io.status_wire = io.status_wire.replace(b'address=02:66:77:88:99:aa', b'address=02:66:77:88:99:ab')
                    with self.assertRaises(Exception): capsule.proof(capsule.context, 5)
                    self.assertTrue(capsule.status()['resource_pending'])
                    self.assertIsNone(provider._active_association_receipt)
                finally:
                    capsule.close(); store.close(); v19.p._OWNERS[:] = []
    def test_real_original_reader_and_files_budgets_block_full_dora(self):
        capsule, lease, provider, store, _, raw = self.connected()
        failure = None
        try:
            capsule.open()
            capsule.poll()
        except Exception as error: failure = error
        self.assertIsNotNone(failure, 'Original budgets must not be enlarged to fake full DORA')
        self.assertLessEqual(len(provider._kernel_readers), 8); self.assertLessEqual(len(provider._caps_readers), 8)
        self.assertLessEqual(len(provider._association_receipts), 8); self.assertLessEqual(len(store._files._inventory), 256)
        self.assertTrue(capsule.status()['resource_pending']); self.assertIsNone(provider._active_association_receipt)
        self.assertFalse(capsule._issued); self.assertEqual(10, lease.record.deadline)
        self.assertIs(type(failure), dhcp.DhcpSocketClientError)
        self.assertEqual('proof_failed', str(failure))
        print('V21_EXPECTED_CAPACITY_BLOCK=DhcpSocketClientError:proof_failed')
        source_failure = capsule._proof_calls[-1]['failure']
        self.assertIn(source_failure, (('files', 'resource_budget'), ('connection', 'kernel_unverified'),
            ('connection', 'channel_unverified')))
        print('V21_EXPECTED_CAPACITY_SOURCE=' + repr(source_failure))
        print('V21_CAPACITY_COUNTS=' + repr((len(provider._kernel_readers), len(provider._caps_readers),
            len(provider._association_receipts), len(store._files._inventory))))
    def test_live_issued_original_current_core_ack_close_and_historical_rejected(self):
        capsule, _, provider, _, _, raw = self.connected()
        actual = self.seed_ack(capsule, raw)
        current = capsule.candidate()
        self.assertIs(type(current), dora.LiveAllocation); self.assertIs(current._configuration, actual)
        self.assertIs(current._client, capsule._client); self.assertIs(current._socket, raw)
        self.assertIs(current._context, capsule.context); self.assertIs(current._receipt, capsule._receipt)
        self.assertEqual('192.168.49.123', actual.local_ip)  # Not GO network+1.
        fake = dora.LiveAllocation(capsule, capsule._client, actual, current._ack, current._receipt)
        self.assertFalse(capsule.validate_live(fake)); self.assertIs(capsule._active_live, current)
        with self.assertRaises(AttributeError): current._expires = 100
        # First positive revalidation attempt was retained as a real FILES256
        # ERROR. Do not trim inventory/cache proof to manufacture True.
        with self.assertRaises(M['mta_client_files'].ClientFileError): capsule.validate_live(current)
        self.assertEqual(('files', 'resource_budget'), capsule._proof_calls[-1]['failure'])
        self.assertEqual(256, len(capsule.store._files._inventory))
        self.assertIsNone(capsule._active_live); self.assertEqual(-1, raw.fileno())
        self.assertIsNone(provider._active_association_receipt)
        self.assertTrue(capsule.status()['resource_pending'])
        self.assertFalse(capsule.close()); self.assertFalse(capsule.validate_live(current))
        self.assertIsNone(capsule._core.configuration(capsule._now()))
        with self.assertRaises(Exception): capsule.candidate()
        self.assertFalse(capsule.status()['interface_configured']); self.assertFalse(provider.status()['send_available'])
    def test_entry_epoch_or_original_deadline_revokes_live_and_closes_socket_without_io(self):
        for mode in ('epoch', 'deadline'):
            with self.subTest(mode=mode):
                capsule, lease, provider, store, io, raw = self.connected()
                try:
                    self.seed_ack(capsule, raw); current = capsule.candidate()
                    before = len(capsule._proof_calls)
                    if mode == 'epoch': store._journal_epoch = object()
                    else: io.clock.value = lease.record.deadline
                    with self.assertRaises(dora.DoraError): capsule.validate_live(current)
                    self.assertEqual(before, len(capsule._proof_calls)); self.assertEqual(-1, raw.fileno())
                    self.assertIsNone(capsule._active_live); self.assertIsNone(provider._active_association_receipt)
                    self.assertFalse(capsule.validate_live(current)); self.assertEqual(10, lease.record.deadline)
                    if mode == 'epoch': self.assertTrue(capsule.status()['resource_pending'])
                finally:
                    capsule.close(); store.close(); v19.p._OWNERS[:] = []
    def test_ast35_constructor_has_no_context_proof_input_and_frozen_graph_identity(self):
        for path in (NEW / 'mta_client_dora.py', NEW / 'mta_dhcp_client.py', Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertIs(dora.linux, v19.p); self.assertIs(dora.core, v19.core); self.assertIs(dora.connection, v19.c)
        self.assertIs(dora.ip, v19.M['mta_ip']); self.assertIs(dora.dhcp, dhcp)
        ctor = next(x for x in ast.walk(ast.parse((NEW / 'mta_client_dora.py').read_text()))
            if isinstance(x, ast.FunctionDef) and x.name == '__init__' and len(x.args.args) == 3)
        self.assertEqual(['self', 'lease', 'receipt'], [x.arg for x in ctor.args.args])
        self.assertFalse(ctor.args.kwarg); self.assertFalse(ctor.args.vararg)

    def test_expired_proof_slice_before_io_never_starts_reader(self):
        capsule, lease, provider, store, io, raw = self.connected()
        original_now, calls = capsule._now, []
        before = (len(provider._kernel_readers), len(provider._caps_readers),
            len(provider._association_receipts), len(store._files._inventory))
        def resumed_clock():
            calls.append(None)
            if len(calls) == 2: io.clock.value += .11
            return original_now()
        capsule._now = resumed_clock
        with mock.patch.object(lease, 'read_association_receipt',
                side_effect=AssertionError('expired slice must not start original reader')) as reader:
            with self.assertRaisesRegex(dora.DoraError, 'proof_budget'):
                capsule.proof(capsule.context, .1)
            reader.assert_not_called()
        self.assertEqual(before, (len(provider._kernel_readers), len(provider._caps_readers),
            len(provider._association_receipts), len(store._files._inventory)))
        call = capsule._proof_calls[-1]
        self.assertIsNone(call['returned']); self.assertFalse(call['active'])
        self.assertEqual(('dora', 'proof_budget'), call['failure'])
        self.assertEqual(0, capsule._proof_active); self.assertTrue(capsule.status()['resource_pending'])
        self.assertIsNone(provider._active_association_receipt); self.assertFalse(raw.sent)

    def test_direct_proof_actor_blocks_close_until_actual_return_without_thread(self):
        for mode in ('normal', 'close_during_readback'):
            with self.subTest(mode=mode):
                capsule, lease, provider, store, io, raw = self.connected()
                original = lease.read_association_receipt
                observed = []
                def returning(receipt):
                    self.assertEqual(1, capsule._proof_active)
                    self.assertTrue(capsule._proof_calls[-1]['active'])
                    self.assertEqual(0, capsule._client._proofs)
                    self.assertIsNone(capsule._active)
                    if mode == 'close_during_readback':
                        observed.append(capsule.close())
                        self.assertFalse(observed[-1])
                        self.assertTrue(capsule.status()['resource_pending'])
                        self.assertTrue(capsule._client.status()['socket_close_verified'])
                    return original(receipt)
                lease.read_association_receipt = returning
                try:
                    if mode == 'normal':
                        value = capsule.proof(capsule.context, 5)
                        self.assertIs(type(value), dhcp.AssociationProof)
                        self.assertFalse(capsule.status()['resource_pending'])
                        self.assertTrue(capsule.close())
                    else:
                        with self.assertRaisesRegex(dora.DoraError, 'closed'):
                            capsule.proof(capsule.context, 5)
                        self.assertEqual([False], observed)
                        self.assertIsNotNone(capsule._proof_calls[-1]['returned'])
                        self.assertTrue(capsule._proof_calls[-1]['unknown'])
                        self.assertTrue(capsule.status()['resource_pending'])
                        self.assertFalse(capsule.close())
                        self.assertIsNone(provider._active_association_receipt)
                    self.assertEqual(0, capsule._proof_active)
                    self.assertFalse(capsule._proof_calls[-1]['active'])
                    self.assertFalse(capsule._actor_lock._is_owned())
                finally:
                    capsule.close(); store.close(); v19.p._OWNERS[:] = []


if __name__ == '__main__': unittest.main()
