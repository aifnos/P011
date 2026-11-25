"""Only new v15 SOURCE/Fake methods. No device, RF, real socket or restore."""
import ast
import errno
import hashlib
import stat
import struct
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_connect_provider_v14 as prior
import test_client_kernel_proof_v13 as kernel_fixture
import test_client_caps_transport as wire
import test_client_proc as proc_fixture

old = prior.old
ROOT = BASE / 'candidate/client-kernel-connect-v15/runtime'
k = prior.load('kernel_provider_v15_kernel', ROOT / 'mta_client_kernel_proof.py')
c = prior.load('kernel_provider_v15_connection', ROOT / 'mta_client_connection.py', {'mta_client_kernel_proof': k})
p = prior.load('kernel_provider_v15_provider', ROOT / 'mta_client_linux_provider.py',
    {'mta_client_connection': c, 'mta_client_kernel_proof': k, 'mta_client_tmp_alias': prior.alias})
manifest = prior.fixture(prior.manifest, {'p': p})
ARGV = b'/usr/bin/python3\0-B\0fixed-private-entry\0'
SELF = p.core.Actor(123, 300, '/usr/bin/python3', hashlib.sha256(ARGV).hexdigest(), ((123, 300, 'S'),))
EPOCH = 100000001
BSSID = b'\x02\xaa\xbb\xcc\xdd\xee'


class StoreReader(old.Reader):
    def __init__(self):
        old.Reader.__init__(self); self.actor = SELF


class ProviderProc(old.Proc):
    def read_self(self): return self.observation(SELF)


def proc_fs(lowest_fd=False):
    fs = proc_fixture.FakeFs()
    fs.files = {proc_fixture.BOOT_PATH: old.baseline().boot.encode() + b'\n',
        '/proc/123/stat': proc_fixture.stat_data(123, start=300),
        '/proc/123/task/123/stat': proc_fixture.stat_data(123, start=300),
        '/proc/123/cmdline': ARGV}
    fs.dirs = {'/proc', '/proc/123', '/proc/123/task', '/proc/123/task/123'}
    fs.links = {'/proc/123/exe': SELF.exe}; fs.getpid = lambda: 123
    if lowest_fd:
        original = fs.open
        def open_once(path, flags):
            fd = original(path, flags)
            if fd != 11: fs.live[11] = fs.live.pop(fd)
            return 11
        fs.open = open_once
    return fs


def interface(role=8, frequency=2412):
    owned = old.OWNED
    data = wire.u32(1, owned.phy) + wire.u32(3, owned.ifindex) + wire.attr(4, owned.name.encode() + b'\0') + wire.attr(153, struct.pack('<Q', owned.wdev))
    if role is not None: data += wire.u32(5, role)
    if frequency is not None: data += wire.u32(38, frequency)
    return data


def station(mac=BSSID, mask=0xa2, values=0xa2):
    flags = b'' if mask is None else wire.attr(17, struct.pack('<II', mask, values))
    return wire.u32(3, old.OWNED.ifindex) + wire.attr(6, mac) + wire.u32(46, 2) + wire.attr(21, flags)


def packets(face=None, peers=None):
    face = interface() if face is None else face
    peers = [station()] if peers is None else peers
    return kernel_fixture.packets([face] * 3, [peers, peers])


class KernelIo(kernel_fixture.FakeIo):
    def __init__(self, values):
        kernel_fixture.FakeIo.__init__(self, values)
        self.index_values = [str(old.OWNED.ifindex).encode() + b'\n'] * 2
        self.raw.fd = 500
    def new_socket(self):
        self.live[500] = [None, b'', 0, stat.S_IFSOCK | 0o600]
        return self.raw
    def open_ifindex(self, name):
        if name != old.OWNED.name: raise AssertionError('wrong selector')
        self.next += 1; self.open_calls.append(name)
        self.live[self.next] = [name, self.index_values[len(self.open_calls)-1], 0, stat.S_IFREG | 0o444]
        return self.next


class CapsSocket(wire.FakeSocket):
    def __init__(self, io, values, fd):
        wire.FakeSocket.__init__(self, values); self.fd = fd; self.io = io
        self.timeout_nanosecond_quantized = True
    def close(self):
        original = self.fd
        wire.FakeSocket.close(self)
        if self.fd == -1: self.io.close(original)


def caps_packets(channels=1, maximum=2, limit=2, software=b'', radar=0, beacon=False, bi=None):
    limits = wire.u32(1, limit) + wire.attr(2, wire.attr(2) + wire.attr(8))
    combo = wire.attr(1, wire.attr(1, limits)) + wire.u32(2, maximum) + wire.u32(4, channels) + wire.u32(5, radar) + wire.u32(6, 0)
    if beacon: combo += wire.attr(3)
    if bi is not None: combo += wire.u32(7, bi)
    parts = (wire.identity() + wire.attr(32, wire.attr(2) + wire.attr(8)),
        wire.identity() + wire.attr(50, wire.u32(1, 7)),
        wire.identity() + wire.attr(121, software) + wire.attr(120, wire.attr(1, combo)))
    return wire.fixture(parts)


class KernelProviderV15Tests(unittest.TestCase):
    setUp = prior.fixture(old.ConnectionTests.setUp, {'p': p})
    _make = prior.fixture(old.ConnectionTests.make, {'p': p, 'c': c, 'manifest': manifest,
        'Reader': StoreReader, 'Proc': ProviderProc})
    def make(self, rows=None, caps=None, hook=None, fail_close=False, lowest_fd=False):
        lease, provider, store, io = self._make()
        kernels, caps_sockets = [], []
        def kernel_factory(*args, **kwargs):
            values = rows(len(kernels)) if callable(rows) else rows
            actual_io = KernelIo(packets() if values is None else values)
            actual_io.fail_file_close = fail_close
            if hook is not None: actual_io.raw.on_recv = lambda raw: hook(provider, actual_io, raw)
            actual = k.ClientKernelReader(*args, _io=actual_io,
                _proc_factory=lambda **kw: p.proc.ProcReader(_fs=proc_fs(lowest_fd), **kw), **kwargs)
            kernels.append((actual, actual_io)); return actual
        def genl():
            path = old.RUN + '/kernel-caps-' + str(len(caps_sockets))
            io.add(path, stat.S_IFSOCK | 0o600); fd = io._open(path, 0, 0)
            values = caps(len(caps_sockets)) if callable(caps) else caps
            raw = CapsSocket(io, caps_packets() if values is None else values, fd)
            caps_sockets.append(raw); return raw
        provider._kernel_factory, io.new_genl = kernel_factory, genl
        return lease, provider, store, io, kernels, caps_sockets
    def connect(self, lease):
        return lease.connect_p2p(old.info(), _checkpoint=lambda: False, _operation_epoch=EPOCH)
    def reject(self, lease, reason):
        with self.assertRaises(c.ConnectionError) as error: self.connect(lease)
        self.assertEqual(reason, error.exception.code)
        self.assertIsNone(lease.provider._connection.result)
    def closed(self, provider):
        self.assertTrue(all(not row['unknown'] for row in provider._kernel_readers))
        for row in provider._kernel_readers:
            self.assertTrue(all(a and closed for a, closed in provider._kernel_closed_facts(row)))
            self.assertIs(row['operation'], provider._connection)
            self.assertIs(row['reader']._cancel_callback, provider._connection._cancel_checkpoint)
            self.assertEqual(row['reader']._external_deadline, provider._connection.deadline)
    def test_actual_reader_two_rounds_readback_fresh_same_f_caps_and_no_l3(self):
        lease, provider, store, io, kernels, rawcaps = self.make()
        device = lease.locks._device; first = self.connect(lease)
        self.assertIs(type(first), c.ConnectionObservation)
        self.assertEqual(len(kernels), 2); self.assertEqual(len(rawcaps), 2)
        self.assertEqual(first._kernels, tuple(row['value'] for row in provider._kernel_readers))
        self.assertEqual(first._caps, tuple(row['value'] for row in provider._caps_readers))
        self.assertTrue(first.public_summary()['peer_mac_hint_matches'])
        self.assertNotEqual(BSSID, provider._connection.peer_mac)
        second = lease.read_connection(first)
        self.assertEqual(len(kernels), 4); self.assertEqual(len(rawcaps), 4)
        self.assertIsNot(first, second); self.assertIs(lease.locks._device, device)
        self.assertEqual(10, provider._connection.deadline)
        self.closed(provider)
        self.assertTrue(all(reader.status()['resources_closed'] and not observer.live for reader, observer in kernels))
        self.assertTrue(all(raw.close_count == 1 for raw in rawcaps))
        self.assertFalse(second.public_summary()['endpoint_verified'])
        self.assertFalse(provider.status()['send_available'])
    def test_epoch_missing_bool_out_of_range_no_handoff_no_kernel_io(self):
        lease, provider, store, io, kernels, _ = self.make()
        for epoch in (None, True, 0, 2**53 + 1):
            with self.assertRaises(c.ConnectionError): lease.connect_p2p(old.info(), _checkpoint=lambda: False, _operation_epoch=epoch)
        self.assertIsNone(provider._connection); self.assertFalse(kernels)
        self.assertEqual(6, len(store._coordination._inventory))
    def test_actual_proc_lowest_fd_reuse_preserves_close_receipt_multiplicity(self):
        lease, provider, _, _, kernels, _ = self.make(lowest_fd=True)
        self.assertTrue(self.connect(lease).public_summary()['connection_observed']); self.closed(provider)
        for reader, observer in kernels:
            for row in reader.proc_readers:
                original = row['reader']; self.assertGreater(original._files, 1)
                self.assertEqual(original._files, len(original._fd_refs))
                self.assertEqual({11}, set(fd for fs, fd in original._fd_refs))
                actual = [r for r in reader.closed_receipts if r[2] is original]
                self.assertEqual(original._files, len(actual))
                self.assertTrue(all(provider._closed_fd(fs, fd, owner) for fs, fd, owner in actual))
    def test_station_mac_uses_status_bssid_not_ble_mac_closed_business_failure(self):
        lease, provider, _, _, _, _ = self.make(rows=packets(peers=[station(mac=old.MAC)]))
        self.reject(lease, 'kernel_unverified'); self.closed(provider)
        provider._begin(10)  # Semantic mismatch did not invent unknown resources.
    def test_missing_flag_mask_not_authorized_closed_business_failure(self):
        lease, provider, _, _, _, _ = self.make(rows=packets(peers=[station(mask=None)]))
        self.reject(lease, 'kernel_unverified'); self.closed(provider)
    def test_empty_station_dump_remains_unknown_not_status_proof(self):
        lease, provider, _, _, _, _ = self.make(rows=packets(peers=[]))
        self.reject(lease, 'kernel_unverified'); self.closed(provider)
    def test_actual_role_go_and_missing_frequency_cannot_sign(self):
        lease, provider, _, _, _, _ = self.make(rows=packets(face=interface(role=9)))
        self.reject(lease, 'channel_unverified'); self.closed(provider)
    def test_missing_actual_frequency_cannot_sign(self):
        lease, provider, _, _, _, _ = self.make(rows=packets(face=interface(frequency=None)))
        self.reject(lease, 'channel_unverified'); self.closed(provider)
    def test_two_round_kernel_peer_change_does_not_reuse_first_proof(self):
        lease, provider, _, _, kernels, _ = self.make(rows=lambda n: packets(peers=[station(values=0xa2 if n == 0 else 0x82)]))
        self.reject(lease, 'kernel_unverified'); self.assertEqual(2, len(kernels)); self.closed(provider)
    def test_distinct_actual_channels_need_raw_combo_channels_two(self):
        lease, provider, _, io, _, _ = self.make(rows=packets(face=interface(frequency=2437)), caps=caps_packets(channels=2))
        io.status_wire = old.CONNECTED.replace(b'freq=2412', b'freq=2437')
        io.group_wire = old.GROUP.replace(b'freq=2412', b'freq=2437')
        self.assertTrue(self.connect(lease).public_summary()['connection_observed'])
        self.closed(provider)
    def test_one_channel_combo_rejects_real_sta_client_distinct_frequencies(self):
        lease, provider, _, io, _, _ = self.make(rows=packets(face=interface(frequency=2437)))
        io.status_wire = old.CONNECTED.replace(b'freq=2412', b'freq=2437')
        io.group_wire = old.GROUP.replace(b'freq=2412', b'freq=2437')
        self.reject(lease, 'channel_unverified'); self.closed(provider)
    def test_shared_limit_retained_no_additional_empty_client(self):
        lease, provider, _, _, _, _ = self.make(caps=caps_packets(limit=1))
        self.reject(lease, 'channel_unverified'); self.closed(provider)
    def test_second_raw_caps_changed_cannot_sign(self):
        lease, provider, _, _, _, caps = self.make(caps=lambda n: caps_packets(channels=1 if n == 0 else 2))
        self.reject(lease, 'kernel_mismatch'); self.assertEqual(2, len(caps)); self.closed(provider)
    def test_kernel_cancellation_after_actual_packet_retains_raw_and_closes_once(self):
        flag = [False]
        def hook(provider, io, raw): flag[0] = True
        lease, provider, _, _, kernels, _ = self.make(hook=hook)
        with self.assertRaises(c.ConnectionError) as error:
            lease.connect_p2p(old.info(), _checkpoint=lambda: flag[0], _operation_epoch=EPOCH)
        self.assertEqual('cancelled', error.exception.code)
        self.assertTrue(provider.cancelled.is_set()); self.assertEqual('cancelled', provider._connection.reason)
        self.assertEqual(len(kernels[0][0].raw_datagrams), 1)
        self.assertEqual(kernels[0][1].raw.close_count, 1); self.closed(provider)
    def test_kernel_close_unknown_blocks_begin_and_proof_not_reclosed(self):
        lease, provider, _, _, kernels, _ = self.make(fail_close=True)
        self.reject(lease, 'kernel_unverified')
        row = provider._kernel_readers[0]; self.assertTrue(row['unknown'])
        before = tuple(kernels[0][1].close_calls)
        with self.assertRaises(p.LinuxProviderError) as error: provider._begin(10, True)
        self.assertEqual('resource_unknown', error.exception.code)
        self.assertFalse(all(closed for attempted, closed in provider._closed_objects()))
        self.assertEqual(before, tuple(kernels[0][1].close_calls))
    def test_exact_observer_receipts_known_live_generation_not_foreign_reuse(self):
        lease, provider, _, io, kernels, _ = self.make(); self.connect(lease)
        reader, observer = kernels[0]; original = next(r for r in reader.original_resources if r['kind'] == 'socket'); fd = original['fd']
        path = old.RUN + '/known-reuse'; io.add(path, stat.S_IFREG | 0o600)
        saved = io.fd; io.fd = fd - 1
        self.assertNotIn(fd, io.handles)
        current = provider._ledger.open(path, 0); io.fd = max(saved, io.fd)
        original_fstat = observer.fstat
        observer.fstat = lambda value: io.fstat(value) if value == fd else original_fstat(value)
        self.assertTrue(provider._closed_fd(observer, fd, original))
        foreign = current; provider._ledger.rows.remove(foreign)
        self.assertFalse(provider._closed_fd(observer, fd, original))
        provider._ledger.rows.append(foreign)
        self.assertEqual(fd, current.fd); self.assertFalse(current.attempted)
    def test_source_preserves_all_restore_caps_alias_bridge_defs_and_ast35(self):
        old_provider = (BASE / 'candidate/client-connect-v14/runtime/mta_client_linux_provider.py').read_bytes()
        self.assertEqual('4683e4ddc0e9b41adb44c028fb9dd102a63e3b62180e9f7e011fa1508414218c', hashlib.sha256(old_provider).hexdigest())
        old_tree = ast.parse(old_provider.decode()); new_tree = ast.parse((ROOT / 'mta_client_linux_provider.py').read_text(encoding='utf-8'))
        allowed = {'__init__', '_begin', 'status', '_closed_objects', 'connect_p2p'}
        for node in old_tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                target = next(n for n in new_tree.body if type(n) is type(node) and n.name == node.name)
                if isinstance(node, ast.FunctionDef): self.assertEqual(ast.dump(node), ast.dump(target))
                else:
                    for method in node.body:
                        if isinstance(method, ast.FunctionDef) and not (node.name == 'LinuxClientInitProvider' and method.name in allowed or node.name == 'LinuxClientInitLease' and method.name == 'connect_p2p'):
                            actual = next(n for n in target.body if isinstance(n, ast.FunctionDef) and n.name == method.name)
                            self.assertEqual(ast.dump(method), ast.dump(actual), (node.name, method.name))
        for path in (ROOT / 'mta_client_linux_provider.py', ROOT / 'mta_client_connection.py', Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(p.LinuxClientInitProvider().status()['receive_available'])


if __name__ == '__main__': unittest.main()
