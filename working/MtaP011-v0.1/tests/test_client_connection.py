"""New candidate methods only, real Store/ledger over explicit FakeIO.

No actual init/association/actors/kernel/locks/sockets or phone are validated.
Synthetic saved launch actors model an already admitted init journal.
"""
import ast
import errno
import hashlib
import importlib.util
import os
import socket
import stat
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'tests'))
from test_durable_client_store import StoreIo
from test_client_pending import Reader
from test_client_files import TOKEN, RUN
from test_client_journal_codec import baseline, IDENTITY, OWNED
from test_client_linux_provider import Sock, ClosedProc, Collector
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_pending as pending
import mta_client_store as stores
import mta_client_process_owner as processes
import mta_p2p_client_init as core
import mta_protocol as protocol

CANDIDATE = BASE / 'candidate/client-connection/runtime'
sys.path.insert(0, str(CANDIDATE))
spec = importlib.util.spec_from_file_location('connection_candidate_provider', str(CANDIDATE / 'mta_client_linux_provider.py'))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
import mta_client_connection as c

SSID = b'DIRECT-xy-fixture'
MAC = b'\x02\x11\x22\x33\x44\x55'
CONNECTED = (b'bssid=02:aa:bb:cc:dd:ee\nfreq=2412\nssid=' + SSID +
    b'\nid=0\nmode=station\npairwise_cipher=CCMP\ngroup_cipher=CCMP\n'
    b'key_mgmt=WPA2-PSK\nwpa_state=COMPLETED\naddress=02:66:77:88:99:aa\n'
    b'p2p_device_address=02:00:00:00:00:01\n')
GROUP = b'<3>P2P-GROUP-STARTED ' + OWNED.name.encode() + b' client ssid="' + SSID + b'" freq=2412 go_dev_addr=02:11:22:33:44:55 [PERSISTENT]'


def manifest():
    return p.ProviderManifest({'version': 1, 'run_token': TOKEN, 'candidate_sha': 'a' * 64,
        'ifname': OWNED.name, 'baseline_manifest': core.STOCK_PINS + ((p.baseline.CLI, 'b' * 64),),
        'status_manifest': {'daemon_exe': '/usr/sbin/wpa_supplicant', 'daemon_sha256': 'c' * 64,
            'endpoint': '/var/run/wpa_supplicant/wlan0', 'real_uid': 0, 'real_gid': 0,
            'namespace_kind': 'namespaces_disabled_cgroup_mnt', 'config_sha256': 'd' * 64},
        'wpa_exe': RUN + '/wpa_supplicant', 'wpa_sha': core.WPA_SHA,
        'python_exe': '/usr/bin/python3.5', 'python_sha': 'e' * 64,
        'executor_path': RUN + '/mta_client_executor.py', 'executor_sha': 'f' * 64}, _manifest_sha256='1' * 64)


def info(): return protocol.P2pInfo(SSID.decode(), 'fixture-passphrase', '02:11:22:33:44:55', 12345)


class Io(StoreIo):
    FLAGS = dict(StoreIo.FLAGS, O_NOFOLLOW=0x8000, O_DIRECTORY=0x4000)
    def __init__(self):
        StoreIo.__init__(self)
        self.add(RUN + '/ctrl', stat.S_IFDIR | 0o700)
        self.add(RUN + '/ctrl/' + OWNED.name, stat.S_IFSOCK | 0o770)
        self.add('/sys/class/net/' + OWNED.name + '/flags', data=b'0x1\n')
        self.sockets, self.queue_event, self.command_hook = [], [], None
        self.status_wire, self.group_wire, self.add_wire = CONNECTED, GROUP, b'0\n'
        self.actor_alive, self.changed_baseline, self.changed_origin = True, False, False
        self.disconnected = False
    def open(self, path, flags): return self._open(path, flags, 0)
    def fstat(self, fd):
        value = StoreIo.fstat(self, fd); value.st_rdev = 0; return value
    def stat(self, path):
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST')
        return self.nodes[path].metadata()
    def pid(self): return 123
    def cmsg_space(self, n): return 16 + ((n + 3) & ~3)
    def new_ctrl(self):
        path = RUN + '/fake-channel-' + str(len(self.sockets))
        self.add(path, stat.S_IFSOCK | 0o600)
        raw = CtrlSock(self, self._open(path, 0, 0), 'ctrl')
        self.sockets.append(raw); return raw


class CtrlSock(Sock):
    def send(self, raw):
        self.sent.append(raw)
        if self.io.command_hook: self.io.command_hook(self, raw)
        if raw == b'ATTACH': reply = b'OK\n'
        elif raw == b'ADD_NETWORK': reply = self.io.add_wire
        elif raw == b'STATUS': reply = b'wpa_state=DISCONNECTED\n' if self.io.disconnected else self.io.status_wire
        elif raw == b'DISCONNECT': self.io.disconnected = True; reply = b'OK\n'
        else: reply = b'OK\n'
        self.queue.append((reply, [(1, 2, p._CRED.pack(300, 0, 0))], 0, self.peer))
        if raw.startswith(b'P2P_GROUP_ADD'):
            self.io.sockets[1].queue.extend(self.io.queue_event or [(self.io.group_wire,
                [(1, 2, p._CRED.pack(300, 0, 0))], 0, self.peer)])
        return len(raw)
    def recvmsg(self, *args):
        if not self.queue:
            if self.timeout == 0: raise BlockingIOError(errno.EAGAIN, 'HOST')
            self.io.clock.value += .21
            raise socket.timeout('HOST')
        return self.queue.pop(0)


class Proc(ClosedProc):
    def observation(self, expected=None, absent=False):
        if expected is not None and expected.pid == 300 and not self.io.actor_alive:
            raise OSError(errno.ESRCH, 'HOST')
        return ClosedProc.observation(self, expected, absent)
    def __init__(self, io, **kwargs):
        self.io = io; ClosedProc.__init__(self, io, **kwargs)
    def read_self(self):
        return self.observation(core.Actor(123, 300, '/usr/bin/python3', 'b' * 64, ((123, 300, 'S'),)))


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        p._OWNERS[:] = []
        self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
        for target in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for cls in (coordination._LinuxIo, files._LinuxIo, pending._LinuxIo):
            patcher = mock.patch.object(cls, 'open_root', side_effect=AssertionError('actual root forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
    def make(self):
        io, reader = Io(), Reader(); reader.boot = baseline().boot
        store = stores.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock)
        self.addCleanup(store.close)
        provider = p.LinuxClientInitProvider(manifest(), _io=io, _clock=io.clock,
            _proc_factory=lambda **kw: Proc(io, **kw), _collector_factory=Collector)
        owner = processes.DirectChildOwner(_clock=io.clock)
        bridge = p.LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
        lease = p.LinuxClientInitLease(provider, store, IDENTITY, io.clock, bridge)
        provider.attach(store, owner, bridge, lease)
        locks = store.acquire(IDENTITY, 3)
        journal = store.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 10))
        tickets, actors = {}, {}
        for role, pid in (('watchdog', 200), ('controller', 300)):
            spec = bridge.specs[role]
            tickets[role] = core.Ticket(('1' if role == 'watchdog' else '2') * 32, role, baseline().boot, spec.exe, spec.argv_sha)
            actors[role] = core.Actor(pid, 30, spec.exe, spec.argv_sha, ((pid, 30, 'S'),))
            child = owner.register(spec, locks._device.fd, 10)
            child.postexec, child.pid = actors[role], pid
            lease.handles[role] = core.Handle(tickets[role], actors[role], child)
        interface = core.InterfaceTicket(baseline().boot, 0, OWNED.name, 1, 900)
        changes = (dict(stage='watchdog_intent', watchdog_ticket=tickets['watchdog']),
            dict(stage='watchdog_saved', watchdog=actors['watchdog']),
            dict(stage='interface_intent', interface_ticket=interface), dict(stage='interface_owned', owned=OWNED),
            dict(stage='controller_intent', controller_ticket=tickets['controller']),
            dict(stage='controller_saved', controller=actors['controller']), dict(stage='client_init_ready', ready=True))
        for change in changes: journal = store.commit(locks, journal.replace(**change))
        provider._tickets, provider._owned = tickets, OWNED
        provider._self, provider._boot = reader.actor, baseline().boot
        provider._baseline_record = baseline()
        b = baseline()
        provider.fake_snapshot = core.Snapshot(b.boot, b.stock_hashes, b.stock_actors, b.station,
            b.station_state_sha, b.station_frequency, b.interfaces + (OWNED,), b.ipv4,
            b.ipv6_addresses, b.ipv6_routes, b.station_completed)
        provider._kernel.interfaces = lambda deadline: (() if io.changed_origin else provider.fake_snapshot.interfaces)
        provider._anchors(3)
        provider._ctrl = provider._ledger.sock(io.new_ctrl)
        provider._ctrl_setup = True
        raw = provider._ctrl.value; raw.setsockopt(1, 16, 1)
        local = b'\0p011-client-' + TOKEN.encode(); raw.bind(local)
        endpoint = provider.manifest.ctrl_dir + '/' + OWNED.name; raw.connect(endpoint)
        provider._ctrl_endpoint = (endpoint, p.baseline._metadata(io.stat(endpoint)), local)
        lease.record, lease.locks = journal, locks
        store.active_return(locks, journal)
        self.addCleanup(provider._ledger.close_all)
        return lease, provider, store, io
    def reject(self, lease, value=None):
        with self.assertRaises(Exception): lease.connect_p2p(info() if value is None else value)
        self.assertIsNotNone(lease.provider._connection)
        self.assertTrue(lease.provider._connection.failed)
    def test_real_store_handoff_fixed_commands_authenticated_group_and_two_status(self):
        lease, provider, store, io = self.make(); device = lease.locks._device
        observation = lease.connect_p2p(info())
        self.assertIs(type(observation), c.ConnectionObservation)
        self.assertIs(lease.locks._device, device); self.assertTrue(lease._restore_held)
        self.assertEqual(7, len(store._coordination._inventory))
        self.assertEqual([b'ATTACH'], io.sockets[1].sent)
        commands = io.sockets[0].sent
        self.assertEqual(b'ADD_NETWORK', commands[0]); self.assertEqual(b'P2P_GROUP_ADD persistent=0', commands[-3])
        self.assertEqual([b'STATUS', b'STATUS'], commands[-2:])
        self.assertFalse(any(b'SAVE_CONFIG' in wire or b'SCAN' == wire for wire in commands))
        self.assertFalse(observation.public_summary()['dhcp_proof_issued'])
        self.assertFalse(provider.status()['send_available'])
        self.assertLess(len(store._files._inventory), files.MAX_RESOURCES)
    def test_constructor_unavailable_and_exact_protocol_revalidation(self):
        self.assertFalse(p.LinuxClientInitProvider().status()['send_available'])
        for bad in ({'ssid': 'x'}, protocol.P2pInfo('test', 'password1', '02:11:22:33:44:55', 8)):
            if type(bad) is protocol.P2pInfo: bad.key = 'encrypted'
            with self.assertRaises(c.ConnectionError): c._info(bad)
        bad = info(); bad.port = True
        with self.assertRaises(c.ConnectionError): c._info(bad)
    def test_cancellation_before_reacquire_zero_new_socket_and_handoff(self):
        lease, provider, store, io = self.make(); provider.cancelled.set()
        self.reject(lease)
        self.assertEqual(6, len(store._coordination._inventory)); self.assertEqual(1, len(io.sockets))
    def test_reacquire_then_cancel_restore_does_not_acquire_twice(self):
        lease, provider, store, io = self.make()
        original = store.acquire; calls = []
        def acquire(*args):
            calls.append(args); returned = original(*args); provider.cancelled.set(); return returned
        store.acquire = acquire
        self.reject(lease); self.assertTrue(lease._restore_held)
        provider.cancelled.clear()
        bridge = provider._bridge
        bridge.cleanup = lambda *args: (_ for _ in ()).throw(OSError(errno.EIO, 'HOST cleanup stop'))
        lease.restore(); self.assertEqual(1, len(calls))
        self.assertEqual('cleanup_intent', lease.record.stage); self.assertFalse(lease.cleanup_complete)
    def test_handoff_unknown_retains_old_new_refs_no_command(self):
        lease, provider, store, io = self.make(); old = lease.locks
        original = store.acquire
        def broken(*args): original(*args); raise OSError(errno.EIO, 'HOST post-return')
        store.acquire = broken
        self.reject(lease)
        self.assertIs(lease.locks, old); self.assertIsNot(store._current_locks, old)
        self.assertFalse(lease._restore_held); self.assertEqual([], io.sockets[0].sent)
    def test_unknown_network_id_no_set_or_guessed_remove(self):
        lease, provider, store, io = self.make(); io.add_wire = b'FAIL\n'; self.reject(lease)
        self.assertEqual([b'ADD_NETWORK'], io.sockets[0].sent)
        self.assertIsNone(provider._connection.network_id)
    def test_command_fail_keeps_owned_journal_and_original_sockets_for_restore(self):
        lease, provider, store, io = self.make()
        def hook(raw, command):
            if command.startswith(b'SET_NETWORK'): raw.queue.append((b'FAIL\n', [(1, 2, p._CRED.pack(300, 0, 0))], 0, raw.peer))
        io.command_hook = hook; self.reject(lease)
        self.assertEqual(OWNED.key(), store.current(lease.locks).owned.key())
        self.assertEqual(0, sum(raw.close_calls for raw in io.sockets))
    def test_wrong_event_credential_rejected_no_observation(self):
        lease, provider, store, io = self.make()
        io.queue_event = [(GROUP, [(1, 2, p._CRED.pack(999, 0, 0))], 0, provider._ctrl_endpoint[0])]
        self.reject(lease); self.assertIsNone(provider._connection.result)
    def test_rights_rejected_retained_and_closed_once_by_original_ledger(self):
        lease, provider, store, io = self.make()
        fd = io.open('/', p.ARM_DIR)
        io.queue_event = [(GROUP, [(1, 2, p._CRED.pack(300, 0, 0)), (1, 1, struct.pack('=i', fd))], 0, provider._ctrl_endpoint[0])]
        self.reject(lease)
        self.assertEqual(1, len(provider._ctrl_rights)); self.assertEqual(fd, provider._ctrl_rights[0].fd)
        self.assertTrue(provider._ledger.close_all()); before = list(io.closed)
        self.assertTrue(provider._ledger.close_all()); self.assertEqual(before, io.closed)
    def test_truncation_unknown_is_sticky_even_after_known_socket_close(self):
        lease, provider, store, io = self.make()
        io.queue_event = [(GROUP, [(1, 2, p._CRED.pack(300, 0, 0))], 32, provider._ctrl_endpoint[0])]
        self.reject(lease); self.assertTrue(provider._ctrl_receive_unknown)
        provider._ledger.close_all(); self.assertFalse(provider._proof().complete())
    def test_stale_group_before_group_command_cannot_be_used(self):
        lease, provider, store, io = self.make()
        def hook(raw, wire):
            if wire == b'ATTACH':
                # Reply precedes an already queued old event.
                raw.queue.extend([(b'OK\n', [(1, 2, p._CRED.pack(300, 0, 0))], 0, raw.peer),
                    (GROUP, [(1, 2, p._CRED.pack(300, 0, 0))], 0, raw.peer)])
        io.command_hook = hook; self.reject(lease)
        self.assertEqual([], io.sockets[0].sent)
    def test_wrong_group_role_name_ssid_frequency_or_key_rejected(self):
        for old, new in ((b' client ', b' GO '), (OWNED.name.encode(), b'mta00000000'),
                (SSID, b'DIRECT-other'), (b'freq=2412', b'freq=5200'),
                (b' [PERSISTENT]', b' psk=' + b'0' * 64)):
            p._OWNERS[:] = []
            lease, provider, store, io = self.make(); io.group_wire = GROUP.replace(old, new)
            self.reject(lease); self.assertIsNone(provider._connection.result)
    def test_zero_or_mismatched_remote_mac_observed_not_dhcp_proof(self):
        for mac in (b'00:00:00:00:00:00', b'02:00:00:00:00:09'):
            p._OWNERS[:] = []
            lease, provider, store, io = self.make()
            io.group_wire = GROUP.replace(b'02:11:22:33:44:55', mac)
            result = lease.connect_p2p(info())
            self.assertFalse(result.public_summary()['peer_mac_hint_matches'])
            self.assertFalse(result.public_summary()['dhcp_proof_issued'])
    def test_status_local_p2p_mac_does_not_replace_remote_go(self):
        lease, provider, store, io = self.make(); result = lease.connect_p2p(info())
        self.assertEqual(MAC, result._event.private_fields()['go_dev_addr'])
        self.assertNotEqual(MAC, result._statuses[0].private_fields()['p2p_device_address'])
    def test_completed_wrong_network_security_or_new_ip_cannot_observe(self):
        for old, new in ((b'id=0', b'id=1'), (b'CCMP', b'TKIP'),
                (b'wpa_state=COMPLETED\n', b'wpa_state=COMPLETED\nip_address=192.168.49.2\n')):
            p._OWNERS[:] = []
            lease, provider, store, io = self.make(); io.status_wire = CONNECTED.replace(old, new)
            self.reject(lease)
    def test_changed_original_baseline_rejects_before_add(self):
        lease, provider, store, io = self.make()
        b = provider.fake_snapshot
        provider.fake_snapshot = core.Snapshot(b.boot, b.stock_hashes, b.stock_actors, b.station,
            '0' * 64, b.station_frequency, b.interfaces, b.ipv4, b.ipv6_addresses, b.ipv6_routes, True)
        self.reject(lease); self.assertEqual([], io.sockets[0].sent)
    def test_replaced_endpoint_and_actor_or_origin_fail_authentication(self):
        for fault in ('endpoint', 'actor', 'origin'):
            p._OWNERS[:] = []
            lease, provider, store, io = self.make()
            def hook(raw, wire):
                if wire == b'ATTACH':
                    if fault == 'endpoint': io.nodes[provider._ctrl_endpoint[0]].ino += 1
                    elif fault == 'actor': io.actor_alive = False
                    else: io.changed_origin = True
            io.command_hook = hook; self.reject(lease)
            self.assertEqual([], io.sockets[0].sent)
    def test_fresh_readback_distinct_and_old_receipt_not_reusable(self):
        lease, provider, store, io = self.make(); first = lease.connect_p2p(info())
        second = lease.read_connection(first)
        self.assertIsNot(first, second)
        with self.assertRaises(c.ConnectionError): lease.read_connection(first)
    def test_disconnect_is_observation_not_restore_or_completion(self):
        lease, provider, store, io = self.make(); observation = lease.connect_p2p(info())
        result = lease.disconnect_p2p()
        self.assertTrue(result['disconnect_observed']); self.assertFalse(result['restored'])
        self.assertIn(b'DISCONNECT', io.sockets[0].sent)
        with self.assertRaises(c.ConnectionError): lease.read_connection(observation)
        self.assertEqual('client_init_ready', store.current(lease.locks).stage)
    def test_group_removed_between_status_samples_revokes_observation(self):
        lease, provider, store, io = self.make(); statuses = []
        def hook(raw, wire):
            if wire == b'STATUS':
                statuses.append(wire)
                if len(statuses) == 1: io.sockets[1].queue.append((b'<3>P2P-GROUP-REMOVED ' + OWNED.name.encode() + b' client reason=REQUESTED', [(1, 2, p._CRED.pack(300, 0, 0))], 0, raw.peer))
        io.command_hook = hook; self.reject(lease)
    def test_original_ttl_not_extended_and_cancel_checked_after_reply(self):
        lease, provider, store, io = self.make()
        io.command_hook = lambda raw, wire: setattr(io.clock, 'value', 10.) if wire.startswith(b'SET_NETWORK') else None
        self.reject(lease); self.assertEqual(10, lease.record.deadline)
        self.assertFalse(any(w.startswith(b'P2P_GROUP_ADD') for w in io.sockets[0].sent))
    def test_second_connect_and_arbitrary_command_rejected(self):
        lease, provider, store, io = self.make(); lease.connect_p2p(info())
        with self.assertRaises(c.ConnectionError): lease.connect_p2p(info())
        operation = provider._connection
        with self.assertRaises(p.LinuxProviderError): provider._connection_exchange(operation, b'SCAN', operation.deadline)
        self.assertNotIn(b'SCAN', io.sockets[0].sent)
    def test_late_event_factory_unknown_reference_retained_no_retry(self):
        lease, provider, store, io = self.make()
        def unknown(): io.new_ctrl_original(); raise KeyboardInterrupt('HOST after resource')
        io.new_ctrl_original = io.new_ctrl; io.new_ctrl = unknown
        with self.assertRaises(KeyboardInterrupt): lease.connect_p2p(info())
        self.assertTrue(provider._ledger.pending); self.assertTrue(provider._connection_event_requested)
        self.assertEqual(2, len(io.sockets)); self.assertFalse(provider._ledger.close_all())
    def test_python35_and_original_restore_byte_preservation(self):
        original = (BASE / 'runtime/mta_client_linux_provider.py').read_text(encoding='utf-8')
        candidate = (CANDIDATE / 'mta_client_linux_provider.py').read_text(encoding='utf-8')
        def body(source, cls, name):
            tree = ast.parse(source, feature_version=(3, 5))
            item = next(n for n in tree.body if type(n) is ast.ClassDef and n.name == cls)
            return ast.dump(next(n for n in item.body if type(n) is ast.FunctionDef and n.name == name), include_attributes=False)
        self.assertEqual(body(original, 'LinuxClientInitLease', 'restore'), body(candidate, 'LinuxClientInitLease', 'restore'))
        for name in ('mta_client_connection.py', 'mta_client_linux_provider.py'):
            ast.parse((CANDIDATE / name).read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertEqual('8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544', hashlib.sha256((BASE / 'runtime/mta_client_linux_provider.py').read_bytes()).hexdigest())


if __name__ == '__main__': unittest.main()
