"""HOST FakeIO only; no real sockets, processes, /tmp or P011 calls."""
import ast
import copy
import errno
import os
import stat
import struct
import sys
import types
import unittest
from unittest import mock

RUNTIME = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime'))
sys.path.insert(0, RUNTIME)
import mta_client_linux_provider as p
import mta_client_baseline as base
import mta_client_coordination as coord
import mta_client_files as files
import mta_client_proc as proc
import mta_client_process_owner as owner
import mta_client_store as stores
import mta_client_two_phase_lease as phases
import mta_ip as ip
import mta_p2p_client_init as core
from test_client_files import FakeIo, TOKEN, RUN
from test_client_launch_registration import SidecarIo, CompositeReader
from test_client_proc import FakeFs
from test_p2p_client_init import snapshot, STATUS, OWN, BOOT, caps
from test_client_caps import phy, combo


def manifest():
    return p.ProviderManifest({'version': 1, 'run_token': TOKEN, 'candidate_sha': 'a' * 64,
        'ifname': OWN.name, 'baseline_manifest': core.STOCK_PINS + ((base.CLI, 'b' * 64),),
        'status_manifest': {'daemon_exe': '/usr/sbin/wpa_supplicant', 'daemon_sha256': 'c' * 64,
            'endpoint': '/var/run/wpa_supplicant/wlan0', 'real_uid': 0, 'real_gid': 0,
            'namespace_kind': 'namespaces_disabled_cgroup_mnt', 'config_sha256': 'd' * 64},
        'wpa_exe': RUN + '/wpa_supplicant', 'wpa_sha': core.WPA_SHA,
        'python_exe': '/usr/bin/python3.5', 'python_sha': 'e' * 64,
        'executor_path': RUN + '/mta_client_executor.py', 'executor_sha': 'f' * 64},
        _manifest_sha256='1' * 64)


class Io(FakeIo):
    FLAGS = dict(FakeIo.FLAGS, O_NOFOLLOW=0x8000, O_DIRECTORY=0x4000)
    def __init__(self):
        FakeIo.__init__(self)
        self.add(RUN + '/ctrl', stat.S_IFDIR | 0o700)
        self.add(RUN + '/ctrl/' + OWN.name, stat.S_IFSOCK | 0o770)
        self.add('/sys/class/net/' + OWN.name + '/flags', data=b'0x0\n')
        self.socket_hook, self.sockets, self.signals = None, [], []
    def open(self, path, flags): return self._open(path, flags, 0)
    def fstat(self, fd):
        value = FakeIo.fstat(self, fd)
        value.st_rdev = 0  # os.stat_result supplies this; original Fake did not.
        return value
    def stat(self, path):
        self.event('stat', path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST')
        return self.nodes[path].metadata()
    def listdir(self, path):
        if path == '/proc': return ['100', '300', '999']
        return [coord.RUN_PREFIX + TOKEN]
    def pid(self): return 100
    def cmsg_space(self, n): return 16 + ((n + 3) & ~3)
    def new_genl(self): return self.make_socket('genl')
    def new_ctrl(self): return self.make_socket('ctrl')
    def make_socket(self, kind):
        path = RUN + '/HOST-raw-' + str(len(self.sockets))
        self.add(path, stat.S_IFSOCK | 0o600)
        raw = Sock(self, self._open(path, 0, 0), kind)
        self.sockets.append(raw)
        if self.socket_hook: self.socket_hook(raw)
        return raw
    def kill(self, pid): self.signals.append(pid)
    def getpid(self): return 100
    def set_inheritable(self, fd, value):
        if not hasattr(self, 'inherits'): self.inherits = {}
        self.inherits[fd] = value
    def get_inheritable(self, fd): return self.inherits.get(fd, False)


class Sock(object):
    def __init__(self, io, fd, kind):
        self.io, self.fd, self.original, self.kind = io, fd, fd, kind
        self.local, self.peer, self.timeout, self.inherit = None, None, None, False
        self.passcred, self.queue, self.sent, self.close_calls = 0, [], [], 0
        self.respond = None
    def fileno(self): return self.fd
    def set_inheritable(self, v): self.inherit = v
    def get_inheritable(self): return self.inherit
    def bind(self, v): self.local = (900, 0) if v == (0, 0) else v
    def getsockname(self): return self.local
    def connect(self, v): self.peer = v
    def getpeername(self): return self.peer
    def setsockopt(self, *a): self.passcred = a[-1]
    def getsockopt(self, *a): return self.passcred
    def settimeout(self, t): self.timeout = t
    def gettimeout(self): return self.timeout
    def send(self, raw): self.sent.append(raw); return len(raw)
    def sendto(self, raw, destination):
        self.sent.append(raw)
        if self.respond: self.queue.extend(self.respond(raw))
        return len(raw)
    def recvmsg(self, *args):
        if not self.queue: raise OSError(errno.ETIMEDOUT, 'HOST timeout')
        return self.queue.pop(0)
    def close(self):
        self.close_calls += 1
        self.io.close(self.fd); self.fd = -1


class ClosedProc(object):
    def __init__(self, io, value=None, absent=False, count=1, **kwargs):
        self._fd_refs, self._files, self._closed, self._pending = [], count, count, False
        self.value, self.absent = value, absent
        for unused in range(count):
            fd = io.open('/', p.ARM_DIR); self._fd_refs.append((io, fd)); io.close(fd)
    def read_self(self): return self.observation()
    def read_actor(self, pid, expected=None): return self.observation(expected)
    def read_absence(self, value, boot): return self.observation(None, True)
    def observation(self, expected=None, absent=False):
        actual = self.value or expected or core.Actor(100, 10, '/usr/bin/python3.5', '2' * 64, ((100, 10, 'S'),))
        return proc.ProcObservation('absence' if absent or self.absent else 'live_actor', '', 'HOST_ONLY', BOOT,
            None if absent or self.absent else actual, absent or self.absent, (), True, 2, (), self._files,
            self._closed, self._pending, 0 if absent else len(actual.tasks))


class Collector(object):
    def __init__(self, provider, timeout):
        self.p, self._io, self._tickets, self.status_readers = provider, provider._io, [], []
        self._reader = ClosedProc(provider._io)
        self._ended = False
    def collect(self, deadline):
        self._ended = True
        b = self.p.fake_snapshot
        return core.Snapshot(b.boot, b.stock_hashes, b.stock_actors, b.station, b.station_state_sha,
            b.station_frequency, b.interfaces, b.ipv4, b.ipv6_addresses, b.ipv6_routes, b.station_completed)
    def status(self): return {'read_success': True, 'resource_pending': False, 'resource_count': 0, 'closed_count': 0}


class Caps(object):
    def __init__(self, phy, socket_factory, **kwargs):
        self.creator, self._finished, self._created, self._socket = socket_factory, False, False, None
    def read(self):
        self._socket = self.creator(16, 3, 16); self._created = True
        try: return p.caps_transport.caps.decode_wiphy_projection((phy(commands=(7, 8)),))
        finally: self._socket.close(); self._finished = True
    def status(self): return {'read_success': True, 'resource_pending': False, 'socket_closed': True}


def origin_bytes(value):
    return b''.join((p._attr(1, struct.pack('<I', value.phy)), p._attr(153, struct.pack('<Q', value.wdev)),
        p._attr(3, struct.pack('<I', value.ifindex)), p._attr(4, value.name.encode('ascii') + b'\0'),
        p._attr(5, struct.pack('<I', value.iftype))))


def frame(request, kind, body, flags=0, wrong_seq=False, wrong_port=False):
    n, family, sentflags, seq, port = p._NL.unpack(request[:16])
    raw = p._NL.pack(16 + len(body), kind, flags, seq + int(wrong_seq), port + int(wrong_port)) + body
    return (raw + b'\0' * (-len(raw) % 4), [], 0, (0, 0))


class LinuxProviderTests(unittest.TestCase):
    def setUp(self):
        p._OWNERS[:] = []
        for target in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open', 'os.kill'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
    def make(self, **options):
        io = Io()
        provider = p.LinuxClientInitProvider(manifest(), _io=io, _clock=lambda: 1.,
            _proc_factory=lambda **kw: ClosedProc(io, **kw), _collector_factory=Collector, **options)
        provider._store = types.SimpleNamespace(_current_locks=None, lock_valid=lambda locks: True)
        provider._boot, provider._baseline_record, provider.fake_snapshot = BOOT, snapshot(), snapshot(OWN)
        return provider, io
    def kernel(self, replies):
        provider, io = self.make()
        raw = io.new_genl(); raw.local = (900, 0); raw.respond = replies
        row = provider._ledger.new('socket'); provider._ledger.adopt(row, raw)
        k = provider._kernel; k.row, k.family, k.port = row, 30, 900
        return provider, io, k
    def ctrl(self, flags=0, controls=None):
        provider, io = self.make()
        provider._owned = OWN
        actor = core.Actor(300, 30, provider.manifest.wpa_exe, '3' * 64, ((300, 30, 'S'),))
        handle = types.SimpleNamespace(actor=actor)
        provider.live_actor = lambda *a: actor
        endpoint = provider.manifest.ctrl_dir + '/' + OWN.name
        controls = [(1, 2, p._CRED.pack(300, 0, 0))] if controls is None else controls
        io.socket_hook = lambda raw: raw.queue.append((STATUS, controls, flags, endpoint))
        provider._anchors(3.)
        return provider, io, handle

    def test_default_constructor_and_status_no_io(self):
        value = p.LinuxClientInitProvider()
        self.assertFalse(value.status()['attempted'])
        with self.assertRaises(p.LinuxProviderError): value.executor(3.)
        self.assertEqual(value._ledger.rows, [])
    def test_pure_assembly_new_lease_and_refs(self):
        values = p.assemble(manifest())
        self.assertIs(type(values[4]), p.LinuxClientInitLease)
        self.assertIs(values[4].provider, values[0]); self.assertIs(values[4].store, values[1])
        self.assertIs(values[4].bridge, values[3]); self.assertEqual(values[0]._ledger.rows, [])
    def test_new_bridge_lease_attach_exact_owner_binding(self):
        first, other = p.LinuxClientInitProvider(manifest()), p.LinuxClientInitProvider(manifest())
        store = stores.DurableClientInitStore(TOKEN, first.manifest.identity)
        actual_owner = owner.DirectChildOwner()
        bridge = p.LinuxDirectChildLaunchBridge(store, actual_owner, first.specs(), first)
        with self.assertRaises(core.ClientInitError):
            p.LinuxClientInitLease(other, store, other.manifest.identity, lambda: 1., bridge)
        with self.assertRaises(p.LinuxProviderError): other.attach(store, actual_owner, bridge)
        with self.assertRaises(p.LinuxProviderError): first.attach(store, actual_owner, bridge, object())
        self.assertIsNone(first._store); self.assertIsNone(other._store)
    def test_manifest_immutable_and_private_repr(self):
        value = manifest()
        with self.assertRaises(AttributeError): value.ifname = 'wlan0'
        self.assertNotIn(TOKEN, repr(value)); self.assertNotIn(value.run_dir, repr(value))
    def test_specs_exact_wpa_config_and_watchdog_ttl(self):
        provider, io = self.make(); watchdog, controller = provider.specs()
        self.assertEqual(watchdog.argv[-2:], ('--ttl', '20'))
        self.assertEqual(controller.env, (('MTA_PRIVATE_P2P', '1'),))
        self.assertEqual(controller.sha, core.WPA_SHA)
        self.assertFalse(any('scan' in x.lower() or 'group_add' in x.lower() for x in controller.argv))
    def test_backward_clock_and_boolean_deadline_rejected(self):
        provider, io = self.make()
        provider._last = 2
        with self.assertRaises(p.LinuxProviderError): provider._now(3)
        provider._last = None
        with self.assertRaises(p.LinuxProviderError): provider._now(True)
    def test_arm_baseline_open_override_only(self):
        with mock.patch.object(base.BaselineCollector, '_open', return_value='row') as called:
            value = object.__new__(p._AuthenticatedCollector)
            self.assertEqual(value._open('/fixed'), 'row')
            called.assert_called_once_with('/fixed', p.ARM_READ)
        self.assertEqual(p.ARM_DIR, 0x8c000)
    def test_negative_open_not_fabricated_close_attempt(self):
        provider, io = self.make()
        with self.assertRaises(OSError): provider._ledger.open('/absent', p.ARM_READ)
        row = provider._ledger.rows[0]
        self.assertFalse(row.returned); self.assertFalse(row.attempted)
        self.assertTrue(provider._ledger.close_all()); self.assertEqual(provider._proof().expected, 0)
    def test_unknown_open_blocks_new_action_retains_record(self):
        provider, io = self.make(); io.unknown_open = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): provider._ledger.open('/', p.ARM_DIR)
        self.assertTrue(provider._ledger.pending)
        with self.assertRaises(p.LinuxProviderError): provider.snapshot(3.)
        self.assertEqual(len(provider._ledger.rows), 1)
    def test_close_failure_independent_once_sticky(self):
        provider, io = self.make()
        a = provider._ledger.open('/', p.ARM_DIR); b = provider._ledger.open('/tmp', p.ARM_DIR)
        io.close_fail[a.fd] = OSError(errno.EIO, 'HOST')
        self.assertFalse(provider._ledger.close_all()); self.assertTrue(b.closed)
        calls = list(io.closed); provider._ledger.close_all(); self.assertEqual(io.closed, calls)
        self.assertTrue(a.unknown)
    def test_config_exact_excl_fsync_readback_no_update(self):
        provider, io = self.make(); provider._owned = OWN
        provider._prepare_config(3.)
        raw = io.nodes[provider.manifest.cfg].data
        self.assertEqual(raw, b'ctrl_interface=' + provider.manifest.ctrl_dir.encode('ascii') + b'\n' + core.CLIENT_CONFIG)
        self.assertNotIn(b'update_config', raw); self.assertTrue(provider._config.closed)
        with self.assertRaises(p.LinuxProviderError): provider._prepare_config(3.)
    def test_existing_config_never_overwritten(self):
        provider, io = self.make(); provider._owned = OWN
        io.add(provider.manifest.cfg, data=b'HOST-existing')
        with self.assertRaises(p.LinuxProviderError) as e: provider._prepare_config(3.)
        self.assertEqual(e.exception.code, 'config_exists')
        self.assertEqual(io.nodes[provider.manifest.cfg].data, b'HOST-existing')
    def test_anchor_replaced_rejected(self):
        provider, io = self.make(); provider._anchors(3.)
        io.nodes[RUN + '/ctrl'].ino += 1
        with self.assertRaises(p.LinuxProviderError): provider._verify_anchors(3.)
    def test_ctrl_exact_0770_root_endpoint_credential(self):
        provider, io, handle = self.ctrl()
        self.assertEqual(provider._control(handle, OWN, 3.), STATUS)
        self.assertEqual(io.sockets[0].sent, [b'STATUS'])
        self.assertFalse(provider._ctrl_receive_unknown)
    def test_ctrl_wrong_group_or_permission_rejected(self):
        for group, mode in ((10, 0o770), (0, 0o777), (0, 0o700)):
            provider, io, handle = self.ctrl()
            node = io.nodes[provider.manifest.ctrl_dir + '/' + OWN.name]; node.gid, node.mode = group, stat.S_IFSOCK | mode
            with self.assertRaises(p.LinuxProviderError): provider._control(handle, OWN, 3.)
            self.assertEqual(io.sockets[0].sent, [])
    def test_ctrl_wrong_credential_does_not_authenticate(self):
        provider, io, handle = self.ctrl(controls=[(1, 2, p._CRED.pack(999, 0, 0))])
        with self.assertRaises(p.LinuxProviderError): provider._control(handle, OWN, 3.)
        self.assertTrue(provider._ctrl_failed)
    def test_ctrl_rights_retained_closed_once_before_reject(self):
        provider, io, handle = self.ctrl()
        fd = io.open('/', p.ARM_DIR)
        io.socket_hook = lambda raw: raw.queue.append((STATUS, [(1, 1, struct.pack('=i', fd)),
            (1, 2, p._CRED.pack(300, 0, 0))], 0, provider.manifest.ctrl_dir + '/' + OWN.name))
        with self.assertRaises(p.LinuxProviderError): provider._control(handle, OWN, 3.)
        self.assertEqual(len(provider._ctrl_rights), 1)
        self.assertTrue(provider._ctrl_rights[0].closed)
        before = list(io.closed)
        with self.assertRaises(p.LinuxProviderError): provider._control(handle, OWN, 3.)
        self.assertEqual(io.closed, before)
    def test_ctrl_ctrunc_known_rights_close_unknown_sticky(self):
        provider, io, handle = self.ctrl(flags=8)
        with self.assertRaises(p.LinuxProviderError): provider._control(handle, OWN, 3.)
        self.assertTrue(provider._ctrl_receive_unknown)
    def test_ctrl_path_or_peer_change_rejected(self):
        provider, io, handle = self.ctrl()
        self.assertEqual(provider._control(handle, OWN, 3.), STATUS)
        provider._ctrl.value.peer = '/HOST/foreign'
        with self.assertRaises(p.LinuxProviderError): provider._control(handle, OWN, 3.)
    def test_create_requires_echo_and_ack(self):
        def replies(request):
            return [frame(request, 30, p._GENL.pack(7, 1, 0) + origin_bytes(OWN)),
                    frame(request, 2, b'\0' * 4 + request[:16])]
        provider, io, k = self.kernel(replies)
        rows = k.request(30, 7, b'', 4 | 8 | 0x600, 3.)
        self.assertEqual(rows[0][0], 7); self.assertEqual(p._origin(rows[0][1]).key(), OWN.key())
    def test_ack_without_echo_never_grants_origin(self):
        provider, io, k = self.kernel(lambda r: [frame(r, 2, b'\0' * 4 + r[:16])])
        with self.assertRaises(OSError): k.request(30, 7, b'', 4 | 8 | 0x600, 3.)
        self.assertIsNone(provider._owned)
    def test_wrong_ack_echo_seq_port_fail(self):
        for bad in ('seq', 'port', 'echo'):
            def response(r):
                body = b'\0' * 4 + (b'x' * 16 if bad == 'echo' else r[:16])
                return [frame(r, 2, body, wrong_seq=bad == 'seq', wrong_port=bad == 'port')]
            provider, io, k = self.kernel(response)
            with self.assertRaises(p.LinuxProviderError): k.request(30, 8, b'', 4, 3.)
    def test_error_ack_not_success(self):
        provider, io, k = self.kernel(lambda r: [frame(r, 2, struct.pack('<i', -5) + r[:16])])
        with self.assertRaises(p.LinuxProviderError) as e: k.request(30, 8, b'', 4, 3.)
        self.assertEqual(e.exception.code, 'kernel_error')
    def test_origin_full_tuple_no_guess(self):
        self.assertEqual(p._origin(origin_bytes(OWN)).key(), OWN.key())
        with self.assertRaises(p.LinuxProviderError): p._origin(origin_bytes(OWN) + p._attr(5, struct.pack('<I', 8)))
    def test_caps_real_factory_fd_close_ebadf(self):
        provider, io = self.make(_caps_factory=Caps)
        self.assertTrue(provider.caps(3.)['complete'])
        self.assertTrue(provider._caps_readers[0]['socket'].attempted)
        self.assertTrue(provider._proof().complete())
    def test_caps_closed_flag_alone_not_proof(self):
        provider, io = self.make(_caps_factory=Caps); provider.caps(3.)
        raw = provider._caps_readers[0]['socket']
        io.handles[raw.fd] = [io.nodes['/'], 0]
        self.assertFalse(provider._proof().complete())
    def test_caps_mapping_preserves_constraints_and_commands(self):
        codec = p.caps_transport.caps
        self.assertTrue(p._caps_core(codec.decode_wiphy_projection((phy(commands=(7, 8)),)))['complete'])
        for raw in (phy(commands=(7,)), phy(combinations=(combo(bi=None),), commands=(7, 8)),
                    phy(combinations=(combo(radar=(None, 0)),), commands=(7, 8))):
            with self.assertRaises(p.LinuxProviderError): p._caps_core(codec.decode_wiphy_projection((raw,)))
    def test_initial_proc_b_anchor_authorized_generation_reuse(self):
        io = SidecarIo(); reader = CompositeReader()
        store = stores.DurableClientInitStore(TOKEN, core.Identity('a' * 64), _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock)
        provider = p.LinuxClientInitProvider(manifest(), _io=io, _clock=io.clock)
        provider._store = store
        fd = io.open_root(io.flag('O_RDONLY')); io.close(fd); original = object()
        self.assertTrue(provider._remember(io, fd, original))
        io.fd = fd - 1
        locks = store.acquire(manifest().identity, 3.)
        self.assertEqual(store._coordination._anchors[0][0].fd, fd)
        self.assertTrue(provider._closed_fd(io, fd, original))
        self.assertFalse(store._coordination._anchors[0][0].attempted)
    def test_unknown_same_metadata_reuse_not_authorized(self):
        provider, io = self.make()
        fd = io.open('/', p.ARM_DIR); io.close(fd); original = object()
        self.assertTrue(provider._remember(io, fd, original))
        io.handles[fd] = [io.nodes['/'], 0]
        self.assertFalse(provider._closed_fd(io, fd, original))
        self.assertNotIn(fd, io.closed[len(io.closed):])
    def cleanup(self):
        provider, io = self.make(); provider._owned = OWN
        provider._kernel.interfaces = lambda deadline: (core.Origin(0, 1, 22, 'wlan0', 2), OWN)
        provider._bridge = types.SimpleNamespace(verify_closed=lambda: True)
        provider._owner = owner.DirectChildOwner(_clock=lambda: 1.)
        return provider, io
    def test_down_cleanup_full_origin_baseline_not_up(self):
        provider, io = self.cleanup()
        self.assertFalse(provider.origin_up(OWN, 3.))
        self.assertTrue(provider.cleanup_origin_ready(OWN, 3.))
    def test_cleanup_origin_changed_never_delete(self):
        provider, io = self.cleanup()
        provider._kernel.interfaces = lambda d: (core.Origin(0, OWN.wdev, OWN.ifindex, OWN.name, 9),)
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
    def test_cleanup_children_not_reaped_rejected(self):
        provider, io = self.cleanup(); ticket = owner.ChildTicket(provider._owner, provider.specs()[0], 100, 3.)
        ticket.fork_requested = True; provider._owner._tickets.append(ticket)
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
    def test_cleanup_bridge_not_closed_rejected(self):
        provider, io = self.cleanup(); provider._bridge.verify_closed = lambda: False
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
    def test_cleanup_original_network_changed_rejected(self):
        provider, io = self.cleanup(); provider.fake_snapshot = snapshot(OWN, sha='7' * 64)
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
    def test_cleanup_owned_ipv4_rejected(self):
        provider, io = self.cleanup()
        addr = ip.AddressRecord(OWN.ifindex, 0xc0a80101, 0xc0a80101, 24, 0x80, 0, None, None, (0xffffffff, 0xffffffff, 1, 1))
        provider.fake_snapshot = snapshot(OWN, ipv4=ip.IpSnapshot((addr,), (), snapshot().ipv4.rules))
        with self.assertRaises(core.ClientInitError): provider.cleanup_origin_ready(OWN, 3.)
    def test_cleanup_allowed_ipv6_exact_only(self):
        provider, io = self.cleanup()
        row = ('ff' + '0' * 30, '08', '0' * 32, '00', '0' * 32, '00000100', '00000000', '00000000', '00000001', OWN.name)
        provider.fake_snapshot = snapshot(OWN, ipv6_routes=(row,))
        self.assertTrue(provider.cleanup_origin_ready(OWN, 3.))
        with self.assertRaises(core.ClientInitError): snapshot(OWN, ipv6_routes=(row, row))
        bad = row[:1] + ('00',) + row[2:]
        provider.fake_snapshot = snapshot(OWN, ipv6_routes=(bad,))
        with self.assertRaises(core.ClientInitError): provider.cleanup_origin_ready(OWN, 3.)
    def ctrl_rmdir(self):
        provider, io = self.cleanup()
        io.nodes[RUN].links = 3; io.nodes[RUN + '/ctrl'].links = 2
        provider._anchors(3.)
        child = owner.ChildTicket(provider._owner, provider.specs()[1], 100, 3.)
        child.pid = 300; child.postexec = core.Actor(300, 30, child.spec.exe, child.spec.argv_sha, ((300, 30, 'S'),))
        child.fork_requested, child.waited, child.exit_verified = True, True, True
        provider._owner._tickets.append(child)
        io.nodes.pop(RUN + '/ctrl/' + OWN.name)
        gone = io.nodes.pop(RUN + '/ctrl'); gone.links = 0; io.nodes[RUN].links = 2
        return provider, io, child, gone
    def test_ctrl_deinit_rmdir_normal_original_fds_close(self):
        provider, io, child, gone = self.ctrl_rmdir()
        self.assertTrue(provider.cleanup_origin_ready(OWN, 3.))
        self.assertEqual(provider._ctrl_anchor.close_meta[5], 0)
        self.assertTrue(provider._ledger.close_all())
        self.assertTrue(all(provider._ledger.ebadf(r) for r in provider._ledger.rows))
    def test_ctrl_deinit_rmdir_without_waited_controller_rejected(self):
        provider, io, child, gone = self.ctrl_rmdir(); child.waited = False
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
        self.assertIsNone(provider._ctrl_anchor.close_meta)
    def test_ctrl_deinit_replaced_directory_rejected(self):
        provider, io, child, gone = self.ctrl_rmdir()
        io.add(RUN + '/ctrl', stat.S_IFDIR | 0o700)
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
    def test_ctrl_deinit_unrelated_nlink_change_rejected(self):
        provider, io, child, gone = self.ctrl_rmdir(); io.nodes[RUN].links = 1
        self.assertFalse(provider.cleanup_origin_ready(OWN, 3.))
    def test_private_child_filter_requires_actual_owner_actor(self):
        provider, io = self.make(); provider._owner = owner.DirectChildOwner(_clock=lambda: 1.)
        child = owner.ChildTicket(provider._owner, provider.specs()[1], 100, 3.)
        child.pid = 300; child.postexec = core.Actor(300, 30, child.spec.exe, child.spec.argv_sha, ((300, 30, 'S'),))
        provider._owner._tickets.append(child)
        self.assertEqual(p._ObservationIo(provider).listdir('/proc'), ['100', '999'])
        child.unknown = True
        with self.assertRaises(p.LinuxProviderError): p._ObservationIo(provider).listdir('/proc')
    def test_closed_resources_cannot_be_reclosed(self):
        provider, io = self.make(); provider._ledger.open('/', p.ARM_DIR)
        self.assertTrue(provider.close_resources((), 3.).complete())
        before = list(io.closed)
        with self.assertRaises(p.LinuxProviderError): provider.close_resources((), 3.)
        self.assertEqual(io.closed, before)
    def test_restore_producer_missing_seal_not_authorized(self):
        provider, io = self.make()
        record = core.Journal(provider.manifest.identity, 'cleanup_verified', snapshot(), 3.)
        with self.assertRaises(p.LinuxProviderError): provider.read_restore(provider._store, None, record, 3.)
    def test_restore_producer_fresh_tuple_snapshot_and_auth(self):
        provider, io = self.make(); provider.fake_snapshot = snapshot(); provider._sealed = True
        record = core.Journal(provider.manifest.identity, 'cleanup_verified', snapshot(), 3.)
        first = provider.read_restore(provider._store, None, record, 3.)
        second = provider.read_restore(provider._store, None, record, 3.)
        self.assertIsNot(first, second); self.assertIsNot(first[0], second[0]); self.assertIsNot(first[1], second[1])
        self.assertIsNone(provider.authenticate_restore(provider._store, None, record, second, 3.))
        with self.assertRaises(p.LinuxProviderError): provider.authenticate_restore(provider._store, None, record, tuple(list(second)), 3.)
    def issued_bridge(self):
        provider, io = self.make()
        reader = CompositeReader()
        store = stores.DurableClientInitStore(TOKEN, provider.manifest.identity,
            _coordination_io=io, _files_io=io, _pending_io=io, _proc_reader=reader, _clock=lambda: 1.)
        actual_owner = owner.DirectChildOwner(_os=io, _reader=reader, _clock=lambda: 1., _threads=lambda: 1)
        bridge = p.LinuxDirectChildLaunchBridge(store, actual_owner, provider.specs(), provider)
        provider._store, provider._owner, provider._bridge = store, actual_owner, bridge
        child = actual_owner.register(provider.specs()[0], 3, 3.)
        original = actual_owner._open(child, 'HOST-original', '/tmp', p.ARM_DIR)
        self.assertTrue(actual_owner._close_fd(child, original))
        ticket = core.Ticket(TOKEN, 'watchdog', BOOT, child.spec.exe, child.spec.argv_sha)
        record = core.Journal(provider.manifest.identity, 'watchdog_intent', snapshot(), 3., watchdog_ticket=ticket)
        op = phases._Launch(bridge, ticket, None, record); op.child = child; op.inventory_closed = True
        bridge._operations.append(op); bridge._registry_close_requested = True
        self.assertTrue(bridge._capture_closed())
        return provider, io, bridge, child, original
    def test_bridge_lowest_fd_reuse_exact_provider_ticket(self):
        provider, io, bridge, child, old = self.issued_bridge()
        io.fd = old.fd - 1; current = provider._ledger.open('/tmp', p.ARM_DIR)
        self.assertEqual(current.fd, old.fd)
        self.assertTrue(bridge.verify_closed())
        self.assertFalse(current.attempted)
        self.assertFalse(p.phases.DirectChildLaunchBridge.verify_closed(bridge))
    def test_bridge_same_metadata_unregistered_reuse_rejected(self):
        provider, io, bridge, child, old = self.issued_bridge()
        io.fd = old.fd - 1; unknown = io.open('/tmp', p.ARM_DIR)
        self.assertEqual(unknown, old.fd)
        self.assertFalse(bridge.verify_closed())
        self.assertIn(unknown, io.handles)
    def test_bridge_fabricated_unissued_closed_row_rejected(self):
        provider, io, bridge, child, old = self.issued_bridge()
        invented = owner._FD('HOST-invented', io.open)
        invented.fd, invented.returned, invented.attempted, invented.closed, invented.metadata = old.fd, True, True, True, old.metadata
        self.assertFalse(provider._capture_issued_closed(io, invented.fd, invented))
    def test_bridge_changed_live_ticket_metadata_rejected(self):
        provider, io, bridge, child, old = self.issued_bridge()
        io.fd = old.fd - 1; current = provider._ledger.open('/tmp', p.ARM_DIR)
        current.meta = (current.meta[0], current.meta[1] + 1) + current.meta[2:]
        self.assertFalse(bridge.verify_closed())
    def test_bridge_real_proc_reader_closed_attempt_contract(self):
        provider, io, bridge, child, old = self.issued_bridge()
        fs = FakeFs()
        reader = proc.ProcReader(_fs=fs, _clock=lambda: 1.)
        observed = reader.read_actor(42)
        self.assertEqual(observed.kind, 'live_actor')
        self.assertEqual(observed.passes, 2)
        self.assertIsNotNone(observed.actor)
        self.assertFalse(observed.resource_pending)
        self.assertFalse(reader._pending)
        self.assertFalse(reader._active)
        self.assertIsNone(reader._open_attempt)
        self.assertEqual(reader._files, reader._closed)
        bridge.owner._reader = reader
        for actual_fs, original_fd in reader._fd_refs:
            self.assertTrue(provider._capture_issued_closed(actual_fs, original_fd, reader))
        self.assertTrue(bridge._capture_closed())
    def test_status_contains_no_private_identifiers(self):
        provider, io = self.make(); text = repr(provider.status())
        for secret in (TOKEN, OWN.name, provider.manifest.run_dir, '300', 'wlan0'):
            self.assertNotIn(secret, text)
        self.assertFalse(provider.status()['receive_available'])
    def test_python35_and_restore_single_gate_diff(self):
        with open(os.path.join(RUNTIME, 'mta_client_linux_provider.py'), encoding='utf-8') as f: source = f.read()
        tree = ast.parse(source, feature_version=(3, 5))
        new = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'LinuxClientInitLease')
        new = copy.deepcopy(next(n for n in new.body if isinstance(n, ast.FunctionDef) and n.name == 'restore'))
        with open(os.path.join(RUNTIME, 'mta_client_two_phase_lease.py'), encoding='utf-8') as f: oldtree = ast.parse(f.read())
        old = next(n for n in oldtree.body if isinstance(n, ast.ClassDef) and n.name == 'TwoPhaseClientInitLease')
        old = next(n for n in old.body if isinstance(n, ast.FunctionDef) and n.name == 'restore')
        for n in ast.walk(new):
            if isinstance(n, ast.Attribute) and n.attr == 'cleanup_origin_ready': n.attr = 'origin_up'
        self.assertEqual(ast.dump(new, include_attributes=False), ast.dump(old, include_attributes=False))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))


if __name__ == '__main__': unittest.main()
