"""New HOST actual collector/STATUS subgraph, not INIT or device evidence.

The fixed v24 29-source domain runs over one synthetic FD namespace. Three
stock images are real PC backup bytes with their exact fixed hashes. CLI,
original WPA daemon/config/processes/netlink/credentials are explicitly HOST
assumptions. No hash substitution, ready Journal, Handle or ProcObservation
injection, old test method, lease.start, CREATE/CONNECT, actual OS or RF.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import hashlib
import importlib
import json
import math
from pathlib import Path
import stat
import struct
import sys
import types
import unittest
from unittest import mock
import zlib

BASE = Path(__file__).resolve().parents[1]
ARCHIVE = BASE.parents[1] / '06_Firmware/backups/v2.4.0-20260923-162730/files'
MANIFEST_SHA = 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e'
FULL_SHA = '95ab61699cdf0e5efcd2a057d7c3d6d6a36d3843ee2fd45a9c27d3fea217119e'
BASE_FIXTURE_SHA = 'f80965117e0b4c4f3471ab5c109fc5034b6342c58e62ffb10d65cbbcfc4b4f80'
CLI_BYTES = b'HOST-v25-synthetic-wpa-cli-not-a-P011-image'
DAEMON_BYTES = b'\x7fELFHOST-v25-original-endpoint-daemon-synthetic'
CONFIG_BYTES = b'CONFIG_IKCONFIG=y\n# CONFIG_NAMESPACES is not set\n'
STATUS = b'wpa_state=COMPLETED\nfreq=2412\nmode=station\nbssid=02:00:00:00:00:01\nssid=HOST\n'
DAEMON_PID = 987


def pinned(path, digest):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('HOST fixed input drift')
    return raw


def domain():
    rows = json.loads(pinned(BASE / 'host/client_proc_history_v24_source_manifest.json',
        MANIFEST_SHA).decode('utf-8'))['sources']
    if len(rows) != 29 or len({row['module'] for row in rows}) != 29:
        raise ValueError('HOST domain shape drift')
    modules, original_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private dependency unavailable')
            return modules[name]
        return original_import(name, *args, **kwargs)
    for row in rows:
        raw = pinned(BASE / row['path'], row['sha256'])
        if len(raw) != row['bytes']: raise ValueError('HOST source bytes drift')
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('HOST target assert drift')
        module = types.ModuleType(row['module']); module.__file__ = str(BASE / row['path'])
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[row['module']] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


def dependencies():
    sys.path.insert(0, str(BASE / 'tests'))
    pinned(BASE / 'tests/test_client_full_lifecycle_v24.py', FULL_SHA)
    pinned(BASE / 'tests/test_client_baseline.py', BASE_FIXTURE_SHA)
    full = importlib.import_module('test_client_full_lifecycle_v24')
    # Only pure fixture definitions and packet encoders, never its TestCase.
    baseline_fixture = importlib.import_module('test_client_baseline')
    return full, baseline_fixture


class Clock:
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


def make_fixture(modules, full, packets):
    fixture, proc_helpers, owner_helpers = full.setup_definitions(modules)
    lease, provider, store, owner, bridge, io, fs, kernel, net = full.make_full(
        modules, fixture, proc_helpers, owner_helpers)
    p, core, proc, baseline = (modules[name] for name in
        ('mta_client_linux_provider', 'mta_p2p_client_init', 'mta_client_proc', 'mta_client_baseline'))
    clock = Clock()
    io.clock = clock
    for obj in (provider, store, owner): obj._clock = clock
    for reader in store._resource_budget_v23._readers: reader._clock = clock
    kernel.clock = clock
    # Full fixture starts with pure construction only. Replace its unused
    # SnapshotAssumption with the actual default producer before any snapshot.
    provider._collector_factory = p._AuthenticatedCollector
    if provider._status_factory is not modules['mta_client_wpa_status'].AuthenticatedStatusReader:
        raise ValueError('HOST status factory drift')
    values = {key: getattr(provider.manifest, key) for key in p._KEYS}
    values['baseline_manifest'] = core.STOCK_PINS + ((baseline.CLI, hashlib.sha256(CLI_BYTES).hexdigest()),)
    values['status_manifest'] = dict(values['status_manifest'],
        daemon_sha256=hashlib.sha256(DAEMON_BYTES).hexdigest(),
        config_sha256=hashlib.sha256(CONFIG_BYTES).hexdigest())
    provider.manifest = p.ProviderManifest(values, _manifest_sha256='1' * 64)
    status_manifest = dict(provider.manifest.status_manifest)
    endpoint, daemon_exe = (status_manifest[key] for key in ('endpoint', 'daemon_exe'))
    command = daemon_exe.encode('ascii') + b'\0-iwlan0\0'

    def install(pid, start, exe, argv, comm):
        root = '/proc/' + str(pid)
        fs.dirs.update((root, root + '/task', root + '/task/' + str(pid)))
        data = proc_helpers.stat_data(pid, start=start, comm=comm, threads=1)
        fs.files[root + '/stat'] = data
        fs.files[root + '/task/' + str(pid) + '/stat'] = data
        fs.files[root + '/cmdline'], fs.files[root + '/comm'] = argv, comm + b'\n'
        fs.links[root + '/exe'] = exe
    # The full-lifecycle fixture's network snapshot has codec edge-case actors
    # (including a non-ASCII executable). This producer fixture enumerates a
    # separate explicit synthetic /proc tree, not those fabricated Actors.
    boot_bytes = fs.files[proc_helpers.BOOT_PATH]
    fs.files, fs.dirs, fs.links = {proc_helpers.BOOT_PATH: boot_bytes}, {'/proc'}, {}
    for pid, name in ((101, 'Z03'), (102, 'control_engine'), (103, 'weston')):
        install(pid, pid + 100, '/usr/bin/' + name,
            ('HOST-stock-' + str(pid) + '\0').encode('ascii'), name.encode('ascii'))
    install(fixture.SELF.pid, fixture.SELF.start, fixture.SELF.exe, fixture.ARGV, b'python3')
    install(DAEMON_PID, 400, daemon_exe, command, b'wpa_supplicant')
    fs.files['/proc/' + str(DAEMON_PID) + '/status'] = b'Name:\twpa_supplicant\nUid:\t0 0 0 0\nGid:\t0 0 0 0\n'

    for path in ('/usr', '/usr/bin', '/usr/sbin', '/var', '/var/run', '/var/run/wpa_supplicant'):
        io.add(path, stat.S_IFDIR | 0o755)
    for path, pin in core.STOCK_PINS:
        raw = pinned(ARCHIVE / path.rsplit('/', 1)[-1], pin)
        io.add(path, stat.S_IFREG | 0o755, raw)
    io.add(baseline.CLI, stat.S_IFREG | 0o755, CLI_BYTES)
    io.add(daemon_exe, stat.S_IFREG | 0o755, DAEMON_BYTES)
    io.add(endpoint, stat.S_IFSOCK | 0o770)
    for pid in (101, 102, DAEMON_PID):
        io.nodes['/proc/' + str(pid) + '/exe'] = io.nodes[fs.links['/proc/' + str(pid) + '/exe']]
    fs.files['/proc/net/unix'] = (b'Num RefCount Protocol Flags Type St Inode Path\n'
        b'00000001: 00000002 00000000 00000000 0002 01 991 ' + endpoint.encode('ascii') + b'\n')
    compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
    fs.files['/proc/config.gz'] = compressor.compress(CONFIG_BYTES) + compressor.flush()
    fs.files['/proc/net/if_inet6'] = b'fe800000000000000000000000000001 02 40 20 80 wlan0\n'
    fs.files['/proc/net/ipv6_route'] = (b'fe800000000000000000000000000000 40 ' + b'0' * 32 +
        b' 00 ' + b'0' * 32 + b' 00000100 00000000 00000000 00000001 wlan0\n')
    for root in ('/proc/' + str(DAEMON_PID) + '/ns', '/proc/self/ns'):
        fs.dirs.add(root)
        for name in ('cgroup', 'mnt'): fs.links[root + '/' + name] = name + ':[101]'
    fs.dirs.add('/proc/' + str(DAEMON_PID) + '/fd')
    fs.links['/proc/' + str(DAEMON_PID) + '/fd/6'] = 'socket:[991]'
    fs.dirs.add('/proc/987/fd/6')  # listdir fixture enumerates directory entries.

    base_open, base_read, base_fstat, base_close, base_stat = io.open, io.read, io.fstat, io.close, io.stat
    original_lstat, original_listdir, original_readlink = fs.lstat, fs.listdir, fs.readlink
    io.read_log, io.enumerations = [], []
    def open_file(path, flags):
        if path in fs.files:
            if path not in io.nodes: io.add(path, stat.S_IFREG | 0o444, fs.files[path])
            io.nodes[path].data = fs.files[path]
            io.nodes[path].ino = fs.inode(path)
        fd = base_open(path, flags)
        if fd in kernel.live: raise AssertionError('HOST namespace collision')
        return fd
    def read_file(fd, count):
        path = io.handles[fd][0].path
        raw = base_read(fd, count); io.read_log.append((path, count, raw))
        return raw
    def fstat_fd(fd):
        return kernel.fstat(fd) if fd in kernel.live else base_fstat(fd)
    def proc_lstat(path):
        if path in fs.files:
            meta = original_lstat(path)
            if path in io.nodes:
                io.nodes[path].data = fs.files[path]; io.nodes[path].ino = fs.inode(path)
            return meta
        return original_lstat(path)
    def listdir(path):
        if path == '/proc':
            names = original_listdir(path); io.enumerations.append(tuple(names)); return names
        if path.endswith('/ns'):
            prefix = path + '/'
            return sorted(name[len(prefix):] for name in fs.links if name.startswith(prefix))
        if path == '/proc/' + str(DAEMON_PID) + '/fd': return ['6']
        return original_listdir(path)
    io.open, io.read, io.fstat = open_file, read_file, fstat_fd
    io.listdir, io.readlink = listdir, original_readlink
    io.token = lambda: b'HOSTTOKEN1234567'
    io.spawn = lambda *unused: (_ for _ in ()).throw(AssertionError('CLI/Popen fallback forbidden'))
    io.readable = lambda *unused: (_ for _ in ()).throw(AssertionError('CLI/select fallback forbidden'))
    fs.lstat, fs.open, fs.read, fs.fstat, fs.close = proc_lstat, open_file, read_file, fstat_fd, base_close
    fs.listdir = listdir
    # Proc's synthetic FS and every baseline/status syscall now issue through
    # the same io.handles allocator. FakeKernel originals use a disjoint range
    # visible to the SAME fstat gate; no per-reader hidden low-FD collisions.
    fs.live = io.handles
    io.interface_calls = 0
    io.changed_interface = io.missing_station = io.duplicate_attr = False
    io.packet_hook, io.route_flags, io.recv_flags, io.peer = None, 0, 0, (0, 0)
    io.socket_close_error = None

    class Netlink(packets.FakeSocket):
        def __init__(self, protocol):
            self.io, self.protocol = io, protocol
            path = '/HOST-netlink-' + str(len(io.sockets))
            io.add(path, stat.S_IFSOCK | 0o600)
            self.fd = open_file(path, 0); self.port = self.fd + 100
            self.inheritable, self.timeout, self.packets = True, None, []
            self.close_count, self.sent = 0, []
        def close(self):
            self.close_count += 1; base_close(self.fd); self.fd = -1
    def new_netlink(protocol):
        if protocol not in (0, 16): raise AssertionError('HOST protocol mutation')
        raw = Netlink(protocol); io.sockets.append(raw); return raw
    io.socket = new_netlink

    class StatusSocket:
        family, type, proto = 1, 2, 0
        def __init__(self):
            self.local = self.peer = self.timeout = None
            self.inheritable, self.passcred, self.sent, self.received, self.close_count = True, 0, [], 0, 0
            path = '/HOST-status-' + str(len(io.sockets))
            io.add(path, stat.S_IFSOCK | 0o600); self.fd = open_file(path, 0)
        def fileno(self): return self.fd
        def set_inheritable(self, value): self.inheritable = value
        def get_inheritable(self): return self.inheritable
        def setsockopt(self, level, option, value): self.passcred = value
        def getsockopt(self, level, option): return self.passcred
        def bind(self, path): self.local = path
        def getsockname(self): return self.local
        def connect(self, path): self.peer = path
        def getpeername(self): return self.peer
        def settimeout(self, value):
            seconds, fraction = divmod(math.ceil(value * 1e9), 1000000000)
            self.timeout = seconds + fraction * 1e-9
        def gettimeout(self): return self.timeout
        def send(self, raw):
            if raw != b'STATUS': raise AssertionError('HOST control mutation')
            self.sent.append(raw); return len(raw)
        def recvmsg(self, count, cmsg, flags):
            self.received += 1
            return STATUS, [(1, 2, struct.pack('=iII', DAEMON_PID, 0, 0))], 0, endpoint
        def close(self):
            self.close_count += 1; base_close(self.fd); self.fd = -1
    def new_status():
        raw = StatusSocket(); io.sockets.append(raw); return raw
    io.new_socket = new_status

    # Prevent accidental actual algorithm expansion from this collector-only
    # fixture, independent of all external OS tripwires.
    lease.start = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('HOST INIT forbidden'))
    return lease, provider, store, owner, bridge, io, fs, kernel, net, clock


class ActualCollectorV25Tests(unittest.TestCase):
    def test_actual_two_round_collector_and_authenticated_status_with_issued_private_controller(self):
        with ExitStack() as stack:
            sys.path.insert(0, str(BASE / 'tests'))
            pinned(BASE / 'tests/test_client_full_lifecycle_v24.py', FULL_SHA)
            full = importlib.import_module('test_client_full_lifecycle_v24')
            full.tripwires(stack)
            modules = domain()
            full, packets = dependencies()
            p = modules['mta_client_linux_provider']
            p._OWNERS[:] = []
            self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
            values = make_fixture(modules, full, packets)
            lease, provider, store, owner, bridge, io, fs, kernel, net, clock = values
            locks = store.acquire(provider.manifest.identity, clock() + 3)
            self.assertIsNone(lease.record); self.assertFalse(lease.handles)
            self.assertFalse(bridge._operations); self.assertFalse(provider._collectors)
            child = owner.register(provider.specs()[1], locks._device.fd, clock() + 10)
            self.assertIs(owner.launch(child), child)
            def persist(original, actor):
                # Explicit synthetic persistence seam, no ready journal.
                return modules['mta_client_process_owner'].PersistReceipt(original, actor)
            self.assertTrue(owner.release(child, persist))
            observed = owner.resolve(child)
            self.assertIs(child.postexec, observed); self.assertTrue(child.released)
            self.assertFalse(child.unknown); self.assertTrue(child.fork_returned)
            fs.files['/proc/' + str(child.pid) + '/comm'] = b'wpa_supplicant\n'
            provider.executor(clock() + 5)
            snapshot = provider.snapshot(clock() + 5)
            collector = provider._collectors[-1]['reader']
            self.assertIs(type(collector), p._AuthenticatedCollector)
            self.assertIs(type(snapshot), modules['mta_p2p_client_init'].Snapshot)
            self.assertEqual(2, len(collector._rounds)); self.assertEqual(2, len(collector.status_readers))
            self.assertEqual(collector._rounds[0].key(), collector._rounds[1].key())
            self.assertIn(str(child.pid), io.enumerations[0])
            self.assertNotIn(child.pid, [actor.pid for actor in snapshot.stock_actors])
            self.assertIn(DAEMON_PID, [actor.pid for actor in snapshot.stock_actors])
            self.assertEqual(tuple(sorted(modules['mta_p2p_client_init'].STOCK_PINS)), tuple(sorted(snapshot.stock_hashes)))
            for path, digest in provider.manifest.baseline_manifest:
                self.assertEqual(2, sum(raw[0] == 'file' and raw[1] == path for raw in collector._raw))
            self.assertEqual(4, sum(raw[0] == 'actor_image' for raw in collector._raw))
            self.assertEqual(1, len(snapshot.ipv4.addresses)); self.assertEqual(2, len(snapshot.ipv4.routes))
            self.assertEqual(3, len(snapshot.ipv4.rules)); self.assertEqual(1, len(snapshot.ipv6_addresses))
            self.assertEqual(1, len(snapshot.ipv6_routes))
            for row in collector.status_readers:
                source, reader = row['source'], row['reader']
                self.assertIs(type(source), modules['mta_client_wpa_status'].LinuxStatusSource)
                self.assertIs(type(reader), modules['mta_client_wpa_status'].AuthenticatedStatusReader)
                self.assertEqual(2, len(source._issued)); self.assertEqual(2, len(source._files))
                self.assertEqual(8, len(source._actor_calls)); self.assertEqual(2, len(reader._sources))
                self.assertIsNot(reader._sources[0], reader._sources[1])
                self.assertEqual(source._issued[0][2], source._issued[1][2])
                self.assertTrue(all(call['reader'] is source._reader for call in source._actor_calls))
                self.assertEqual(8, len(source._reader._history))
                self.assertTrue(all(call['returned'] and not call['unknown'] for call in source._actor_calls))
                self.assertTrue(all(original['daemon_actor'].pid == DAEMON_PID for original in reader._sources))
                self.assertTrue(all(proof.complete() for original in reader._sources for proof in original['files_closed']))
                self.assertTrue(reader.status()['socket_closed']); self.assertFalse(reader.status()['resource_pending'])
                self.assertEqual([b'STATUS'], reader._socket.sent); self.assertEqual(1, reader._socket.received)
                self.assertEqual(1, reader._socket.close_count)
                self.assertLessEqual(reader._deadline, collector._deadline)
                self.assertIs(source._reader._resource_budget_v24, store._resource_budget_v23)
            self.assertTrue(collector.status()['read_success']); self.assertFalse(collector.status()['resource_pending'])
            self.assertTrue(all(row['attempted'] and row['closed'] and not row['unknown'] for row in collector._tickets))
            self.assertTrue(all(reader.history_closed() for reader in store._resource_budget_v23._readers))
            self.assertFalse(set(io.handles) & set(kernel.live))
            # Actual owner reap/absence/FD close and Store close, not restoration.
            net.stopped.add(child.pid)
            self.assertTrue(owner.wait_reap(child, 1)); self.assertTrue(owner.fresh_exit(child))
            self.assertTrue(owner.close_inventory(child)); store.close()
            self.assertFalse(io.handles); self.assertFalse(kernel.live)
            self.assertIsNone(lease.record); self.assertFalse(lease.handles)
            self.assertFalse(provider._create_requested); self.assertFalse(provider._connection is not None)
            self.assertEqual(0, store._resource_budget_v23.status()['active_producers'])


if __name__ == '__main__': unittest.main()
