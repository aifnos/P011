"""New HOST method only: actual frozen lifecycle over explicit synthetic IO.

No ready Journal, Handle, control FD or restored-stage injection. Proc parsing,
launch/persistence, CREATE/DELETE, connect, DORA and finish algorithms are actual.
Network snapshots, process execution, netlink/control/DHCP ingress are synthetic
platform assumptions. This does not prove device RF, wall clock, heap, or F wiring.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import hashlib
import importlib
import json
from pathlib import Path
import socket
import stat
import struct
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
PLAN_SHA = '54636ca4449a334abeef54be3de57ad4d6c096c06de7feb45172590dd2338a27'
V19_SHA = 'f92ab1be262d6da641e4cc3306f218f44d1c500f70c35d0352017cbae396bab1'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'


def checked(relative, pin):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('HOST frozen source drift')
    return raw


def tripwires(stack):
    for target in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.fork', 'os.execve', 'os.kill', 'os.waitpid',
            'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(target, side_effect=AssertionError('actual OS forbidden'), create=True))
    # Windows lacks this POSIX API; model only bounded ancillary sizing, no IO.
    stack.enter_context(mock.patch.object(socket, 'CMSG_SPACE',
        lambda size: 16 + ((size + 7) // 8) * 8, create=True))


def frozen_domain():
    plan = json.loads(checked('host/client_resource_v23_source_manifest.json', PLAN_SHA).decode('utf-8'))
    rows, modules, original = plan['sources'], {}, builtins.__import__
    if len(rows) != 29: raise ValueError('HOST graph drift')
    def private_import(name, *args, **kwargs):
        if name in modules: return modules[name]
        if name.startswith(('mta_', 'p011_')): raise ImportError('HOST private graph only')
        return original(name, *args, **kwargs)
    for row in rows:
        raw = checked(row['path'], row['sha256'])
        if len(raw) != row['bytes']: raise ValueError('HOST source size drift')
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('HOST target assert forbidden')
        module = types.ModuleType(row['module']); module.__file__ = str(BASE / row['path'])
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[row['module']] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


def setup_definitions(modules):
    """Only fixture definitions are reused; no existing TestCase method runs."""
    sys.path.insert(0, str(BASE / 'tests'))
    raw = checked('tests/test_client_durable_connect_v19.py', V19_SHA).decode('utf-8')
    if raw.count('M = graph()') != 1: raise ValueError('HOST fixture scope drift')
    fixture = types.ModuleType('HOST_full_lifecycle_v23_definitions')
    fixture.__file__ = str(BASE / 'tests/test_client_durable_connect_v19.py')
    fixture.HOST_GRAPH = modules
    exec(compile(raw.replace('M = graph()', 'M = HOST_GRAPH'), fixture.__file__, 'exec'), fixture.__dict__)
    proc_helpers = importlib.import_module('test_client_proc')
    owner_helpers = importlib.import_module('test_client_process_owner')
    return fixture, proc_helpers, owner_helpers


def make_full(modules, fixture, proc_helpers, owner_helpers):
    p, core, proc = (modules[n] for n in ('mta_client_linux_provider', 'mta_p2p_client_init', 'mta_client_proc'))
    net = types.SimpleNamespace(owned=None, connection_started=False, stopped=set(), reaped=set())
    io = fixture.Io()
    fs = proc_helpers.FakeFs()
    fs.files, fs.dirs, fs.links = {}, {'/proc'}, {}
    fs.files[proc_helpers.BOOT_PATH] = fixture.baseline().boot.encode('ascii') + b'\n'
    fs.getpid = lambda: fixture.SELF.pid

    def install(pid, start, exe, argv, tasks=None):
        tasks = ((pid, start, 'S'),) if tasks is None else tasks
        root = '/proc/' + str(pid)
        fs.dirs.update((root, root + '/task'))
        fs.files[root + '/stat'] = proc_helpers.stat_data(pid, start=start, state=tasks[0][2], threads=len(tasks))
        fs.files[root + '/cmdline'] = argv
        fs.links[root + '/exe'] = exe
        for tid, began, state in tasks:
            fs.dirs.update((root + '/task/' + str(tid), '/proc/' + str(tid)))
            data = proc_helpers.stat_data(tid, start=began, state=state, threads=len(tasks))
            fs.files[root + '/task/' + str(tid) + '/stat'] = data
            fs.files['/proc/' + str(tid) + '/stat'] = data
        return core.Actor(pid, start, exe, hashlib.sha256(argv).hexdigest(), tasks)

    def remove(pid):
        root = '/proc/' + str(pid)
        for mapping in (fs.files, fs.links):
            for path in list(mapping):
                if path == root or path.startswith(root + '/'): del mapping[path]
        fs.dirs = {path for path in fs.dirs if path != root and not path.startswith(root + '/')}

    parent = install(fixture.SELF.pid, fixture.SELF.start, fixture.SELF.exe, fixture.ARGV)
    original = fixture.baseline()
    stocks = tuple(install(a.pid, a.start, a.exe, ('HOST-stock-' + str(a.pid) + '\0').encode('ascii'), a.tasks)
        for a in original.stock_actors)
    base = core.Snapshot(original.boot, original.stock_hashes, stocks, original.station,
        original.station_state_sha, original.station_frequency, original.interfaces,
        original.ipv4, original.ipv6_addresses, original.ipv6_routes, original.station_completed)
    watchdog_bytes = owner_helpers.ELF
    native = checked('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant', WPA_SHA)
    old_manifest = fixture.manifest()
    values = {key: getattr(old_manifest, key) for key in p._KEYS}
    values['status_manifest'] = dict(values['status_manifest'])
    values['python_sha'] = hashlib.sha256(watchdog_bytes).hexdigest()
    manifest = p.ProviderManifest(values, _manifest_sha256='1' * 64)

    class SnapshotAssumption:
        """Typed network projection is SYNTHETIC; actual Provider validates it."""
        def __init__(self, provider, timeout):
            self.p, self._io, self._tickets, self.status_readers = provider, io, [], []
            self._reader = proc.ProcReader(_fs=fs, _clock=io.clock, timeout=timeout)
            self._ended, self._observations = False, []
        def collect(self, deadline):
            self._observations.append(self._reader.read_self())
            self._ended = True
            interfaces = base.interfaces + (() if net.owned is None else (net.owned,))
            return core.Snapshot(base.boot, base.stock_hashes, base.stock_actors, base.station,
                base.station_state_sha, base.station_frequency, interfaces, base.ipv4,
                base.ipv6_addresses, base.ipv6_routes, base.station_completed)
        def status(self):
            return {'read_success': self._ended, 'resource_pending': self._reader._pending,
                'resource_count': 0, 'closed_count': 0}

    provider = p.LinuxClientInitProvider(manifest, _io=io, _clock=io.clock,
        _proc_factory=lambda **kw: proc.ProcReader(_fs=fs, **kw),
        _collector_factory=SnapshotAssumption, _connect_binding=fixture.binding())
    store = modules['mta_client_store'].DurableClientInitStore(manifest.run_token, manifest.identity,
        _coordination_io=io, _files_io=io, _pending_io=io,
        _proc_reader=proc.ProcReader(_fs=fs, _clock=io.clock), _clock=io.clock,
        _prior_reader=provider, _restore_reader=provider)

    class ProcessKernel(owner_helpers.FakeKernel):
        def __init__(self):
            owner_helpers.FakeKernel.__init__(self, io.clock)
            self.nextfd, self.store, self.owner = 10000, store, None
            self.live = {}
            self.device_ofd = object()  # Synthetic shared original OFD, not another open FD.
        def getpid(self): return parent.pid
        def fstat(self, fd):
            if fd not in self.live and store._current_locks is not None and fd == store._current_locks._device.fd:
                return io.fstat(fd)  # Same original adapter FD; do not create a mirror inventory FD.
            return super(ProcessKernel, self).fstat(fd)
        def dup(self, original):
            if original not in self.live and store._current_locks is not None and original == store._current_locks._device.fd:
                self.event('dup', original)
                observed = io.fstat(original)
                return self.alloc(types.SimpleNamespace(**vars(observed)), b'', self.device_ofd)
            return super(ProcessKernel, self).dup(original)
        def open(self, path, flags):
            if path == '/dev/null': return super(ProcessKernel, self).open(path, flags)
            self.event('open', path, flags)
            data = watchdog_bytes if path == manifest.python_exe else native if path == manifest.wpa_exe else None
            if data is None: raise AssertionError('unlisted HOST executable')
            self.nextino += 1
            return self.alloc(owner_helpers.metadata(self.nextino, stat.S_IFREG | 0o755, data), data)
        def fork(self):
            self.event('fork')
            child = self.owner._tickets[-1]
            pid = 200 if child.spec.role == 'watchdog' else 300
            install(pid, 20 if pid == 200 else 30, parent.exe, fixture.ARGV)
            return pid
        def write(self, fd, data):
            result = super(ProcessKernel, self).write(fd, data)
            if data == b'1':
                child = next(c for c in self.owner._tickets if any(r.role == 'gate_write' and r.fd == fd for r in c.fds))
                argv = b'\0'.join(a.encode('utf-8') for a in child.spec.argv) + b'\0'
                install(child.pid, child.preexec.start, child.spec.exe, argv)
            return result
        def waitpid(self, pid, flags):
            self.event('waitpid', pid, flags)
            if pid not in net.stopped: return (0, 0)
            net.reaped.add(pid); remove(pid)
            return (pid, 0)

    kernel = ProcessKernel()
    owner = modules['mta_client_process_owner'].DirectChildOwner(_os=kernel,
        _reader=proc.ProcReader(_fs=fs, _clock=io.clock), _clock=io.clock,
        _threads=lambda: 1, _flags=kernel.flags)
    kernel.owner = owner
    bridge = p.LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
    lease = p.LinuxClientInitLease(provider, store, manifest.identity, io.clock, bridge)
    provider.attach(store, owner, bridge, lease)
    io.kill = lambda pid: (net.stopped.add(pid), io.signals.append(pid)) and None
    io.signals = []
    io.listdir = lambda path: [modules['mta_client_coordination'].RUN_PREFIX + manifest.run_token]

    class Control(fixture.CtrlSock):
        def send(self, raw):
            if raw == b'STATUS' and not net.connection_started:
                self.sent.append(raw)
                reply = (b'wpa_state=INACTIVE\np2p_device_address=02:11:22:33:44:55\n'
                    b'address=02:66:77:88:99:aa\nuuid=12345678-1234-1234-1234-123456789abc\n')
                self.queue.append((reply, [(1, 2, p._CRED.pack(300, 0, 0))], 0, self.peer))
                return len(raw)
            if raw.startswith(b'P2P_GROUP_ADD'): net.connection_started = True
            return super(Control, self).send(raw)
    def new_ctrl():
        path = fixture.old.RUN + '/HOST-lifecycle-ctrl-' + str(len(io.sockets))
        io.add(path, stat.S_IFSOCK | 0o600)
        raw = Control(io, io._open(path, 0, 0), 'ctrl'); io.sockets.append(raw)
        return raw
    io.new_ctrl = new_ctrl

    wire_helpers = fixture.fixtures.old.wire
    def nl_reply(request, kind, body, flags=0):
        unused, family, sentflags, seq, port = p._NL.unpack(request[:16])
        raw = p._NL.pack(16 + len(body), kind, flags, seq, port) + body
        return raw + b'\0' * (-len(raw) % 4)
    def origin_bytes(value):
        return (p._attr(1, struct.pack('<I', value.phy)) + p._attr(153, struct.pack('<Q', value.wdev)) +
            p._attr(3, struct.pack('<I', value.ifindex)) + p._attr(4, value.name.encode('ascii') + b'\0') +
            p._attr(5, struct.pack('<I', value.iftype)))
    class Legacy(fixture.observer_fixture.Sock):
        def sendto(self, request, endpoint):
            self.sent.append(request)
            unused, family, flags, seq, port = p._NL.unpack(request[:16])
            command, version, reserved = p._GENL.unpack(request[16:20])
            if family == 16:
                packets = [nl_reply(request, family, p._GENL.pack(3, 2, 0) + wire_helpers.family())]
            elif command == 5:
                interfaces = base.interfaces + (() if net.owned is None else (net.owned,))
                packets = [nl_reply(request, family, p._GENL.pack(7, 1, 0) + origin_bytes(v), 2) for v in interfaces]
                packets.append(nl_reply(request, 3, b'\0' * 4, 2))
            elif command == 7:
                if net.owned is not None: raise AssertionError('duplicate HOST CREATE')
                net.owned = core.Origin(*fixture.OWNED.key())
                packets = [nl_reply(request, family, p._GENL.pack(7, 1, 0) + origin_bytes(net.owned)),
                    nl_reply(request, 2, b'\0' * 4 + request[:16])]
            elif command == 8:
                if net.owned is None: raise AssertionError('duplicate HOST DELETE')
                net.owned = None
                packets = [nl_reply(request, 2, b'\0' * 4 + request[:16])]
            else: raise AssertionError('unlisted HOST netlink command')
            self.queue.extend((raw, [], 0, (0, 0)) for raw in packets)
            return len(request)
    genls = []
    def new_genl():
        path = fixture.old.RUN + '/HOST-lifecycle-genl-' + str(len(genls))
        io.add(path, stat.S_IFSOCK | 0o600); fd = io._open(path, 0, 0)
        if provider._caps_readers and provider._caps_readers[-1]['socket'] is None:
            raw = fixture.fixtures.old.CapsSocket(io, fixture.fixtures.old.caps_packets(), fd)
        else: raw = Legacy(io, fd, 'genl')
        genls.append(raw); return raw
    io.new_genl = new_genl
    def kernel_factory(*args, **kwargs):
        actual_io = fixture.fixtures.old.KernelIo(fixture.fixtures.packets())
        return modules['mta_client_kernel_proof'].ClientKernelReader(*args, _io=actual_io,
            _proc_factory=lambda **kw: proc.ProcReader(_fs=fs, **kw), **kwargs)
    provider._kernel_factory = kernel_factory
    return lease, provider, store, owner, bridge, io, fs, kernel, net


class HostDatagram:
    def __init__(self, dhcp):
        self.dhcp, self.family, self.fd = dhcp, socket.AF_INET, 800000
        self.options, self.sent, self.queue = {}, [], []
        self.inheritable, self.timeout, self.address = True, None, None
    def fileno(self): return self.fd
    def close(self): self.fd = -1
    def set_inheritable(self, value): self.inheritable = value
    def get_inheritable(self): return self.inheritable
    def setsockopt(self, level, option, value): self.options[level, option] = value
    def getsockopt(self, level, option, *unused):
        if option == socket.SO_TYPE: return int(socket.SOCK_DGRAM)
        if option in (socket.SO_REUSEADDR, self.dhcp.SO_REUSEPORT): return 0
        return self.options.get((level, option))
    def bind(self, address): self.address = address
    def getsockname(self): return self.address
    def settimeout(self, value): self.timeout = value
    def gettimeout(self): return self.timeout
    def sendmsg(self, buffers, ancillary, flags, target):
        self.sent.append((buffers, ancillary, flags, target)); return len(buffers[0])
    def recvmsg(self, *args):
        if self.queue: return self.queue.pop(0)
        raise socket.timeout()


class ClientFullLifecycleV23Tests(unittest.TestCase):
    def test_actual_start_connect_dora_and_single_restore_over_synthetic_platform(self):
        with ExitStack() as stack:
            tripwires(stack)
            modules = frozen_domain()
            fixture, proc_helpers, owner_helpers = setup_definitions(modules)
            p, core, dora, dhcp, wire = (modules[n] for n in
                ('mta_client_linux_provider', 'mta_p2p_client_init', 'mta_client_dora', 'mta_dhcp_client', 'mta_dhcp'))
            p._OWNERS[:] = []
            self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
            values = make_full(modules, fixture, proc_helpers, owner_helpers)
            lease, provider, store, owner, bridge, io, fs, kernel, net = values
            self.assertIsNone(lease.record); self.assertFalse(lease.handles); self.assertFalse(bridge._operations)
            self.assertIsNone(provider._ctrl); self.assertIsNone(provider._owned)
            started = lease.start(ttl=20)
            self.assertTrue(started['client_init_ready'], (started, getattr(lease, '_diagnostic_start', None)))
            self.assertEqual(2, len(lease.launches)); self.assertEqual(2, len(lease.handles))
            self.assertEqual(2, len(provider._caps_readers))
            self.assertTrue(all(c.released and c.preexec is not None and c.postexec is not None for c in owner._tickets))
            deadline = lease.record.deadline
            self.assertEqual('client_init_ready', lease.record.stage)
            decoder = modules['mta_client_control_frame'].ControlFrameDecoder(provider._connect_binding)
            decoder.feed(modules['mta_client_control_frame'].encode_connect(provider._connect_binding, fixture.info()))
            request = decoder.take_connect()
            lease.connect_p2p(request, _checkpoint=lambda: False)
            capsule = dora.PrivateClientDora(lease, provider._active_association_receipt)
            raw = HostDatagram(dhcp)
            capsule._client._factory = lambda *args: raw; capsule._client._real_factory = False
            capsule._client._index_reader = lambda name: capsule.context.ifindex
            self.assertIs(capsule.open(), capsule)
            def reply(kind):
                server = wire.ipv4('192.168.49.7')
                packet = wire.encode(2, capsule._core._xid, capsule.context.mac,
                    {53: bytes(bytearray((kind,))), 54: server, 1: wire.ipv4('255.255.255.0'),
                     51: struct.pack('!I', 60)}, yiaddr=wire.ipv4('192.168.49.123'))
                ancillary = [(socket.IPPROTO_IP, dhcp.IP_PKTINFO,
                    dhcp.PKTINFO.pack(capsule.context.ifindex, wire.ZERO, b'\xff' * 4))]
                return packet, ancillary, 0, ('192.168.49.7', 67)
            raw.queue.append(reply(wire.OFFER)); self.assertEqual('waiting', capsule.poll()['event'])
            raw.queue.append(reply(wire.ACK)); self.assertEqual('candidate_received', capsule.poll()['event'])
            live = capsule.candidate(); self.assertTrue(capsule.validate_live(live))
            self.assertEqual(10, len(capsule._proof_calls)); self.assertEqual(2, len(raw.sent))
            self.assertEqual(deadline, lease.record.deadline)
            self.assertFalse(capsule.status()['interface_configured'])
            # Explicit composition closure, NOT automatic F/DORA inventory wiring.
            self.assertTrue(capsule.close()); self.assertFalse(capsule.status()['resource_pending'])
            self.assertFalse(capsule.validate_live(live)); self.assertEqual(-1, raw.fileno())
            device = lease.locks._device.fd
            restored = lease.restore(timeout=60)  # Exactly one restore attempt.
            self.assertTrue(restored['cleanup_complete'], (restored, lease._diagnostic_restore))
            self.assertIs(type(lease.finish_receipt), core.FinishReceipt)
            self.assertTrue(lease.finish_receipt.complete); self.assertEqual('reconciled', restored['stage'])
            self.assertTrue(bridge.verify_closed()); self.assertEqual({200, 300}, net.reaped)
            self.assertIsNone(net.owned); self.assertNotIn(fixture.pending_fixture.PENDING, io.nodes)
            self.assertEqual(device, io.closed[-1]); self.assertFalse(io.handles); self.assertFalse(kernel.live)
            self.assertFalse(fs.live); self.assertEqual(len(fs.opens), len(fs.closed))
            self.assertIsNone(provider._active_association_receipt)
            self.assertTrue(all(all(a and c for a, c in provider._kernel_closed_facts(row))
                for row in provider._kernel_readers))
            state = store._resource_budget_v23.status()
            self.assertEqual(0, state['active_producers']); self.assertFalse(state['resource_pending'])
            self.assertFalse(provider.status()['send_available']); self.assertFalse(provider.status()['receive_available'])
            self.assertEqual(24, len(modules['mta_client_executor'].MODULES))
            print('HOST_FULL_LIFECYCLE_V23_COUNTS', len(store._files._inventory),
                len(store._files._issued_canonicals), len(provider._collectors), len(provider._proc_calls),
                len(provider._fd_receipts), len(provider._caps_readers), len(provider._kernel_readers),
                len(owner._tickets), len(bridge.registry._inventory), state['counts'], state['retained_payload_bytes'])
            ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))


if __name__ == '__main__': unittest.main()
