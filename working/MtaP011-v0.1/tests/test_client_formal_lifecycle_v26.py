"""One new HOST FormalF lifecycle, never a device/phone/resource-cost proof.

The 29-definition domain and lifecycle algorithms are actual fixed sources.
Source-loader approval, process execution, RF/netlink/control/DHCP ingress are
explicit synthetic assumptions. Real PC stock backup bytes and their original
pins feed the actual collector/STATUS parsers. No ready/Handle/FinishReceipt,
Snapshot or lifecycle closure boolean is injected. Only fixture definitions
are reused; source-loader closure/approval remains a stated HOST assumption.
Only shared FakeIO and ProcessKernel allocations use one descriptor namespace;
KernelReader socket descriptors and subprocess observation remain independent
synthetic domains. The fixed clock does not prove wall-clock deadlines or the
final passive owner/history late-return cap check.
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
sys.path.insert(0, str(BASE / 'tests'))
INPUT_PINS = {
    'tests/test_client_actual_collector_v25.py': 'd3285398a5a6eb6f0b48826dbcfce0281ad97be41a7a1723d7bb0060b346f657',
    'host/client_formal_v26_source_manifest.json': '1dbfc59425315d8ab2bcc3bf4a60aaa551fdb36d8707d884d5f9a512a694d586',
}
FORMAL_PINS = {
    'mta_client_executor': '11b17396c8ff825069d4c32c9beec05983558bc2a3ca54ad03d7a69278d70ff5',
    'mta_client_process_owner': '4bbf9e64f5508e6498f64d4cd8f94383612939552eb740ef46ad1354f416e27b',
    'mta_client_linux_provider': 'a4fbc089bf594997f01280d8d469188ca8a85e10feaecca5ef033ed2db529a08',
    'mta_client_dora': 'af501b1426bda15a54c531fab26a1aa3d408c8bcd288d98af1cbe066805ed83c',
}


def fixed(relative, pin):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('HOST fixed input changed')
    return raw


def definitions():
    # Only fixed SOURCE path/definition imports precede OS tripwires. Fresh
    # target definitions and every lifecycle constructor/call remain inside.
    for path, pin in INPUT_PINS.items(): fixed(path, pin)
    collector = importlib.import_module('test_client_actual_collector_v25')
    full, packets = collector.dependencies()
    fixed('tests/test_client_durable_connect_v19.py', full.V19_SHA)
    importlib.import_module('test_client_durable_connect_v19')
    importlib.import_module('test_client_proc')
    importlib.import_module('test_client_process_owner')
    return collector, full, packets


def domain(collector):
    rows = json.loads(fixed('host/client_formal_v26_source_manifest.json',
        INPUT_PINS['host/client_formal_v26_source_manifest.json']))['sources']
    if len(rows) != 29 or len({row['module'] for row in rows}) != 29:
        raise ValueError('HOST source graph changed')
    inputs = {}
    for row in rows:
        raw = fixed(row['path'], row['sha256'])
        if len(raw) != row['bytes'] or row['module'] in FORMAL_PINS and \
                row['sha256'] != FORMAL_PINS[row['module']]:
            raise ValueError('HOST source length/pin changed')
        inputs[row['module']] = raw
    modules, actual_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private source unavailable')
            return modules[name]
        return actual_import(name, *args, **kwargs)
    for name in inputs:
        raw = inputs[name]
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-fixed-v26/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(modules) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST fixed graph order changed')
    return modules, inputs, collector


class SyntheticDeploymentAuthentication:
    """HOST assumption only. Actual Loader's 33 reads have separate evidence."""
    def __init__(self, python_record):
        self.owner = types.SimpleNamespace(rows=[python_record])
        self.deployment = None
    def authenticate(self, value):
        if value is not self.deployment: raise ValueError('HOST deployment changed')
        return None


def model_tripwires(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat',
            'os.stat', 'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'os.system', 'os.urandom',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name,
            side_effect=AssertionError('actual OS forbidden'), create=True))
    stack.enter_context(mock.patch.object(socket, 'CMSG_SPACE',
        lambda size: 16 + ((size + 7) // 8) * 8, create=True))


class FormalLifecycleV26Tests(unittest.TestCase):
    def test_actual_formal_f_init_connect_dora_single_restore_with_actual_collectors(self):
        collector, full, packets = definitions()
        with ExitStack() as source_stack:
            model_tripwires(source_stack)
            modules, inputs, collector = domain(collector)
        # This exact pinned setup only defines/clones fixture functions and
        # classes. Its SOURCE Path.resolve is not an adapter syscall.
        fixture_definitions = full.setup_definitions(modules)
        fixture, proc_helpers, unused_owner_helpers = fixture_definitions
        with ExitStack() as stack:
            model_tripwires(stack)
            def saved_definitions(target):
                if target is not modules: raise AssertionError('HOST fixture domain changed')
                return fixture_definitions
            stack.enter_context(mock.patch.object(full, 'setup_definitions', saved_definitions))
            values = collector.make_fixture(modules, full, packets)
            lease, provider, store, owner, bridge, io, fs, kernel, net, clock = values
            p, f, core, dhcp, wire = (modules[name] for name in
                ('mta_client_linux_provider', 'mta_client_executor', 'mta_p2p_client_init',
                 'mta_dhcp_client', 'mta_dhcp'))
            p._OWNERS[:] = []
            self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
            # Remove only the collector-only fixture's instance tripwire. The
            # original class's complete INIT/persistence/launch path now runs.
            del lease.start
            lease.clock = clock
            self.assertNotIn('start', lease.__dict__)
            self.assertIs(provider._collector_factory, p._AuthenticatedCollector)
            self.assertIs(provider._status_factory,
                modules['mta_client_wpa_status'].AuthenticatedStatusReader)
            self.assertIsNone(lease.record); self.assertFalse(lease.handles)
            self.assertFalse(store._attempted); self.assertFalse(store._opened)
            self.assertFalse(bridge._operations)
            # Unify only shared FakeIO and ProcessKernel allocations; other
            # observer/subprocess synthetic domains are not unified here.
            # Original alloc/open metadata, OFD, inventory insertion, fstat
            # routing and close remain unchanged.
            original_alloc, original_open = kernel.alloc, io._open
            next_descriptor = [max([2, io.fd] + list(io.handles) + list(kernel.live)) + 1]
            def reserve_descriptor():
                fd = next_descriptor[0]
                if fd in io.handles or fd in kernel.live:
                    raise AssertionError('HOST allocator live collision')
                return fd
            def allocate_kernel(meta, data=b'', ofd=None):
                fd = reserve_descriptor(); kernel.nextfd = fd
                returned = original_alloc(meta, data, ofd)
                if type(returned) is not int or returned != fd or fd in io.handles:
                    raise AssertionError('HOST kernel allocation changed')
                next_descriptor[0] = fd + 1
                return returned
            def open_shared(path, flags, mode):
                fd = reserve_descriptor(); io.fd = fd - 1
                returned = original_open(path, flags, mode)
                if type(returned) is not int or returned != fd or fd in kernel.live:
                    raise AssertionError('HOST file allocation changed')
                next_descriptor[0] = fd + 1
                return returned
            kernel.alloc, io._open = allocate_kernel, open_shared
            # The collector-only fixture's directory model contains /proc,
            # while this full lifecycle's real FakeIO nodes contain the
            # existing private run. Enumerate all actual model entries; do
            # not inject a prior-clear boolean or hide foreign children.
            original_listdir = io.listdir
            base_dir = '/tmp/' + modules['mta_client_coordination'].BASE
            def listdir_current(path):
                if path != base_dir: return original_listdir(path)
                prefix = path + '/'
                return sorted(name[len(prefix):] for name in io.nodes if
                    name.startswith(prefix) and '/' not in name[len(prefix):])
            io.listdir = listdir_current
            self.assertEqual([], original_listdir(base_dir))
            self.assertEqual([modules['mta_client_coordination'].RUN_PREFIX +
                provider.manifest.run_token], io.listdir(base_dir))
            # Narrow diagnostic only: preserve the original exception before
            # the existing fixed remapping, with no changed control behavior.
            remapped_errors = []
            original_report = store._coordination._report
            def report_original(error):
                allowed = (AssertionError, AttributeError, KeyError, OSError,
                    RuntimeError, TypeError, ValueError)
                kind = type(error).__name__ if type(error) in allowed else 'other'
                number = getattr(error, 'errno', None)
                number = number if type(number) is int and 1 <= number <= 4095 else 0
                trace, frame = [], error.__traceback__
                while frame is not None:
                    code = frame.tb_frame.f_code
                    if code.co_filename.startswith('HOST-fixed-v26/'):
                        trace.append((code.co_name, frame.tb_lineno))
                    frame = frame.tb_next
                remapped_errors.append((error, (kind, number, tuple(trace))))
                return original_report(error)
            stack.enter_context(mock.patch.object(store._coordination, '_report', report_original))

            # Keep the actual manifest/binding classes in this graph. Only its
            # fixed executor image pin changes to the new FormalF source.
            pm_values = {key: getattr(provider.manifest, key) for key in p._KEYS}
            pm_values['status_manifest'] = dict(pm_values['status_manifest'])
            pm_values['executor_sha'] = hashlib.sha256(inputs['mta_client_executor']).hexdigest()
            provider.manifest = p.ProviderManifest(pm_values, _manifest_sha256='1' * 64)
            pm = provider.manifest
            io.add(pm.executor_path, stat.S_IFREG | 0o400, inputs['mta_client_executor'])
            python = unused_owner_helpers.ELF
            if hashlib.sha256(python).hexdigest() != pm.python_sha:
                raise ValueError('HOST synthetic Python image changed')
            io.add(pm.python_exe, stat.S_IFREG | 0o755, python)
            python_meta = f._meta(io.stat(pm.python_exe))
            source_row = {'path': pm.python_exe, 'raw': python, 'metadata': python_meta,
                'unknown': False, 'closed': True}
            authentication = SyntheticDeploymentAuthentication(source_row)
            dep = f.LoadedDeployment(authentication, modules, pm, pm.manifest_sha256,
                pm.run_dir, provider._connect_binding)
            authentication.deployment = dep
            argv = f._argv(dep, '--execute-client-init', '20.0')
            current_argv = b'\0'.join(value.encode('ascii') for value in argv) + b'\0'
            self_root = '/proc/' + str(fixture.SELF.pid)
            fs.files[self_root + '/cmdline'] = current_argv
            fs.links[self_root + '/exe'] = pm.python_exe
            fs.files[self_root + '/comm'] = b'python3\n'

            original_fork, original_write = kernel.fork, kernel.write
            def fork_current():
                pid = original_fork()
                child_root = '/proc/' + str(pid)
                fs.files[child_root + '/cmdline'] = fs.files[self_root + '/cmdline']
                fs.links[child_root + '/exe'] = fs.links[self_root + '/exe']
                fs.files[child_root + '/comm'] = b'python3\n'
                return pid
            def release_current(fd, data):
                result = original_write(fd, data)
                if data == b'1':
                    child = next(child for child in owner._tickets if
                        any(row.role == 'gate_write' and row.fd == fd for row in child.fds))
                    fs.files['/proc/' + str(child.pid) + '/comm'] = (
                        b'wpa_supplicant\n' if child.spec.role == 'controller' else b'python3\n')
                return result
            kernel.fork, kernel.write = fork_current, release_current

            # Collector sockets precede private control sockets in this full
            # fixture. Route the synthetic group datagram to its exact saved
            # event raw object, never the old fixture's numeric list index.
            original_ctrl = io.new_ctrl
            def new_ctrl():
                raw = original_ctrl()
                def send_control(command):
                    raw.sent.append(command)
                    if io.command_hook: io.command_hook(raw, command)
                    if command == b'STATUS' and not net.connection_started:
                        reply = (b'wpa_state=INACTIVE\np2p_device_address=02:11:22:33:44:55\n'
                            b'address=02:66:77:88:99:aa\nuuid=12345678-1234-1234-1234-123456789abc\n')
                    elif command == b'STATUS':
                        reply = b'wpa_state=DISCONNECTED\n' if io.disconnected else io.status_wire
                    elif command == b'ADD_NETWORK': reply = io.add_wire
                    else:
                        if command == b'DISCONNECT': io.disconnected = True
                        reply = b'OK\n'
                    credentials = [(1, 2, p._CRED.pack(300, 0, 0))]
                    raw.queue.append((reply, credentials, 0, raw.peer))
                    if command.startswith(b'P2P_GROUP_ADD'):
                        net.connection_started = True
                        event = provider._connection_event.value
                        event.queue.extend(io.queue_event or [(io.group_wire, credentials, 0, raw.peer)])
                    return len(command)
                raw.send = send_control
                return raw
            io.new_ctrl = new_ctrl

            def interface_wire():
                # The single modeled kernel inventory is the collector's
                # original raw wlan0 plus only the actual CREATE state.
                station = (packets.u32(1, 0) + packets.u32(3, 2) +
                    packets.attr(4, b'wlan0\0') + packets.u32(5, 2) +
                    packets.attr(153, struct.pack('<Q', 1)))
                result = [station]
                if net.owned is not None:
                    owned = net.owned
                    result.append(packets.u32(1, owned.phy) + packets.u32(3, owned.ifindex) +
                        packets.attr(4, owned.name.encode('ascii') + b'\0') +
                        packets.u32(5, owned.iftype) + packets.attr(153, struct.pack('<Q', owned.wdev)))
                return result
            original_genl = io.new_genl
            def new_genl_current():
                raw = original_genl()
                send = raw.sendto
                def send_inventory(request, peer):
                    unused, family, flags, seq, port = p._NL.unpack(request[:16])
                    if family == 16 or request[16] != 5: return send(request, peer)
                    if peer != (0, 0) or flags & 0x300 != 0x300:
                        raise AssertionError('HOST unplanned interface query')
                    raw.sent.append(request)
                    replies = [packets.genl(family, seq, 7, body, flags=2, port=port)
                        for body in interface_wire()]
                    replies.append(packets.nl(3, seq, b'\0' * 4, flags=2, port=port))
                    raw.queue.extend((reply, [], 0, (0, 0)) for reply in replies)
                    return len(request)
                raw.sendto = send_inventory
                return raw
            io.new_genl = new_genl_current

            # The actual collector parses these raw kernel replies. A newly
            # created owned interface is supplied by the existing CREATE state,
            # not a fabricated ready Snapshot or a replacement collector.
            original_socket = io.socket
            def baseline_socket(protocol):
                raw = original_socket(protocol)
                send = raw.sendto
                def send_with_current(request, peer):
                    result = send(request, peer)
                    if protocol == 16 and request[16] == 5 and net.owned is not None:
                        owned = net.owned
                        body = (packets.u32(1, owned.phy) + packets.u32(3, owned.ifindex) +
                            packets.attr(4, owned.name.encode('ascii') + b'\0') +
                            packets.u32(5, owned.iftype) + packets.attr(153, struct.pack('<Q', owned.wdev)))
                        unused_length, unused_kind, unused_flags, seq, port = p._NL.unpack(request[:16])
                        raw.packets.insert(-1, packets.genl(23, seq, 7, body, flags=2, port=port))
                    return result
                raw.sendto = send_with_current
                return raw
            io.socket = baseline_socket

            datagrams = []
            class Datagram(full.HostDatagram):
                def __init__(self):
                    full.HostDatagram.__init__(self, dhcp)
                    path = '/HOST-formal-dora-' + str(len(datagrams))
                    io.add(path, stat.S_IFSOCK | 0o600)
                    self.fd = io.open(path, 0)
                    self.original_fd, self.close_count = self.fd, 0
                def close(self):
                    self.close_count += 1
                    if self.close_count != 1: raise AssertionError('HOST duplicate UDP close')
                    result = io.close(self.fd)
                    self.fd = -1
                    return result
                def sendmsg(self, buffers, ancillary, flags, target):
                    result = full.HostDatagram.sendmsg(self, buffers, ancillary, flags, target)
                    request = wire.decode(buffers[0])
                    if request['type'] not in (wire.DISCOVER, wire.REQUEST):
                        raise AssertionError('HOST unplanned DHCP command')
                    kind = wire.OFFER if request['type'] == wire.DISCOVER else wire.ACK
                    response = wire.encode(2, request['xid'], request['chaddr'],
                        {53: bytes(bytearray((kind,))), 54: wire.ipv4('192.168.49.7'),
                         1: wire.ipv4('255.255.255.0'), 51: struct.pack('!I', 60)},
                        yiaddr=wire.ipv4('192.168.49.123'))
                    control = [(socket.IPPROTO_IP, dhcp.IP_PKTINFO,
                        dhcp.PKTINFO.pack(net.owned.ifindex, wire.ZERO, b'\xff' * 4))]
                    self.queue.append((response, control, 0, ('192.168.49.7', 67)))
                    return result
            def socket_factory(family, kind, protocol):
                if (family, kind, protocol) != (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP):
                    raise AssertionError('HOST unplanned socket')
                raw = Datagram(); datagrams.append(raw); return raw
            actual_client_ctor = dhcp.DhcpSocketClient.__init__
            def client_ctor(instance, *args, **kwargs):
                if 'socket_factory' in kwargs or 'if_nametoindex' in kwargs:
                    raise AssertionError('HOST unexpected DHCP seam')
                kwargs['socket_factory'] = socket_factory
                kwargs['if_nametoindex'] = lambda name: net.owned.ifindex if name == net.owned.name else 0
                kwargs['xid'] = 0x12345678  # Synthetic transaction entropy, not an authorization.
                return actual_client_ctor(instance, *args, **kwargs)
            stack.enter_context(mock.patch.object(dhcp.DhcpSocketClient, '__init__', client_ctor))

            class Input:
                reason = None
                def __init__(self): self.executor = self.request = None
                def poll(self):
                    done = self.executor.dora_ticket is not None and self.executor.dora_ticket['allocation'] is not None
                    if done: self.reason = 'cancelled'
                    return bool(done)
                def take_connect(self):
                    if self.request is not None: return None
                    codec = modules['mta_client_control_frame']
                    decoder = codec.ControlFrameDecoder(provider._connect_binding)
                    decoder.feed(codec.encode_connect(provider._connect_binding, fixture.info()))
                    self.request = decoder.take_connect()
                    return self.request
            control = Input()
            inherited_fd = io.open(pm.python_exe, 0)
            assembly = (provider, store, owner, bridge, lease)
            def assemble_original(manifest, _connect_binding=None):
                if manifest is not pm or _connect_binding is not provider._connect_binding:
                    raise AssertionError('HOST assembly ownership changed')
                return assembly
            stack.enter_context(mock.patch.object(p, 'assemble', assemble_original))
            original_io_write = io.write
            io.write = lambda fd, raw: len(raw) if fd == 2 else original_io_write(fd, raw)
            io.ready = lambda descriptors, seconds: []
            frames = []
            executor = f.ClientExecutor(dep, _io=io, _clock=clock, _input=control,
                _emit=frames.append, _ttl_text='20.0',
                _environ={'P011_CLIENT_EXECUTABLE_FD': str(inherited_fd)}, _proc_fs=fs)
            control.executor = executor
            result = executor.run(ttl=20)
            marker_reader = None if store._marker is None else store._marker._reader
            history = () if marker_reader is None else marker_reader.operation_history
            marker_diagnostic = None
            if history:
                generation = history[-1]
                observation = generation.observation
                caught = generation.error
                error_kind = ('AssertionError' if type(caught) is AssertionError else
                    'os' if type(caught) is OSError else 'none' if caught is None else 'other')
                trace, frame = [], None if caught is None else caught.__traceback__
                while frame is not None:
                    code = frame.tb_frame.f_code
                    if code.co_filename.startswith('HOST-fixed-v26/') or code.co_filename == __file__:
                        trace.append((code.co_name, frame.tb_lineno))
                    frame = frame.tb_next
                marker_diagnostic = (None if observation is None else
                    (observation.kind, observation.reason, observation.stage,
                     observation.file_count, observation.closed_count, observation.resource_pending),
                    error_kind, tuple(trace), io.fd, len(set(kernel.live).intersection(io.handles)))
            self.assertTrue(result['done'], (result, executor._diagnostic_start,
                executor._diagnostic_restore, executor._diagnostic_complete,
                tuple(summary for error, summary in remapped_errors), marker_diagnostic))
            self.assertFalse(result['resource_pending']); self.assertEqual('restored', result['reason'])
            self.assertTrue(executor.start_call_started); self.assertTrue(executor.init_ready)
            self.assertEqual(2, len(owner._tickets)); self.assertEqual({200, 300}, net.reaped)
            self.assertTrue(any(frame['client_init_ready'] for frame in frames))
            self.assertTrue(frames[-1]['done']); self.assertFalse(frames[-1]['resource_pending'])
            self.assertIs(type(executor.dora_ticket['allocation']), modules['mta_client_dora'].LiveAllocation)
            self.assertIs(executor.dora_ticket['returned'], provider._dora_v26_creation['returned'])
            self.assertEqual(1, len(datagrams)); self.assertEqual(2, len(datagrams[0].sent))
            self.assertEqual(1, datagrams[0].close_count); self.assertEqual(-1, datagrams[0].fileno())
            with self.assertRaises(OSError) as closed: io.fstat(datagrams[0].original_fd)
            self.assertEqual(errno.EBADF, closed.exception.errno)
            self.assertIs(type(executor.finish), core.FinishReceipt); self.assertTrue(executor.finish.complete)
            self.assertEqual('absent_observed', executor.finish.marker_state)
            self.assertEqual('verified', executor.finish.clear_durability)
            self.assertEqual('reconciled', lease.record.stage)
            self.assertIsNone(net.owned); self.assertNotIn(fixture.pending_fixture.PENDING, io.nodes)
            self.assertIsNone(lease.locks)
            # Device-last belongs to B's exact component inventory, not the
            # later independent F read-only Proc close observations.
            store_tickets = tuple(store._coordination._inventory) + tuple(store._files._inventory) + (store._marker._ticket,)
            self.assertTrue(all(ticket.closed and (ticket.fd is None or ticket.attempted)
                for ticket in store_tickets))
            store_fds = {ticket.fd for ticket in store_tickets if type(ticket.fd) is int}
            store_closes = [fd for fd in io.closed if fd in store_fds]
            self.assertEqual(store_fds, set(store_closes))
            self.assertEqual(len(store_fds), len(store_closes))
            self.assertEqual(executor.finish.locks._device.fd, store_closes[-1])
            self.assertFalse(io.handles); self.assertFalse(kernel.live)
            self.assertTrue(all(reader.history_closed() for reader in store._resource_budget_v23._readers))
            self.assertFalse(provider.status()['send_available']); self.assertFalse(provider.status()['receive_available'])
            self.assertFalse(result['ip_ready']); self.assertFalse(result['association_verified'])
            self.assertFalse(result['phone_tested']); self.assertEqual(29, len(modules))
            self.assertTrue(all(row['reader']._io is not None and type(row['reader']) is p._AuthenticatedCollector
                for row in provider._collectors))
            print('HOST_FORMAL_F_V26_COUNTS', len(provider._collectors), len(provider._caps_readers),
                len(provider._kernel_readers), len(store._files._inventory), len(owner._tickets),
                len(datagrams), len(store._resource_budget_v23._readers))
            ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))


if __name__ == '__main__': unittest.main()
