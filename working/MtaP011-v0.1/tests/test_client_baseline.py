"""HOST FakeIO only; all real OS/proc/Popen/socket entry points are tripwired."""
import ast
import errno
import hashlib
import json
import math
import os
import stat
import struct
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime')))
import mta_client_baseline as b
from test_ip import message, done, address_payload, route_payload, rule_payload
from test_client_caps_transport import attr, u32, nl, genl, family

REAL_SHA = hashlib.sha256
BOOT = '00000000-0000-0000-0000-000000000003'
STOCK_BYTES = dict((path, ('HOST_SYNTHETIC_BINARY:' + path).encode()) for path, unused in b.core.STOCK_PINS)
CLI_BYTES = b'HOST_SYNTHETIC_CLI'
MANIFEST = b.core.STOCK_PINS + ((b.CLI, REAL_SHA(CLI_BYTES).hexdigest()),)


def fake_hash(data=b''):
    for path, content in STOCK_BYTES.items():
        if data == content:
            return SimpleNamespace(hexdigest=lambda: dict(b.core.STOCK_PINS)[path])
    return REAL_SHA(data)


def metadata(inode, mode, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=0,
        st_gid=0, st_nlink=1, st_size=size, st_mtime_ns=10, st_ctime_ns=10)


class FakeReader(object):
    def __init__(self):
        self.calls, self.self_calls = [], 0
        self.multiple = self.pending = self.changed = self.state_changed = False
        self.boot = BOOT
    def observe(self, number, name, single=False):
        tasks = ((number, number + 100, 'S'),)
        if single and self.multiple: tasks += ((number + 1, 999, 'S'),)
        start = number + 100 + int(single and self.changed and self.self_calls > 1)
        if start != number + 100: tasks = ((number, start, 'S'),)
        actor = b.core.Actor(number, start, '/usr/bin/' + name, 'a' * 64, tasks)
        return b.proc.ProcObservation('live_actor', 'live_actor', 'observed', self.boot,
            actor, False, (), True, 2, (b'HOST_SYNTHETIC_PROC',), 12, 12, self.pending, len(tasks))
    def read_self(self):
        self.self_calls += 1; self.calls.append(('self',))
        return self.observe(200, 'python3', True)
    def read_actor(self, number, expected=None):
        self.calls.append(('actor', number))
        observed = self.observe(number, {101: 'Z03', 102: 'control_engine', 103: 'weston'}[number])
        if self.state_changed and self.self_calls >= 3:
            old = observed.actor
            actor = b.core.Actor(old.pid, old.start, old.exe, old.argv_sha, tuple((t[0],t[1],'R') for t in old.tasks))
            return b.proc.ProcObservation(observed.kind, observed.reason, observed.stage, observed.boot,
                actor, observed.pid_path_absent, observed.remaining_tasks, observed.same_boot, observed.passes,
                observed.raw, observed.file_count, observed.closed_count, observed.resource_pending, observed.task_count)
        return observed


class FakePipe(object):
    def __init__(self, io, data):
        self.io, self.fd, self.closed, self.close_count = io, io.allocate(), False, 0
        io.fds[self.fd] = ['pipe', data, 0]
        self.error = None
    def fileno(self): return self.fd if not self.closed else -1
    def close(self):
        self.close_count += 1
        self.io.fds.pop(self.fd, None); self.closed = True
        if self.error: raise self.error


class FakeProcess(object):
    def __init__(self, io, output):
        self.stdout, self.stderr = FakePipe(io, output), FakePipe(io, b'')
        self.code, self.wait_count, self.kill_count = None, 0, 0
        self.wait_error, self.keep_alive, self.exit_code = None, False, 0
    def poll(self): return self.code
    def wait(self, timeout=None):
        self.wait_count += 1
        if self.wait_error: raise self.wait_error
        if not self.keep_alive: self.code = self.exit_code
        return self.code
    def kill(self): self.kill_count += 1


class FakeSocket(object):
    def __init__(self, io, protocol):
        self.io, self.protocol, self.fd = io, protocol, io.allocate()
        self.port = self.fd + 100; self.inheritable, self.timeout = True, None
        self.packets, self.close_count, self.sent = [], 0, []
        io.fds[self.fd] = ['socket', b'', 0]
    def fileno(self): return self.fd
    def set_inheritable(self, value): self.inheritable = value
    def get_inheritable(self): return self.inheritable
    def bind(self, address):
        if address != (0, 0): raise AssertionError('HOST bind')
    def getsockname(self): return self.port, 0
    def settimeout(self, timeout):
        ns = math.ceil(timeout * 1e9); sec, frac = divmod(ns, 1000000000)
        self.timeout = sec + frac * 1e-9
    def gettimeout(self): return self.timeout
    def sendto(self, request, peer):
        self.sent.append(request); size, kind, flags, seq, port = b._NL.unpack_from(request)
        if peer != (0, 0) or port != self.port: raise AssertionError('HOST peer')
        if self.protocol == 16:
            cmd = request[16]
            if kind == 16 and cmd == 3:
                self.packets.append(genl(16, seq, 1, family(), version=2, port=port))
            elif cmd == 5:
                self.io.interface_calls += 1
                name = b'wlan0\0' if not self.io.missing_station else b'other\0'
                index = 2 + int(self.io.changed_interface and self.io.interface_calls > 1)
                body = u32(1, 0) + u32(3, index) + attr(4, name) + u32(5, 2) + attr(153, struct.pack('<Q', 1))
                if self.io.duplicate_attr: body += u32(3, index)
                self.packets.extend((genl(23, seq, 7, body, flags=2, port=port), nl(3, seq, b'\0' * 4, flags=2, port=port)))
            else: raise AssertionError('HOST nonread-only generic command')
        else:
            mapping = {22: (20, [address_payload()]),
                       26: (24, [route_payload(), route_payload('10.2.0.0', 16, table=1000)]),
                       34: (32, [rule_payload(p, t) for p, t in ((0,255),(32766,254),(32767,253))])}
            if kind not in mapping: raise AssertionError('HOST mutation request')
            reply, rows = mapping[kind]
            self.packets.extend(message(reply, value, sequence=seq, port=port) for value in rows)
            if self.io.route_flags and kind == 26:
                value = self.packets[-1]
                self.packets[-1] = value[:6] + struct.pack('<H', self.io.route_flags) + value[8:]
            self.packets.append(done(seq, port))
        return len(request)
    def recvmsg(self, count, ancillary, flags):
        packet = self.packets.pop(0)
        if self.io.packet_hook: packet = self.io.packet_hook(packet, self)
        return packet, [], self.io.recv_flags, self.io.peer
    def close(self):
        self.close_count += 1
        if self.io.socket_close_error: raise self.io.socket_close_error
        self.io.fds.pop(self.fd, None); self.fd = -1


class FakeIo(object):
    def __init__(self):
        self.clock_value, self.counter = 1.0, 10
        self.fds, self.nodes, self.closed, self.events = {}, {}, [], []
        for path in ('/', '/usr', '/usr/bin', '/usr/sbin'):
            self.nodes[path] = (b'', metadata(len(self.nodes) + 1, stat.S_IFDIR | 0o755))
        for path, data in list(STOCK_BYTES.items()) + [(b.CLI, CLI_BYTES)]:
            self.nodes[path] = (data, metadata(len(self.nodes) + 1, stat.S_IFREG | 0o755, len(data)))
        for number, comm in ((101, b'Z03\n'), (102, b'control_engine\n'), (103, b'weston\n')):
            path = '/proc/' + str(number) + '/comm'
            self.nodes[path] = (comm, metadata(len(self.nodes) + 1, stat.S_IFREG | 0o444))
        for number, name in ((101,'Z03'), (102,'control_engine')):
            self.nodes['/proc/' + str(number) + '/exe'] = self.nodes['/usr/bin/' + name]
        for path, data in (('/proc/net/if_inet6', b'fe800000000000000000000000000001 02 40 20 80 wlan0\n'),
                ('/proc/net/ipv6_route', b'fe800000000000000000000000000000 40 ' + b'0'*32 + b' 00 ' + b'0'*32 + b' 00000100 00000000 00000000 00000001 wlan0\n')):
            self.nodes[path] = (data, metadata(len(self.nodes) + 1, stat.S_IFREG | 0o444))
        self.names, self.sockets, self.processes = ['101','102','103'], [], []
        self.output = b'wpa_state=COMPLETED\nfreq=2412\nssid=HOST_PRIVATE\n'
        self.peer, self.recv_flags, self.route_flags = (0, 0), 0, 0
        self.interface_calls = 0; self.changed_interface = self.missing_station = self.duplicate_attr = False
        self.open_error = self.socket_error = self.spawn_error = self.socket_close_error = None
        self.read_hook = self.packet_hook = self.process_hook = None
        self.fd_close_error = None
    def clock(self): self.clock_value += 0.00001; return self.clock_value
    def allocate(self): self.counter += 1; return self.counter
    def validate(self): self.events.append('validate')
    def stat(self, path):
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST missing')
        return self.nodes[path][1]
    def fstat(self, fd):
        if fd not in self.fds: raise OSError(errno.EBADF, 'HOST closed')
        kind, value, position = self.fds[fd]
        return self.stat(value) if kind == 'file' else metadata(fd, stat.S_IFIFO | 0o600)
    def open(self, path, flags):
        self.events.append(('open', path))
        if self.open_error: raise self.open_error
        self.stat(path); fd = self.allocate(); self.fds[fd] = ['file', path, 0]; return fd
    def read(self, fd, count):
        if self.read_hook: self.read_hook(fd)
        row = self.fds[fd]; data = self.nodes[row[1]][0] if row[0] == 'file' else row[1]
        result = data[row[2]:row[2] + count]; row[2] += len(result); return result
    def close(self, fd):
        self.closed.append(fd)
        if self.fd_close_error: raise self.fd_close_error
        self.fds.pop(fd, None)
    def listdir(self, path):
        if path != '/proc': raise AssertionError('HOST fixed proc')
        return self.names
    def socket(self, protocol):
        if self.socket_error: raise self.socket_error
        value = FakeSocket(self, protocol); self.sockets.append(value); return value
    def readable(self, fds, timeout): return list(fds)
    def spawn(self, descriptor):
        self.events.append(('spawn', descriptor))
        if self.spawn_error: raise self.spawn_error
        value = FakeProcess(self, self.output)
        self.processes.append(value)
        if self.process_hook: self.process_hook(value)
        return value


class BaselineTests(unittest.TestCase):
    def setUp(self):
        for name in ('validate','open','read','fstat','stat','close','listdir','socket','readable','spawn'):
            patcher = mock.patch.object(b._LinuxIo, name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for target in ('socket.socket','subprocess.Popen','select.select','ctypes.CDLL'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('read_self', 'read_actor'):
            patcher = mock.patch.object(b.proc.ProcReader, name, side_effect=AssertionError('actual proc forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(b.hashlib, 'sha256', side_effect=fake_hash)
        patcher.start(); self.addCleanup(patcher.stop)
    def make(self):
        io, reader = FakeIo(), FakeReader()
        return b.BaselineCollector(MANIFEST, _io=io, _reader=reader, _clock=io.clock), io, reader
    def reject(self, value, code=None):
        with self.assertRaises(b.BaselineError) as caught: value.collect(6.0)
        if code: self.assertEqual(code, caught.exception.code)
        self.assertNotIn('HOST_PRIVATE', str(caught.exception)); return caught.exception

    def test_ctor_pure_missing_manifest_and_fixed_scope(self):
        for manifest in (None, (), MANIFEST[:-1], MANIFEST + (('/foreign', 'f'*64),), dict(MANIFEST)):
            with self.assertRaises(b.BaselineError): b.BaselineCollector(manifest)
        owner, io, reader = self.make()
        self.assertEqual([], io.events); self.assertEqual([], reader.calls)
        self.assertFalse(owner.status()['attempted'])
    def test_python35_ast_and_no_mutation_or_fallback_imports(self):
        with open(b.__file__, encoding='utf-8') as handle: tree = ast.parse(handle.read(), feature_version=(3,5))
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertFalse({'unlink','mkdir','flock','fork','execve','system','P2P_GROUP_ADD','restore'} & names)
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        self.assertEqual((b.CLI,'-i','wlan0','status'), b.ARGV)
    def test_complete_two_rounds_real_parsers_all_tables_and_private_raw(self):
        owner, io, reader = self.make(); result = owner.collect(6.0)
        self.assertIs(type(result), b.core.Snapshot); self.assertEqual(2, len(owner._rounds))
        self.assertIn(1000, [r.table for r in result.ipv4.routes]); self.assertEqual(3, len(result.ipv4.rules))
        self.assertEqual(1, len(result.ipv6_addresses)); self.assertEqual(1, len(result.ipv6_routes))
        self.assertFalse(io.fds); self.assertTrue(owner.status()['read_success'])
        self.assertTrue(owner._raw); self.assertTrue(owner._observations)
        self.assertTrue(all(p.stdout.close_count == p.stderr.close_count == 1 for p in io.processes))
        text = json.dumps(owner.status())
        for secret in ('HOST_PRIVATE', 'wlan0', BOOT, b.CLI, '2412', '/usr/bin'): self.assertNotIn(secret, text)
        self.assertFalse(owner.status()['mutation_admission']); self.assertFalse(owner.status()['restoration_verified'])
    def test_status_and_repeated_close_passive_no_second_creation(self):
        owner, io, unused = self.make(); owner.collect(6.0)
        events, closed = list(io.events), list(io.closed)
        self.assertTrue(owner.close()); owner.status()
        self.assertEqual(events, io.events); self.assertEqual(closed, io.closed)
        with self.assertRaises(b.BaselineError): owner.collect(6.0)
    def test_manifest_stock_pin_mismatch_rejected_pure(self):
        bad = (MANIFEST[0][0], 'f'*64)
        with self.assertRaises(b.BaselineError): b.BaselineCollector((bad,) + MANIFEST[1:])
    def test_actual_read_pin_failure_before_socket_or_child(self):
        owner, io, unused = self.make(); io.nodes[b.CLI] = (b'bad', io.nodes[b.CLI][1])
        self.reject(owner, 'file_pin'); self.assertFalse(io.sockets); self.assertFalse(io.processes)
        self.assertFalse(io.fds)
    def test_binary_parent_symlink_or_writable_refused(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o777):
            owner, io, unused = self.make(); io.nodes['/usr'] = (b'', metadata(2, mode))
            self.reject(owner, 'file_identity'); self.assertFalse(io.sockets)
    def test_binary_same_bytes_inode_changed_at_final_readback(self):
        owner, io, unused = self.make()
        def hook(process):
            if len(io.processes) == 2: io.nodes[b.CLI][1].st_ino += 1
        io.process_hook = hook
        self.reject(owner, 'file_identity'); self.assertFalse(owner.status()['read_success'])
    def test_single_thread_caller_and_original_tasks_complete(self):
        owner, io, reader = self.make(); reader.multiple = True
        self.reject(owner, 'actor_unknown'); self.assertFalse(io.sockets); self.assertFalse(io.processes)
    def test_proc_unknown_sticky_not_erased_by_successful_other_closes(self):
        owner, io, reader = self.make(); reader.pending = True
        self.reject(owner, 'close_unknown'); self.assertTrue(owner.status()['resource_pending'])
    def test_self_identity_changed_between_rounds(self):
        owner, io, reader = self.make(); reader.changed = True
        self.reject(owner, 'actor_changed'); self.assertFalse(io.fds)
    def test_missing_original_actor_census_failclosed(self):
        owner, io, reader = self.make(); io.names.remove('103')
        self.reject(owner, 'actor_unknown'); self.assertFalse(io.processes)
    def test_proc_read_errno_not_silently_skipped(self):
        owner, io, unused = self.make(); del io.nodes['/proc/103/comm']
        self.reject(owner, 'io_error'); self.assertFalse(io.processes)
    def test_kernel_sender_and_truncation_rejected(self):
        for peer, flags in (((7,0),0), ((0,0),32), ((0,0),8)):
            owner, io, unused = self.make(); io.peer, io.recv_flags = peer, flags
            self.reject(owner); self.assertFalse(io.fds)
    def test_dump_filtered_or_interrupted_rejected(self):
        for flags in (2 | 16, 2 | 32):
            owner, io, unused = self.make(); io.route_flags = flags
            self.reject(owner); self.assertFalse(owner.status()['read_success'])
    def test_generic_header_sequence_port_and_done_ack_mismatch(self):
        for change in ('seq','port','ack'):
            owner, io, unused = self.make()
            def hook(packet, sock):
                if sock.protocol != 16: return packet
                row = list(b._NL.unpack_from(packet))
                if change == 'seq': row[3] += 1
                elif change == 'port': row[4] = 0
                else: row[1] = 2
                return b._NL.pack(*row) + packet[16:]
            io.packet_hook = hook; self.reject(owner, 'netlink_format')
    def test_duplicate_interface_and_missing_wlan0_failclosed(self):
        for field in ('duplicate_attr','missing_station'):
            owner, io, unused = self.make(); setattr(io, field, True)
            self.reject(owner); self.assertFalse(io.processes)
    def test_second_round_full_origin_changed(self):
        owner, io, unused = self.make(); io.changed_interface = True
        self.reject(owner, 'snapshot_changed'); self.assertEqual(2, len(owner._rounds))
    def test_ipv6_full_width_and_duplicate_failclosed(self):
        for data in (b'invalid\n', b'fe800000000000000000000000000001 02 40 20 80 wlan0\n'*2):
            owner, io, unused = self.make(); path = '/proc/net/if_inet6'; io.nodes[path] = (data, io.nodes[path][1])
            self.reject(owner, 'ipv6_format')
    def test_ipv6_kernel_minimum_hex_width_not_truncated(self):
        owner, io, unused = self.make(); path = '/proc/net/if_inet6'
        io.nodes[path] = (b'fe800000000000000000000000000001 100 40 20 80 wlan0\n', io.nodes[path][1])
        result = owner.collect(6.0); self.assertEqual(('100','40','20','80'), result.ipv6_addresses[0][1:5])
    def test_status_only_completed_frequency_and_duplicate_keys(self):
        for output in (b'wpa_state=INACTIVE\nfreq=2412\n', b'wpa_state=COMPLETED\nfreq=5180\n',
                b'wpa_state=COMPLETED\nfreq=2412\nfreq=2412\n', b'noise\n'):
            owner, io, unused = self.make(); io.output = output
            self.reject(owner); self.assertFalse(io.fds)
    def test_bounded_stdout_before_buffering_unlimited_output(self):
        owner, io, unused = self.make(); io.output = b'x' * 20000
        self.reject(owner, 'file_budget'); row = [r for r in owner._tickets if r['kind'] == 'process'][0]
        self.assertLessEqual(len(row['chunks'][row['pipes'][0]['fd']]), 16385)
        self.assertEqual(1, io.processes[0].kill_count)
    def test_spawn_unknown_no_guess_kill_no_retry_preserves_ticket(self):
        owner, io, unused = self.make(); io.spawn_error = KeyboardInterrupt('HOST_PRIVATE')
        self.reject(owner, 'close_unknown'); rows = [r for r in owner._tickets if r['kind'] == 'process']
        self.assertEqual(1, len(rows)); self.assertTrue(rows[0]['unknown'])
        self.assertIsNone(rows[0]['value']); self.assertTrue(owner.status()['resource_pending'])
        owner.close(); self.assertEqual(1, sum(e[0] == 'spawn' for e in io.events if type(e) is tuple))
    def test_bad_factory_return_retained_not_closed_as_foreign(self):
        owner, io, unused = self.make(); returned = object(); io.socket = lambda protocol: returned
        self.reject(owner, 'close_unknown'); self.assertIs(owner._tickets[-1]['value'], returned)
    def test_close_error_attempts_remaining_originals_once(self):
        owner, io, unused = self.make(); io.socket_close_error = OSError(errno.EIO, 'HOST_PRIVATE')
        self.reject(owner, 'close_unknown'); self.assertEqual([1,1], [s.close_count for s in io.sockets])
        self.assertTrue(all(p.stdout.closed and p.stderr.closed for p in io.processes))
        owner.close(); self.assertEqual([1,1], [s.close_count for s in io.sockets])
    def test_pipe_close_consumed_error_sticky_even_closed_true(self):
        owner, io, unused = self.make()
        io.process_hook = lambda p: setattr(p.stdout, 'error', MemoryError('HOST_PRIVATE'))
        self.reject(owner, 'close_unknown'); value = io.processes[0]
        self.assertTrue(value.stdout.closed); self.assertEqual(1, value.stderr.close_count)
        owner.close(); self.assertEqual(1, value.stdout.close_count)
    def test_process_wait_unknown_keeps_owner_but_still_closes_pipes_and_fd(self):
        owner, io, unused = self.make(); io.process_hook = lambda p: setattr(p, 'wait_error', RuntimeError('HOST_PRIVATE'))
        self.reject(owner, 'close_unknown'); process = io.processes[0]
        self.assertTrue(process.stdout.closed and process.stderr.closed)
        row = [r for r in owner._tickets if r['kind'] == 'process'][0]
        self.assertIs(row['value'], process); self.assertFalse(row['closed'])
    def test_foreign_pipe_swap_retains_original_and_never_closes_foreign(self):
        owner, io, unused = self.make(); saved = []
        def change(fd):
            if not io.processes or saved: return
            process = io.processes[0]
            if fd != process.stdout.fd: return
            original, foreign = process.stdout, FakePipe(io, b'HOST_FOREIGN')
            process.stdout = foreign; saved.extend((original, foreign))
        io.read_hook = change
        self.reject(owner, 'close_unknown')
        self.assertEqual([0,0], [p.close_count for p in saved])
        self.assertEqual(1, io.processes[0].stderr.close_count)
        original_ticket = [r for r in owner._tickets if r['kind'] == 'pipe' and r['name'] == 'stdout'][0]
        self.assertIs(original_ticket['value'], saved[0]); self.assertFalse(original_ticket['closed'])
        self.assertFalse(io.sockets[0].fd >= 0 or io.sockets[1].fd >= 0)
    def test_partial_pipe_creation_retains_process_without_guessing_kill(self):
        owner, io, unused = self.make()
        def change(process): process.stderr = object()
        io.process_hook = change
        self.reject(owner, 'close_unknown'); process = io.processes[0]
        self.assertEqual(0, process.kill_count); self.assertEqual(1, process.stdout.close_count)
        record = [r for r in owner._tickets if r['kind'] == 'process'][0]
        self.assertIs(record['value'], process); self.assertTrue(record['unknown'])
        self.assertTrue(any(r['unknown'] and r['kind'] == 'pipe' for r in owner._tickets))
    def test_second_round_raw_wpa_fingerprint_must_match(self):
        owner, io, unused = self.make()
        def change(process):
            if len(io.processes) == 1: io.output += b'bssid=HOST_CHANGED\n'
        io.process_hook = change
        self.reject(owner, 'snapshot_changed'); self.assertEqual(2, len(owner._rounds))
        self.assertFalse(io.fds)
    def test_full_stock_task_state_change_between_rounds_rejected(self):
        owner, io, reader = self.make(); reader.state_changed = True
        self.reject(owner, 'snapshot_changed'); self.assertEqual(2, len(owner._rounds))
        self.assertFalse(io.fds)
    def test_actual_process_image_digest_and_inode_not_pathname_or_argv_sha(self):
        for change in ('digest','inode'):
            owner, io, unused = self.make(); path = '/proc/101/exe'; data, meta = io.nodes[path]
            if change == 'digest': io.nodes[path] = (b'x' * len(data), meta)
            else: io.nodes[path] = (data, metadata(meta.st_ino + 100, meta.st_mode, meta.st_size))
            self.reject(owner, 'file_pin' if change == 'digest' else 'file_identity')
            self.assertFalse(io.processes); self.assertFalse(io.fds)
            self.assertFalse(owner.status()['read_success'])
    def test_actor_image_readback_requires_fresh_exact_actor_tasks(self):
        owner, io, reader = self.make(); original = reader.read_actor
        def changed(number, expected=None):
            observed = original(number, expected)
            if expected is None: return observed
            actor = observed.actor
            replaced = b.core.Actor(actor.pid, actor.start + 1, actor.exe, actor.argv_sha,
                ((actor.pid,actor.start + 1,'S'),))
            return b.proc.ProcObservation(observed.kind, observed.reason, observed.stage, observed.boot,
                replaced, False, (), True, 2, observed.raw, observed.file_count,
                observed.closed_count, observed.resource_pending, observed.task_count)
        reader.read_actor = changed; self.reject(owner, 'actor_changed')
        self.assertFalse(io.processes); self.assertFalse(io.fds)
    def test_packet_budget_bound_and_raw_retention_failure_closes_known_sockets(self):
        owner, io, unused = self.make()
        with mock.patch.object(b, 'MAX_PACKETS', 1): self.reject(owner, 'netlink_budget')
        self.assertEqual(2, owner.status()['datagram_count']); self.assertFalse(io.fds)
        owner, io, unused = self.make()
        class FailRaw(list):
            def append(self, value):
                if value[0] == 'netlink': raise MemoryError('HOST_PRIVATE')
                super(FailRaw, self).append(value)
        owner._raw = FailRaw(); self.reject(owner, 'io_error')
        self.assertIsNotNone(owner._incoming); self.assertFalse(io.fds)
    def test_expired_budget_invalid_types_and_clock(self):
        for deadline in (True, 10**1000, float('nan'), float('inf')):
            owner, io, unused = self.make()
            with self.assertRaises(b.BaselineError): owner.collect(deadline)
            self.assertFalse(io.events)
        owner, io, unused = self.make(); io.clock_value = 9
        self.reject(owner, 'deadline'); self.assertFalse(io.events)


if __name__ == '__main__': unittest.main()
