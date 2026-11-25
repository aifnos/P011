"""New limited HOST wire/fact/once-close tests, NOT native MTA permission.

Actual mta_ip/core/dynamic-IP definitions are isolated under OS tripwires. A
synthetic netlink kernel answers real encoded requests; its automatic routes,
socket metadata, descriptor table and clock are explicit model assumptions.
The positive method exercises ClientRouteTransport and immutable schema facts,
NOT ClientDynamicIp.start, actual DORA L3Handoff, actual durable Journal fsync,
INIT/CONNECT, Linux namespace, P011 address installation or phone transfer.
No previous test suite/method or archived device script is imported/invoked.
"""
from contextlib import ExitStack
import ast
import builtins
import errno
from pathlib import Path
import socket
import stat
import struct
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SOURCES = (('mta_ip', 'runtime/mta_ip.py'),
    ('mta_p2p_client_init', 'candidate/client-session-v28/runtime/mta_p2p_client_init.py'),
    ('mta_client_dynamic_ip', 'candidate/client-session-v28/runtime/mta_client_dynamic_ip.py'))


def tripwires(stack):
    stack.enter_context(mock.patch('socket.AF_NETLINK', 16, create=True))  # Explicit Linux ABI MODEL on Windows.
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.close', 'os.fstat', 'os.urandom', 'os.system',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))


def domain():
    modules, imported = {}, builtins.__import__
    raw_sources = [(name, str(BASE / path), (BASE / path).read_bytes()) for name, path in SOURCES]
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private dependency unavailable')
            return modules[name]
        return imported(name, *args, **kwargs)
    with ExitStack() as stack:
        tripwires(stack)
        for name, path, raw in raw_sources:
            tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
                raise ValueError('target assertions forbidden')
            module = types.ModuleType(name); module.__file__ = path
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            modules[name] = module
            exec(compile(raw, path, 'exec'), module.__dict__)
    return modules


M = domain()
ip, core, dynamic = M['mta_ip'], M['mta_p2p_client_init'], M['mta_client_dynamic_ip']


class Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class Kernel(object):
    """Explicit MODEL: one netlink FD; permanent IPv4 + four auto routes."""
    def __init__(self, owned, clock):
        self.owned, self.clock = owned, clock
        self.snapshot = ip.IpSnapshot((), (), (ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254), ip.RuleRecord(32767, 253)))
        self.raw = None; self.sent = []; self.inode = 42; self.close_count = 0
        self.factory_count = 0; self.reuse_reads = 0; self.factory_late = False
    def fstat(self, descriptor):
        if descriptor != 17 or self.raw is None or self.raw.closed:
            raise OSError(errno.EBADF, 'synthetic closed descriptor')
        return types.SimpleNamespace(st_dev=1, st_ino=self.inode, st_mode=stat.S_IFSOCK | 0o600, st_rdev=0)
    def factory(self, family, kind, protocol):
        if (family, kind, protocol) != (socket.AF_NETLINK, socket.SOCK_RAW, 0): raise AssertionError('unexpected socket')
        self.factory_count += 1
        self.raw = Raw(self)
        if self.factory_late: self.clock.value = 8.0
        return self.raw
    def _dump(self, command, sequence, port):
        messages = []
        if command == ip.RTM_GETADDR:
            for r in self.snapshot.addresses:
                payload = struct.pack('<BBBBI', ip.AF_INET, r.prefixlen, r.flags, r.scope, r.ifindex)
                for kind, data in ((ip.IFA_ADDRESS, struct.pack('>I', r.address)),
                        (ip.IFA_LOCAL, struct.pack('>I', r.local)), (ip.IFA_LABEL, r.label),
                        (ip.IFA_BROADCAST, struct.pack('>I', r.broadcast)),
                        (ip.IFA_CACHEINFO, struct.pack('<IIII', *r.cacheinfo))):
                    payload += ip._attribute(kind, data)
                messages.append(ip._message(ip.RTM_NEWADDR, ip.NLM_F_MULTI, sequence, port, payload))
        elif command == ip.RTM_GETROUTE:
            for r in self.snapshot.routes:
                payload = struct.pack('<BBBBBBBBI', ip.AF_INET, r.prefixlen, 0, 0,
                    r.table, r.protocol, r.scope, r.kind, r.flags)
                if r.prefixlen: payload += ip._attribute(ip.RTA_DST, struct.pack('>I', r.network))
                payload += ip._attribute(ip.RTA_OIF, struct.pack('<I', r.oif))
                payload += ip._attribute(ip.RTA_PREFSRC, struct.pack('>I', r.prefsrc))
                messages.append(ip._message(ip.RTM_NEWROUTE, ip.NLM_F_MULTI, sequence, port, payload))
        elif command == ip.RTM_GETRULE:
            for r in self.snapshot.rules:
                payload = struct.pack('<BBBBBBBBI', ip.AF_INET, 0, 0, 0, r.table, 0, 0, 1, 0)
                payload += ip._attribute(ip.FRA_PRIORITY, struct.pack('<I', r.priority))
                messages.append(ip._message(ip.RTM_NEWRULE, ip.NLM_F_MULTI, sequence, port, payload))
        else: raise AssertionError('non-address mutation unsupported')
        messages.append(ip._message(ip.NLMSG_DONE, ip.NLM_F_MULTI, sequence, port, struct.pack('<i', 0)))
        return b''.join(messages)
    def respond(self, request):
        messages = ip._messages(request)
        if len(messages) != 1: raise AssertionError('unexpected request shape')
        command, flags, sequence, port, payload = messages[0]
        if command in (ip.RTM_GETADDR, ip.RTM_GETROUTE, ip.RTM_GETRULE):
            return self._dump(command, sequence, port)
        if command not in (ip.RTM_NEWADDR, ip.RTM_DELADDR): raise AssertionError('forbidden mutation')
        row = ip._parse_address(payload)
        spec = dynamic.DynamicAddressSpec(row.ifindex, ip.ipv4_text(row.address), row.prefixlen)
        if command == ip.RTM_NEWADDR:
            if self.snapshot.addresses: raise AssertionError('model duplicate address')
            label = self.owned.name.encode('ascii') + b'\0'
            actual = ip.AddressRecord(row.ifindex, row.local, row.address, row.prefixlen, row.flags,
                row.scope, label, row.broadcast, (ip.UINT_MAX, ip.UINT_MAX, 1, 1))
            self.snapshot = ip.IpSnapshot((actual,), dynamic.expected_routes(spec), self.snapshot.rules)
        else:
            if len(self.snapshot.addresses) != 1 or self.snapshot.addresses[0].local != row.local:
                raise AssertionError('model non-owned deletion')
            self.snapshot = ip.IpSnapshot((), (), self.snapshot.rules)
        return ip._message(ip.NLMSG_ERROR, 0, sequence, port, struct.pack('<i', 0) + request[:16])


class Raw(object):
    def __init__(self, kernel):
        self.kernel, self.closed, self.responses = kernel, False, []
        self.descriptor = 17; self.timeout = None
    def fileno(self): return -1 if self.closed else self.descriptor
    def set_inheritable(self, value):
        if value is not False: raise AssertionError('inheritable descriptor')
    def bind(self, address):
        if address != (0, 0): raise AssertionError('non-kernel bind')
    def getsockname(self): return (70001, 0)
    def settimeout(self, value): self.timeout = value
    def sendto(self, request, target):
        if target != (0, 0): raise AssertionError('non-kernel target')
        self.kernel.sent.append(request)
        self.responses.append(self.kernel.respond(request))
        return len(request)
    def recvfrom(self, maximum):
        if maximum != ip.MAX_DATAGRAM_BYTES + 1: raise AssertionError('unbounded read')
        return self.responses.pop(0), (0, 0)
    def close(self): self.kernel.close_count += 1; self.closed = True


class DynamicIpV28Tests(unittest.TestCase):
    def model(self):
        clock = Clock(); owned = core.Origin(0, 99, 7, 'mta11223344', 8)
        kernel = Kernel(owned, clock)
        transport = dynamic.ClientRouteTransport(clock, _socket_factory=kernel.factory, _io=kernel, _sequence=100)
        return clock, owned, kernel, transport
    def test_native_wire_records_and_restoration_under_synthetic_kernel_only(self):
        with ExitStack() as stack:
            tripwires(stack)
            clock, owned, kernel, transport = self.model()
            baseline = kernel.snapshot
            intent = dynamic.DynamicIpRecord('intent', owned, '192.168.49.2', 24, 100.0, baseline)
            transport.open(5.0)
            self.assertEqual(dynamic.snapshot_key(transport.stable_snapshot(5.0)), dynamic.snapshot_key(baseline))
            spec = dynamic.DynamicAddressSpec(owned.ifindex, '192.168.49.2', 24)
            request = transport.prepare_address(spec, True)
            ack = transport.address_ack(request, 5.0, lambda: True)  # Transport-only synthetic admission.
            self.assertTrue(ack.success)
            observed = transport.stable_snapshot(5.0)
            applied = intent.replace('applied', observed)
            self.assertEqual(intent.facts_key(), applied.facts_key())
            self.assertTrue(dynamic.same_record(applied, dynamic.record_from_data(dynamic.record_data(applied))))
            changed = observed.addresses[0]._replace(cacheinfo=(ip.UINT_MAX, ip.UINT_MAX, 2, 1))
            timestamps = ip.IpSnapshot((changed,), observed.routes, observed.rules)
            self.assertNotEqual(dynamic.snapshot_key(observed), dynamic.snapshot_key(timestamps))
            deleting = applied.replace('delete_intent', observed)
            transport.address_ack(transport.prepare_address(spec, False), 5.0, lambda: True)
            restored = deleting.replace('restored', transport.stable_snapshot(5.0))
            self.assertEqual(dynamic.snapshot_key(restored.observed), dynamic.snapshot_key(baseline))
            self.assertEqual(transport.close(5.0), True)
            original_error = transport.ticket['ebadf']
            self.assertIsInstance(original_error, OSError)
            self.assertEqual(original_error.errno, errno.EBADF)
            self.assertEqual(transport.closed_facts(), ((True, True),))
            # After successful close, even legal numeric reuse cannot turn
            # passive original evidence into a new fstat/close producer.
            kernel.raw.closed = False; kernel.inode = 88
            self.assertTrue(transport.close(5.0))
            self.assertEqual(kernel.close_count, 1)
            self.assertIs(transport.ticket['ebadf'], original_error)
            commands = [ip._messages(blob)[0][0] for blob in kernel.sent]
            self.assertEqual(commands.count(ip.RTM_NEWADDR), 1)
            self.assertEqual(commands.count(ip.RTM_DELADDR), 1)
            self.assertNotIn(ip.RTM_NEWROUTE, commands)
            self.assertNotIn(ip.RTM_NEWRULE, commands)
    def test_prefix_and_schema_negatives_do_not_admit_owned_l3(self):
        with ExitStack() as stack:
            tripwires(stack)
            unused, owned, kernel, unused_transport = self.model()
            for prefix in (True, 0, 7, 31, 32):
                with self.assertRaises((dynamic.DynamicIpError, ip.IpCoreError)):
                    dynamic.DynamicAddressSpec(7, '192.168.49.2', prefix)
            spec = dynamic.DynamicAddressSpec(7, '10.1.2.3', 16)
            parsed = ip._parse_address(ip._messages(dynamic.encode_address(spec, 1, 2, True))[0][4])
            self.assertEqual(parsed.prefixlen, 16)
            self.assertEqual(parsed.broadcast, ip.ipv4_number('10.1.255.255'))
            with self.assertRaises(dynamic.DynamicIpError):
                dynamic.DynamicAddressSpec(7, '10.1.0.0', 16)
            intent = dynamic.DynamicIpRecord('intent', owned, '192.168.49.2', 24, 20.0, kernel.snapshot)
            value = dynamic.record_data(intent); value['allocation_until'] = 20
            with self.assertRaises(dynamic.DynamicIpError): dynamic.record_from_data(value)
            value = dynamic.record_data(intent); value['prefix'] = True
            with self.assertRaises(dynamic.DynamicIpError): dynamic.record_from_data(value)
            self.assertEqual(kernel.factory_count, 0)
    def test_changed_identity_no_close_retry_and_late_factory_remains_unknown(self):
        with ExitStack() as stack:
            tripwires(stack)
            clock, unused, kernel, transport = self.model()
            transport.open(5.0); kernel.inode = 99
            self.assertFalse(transport.close(5.0))
            kernel.inode = 42
            self.assertFalse(transport.close(5.0))
            self.assertEqual(kernel.close_count, 0)
            self.assertIs(transport.ticket['raw'], kernel.raw)
            self.assertTrue(transport.ticket['unknown'])
            clock, unused, kernel, transport = self.model()
            kernel.factory_late = True
            with self.assertRaises(dynamic.DynamicIpError): transport.open(5.0)
            self.assertFalse(transport.close(12.0))
            self.assertEqual(kernel.close_count, 1)
            self.assertIs(transport.ticket['raw'], kernel.raw)
            self.assertEqual(transport.closed_facts(), ((True, False),))
    def test_default_no_durable_producer_refuses_before_io_or_dora_import(self):
        with ExitStack() as stack:
            tripwires(stack)
            # Entry-guard primitive only; deliberately not the native owner
            # constructor, registered DORA, INIT or actual handoff grant.
            owner = dynamic.ClientDynamicIp.__new__(dynamic.ClientDynamicIp)
            owner.started, owner.commit = False, None
            with self.assertRaises(dynamic.DynamicIpError) as caught: owner.start()
            self.assertEqual(caught.exception.code, 'durable_journal_unavailable')
            self.assertFalse(owner.started)


if __name__ == '__main__': unittest.main(verbosity=2)
