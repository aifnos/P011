"""First affected v35 read-only STATUS receive-entry reuse HOST flow; no old invocation.

Actual pinned 35-definition F/INIT/CONNECT/DORA/IP/peer/Transfer/Transport,
canonical Store facts, control parser and ZIP/storage byte verification execute.
Deployment approval, RF/kernel/child Proc/TCP/TLS and borrowed stdin/stdout are
explicit synthetic platform seams, NOT P011/phone/RF or physical socket proof.
The fixed logical receive path maps to one fresh private PC temporary root;
actual archive parsing, CRC and file contents remain native and observed.
No ready Journal/HandOff/restore result or budget success boolean is injected.
Existing v29-r3 fixture setup is copied into this new method, never invoked as
an old TestCase. Resource quotas are NOT increased, reset or refunded. Any
actual native budget/failure remains a failing first raw, not hidden/skipped.
The old kernel fixture's empty FIFO read is refined only for the original
nonblocking watchdog notify_read while its explicitly modeled fork-inherited
child writer remains live. Empty then raises typed EAGAIN, not invented EOF;
R payloads and real modeled writer exit/EOF retain the original read behavior.
The actual strict F/watchdog passive stop method is observed, not replaced;
its calls must consume no Proc/resource credits. Original active-loop full
polling and full Store/link/STATUS/kernel observations remain native.
This test does not run Parent.spawn/Popen or certify State/UI consent. Native
Parent receive-frame parser/reply helpers consume modeled original-pipe facts.
The v32-r3 platform fixture and all its old lifecycle assertions are retained.
Only Provider changes. Inclusive budget snapshots observe actual full/gate
calls and delegate every original return/exception, without new credits,
phase removal, clock changes, or an exception-to-success substitution.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import base64
import io as bytes_io
import os
import posixpath
import shutil
import ssl
import tempfile
import threading
import zipfile
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
    'host/client_status_v35_source_manifest.json': '1968909869e20a3f1db02d6cae80b2b919435fa025c041fc5f3702493e14eb2f',
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
    plan = json.loads(fixed('host/client_status_v35_source_manifest.json',
        INPUT_PINS['host/client_status_v35_source_manifest.json']))
    if (plan.get('schema') != 'client-status-v35-host' or
            plan.get('previous_manifest_sha256') != 'b5acd21f1a25d4e70ad357afb4ea18e7269381212d3de127e25e713d524641af'):
        raise ValueError('HOST revised source map changed')
    rows = plan['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST source graph changed')
    inputs = {}
    for row in rows:
        raw = fixed(row['path'], row['sha256'])
        if len(raw) != row['bytes']:
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
        module.__file__ = 'HOST-fixed-v31-receive/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    if tuple(modules) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST actual v31 F graph changed')
    return modules, inputs, collector


class DistinctExecutorPipeIo:
    """Explicit F IO facade over the same HOST OS state, not Provider IO.

    Real default F._LinuxIo and Provider._ArmIo are distinct objects. This
    facade models that separation while preserving every existing borrowed
    pipe/filesystem operation and fresh metadata result. It grants nothing.
    """
    def __init__(self, original): self.original = original
    def __getattr__(self, name): return getattr(self.original, name)


class SyntheticDeploymentAuthentication:
    """HOST assumption only; actual production Loader is not run here."""
    def __init__(self, python_record):
        self.owner = types.SimpleNamespace(rows=[python_record])
        self.deployment = None
    def authenticate(self, value):
        if value is not self.deployment: raise ValueError('HOST deployment changed')
        return None


def model_tripwires(stack):
    stack.enter_context(mock.patch('socket.AF_NETLINK', 16, create=True))
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
            'os.stat', 'os.lstat', 'os.listdir', 'os.readlink', 'os.getpid',
            'os.fork', 'os.execve', 'os.kill', 'os.waitpid', 'os.system', 'os.urandom',
            'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name,
            side_effect=AssertionError('actual OS forbidden'), create=True))
    stack.enter_context(mock.patch.object(socket, 'CMSG_SPACE',
        lambda size: 16 + ((size + 7) // 8) * 8, create=True))


class SyntheticRouteKernel:
    """MODEL only: initial wire inventory, one owned address + auto routes.

    Native collectors and ClientRouteTransport consume the same raw inventory.
    Address mutation is a kernel assumption, never a replacement native grant.
    Raw descriptor creation/metadata/close use the shared original FakeIO table.
    """
    def __init__(self, modules, packets, io, net):
        self.ip, self.dynamic = modules['mta_ip'], modules['mta_client_dynamic_ip']
        self.io, self.net, self.raw = io, net, None
        self.created = self.deleted = self.netdev_deletes = 0
        collectors = []
        for number, (kind, command, rows) in enumerate((
                ('addresses', 20, [packets.address_payload()]),
                ('routes', 24, [packets.route_payload(), packets.route_payload('10.2.0.0', 16, table=1000)]),
                ('rules', 32, [packets.rule_payload(p, t) for p, t in ((0,255),(32766,254),(32767,253))])), 1):
            collector = self.ip.DumpCollector(kind, number, 123)
            collector.feed(b''.join(packets.message(command, row, sequence=number, port=123)
                for row in rows) + packets.done(number, 123))
            collectors.append(collector)
        self.snapshot = self.ip.snapshot_from_dumps(*collectors)
        self.original = self.snapshot
        self.original_key = self.dynamic.snapshot_key(self.snapshot)
        self.sent = []
    def dump(self, command, sequence, port):
        ip, messages = self.ip, []
        if command == ip.RTM_GETADDR:
            for row in self.snapshot.addresses:
                payload = ip._ADDR.pack(ip.AF_INET, row.prefixlen, row.flags & 255, row.scope, row.ifindex)
                for kind, value in ((ip.IFA_ADDRESS, row.address), (ip.IFA_LOCAL, row.local),
                        (ip.IFA_BROADCAST, row.broadcast)):
                    if value is not None: payload += ip._attribute(kind, struct.pack('>I', value))
                if row.label is not None: payload += ip._attribute(ip.IFA_LABEL, row.label)
                if row.cacheinfo is not None:
                    payload += ip._attribute(ip.IFA_CACHEINFO, struct.pack('<IIII', *row.cacheinfo))
                payload += ip._attribute(ip.IFA_FLAGS, struct.pack('<I', row.flags))
                messages.append(ip._message(ip.RTM_NEWADDR, ip.NLM_F_MULTI, sequence, port, payload))
        elif command == ip.RTM_GETROUTE:
            for row in self.snapshot.routes:
                payload = ip._ROUTE.pack(ip.AF_INET, row.prefixlen, 0, 0,
                    row.table if row.table < 256 else 252, row.protocol, row.scope, row.kind, row.flags)
                payload += ip._attribute(ip.RTA_TABLE, struct.pack('<I', row.table))
                if row.prefixlen: payload += ip._attribute(ip.RTA_DST, struct.pack('>I', row.network))
                for kind, value in ((ip.RTA_OIF, row.oif), (ip.RTA_PRIORITY, row.priority)):
                    if value is not None: payload += ip._attribute(kind, struct.pack('<I', value))
                for kind, value in ((ip.RTA_GATEWAY, row.gateway), (ip.RTA_PREFSRC, row.prefsrc)):
                    if value is not None: payload += ip._attribute(kind, struct.pack('>I', value))
                if row.metrics:
                    payload += ip._attribute(ip.RTA_METRICS | 0x8000,
                        b''.join(ip._attribute(k, struct.pack('<I', v)) for k, v in row.metrics))
                messages.append(ip._message(ip.RTM_NEWROUTE, ip.NLM_F_MULTI, sequence, port, payload))
        elif command == ip.RTM_GETRULE:
            for row in self.snapshot.rules:
                payload = ip._RULE.pack(ip.AF_INET, 0, 0, 0,
                    row.table if row.table < 256 else 0, 0, 0, 1, 0)
                payload += ip._attribute(ip.FRA_TABLE, struct.pack('<I', row.table))
                payload += ip._attribute(ip.FRA_PRIORITY, struct.pack('<I', row.priority))
                messages.append(ip._message(ip.RTM_NEWRULE, ip.NLM_F_MULTI, sequence, port, payload))
        else: raise AssertionError('HOST non-dump command')
        messages.append(ip._message(ip.NLMSG_DONE, ip.NLM_F_MULTI, sequence, port, struct.pack('<i', 0)))
        return b''.join(messages)
    def respond(self, request):
        ip, dynamic = self.ip, self.dynamic
        messages = ip._messages(request)
        if len(messages) != 1: raise AssertionError('HOST request shape')
        command, flags, sequence, port, payload = messages[0]
        if command in (ip.RTM_GETADDR, ip.RTM_GETROUTE, ip.RTM_GETRULE):
            return self.dump(command, sequence, port)
        if command not in (ip.RTM_NEWADDR, ip.RTM_DELADDR): raise AssertionError('HOST non-address mutation')
        owned, store = self.net.owned, self.io.store_v28
        row = ip._parse_address(payload)
        if owned is None or row.ifindex != owned.ifindex: raise AssertionError('HOST wrong modeled link')
        fact = store._canonical.journal.client_ip
        if fact is None: raise AssertionError('HOST mutation before durable intent')
        spec = dynamic.DynamicAddressSpec(owned.ifindex, ip.ipv4_text(row.local), row.prefixlen)
        if command == ip.RTM_NEWADDR:
            if fact.phase != 'intent' or self.created: raise AssertionError('HOST duplicate/pre-intent create')
            self.created += 1
            actual = ip.AddressRecord(row.ifindex, row.local, row.address, row.prefixlen, row.flags,
                row.scope, owned.name.encode('ascii') + b'\0', row.broadcast, (ip.UINT_MAX, ip.UINT_MAX, 1, 1))
            self.snapshot = ip.IpSnapshot(self.original.addresses + (actual,),
                self.original.routes + dynamic.expected_routes(spec), self.original.rules)
        else:
            if fact.phase != 'delete_intent' or self.created != 1 or self.deleted:
                raise AssertionError('HOST duplicate/pre-intent delete')
            self.deleted += 1
            self.snapshot = self.original
        return ip._message(ip.NLMSG_ERROR, 0, sequence, port, struct.pack('<i', 0) + request[:16])
    def factory(self, family, kind, protocol):
        if (family, kind, protocol) != (socket.AF_NETLINK, socket.SOCK_RAW, 0) or self.raw is not None:
            raise AssertionError('HOST unexpected route socket')
        model = self
        class Raw:
            def __init__(self):
                path = '/HOST-v28-dynamic-route'
                model.io.add(path, stat.S_IFSOCK | 0o600)
                self.fd = model.io._open(path, 0, 0)
                self.original_fd, self.close_count, self.responses = self.fd, 0, []
                self.timeout = None
            def fileno(self): return self.fd
            def set_inheritable(self, value):
                if value is not False: raise AssertionError('HOST route inheritable')
            def bind(self, address):
                if address != (0, 0): raise AssertionError('HOST route bind')
            def getsockname(self): return (self.original_fd + 100, 0)
            def settimeout(self, value): self.timeout = value
            def sendto(self, request, target):
                if target != (0, 0): raise AssertionError('HOST route peer')
                model.sent.append(request); self.responses.append(model.respond(request))
                return len(request)
            def recvfrom(self, maximum):
                if maximum != model.ip.MAX_DATAGRAM_BYTES + 1: raise AssertionError('HOST route read bound')
                return self.responses.pop(0), (0, 0)
            def close(self):
                self.close_count += 1
                if self.close_count != 1: raise AssertionError('HOST route duplicate close')
                result = model.io.close(self.fd); self.fd = -1
                return result
        self.raw = Raw()
        return self.raw


class SyntheticPeerRouteKernel(SyntheticRouteKernel):
    """MODEL: bounded native peer+four full-read neighbour dumps; no active ARP/probe.

    Candidate and BSSID are the original fixed fixture wire-vector values,
    not a fabricated return object or detached permission supplied to reader.
    Each transport gets a distinct original FD in the shared FakeIO table.
    """
    def __init__(self, modules, packets, io, net, bssid):
        SyntheticRouteKernel.__init__(self, modules, packets, io, net)
        self.peer, self.bssid = modules['mta_client_peer'], bssid
        self.raws, self.neighbor_dumps = [], 0
    def neighbor_payload(self, ifindex, state=None, link_layer=None):
        peer, ip = self.peer, self.ip
        state = peer.NUD_REACHABLE if state is None else state
        link_layer = self.bssid if link_layer is None else link_layer
        payload = peer._ND.pack(ip.AF_INET, 0, 0, ifindex, state, 0, 1)
        payload += ip._attribute(peer.NDA_DST, struct.pack('>I', ip.ipv4_number('192.168.49.7')))
        payload += ip._attribute(peer.NDA_LLADDR, link_layer)
        payload += ip._attribute(peer.NDA_CACHEINFO, peer._CACHE.pack(1, 2, 3, 1))
        payload += ip._attribute(peer.NDA_PROBES, peer._U32.pack(0))
        return payload
    def respond(self, request):
        peer, ip = self.peer, self.ip
        messages = ip._messages(request)
        if len(messages) != 1: raise AssertionError('HOST neighbor request shape')
        command, flags, sequence, port, payload = messages[0]
        if command != peer.RTM_GETNEIGH:
            if command == ip.RTM_DELADDR:
                transfer_owner = self.io.store_v28._resource_budget_v23._provider._client_transfer_owner_v30
                if transfer_owner is None or not all(a and c for a, c in transfer_owner.closed_facts()):
                    raise AssertionError('HOST IP delete before transfer closure')
                provider = self.io.store_v28._resource_budget_v23._provider
                original = getattr(provider, '_client_peer_owner_v29', None)
                if (type(original) is not peer.ClientPeerReader or
                        not all(a and c for a, c in original.closed_facts())):
                    raise AssertionError('HOST IP delete before native peer original closed')
            return SyntheticRouteKernel.respond(self, request)
        if flags != ip.NLM_F_REQUEST | ip.NLM_F_DUMP:
            raise AssertionError('HOST neighbor command flags')
        family, pad1, pad2, index, state, nflags, kind = peer._ND.unpack_from(payload)
        attrs = ip._attributes(payload[peer._ND.size:], (peer.NDA_IFINDEX,))
        owned = self.net.owned
        if (owned is None or (family, pad1, pad2, index, state, nflags, kind) !=
                (ip.AF_INET, 0, 0, owned.ifindex, 0, 0, 0) or
                attrs != {peer.NDA_IFINDEX: peer._U32.pack(owned.ifindex)}):
            raise AssertionError('HOST neighbor dump filter')
        current = self.io.store_v28._canonical.journal
        if current.client_ip is None or current.client_ip.phase != 'applied':
            raise AssertionError('HOST neighbor read before durable IP applied')
        self.neighbor_dumps += 1
        if self.neighbor_dumps > 10: raise AssertionError('HOST unexpected neighbor repeat')
        flags = ip.NLM_F_MULTI | ip.NLM_F_DUMP_FILTERED
        # Distinct datagrams deliberately exercise multipart correlation.
        return (ip._message(peer.RTM_NEWNEIGH, flags, sequence, port, self.neighbor_payload(owned.ifindex)),
            ip._message(ip.NLMSG_DONE, flags, sequence, port, struct.pack('<i', 0)))
    def factory(self, family, kind, protocol):
        if (family, kind, protocol) != (socket.AF_NETLINK, socket.SOCK_RAW, 0) or len(self.raws) >= 6:
            raise AssertionError('HOST unexpected route socket')
        model = self
        class Raw:
            def __init__(self):
                path = '/HOST-v29-route-' + str(len(model.raws))
                model.io.add(path, stat.S_IFSOCK | 0o600)
                self.fd = model.io._open(path, 0, 0)
                self.original_fd, self.close_count, self.responses = self.fd, 0, []
                self.timeout = None
            def fileno(self): return self.fd
            def set_inheritable(self, value):
                if value is not False: raise AssertionError('HOST route inheritable')
            def bind(self, address):
                if address != (0, 0): raise AssertionError('HOST route bind')
            def getsockname(self): return (self.original_fd + 100, 0)
            def settimeout(self, value): self.timeout = value
            def sendto(self, request, target):
                if target != (0, 0): raise AssertionError('HOST route peer')
                model.sent.append(request)
                replies = model.respond(request)
                self.responses.extend(replies if type(replies) is tuple else (replies,))
                return len(request)
            def recvfrom(self, maximum):
                if maximum != model.ip.MAX_DATAGRAM_BYTES + 1: raise AssertionError('HOST route read bound')
                return self.responses.pop(0), (0, 0)
            def close(self):
                self.close_count += 1
                if self.close_count != 1: raise AssertionError('HOST route duplicate close')
                result = model.io.close(self.fd); self.fd = -1
                return result
        raw = Raw(); self.raws.append(raw)
        if self.raw is None: self.raw = raw  # Original IP socket remains separate.
        return raw



class LogicalPcFiles:
    """Only the fixed logical incoming tree maps to fresh, real PC files.

    Logical root ownership/permissions/ancestors belong to FakeIO, not Windows.
    Actual file content, ZIP CRC, rename, fstat and fsync use saved PC calls.
    No system or user tree outside this test's generated directory is writable.
    """
    ROOT = '/mnt/data/p011-toolbox/user/Received'
    def __init__(self, directory):
        self.directory = str(Path(directory).resolve())
        self.counter, self.fd_calls, self.paths = 0, [], []
        self.actual = {name: getattr(os, name) for name in
            ('open', 'close', 'fstat', 'lstat', 'stat', 'chmod', 'rename', 'unlink',
             'mkdir', 'rmdir', 'listdir', 'fsync', 'fdopen')}
        self.actual_open = builtins.open
        self.actual_zip, self.disk_usage = zipfile.ZipFile, shutil.disk_usage
        self.actual_path = os.path
        self.file_fds = set()
    def physical(self, path):
        if type(path) is not str or posixpath.normpath(path) != path or not \
                (path == self.ROOT or path.startswith(self.ROOT + '/')):
            raise AssertionError('HOST file path outside generated incoming root')
        relative = path[len(self.ROOT):].lstrip('/')
        result = self.actual_path.join(self.directory, *relative.split('/')) if relative else self.directory
        if self.actual_path.commonpath((self.directory, result)) != self.directory:
            raise AssertionError('HOST file path escaped private root')
        self.paths.append(path)
        return result
    def open(self, path, *args, **kwargs):
        return self.actual_open(self.physical(path), *args, **kwargs)
    def has(self, path, kind):
        if not (path == self.ROOT or path.startswith(self.ROOT + '/')): return False
        try: value = self.actual['lstat'](self.physical(path))
        except FileNotFoundError: return False
        return True if kind == 'exists' else kind(value.st_mode)
    def stat(self, path): return self.actual['stat'](self.physical(path))
    def mkdir(self, path, mode=0o700): return self.actual['mkdir'](self.physical(path), mode)
    def makedirs(self, path, mode=0o700):
        # Every component is in the generated tree; native archive path checks
        # already reject traversal. Existing logical ancestors are not created.
        parts = path[len(self.ROOT):].lstrip('/').split('/')
        current = self.ROOT
        for part in parts:
            current += '/' + part
            if not self.has(current, stat.S_ISDIR): self.mkdir(current, mode)
    def file_open(self, path, flags, mode=0o600):
        fd = self.actual['open'](self.physical(path), flags, mode)
        self.file_fds.add(fd); self.fd_calls.append(('open', fd))
        return fd
    def fstat(self, fd):
        if fd not in self.file_fds: raise AssertionError('HOST foreign physical file descriptor')
        self.fd_calls.append(('fstat', fd)); return self.actual['fstat'](fd)
    def close(self, fd):
        if fd not in self.file_fds: raise AssertionError('HOST foreign physical close')
        self.fd_calls.append(('close', fd)); return self.actual['close'](fd)
    def fsync(self, fd):
        if fd not in self.file_fds: raise AssertionError('HOST foreign physical fsync')
        self.fd_calls.append(('fsync', fd)); return self.actual['fsync'](fd)
    def generated(self, prefix, suffix=''):
        self.counter += 1
        return self.ROOT + '/' + prefix + ('%08x' % self.counter) + suffix
    def mkstemp(self, prefix, suffix='', dir=None):
        if dir != self.ROOT: raise AssertionError('HOST temporary root changed')
        logical = self.generated(prefix, suffix)
        fd = self.file_open(logical, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        return fd, logical
    def mkdtemp(self, prefix, dir=None):
        if dir != self.ROOT: raise AssertionError('HOST staging root changed')
        logical = self.generated(prefix); self.mkdir(logical); return logical
    def remove_generated(self, logical):
        if logical == self.ROOT: raise AssertionError('HOST cannot remove incoming root')
        path = self.physical(logical)
        def remove(current):
            for name in self.actual['listdir'](current):
                child = self.actual_path.join(current, name)
                value = self.actual['lstat'](child)
                if stat.S_ISDIR(value.st_mode): remove(child)
                else: self.actual['unlink'](child)
            self.actual['rmdir'](current)
        return remove(path)
    def install(self, modules, stack):
        path = types.SimpleNamespace(abspath=posixpath.abspath, isabs=posixpath.isabs,
            dirname=posixpath.dirname, join=posixpath.join, realpath=posixpath.normpath,
            expanduser=lambda unused: '/HOST-home-not-incoming',
            isdir=lambda value: self.has(value, stat.S_ISDIR),
            isfile=lambda value: self.has(value, stat.S_ISREG),
            islink=lambda value: self.has(value, stat.S_ISLNK),
            lexists=lambda value: self.has(value, 'exists'), getsize=lambda value: self.stat(value).st_size)
        file_os = types.SimpleNamespace(name='posix', path=path,
            O_WRONLY=os.O_WRONLY, O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL,
            open=self.file_open, close=self.close, fstat=self.fstat, fsync=self.fsync,
            fdopen=self.actual['fdopen'], lstat=lambda value: self.actual['lstat'](self.physical(value)),
            chmod=lambda value, mode: self.actual['chmod'](self.physical(value), mode),
            rename=lambda a, b: self.actual['rename'](self.physical(a), self.physical(b)),
            unlink=lambda value: self.actual['unlink'](self.physical(value)), makedirs=self.makedirs,
            urandom=lambda size: b'\x17' * size)  # Synthetic WS entropy, NOT cryptographic evidence.
        temporary = types.SimpleNamespace(mkstemp=self.mkstemp, mkdtemp=self.mkdtemp)
        native_zip = types.SimpleNamespace(ZipFile=lambda path, *a, **kw:
            self.actual_zip(self.physical(path), *a, **kw), BadZipFile=zipfile.BadZipFile,
            LargeZipFile=zipfile.LargeZipFile, ZIP_STORED=zipfile.ZIP_STORED, ZIP_DEFLATED=zipfile.ZIP_DEFLATED)
        native_shutil = types.SimpleNamespace(disk_usage=lambda unused: self.disk_usage(self.directory),
            rmtree=self.remove_generated)
        for name in ('mta_storage', 'mta_transport'):
            stack.enter_context(mock.patch.object(modules[name], 'os', file_os))
            stack.enter_context(mock.patch.object(modules[name], 'tempfile', temporary))
        stack.enter_context(mock.patch.object(modules['mta_storage'], 'zipfile', native_zip))
        stack.enter_context(mock.patch.object(modules['mta_storage'], 'shutil', native_shutil))
        stack.enter_context(mock.patch.dict(modules['mta_storage'].__dict__['__builtins__'], {'open': self.open}))


class SyntheticTcpTls:
    """Explicit Linux TCP/options/TLS OS assumptions, NOT physical sockets.

    Actual native ReceiverTransport, Stream, WS, HTTP and archive parsers consume
    byte buffers. Full gates/records/IPC/accounting are NOT replaced by booleans.
    Descriptor metadata and modeled onceclose share the original FakeIO table.
    """
    def __init__(self, modules, io, net, archive, request):
        self.modules, self.io, self.net = modules, io, net
        self.archive, self.request = archive, request
        self.raws, self.wrappers, self.events, self.messages = [], [], [], []
        model = self
        class Raw:
            family = socket.AF_INET
            def __init__(self, family, kind, protocol):
                if (family, kind, protocol) != (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) or len(model.raws) >= 2:
                    raise AssertionError('HOST unplanned TCP factory')
                path = '/HOST-v31-tcp-' + str(len(model.raws))
                model.io.add(path, stat.S_IFSOCK | 0o600)
                self.fd = model.io.open(path, 0)
                self.original_fd, self.close_count = self.fd, 0
                self.inherit, self.device, self.source, self.peer, self.timeout = True, b'', None, None, None
                model.raws.append(self); model.events.append(('factory', self))
            def fileno(self): return self.fd
            def set_inheritable(self, value): self.inherit = value
            def get_inheritable(self): return self.inherit
            def setsockopt(self, level, option, value):
                if (level, option) != (socket.SOL_SOCKET, modules['mta_scoped_sockets'].SO_BINDTODEVICE):
                    raise AssertionError('HOST unplanned TCP option')
                self.device = value
            def getsockopt(self, level, option, size=None):
                if level != socket.SOL_SOCKET: raise AssertionError('HOST TCP option level')
                if option == modules['mta_scoped_sockets'].SO_BINDTODEVICE: return self.device
                if option == socket.SO_LINGER: return struct.pack('=ii', 0, 0)
                if option == socket.SO_TYPE: return int(socket.SOCK_STREAM)
                if option in (socket.SO_ACCEPTCONN, socket.SO_REUSEADDR,
                        modules['mta_scoped_sockets'].SO_REUSEPORT, socket.SO_ERROR): return 0
                raise AssertionError('HOST unplanned TCP option read')
            def bind(self, source):
                current = model.io.store_v28._canonical.journal.client_ip
                if source != (modules['mta_ip'].ipv4_text(current.local_ip), 0):
                    raise AssertionError('HOST foreign TCP source')
                self.source = (source[0], 41000 + len(model.raws))
            def getsockname(self): return self.source
            def getpeername(self):
                if self.peer is None: raise OSError(errno.ENOTCONN, 'HOST unconnected')
                return self.peer
            def setblocking(self, value): self.timeout = None if value else 0.0
            def settimeout(self, value): self.timeout = value
            def gettimeout(self): return self.timeout
            def connect_ex(self, destination):
                operation = model.io.store_v28._resource_budget_v23._provider._connection
                if destination != ('192.168.49.7', operation.peer_port):
                    raise AssertionError('HOST foreign TCP destination')
                self.peer = destination
                model.events.append(('connect', self)); return 0
            def shutdown(self, unused): return None
            def close(self):
                self.close_count += 1
                if self.fd != -1: model.io.close(self.fd); self.fd = -1
        self.Raw = Raw
        class Tls:
            def __init__(self, raw):
                owner = model.io.store_v28._resource_budget_v23._provider._client_transfer_owner_v30
                rows = [row for row in owner.rows if row['raw'] is raw]
                if len(rows) != 1 or not rows[0]['adopted']:
                    raise AssertionError('HOST TLS before actual native raw handoff')
                life = owner.transport._life._record(raw)
                if life is None or not life['wrapping'] or life['tls'] is not None:
                    raise AssertionError('HOST foreign wrap transition')
                self.raw, self.fd, self.original_fd = raw, raw.fd, raw.fd
                self.close_count, self.input, self.output, self.timeout = 0, bytearray(), bytearray(), None
                self.stage = 'http'
                raw.fd = -1  # Explicit synthetic detach, not physical close.
                model.wrappers.append(self); model.events.append(('wrap', raw))
            def fileno(self): return self.fd
            def settimeout(self, value): self.timeout = value
            def do_handshake(self): model.events.append(('modeled_handshake', self.raw))
            def getpeercert(self, binary_form=False): return b'HOST modeled certificate fingerprint bytes'
            def shutdown(self, unused): return None
            def close(self):
                self.close_count += 1
                if self.close_count != 1: raise AssertionError('HOST duplicate modeled TLS close')
                result = model.io.close(self.fd); self.fd = -1; return result
            def recv(self, size):
                if not self.output: raise AssertionError('HOST scripted protocol response exhausted')
                result = bytes(self.output[:size]); del self.output[:size]; return result
            def send(self, raw):
                self.input.extend(raw)
                if self.stage == 'http' and b'\r\n\r\n' in self.input:
                    header, rest = bytes(self.input).split(b'\r\n\r\n', 1)
                    self.input = bytearray(rest)
                    if header.startswith(b'GET /websocket '):
                        key = next(line.split(b': ', 1)[1] for line in header.split(b'\r\n')
                            if line.startswith(b'Sec-WebSocket-Key: '))
                        digest = base64.b64encode(hashlib.sha1(key + modules['mta_transport'].WS_GUID.encode('ascii')).digest())
                        self.output.extend(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                            b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + digest + b'\r\n\r\n')
                        self.output.extend(model.frame(modules['mta_protocol'].WsMessage('action', 0,
                            'versionNegotiation', {'version': 1, 'versions': [1]})))
                        self.output.extend(model.frame(modules['mta_protocol'].WsMessage('action', 1,
                            'sendRequest', model.request)))
                        self.stage = 'ws'
                    elif header.startswith(('GET /download?taskId=' + model.request['taskId'] + ' HTTP/1.1').encode('ascii')):
                        self.output.extend(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(model.archive)).encode('ascii') +
                            b'\r\nConnection: close\r\n\r\n' + model.archive)
                        self.stage = 'download'
                    else: raise AssertionError('HOST unplanned HTTP request')
                if self.stage == 'ws': self.parse_frames()
                return len(raw)
            def parse_frames(self):
                while len(self.input) >= 2:
                    a, b = self.input[:2]; size, start = b & 127, 2
                    if size == 126:
                        if len(self.input) < 4: return
                        size, start = struct.unpack('!H', bytes(self.input[2:4]))[0], 4
                    if a != 0x81 or not b & 128 or size == 127:
                        raise AssertionError('HOST unexpected native client WS frame')
                    if len(self.input) < start + 4 + size: return
                    mask = self.input[start:start+4]; start += 4
                    payload = bytes(c ^ mask[i % 4] for i, c in enumerate(self.input[start:start+size]))
                    del self.input[:start+size]
                    message = modules['mta_protocol'].WsMessage.parse(payload)
                    model.messages.append(message)
                    if message.msg_type == 'action' and message.name == 'status':
                        if message.payload.get('type') != 1: raise AssertionError('HOST expected actual committed status')
                        self.output.extend(model.frame(message.make_ack()))
        self.Tls = Tls
        class Context:
            def __init__(self, unused): self.verify_mode = None
            def set_ciphers(self, unused): return None
            def wrap_socket(self, raw, server_hostname, do_handshake_on_connect):
                if server_hostname != '192.168.49.7' or do_handshake_on_connect is not False:
                    raise AssertionError('HOST TLS scope changed')
                return Tls(raw)
        self.Context = Context
    def frame(self, message):
        payload = message.serialize().encode('utf-8')
        return (b'\x81' + bytes(bytearray((len(payload),))) if len(payload) < 126 else
            b'\x81\x7e' + struct.pack('!H', len(payload))) + payload
    def install(self, stack):
        stack.enter_context(mock.patch.object(socket, 'socket', self.Raw))
        stack.enter_context(mock.patch.object(socket, 'if_nametoindex',
            lambda name: self.net.owned.ifindex if self.net.owned and name == self.net.owned.name else 0, create=True))
        stack.enter_context(mock.patch.object(sys, 'platform', 'linux'))
        fake_ssl = types.SimpleNamespace(SSLContext=self.Context, SSLSocket=self.Tls,
            PROTOCOL_TLSv1_2=ssl.PROTOCOL_TLSv1_2, CERT_NONE=ssl.CERT_NONE)
        stack.enter_context(mock.patch.object(self.modules['mta_transport'], 'ssl', fake_ssl))


class ClientStatusV35Tests(unittest.TestCase):
    def test_actual_f_receive_status_once_original_context_and_phase_budget(self):
        collector, full, packets = definitions()
        with ExitStack() as source_stack:
            model_tripwires(source_stack)
            modules, inputs, collector = domain(collector)
        pc_directory = tempfile.mkdtemp(prefix='mta-v31-native-flow-')
        # Cleanup runs after ExitStack releases OS tripwires. Only this unique,
        # test-created directory is owned; no user/device tree is targeted.
        self.addCleanup(shutil.rmtree, pc_directory)
        pc_files = LogicalPcFiles(pc_directory)
        expected_bytes = b'v31 actual CRC-verified HOST file bytes\x00\xff' * 128
        archive_buffer = bytes_io.BytesIO()
        with zipfile.ZipFile(archive_buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('Music/HOST.bin', expected_bytes)
        archive_bytes = archive_buffer.getvalue()
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
            # Exact FORMAL selection is a fixture constructor input before any
            # original Store IO/publication. Native constructor/budget execute.
            stores = modules['mta_client_store']
            actual_store_ctor = stores.DurableClientInitStore.__init__
            def formal_store_ctor(instance, *args, **kwargs):
                if '_session_profile' in kwargs: raise AssertionError('HOST profile duplicate')
                kwargs['_session_profile'] = modules['mta_p2p_client_init'].FORMAL_SESSION_PROFILE
                return actual_store_ctor(instance, *args, **kwargs)
            stack.enter_context(mock.patch.object(stores.DurableClientInitStore, '__init__', formal_store_ctor))
            values = collector.make_fixture(modules, full, packets)
            lease, provider, store, owner, bridge, io, fs, kernel, net, clock = values
            io.store_v28 = store
            p, f, core, dhcp, wire, dynamic, peer = (modules[name] for name in
                ('mta_client_linux_provider', 'mta_client_executor', 'mta_p2p_client_init',
                 'mta_dhcp_client', 'mta_dhcp', 'mta_client_dynamic_ip', 'mta_client_peer'))
            self.assertEqual(35, len(f.MODULES))
            self.assertEqual(f.MODULES, tuple(modules))
            stack.enter_context(mock.patch.dict(sys.modules, modules))
            p._OWNERS[:] = []
            self.assertIs(store._session_profile, core.FORMAL_SESSION_PROFILE)
            self.assertIs(store._resource_budget_v23._profile, modules['mta_client_resource_budget'].FORMAL_PROFILE)
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
            stop_only_calls, full_poll_calls = [], []
            actual_stop = p.LinuxClientInitProvider.poll_executor_stop_v32
            actual_full_poll = p.LinuxClientInitProvider.poll_requests
            def observe_stop(producer, native_executor, original_until):
                # Record actual invocation/return, not a cached False or proof.
                budget = producer._store._resource_budget_v23
                row = {'provider': producer, 'executor': native_executor,
                    'until': original_until, 'returned': False, 'result': None,
                    'before': tuple(tuple(counts) for counts in budget._used), 'after': None}
                stop_only_calls.append(row)
                try:
                    returned = actual_stop(producer, native_executor, original_until)
                    row['result'], row['returned'] = returned, True
                    return returned
                finally: row['after'] = tuple(tuple(counts) for counts in budget._used)
            def observe_full_poll(producer):
                full_poll_calls.append(producer)
                return actual_full_poll(producer)
            stack.enter_context(mock.patch.object(p.LinuxClientInitProvider,
                'poll_executor_stop_v32', observe_stop))
            stack.enter_context(mock.patch.object(p.LinuxClientInitProvider,
                'poll_requests', observe_full_poll))
            # Passive inclusive observation only. No gate result, exception,
            # original budget/profile, stage, clock, or cancellation is changed.
            phase_rows, actual_context_calls = [], [0]
            native_context = p.LinuxClientInitProvider._connection_context
            native_channel = p.LinuxClientInitProvider._connection_channel_gate
            transfer_class = modules['mta_client_transfer'].ClientTransferOwner
            native_full = transfer_class._full
            def budget_counts():
                return [list(counts) for counts in store._resource_budget_v23._used]
            def phase_observation(kind, phase):
                row = {'kind': kind, 'phase': phase, 'ordinal': len(phase_rows) + 1,
                    'before': budget_counts(), 'after': None, 'returned': False,
                    'context_before': actual_context_calls[0], 'context_calls': None}
                phase_rows.append(row)
                return row
            def phase_finished(row):
                row['after'] = budget_counts()
                row['context_calls'] = actual_context_calls[0] - row['context_before']
            def count_context(producer, operation, original_until):
                actual_context_calls[0] += 1
                return native_context(producer, operation, original_until)
            def count_channel(producer, operation, original_until, event, _status_ticket=None):
                is_status = operation._command == b'STATUS' and event is False
                phase = ('status_receive' if _status_ticket is not None else
                    'status_post' if is_status and producer._status_exchange_v35 is not None else
                    'status_send' if is_status else 'other')
                row = phase_observation('connection_gate', phase)
                try:
                    value = native_channel(producer, operation, original_until, event, _status_ticket)
                    row['returned'] = True
                    return value
                finally: phase_finished(row)
            def count_full(producer):
                row = phase_observation('transfer_full', 'full')
                try:
                    value = native_full(producer)
                    row['returned'] = True
                    return value
                finally: phase_finished(row)
            stack.enter_context(mock.patch.object(p.LinuxClientInitProvider,
                '_connection_context', count_context))
            stack.enter_context(mock.patch.object(p.LinuxClientInitProvider,
                '_connection_channel_gate', count_channel))
            stack.enter_context(mock.patch.object(transfer_class, '_full', count_full))
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
            pending_errors = []
            pending_class = modules['mta_client_pending'].ClientPendingMarker
            pending_report_original = pending_class._record_error
            def pending_report(instance, error):
                pending_errors.append(error)  # Original before native symbolic remapping.
                return pending_report_original(instance, error)
            stack.enter_context(mock.patch.object(pending_class, '_record_error', pending_report))
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
                    if code.co_filename.startswith('HOST-fixed-v31-receive/'):
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
            for directory in ('/mnt', '/mnt/data', '/mnt/data/p011-toolbox',
                    '/mnt/data/p011-toolbox/user', f.RECEIVE_ROOT):
                io.add(directory, stat.S_IFDIR | (0o700 if directory.endswith('/user') or directory == f.RECEIVE_ROOT else 0o755))
            receive_metadata = f._receive_directory(io, clock, clock() + 20)
            dep = f.LoadedDeployment(authentication, modules, pm, pm.manifest_sha256,
                pm.run_dir, provider._connect_binding, f.RECEIVE_ROOT, receive_metadata)
            authentication.deployment = dep
            argv = f._argv(dep, '--execute-client-init', '300.0')
            current_argv = b'\0'.join(value.encode('ascii') for value in argv) + b'\0'
            self_root = '/proc/' + str(fixture.SELF.pid)
            fs.files[self_root + '/cmdline'] = current_argv
            fs.links[self_root + '/exe'] = pm.python_exe
            fs.files[self_root + '/comm'] = b'python3\n'

            original_fork, original_write, original_kernel_read, original_waitpid = (
                kernel.fork, kernel.write, kernel.read, kernel.waitpid)
            watchdog_writer_peers, watchdog_reads = [], []
            def fork_current():
                # Explicit OS model: fork inherits the child's writer copy.
                # Closing the parent's notify_write must not invent pipe EOF.
                calling = tuple(child for child in owner._tickets if
                    child.fork_requested and not child.fork_returned)
                if len(calling) != 1: raise AssertionError('HOST fork owner ambiguous')
                child = calling[0]
                pid = original_fork()
                if child.spec.role == 'watchdog':
                    read_row = next(row for row in child.fds if row.role == 'notify_read')
                    write_row = next(row for row in child.fds if row.role == 'notify_write')
                    if (read_row.metadata[:3] != write_row.metadata[:3] or
                            not stat.S_ISFIFO(read_row.metadata[2])):
                        raise AssertionError('HOST watchdog pipe pair changed')
                    watchdog_writer_peers.append({'child': child, 'pid': pid,
                        'read_row': read_row, 'write_row': write_row,
                        'writer_live': True})
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
            def read_watchdog(fd, count):
                peers = tuple(row for row in watchdog_writer_peers if row['read_row'].fd == fd)
                if peers:
                    if len(peers) != 1: raise AssertionError('HOST watchdog read ambiguous')
                    row, child = peers[0], peers[0]['child']
                    original_read_row = row['read_row']
                    writer_live = (row['writer_live'] and child.fork_returned and
                        child.pid == row['pid'] and child.released and not child.waited)
                    if (not kernel.notify and writer_live and
                            kernel.flags(fd) & kernel.O_NONBLOCK and
                            original_read_row.returned and not original_read_row.closed and
                            not original_read_row.unknown and
                            owner._reader is not None and
                            modules['mta_client_process_owner']._meta(kernel.fstat(fd)) == original_read_row.metadata):
                        watchdog_reads.append(('empty_live_writer_eagain', True))
                        raise OSError(errno.EAGAIN, 'HOST modeled nonblocking live pipe')
                    returned = original_kernel_read(fd, count)
                    watchdog_reads.append(('eof' if returned == b'' else 'payload', writer_live))
                    return returned
                return original_kernel_read(fd, count)
            def waitpid_writer(pid, flags):
                returned = original_waitpid(pid, flags)
                if (type(returned) is tuple and len(returned) == 2 and returned[0] == pid and
                        (kernel.WIFEXITED(returned[1]) or kernel.WIFSIGNALED(returned[1]))):
                    for row in watchdog_writer_peers:
                        if row['pid'] == pid: row['writer_live'] = False
                return returned
            kernel.fork, kernel.write, kernel.read, kernel.waitpid = (
                fork_current, release_current, read_watchdog, waitpid_writer)

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
                        ip_owner = provider._client_ip_owner_v28
                        if (not io.disconnected and ip_owner is not None and ip_owner.applied and
                                not ip_owner.cleanup_called):
                            reply += b'ip_address=' + modules['mta_ip'].ipv4_text(ip_owner.record.local_ip).encode('ascii') + b'\n'
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
                    if family != 16 and request[16] == 8:
                        current = store._canonical.journal
                        if current.client_ip is None or current.client_ip.phase != 'restored':
                            raise AssertionError('HOST netdev delete before durable IP restore')
                        ip_kernel.netdev_deletes += 1
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
            ip_kernel = SyntheticPeerRouteKernel(modules, packets, io, net, fixture.BSSID)
            original_socket = io.socket
            def baseline_socket(protocol):
                raw = original_socket(protocol)
                send = raw.sendto
                def send_with_current(request, peer):
                    result = send(request, peer)
                    if protocol == 0:
                        command, flags, seq, port, body = modules['mta_ip']._messages(request)[0]
                        raw.packets[:] = [ip_kernel.dump(command, seq, port)]
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
            actual_transport_ctor = dynamic.ClientRouteTransport.__init__
            def transport_ctor(instance, *args, **kwargs):
                if '_socket_factory' in kwargs or '_sequence' in kwargs:
                    raise AssertionError('HOST transport input duplicate')
                kwargs['_socket_factory'] = ip_kernel.factory
                kwargs['_sequence'] = 100  # Explicit synthetic transaction entropy.
                return actual_transport_ctor(instance, *args, **kwargs)
            stack.enter_context(mock.patch.object(dynamic.ClientRouteTransport, '__init__', transport_ctor))

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

            transport, transfer, codec = (modules[name] for name in
                ('mta_transport', 'mta_client_transfer', 'mta_client_control_frame'))
            pc_files.install(modules, stack)
            request = {'taskId': 'v31-host-single', 'senderName': 'HOST synthetic sender',
                'fileName': 'HOST.bin', 'mimeType': 'application/octet-stream',
                'fileCount': 1, 'totalSize': len(expected_bytes)}
            self.assertEqual(request, modules['mta_protocol'].validate_send_request(request))
            tcp_tls = SyntheticTcpTls(modules, io, net, archive_bytes, request)
            tcp_tls.install(stack)
            # Fixed modeled borrowed pipes, not F-owned newly created sockets.
            # FIFOs have stable st_size=0 even while their in-memory queue grows.
            stdin_node = io.add('/HOST-v31-borrowed-stdin', stat.S_IFIFO | 0o600,
                codec.encode_connect(provider._connect_binding, fixture.info()))
            stdout_node = io.add('/HOST-v31-borrowed-stdout', stat.S_IFIFO | 0o600)
            self.assertNotIn(0, io.handles); self.assertNotIn(1, io.handles)
            io.handles[0], io.handles[1] = [stdin_node, 0], [stdout_node, 0]
            original_fstat, original_read, original_io_write = io.fstat, io.read, io.write
            def borrowed_fstat(fd):
                value = original_fstat(fd)
                if fd in (0, 1):
                    value = types.SimpleNamespace(**vars(value)); value.st_size = 0
                return value
            io.fstat = borrowed_fstat
            assembly = (provider, store, owner, bridge, lease)
            inherited_fd = io.open(pm.python_exe, 0)
            def assemble_original(manifest, _connect_binding=None):
                if manifest is not pm or _connect_binding is not provider._connect_binding:
                    raise AssertionError('HOST assembly originals changed')
                return assembly
            stack.enter_context(mock.patch.object(p, 'assemble', assemble_original))
            # Observe native calls, never substitute restore/closure values.
            restore_calls, close_order = [], []
            native_restore = lease.restore
            def restore_original(*args, **kwargs):
                restore_calls.append((args, kwargs)); return native_restore(*args, **kwargs)
            stack.enter_context(mock.patch.object(lease, 'restore', restore_original))
            for native_type, method_name, label in ((transfer.ClientTransferOwner, 'close', 'transfer'),
                    (peer.ClientPeerReader, 'close', 'peer'), (dynamic.ClientDynamicIp, 'cleanup', 'ip')):
                native_method = getattr(native_type, method_name)
                def observe_close(instance, *args, _original=native_method, _label=label, **kwargs):
                    close_order.append((_label, instance))
                    return _original(instance, *args, **kwargs)
                stack.enter_context(mock.patch.object(native_type, method_name, observe_close))
            frames, ipc_writes, pipe_read_calls, snapshots = [], [], [], {}
            executor_io = DistinctExecutorPipeIo(io)
            self.assertIsNot(executor_io, provider._io)
            self.assertIs(executor_io.original, provider._io)
            executor = f.ClientExecutor(dep, _io=executor_io, _clock=clock, _input=None,
                _emit=frames.append, _ttl_text='300.0',
                _environ={'P011_CLIENT_EXECUTABLE_FD': str(inherited_fd)}, _proc_fs=fs)
            # Native Parent IPC parser/reply only. Original-child launch/Popen,
            # CONNECT issuance and UI consent are explicit modeled prerequisites.
            parent = f.ParentExecutor(dep, _io=io, _clock=clock)
            parent.connect_ticket = {'unknown': False, 'sent': True}
            parent._connect_worker = threading.current_thread()
            parent.pipes = [{'fd': 0, 'pipe': types.SimpleNamespace(fileno=lambda: 0),
                'metadata': f._meta(io.fstat(0)), 'unknown': False, 'closed': False, 'attempted': False}]
            def ready_current(descriptors, seconds):
                if tuple(descriptors) not in ((), (0,)):
                    raise AssertionError('HOST unexpected control poll')
                ticket = executor.ip_ticket
                if (ticket is not None and not ticket['unknown'] and ticket['result'] is not None and
                        executor.peer_ticket is None and 'before_peer' not in snapshots):
                    snapshots['before_peer'] = tuple(tuple(row) for row in store._resource_budget_v23._used)
                    snapshots['original'] = lease.record
                return [0] if descriptors and io.handles[0][1] < len(stdin_node.data) else []
            def read_current(fd, count):
                if fd == 0: pipe_read_calls.append((fd, count))
                return original_read(fd, count)
            def write_current(fd, raw):
                if fd == 2: return len(raw)  # Native stderr diagnostics remain private, not success frames.
                if fd not in (0, 1): return original_io_write(fd, raw)
                ipc_writes.append((fd, raw))
                if fd == 0:
                    stdin_node.data += raw  # Parent one-write reply feeds actual F decoder.
                    return len(raw)
                if len(raw) > 4096: raise AssertionError('HOST stdout PIPE_BUF exceeded')
                value = original_io_write(fd, raw)
                f.ParentExecutor._receive_event(parent, raw)
                if parent.receive_state == 'awaiting_confirmation':
                    prompt = parent.receive_prompt
                    self.assertIs(type(prompt), codec.ReceivePrompt)
                    answer = parent.answer_receive(prompt, True)
                    self.assertEqual('accepted', answer['state'])
                    self.assertFalse(parent.failures)
                return value
            io.ready, io.read, io.write = ready_current, read_current, write_current
            io.ready_write = lambda fd, seconds: (1,) if fd == 1 and 0 < seconds <= .05 else ()
            io.pipe_buf = lambda fd: 4096 if fd == 1 else 0
            try:
                result = executor.run(ttl=300)
            finally:
                # Numeric fixed native accounting plus stop-only observations;
                # no original command/device/actor/path/file/private wire bytes.
                budget_v35 = store._resource_budget_v23
                print('HOST_STATUS_V35_COUNTS:' + json.dumps({
                    'schema': 'client-status-v35-inclusive-counts',
                    'kinds': list(modules['mta_client_resource_budget'].KINDS),
                    'limits': [list(counts) for counts in budget_v35._profile.counts],
                    'used': budget_counts(), 'phase_rows': phase_rows,
                    'context_calls': actual_context_calls[0],
                    'status_tickets': len(provider._status_exchanges_v35),
                    'tickets_claimed': sum(t['claimed'] is True for t in provider._status_exchanges_v35),
                    'tickets_revoked': sum(t['revoked'] is True for t in provider._status_exchanges_v35),
                    'active_ticket_cleared': provider._status_exchange_v35 is None,
                    'safe_exhaustion': list(budget_v35.status()['safe_exhaustion']),
                    'inclusive_overlaps': True, 'os_rf_proc_tcp_tls_modeled': True,
                    'device_accessed': False, 'phone_tested': False,
                }, sort_keys=True, separators=(',', ':')), flush=True)
            # Failure attribution is restricted to fixed symbolic type/code and
            # target-frame names/lines. No exception repr/private data is logged.
            native_codes, native_types = set(), []
            for name, raw in inputs.items():
                for node in ast.walk(ast.parse(raw.decode('utf-8'), feature_version=(3, 5))):
                    if isinstance(node, ast.ClassDef) and node.name.endswith('Error'):
                        kind = getattr(modules[name], node.name, None)
                        if type(kind) is type: native_types.append((kind, (name, node.name)))
                    if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                        called = node.func.id if isinstance(node.func, ast.Name) else ''
                        value = node.args[0].value
                        if called in ('_fail', '_durable_fail') and type(value) is str and \
                                value and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in value):
                            native_codes.add(value)
            def fixed_error(error):
                kind = next((label for native, label in native_types if type(error) is native),
                    ('HOST', 'AssertionError') if type(error) is AssertionError else ('other', 'other'))
                code = getattr(error, 'code', getattr(error, 'reason', None))
                code = code if type(code) is str and code in native_codes else 'other'
                if kind == ('mta_scoped_sockets', 'ScopedSocketError') and len(error.args) == 1:
                    scoped_code = error.args[0]
                    # Native symbolic whitelist only; never exception repr or OS text.
                    if type(scoped_code) is str and scoped_code in modules['mta_scoped_sockets']._ERROR_CODES:
                        code = scoped_code
                trace, cursor = [], error.__traceback__
                while cursor is not None:
                    function = cursor.tb_frame.f_code
                    if function.co_filename.startswith('HOST-fixed-v31-receive/'):
                        trace.append((function.co_name, cursor.tb_lineno))
                    cursor = cursor.tb_next
                return kind, code, tuple(trace)
            budget = store._resource_budget_v23
            actual_transfer = (executor.receive_ticket['returned'] if
                executor.receive_ticket is not None else None)
            transfer_failures = (() if actual_transfer is None else
                tuple(fixed_error(e) for e in actual_transfer.failures))
            notify_facts = tuple((child.spec.role, child.notify_requests,
                child.notify_eof_v30, child.notify_failure_v30, child.unknown)
                for child in owner._tickets if child.spec.role == 'watchdog')
            attribution = (result, executor._diagnostic_start, executor._diagnostic_restore,
                executor._diagnostic_complete, tuple(fixed_error(e) for e in executor.failures),
                tuple(fixed_error(e) for e in pending_errors),
                tuple(tuple(row) for row in budget._used), snapshots.get('before_peer'),
                transfer_failures, notify_facts, (len(watchdog_reads),
                    sum(kind == 'empty_live_writer_eagain' for kind, live in watchdog_reads),
                    sum(kind == 'eof' and live for kind, live in watchdog_reads),
                    tuple(watchdog_reads[:1]), tuple(watchdog_reads[-1:])), budget.status(),
                None if executor.receive_failure_original is None else fixed_error(executor.receive_failure_original),
                tuple(fixed_error(e) for e in executor.receive_terminal_failures),
                (len(stop_only_calls), sum(row['returned'] for row in stop_only_calls),
                    sum(row['before'] != row['after'] for row in stop_only_calls), len(full_poll_calls)))
            self.assertTrue(result['done'], attribution)
            self.assertFalse(result['resource_pending']); self.assertEqual('restored', result['reason'])
            self.assertEqual('committed', executor.receive_outcome, attribution)
            self.assertFalse(executor.failures); self.assertFalse(parent.failures)
            self.assertIsNone(executor.receive_failure_original)
            self.assertFalse(executor.receive_terminal_failures)
            self.assertTrue(watchdog_reads)
            self.assertTrue(any(kind == 'empty_live_writer_eagain' for kind, unused in watchdog_reads))
            self.assertFalse(any(kind == 'eof' and live for kind, live in watchdog_reads))
            self.assertTrue(stop_only_calls); self.assertTrue(full_poll_calls)
            self.assertTrue(all(row['provider'] is provider and row['executor'] is executor and
                row['returned'] and type(row['result']) is bool and row['result'] is False and
                row['before'] == row['after'] for row in stop_only_calls))
            self.assertTrue(all(producer is provider for producer in full_poll_calls))
            self.assertIs(executor._stop_worker_v32, threading.current_thread())
            self.assertIs(executor._stop_input_v32, executor.input)
            self.assertIs(type(executor.input), f._StdinControl)
            self.assertIs(executor.io, executor_io)
            self.assertIs(executor.input.io, executor_io)
            self.assertIsNot(executor.input.io, provider._io)
            self.assertIs(executor._stop_input_facts_v32[3], executor_io)
            self.assertIs(executor.input.codec, codec)
            self.assertIs(executor.input.binding, provider._connect_binding)
            self.assertTrue(pipe_read_calls)
            self.assertEqual(1, len(restore_calls))
            self.assertEqual(executor.recovery_until, restore_calls[0][1]['_absolute_deadline'])
            self.assertIs(type(executor.finish), core.FinishReceipt); self.assertTrue(executor.finish.complete)
            self.assertEqual('absent_observed', executor.finish.marker_state)
            self.assertEqual('verified', executor.finish.clear_durability)
            self.assertEqual('reconciled', lease.record.stage); self.assertIsNone(lease.locks)
            self.assertFalse(kernel.live); self.assertEqual({0, 1}, set(io.handles))
            self.assertNotIn(0, io.closed); self.assertNotIn(1, io.closed)
            self.assertEqual({200, 300}, net.reaped); self.assertEqual(2, len(owner._tickets))
            self.assertTrue(all(reader.history_closed() for reader in budget._readers))
            ip_owner, peer_owner, receive_owner = (executor.ip_ticket['returned'],
                executor.peer_ticket['returned'], executor.receive_ticket['returned'])
            self.assertIs(ip_owner, provider._client_ip_owner_v28)
            self.assertIs(peer_owner, provider._client_peer_owner_v29)
            self.assertIs(receive_owner, provider._client_transfer_owner_v30)
            self.assertIs(receive_owner.executor, executor); self.assertIs(receive_owner.input, executor.input)
            self.assertIs(receive_owner.peer, peer_owner); self.assertIs(receive_owner.ip_owner, ip_owner)
            self.assertIs(receive_owner.operation, provider._connection)
            self.assertIs(receive_owner.handoff, ip_owner.handoff)
            self.assertIs(receive_owner.mapping, executor.peer_ticket['result'])
            self.assertIs(type(receive_owner.receiver), modules['mta_storage'].SafeZipReceiver)
            self.assertIs(executor.receive_ticket['receiver'], receive_owner.receiver)
            self.assertEqual(f.RECEIVE_ROOT, receive_owner.receiver.root)
            self.assertFalse(executor.peer_ticket['unknown']); self.assertFalse(executor.receive_ticket['unknown'])
            self.assertEqual(['transfer', 'peer', 'ip'], [label for label, obj in close_order[:3]])
            # Provider later revisits already-closed transfer/peer inventories
            # during its own final close_resources. Those are idempotent native
            # checks, not another restoration or another physical descriptor close.
            self.assertTrue(all(label in ('transfer', 'peer') for label, obj in close_order[3:]))
            self.assertIs(close_order[0][1], receive_owner); self.assertIs(close_order[1][1], peer_owner)
            self.assertIs(close_order[2][1], ip_owner)
            self.assertTrue(all(a and c for a, c in receive_owner.closed_facts()))
            self.assertTrue(all(a and c for a, c in peer_owner.closed_facts()))
            self.assertTrue(all(a and c for a, c in ip_owner.closed_facts()))
            self.assertEqual(['intent', 'applied', 'delete_intent', 'restored'],
                [row['proposed'].phase for row in ip_owner.commits])
            self.assertTrue(all(type(row['returned']) is core.Journal and not row['unknown'] for row in ip_owner.commits))
            self.assertEqual(ip_kernel.original_key, dynamic.snapshot_key(ip_kernel.snapshot))
            self.assertEqual(1, ip_kernel.created); self.assertEqual(1, ip_kernel.deleted)
            self.assertEqual(1, ip_kernel.netdev_deletes); self.assertIsNone(net.owned)
            self.assertEqual(6, len(ip_kernel.raws)); self.assertEqual(10, ip_kernel.neighbor_dumps)
            self.assertEqual(4, len(receive_owner.full_rows))
            # Native peer read brackets once plus FOUR native TCP full stages;
            # no cancellation-poll optimization can suppress these fresh gates.
            self.assertEqual(10, len(peer_owner.link_rows))
            self.assertEqual(10, len(peer_owner.associations))
            self.assertTrue(all(row['constructor_started'] and row['success'] and
                transfer.ClientTransferOwner._route_closed(row) for row in receive_owner.full_rows))
            self.assertEqual(2, len(receive_owner.rows)); self.assertEqual(2, len(tcp_tls.raws))
            self.assertEqual(2, len(tcp_tls.wrappers))
            self.assertTrue(all(row['returned'] and row['adopted'] for row in receive_owner.rows))
            self.assertEqual(tcp_tls.raws, [row['raw'] for row in receive_owner.rows])
            self.assertTrue(all(receive_owner.transport._life._record(raw)['transferred'] for raw in tcp_tls.raws))
            self.assertTrue(all(wrapper.fileno() == -1 and wrapper.close_count == 1 for wrapper in tcp_tls.wrappers))
            for raw in ip_kernel.raws:
                self.assertEqual(-1, raw.fileno()); self.assertEqual(1, raw.close_count)
                with self.assertRaises(OSError) as model_closed: io.fstat(raw.original_fd)
                self.assertEqual(errno.EBADF, model_closed.exception.errno)
            self.assertEqual(1, len(datagrams)); self.assertEqual(1, datagrams[0].close_count)
            self.assertTrue(transport.ReceiverTransport.closed(receive_owner.transport))
            self.assertEqual(receive_owner.deadline, receive_owner.transport.deadline)
            self.assertEqual(receive_owner.deadline, receive_owner.transport._budget.until)
            original = snapshots['original']
            self.assertTrue(all(row['until'] == original.deadline for row in stop_only_calls))
            self.assertEqual('formal300', original.session_profile)
            self.assertEqual(300.0, original.deadline - original.issued_at)
            self.assertEqual((original.session_profile, original.issued_at, original.deadline),
                (lease.record.session_profile, lease.record.issued_at, lease.record.deadline))
            self.assertEqual(min(original.deadline, ip_owner.handoff._until), receive_owner.deadline)
            self.assertEqual(('--until', str(original.deadline)),
                next(child for child in owner._tickets if child.spec.role == 'watchdog').spec.argv[-2:])
            self.assertEqual((core.FORMAL_SESSION_PROFILE, 'formal300', original.issued_at, original.deadline),
                store._session_issued_v28)
            self.assertEqual(clock() + 60, executor.recovery_until)
            self.assertEqual(executor.recovery_until, ip_owner._cleanup_until)
            self.assertLess(clock(), original.deadline)  # This success is not synthetic active expiry.
            self.assertIs(budget._profile, modules['mta_client_resource_budget'].FORMAL_PROFILE)
            self.assertEqual(modules['mta_client_resource_budget'].SOURCE_PROFILE.counts, budget._profile.counts)
            after_counts = tuple(tuple(row) for row in budget._used)
            before_counts = snapshots['before_peer']
            self.assertGreater(after_counts[0][2], before_counts[0][2])  # Actual Proc call accounting.
            self.assertGreater(after_counts[0][4], before_counts[0][4])  # Actual native kernel reader credits.
            self.assertTrue(all(after_counts[lane][column] <= budget._profile.counts[lane][column]
                for lane in range(2) for column in range(len(after_counts[lane]))))
            self.assertTrue(provider._status_exchanges_v35)
            self.assertIsNone(provider._status_exchange_v35)
            self.assertTrue(all(t['claimed'] and t['revoked'] and t['send_attempted'] and
                type(t['send_return']) is int and t['send_return'] == len(t['wire']) and
                t['wire'] == b'STATUS' and t['event'] is False and
                t['deadline'] == original.deadline and t['until'] <= t['deadline']
                for t in provider._status_exchanges_v35))
            self.assertEqual(4, len([row for row in phase_rows if row['kind'] == 'transfer_full']))
            self.assertTrue(all(row['returned'] for row in phase_rows))
            for phase in ('status_send', 'status_receive', 'status_post'):
                rows_v35 = [row for row in phase_rows if row['kind'] == 'connection_gate' and row['phase'] == phase]
                self.assertEqual(len(provider._status_exchanges_v35), len(rows_v35))
                self.assertTrue(all(row['context_calls'] == (0 if phase == 'status_receive' else 1)
                    for row in rows_v35))
                if phase == 'status_receive':
                    self.assertTrue(all(row['before'] == row['after'] for row in rows_v35))
            self.assertFalse(any(budget.status()['safe_exhaustion']))
            self.assertTrue(budget.status()['network_cancelled'])
            native_result = executor.receive_result
            self.assertIs(native_result, receive_owner.result)
            self.assertEqual('v31-host-single', native_result['taskId'])
            self.assertEqual(1, native_result['fileCount']); self.assertEqual(len(expected_bytes), native_result['totalSize'])
            self.assertTrue(native_result['peer_ack_verified'])  # Modeled byte ACK, never phone UI acceptance.
            self.assertEqual(1, len(native_result['files']))
            with pc_files.open(native_result['files'][0], 'rb') as actual_file:
                self.assertEqual(expected_bytes, actual_file.read())
            self.assertTrue(any(kind == 'fsync' for kind, fd in pc_files.fd_calls))
            self.assertFalse(receive_owner.transport._temporary_paths)
            self.assertFalse(receive_owner.transport._temporary_fds)
            self.assertFalse(receive_owner.transport._temporary_outputs)
            self.assertEqual(['prompt', 'progress', 'progress', 'result'],
                [row['value']['kind'] for row in parent.receive_events])
            self.assertTrue(all(row['sent'] and row['write_result'] == len(row['wire']) for row in executor.receive_events))
            self.assertIs(parent.receive_reply_ticket['prompt'], parent.receive_prompt)
            self.assertTrue(parent.receive_reply_ticket['sent']); self.assertFalse(parent.receive_reply_ticket['unknown'])
            self.assertIs(executor.receive_decision.prompt, executor.receive_prompt)
            self.assertTrue(executor.receive_decision.accepted)
            self.assertEqual('committed', parent.receive_result['outcome'])
            self.assertEqual(1, len([wire for fd, wire in ipc_writes if fd == 0]))
            self.assertFalse(parent.attempted); self.assertIsNone(parent.process)  # No Parent spawn/launch claim.
            self.assertFalse(result['phone_tested']); self.assertFalse(result['receive_available'])
            self.assertFalse(receive_owner.status()['phone_tested'])
            self.assertFalse(receive_owner.status()['receive_available'])
            # Small post-flow CANCEL parser check on the ORIGINAL borrowed pipe;
            # it cannot reopen/renew the completed session or invoke restoration.
            stdin_node.data += codec.CANCEL
            self.assertTrue(f._StdinControl.poll(executor.input))
            self.assertEqual('cancelled', executor.input.reason)
            self.assertEqual(1, len(restore_calls)); self.assertEqual(original.deadline, lease.record.deadline)


if __name__ == '__main__':
    unittest.main()
