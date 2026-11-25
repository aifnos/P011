"""One new HOST resource-primitive method; not a DORA/network permission.

The exact frozen 29-source definitions are loaded under creation/process/OS
tripwires. PrivateClientDora.__new__ initializes ONLY the local accounting and
FD-close primitive fixture. It does not call its permission constructor, proof,
open/poll/candidate/run_sync, INIT, CONNECT, restore or Formal F. The intentionally
non-DhcpSocketClient accounting object must never yield complete closure facts.
All descriptors, metadata, socket factory/close and clock values are synthetic.
No earlier TestCase or method is imported or invoked.
"""
from contextlib import ExitStack
import ast
import builtins
import errno
import hashlib
import json
from pathlib import Path
import socket
import stat
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
MANIFEST_SHA = '532faac02318504b0ed7d336391bc52f4e7b808efe485ac242aa926d8d3e4d2b'


def blocked(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen',
            'ctypes.CDLL', 'os.open', 'os.read', 'os.close', 'os.fstat', 'os.lstat',
            'os.listdir', 'os.readlink', 'os.getpid', 'os.fork', 'os.execve',
            'os.kill', 'os.waitpid', 'os.system', 'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('actual OS forbidden'), create=True))


def domain():
    raw = (BASE / 'host/client_formal_v26_source_manifest.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA:
        raise ValueError('fixed v26 manifest changed')
    document = json.loads(raw.decode('utf-8'))
    rows = document['sources']
    if document['schema'] != 'client-formal-v26-source-only' or len(rows) != 29 or \
            len({row['module'] for row in rows}) != 29 or len({row['path'] for row in rows}) != 29:
        raise ValueError('fixed graph shape changed')
    modules, imported = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private dependency unavailable')
            return modules[name]
        return imported(name, *args, **kwargs)
    with ExitStack() as stack:
        blocked(stack)
        for row in rows:
            path = BASE / row['path']; raw = path.read_bytes()
            if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise ValueError('fixed source changed')
            tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
            if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
                raise ValueError('target assertion forbidden')
            module = types.ModuleType(row['module']); module.__file__ = str(path)
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            modules[row['module']] = module
            exec(compile(raw, str(path), 'exec'), module.__dict__)
    return modules


M = domain()  # Source definitions only, no old TestCase/method.
linux, dora = M['mta_client_linux_provider'], M['mta_client_dora']


class Clock(object):
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


def metadata(inode, mode):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode,
        st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)


class SharedIo(object):
    """One synthetic namespace shared by original raw sockets and Provider."""
    def __init__(self): self.handles, self.events, self.next_inode = {}, [], 10
    def allocate(self, fd, mode=stat.S_IFSOCK | 0o600):
        if fd in self.handles: raise AssertionError('synthetic FD collision')
        self.next_inode += 1
        value = metadata(self.next_inode, mode); self.handles[fd] = value
        return value
    def fstat(self, fd):
        self.events.append(('fstat', fd))
        if type(fd) is not int: raise AssertionError('non-integer synthetic fstat')
        if fd not in self.handles: raise OSError(errno.EBADF, 'synthetic absent original')
        return self.handles[fd]
    def close(self, fd):
        self.events.append(('close', fd))
        if type(fd) is not int or fd not in self.handles:
            raise OSError(errno.EBADF, 'synthetic absent original')
        del self.handles[fd]
        return None


class RawSocket(object):
    def __init__(self, io, fd):
        self.io, self.fd, self.close_calls, self.fileno_values = io, fd, 0, []
    def fileno(self):
        return self.fileno_values.pop(0) if self.fileno_values else self.fd
    def close(self):
        self.close_calls += 1
        self.io.close(self.fd); self.fd = -1
        return None


def primitive(fd=8, late=False):
    """No association authority: exact class only for isolated ticket methods."""
    clock, io = Clock(), SharedIo()
    io.allocate(fd); raw = RawSocket(io, fd)
    provider = linux.LinuxClientInitProvider(_io=io, _clock=clock)
    capsule = dora.PrivateClientDora.__new__(dora.PrivateClientDora)
    lease = types.SimpleNamespace(_now=clock, pending=False, resource_pending=False, cleanup_complete=False)
    operation = types.SimpleNamespace(_dora_v21_registration=None)
    accounting = types.SimpleNamespace(_lock=threading.RLock(), _closers=[], _pending_close=[])
    capsule.provider, capsule.store, capsule.lease = provider, None, lease
    capsule._operation, capsule._client = operation, accounting
    capsule._actor_lock = threading.RLock()
    capsule._socket_issuer_v26, capsule._socket_tickets_v26 = object(), []
    capsule._factory_active_v26, capsule._sync_active_v26, capsule._proof_active = 0, False, 0
    capsule._proof_calls, capsule._active = [], None
    capsule._closed, capsule._revoked, capsule._unknown = False, False, False
    capsule.context = types.SimpleNamespace(deadline=10.0)  # Primitive clock cap, never ClientAssociation.
    def creator(family, kind, protocol):
        if (family, kind, protocol) != (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP):
            raise AssertionError('unexpected synthetic factory input')
        if late: clock.value = 10.0
        return raw
    capsule._socket_creator_v26 = creator
    registration = {'issuer': capsule, 'provider': provider, 'store': None,
        'lease': lease, 'client': accounting, 'unknown': False}
    capsule._registration = registration
    provider._store, provider._lease, provider._connection = None, lease, operation
    provider._dora_v21_registration = operation._dora_v21_registration = registration
    provider._dora_v26_creation = {'creator': dora.PrivateClientDora, 'issued': capsule,
        'returned': capsule, 'unknown': False}
    return capsule, provider, io, raw, clock


def issue(capsule):
    return capsule._socket_factory_v26(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)


class ClientFormalDoraV26Tests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack(); self.addCleanup(stack.close); blocked(stack)

    def unknown_retained(self, capsule, raw):
        ticket = capsule._socket_tickets_v26[0]
        self.assertIs(ticket.raw, raw)
        self.assertTrue(ticket.close_requested)
        self.assertFalse(ticket.close_active)
        self.assertTrue(ticket.unknown)
        self.assertTrue(capsule._unknown)
        self.assertTrue(capsule._registration['unknown'])
        self.assertTrue(capsule.lease.pending and capsule.lease.resource_pending)
        self.assertFalse(capsule.lease.cleanup_complete)
        self.assertTrue(any(value is raw for value in capsule._client._pending_close))
        self.assertFalse(capsule.closed_socket_ticket_v26(ticket))
        self.assertFalse(capsule._dispose_socket_v26(raw))  # Latch does not retry close.

    def test_original_udp_ticket_faults_retain_unknown_and_current_reuse_never_recloses(self):
        # Never-opened DORA adds no invented FD; residual roots cannot be complete.
        io, clock = SharedIo(), Clock()
        unused = linux.LinuxClientInitProvider(_io=io, _clock=clock)
        self.assertEqual((None, True), unused._dora_root_v26())
        self.assertTrue(unused._close_dora_v26()); self.assertEqual((), unused._dora_facts_v26())
        unused._dora_v21_registration = {}
        self.assertEqual((None, False), unused._dora_root_v26())
        self.assertFalse(unused._close_dora_v26()); self.assertEqual(((True, False),), unused._dora_facts_v26())
        unused._dora_v21_registration = None
        unused._connection = types.SimpleNamespace(_dora_v21_registration={})
        self.assertEqual((None, False), unused._dora_root_v26())
        self.assertFalse(unused._close_dora_v26()); self.assertEqual(((True, False),), unused._dora_facts_v26())
        self.assertFalse(io.events)

        # Changed raw descriptor/current metadata must never close foreign resources.
        for change in ('descriptor', 'metadata'):
            with self.subTest(change=change):
                capsule, provider, io, raw, clock = primitive()
                self.assertIs(raw, issue(capsule)); ticket = capsule._socket_tickets_v26[0]
                original = io.handles[8]
                if change == 'descriptor':
                    io.allocate(9); raw.fd = 9
                else: io.handles[8] = metadata(original.st_ino + 1, original.st_mode)
                self.assertFalse(capsule._dispose_socket_v26(raw))
                self.unknown_retained(capsule, raw)
                self.assertEqual(0, raw.close_calls); self.assertFalse(ticket.close_called)
                self.assertIn(8, io.handles)
                if change == 'descriptor': self.assertIn(9, io.handles)
                self.assertFalse(any(event[0] == 'close' for event in io.events))

        # Both ownership fileno observations require exact int, not bool/float equality.
        for position in ('before', 'final'):
            for wrong in (True, 1.0):
                with self.subTest(position=position, wrong_type=type(wrong).__name__):
                    capsule, provider, io, raw, clock = primitive(fd=1)
                    issue(capsule); ticket = capsule._socket_tickets_v26[0]
                    raw.fileno_values = [wrong] if position == 'before' else [1, wrong]
                    self.assertFalse(capsule._dispose_socket_v26(raw))
                    self.unknown_retained(capsule, raw)
                    self.assertIs(wrong, ticket.before_fileno if position == 'before' else ticket.final_fileno)
                    self.assertEqual(0, raw.close_calls); self.assertFalse(ticket.close_called)
                    self.assertIn(1, io.handles)

        # A returned-late raw is retained first; close-only metadata cannot wash unknown.
        capsule, provider, io, raw, clock = primitive(late=True)
        with self.assertRaises(dora.DoraError) as caught: issue(capsule)
        self.assertEqual('deadline', caught.exception.reason)
        ticket = capsule._socket_tickets_v26[0]
        self.assertIs(ticket.raw, raw); self.assertTrue(ticket.factory_returned)
        self.assertFalse(ticket.factory_active); self.assertEqual(0, capsule._factory_active_v26)
        self.assertIsNone(ticket.descriptor); self.assertIsNone(ticket.metadata)
        self.assertFalse(capsule._dispose_socket_v26(raw))
        self.unknown_retained(capsule, raw)
        self.assertEqual(1, raw.close_calls); self.assertTrue(ticket.close_called)
        self.assertEqual(8, ticket.cleanup_descriptor); self.assertIsInstance(ticket.cleanup_metadata, tuple)
        self.assertIsNone(ticket.descriptor); self.assertIsNone(ticket.metadata)
        self.assertIsInstance(ticket.ebadf_error, OSError); self.assertEqual(errno.EBADF, ticket.ebadf_errno)
        self.assertFalse(io.handles)

        # Only an original typed immediate EBADF closes a known socket ticket.
        capsule, provider, io, raw, clock = primitive()
        self.assertIs(raw, issue(capsule)); ticket = capsule._socket_tickets_v26[0]
        self.assertTrue(capsule.owns_socket_ticket_v26(ticket))
        self.assertFalse(capsule.owns_socket_ticket_v26(object()))
        self.assertTrue(capsule._dispose_socket_v26(raw))
        self.assertTrue(capsule.closed_socket_ticket_v26(ticket))
        self.assertIsInstance(ticket.ebadf_error, OSError)
        self.assertIs(type(ticket.ebadf_errno), int); self.assertEqual(errno.EBADF, ticket.ebadf_errno)
        immediate_error = ticket.ebadf_error
        self.assertTrue(provider._closed_fd(io, 8, ticket))
        self.assertTrue(capsule._dispose_socket_v26(raw)); self.assertEqual(1, raw.close_calls)

        # Real Provider ledger admission certifies current legal numeric reuse.
        io.allocate(8, stat.S_IFREG | 0o600)
        live = provider._ledger.new('file'); provider._ledger.adopt(live, 8)
        self.assertTrue(provider._closed_fd(io, 8, ticket))
        self.assertTrue(capsule.closed_socket_ticket_v26(ticket))
        self.assertIs(immediate_error, ticket.ebadf_error); self.assertEqual(1, raw.close_calls)
        current = io.handles[8]
        io.handles[8] = metadata(current.st_ino + 1, current.st_mode)
        self.assertFalse(provider._closed_fd(io, 8, ticket))
        self.assertIs(immediate_error, ticket.ebadf_error); self.assertEqual(1, raw.close_calls)
        self.assertIn(8, io.handles)

        # Primitive fixture cannot claim actor/whole-provider closure or network authority.
        facts = capsule.closure_facts_v26(provider)
        self.assertEqual(2, len(facts)); self.assertTrue(all(closed is False for attempted, closed in facts))
        self.assertIsNot(type(capsule._client), M['mta_dhcp_client'].DhcpSocketClient)
        self.assertFalse(capsule._closed); self.assertFalse(capsule._revoked)


if __name__ == '__main__': unittest.main()
