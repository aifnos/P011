"""First-execution-only v30-r2 HOST helper boundaries, not a CLIENT grant.

Loads the pinned 35 actual source definitions, but NEVER invokes a previous
TestCase, full F lifecycle, native peer/INIT/CONNECT/DORA or device operation.
The narrow native _dispose method consumes an actual PC pipe descriptor and
actual os.fstat/close/EBADF. A labelled OS seam projects only its FIFO st_mode
to modeled S_IFSOCK because Windows socket handles cannot use CRT os.fstat.
All other identity fields and EBADF come from actual original pipe fstat.
CloseOnlyRaw is a descriptor-only test collaborator,
NOT a TCP socket, socket proxy, TLS path or SO_BINDTODEVICE permission. Synthetic
time tests fixed-cap cleanup, not wall-time guarantees or whole Owner authority.

The second method invokes actual _full with an explicitly refusing original-
identity collaborator before route construction. Its zero-resource inventory
projection must remain separate from the overall owner, which is NOT closed.
No fake native closure, ready Journal or successful grant is installed.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
MANIFEST_PATH = 'host/client_peer_v29_r3_source_manifest.json'
MANIFEST_SHA = '367a2b156d9ddca18fc1000f92bc827a03b58c71f2a4b9fbb1b59ffc5f175db6'
REPLACEMENTS = {
    'mta_client_linux_provider': ('candidate/client-transfer-v30/runtime/mta_client_linux_provider.py',
        '67981d3566986b169941cf693ba3f7ee0002e8e6699839d89d68492f1a0a3b53', 155376),
    'mta_client_process_owner': ('candidate/client-transfer-v30-r2/runtime/mta_client_process_owner.py',
        'c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb', 34361),
}
APPENDED = (
    ('mta_scoped_sockets', 'runtime/mta_scoped_sockets.py',
     'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8', 26339),
    ('mta_storage', 'runtime/mta_storage.py',
     '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6', 14335),
    ('mta_transport', 'candidate/client-transfer-v30/runtime/mta_transport.py',
     '77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa', 35209),
    ('mta_client_transfer', 'candidate/client-transfer-v30-r2/runtime/mta_client_transfer.py',
     'e43799c1dd6d39bb356c3507a17d846bee741bd4a66b1cb650562888dcfaf640', 28201),
)


def fixed(path, sha, length=None):
    value = (BASE / path).read_bytes()
    if hashlib.sha256(value).hexdigest() != sha or length is not None and len(value) != length:
        raise ValueError('HOST fixed source changed')
    return value


def definitions():
    """Private actual source domain; no old fixture or test method executes."""
    rows = json.loads(fixed(MANIFEST_PATH, MANIFEST_SHA))['sources']
    if len(rows) != 31 or len({r['module'] for r in rows}) != 31:
        raise ValueError('HOST previous graph changed')
    inputs = {}
    for row in rows:
        name = row['module']
        path, sha, size = REPLACEMENTS.get(name, (row['path'], row['sha256'], row['bytes']))
        inputs[name] = fixed(path, sha, size)
    for name, path, sha, size in APPENDED:
        if name in inputs: raise ValueError('HOST duplicated source')
        inputs[name] = fixed(path, sha, size)
    modules, actual_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private definition unavailable')
            return modules[name]
        return actual_import(name, *args, **kwargs)
    for name, raw in inputs.items():
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
            raise ValueError('target assertion changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-v30-r2-helper/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    original_graph = modules['mta_client_executor'].MODULES
    if len(original_graph) != 30 or tuple(modules) != original_graph + ('mta_client_peer',) + tuple(r[0] for r in APPENDED):
        raise ValueError('HOST explicit helper graph changed')
    return modules, inputs


class SyntheticClock:
    def __init__(self, now): self.now = float(now)
    def __call__(self): return self.now


class CloseOnlyRaw:
    """Only actual pipe fileno/close; never admitted as a network raw."""
    def __init__(self, fd): self.fd, self.close_calls = fd, 0
    def fileno(self): return self.fd
    def close(self):
        self.close_calls += 1
        original = self.fd
        value = os.close(original)
        self.fd = -1
        return value


class ActualPipeMetadata:
    """Actual pipe fstat with explicit synthetic socket-kind OS projection."""
    def __init__(self): self.calls = []
    def fstat(self, fd):
        self.calls.append(fd)
        value = os.fstat(fd)  # Physical identity / typed EBADF are not invented.
        if not stat.S_ISFIFO(value.st_mode):
            raise AssertionError('HOST original pipe kind changed')
        return types.SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino,
            st_mode=stat.S_IFSOCK | stat.S_IMODE(value.st_mode), st_rdev=value.st_rdev)


def dispose_helper(transfer, clock, io):
    # Deliberately does not fabricate a peer, F, Journal or native constructor.
    # Only slots consumed by the actual descriptor-only helper are populated.
    result = transfer.ClientTransferOwner.__new__(transfer.ClientTransferOwner)
    result.clock, result._last, result._io, result.failures = clock, None, io, []
    return result


class ClientTransferBoundariesV30Tests(unittest.TestCase):
    def test_native_dispose_original_fixed_cap_actual_pipe_ebadf_once(self):
        modules, inputs = definitions()
        transfer, dynamic = modules['mta_client_transfer'], modules['mta_client_dynamic_ip']
        # The actual socket_factory source allocates this exact fixed cap BEFORE
        # raw creation. This AST check is SOURCE evidence; helper calls below are
        # actual PC descriptor IO, not an executed TCP grant/socket_factory.
        tree = ast.parse(inputs['mta_client_transfer'].decode('utf-8'))
        factory = next(n for c in tree.body if isinstance(c, ast.ClassDef) and c.name == 'ClientTransferOwner'
            for n in c.body if isinstance(n, ast.FunctionDef) and n.name == 'socket_factory')
        assignments = [n for n in ast.walk(factory) if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) and t.value.id == 'row' and
                isinstance(t.slice, ast.Constant) and t.slice.value == 'close_until' for t in n.targets)]
        self.assertEqual(1, len(assignments))
        self.assertEqual(ast.dump(ast.parse('until + FULL_SECONDS + dynamic.IO_SECONDS', mode='eval').body),
            ast.dump(assignments[0].value))
        original_until, dial_until = 103.0, 103.0
        fixed_close_until = dial_until + transfer.FULL_SECONDS + dynamic.IO_SECONDS
        self.assertEqual(113.0, fixed_close_until)
        # Old dial+IO cap=108 would already be past; r2 reserved close cap=113
        # remains usable although the original network session itself expired.
        for case in ('late_post_full', 'expired_close_cap'):
            with self.subTest(case=case):
                read_fd, write_fd = os.pipe()
                raw, io = CloseOnlyRaw(read_fd), ActualPipeMetadata()
                clock = SyntheticClock(110.0 if case == 'late_post_full' else fixed_close_until)
                owner = dispose_helper(transfer, clock, io)
                owner.deadline = original_until
                row = {'factory_started': True, 'factory_returned': True,
                    'raw': raw, 'fd': read_fd, 'metadata': dynamic._metadata(io.fstat(read_fd)),
                    'returned': False, 'close_called': False, 'close_returned': False,
                    'close_result': False, 'ebadf': None, 'fileno_closed': False,
                    'close_until': fixed_close_until, 'unknown': False}
                try:
                    self.assertTrue(stat.S_ISFIFO(os.fstat(read_fd).st_mode))
                    io.calls.clear()  # Keep action-only readback accounting.
                    self.assertGreater(clock(), owner.deadline)
                    transfer.ClientTransferOwner._dispose(owner, row)
                    self.assertEqual(original_until, owner.deadline)
                    self.assertEqual(fixed_close_until, row['close_until'])
                    if case == 'late_post_full':
                        self.assertGreater(clock(), dial_until + dynamic.IO_SECONDS)
                        self.assertLess(clock(), fixed_close_until)
                        self.assertEqual(1, raw.close_calls)
                        self.assertTrue(row['close_called']); self.assertTrue(row['close_returned'])
                        self.assertIsNone(row['close_result']); self.assertTrue(row['fileno_closed'])
                        self.assertIsInstance(row['ebadf'], OSError)
                        self.assertEqual(errno.EBADF, row['ebadf'].errno)
                        self.assertFalse(row['unknown']); self.assertFalse(owner.failures)
                        self.assertTrue(transfer.ClientTransferOwner._tcp_closed(owner, row))
                        count = len(io.calls)
                        transfer.ClientTransferOwner._dispose(owner, row)
                        self.assertEqual(1, raw.close_calls); self.assertEqual(count, len(io.calls))
                        with self.assertRaises(OSError) as actual:
                            os.fstat(read_fd)
                        self.assertEqual(errno.EBADF, actual.exception.errno)
                    else:
                        self.assertEqual(0, raw.close_calls); self.assertFalse(io.calls)
                        self.assertFalse(row['close_called']); self.assertFalse(row['fileno_closed'])
                        self.assertTrue(row['unknown']); self.assertEqual(1, len(owner.failures))
                        self.assertIs(type(owner.failures[0]), transfer.ClientTransferError)
                        self.assertEqual('transfer_deadline', owner.failures[0].code)
                        self.assertFalse(transfer.ClientTransferOwner._tcp_closed(owner, row))
                        self.assertEqual(row['metadata'], dynamic._metadata(io.fstat(read_fd)))
                        # No failure-time renewal and no clock rollback escape.
                        clock.now = fixed_close_until - 1
                        transfer.ClientTransferOwner._dispose(owner, row)
                        self.assertEqual(0, raw.close_calls)
                        self.assertEqual('clock_regressed', owner.failures[-1].code)
                        self.assertEqual(fixed_close_until, row['close_until'])
                finally:
                    # Test-owned PC endpoints only. Teardown is NOT a native
                    # successful cleanup projection for the expired case.
                    if raw.fileno() != -1: raw.close()
                    os.close(write_fd)

    def test_native_full_early_refusal_without_route_constructor_is_zero_resource(self):
        modules, _ = definitions()
        transfer, dynamic = modules['mta_client_transfer'], modules['mta_client_dynamic_ip']
        owner = transfer.ClientTransferOwner.__new__(transfer.ClientTransferOwner)
        owner.clock, owner._last, owner.deadline, owner._scope = SyntheticClock(100), None, 400.0, None
        owner.full_rows, owner.rows, owner.lock_rows, owner.failures = [], [], [], []
        owner._running, owner.close_called, owner.transport = False, False, None
        owner.transport_ticket = {'started': False}
        owner.provider = types.SimpleNamespace(_client_transfer_owner_v30=owner)
        refused = []
        def untrusted_originals():
            refused.append(True)
            raise transfer.ClientTransferError('native_transfer_owner_changed')
        # This collaborator only refuses; it cannot manufacture native success.
        owner._originals = untrusted_originals
        with ExitStack() as stack:
            constructor = stack.enter_context(mock.patch.object(dynamic, 'ClientRouteTransport',
                side_effect=AssertionError('route construction forbidden in zero-resource case')))
            actual_socket = stack.enter_context(mock.patch.object(socket, 'socket',
                side_effect=AssertionError('actual socket forbidden in zero-resource case')))
            with self.assertRaises(transfer.ClientTransferError) as error:
                transfer.ClientTransferOwner._full(owner)
            self.assertEqual('native_transfer_owner_changed', error.exception.code)
            constructor.assert_not_called(); actual_socket.assert_not_called()
        self.assertEqual([True], refused); self.assertEqual(1, len(owner.full_rows))
        row = owner.full_rows[0]
        self.assertFalse(row['constructor_started']); self.assertIsNone(row['transport'])
        self.assertIsNone(row['ticket']); self.assertFalse(row['opened'])
        self.assertFalse(row['close_called']); self.assertFalse(row['close_returned'])
        self.assertFalse(row['success']); self.assertEqual([], row['neighbors'])
        self.assertEqual(110.0, row['cleanup_until']); self.assertIsNone(owner._scope)
        self.assertEqual(400.0, owner.deadline)
        self.assertTrue(transfer.ClientTransferOwner._route_closed(row))
        self.assertEqual(((False, False), (True, True)), transfer.ClientTransferOwner.closed_facts(owner))
        # An attempted constructor with no returned object is genuinely unknown;
        # never convert that distinct outcome into a zero-resource success.
        attempted = dict(row, constructor_started=True)
        self.assertFalse(transfer.ClientTransferOwner._route_closed(attempted))
        owner.full_rows.append(attempted)
        self.assertEqual((False, False), transfer.ClientTransferOwner.closed_facts(owner)[-1])
        self.assertFalse(owner.close_called)  # Overall owner is deliberately not closed.


if __name__ == '__main__':
    unittest.main()
