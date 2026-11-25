"""New v30 HOST component tests, never old TestCase methods or phone evidence.

The first method runs actual native WSS/HTTPS/TLS, protocol, ZIP storage and
sender threads over fixed localhost sockets. Only receiver construction admits
127.0.0.1 through a labelled HOST boundary; native private-address policy is not
changed. The scoped factory is a HOST-only connector, NOT SO_BINDTODEVICE or a
native CLIENT capsule. Handoff only observes actual adopted raw originals.

The second method uses actual socketpair IO and a synthetic clock for finite
deadline cases. No socket proxy, simulated TLS handshake, socket success bool,
old test invocation, P011, RF, phone, native F/capsule or endpoint permission is
used. Clock jumps are component boundary coverage, not wall-time guarantees.
All six source definitions and the OpenSSL-selector definition are pinned.
Actual sender certificate generation is temporary and not public test output.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE_PINS = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_storage', 'runtime/mta_storage.py',
     '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6'),
    ('mta_files', 'runtime/mta_files.py',
     'c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae'),
    ('mta_transport', 'candidate/client-transfer-v30/runtime/mta_transport.py',
     '77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa'),
    ('mta_sender', 'runtime/mta_sender.py',
     'da25d3359d0759f71d8a4483680e3a3d5376c9e745e85224dbaee2a672f0670a'),
)
FIXTURE_PATH = 'tests/test_receiver.py'
FIXTURE_SHA = '4cb55f33d016dabffe5c9e406a9283e5e8d660b84bee2b78ec1e72813fffcf93'


def fixed(relative, expected):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('HOST fixed source changed')
    return raw


def definitions():
    """Private exact-definition domain; no old test/module setup execution."""
    modules, actual_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('private definition unavailable')
            return modules[name]
        return actual_import(name, *args, **kwargs)
    for name, relative, pin in SOURCE_PINS:
        raw = fixed(relative, pin)
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        module = types.ModuleType(name)
        module.__file__ = 'HOST-v30-absolute/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    tree = ast.parse(fixed(FIXTURE_PATH, FIXTURE_SHA).decode('utf-8'))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'host_openssl']
    if len(nodes) != 1: raise ValueError('HOST certificate selector definition changed')
    only_selector = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    fixture_globals = {'os': os}
    exec(compile(only_selector, 'HOST-fixed-openssl-selector', 'exec'), fixture_globals)
    return modules, fixture_globals['host_openssl']


class FixedClock:
    """Synthetic timer; never a native allocation/CLIENT capability."""
    def __init__(self, value): self.value = float(value)
    def __call__(self): return self.value


class TransportAbsoluteV30Tests(unittest.TestCase):
    def _close_native_sender_after_actual_threads_exit(self, server):
        # A returned worker function/current-thread close is not a close proof.
        # Retain the actual original thread inventory and wait for actual exit.
        server.close(2)
        originals = tuple(row['thread'] for row in server._life._threads) + tuple(server._life._callers)
        original_threads = tuple(dict.fromkeys(originals))
        until = time.monotonic() + 2
        for worker in original_threads:
            self.assertIsInstance(worker, threading.Thread)
            self.assertIsNot(worker, threading.current_thread())
            if worker.is_alive(): worker.join(max(0, until - time.monotonic()))
        self.assertFalse(any(worker.is_alive() for worker in original_threads))
        self.assertTrue(server.close(0))
        self.assertTrue(server.closed())
        self.assertEqual(0, server.lifecycle_status()['threads_pending'])
        self.assertEqual(0, server.lifecycle_status()['actors_pending'])

    def test_actual_local_tls_two_handoffs_bytes_and_late_confirmation_rejection(self):
        modules, host_openssl = definitions()
        openssl_path = host_openssl()
        # This method cannot silently skip and be reported as real TLS success.
        self.assertIsNotNone(openssl_path, 'HOST OpenSSL required for this new TLS method')
        transport, sender, files, storage_module = (modules[name] for name in
            ('mta_transport', 'mta_sender', 'mta_files', 'mta_storage'))
        for case in ('complete', 'late_confirmation', 'handoff_failure', 'handoff_none', 'late_handshake'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(prefix='mta-v30-' + case + '-') as folder:
                user, incoming, private = (Path(folder) / name for name in ('user', 'incoming', 'private'))
                (user / 'Music').mkdir(parents=True)
                incoming.mkdir(); private.mkdir()
                expected = b'v30 native localhost bytes\x00\xff' * 128
                (user / 'Music' / 'HOST.bin').write_bytes(expected)
                registry = files.FileRegistry(str(user))
                selection = registry.open_selection([row['id'] for row in registry.list_files()])
                server = sender.SenderTransport('127.0.0.1', 0, selection, openssl_path,
                    task_id='v30-host-' + case, sender_id='0011', timeout=15,
                    allow_loopback=True, allowed_peer_ip='127.0.0.1', temp_root=str(private))
                receiver = None
                try:
                    server.start()  # Native certificate generation and native listener.
                    self.assertEqual('127.0.0.1', server._listener.getsockname()[0])
                    storage = storage_module.SafeZipReceiver(str(incoming), reserve_bytes=0)
                    clock = time.monotonic if case == 'complete' else FixedClock(100.0)
                    started = float(clock())
                    original_until = started + (30.0 if case == 'late_handshake' else 10.0)
                    originals, handoffs, wraps, events, requests, client_messages, temporary_calls = [], [], [], [], [], [], []
                    def factory(host, port, timeout):
                        # No DNS, public/private subnet scan or arbitrary proxy.
                        self.assertEqual(('127.0.0.1', server.port), (host, port))
                        self.assertGreater(timeout, 0); self.assertLessEqual(timeout, 3)
                        raw = socket.create_connection((host, port), timeout,
                            source_address=('127.0.0.1', 0))
                        self.assertIsInstance(raw, socket.socket)
                        self.assertNotIsInstance(raw, ssl.SSLSocket)
                        originals.append(raw); events.append(('factory', raw))
                        return raw
                    def handoff(value, raw):
                        self.assertIs(value, receiver)
                        self.assertIs(raw, originals[-1])
                        row = value._life._record(raw)
                        self.assertIsNotNone(row)
                        self.assertIs(row['raw'], raw); self.assertIsNone(row['tls'])
                        self.assertFalse(row['wrapping']); self.assertFalse(row['transferred'])
                        self.assertGreaterEqual(raw.fileno(), 0)
                        self.assertTrue(value.closure_snapshot(raw)['recognized_raw'])
                        self.assertFalse(value.closure_snapshot(raw)['all_sockets_closed'])
                        handoffs.append((value, raw)); events.append(('handoff', raw))
                        if case == 'handoff_failure': raise RuntimeError('HOST fixed handoff rejection')
                        if case == 'handoff_none': return None
                        return raw  # Actual caller consumes exact-original identity.
                    # HOST-only ctor admission. Native connect/TLS/protocol/storage
                    # execute outside the patch, with actual raw endpoint readback.
                    native_private = transport.private_ipv4
                    with mock.patch.object(transport, 'private_ipv4',
                            side_effect=lambda value: value if value == '127.0.0.1' else native_private(value)):
                        receiver = transport.ReceiverTransport('127.0.0.1', server.port, storage,
                            timeout=15, socket_factory=factory, source_ip='127.0.0.1',
                            absolute_until=original_until, clock=clock, handoff=handoff)
                    with self.assertRaises(transport.TransportError): native_private('127.0.0.1')
                    actual_wrap = receiver.context.wrap_socket
                    def observed_wrap(raw, *args, **kwargs):
                        self.assertTrue(any(value is receiver and owned is raw for value, owned in handoffs))
                        self.assertTrue(receiver._life._record(raw)['wrapping'])
                        events.append(('wrap', raw))
                        wrapped = actual_wrap(raw, *args, **kwargs)
                        wraps.append(wrapped)
                        self.assertIsInstance(wrapped, ssl.SSLSocket)
                        if case == 'late_handshake':
                            # Real local TLS first succeeds. Only return-time
                            # lateness is synthetic; no wall-TLS claim or proxy.
                            native_handshake = wrapped.do_handshake
                            def late_native_handshake(*arguments, **options):
                                returned = native_handshake(*arguments, **options)
                                clock.value = started + 12.0
                                return returned
                            wrapped.do_handshake = late_native_handshake
                        return wrapped
                    actual_send = transport.WebSocket.send
                    def observed_send(ws, message):
                        if ws.client:
                            client_messages.append((message.msg_type, message.id, message.name))
                        return actual_send(ws, message)
                    actual_mkstemp = transport.tempfile.mkstemp
                    def observed_mkstemp(*args, **kwargs):
                        temporary_calls.append(True)
                        return actual_mkstemp(*args, **kwargs)
                    def confirm(request):
                        requests.append(request)
                        if case == 'late_confirmation': clock.value = original_until
                        return True
                    with ExitStack() as observers:
                        observers.enter_context(mock.patch.object(receiver.context, 'wrap_socket', side_effect=observed_wrap))
                        observers.enter_context(mock.patch.object(transport.WebSocket, 'send', observed_send))
                        observers.enter_context(mock.patch.object(transport.tempfile, 'mkstemp', side_effect=observed_mkstemp))
                        if case == 'complete':
                            result = receiver.run(confirm)
                            self.assertTrue(result['peer_ack_verified'])
                            self.assertEqual(1, result['fileCount']); self.assertEqual(len(expected), result['totalSize'])
                            self.assertEqual(1, len(result['files']))
                            self.assertEqual(expected, Path(result['files'][0]).read_bytes())
                            sent = server.wait()
                            self.assertTrue(sent['peer_completion_verified'])
                            self.assertEqual(len(expected), sent['totalSize'])
                            self.assertEqual(2, len(originals)); self.assertEqual(2, len(handoffs)); self.assertEqual(2, len(wraps))
                            self.assertTrue(temporary_calls)
                            self.assertIn(('ack', 1, 'sendRequest'), client_messages)
                        elif case == 'late_confirmation':
                            with self.assertRaises(transport.TransportError): receiver.run(confirm)
                            self.assertEqual(1, len(requests))
                            self.assertEqual(1, len(originals)); self.assertEqual(1, len(handoffs)); self.assertEqual(1, len(wraps))
                            self.assertNotIn(('ack', 1, 'sendRequest'), client_messages)
                            self.assertNotIn(('action', 2, 'status'), client_messages)
                            self.assertEqual([], temporary_calls)
                            self.assertEqual([], list(incoming.iterdir()))
                        elif case == 'handoff_failure':
                            with self.assertRaisesRegex(RuntimeError, '^HOST fixed handoff rejection$'): receiver.run(confirm)
                            self.assertEqual([], requests); self.assertEqual([], wraps)
                            self.assertEqual(1, len(originals)); self.assertEqual(1, len(handoffs))
                            self.assertEqual([], client_messages); self.assertEqual([], temporary_calls)
                            self.assertEqual([], list(incoming.iterdir()))
                        elif case == 'handoff_none':
                            with self.assertRaises(transport.TransportError): receiver.run(confirm)
                            self.assertEqual([], requests); self.assertEqual([], wraps)
                            self.assertEqual(1, len(originals)); self.assertEqual(1, len(handoffs))
                            self.assertEqual([], client_messages); self.assertEqual([], temporary_calls)
                            self.assertEqual([], list(incoming.iterdir()))
                        else:
                            with self.assertRaises(transport.TransportError): receiver.run(confirm)
                            self.assertEqual(started + 12.0, clock())
                            self.assertLess(clock(), original_until)
                            self.assertIsNone(receiver.fingerprint)
                            self.assertEqual([], requests); self.assertEqual(1, len(wraps))
                            self.assertEqual(1, len(originals)); self.assertEqual(1, len(handoffs))
                            self.assertEqual([], client_messages); self.assertEqual([], temporary_calls)
                            self.assertEqual([], list(incoming.iterdir()))
                    self.assertEqual(original_until, receiver.deadline)
                    self.assertEqual(original_until, receiver._budget.until)
                    for raw in originals:
                        labels = tuple(label for label, value in events if value is raw)
                        self.assertEqual(('factory', 'handoff') +
                            (() if case in ('handoff_failure', 'handoff_none') else ('wrap',)), labels)
                        self.assertEqual(-1, raw.fileno())
                        self.assertTrue(receiver.closure_snapshot(raw)['recognized_raw'])
                        self.assertTrue(receiver.closure_snapshot(raw)['all_sockets_closed'])
                    self.assertTrue(receiver.close(0)); self.assertTrue(receiver.closed())
                    self._close_native_sender_after_actual_threads_exit(server)
                    if case != 'complete':
                        self.assertFalse(server._accepted); self.assertFalse(server._download_started)
                        self.assertFalse(server._download_complete); self.assertIsNone(server.result)
                finally:
                    if receiver is not None: receiver.close(0)
                    self._close_native_sender_after_actual_threads_exit(server)
                    selection.close()
                    self.assertTrue(selection.lifecycle_status()['closure_verified'])

    def test_actual_socketpair_fixed_stream_timeout_expiry_regression_and_ctor_bounds(self):
        modules, unused_selector = definitions()
        transport = modules['mta_transport']
        first, second = socket.socketpair()
        try:
            second.settimeout(.5)
            clock = FixedClock(100.0); original_until = 100.75
            stream = transport.Stream(first, deadline=original_until, clock=clock)
            self.assertEqual(original_until, stream.deadline)
            self.assertEqual(original_until, stream._budget.until)
            second.sendall(b'A')
            self.assertEqual(b'A', stream.read(1)); self.assertAlmostEqual(.5, first.gettimeout())
            clock.value = 100.5
            second.sendall(b'line\r\n')
            self.assertEqual(b'line', stream.line()); self.assertAlmostEqual(.25, first.gettimeout())
            clock.value = 100.7
            stream.send(b'B')
            self.assertEqual(b'B', second.recv(1)); self.assertAlmostEqual(.05, first.gettimeout())
            self.assertEqual(original_until, stream.deadline)
            self.assertEqual(original_until, stream._budget.until)
            clock.value = original_until
            second.sendall(b'UNREAD')
            for label, call in (('recv', lambda: stream.read(1)), ('send', lambda: stream.send(b'NO')),
                    ('line', lambda: stream.line())):
                with self.subTest(boundary=label):
                    with self.assertRaises(transport.TransportError): call()
            # Expired recv did not consume, expired send did not produce bytes.
            self.assertEqual(b'UNREAD', first.recv(6))
            with self.assertRaises(socket.timeout): second.recv(1)
            # Caller field mutation cannot renew the originally issued budget.
            stream.deadline = original_until + 30
            with self.assertRaises(transport.TransportError): stream.send(b'NO_RENEW')
            self.assertEqual(original_until, stream._budget.until)
        finally:
            first.close(); second.close()
        first, second = socket.socketpair()
        try:
            clock = FixedClock(50)
            stream = transport.Stream(first, deadline=51, clock=clock)
            with self.assertRaises(transport.TransportError):
                transport.Stream(first, deadline=0, clock=clock)
            clock.value = 49
            with self.assertRaisesRegex(transport.TransportError, 'clock moved backwards'): stream.read(1)
            with self.assertRaisesRegex(transport.TransportError, 'clock moved backwards'): stream.send(b'NO')
            self.assertEqual(51.0, stream._budget.until)
        finally:
            first.close(); second.close()
        with tempfile.TemporaryDirectory(prefix='mta-v30-no-io-') as folder, \
                mock.patch.object(transport.socket, 'create_connection',
                    side_effect=AssertionError('HOST unscoped fallback forbidden')):
            storage = types.SimpleNamespace(root=folder)
            calls = []
            def forbidden_factory(*args):
                calls.append(True)
                raise AssertionError('HOST forbidden connector invocation')
            def receiver(**changes):
                options = dict(socket_factory=forbidden_factory, source_ip='192.168.49.2',
                    absolute_until=101.0, clock=FixedClock(100), handoff=lambda value, raw: raw)
                options.update(changes)
                return transport.ReceiverTransport('192.168.49.1', 9443, storage, **options)
            for label, cap in (('missing', None), ('expired', 100), ('past', 99), ('over300', 400.1),
                    ('bool', True), ('nan', float('nan')), ('inf', float('inf')), ('text', '101')):
                with self.subTest(invalid_cap=label):
                    with self.assertRaises(transport.TransportError): receiver(absolute_until=cap)
            with self.assertRaises(transport.TransportError): receiver(handoff=None)
            with self.assertRaises(transport.TransportError): receiver(clock=1)
            for label, later in (('expired', 101.0), ('regressed', 99.0)):
                with self.subTest(before_factory=label):
                    clock = FixedClock(100)
                    value = receiver(clock=clock)
                    clock.value = later
                    with self.assertRaises(transport.TransportError): value.connect()
                    self.assertEqual(101.0, value.deadline)
                    self.assertEqual(101.0, value._budget.until)
                    self.assertEqual(0, value.lifecycle_status()['socket_records'])
                    self.assertTrue(value.close(0)); self.assertTrue(value.closed())
            self.assertEqual([], calls)


if __name__ == '__main__': unittest.main()
