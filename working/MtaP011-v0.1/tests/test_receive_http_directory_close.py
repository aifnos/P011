"""New Owner directory-release contract, not a State/HTTP/RF acceptance test.

ROOT alone runs this method in an isolated HOST Linux child. Complete verified
Owner and Storage definitions execute; temporary directory FDs, socketpair,
Thread/Event and physical close/EBADF are actual HOST operations. Boot, State,
Server and HTTP-handler ancestors are explicit models. Only the last fixture
instruments cleanup clock expiry; it does not wait out a real 60-second service
timeout. No old TestCase/helper import or previously passed test method replay.
"""
import builtins
import errno
import hashlib
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
OWNER_SOURCE = ('mta_client_service_owner',
    'candidate/receive-http-directory-close-v3/runtime/mta_client_service_owner.py', 42663,
    '6aba9a6f60109b7fb3568e7b85e58889e76dbff99da9f633604ad408e94c029c')
SOURCES = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 'runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_storage', 'candidate/receive-directory-fd-v1/runtime/mta_storage.py', 55562,
     'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
)
MARKER = ('HOST_RECEIVE_HTTP_DIRECTORY_CLOSE new_methods=1 old_methods=0 domains=6 fixtures=8 '
          'linux_kernel=true state_model=true device=false phone=false\n')


def _definitions():
    if OWNER_SOURCE is None:
        raise AssertionError('unfrozen production SOURCE')
    definitions = {}
    original_import = builtins.__import__

    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name.startswith(('mta_', 'p011_')):
            if level or name not in definitions:
                raise AssertionError('unlisted project import')
            return definitions[name]
        return original_import(name, globals, locals, fromlist, level)

    for module, path, size, digest in SOURCES + (OWNER_SOURCE,):
        raw = (BASE / path).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise AssertionError('fixed SOURCE changed')
        value = types.ModuleType(module)
        value.__file__ = str(BASE / path)
        namespace_builtins = dict(vars(builtins))
        namespace_builtins['__import__'] = fixed_import
        value.__dict__['__builtins__'] = namespace_builtins
        exec(compile(raw, value.__file__, 'exec'), value.__dict__)
        definitions[module] = value
    return definitions['mta_storage'], definitions['mta_client_service_owner']


class _OsDescriptors(object):
    """Actual HOST fstat/close; no target-platform/asset validation grant."""
    def pid(self):
        return os.getpid()

    def fstat(self, fd):
        return os.fstat(fd)


class _CleanupExpiryClock(object):
    """Explicit fault model after State.close; all earlier samples are actual."""
    def __init__(self):
        self.original = time.monotonic
        self.expired = False
        self.calls = 0

    def __call__(self):
        self.calls += 1
        now = self.original()
        return now + 1000.0 if self.expired else now


class _StateModel(object):
    def __init__(self):
        raise AssertionError('State construction is outside this test')

    def close(self, timeout):
        self.close_calls += 1
        self.close_timeouts.append(timeout)
        self.closing = True
        if self.close_error is not None:
            raise self.close_error
        if self.expiry_clock is not None:
            self.expiry_clock.expired = True
        return True

    def closed(self):
        return self.closing is True and self.operation is None and self.closed_inventory is True

    def _close_probes(self):
        self.probe_close_calls += 1

    def _probes_closed(self):
        return type(self.probe_actors) is list and not self.probe_actors

    def _restore_receive_owner(self, operation):
        raise AssertionError('no receive restore/Parent invocation is allowed')


class _OperationModel(object):
    def __init__(self):
        raise AssertionError('Operation construction is outside this test')


class _SessionModel(object):
    def __init__(self):
        raise AssertionError('Session construction is outside this test')


class _ServerModel(object):
    def __init__(self):
        raise AssertionError('Server construction is outside this test')


class _HttpModel(object):
    @staticmethod
    def shutdown(server):
        # Only the ancestor shutdown's socket ownership is modeled. The proxy
        # performs actual new Owner._close_socket -> raw.close -> typed EBADF.
        server.shutdown_calls += 1
        server.stopping.set()
        server.socket.close()


class _LoaderModel(object):
    """Only the already-defined Boot/type/cap ancestry, never Boot.load."""
    pass


class _Fixture(object):
    def __init__(self, storage, module, late=False, http=True):
        self.storage, self.module, self.late, self.have_http = storage, module, late, http
        self.temporary = self.owner = self.state = self.ticket = self.request = None
        self.bindings, self.sockets, self.thread_errors = [], [], []
        self.entered, self.release = threading.Event(), threading.Event()
        self.expiry = _CleanupExpiryClock() if late else None
        self.primary = RuntimeError('original HOST business failure')

    def build(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='host-http-directory-close-')
        user = Path(self.temporary.name) / 'user'
        user.mkdir(mode=0o700)
        received = user / 'Received'
        received.mkdir(mode=0o700)
        until = time.monotonic() + 20.0
        boot = types.ModuleType('mta_client_receive_boot')
        boot.BootSourceLoader = _LoaderModel
        loader = _LoaderModel()
        loader._original_until = until
        clock = self.expiry if self.late else time.monotonic
        loader.clock = clock
        # Isolated definition-global ancestry projection, not sys.modules edits
        # or a public production clock/path injection. The Owner methods stay
        # untouched and enforce their own exact-reference context predicates.
        self.module.sys = types.SimpleNamespace(modules={'mta_client_receive_boot': boot})
        self.module.time = types.SimpleNamespace(monotonic=clock)
        self.owner = self.module.FixedStateServiceOwner(loader, until, _io=_OsDescriptors())
        value = self.owner
        value.pid = os.getpid()
        value.failure = self.primary
        value.directory_type = self.storage.DirectoryBinding
        for path in (user, received):
            binding = self.storage.DirectoryBinding.__new__(self.storage.DirectoryBinding)
            self.bindings.append(binding)  # Strong before a partial constructor.
            self.storage.DirectoryBinding.__init__(binding, str(path), until)
        value.user_directory = value._user_directory_original = self.bindings[0]
        value.received_directory = value._received_directory_original = self.bindings[1]
        self.state = _StateModel.__new__(_StateModel)
        self.state.lock = threading.RLock()
        self.state.close_calls, self.state.probe_close_calls = 0, 0
        self.state.close_timeouts = []
        self.state.close_error = None
        self.state.expiry_clock = self.expiry
        self.state.closed_inventory = True
        self.state.closing = False
        self.state.probe_actors = []
        for name in ('operation', 'session', 'worker', 'helper', 'key', 'crypto', 'lease', 'transport'):
            setattr(self.state, name, None)
        self.state._original_received_binding = self.state._received_binding_original = self.bindings[1]
        value.state = value._state_original = self.state
        value.state_called = value.state_complete = True
        value.probe_rows = self.state.probe_actors
        value.service = types.SimpleNamespace(State=_StateModel, Server=_ServerModel,
            Operation=_OperationModel, TransferSession=_SessionModel)
        value.http = types.SimpleNamespace(HTTPServer=_HttpModel)
        if not self.have_http:
            return self
        server = _ServerModel.__new__(_ServerModel)
        server.state = self.state
        server.stopping = threading.Event()
        server.worker_lock = threading.Lock()
        server.workers = {}
        server.shutdown_calls = 0
        value.server = value._server_original = server
        value._http_stopping_original = server.stopping
        value._http_worker_lock_original = server.worker_lock
        value._http_workers_original = server.workers
        value.server_called = value.server_complete = True
        listener = self._socket()
        value.listener = value._listener_original = listener
        server.socket = listener['proxy']
        request = self._socket()
        request['ended'] = False
        self.request = request
        value.requests.append(request)

        def modeled_handler():
            self.entered.set()
            try:
                if not self.release.wait(3.0):
                    self.thread_errors.append(RuntimeError('bounded HOST handler fixture expired'))
            finally:
                request['ended'] = True
                with server.worker_lock:
                    server.workers.pop(request['proxy'], None)

        self.ticket = value._new_thread(modeled_handler)  # Actual producer.
        request['ticket'] = request['ticket_original'] = self.ticket
        with server.worker_lock:
            server.workers[request['proxy']] = self.ticket['thread']
        value._start_thread(self.ticket)  # Actual start inventory/Thread.start.
        if not self.entered.wait(1.0):
            raise AssertionError('HOST handler did not enter')
        return self

    def _socket(self):
        raw, other = socket.socketpair()
        self.sockets.extend((raw, other))  # Retain before fileno/fstat.
        row = dict(socket=raw, fd=None, metadata=None, proxy=None,
                   attempted=False, closed=False, unknown=True, failure=None)
        self.owner._socket_row(raw, row)  # Actual original refs+FD metadata.
        return row

    def end_handler(self):
        self.release.set()
        if self.ticket is not None:
            self.ticket['thread_original'].join(1.0)  # HOST setup wait, not an Owner join proof.
            if self.ticket['thread_original'].is_alive():
                raise AssertionError('HOST handler still alive')
        if self.thread_errors:
            raise self.thread_errors[0]

    def cleanup(self, test, primary):
        errors = []
        # Independent original cleanup: never alter Owner pending/unknown rows
        # to make a production closure gate succeed. A model-unknown raw socket
        # can be physically freed by its separate HOST fixture owner only.
        try:
            self.end_handler()
        except BaseException as error:
            errors.append(error)
        for raw in self.sockets:
            try:
                descriptor = raw.fileno()
                if descriptor >= 0:
                    test.assertIs(raw.close(), None)
                    _badfd(test, descriptor)  # Immediate, before another open.
            except BaseException as error:
                errors.append(error)
        for binding in reversed(self.bindings):
            try:
                test.assertIs(binding.close(), True)
                test.assertIs(binding.closed(), True)
            except BaseException as error:
                errors.append(error)
        if self.temporary is not None and not errors:
            try:
                # This exact fresh test-owned TemporaryDirectory only; never
                # any target/user/managed path or pending recovery inventory.
                self.temporary.cleanup()
            except BaseException as error:
                errors.append(error)
        if errors:
            if primary is not None:
                primary.host_cleanup_errors = tuple(errors)
            else:
                raise errors[0]


def _closed_row_state(binding):
    return tuple((row['close_called'], row['close_return'], row['closed'], row['unknown'], row['ebadf'])
                 for row in binding.rows)


def _badfd(test, descriptor):
    with test.assertRaises(OSError) as caught:
        os.fstat(descriptor)
    test.assertEqual(errno.EBADF, caught.exception.errno)


class ReceiveHttpDirectoryCloseTest(unittest.TestCase):
    def test_http_quiescence_before_directory_release(self):
        self.assertEqual('posix', os.name)
        self.assertTrue(sys.platform.startswith('linux'))
        self.assertEqual(1000, os.getuid())  # HOST profile only, no target UID grant.
        storage, module = _definitions()
        owner_type = module.FixedStateServiceOwner
        methods = ('close', '_close_directories', '_http_closed', '_state_directory_idle',
                   '_state_closed', '_closed', '_close_socket', '_socket_row',
                   '_new_thread', '_start_thread', '_context', '_now', 'status')
        original_methods = {name: getattr(owner_type, name) for name in methods}
        forbidden = (owner_type.start, owner_type._serve, owner_type._request,
                     module._read_asset, _StateModel.__init__, _ServerModel.__init__,
                     _OperationModel.__init__, _SessionModel.__init__)
        counts = {function.__code__: 0 for function in forbidden}
        previous_profile = sys.getprofile()

        def tripwire(frame, event, argument):
            if event == 'call' and frame.f_code in counts:
                counts[frame.f_code] += 1
                raise AssertionError('unexpected service/State/Parent/RF ancestor entry')

        # Original method identities are preserved; no authenticated function
        # is replaced with a Mock. These are actual call-entry tripwires.
        sys.setprofile(tripwire)
        completed = 0
        domains = (
            ('normal', ('normal',)),
            ('alive_http', ('alive_http',)),
            ('unknown_http', ('unknown_thread', 'unknown_socket')),
            ('state_borrow_live', ('live_operation', 'partial_live_operation')),
            ('state_close_error', ('state_close_error',)),
            ('cleanup_expiry_model', ('cleanup_expiry_model',)),
        )
        try:
            for domain, fixtures in domains:
                for fixture in fixtures:
                    with self.subTest(domain=domain, fixture=fixture):
                        f = _Fixture(storage, module, late=fixture == 'cleanup_expiry_model',
                            http=fixture not in ('partial_live_operation', 'cleanup_expiry_model'))
                        primary = None
                        try:
                            f.build()
                            value = f.owner
                            descriptors = tuple(binding.rows[-1]['fd_original'] for binding in f.bindings)
                            initial_rows = tuple(_closed_row_state(binding) for binding in f.bindings)
                            self.assertIs(value.requests, value._requests_original)
                            self.assertIs(value.threads, value._threads_original)
                            self.assertIs(value.failure, f.primary)
                            self.assertTrue(all(not binding.closed() for binding in f.bindings))
                            for descriptor in descriptors:
                                self.assertTrue(os.fstat(descriptor))
                            if f.have_http:
                                self.assertTrue(f.ticket['thread_original'].is_alive())
                                self.assertTrue(os.fstat(value.listener['fd_original']))
                                self.assertTrue(os.fstat(f.request['fd_original']))
                            if fixture == 'alive_http':
                                # Both actual sockets can be closed while the
                                # real original Thread remains alive. Do not
                                # invent an ended/join-returned ticket to pass.
                                self.assertTrue(value._close_socket(value.listener))
                                self.assertTrue(value._close_socket(f.request))
                                value.server.stopping.set()
                                value.stop_called = True
                                with value.server.worker_lock:
                                    value.server.workers.clear()  # Server ancestry model only.
                                self.assertTrue(f.ticket['thread_original'].is_alive())
                                self.assertFalse(value._http_closed())
                                self.assertFalse(value._close_directories())
                                self.assertFalse(value.directory_close_called)
                                self.assertEqual(initial_rows, tuple(_closed_row_state(b) for b in f.bindings))
                                for descriptor in descriptors:
                                    self.assertTrue(os.fstat(descriptor))
                            if fixture in ('live_operation', 'partial_live_operation'):
                                original_operation = _OperationModel.__new__(_OperationModel)
                                original_operation.kind = 'send'  # Not a forged receive/restore receipt.
                                f.state.operation = original_operation
                                if fixture == 'partial_live_operation':
                                    value.state_complete = False
                                    value.state_constructor_failure = RuntimeError('original partial constructor failure')
                                self.assertFalse(value._state_directory_idle())
                            if fixture == 'state_close_error':
                                f.state.close_error = RuntimeError('original State.close exception')
                            if fixture == 'unknown_thread':
                                f.ticket['unknown'] = True  # Explicit returned-start fault ancestry.
                            if fixture == 'unknown_socket':
                                f.request['unknown'] = True  # Explicit original close identity uncertainty.
                            if f.have_http:
                                f.end_handler()
                                self.assertTrue(f.request['ended'])
                                self.assertFalse(f.ticket['thread_original'].is_alive())
                                self.assertFalse(f.ticket['join_called'])
                            result = value.close()  # Complete actual new close algorithm.
                            self.assertIs(value.failure, f.primary)
                            cap = value.cleanup_until
                            snapshot = tuple(_closed_row_state(binding) for binding in f.bindings)
                            close_calls = f.state.close_calls
                            join_facts = None if f.ticket is None else (
                                f.ticket['join_called'], f.ticket['join_returned'], f.ticket['ended'])
                            if fixture in ('normal', 'alive_http'):
                                self.assertIs(result, True)
                                self.assertTrue(value._http_closed())
                                self.assertTrue(value._state_directory_idle())
                                self.assertTrue(value.directory_close_complete)
                                self.assertFalse(value.status()['resource_pending'])
                                self.assertEqual((True, True, True), join_facts)
                                self.assertFalse(f.ticket['thread_original'].is_alive())
                                _badfd(self, value.listener['fd_original'])
                                _badfd(self, f.request['fd_original'])
                                for binding, descriptor in zip(f.bindings, descriptors):
                                    self.assertTrue(binding.closed())
                                    self.assertTrue(all(row['closed'] and not row['unknown'] for row in binding.rows))
                                    _badfd(self, descriptor)
                            elif fixture == 'cleanup_expiry_model':
                                # No HTTP was constructed in this one fault
                                # fixture. State closure is an ancestry model.
                                # The actual directory FDs release after modeled
                                # expiry without producing Owner completion.
                                self.assertIs(result, False)
                                self.assertTrue(value.status()['resource_pending'])
                                self.assertTrue(value.directory_close_complete)
                                self.assertTrue(f.expiry.expired)
                                self.assertTrue(any(type(error) is module.ServiceOwnerError and
                                    error.code == 'deadline' for error in value.failures))
                                for binding, descriptor in zip(f.bindings, descriptors):
                                    self.assertTrue(binding.closed())
                                    _badfd(self, descriptor)
                            else:
                                self.assertIs(result, False)
                                self.assertTrue(value.status()['resource_pending'])
                                self.assertFalse(value.directory_close_called)
                                self.assertFalse(value.directory_close_complete)
                                self.assertEqual(initial_rows, snapshot)
                                for binding, descriptor in zip(f.bindings, descriptors):
                                    self.assertFalse(binding.closed())
                                    self.assertTrue(os.fstat(descriptor))
                                if fixture == 'unknown_thread':
                                    self.assertTrue(f.ticket['unknown'])
                                elif fixture == 'unknown_socket':
                                    self.assertTrue(f.request['unknown'])
                                    self.assertFalse(f.request['attempted'])
                                    self.assertGreaterEqual(f.request['socket_original'].fileno(), 0)
                                elif fixture in ('live_operation', 'partial_live_operation'):
                                    self.assertIs(f.state.operation, original_operation)
                                elif fixture == 'state_close_error':
                                    self.assertIsNone(value.state_close_return)
                                    self.assertTrue(any(error is f.state.close_error for error in value.failures))
                            self.assertIs(value.close(), result)  # No second join/State/free/budget.
                            self.assertIs(value.cleanup_until, cap)
                            self.assertEqual(close_calls, f.state.close_calls)
                            self.assertEqual(snapshot, tuple(_closed_row_state(binding) for binding in f.bindings))
                            self.assertEqual(join_facts, None if f.ticket is None else (
                                f.ticket['join_called'], f.ticket['join_returned'], f.ticket['ended']))
                            self.assertIs(value.failure, f.primary)
                            self.assertFalse(value.status()['native_restored'])
                            self.assertFalse(value.status()['receive_available'])
                            self.assertFalse(value.status()['phone_tested'])
                            if fixture != 'partial_live_operation':
                                self.assertEqual(1, f.state.close_calls)
                            else:
                                self.assertEqual(0, f.state.close_calls)
                        except BaseException as error:
                            primary = error
                            raise
                        finally:
                            f.cleanup(self, primary)
                        completed += 1
            self.assertEqual(6, len(domains))
            self.assertEqual(8, completed)
            self.assertTrue(all(count == 0 for count in counts.values()))
            self.assertTrue(all(getattr(owner_type, name) is original for name, original in original_methods.items()))
        finally:
            sys.setprofile(previous_profile)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
