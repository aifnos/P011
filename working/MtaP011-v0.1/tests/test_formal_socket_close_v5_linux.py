"""One affected contract; exact production function bodies, native Linux FDs.

Run this one method on Linux/WSL only. The fixture deliberately omits startup,
RF, FileCenter and device authority; it cannot grant any full Owner closure.
It verifies the new original-socket receipt and HTTP cleanup, not P011 ABI.
"""
import ast
import errno
import hashlib
import math
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
PINS = (
    ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_client_service_owner.py', 89599,
     'a9a5aa60d4cf5c26df46d6de88a9c79fb1df76eb88ff869f186fcf277ea7af11'),
    ('candidate/formal-send-filecenter-deploy-v5/runtime/minhttp.py', 9690,
     'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235'))
METHODS = ('_socket_row', '_socket_receipt', '_socket_receipt_closed',
           '_close_socket', '_http_passively_closed')


def actual_bodies(pin, class_name, methods, socket_module=socket):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise AssertionError('exact_contract_source_pin')
    tree = ast.parse(raw, filename=pin[0])
    value = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == class_name)
    value.body = [row for row in value.body if isinstance(row, ast.FunctionDef) and row.name in methods]
    if {row.name for row in value.body} != set(methods):
        raise AssertionError('exact_contract_methods')
    helpers = [row for row in tree.body if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and
               row.name in ('ServiceOwnerError', '_fail', '_finite', '_meta', '_SocketRef')]
    selected = ast.Module(body=helpers + [value], type_ignores=[])
    namespace = dict(os=os, errno=errno, math=math, socket=socket_module, stat=stat,
                     threading=threading, types=types)
    exec(compile(ast.fix_missing_locations(selected), pin[0], 'exec'), namespace)
    return namespace[class_name], namespace


def owner_fixture(cls, io):
    owner = cls.__new__(cls)
    owner.lock = threading.RLock()
    owner.io = io
    owner._context = lambda: None  # Contract fixture only; production context is NOT bypassed.
    owner.requests = owner._requests_original = []
    owner.threads = owner._threads_original = []
    owner.socket_close_receipts = owner._socket_close_receipts_original = []
    owner.socket_receipt_methods = owner._socket_receipt_methods_original = (
        cls._socket_receipt, cls._socket_receipt_closed)
    owner.listener = None
    owner.server = owner._server_original = None
    owner.server_called = False
    return owner


def register(owner, raw, listener=False):
    row = dict(socket=raw, fd=None, metadata=None, proxy=None,
               unknown=True, attempted=False, closed=False, ended=True, failure=None)
    if listener:
        owner.listener = row
    else:
        owner.requests.append(row)
    return owner._socket_row(raw, row)


def sealed_server(owner):
    class OriginalServer(object):
        pass
    server = OriginalServer()
    owner.service = types.SimpleNamespace(Server=OriginalServer)
    owner.state = object()
    server.state = owner.state
    server.stopping = threading.Event()
    server.stopping.set()
    server.socket = owner.listener['proxy_original']
    server.workers = {}
    owner.server = owner._server_original = server
    owner.server_called = owner.server_complete = owner.stop_called = True
    thread = threading.Thread(target=lambda: None)
    ticket = dict(thread=thread, thread_original=thread, unknown=False, initialized=True,
                  called=False, returned=False, ended=False)
    owner.threads.append(ticket)
    owner.requests[0]['ticket'] = owner.requests[0]['ticket_original'] = ticket
    return server, ticket


def metadata(value):
    return tuple(getattr(value, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))


class NativeIO(object):
    def __init__(self, original, replacement_fd=None):
        self.original = original
        self.target_fd = original.fileno()
        self.replacement_fd = replacement_fd
        self.injected = False
        self.calls = 0

    def fstat(self, fd):
        self.calls += 1
        if (self.replacement_fd is not None and fd == self.target_fd and
                self.original.fileno() == -1 and not self.injected):
            try:
                os.fstat(fd)
            except OSError as error:
                if type(error.errno) is not int or error.errno != errno.EBADF:
                    raise
            else:
                raise AssertionError('native_slot_not_freed_before_reuse')
            os.dup2(self.replacement_fd, fd)
            self.injected = True
        return os.fstat(fd)


class FakeSocket(object):
    def __init__(self, returned=None, after=-1, before=123, close_error=None):
        self.current = before
        self.returned = returned
        self.after = after
        self.close_error = close_error
        self.close_count = 0

    def fileno(self):
        return self.current

    def close(self):
        self.close_count += 1
        if self.close_error is not None:
            raise self.close_error
        self.current = self.after
        return self.returned


class FakeIO(object):
    def __init__(self, post=None, error=None, before=None):
        self.original = (7, 42, stat.S_IFSOCK | 0o600, 0, 0, 1, 0)
        self.before = self.original if before is None else before
        self.post = self.original if post is None else post
        self.error = error
        self.calls = 0

    def fstat(self, fd):
        self.calls += 1
        value = self.original if self.calls == 1 else self.before if self.calls == 2 else self.post
        if self.calls > 2 and self.error is not None:
            raise self.error
        return types.SimpleNamespace(**dict(zip(
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'), value)))


class SocketCloseV5Contract(unittest.TestCase):
    def test_real_fd_reuse_original_receipt_and_http_finally(self):
        if not sys.platform.startswith('linux'):
            self.skipTest('The one affected contract requires Linux/WSL native FD evidence')
        native, native_ns = actual_bodies(PINS[0], 'FixedStateServiceOwner', METHODS)
        model, model_ns = actual_bodies(PINS[0], 'FixedStateServiceOwner', METHODS,
                                       types.SimpleNamespace(socket=FakeSocket))
        http, unused = actual_bodies(PINS[1], 'HTTPServer', ('process',))
        # Guard the exact changed methods against a numeric-descriptor re-close.
        owner_tree = ast.parse((BASE / PINS[0][0]).read_bytes())
        owner_class = next(row for row in owner_tree.body if isinstance(row, ast.ClassDef) and
                           row.name == 'FixedStateServiceOwner')
        for method in owner_class.body:
            if isinstance(method, ast.FunctionDef) and method.name in METHODS:
                self.assertFalse(any(isinstance(row, ast.Call) and isinstance(row.func, ast.Attribute) and
                    row.func.attr == 'close' and isinstance(row.func.value, ast.Name) and
                    row.func.value.id in ('os', 'io') for row in ast.walk(method)))
        self.native_receipts(native)
        self.refusal_boundaries(model, model_ns['ServiceOwnerError'])
        self.helper_identity(model)
        self.http_finally(http)
        self.real_slot_capacity(http)

    def native_receipts(self, cls):
        for kind in ('socket', 'non_socket', 'badfd_then_reuse'):
            with self.subTest(native=kind):
                original = socket.socket()
                listener = socket.socket()
                replacement_socket = socket.socket() if kind == 'socket' else None
                replacement_fd = replacement_socket.fileno() if replacement_socket is not None else os.open('/dev/null', os.O_RDONLY)
                target_fd = original.fileno()
                self.assertNotEqual(target_fd, replacement_fd)
                io = NativeIO(original, None if kind == 'badfd_then_reuse' else replacement_fd)
                owner = owner_fixture(cls, io)
                target_owned = False
                try:
                    listen_row = register(owner, listener, listener=True)
                    row = register(owner, original)
                    server, ticket = sealed_server(owner)
                    self.assertIsNone(listen_row['proxy_original'].close())
                    self.assertIsNone(row['proxy_original'].close())
                    receipt = row['socket_close_receipt']
                    if kind == 'badfd_then_reuse':
                        self.assertEqual(receipt['post_outcome'], 'badfd')
                        with self.assertRaises(OSError) as caught:
                            os.fstat(target_fd)
                        self.assertEqual(caught.exception.errno, errno.EBADF)
                        os.dup2(replacement_fd, target_fd)
                        target_owned = True
                    else:
                        target_owned = io.injected
                        self.assertTrue(target_owned)
                        self.assertEqual(receipt['post_outcome'], 'reused')
                        actual_type = stat.S_IFMT(os.fstat(target_fd).st_mode)
                        self.assertEqual(actual_type == stat.S_IFSOCK, kind == 'socket')
                    replacement_meta = metadata(os.fstat(target_fd))
                    self.assertIs(receipt['close_return_none'], True)
                    self.assertIs(receipt['post_fileno_minus_one'], True)
                    self.assertEqual(original.fileno(), -1)
                    before_calls = io.calls
                    for repeat in range(3):
                        self.assertIs(owner._socket_receipt_closed(row), True)
                        self.assertIs(owner._close_socket(row), True)
                        self.assertIsNone(row['proxy_original'].close())
                        self.assertIs(owner._http_passively_closed(), True)
                        self.assertEqual(metadata(os.fstat(target_fd)), replacement_meta)
                    self.assertEqual(io.calls, before_calls)
                    server.workers[object()] = object()
                    self.assertIs(owner._http_passively_closed(), False)
                    server.workers.clear()
                    ticket['unknown'] = True
                    self.assertIs(owner._http_passively_closed(), False)
                    ticket['unknown'] = False
                    old_state = server.state
                    server.state = object()
                    self.assertIs(owner._http_passively_closed(), False)
                    server.state = old_state
                    server.stopping.clear()
                    self.assertIs(owner._http_passively_closed(), False)
                    server.stopping.set()
                    self.assertIs(owner._http_passively_closed(), True)
                    # Equal-but-copied proofs and swapped object bindings are not receipts.
                    old_seal = receipt['sealed']
                    receipt['sealed'] = tuple(list(old_seal))
                    self.assertIsNot(receipt['sealed'], old_seal)
                    self.assertIs(owner._socket_receipt_closed(row), False)
                    receipt['sealed'] = old_seal
                    old_original = receipt['original']
                    receipt['original'] = tuple(list(old_original))
                    self.assertIs(owner._socket_receipt_closed(row), False)
                    receipt['original'] = old_original
                    old_receipt = row['socket_close_receipt']
                    row['socket_close_receipt'] = dict(old_receipt)
                    self.assertIs(owner._socket_receipt_closed(row), False)
                    row['socket_close_receipt'] = old_receipt
                    self.assertIs(owner._socket_receipt_closed(dict(row)), False)
                    owner.socket_close_receipts = list(owner.socket_close_receipts)
                    self.assertIs(owner._socket_receipt_closed(row), False)
                    owner.socket_close_receipts = owner._socket_close_receipts_original
                    for key, bad in (('close_return_none', False), ('post_fileno_minus_one', None), ('post_outcome', 'same')):
                        good = receipt[key]
                        receipt[key] = bad
                        self.assertIs(owner._socket_receipt_closed(row), False)
                        receipt[key] = good
                    self.assertIs(owner._http_passively_closed(), True)
                    self.assertEqual(metadata(os.fstat(target_fd)), replacement_meta)
                finally:
                    # Only descriptors allocated/reused by this fixture are closed here.
                    target_owned = target_owned or io.injected
                    if target_owned:
                        os.close(target_fd)
                    original.close()
                    listener.close()
                    if replacement_socket is not None:
                        replacement_socket.close()
                    else:
                        os.close(replacement_fd)

    def refusal_boundaries(self, cls, owner_error):
        original = (7, 42, stat.S_IFSOCK | 0o600, 0, 0, 1, 0)
        same_changed = (7, 42, stat.S_IFSOCK | 0o644, 0, 0, 1, 99)
        different_socket = (7, 43, stat.S_IFSOCK | 0o600, 0, 0, 1, 0)
        different_kind = (7, 42, stat.S_IFREG | 0o600, 0, 0, 1, 0)
        cases = (
            ('same', dict(post=original), {}, False, 'same', 1),
            ('same_changed_permissions_size', dict(post=same_changed), {}, False, 'same', 1),
            ('different_socket', dict(post=different_socket), {}, True, 'reused', 1),
            ('different_resource_type', dict(post=different_kind), {}, True, 'reused', 1),
            ('badfd', dict(error=OSError(errno.EBADF, 'fixture')), {}, True, 'badfd', 1),
            ('bool_errno', dict(error=OSError(True, 'fixture')), {}, False, 'error', 1),
            ('str_errno', dict(error=OSError(str(errno.EBADF), 'fixture')), {}, False, 'error', 1),
            ('unknown_errno', dict(error=OSError()), {}, False, 'error', 1),
            ('other_errno', dict(error=OSError(errno.EIO, 'fixture')), {}, False, 'error', 1),
            ('post_exception', dict(error=RuntimeError('fixture')), {}, False, 'error', 1),
            ('post_metadata_bool', dict(post=(7, True, stat.S_IFREG, 0, 0, 1, 0)), {}, False, 'error', 1),
            ('before_metadata_changed', dict(before=same_changed), {}, False, 'error', 0),
            ('close_non_none', dict(error=OSError(errno.EBADF, 'fixture')), dict(returned=True), False, 'error', 1),
            ('fileno_bool', dict(error=OSError(errno.EBADF, 'fixture')), dict(after=True), False, 'error', 1),
            ('fileno_not_minus_one', dict(error=OSError(errno.EBADF, 'fixture')), dict(after=0), False, 'error', 1),
            ('close_exception', dict(error=OSError(errno.EBADF, 'fixture')), dict(close_error=RuntimeError('fixture')), False, 'error', 1))
        for label, io_args, socket_args, expected, outcome, close_count in cases:
            with self.subTest(model=label):
                raw = FakeSocket(**socket_args)
                io = FakeIO(**io_args)
                owner = owner_fixture(cls, io)
                row = register(owner, raw)
                self.assertIs(owner._close_socket(row), expected)
                self.assertEqual(row['socket_close_receipt']['post_outcome'], outcome)
                self.assertEqual(raw.close_count, close_count)
                calls = io.calls
                self.assertIs(owner._close_socket(row), expected)
                self.assertEqual(raw.close_count, close_count)
                self.assertEqual(io.calls, calls)
                if expected:
                    self.assertIs(row['unknown'], False)
                    self.assertIsNone(row['failure'])
                else:
                    self.assertIs(row['unknown'], True)
                    self.assertIsNotNone(row['failure'])
                    self.assertIsNone(row['socket_close_receipt']['sealed'])
                    with self.assertRaises(owner_error):
                        row['proxy_original'].close()
        for binding in ('fd', 'fd_original', 'metadata', 'proxy', 'socket'):
            with self.subTest(original_binding=binding):
                raw = FakeSocket()
                io = FakeIO(error=OSError(errno.EBADF, 'fixture'))
                owner = owner_fixture(cls, io)
                row = register(owner, raw)
                row[binding] = True if binding.startswith('fd') else tuple(list(row[binding])) if binding == 'metadata' else object()
                self.assertIs(owner._close_socket(row), False)
                self.assertEqual(raw.close_count, 0)

    def helper_identity(self, cls):
        class OriginalIO(object):
            def __init__(self, values):
                self.values = values
            def fstat(self, fd):
                if self.values[fd].fileno() == -1:
                    raise OSError(errno.EBADF, 'fixture')
                return types.SimpleNamespace(st_dev=7, st_ino=fd,
                    st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_gid=0,
                    st_nlink=1, st_size=0)
        for helper in ('_socket_receipt', '_socket_receipt_closed'):
            with self.subTest(helper_replaced=helper):
                raw = FakeSocket()
                owner = owner_fixture(cls, FakeIO(error=OSError(errno.EBADF, 'fixture')))
                row = register(owner, raw)
                retained = getattr(cls, helper)
                setattr(cls, helper, lambda *args: True)
                try:
                    self.assertIs(owner._close_socket(row), False)
                    self.assertIs(owner._http_passively_closed(), False)
                    self.assertEqual(raw.close_count, 0)
                finally:
                    setattr(cls, helper, retained)
                self.assertIs(owner._close_socket(row), True)
                setattr(cls, helper, lambda *args: True)
                try:
                    self.assertIs(owner._close_socket(row), False)
                    self.assertIs(owner._http_passively_closed(), False)
                finally:
                    setattr(cls, helper, retained)
                # Positive original passive proof; only the helper definition changes.
                raw = FakeSocket(before=123)
                listener = FakeSocket(before=124)
                owner = owner_fixture(cls, OriginalIO({123: raw, 124: listener}))
                listen_row = register(owner, listener, listener=True)
                row = register(owner, raw)
                sealed_server(owner)
                self.assertIs(owner._close_socket(listen_row), True)
                self.assertIs(owner._close_socket(row), True)
                self.assertIs(owner._http_passively_closed(), True)
                setattr(cls, helper, lambda *args: True)
                try:
                    self.assertIs(owner._close_socket(row), False)
                    self.assertIs(owner._http_passively_closed(), False)
                    self.assertEqual(raw.close_count, 1)
                finally:
                    setattr(cls, helper, retained)
                self.assertIs(owner._http_passively_closed(), True)
        raw = FakeSocket()
        owner = owner_fixture(cls, FakeIO(error=OSError(errno.EBADF, 'fixture')))
        row = register(owner, raw)
        owner.socket_receipt_methods = tuple(list(owner.socket_receipt_methods))
        self.assertIs(owner._close_socket(row), False)
        self.assertEqual(raw.close_count, 0)

    def http_finally(self, cls):
        for close_fails, pop_fails, release_fails in (
                (False, False, False), (True, False, False), (True, True, False),
                (True, False, True), (True, True, True), (False, True, False),
                (False, False, True), (False, True, True)):
            with self.subTest(close=close_fails, pop=pop_fails, release=release_fails):
                events = []
                close_error = RuntimeError('close fixture')
                pop_error = RuntimeError('pop fixture')
                release_error = RuntimeError('release fixture')
                lock = threading.Lock()
                class Request(object):
                    def close(self):
                        events.append('close')
                        if close_fails: raise close_error
                request = Request()
                class Workers(dict):
                    def pop(self, key, default=None):
                        self_test.assertTrue(lock.locked())
                        events.append('pop')
                        if pop_fails: raise pop_error
                        return dict.pop(self, key, default)
                class Slots(object):
                    def release(self):
                        self_test.assertFalse(lock.locked())
                        events.append('release')
                        if release_fails: raise release_error
                self_test = self
                server = cls.__new__(cls)
                server.stopping = threading.Event()
                server.worker_lock = lock
                server.workers = Workers({request: object()})
                server.slots = Slots()
                server.handler = lambda request, address, server: events.append('handler')
                server.handle_error = lambda request, address: events.append('handler_error')
                caught = None
                try:
                    server.process(request, None)
                except BaseException as error:
                    caught = error
                expected = close_error if close_fails else release_error if release_fails else pop_error if pop_fails else None
                self.assertIs(caught, expected)
                self.assertEqual(events, ['handler', 'close', 'pop', 'release'])
                self.assertFalse(lock.locked())
                self.assertEqual(request in server.workers, pop_fails)

    def real_slot_capacity(self, cls):
        # Actual bounded capacity, not only an event model of release calls.
        primary = RuntimeError('close fixture')
        class Request(object):
            def close(self):
                raise primary
        request = Request()
        server = cls.__new__(cls)
        server.stopping = threading.Event()
        server.worker_lock = threading.Lock()
        server.workers = {request: object()}
        server.slots = threading.BoundedSemaphore(1)
        server.handler = lambda request, address, server: None
        server.handle_error = lambda request, address: None
        self.assertIs(server.slots.acquire(False), True)
        self.assertIs(server.slots.acquire(False), False)
        with self.assertRaises(RuntimeError) as caught:
            server.process(request, None)
        self.assertIs(caught.exception, primary)
        self.assertNotIn(request, server.workers)
        self.assertIs(server.slots.acquire(False), True)
        self.assertIs(server.slots.acquire(False), False)
        server.slots.release()


if __name__ == '__main__':
    unittest.main()
