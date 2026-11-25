"""One actual-Receive socket contract, prepared for ROOT's sole Linux run.

Uses only pinned fixture definitions from the previously reviewed sender
contract, never its test methods. Executes the actual new Receive close and
passive HTTP methods. Startup/Trial/State/Session/RF/UI are NOT exercised or
granted; unchanged source methods retain their separate original gates.
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
OWNER = ('candidate/formal-receive-socket-close-v1/runtime/mta_client_service_owner.py', 78755,
         '7073b4140c62314416237428c1fdffb124407a9dab0043b9dd2f83e48e55992f')
MINHTTP = ('candidate/formal-receive-socket-close-v1/runtime/minhttp.py', 9690,
           'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235')
MINHTTP_ORIGINAL = ('candidate/formal-send-filecenter-deploy-v5/runtime/minhttp.py', 9690,
                    'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235')
FIXTURES = ('tests/test_formal_socket_close_v5_linux.py', 23512,
            '550f071e8c74a77fc37ce069345856ed8a0843f80feacfd769850cef95b27bf0')
DONOR = ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_client_service_owner.py', 89599,
         'a9a5aa60d4cf5c26df46d6de88a9c79fb1df76eb88ff869f186fcf277ea7af11')
METHODS = ('_socket_row', '_socket_receipt', '_socket_receipt_closed', '_close_socket', '_http_closed')


def fixed(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise AssertionError('source_pin')
    return raw


def fixture_definitions():
    tree = ast.parse(fixed(FIXTURES), filename=FIXTURES[0])
    names = {'actual_bodies', 'owner_fixture', 'register', 'metadata', 'NativeIO', 'FakeSocket', 'FakeIO'}
    selected = [row for row in tree.body if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name in names]
    if {row.name for row in selected} != names:
        raise AssertionError('fixture_definition_scope')
    namespace = dict(BASE=BASE, ast=ast, errno=errno, hashlib=hashlib, math=math,
                     os=os, socket=socket, stat=stat, sys=sys, threading=threading, types=types)
    exec(compile(ast.Module(body=selected, type_ignores=[]), FIXTURES[0], 'exec'), namespace)
    return namespace


def server_fixture(owner):
    class OriginalServer(object):
        pass
    server = OriginalServer()
    owner.service = types.SimpleNamespace(Server=OriginalServer)
    owner.state = owner._state_original = object()
    server.state = owner._state_original
    server.socket = owner.listener['proxy_original']
    server.stopping = owner._http_stopping_original = threading.Event()
    server.stopping.set()
    server.worker_lock = owner._http_worker_lock_original = threading.Lock()
    server.workers = owner._http_workers_original = {}
    owner.server = owner._server_original = server
    owner.server_called = owner.server_complete = owner.stop_called = True
    # A real returned and joined thread, not flags claiming an unrun worker.
    thread = threading.Thread(target=lambda: None)
    thread.start()
    thread.join()
    ticket = dict(thread=thread, thread_original=thread, unknown=False, initialized=True,
                  called=True, returned=True, ended=True, join_called=True,
                  join_returned=True, failure=None)
    owner.threads.append(ticket)
    owner.requests[0]['ticket'] = owner.requests[0]['ticket_original'] = ticket
    return server, ticket


class ReceiveSocketCloseV1Contract(unittest.TestCase):
    def test_actual_receive_original_socket_receipt_and_http_borrowers(self):
        if not sys.platform.startswith('linux'):
            self.skipTest('Requires ROOT Linux/WSL native descriptor evidence')
        helpers = fixture_definitions()
        fixed(OWNER)
        self.assertEqual(fixed(MINHTTP), fixed(MINHTTP_ORIGINAL))
        cls, namespace = helpers['actual_bodies'](OWNER, 'FixedStateServiceOwner', METHODS)
        # Algorithm reuse is exact; this contract is not a sender Owner swap.
        def definitions(pin):
            tree = ast.parse(fixed(pin))
            owner = next(row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'FixedStateServiceOwner')
            return {row.name: row for row in owner.body if isinstance(row, ast.FunctionDef)}
        actual, donor = definitions(OWNER), definitions(DONOR)
        for name in ('_socket_receipt', '_socket_receipt_closed', '_close_socket'):
            self.assertEqual(ast.dump(actual[name], include_attributes=False), ast.dump(donor[name], include_attributes=False))
        self.assertIn('_http_closed', actual)
        self.assertNotIn('_http_passively_closed', actual)
        self.native_receive(helpers, cls)
        self.same_resource_refusal(helpers)

    def native_receive(self, helpers, cls):
        for kind in ('socket', 'non_socket', 'badfd_then_reuse'):
            with self.subTest(native_receive=kind):
                original, listener = socket.socket(), socket.socket()
                replacement_socket = socket.socket() if kind == 'socket' else None
                replacement_fd = replacement_socket.fileno() if replacement_socket is not None else os.open('/dev/null', os.O_RDONLY)
                target_fd = original.fileno()
                self.assertNotEqual(target_fd, replacement_fd)
                io = helpers['NativeIO'](original, None if kind == 'badfd_then_reuse' else replacement_fd)
                owner = helpers['owner_fixture'](cls, io)
                target_owned = False
                try:
                    listen_row = helpers['register'](owner, listener, listener=True)
                    owner._listener_original = listen_row
                    row = helpers['register'](owner, original)
                    server, ticket = server_fixture(owner)
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
                        self.assertIs(target_owned, True)
                        self.assertEqual(receipt['post_outcome'], 'reused')
                        self.assertEqual(stat.S_ISSOCK(os.fstat(target_fd).st_mode), kind == 'socket')
                    replacement_meta = helpers['metadata'](os.fstat(target_fd))
                    calls = io.calls
                    self.assertIs(receipt['close_return_none'], True)
                    self.assertIs(receipt['post_fileno_minus_one'], True)
                    self.assertIs(owner._http_closed(), True)
                    for repeat in range(2):
                        self.assertIs(owner._socket_receipt_closed(row), True)
                        self.assertIs(owner._close_socket(row), True)
                        self.assertIsNone(row['proxy_original'].close())
                        self.assertIs(owner._http_closed(), True)
                        self.assertEqual(helpers['metadata'](os.fstat(target_fd)), replacement_meta)
                    self.assertEqual(io.calls, calls)
                    self.receive_gates(owner, row, ticket, server)
                    self.helper_and_receipt_gates(cls, owner, row)
                    self.assertEqual(helpers['metadata'](os.fstat(target_fd)), replacement_meta)
                finally:
                    # Only the duplicate descriptor created by this fixture.
                    if target_owned or io.injected:
                        os.close(target_fd)
                    original.close()
                    listener.close()
                    if replacement_socket is not None:
                        replacement_socket.close()
                    else:
                        os.close(replacement_fd)

    def receive_gates(self, owner, row, ticket, server):
        for key in ('returned', 'ended', 'join_called', 'join_returned'):
            original = ticket[key]
            ticket[key] = False
            self.assertIs(owner._http_closed(), False)
            ticket[key] = original
            self.assertIs(owner._http_closed(), True)
        ticket['failure'] = RuntimeError('fixture')
        self.assertIs(owner._http_closed(), False)
        ticket['failure'] = None
        row['ended'] = False
        self.assertIs(owner._http_closed(), False)
        row['ended'] = True
        server.workers[object()] = object()
        self.assertIs(owner._http_closed(), False)
        server.workers.clear()
        server.worker_lock.acquire()
        try:
            self.assertIs(owner._http_closed(), False)
        finally:
            server.worker_lock.release()
        for name in ('state', 'stopping', 'worker_lock', 'workers'):
            original = getattr(server, name)
            setattr(server, name, {} if name == 'workers' else object())
            self.assertIs(owner._http_closed(), False)
            setattr(server, name, original)
            self.assertIs(owner._http_closed(), True)
        original = owner.listener
        owner.listener = dict(original)
        self.assertIs(owner._http_closed(), False)
        owner.listener = original
        self.assertIs(owner._http_closed(), True)

    def helper_and_receipt_gates(self, cls, owner, row):
        self.assertIs(owner._http_closed(), True)
        for helper in ('_socket_receipt', '_socket_receipt_closed'):
            original = getattr(cls, helper)
            setattr(cls, helper, lambda *args: True)
            try:
                self.assertIs(owner._close_socket(row), False)
                self.assertIs(owner._http_closed(), False)
            finally:
                setattr(cls, helper, original)
            self.assertIs(owner._http_closed(), True)
        methods = owner.socket_receipt_methods
        owner.socket_receipt_methods = tuple(list(methods))
        self.assertIs(owner._close_socket(row), False)
        self.assertIs(owner._http_closed(), False)
        owner.socket_receipt_methods = methods
        receipt = row['socket_close_receipt']
        seal = receipt['sealed']
        receipt['sealed'] = tuple(list(seal))
        self.assertIs(owner._http_closed(), False)
        receipt['sealed'] = seal
        row['failure'] = RuntimeError('fixture')
        self.assertIs(owner._http_closed(), False)
        row['failure'] = None
        self.assertIs(owner._http_closed(), True)

    def same_resource_refusal(self, helpers):
        fake = helpers['FakeSocket']
        cls, namespace = helpers['actual_bodies'](OWNER, 'FixedStateServiceOwner', METHODS,
                                                types.SimpleNamespace(socket=fake))
        # Same inode/type but changed permission/size cannot prove replacement.
        io = helpers['FakeIO'](post=(7, 42, stat.S_IFSOCK | 0o644, 0, 0, 1, 99))
        raw = fake()
        owner = helpers['owner_fixture'](cls, io)
        row = helpers['register'](owner, raw)
        self.assertIs(owner._close_socket(row), False)
        self.assertEqual(row['socket_close_receipt']['post_outcome'], 'same')
        self.assertIsNone(row['socket_close_receipt']['sealed'])
        self.assertIs(row['unknown'], True)
        self.assertEqual(raw.close_count, 1)


if __name__ == '__main__':
    unittest.main()
