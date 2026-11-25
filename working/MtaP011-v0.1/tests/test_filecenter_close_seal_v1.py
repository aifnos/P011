"""One Linux primitive contract: old FD reuse refusal and new close seals.

Prepared for ROOT's sole, explicit Linux/WSL single-method execution. This
file is not a P011/firmware/ABI, full Owner/graph, guardian, UI or RF test.
It loads only the fixed FileCenter nine-source definitions, uses real
loopback listening sockets/threads and Linux directory FDs, but sends NO
HTTP requests and launches NO audio, subprocess, radio or old test suite.

The Owner fixture compiles only three actual affected method bodies. Its
known-definition precondition and temporary USER_ROOT are labelled fixture
seams, not production admission or original directory authentication.
No fstat result is mocked. Faults intercept a real close or semaphore
constructor only and cannot fabricate a closed resource or device grant.
"""
import ast
from contextlib import contextmanager
import errno
import hashlib
import math
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
METHODS = ('_filecenter_current', '_filecenter_closed', '_close_filecenter')
OLD_OWNER = ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_client_service_owner.py',
             89599, 'a9a5aa60d4cf5c26df46d6de88a9c79fb1df76eb88ff869f186fcf277ea7af11')
OLD_STORAGE = ('candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py',
               4581, '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169')
OLD_COMPANION = ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_companion.py',
                 25966, '51f212ef07e0e323cc3803cfd2583ec29867ce0bbf7daff9129ad51d4f6eeeb3')
# Independently frozen, not-yet-packaged three-source primitive candidate.
NEW_OWNER = ('candidate/filecenter-close-seal-v1/runtime/mta_client_service_owner.py',
             90745, '9341ffdf01bd9927384ad78a9c824b3f7c42a29ffdbe19858b9bbba14c1826f8')
NEW_STORAGE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py',
               10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4')
NEW_COMPANION = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py',
                 33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284')


def fixed(pin):
    if type(pin[1]) is not int or type(pin[2]) is not str:
        raise AssertionError('isolated_source_freeze_pending')
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise AssertionError('exact_contract_source_pin')
    return raw


def literal(tree, name):
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name
                    for target in node.targets)]
    if len(rows) != 1:
        raise AssertionError('single_actual_literal')
    return ast.literal_eval(rows[0])


def actual_owner(raw, filename, temporary_root):
    tree = ast.parse(raw, filename=filename)
    cls = next(row for row in tree.body if isinstance(row, ast.ClassDef)
               and row.name == 'FixedStateServiceOwner')
    selected = [row for row in cls.body if isinstance(row, ast.FunctionDef)
                and row.name in METHODS]
    if {row.name for row in selected} != set(METHODS):
        raise AssertionError('actual_three_method_scope')
    cls.body = selected
    helper_names = {'ServiceOwnerError', '_fail', '_meta'}
    helpers = [row for row in tree.body if isinstance(row, (ast.ClassDef, ast.FunctionDef))
               and row.name in helper_names]
    if {row.name for row in helpers} != helper_names:
        raise AssertionError('actual_owner_helper_scope')
    namespace = dict(os=os, errno=errno, math=math, socket=socket, stat=stat,
                     sys=sys, threading=threading, types=types,
                     USER_ROOT=temporary_root)
    selected_tree = ast.Module(body=helpers + [cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(selected_tree), filename, 'exec'), namespace)
    return namespace['FixedStateServiceOwner'], namespace


@contextmanager
def family(sealed):
    owner_pin = NEW_OWNER if sealed else OLD_OWNER
    storage_pin = NEW_STORAGE if sealed else OLD_STORAGE
    companion_pin = NEW_COMPANION if sealed else OLD_COMPANION
    owner_raw = fixed(owner_pin)
    pins = literal(ast.parse(owner_raw), 'FILECENTER_PINS')
    names = tuple(row[0] for row in pins)
    expected = ('mta_toolbox_json', 'mta_toolbox_minhttp', 'mta_toolbox_storage',
                'mta_toolbox_metrics', 'mta_toolbox_audio', 'mta_toolbox_server',
                'mta_filecenter_audio', 'mta_filecenter_storage', 'mta_filecenter_companion')
    if names != expected:
        raise AssertionError('actual_filecenter_nine_definition_order')
    old_values = {name: sys.modules.get(name) for name in names}
    old_presence = {name: name in sys.modules for name in names}
    modules = {}
    try:
        for name, size, digest in pins:
            if name == 'mta_filecenter_storage':
                pin = storage_pin
            elif name == 'mta_filecenter_companion':
                pin = companion_pin
            elif name == 'mta_filecenter_audio':
                pin = ('candidate/filecenter-deadline-v2/runtime/' + name + '.py', size, digest)
            else:
                pin = ('integration/ToolboxMta-v0.1/runtime/' + name + '.py', size, digest)
            raw = fixed(pin)
            # The new three-source patch is deliberately not packaged into
            # Owner.FILECENTER_PINS yet. Only these two actual isolated input
            # files use their independently frozen override pins. This cannot
            # grant production create_filecenter()/nine-source admission.
            isolated_override = sealed and name in ('mta_filecenter_storage', 'mta_filecenter_companion')
            if not isolated_override and (len(raw), hashlib.sha256(raw).hexdigest()) != (size, digest):
                raise AssertionError('owner_filecenter_pin_binding')
            module = types.ModuleType(name)
            module.__file__ = str(BASE / pin[0])
            sys.modules[name] = module
            modules[name] = module
            # Names are their real module names, never __main__: no server CLI.
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        yield modules, owner_pin, owner_raw
    finally:
        for name in names:
            if old_presence[name]:
                sys.modules[name] = old_values[name]
            else:
                sys.modules.pop(name, None)


def metadata(fd):
    value = os.fstat(fd)
    return tuple(getattr(value, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))


def bind_owner(owner_raw, filename, value, modules):
    cls, namespace = actual_owner(owner_raw, filename, value.root)
    owner = cls.__new__(cls)
    owner.worker = value.worker
    owner.original_until = value.until
    owner._cleanup_until_original = float(time.monotonic() + 2.0)
    # Only this unrelated provenance precondition is a HOST fixture seam.
    owner._filecenter_definitions_current = lambda: True
    owner._filecenter_partial_current = lambda: False
    value.owner = owner
    store, listener = value.state.store, value.server.socket
    ticket = dict(original=value, cls=type(value), create_returned=True,
                  failure=None, close_failure=None, close_called=False, close_return=None,
                  state=value.state, server=value.server, thread=value.thread,
                  media=value.media, audio=value.audio, audio_tickets=value.audio.tickets,
                  store=store, store_fd=store.rootfd, store_metadata=metadata(store.rootfd),
                  socket=listener, socket_fd=listener.fileno(), socket_metadata=metadata(listener.fileno()),
                  store_close_original=getattr(store, '_root_close_original', None),
                  listener_close_original=getattr(value.server, '_listener_close_original', None),
                  module=modules['mta_filecenter_companion'],
                  modules=[dict(module=modules[name]) for name in (
                      'mta_toolbox_json', 'mta_toolbox_minhttp', 'mta_toolbox_storage',
                      'mta_toolbox_metrics', 'mta_toolbox_audio', 'mta_toolbox_server',
                      'mta_filecenter_audio', 'mta_filecenter_storage', 'mta_filecenter_companion')],
                  methods={'close': type(value).close, 'closed': type(value).closed})
    # Same retained objects/integers as original create_filecenter, not copies
    # pretending to represent its full original nine-source admission ticket.
    owner.filecenter_ticket = owner._filecenter_ticket_original = ticket
    return owner, ticket, namespace


def free_fixture_duplicate(fd, expected):
    try:
        actual = metadata(fd)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise
    if actual != expected:
        raise AssertionError('fixture_refuses_foreign_numeric_slot_close')
    os.close(fd)


class FileCenterCloseSealV1Contract(unittest.TestCase):
    def test_actual_filecenter_original_close_seals_and_numeric_reuse(self):
        if not sys.platform.startswith('linux'):
            self.skipTest('ROOT Linux/WSL native directory FD and dup2 contract only')
        cases = []
        for sealed in (False, True):
            with family(sealed) as (modules, owner_pin, owner_raw):
                companion = modules['mta_filecenter_companion']
                for resource in ('directory', 'listener'):
                    with self.subTest(sealed=sealed, resource=resource), \
                            tempfile.TemporaryDirectory(prefix='p011-fc-seal-native-') as temporary:
                        value = companion._Companion(temporary, float(time.monotonic() + 20), lambda: True)
                        owner, ticket, namespace = bind_owner(owner_raw, owner_pin[0], value, modules)
                        target = ticket['store_fd'] if resource == 'directory' else ticket['socket_fd']
                        duplicated = False
                        with tempfile.TemporaryFile() as sentinel:
                            payload = b'HOST native sentinel: never a product resource\n'
                            sentinel.write(payload); sentinel.flush()
                            expected = metadata(sentinel.fileno())
                            try:
                                self.assertTrue(value.state.store.fd_mode)
                                self.assertTrue(stat.S_ISDIR(ticket['store_metadata'][2]))
                                self.assertTrue(stat.S_ISSOCK(ticket['socket_metadata'][2]))
                                self.assertNotEqual(target, sentinel.fileno())
                                if sealed:
                                    self.assertIs(value.state.store.root_closed(), False)
                                    self.assertIs(value.server.listener_closed(), False)
                                self.assertIs(owner._filecenter_current(), True)
                                self.assertIs(owner._close_filecenter(), True)
                                self.assertIs(value.close_complete, True)
                                self.assertIs(value.closed(), True)
                                self.assertIsNone(value.state.store.rootfd)
                                self.assertEqual(value.socket_original.fileno(), -1)
                                self.assertFalse(value.thread.is_alive())
                                self.assertTrue(value.server.actors_closed())
                                self.assertTrue(value.audio.actors_closed())
                                if sealed:
                                    self.assertIs(value.state.store.root_closed(), True)
                                    self.assertIs(value.server.listener_closed(), True)
                                    self.assertIs(value.state.store.root_close_seal,
                                                  value.state.store._root_close_seal_retained)
                                    self.assertIs(value.server.listener_close_seal,
                                                  value.server._listener_close_seal_retained)
                                with self.assertRaises(OSError) as absent:
                                    os.fstat(target)
                                self.assertEqual(absent.exception.errno, errno.EBADF)
                                os.dup2(sentinel.fileno(), target)
                                duplicated = True
                                self.assertEqual(metadata(target), expected)
                                self.assertEqual(os.pread(target, len(payload), 0), payload)
                                expected_companion = sealed or resource == 'listener'
                                self.assertIs(value.closed(), expected_companion)
                                self.assertIs(owner._filecenter_current(), sealed)
                                self.assertIs(owner._filecenter_closed(), sealed)
                                if sealed:
                                    self.assertIs(value.state.store.root_closed(), True)
                                    self.assertIs(value.server.listener_closed(), True)
                                # Retry uses original close paths, not a fake receipt.
                                self.assertIs(owner._close_filecenter(), sealed)
                                self.assertIs(value.close(), True)
                                self.assertEqual(metadata(target), expected)
                                self.assertEqual(os.pread(target, len(payload), 0), payload)
                                self.assertIsNone(value.state.store.rootfd)
                                self.assertEqual(value.socket_original.fileno(), -1)
                                free_fixture_duplicate(target, expected); duplicated = False
                                self.assertIs(value.closed(), True)
                                self.assertIs(owner._filecenter_closed(), True)
                                cases.append(('sealed' if sealed else 'old', resource))
                            finally:
                                if duplicated:
                                    free_fixture_duplicate(target, expected)
                                if not value.close_called:
                                    value.close(cleanup_until=float(time.monotonic() + 2.0))

        # Real original root-close error: distinguish unconsumed and consumed
        # uncertain outcomes. fstat is always the native Linux observation.
        with family(True) as (modules, owner_pin, owner_raw):
            companion = modules['mta_filecenter_companion']
            for consumed in (False, True):
                with self.subTest(close_error_consumed=consumed), \
                        tempfile.TemporaryDirectory(prefix='p011-fc-seal-error-') as temporary:
                    value = companion._Companion(temporary, float(time.monotonic() + 20), lambda: True)
                    owner, ticket, namespace = bind_owner(owner_raw, owner_pin[0], value, modules)
                    target = ticket['store_fd']
                    original_close = os.close
                    marker = OSError(errno.EIO, 'HOST actual close fault')
                    calls = []
                    duplicated = False
                    def failed_original_close(fd):
                        if fd == target:
                            calls.append(fd)
                            if consumed:
                                original_close(fd)
                            raise marker
                        return original_close(fd)
                    with tempfile.TemporaryFile() as sentinel:
                        payload = b'HOST close-error sentinel'
                        sentinel.write(payload); sentinel.flush()
                        expected = metadata(sentinel.fileno())
                        try:
                            with mock.patch.object(os, 'close', side_effect=failed_original_close):
                                self.assertIs(owner._close_filecenter(), False)
                            self.assertEqual(calls, [target])
                            self.assertIn(marker, value.cleanup_failures)
                            self.assertIs(value.close_complete, False)
                            self.assertIs(value.closed(), False)
                            self.assertIs(owner._filecenter_closed(), False)
                            self.assertIs(value.state.store.root_close_error, marker)
                            self.assertIsNone(value.state.store.root_close_seal)
                            self.assertIs(value.state.store.root_closed(), False)
                            self.assertIs(value.server.listener_closed(), True)
                            self.assertFalse(value.thread.is_alive())
                            self.assertEqual(value.socket_original.fileno(), -1)
                            if not consumed:
                                self.assertEqual(metadata(target)[:5], ticket['store_metadata'][:5])
                                original_close(target)  # Only HOST's retained original.
                            with self.assertRaises(OSError) as absent:
                                os.fstat(target)
                            self.assertEqual(absent.exception.errno, errno.EBADF)
                            os.dup2(sentinel.fileno(), target); duplicated = True
                            self.assertIs(owner._close_filecenter(), False)
                            self.assertIs(value.close(), False)
                            self.assertIs(value.closed(), False)
                            self.assertEqual(metadata(target), expected)
                            self.assertEqual(os.pread(target, len(payload), 0), payload)
                            free_fixture_duplicate(target, expected); duplicated = False
                            cases.append(('close_error', consumed))
                        finally:
                            if duplicated:
                                free_fixture_duplicate(target, expected)
                            if not value.close_called:
                                value.close(cleanup_until=float(time.monotonic() + 2.0))
                            # A failed product close cannot authorize a retry of
                            # an uncertain number. Fixture closes only the exact
                            # still-live directory if its original metadata holds.
                            try:
                                current = metadata(target)
                            except OSError as error:
                                if error.errno != errno.EBADF: raise
                            else:
                                if current[:5] != ticket['store_metadata'][:5]:
                                    raise AssertionError('fixture_refuses_unknown_root_cleanup')
                                original_close(target)

            # Actual partial server construction, no fake State/server flags.
            with tempfile.TemporaryDirectory(prefix='p011-fc-seal-partial-') as temporary:
                value = companion._Companion.__new__(companion._Companion)
                marker = RuntimeError('HOST actual semaphore constructor fault')
                with mock.patch.object(threading, 'BoundedSemaphore', side_effect=marker):
                    with self.assertRaises(RuntimeError) as failure:
                        companion._Companion.__init__(value, temporary,
                                                     float(time.monotonic() + 20), lambda: True)
                self.assertIs(failure.exception, marker)
                self.assertIs(value.failure, marker)
                self.assertFalse(value.server_complete)
                listener = value.server.socket
                listener_fd = listener.fileno()
                root_fd = value.state.store.rootfd
                listener_meta, root_meta = metadata(listener_fd), metadata(root_fd)
                self.assertGreaterEqual(listener.fileno(), 0)
                try:
                    self.assertIs(value.close(cleanup_until=float(time.monotonic() + 2.0)), False)
                    self.assertEqual(listener.fileno(), -1)
                    self.assertIsNone(value.state.store.rootfd)
                    for fd in (listener_fd, root_fd):
                        with self.assertRaises(OSError) as absent:
                            os.fstat(fd)
                        self.assertEqual(absent.exception.errno, errno.EBADF)
                    self.assertIs(value.closed(), False)
                    self.assertIs(value.close(), False)
                    self.assertIs(value.failure, marker)
                    cases.append(('partial', 'known originals closed; no complete grant'))
                finally:
                    # Fixture-only cleanup after an assertion failure; the
                    # partial product still never receives a complete grant.
                    if not value.close_called:
                        value.close(cleanup_until=float(time.monotonic() + 2.0))
                    if listener.fileno() >= 0:
                        if metadata(listener.fileno()) != listener_meta:
                            raise AssertionError('fixture_refuses_foreign_partial_listener')
                        listener.close()
                    try:
                        current = metadata(root_fd)
                    except OSError as error:
                        if error.errno != errno.EBADF: raise
                    else:
                        if current[:5] != root_meta[:5]:
                            raise AssertionError('fixture_refuses_unknown_partial_root')
                        os.close(root_fd)

        self.assertEqual(len(cases), 7)
        print('HOST_LINUX_FILECENTER_CLOSE_SEAL_CONTRACTS=7')


if __name__ == '__main__':
    unittest.main()
