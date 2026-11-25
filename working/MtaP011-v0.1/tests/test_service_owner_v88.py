# -*- coding: utf-8 -*-
"""One affected Owner88 method; SOURCE-authored, not agent-executed.

The complete pinned Owner88 definition executes in this HOST test. Boot/Loader,
all 26 module roles, State/init, server/socket/thread, clock and filesystem are
explicit inert models. State78's pinned constructor contract is checked as
SOURCE, not imported or constructed: no real capability helper or FileRegistry
is called. Model authenticate/closure facts are not production authentication
or kernel EBADF evidence. No old TestCase, HTTP70 or Boot83 load method runs.

Ten independent fixtures cover only the new Boot83 role contract and original
service-cap handoff, including the default no-IO entry. The fixture removes
only exact module objects it installed; this is not production rollback.
There is no HTTP listener, service thread, Handoff, Parent, GO/RF, observer,
network receipt, active-worker restoration, phone or admission in this scope.
"""
import errno
import hashlib
import io
import math
from pathlib import Path
import posixpath
import re
import stat
import sys
import types
import unittest
from contextlib import redirect_stdout


ROOT = Path(__file__).resolve().parents[1]
OWNER_SOURCE = (
    'candidate/client-service-owner-v88/runtime/mta_client_service_owner.py',
    27038, '160d507a99ce114e005f6b21b46d1632de391c4cca32080e025a9d675dee36fe')
BOOT_SOURCE = (
    'candidate/go-send-fixed-boot-v83/runtime/mta_client_receive_boot.py',
    18910, '43c095f8bf78cf7fff493f76645a700c67a9c278a423ab531b1954109a6bc1b1')
STATE_SOURCE = (
    'candidate/go-send-state-v78/runtime/mta_service.py',
    84637, 'b7729b6d0272b83a9c2af9e7b3003b97f68bc0fa15038c214ec8e04b7bb41998')
MARKER = (b'HOST88_SERVICE_CAP new_methods=1 old_methods=0 cases=10 '
          b'dependencies_model=true device=false phone=false\n')
CASES = ('same_original_cap', 'legacy_state_keyword', 'schema', 'role_order',
         'go_loader_file', 'module_identity', 'loader_cap_reference',
         'state_original_reference', 'state_saved_reference', 'default_no_io')


def _source(spec):
    path, size, pin = spec
    raw = (ROOT / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('HOST88 fixed SOURCE changed')
    return raw


class _Clock(object):
    def __init__(self): self.value, self.calls = 100.0, 0
    def __call__(self): self.calls += 1; return self.value


class _Lock(object):
    def __enter__(self): return self
    def __exit__(self, *args): return False


class _Event(object):
    def __init__(self): self.value = False
    def is_set(self): return self.value
    def set(self): self.value = True


class _Thread(object):
    """A start ticket only. Never executes its target or creates an actor."""
    def __init__(self, target):
        self.target, self.started, self.joined, self.daemon = target, False, False, False
    def start(self): self.started = True
    def join(self, timeout=None): self.joined = True
    def is_alive(self): return False


class _Platform(object):
    def __init__(self, fixture): self.fixture, self.path = fixture, posixpath
    def __getattr__(self, name):
        self.fixture.platform_calls += 1
        raise AssertionError('HOST88 unexpected platform IO')


class _Factory(object):
    def __call__(self, handoff):
        raise AssertionError('HOST88 must not construct a Handoff or publication')


class _Fs(object):
    """In-memory native asset bytes, descriptors and typed EBADF model."""
    def __init__(self, fixture):
        self.fixture, self.files, self.live = fixture, {}, {}
        self.next_fd, self.calls = 700, []
    def validate(self): self.calls.append('validate')
    def pid(self): self.calls.append('pid'); return 41
    def state_paths(self):
        return ('/model/user', '/model/bluez-helper', '/model/network-helper')
    def add(self, path, raw):
        self.files[path] = (raw, self._metadata(stat.S_IFREG | 0o500, len(raw), len(self.files) + 80))
    @staticmethod
    def _metadata(mode, size, inode):
        return types.SimpleNamespace(st_dev=7, st_ino=inode, st_mode=mode,
                                     st_uid=0, st_gid=0, st_nlink=1, st_size=size)
    def open(self, path):
        self.calls.append('open')
        raw, metadata = self.files[path]
        fd = self.next_fd; self.next_fd += 1
        self.live[fd] = {'raw': raw, 'metadata': metadata, 'offset': 0}
        return fd
    def socket(self):
        fd = self.next_fd; self.next_fd += 1
        self.live[fd] = {'raw': b'', 'metadata': self._metadata(stat.S_IFSOCK | 0o600, 0, fd), 'offset': 0}
        return fd
    def fstat(self, fd):
        self.calls.append('fstat')
        if fd not in self.live: raise OSError(errno.EBADF, 'modeled closed descriptor')
        return self.live[fd]['metadata']
    def stat(self, path): self.calls.append('stat'); return self.files[path][1]
    def read(self, fd, count):
        self.calls.append('read'); row = self.live[fd]
        value = row['raw'][row['offset']:row['offset'] + count]
        row['offset'] += len(value); return value
    def close(self, fd):
        self.calls.append('close')
        if fd not in self.live: raise OSError(errno.EBADF, 'modeled closed descriptor')
        del self.live[fd]
        return None


class _Fixture(object):
    def __init__(self, raw, case):
        self.case, self.platform_calls, self.installed = case, 0, []
        self.worker, self.clock = object(), _Clock()
        self.cap = float('500.125')
        self.factory = _Factory()  # Explicit model, never a FixedReceiveFactory producer.
        self.state_init_calls = self.server_init_calls = self.factory_calls = self.auth_calls = 0
        self.owner_module = types.ModuleType('_host88_owner')
        self.owner_module.__file__ = str(ROOT / OWNER_SOURCE[0])
        exec(compile(raw, self.owner_module.__file__, 'exec'), self.owner_module.__dict__)
        m = self.owner_module
        self.io = _Fs(self)
        self.io.add('/model/bluez-helper', b'HOST model bluez asset')
        self.io.add('/model/network-helper', b'HOST model network asset')
        # Actual _read_asset runs on these explicitly synthetic bytes/metadata.
        m.HELPER_PINS = tuple((len(self.io.files[p][0]), hashlib.sha256(self.io.files[p][0]).hexdigest())
                              for p in self.io.state_paths()[1:])
        m.os = _Platform(self)
        m.time = types.SimpleNamespace(monotonic=self.clock)
        m.threading = types.SimpleNamespace(current_thread=lambda: self.worker, RLock=_Lock, Thread=_Thread)
        fixture = self

        class Socket(object):
            def __init__(self): self.fd, self.timeout = fixture.io.socket(), 0.2
            def fileno(self): return self.fd
            def close(self): return fixture.io.close(self.fd)
            def gettimeout(self): return self.timeout
            def settimeout(self, value): self.timeout = value
            def shutdown(self, how): return None
            def accept(self): raise AssertionError('HOST88 model must not serve HTTP')
            def recv(self, count): raise AssertionError('HOST88 model must not read request bytes')
            def sendall(self, data): raise AssertionError('HOST88 model must not send response bytes')
        m.socket = types.SimpleNamespace(socket=Socket, timeout=TimeoutError, SHUT_RDWR=2)

        class State(object):
            def __init__(self, user, bluez, network, trusted_receive_deployment_factory=None,
                         original_service_until=None):
                fixture.state_init_calls += 1
                self.paths = (user, bluez, network)
                self._trusted_receive_deployment_factory = trusted_receive_deployment_factory
                # SOURCE-checked State78 value contract, modeled initialization.
                if trusted_receive_deployment_factory is not None and not callable(trusted_receive_deployment_factory):
                    raise ValueError('Trusted receive deployment factory required')
                if original_service_until is not None and (type(original_service_until) is not float or
                        not math.isfinite(original_service_until) or not 0 < original_service_until < 2**53):
                    raise ValueError('Original finite service cap required')
                self._original_service_until = self._service_until_original = original_service_until
                if fixture.case == 'state_original_reference':
                    self._original_service_until = float(str(original_service_until))
                elif fixture.case == 'state_saved_reference':
                    self._service_until_original = float(str(original_service_until))
                self.receive_available = self.send_available = False
                self.scan_available = True  # Owner must impose the existing False policy.
                self.wifi_restore_pending = self.radio_restore_pending = False
                self.probe_actors, self.token = [], 'MODEL_TOKEN_NOT_PRINTED'
                for key in ('operation', 'session', 'helper', 'key', 'crypto', 'lease', 'transport', 'worker'):
                    setattr(self, key, None)
            def _probes_closed(self): return type(self.probe_actors) is list and not self.probe_actors
            def _close_probes(self): return None
            def close(self): return True  # MODEL only, not native restoration.

        class LegacyState(object):
            def __init__(self, user, bluez, network, trusted_receive_deployment_factory=None):
                fixture.state_init_calls += 1
                raise AssertionError('HOST88 old State body must not be entered')

        class Server(object):
            def __init__(self, state, port, loopback):
                fixture.server_init_calls += 1
                self.state, self.socket = state, Socket()
                self.stopping, self.workers, self.worker_lock = _Event(), {}, _Lock()
                self.bootstrap_deadline = fixture.clock.value + 30.0
                self.expected_host = '127.0.0.1:0'

        class Handler(object):
            def setup(self): raise AssertionError('HOST88 must not execute HTTP handler')
            def do_GET(self): raise AssertionError('HOST88 must not execute HTTP handler')
            def do_POST(self): raise AssertionError('HOST88 must not execute HTTP handler')

        class HttpServer(object):
            @staticmethod
            def shutdown(server): server.stopping.set(); server.socket.close()
            @staticmethod
            def process(*args): raise AssertionError('HOST88 must not dispatch HTTP')

        self.boot = types.ModuleType('mta_client_receive_boot')
        self.boot.__file__ = m.BOOT_PATH
        self.boot.SOURCE_SCHEMA, self.boot.MODULES = m.BOOT_SCHEMA, m.BOOT_MODULES

        class BootSourceLoader(object):
            def __init__(self):
                self._original_until, self.clock = fixture.cap, fixture.clock
                self.deadline = fixture.clock.value + 10.0  # Not the service cap.
                self.modules = {}
            def authenticate(self): fixture.auth_calls += 1; return self  # MODEL only.
            def create_fixed_factory(self): fixture.factory_calls += 1; return fixture.factory

        self.boot.BootSourceLoader = BootSourceLoader
        self.loader = BootSourceLoader()
        self.install('mta_client_receive_boot', self.boot)
        for name in m.BOOT_MODULES:
            role = types.ModuleType(name)
            prefix = m.GO_ASSET_RUNTIME if name == 'mta_go_deployment' else m.ROOT + '/runtime'
            role.__file__ = prefix + '/' + name + '.py'
            self.loader.modules[name] = role
            self.install(name, role)
        self.loader.modules['mta_service'].State = LegacyState if case == 'legacy_state_keyword' else State
        self.loader.modules['mta_service'].Server = Server
        self.loader.modules['mta_service'].Handler = Handler
        self.loader.modules['minhttp'].HTTPServer = HttpServer
        self.loader.modules['minhttp'].BaseHTTPRequestHandler = Handler
        self.owner = None

    def install(self, name, module, replace=False):
        if name in sys.modules and not replace:
            raise AssertionError('HOST88 foreign namespace would be overwritten')
        if replace and not any(n == name and sys.modules.get(name) is value for n, value in self.installed):
            raise AssertionError('HOST88 can replace only this fixture namespace')
        sys.modules[name] = module
        self.installed.append((name, module))

    def make_owner(self):
        self.owner = self.owner_module.FixedStateServiceOwner(self.loader, self.cap, _io=self.io)
        return self.owner

    def teardown(self):
        # Models own no OS resources. Still exercise original owner close where
        # possible; a partial State remains unknown, never patched into success.
        if self.owner is not None: self.owner.close()
        for name, module in reversed(self.installed):
            if sys.modules.get(name) is module: del sys.modules[name]
        if any(sys.modules.get(name) is module for name, module in self.installed):
            raise AssertionError('HOST88 exact fixture module remained')


class ServiceOwner88Test(unittest.TestCase):
    def test_fixed_boot_roles_and_original_service_cap(self):
        owner_raw, boot_raw, state_raw = (_source(spec) for spec in (OWNER_SOURCE, BOOT_SOURCE, STATE_SOURCE))
        boot_text = boot_raw.decode('utf-8').replace('\r\n', '\n')
        state_text = state_raw.decode('utf-8').replace('\r\n', '\n')
        # These are pinned SOURCE contract checks, not execution of State78 or
        # Boot83. All future test execution below uses only actual Owner88.
        self.assertIn('trusted_receive_deployment_factory=None,original_service_until=None):', state_text)
        self.assertIn('trusted_receive_deployment_factory is not None and not callable(trusted_receive_deployment_factory)', state_text)
        self.assertIn('type(original_service_until) is not float', state_text)
        self.assertIn('not math.isfinite(original_service_until) or not 0<original_service_until<2**53', state_text)
        self.assertIn('self._original_service_until=self._service_until_original=original_service_until', state_text)
        pin_rows = boot_text.split('SOURCE_PINS = (\n', 1)[1].split('\n)\n', 1)[0]
        role_names = tuple(re.findall(r"^    \('([^']+)',", pin_rows, re.M))
        self.assertEqual(len(role_names), 26)
        self.assertIn("SOURCE_SCHEMA = 'sender-state-boot-v83-source'", boot_text)
        self.assertIn("GO_ASSET_ROOT = '/var/volatile/tmp/p011-mta-go-send-v76-assets'", boot_text)
        completed = 0
        for case in CASES:
            with self.subTest(case=case):
                fixture = _Fixture(owner_raw, case)
                try:
                    m = fixture.owner_module
                    self.assertEqual(m.BOOT_PIN, BOOT_SOURCE[1:])
                    self.assertEqual(m.BOOT_MODULES, role_names)
                    self.assertIs(fixture.loader._original_until, fixture.cap)
                    if case == 'default_no_io':
                        output = io.StringIO()
                        with redirect_stdout(output): self.assertEqual(m.main([]), 0)
                        self.assertEqual(output.getvalue(), 'SOURCE88_SERVICE definitions=false state=false service=false rf=false\n')
                        self.assertIsNone(m._MAIN)
                        self.assertEqual((fixture.auth_calls, fixture.factory_calls, fixture.state_init_calls,
                                          fixture.server_init_calls, fixture.clock.calls), (0, 0, 0, 0, 0))
                        self.assertEqual(fixture.io.calls, [])
                    else:
                        owner = fixture.make_owner()
                        self.assertIs(owner.original_until, fixture.cap)
                        self.assertIs(owner.until, fixture.cap)
                        if case == 'schema': fixture.boot.SOURCE_SCHEMA = 'unsealed-model-schema'
                        elif case == 'role_order': fixture.boot.MODULES = tuple(reversed(m.BOOT_MODULES))
                        elif case == 'go_loader_file':
                            fixture.loader.modules['mta_go_deployment'].__file__ = m.ROOT + '/runtime/mta_go_deployment.py'
                        elif case == 'module_identity': fixture.install('mta_service', types.ModuleType('mta_service'), True)
                        elif case == 'loader_cap_reference':
                            fixture.loader._original_until = float(str(fixture.cap))
                            self.assertEqual(fixture.loader._original_until, fixture.cap)
                            self.assertIsNot(fixture.loader._original_until, fixture.cap)
                        if case == 'same_original_cap':
                            self.assertIs(owner.start(), owner)
                            self.assertIs(owner.state._original_service_until, fixture.cap)
                            self.assertIs(owner.state._service_until_original, fixture.cap)
                            self.assertGreater(owner.until, fixture.loader.deadline)
                            self.assertIs(owner.state._trusted_receive_deployment_factory, fixture.factory)
                            self.assertEqual((fixture.auth_calls, fixture.factory_calls, fixture.state_init_calls,
                                              fixture.server_init_calls), (1, 1, 1, 1))
                            self.assertIs(owner.state.receive_available, False)
                            self.assertIs(owner.state.send_available, False)
                            self.assertIs(owner.state.scan_available, False)
                            self.assertEqual(owner.server.bootstrap_deadline, fixture.clock.value + 30.0)
                            self.assertTrue(owner.start_complete)
                            self.assertEqual(len(owner.threads), 1)
                            self.assertTrue(owner.threads[0]['called'])
                            self.assertEqual(owner.requests, [])
                        elif case == 'legacy_state_keyword':
                            with self.assertRaises(TypeError) as caught: owner.start()
                            self.assertIs(owner.failure, caught.exception)
                            self.assertIsNotNone(owner.state)
                            self.assertTrue(owner.state_called)
                            self.assertFalse(owner.state_complete)
                            self.assertIsNone(owner.server)
                            self.assertEqual(fixture.state_init_calls, 0)
                        else:
                            code = ('owner_changed' if case == 'loader_cap_reference' else
                                    'state_start_pending' if case.startswith('state_') else 'boot_roles_changed')
                            with self.assertRaises(m.ServiceOwnerError) as caught: owner.start()
                            self.assertEqual(caught.exception.code, code)
                            self.assertIs(owner.failure, caught.exception)
                            self.assertFalse(owner.start_complete)
                            self.assertIsNone(owner.server)
                            if case.startswith('state_'):
                                self.assertTrue(owner.state_complete)
                                self.assertEqual(fixture.state_init_calls, 1)
                                changed = (owner.state._original_service_until if case == 'state_original_reference'
                                           else owner.state._service_until_original)
                                self.assertEqual(changed, fixture.cap)
                                self.assertIsNot(changed, fixture.cap)
                            else:
                                self.assertFalse(owner.factory_called)
                                self.assertEqual(fixture.state_init_calls, 0)
                        status = owner.status()
                        self.assertEqual(status['kind'], 'fixed-state-service-owner-v88')
                        for field in ('receive_available', 'send_available', 'scan_available', 'native_restored', 'phone_tested'):
                            self.assertIs(status[field], False)
                    self.assertEqual(fixture.platform_calls, 0)
                    completed += 1
                finally:
                    fixture.teardown()
                self.assertEqual(fixture.platform_calls, 0)
        self.assertEqual(completed, 10)
        sys.stdout.buffer.write(MARKER)


if __name__ == '__main__':
    unittest.main()
