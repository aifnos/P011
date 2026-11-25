# -*- coding: utf-8 -*-
"""One remaining owner70 method; SOURCE-authored, not agent-executed.

The definitions boot's root/ARM/FD values below are explicit HOST models.
Nine independent fixtures use actual State32 and actual 127.0.0.1 HTTP sockets;
capability subprocesses and fixed user/helper paths are private HOST seams,
not P011 radio observations. No Handoff, Parent, publication or receive/send
admission is constructed. No old TestCase, helper or method is loaded.

The original HOST70 method remains whole FAIL: its normal_http fixture
completed, but the following nine stopped in Boot.load before owner business
because the HOST teardown omitted minhttp. This r2 runs only those nine;
normal_http is not replayed and the original overall result is not upgraded.
"""
import builtins
import errno
import hashlib
import io
import json
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


ROOT = Path(__file__).resolve().parents[1]
BOOT_PATH = 'candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_boot.py'
BOOT_BYTES = 17973
BOOT_SHA = '1c3d05c3bf588aa2b6438e6d940fd5e36e467860c1b183305566a18ed69695aa'
SPECIAL = {
    'mta_client_executor': 'candidate/client-integrated-v37/runtime/mta_client_executor.py',
    'mta_client_control_frame': 'candidate/client-integrated-v37/runtime/mta_client_control_frame.py',
    'mta_client_connect_handoff': 'candidate/client-connect-v13/runtime/mta_client_connect_handoff.py',
    'mta_client_tmp_alias': 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py',
    'mta_service': 'candidate/client-state-integration-v32/runtime/mta_service.py',
    'mta_client_receive_factory': 'candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_factory.py',
    'mta_client_state_bridge': 'candidate/client-receive-factory-v69/runtime/mta_client_state_bridge.py',
}
ASSETS = (
    ('out/native/mta-bluez-helper', 65832,
     '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('out/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
)
OWNER_PATH = 'candidate/client-service-owner-v70/runtime/mta_client_service_owner.py'
OWNER_BYTES = 24962
OWNER_SHA = 'f70046e538db7427dd0af374067f684eb41bafb2f70999a2c3deaf87e8705466'
MARKER = ('HOST70_R2_SERVICE_OWNER new_methods=1 old_methods=0 boot_model=true '
          'loopback=true device=false phone=false')
# Only ROOT performs the first fixed-snapshot execution after SOURCE review.


def _raw(path, expected_size, expected_sha):
    data = (ROOT / path).read_bytes()
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha:
        raise AssertionError('HOST70 frozen SOURCE changed')
    return data


class _ReadOnlyBootFs(object):
    """New in-memory fixed boot FS model, not an old test fixture import."""
    def __init__(self, sources):
        self.nodes, self.live, self.history, self.close_counts = {}, {}, [], {}
        self.next_fd = 901
        self.next_ino = 61
        dirs = (('/', 0o755), ('/var', 0o755),
                ('/var/volatile', 0o1777), ('/var/volatile/tmp', 0o1777),
                ('/var/volatile/tmp/p011-mta-state-v69', 0o700),
                ('/var/volatile/tmp/p011-mta-state-v69/runtime', 0o700))
        for path, mode in dirs:
            self._node(path, stat.S_IFDIR | mode)
        self._node('/tmp', stat.S_IFLNK | 0o777, target='/var/tmp')
        self._node('/var/tmp', stat.S_IFLNK | 0o777, target='/var/volatile/tmp')
        for name, data in sources:
            self._node('/var/volatile/tmp/p011-mta-state-v69/runtime/' + name + '.py',
                       stat.S_IFREG | 0o400, data)

    def _node(self, path, mode, data=b'', target=None):
        self.next_ino += 1
        self.nodes[path] = (self.next_ino, mode, data, target)

    def _physical(self, path):
        if path.startswith('/tmp/p011-mta-state-v69'):
            return '/var/volatile/tmp' + path[4:]
        return path

    def validate(self):
        # Explicit modeled ARM/root admission, not the native LinuxIo syscall.
        return None

    def pid(self):
        return os.getpid()

    def stat(self, path):
        value = self.nodes.get(self._physical(path))
        if value is None:
            raise OSError(errno.ENOENT, 'HOST70 absent modeled boot path')
        ino, mode, data, target = value
        size = len(target) if target is not None else len(data)
        return types.SimpleNamespace(st_dev=19, st_ino=ino, st_mode=mode,
            st_uid=0, st_gid=0, st_nlink=1, st_size=size,
            st_mtime_ns=7, st_ctime_ns=11)

    def readlink(self, path):
        value = self.nodes.get(path)
        if value is None or value[3] is None:
            raise OSError(errno.EINVAL, 'HOST70 not modeled link')
        return value[3]

    def open(self, path):
        physical = self._physical(path)
        self.stat(physical)
        self.next_fd += 1
        fd = self.next_fd
        self.live[fd] = [physical, 0]
        self.history.append(fd)
        return fd

    def fstat(self, fd):
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST70 modeled boot descriptor closed')
        return self.stat(self.live[fd][0])

    def read(self, fd, count):
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST70 modeled boot descriptor closed')
        path, offset = self.live[fd]
        data = self.nodes[path][2][offset:offset + count]
        self.live[fd][1] += len(data)
        return data

    def close(self, fd):
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST70 modeled boot descriptor closed')
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        del self.live[fd]
        return None


def _http(port, path='/v1/status', token=None, body=None, origin=None):
    """Actual HOST TCP/HTTP bytes; neither a mocked handler nor a radio path."""
    headers = ['%s %s HTTP/1.1' % ('GET' if body is None else 'POST', path),
               'Host: 127.0.0.1:%d' % port]
    if token is not None:
        headers.append('X-P011-MTA-Token: ' + token)
    if origin is not None:
        headers.append('Origin: ' + origin)
    if body is not None:
        headers.extend(['Content-Type: application/json',
                        'Content-Length: ' + str(len(body))])
    wire = ('\r\n'.join(headers) + '\r\n\r\n').encode('ascii') + (body or b'')
    chunks = []
    with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
        raw.sendall(wire)
        while True:
            block = raw.recv(65536)
            if not block:
                break
            chunks.append(block)
    reply = b''.join(chunks)
    head, separator, value = reply.partition(b'\r\n\r\n')
    if not separator:
        raise AssertionError('HOST70 response missing headers')
    code = int(head.split(b'\r\n', 1)[0].split(b' ')[1])
    lengths = [line.split(b':', 1)[1].strip() for line in head.split(b'\r\n')[1:]
               if line.lower().startswith(b'content-length:')]
    if len(lengths) != 1 or int(lengths[0]) != len(value):
        raise AssertionError('HOST70 response framing changed')
    return code, value


class _CapabilityProcessFixture(object):
    """Modeled read-only capabilities process; not a native helper execution."""
    def __init__(self, output):
        self.stdout, self.stderr = io.BytesIO(output), io.BytesIO(b'')
        self.returncode = None
        self.output = output
        self.communications = 0

    def communicate(self, timeout=None):
        if timeout not in (12, 3):
            raise AssertionError('HOST70 unbounded capabilities fixture')
        self.communications += 1
        self.returncode = 0
        self.stdout.close()
        self.stderr.close()
        return self.output, b''

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = 0


class _CapabilitySubprocessFixture(object):
    def __init__(self, bluez, network, unknown=False):
        self.bluez, self.network, self.unknown = bluez, network, unknown
        self.calls, self.processes = [], []

    def Popen(self, args, **options):
        if args not in ([self.bluez, '--capabilities', 'hci0'],
                        [self.network, '--capabilities']):
            raise AssertionError('HOST70 no radio/mutation/helper/Parent command')
        self.calls.append(tuple(args))
        if self.unknown:
            raise OSError(errno.EIO, 'HOST70 modeled capability spawn unknown')
        value = _CapabilityProcessFixture(b'{"powered":false,"discovering":false}\n')
        self.processes.append(value)
        return value

    def __getattr__(self, name):
        # PIPE/TimeoutExpired constants are actual stdlib data, not mutation.
        import subprocess
        return getattr(subprocess, name)


class _BootDomain(object):
    """Actual definitions loader, distinct canonical domain for each fixture.

    SOURCE bytes come from the actual fixed Boot's 22 SOURCE_PINS, not old
    helper code or an additional unrecorded manifest input.
    Every boot file descriptor is modeled and has original once-close/EBADF
    observations. Service sockets later are actual unrelated HOST descriptors.
    """
    def __init__(self, seconds=90.0):
        occupied = [name for name in sys.modules
                    if name == 'minhttp' or name.startswith(('mta_', 'p011_'))]
        if occupied:
            raise AssertionError('HOST70 unexpected pre-existing target domain')
        raw_boot = _raw(BOOT_PATH, BOOT_BYTES, BOOT_SHA)
        self.boot = types.ModuleType('mta_client_receive_boot')
        self.boot.__file__ = '/HOST70/private-model/mta_client_receive_boot.py'
        sys.modules[self.boot.__name__] = self.boot
        self.loader, self.owner_module = None, None
        self.module_names = ()
        try:
            exec(compile(raw_boot, self.boot.__file__, 'exec'), self.boot.__dict__)
            pins = self.boot.SOURCE_PINS
            if type(pins) is not tuple or len(pins) != 22:
                raise AssertionError('HOST70 fixed graph shape changed')
            self.module_names = self.boot.MODULES
            if self.module_names != tuple(row[0] for row in pins) or 'minhttp' not in self.module_names:
                raise AssertionError('HOST70 exact fixed domain shape changed')
            sources = []
            for name, size, digest in pins:
                sources.append((name, _raw(SPECIAL.get(name, 'runtime/' + name + '.py'),
                                           size, digest)))
            if len({name for name, raw in sources}) != 22:
                raise AssertionError('HOST70 fixed graph duplicates changed')
            self.io = _ReadOnlyBootFs(sources)
            self.until = time.monotonic() + seconds
            self.loader = self.boot.BootSourceLoader(self.until, _io=self.io,
                                                    _clock=time.monotonic)
            self.loader.load()
            self.deadline = self.loader.deadline
        except BaseException:
            self.teardown()
            raise

    def teardown(self):
        # Fixture-only teardown of retained ORIGINAL module references, not a
        # prefix-based namespace sweep. Production Boot's busy-namespace gate
        # and its partial-publication retention remain unchanged. A replaced
        # foreign module is preserved and causes this fixture to fail.
        originals = []
        if self.loader is not None:
            for name in self.module_names:
                if name in self.loader.modules:
                    original = self.loader.modules[name]
                    if not any(row[0] == name and row[1] is original and
                               row[2] is original.__dict__ for row in self.loader.module_originals):
                        raise AssertionError('HOST70 module original not retained')
                    originals.append((name, original))
        if self.owner_module is not None:
            originals.append(('mta_client_service_owner', self.owner_module))
        originals.append(('mta_client_receive_boot', self.boot))
        foreign = []
        for name, original in reversed(originals):
            current = sys.modules.get(name)
            if current is original:
                del sys.modules[name]
            elif current is not None:
                foreign.append(name)
        # Explicit readback includes minhttp and the exact Boot/Owner entries.
        expected_absent = self.module_names + ('mta_client_receive_boot', 'mta_client_service_owner')
        if foreign or any(name in sys.modules for name in expected_absent):
            raise AssertionError('HOST70 foreign or retained domain after teardown')

    def boot_closed(self, testcase):
        testcase.assertEqual(self.io.live, {})
        testcase.assertEqual(len(self.io.history), 22)
        testcase.assertEqual(len(self.io.close_counts), 22)
        testcase.assertTrue(all(count == 1 for count in self.io.close_counts.values()))
        testcase.assertIs(self.loader.deadline, self.deadline)
        testcase.assertEqual(self.loader.until, self.until)
        testcase.assertIs(self.loader.pending, False)
        testcase.assertIs(self.loader.failure, None)
        testcase.assertEqual(len(self.loader.modules), 22)
        for row in self.loader.rows:
            testcase.assertIs(row['closed'], True)
            testcase.assertIs(row['unknown'], False)
            with testcase.assertRaises(OSError) as caught:
                self.io.fstat(row['fd'])
            testcase.assertEqual(caught.exception.errno, errno.EBADF)


class _PrivatePreflightIo(object):
    """Real private HOST file bytes/FDs, with explicit modeled Linux metadata.

    The user root is an actual tempfile subdirectory. Helper bytes are the
    exact fixed PC artifacts, but their ELF/owner/0500 shape is a preflight
    fixture, not device installation or helper execution. Windows file FD
    identity/size and close/EBADF are actual; uid/gid/mode are declared modeled.
    """
    def __init__(self, root):
        self.user = str(root / 'user')
        self.bluez = str(root / 'native' / 'mta-bluez-helper')
        self.network = str(root / 'native' / 'mta-network-helper')
        (root / 'user').mkdir()
        (root / 'native').mkdir()
        for entry, destination in zip(ASSETS, (self.bluez, self.network)):
            (Path(destination)).write_bytes(_raw(*entry))
        self.paths = {self.bluez, self.network}
        self.live, self.open_counts, self.close_counts = {}, {}, {}
        self.owner = None
        self.socket_rows = []

    def validate(self):
        return None  # modeled root/ARM only; never the production ABI syscall.

    def pid(self):
        return os.getpid()

    def state_paths(self):
        return self.user, self.bluez, self.network

    def _metadata(self, value):
        return types.SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino,
            st_mode=stat.S_IFREG | 0o500, st_uid=0, st_gid=0, st_nlink=1,
            st_size=value.st_size)

    def stat(self, path):
        if path not in self.paths:
            raise AssertionError('HOST70 preflight outside private helper paths')
        return self._metadata(os.stat(path, follow_symlinks=False))

    def open(self, path):
        if path not in self.paths:
            raise AssertionError('HOST70 preflight outside private helper paths')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        self.live[fd] = path
        self.open_counts[fd] = self.open_counts.get(fd, 0) + 1
        return fd

    def fstat(self, fd):
        if fd in self.live:
            # Actual os.fstat for real HOST file-descriptor identity/existence.
            return self._metadata(os.fstat(fd))
        for row in self.socket_rows:
            if row['fd'] == fd and row['socket'].fileno() == fd:
                return row['metadata']
        if self.owner is not None:
            possible = [row.get('socket') for row in self.owner.requests]
            if self.owner.server is not None:
                possible.append(getattr(self.owner.server, 'socket', None))
            for raw in possible:
                if type(raw) is socket.socket and raw.fileno() == fd:
                    if type(raw.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)) is not int:
                        raise AssertionError('HOST70 socket native readback changed')
                    # Windows socket handles cannot be os.fstat'ed. This is
                    # explicitly modeled metadata/typed EBADF around actual
                    # exact socket/fileno/getsockopt/close/TCP operations, NOT
                    # a Linux socket-inode/root/physical EBADF certificate.
                    value = types.SimpleNamespace(st_dev=71,
                        st_ino=1000 + len(self.socket_rows), st_mode=stat.S_IFSOCK | 0o600,
                        st_uid=0, st_gid=0, st_nlink=1, st_size=0)
                    self.socket_rows.append({'socket': raw, 'fd': fd, 'metadata': value})
                    return value
        if any(row['fd'] == fd for row in self.socket_rows):
            raise OSError(errno.EBADF, 'HOST70 modeled socket closed after actual fileno -1')
        return self._metadata(os.fstat(fd))

    def read(self, fd, count):
        return os.read(fd, count)

    def close(self, fd):
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        result = os.close(fd)
        self.live.pop(fd, None)
        return result


class _NoProductionJournalPath(object):
    """Private WifiBackend read-only path seam; no production FS inspection."""
    def __init__(self, original, read_failure=None):
        self.original = original
        self.journal = original.abspath('/mnt/data/p011-toolbox/sessions/mta-network')
        self.denied_reads = 0
        self.read_failure = read_failure

    def lexists(self, path):
        if path == self.journal:
            self.denied_reads += 1
            if self.read_failure is not None:
                raise self.read_failure
            return False  # explicitly empty HOST fixture, not device absence.
        return self.original.lexists(path)

    def __getattr__(self, name):
        return getattr(self.original, name)


class _WifiReadOnlyOs(object):
    def __init__(self, read_failure=None):
        self.path = _NoProductionJournalPath(os.path, read_failure=read_failure)

    def __getattr__(self, name):
        return getattr(os, name)


class _UserDirectoryRefusal(object):
    """One explicit failed directory-stat fixture, in the real Registry body."""
    def __init__(self, user):
        self.user, self.calls = user, 0

    def isdir(self, path):
        if path == self.user:
            self.calls += 1
            return False
        return os.path.isdir(path)

    def __getattr__(self, name):
        return getattr(os.path, name)


class _RegistryOsRefusal(object):
    def __init__(self, user):
        self.path = _UserDirectoryRefusal(user)

    def __getattr__(self, name):
        return getattr(os, name)


def _eventually(predicate, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(.01)
    return bool(predicate())


class _ServiceFixture(object):
    def __init__(self, testcase, name, seconds=90.0):
        self.testcase, self.name = testcase, name
        self.domain = _BootDomain(seconds)
        self.temp = tempfile.TemporaryDirectory(prefix='HOST70-private-')
        self.files = _PrivatePreflightIo(Path(self.temp.name))
        self.module = types.ModuleType('mta_client_service_owner')
        self.module.__file__ = '/HOST70/private-source/mta_client_service_owner.py'
        sys.modules[self.module.__name__] = self.module
        self.domain.owner_module = self.module
        raw_owner = _raw(OWNER_PATH, OWNER_BYTES, OWNER_SHA)
        exec(compile(raw_owner, self.module.__file__, 'exec'), self.module.__dict__)
        self.owner = self.module.FixedStateServiceOwner(self.domain.loader,
                            self.domain.loader._original_until, _io=self.files)
        self.files.owner = self.owner
        self.service = self.domain.loader.modules['mta_service']
        self.http = self.domain.loader.modules['minhttp']
        self.probe = _CapabilitySubprocessFixture(self.files.bluez, self.files.network,
                                                unknown=name == 'probe_unknown')
        self.service.subprocess = self.probe  # module-private, no global patch.
        self.wifi_read_failure = (OSError(errno.EACCES, 'HOST70 modeled readonly Wi-Fi journal refusal')
                                  if name == 'wifi_pending' else None)
        self.wifi_os = _WifiReadOnlyOs(read_failure=self.wifi_read_failure)
        self.domain.loader.modules['mta_wifi'].os = self.wifi_os
        self.denials = []
        self.denials.append(mock.patch.object(
            self.domain.loader.modules['mta_client_receive_factory'].FixedReceiveDeploymentFactory,
            '__call__', side_effect=AssertionError('HOST70 no publication/Handoff')))
        self.denials.append(mock.patch.object(
            self.domain.loader.modules['mta_client_state_bridge'].StateClientBridge,
            '__init__', side_effect=AssertionError('HOST70 no Bridge/Parent')))
        self.denials.append(mock.patch.object(self.service.State, '_new_operation_locked',
            side_effect=AssertionError('HOST70 no RF/session operation')))
        self.denial_mocks = [patch.start() for patch in self.denials]
        self.socket_events, self.socket_closes = [], {}
        self.listener_close_error = None
        self.socket_patches = []
        for method in ('recv', 'sendall', 'accept', 'close'):
            original = getattr(socket.socket, method)
            def observed(raw, *args, _method=method, _original=original, **kwargs):
                managed = any(value.get('socket') is raw for value in self.owner.requests)
                managed = managed or (self.owner.listener is not None and
                                      self.owner.listener['socket'] is raw)
                if managed:
                    self.socket_events.append((_method, raw, time.monotonic()))
                if _method == 'close' and managed:
                    self.socket_closes[id(raw)] = self.socket_closes.get(id(raw), 0) + 1
                    result = _original(raw, *args, **kwargs)
                    if self.listener_close_error is not None and self.owner.listener['socket'] is raw:
                        raise self.listener_close_error
                    return result
                return _original(raw, *args, **kwargs)
            patch = mock.patch.object(socket.socket, method, observed)
            patch.start()
            self.socket_patches.append(patch)

    def endpoint(self):
        endpoint = self.owner.endpoint()
        self.testcase.assertEqual(set(endpoint), {'endpoint', 'token'})
        self.testcase.assertTrue(endpoint['endpoint'].startswith('http://127.0.0.1:'))
        port = int(endpoint['endpoint'].rsplit(':', 1)[1])
        self.testcase.assertTrue(1 <= port <= 65535)
        self.testcase.assertEqual(endpoint['token'], self.owner.state.token)
        return port, endpoint['token']

    def unavailable(self):
        case, owner = self.testcase, self.owner
        value = owner.status()
        for name in ('receive_available', 'send_available', 'scan_available',
                     'native_restored', 'phone_tested'):
            case.assertIs(value[name], False)
        case.assertNotIn('token', value)
        case.assertNotIn('endpoint', value)
        if owner.state_complete:
            case.assertIs(type(owner.state), self.service.State)
            case.assertIs(owner.state._trusted_receive_deployment_factory, owner.factory)
            case.assertIs(owner.state.receive_available, False)
            case.assertIs(owner.state.send_available, False)
            case.assertIs(owner.state.scan_available, False)
            for name in ('operation', 'session', 'helper', 'key', 'crypto',
                         'lease', 'transport', 'worker'):
                case.assertIs(getattr(owner.state, name), None)
        for value in self.denial_mocks:
            case.assertEqual(value.call_count, 0)

    def assets_closed(self):
        case = self.testcase
        case.assertEqual(len(self.owner.assets), 2)
        case.assertEqual(self.files.live, {})
        case.assertEqual(sum(self.files.open_counts.values()), 2)
        case.assertEqual(sum(self.files.close_counts.values()), 2)
        for row, expected in zip(self.owner.assets, ASSETS):
            case.assertIs(row['attempted'], True)
            case.assertIs(row['closed'], True)
            case.assertIs(row['unknown'], False)
            case.assertEqual(len(row['raw']), expected[1])
            case.assertEqual(hashlib.sha256(row['raw']).hexdigest(), expected[2])

    def actual_sockets_closed(self):
        for row in self.files.socket_rows:
            self.testcase.assertEqual(row['socket'].fileno(), -1)
            self.testcase.assertEqual(self.socket_closes[id(row['socket'])], 1)
        for ticket in self.owner.threads:
            if ticket['initialized']:
                self.testcase.assertFalse(ticket['thread'].is_alive())

    def teardown(self):
        try:
            if self.owner.started and not self.owner.close_called:
                self.owner.close()
            self.unavailable()
        finally:
            for patch in reversed(self.denials):
                patch.stop()
            for patch in reversed(self.socket_patches):
                patch.stop()
            self.domain.teardown()
            self.temp.cleanup()


class ServiceOwner70R2Test(unittest.TestCase):
    def test_remaining_cases_and_exact_domain_teardown(self):
        completed = []
        names = ('active_request_expiry', 'state_ctor_failure',
                 'probe_unknown', 'wifi_pending', 'server_ctor_failure',
                 'thread_before_start', 'thread_after_start',
                 'listener_close_unknown', 'state_close_false')
        for name in names:
            with self.subTest(case=name):
                fixture = _ServiceFixture(self, name,
                    seconds=3.0 if name == 'active_request_expiry' else 90.0)
                try:
                    owner, module = fixture.owner, fixture.module
                    self.assertFalse(owner.started)
                    self.assertEqual(owner.assets, [])
                    self.assertEqual(owner.requests, [])
                    self.assertEqual(owner.threads, [])
                    self.assertIs(owner.until, fixture.domain.loader._original_until)
                    original_until = owner.until
                    original_boot_deadline = fixture.domain.loader.deadline

                    if name == 'state_ctor_failure':
                        files = fixture.domain.loader.modules['mta_files']
                        refused_os = _RegistryOsRefusal(fixture.files.user)
                        files.os = refused_os
                        with self.assertRaises(ValueError) as caught:
                            owner.start()
                        self.assertIs(owner.failure, caught.exception)
                        self.assertEqual(caught.exception.args, ('User directory does not exist',))
                        self.assertEqual(refused_os.path.calls, 1)
                        self.assertTrue(owner.state_called)
                        self.assertIs(type(owner.state), fixture.service.State)
                        self.assertFalse(owner.state_complete)
                        self.assertFalse(owner.server_called)
                        self.assertIsNone(owner.server)
                        self.assertEqual(owner.threads, [])
                        self.assertFalse(owner.close())
                        self.assertTrue(owner.status()['resource_pending'])

                    elif name == 'probe_unknown':
                        with self.assertRaises(module.ServiceOwnerError) as caught:
                            owner.start()
                        self.assertEqual(caught.exception.code, 'state_start_pending')
                        self.assertIs(owner.failure, caught.exception)
                        self.assertTrue(owner.state_complete)
                        self.assertEqual(fixture.probe.calls,
                            [(fixture.files.bluez, '--capabilities', 'hci0')])
                        self.assertIs(owner.probe_rows, owner.state.probe_actors)
                        self.assertEqual(len(owner.probe_rows), 1)
                        row = owner.probe_rows[0]
                        self.assertIs(row['spawn_unknown'], True)
                        self.assertIs(row['spawn_pending'], False)
                        self.assertIs(row['closed'], False)
                        self.assertIsNone(row['process'])
                        self.assertIs(owner.state.radio_restore_pending, True)
                        self.assertIs(owner.state.wifi_restore_pending, False)
                        self.assertFalse(owner.server_called)
                        self.assertFalse(owner.close())
                        self.assertIs(row['spawn_unknown'], True)
                        self.assertTrue(owner.status()['resource_pending'])

                    elif name == 'wifi_pending':
                        # Only the private read-only OS/path syscall seam
                        # fails. Actual WifiBackend._refresh_pending and the
                        # actual State ctor produce these pending facts;
                        # neither State flags nor owner admission are mocked.
                        with self.assertRaises(module.ServiceOwnerError) as caught:
                            owner.start()
                        self.assertEqual(caught.exception.code, 'state_start_pending')
                        self.assertIs(owner.failure, caught.exception)
                        self.assertTrue(owner.state_complete)
                        self.assertIs(owner.state.wifi_backend._recovery_locked, True)
                        self.assertEqual(owner.state.wifi_backend._reason, '网络恢复记录无法读取')
                        self.assertGreaterEqual(fixture.wifi_os.path.denied_reads, 2)
                        self.assertIs(owner.state.wifi_restore_pending, True)
                        self.assertIs(owner.state.radio_restore_pending, False)
                        self.assertIs(owner.probe_rows, owner.state.probe_actors)
                        self.assertEqual(len(owner.probe_rows), 2)
                        self.assertTrue(owner.state._probes_closed())
                        self.assertEqual(fixture.probe.calls, [
                            (fixture.files.bluez, '--capabilities', 'hci0'),
                            (fixture.files.network, '--capabilities')])
                        self.assertTrue(all(process.communications == 1 and
                            process.stdout.closed and process.stderr.closed
                            for process in fixture.probe.processes))
                        self.assertFalse(owner.server_called)
                        self.assertIsNone(owner.server)
                        self.assertEqual(owner.threads, [])
                        self.assertFalse(owner.close())
                        self.assertIs(owner.state_close_called, True)
                        # Original State.close enters its retained-owner
                        # gate and raises for Wi-Fi pending. No return value
                        # has been obtained; the owner retains that exact
                        # close exception and must not turn it into False or
                        # retry the original close on a later owner.close().
                        self.assertIsNone(owner.state_close_return)
                        close_failures = [error for error in owner.failures
                            if type(error) is ValueError and error.args ==
                            ('Retained original recovery owner required',)]
                        self.assertEqual(len(close_failures), 1)
                        self.assertIs(owner.failures[-1], close_failures[0])
                        failed_inventory = tuple(owner.failures)
                        first_cleanup_cap = owner.cleanup_until
                        self.assertFalse(owner.close())
                        self.assertEqual(len(owner.failures), len(failed_inventory))
                        self.assertTrue(all(actual is original for actual, original
                            in zip(owner.failures, failed_inventory)))
                        self.assertIs(owner.cleanup_until, first_cleanup_cap)
                        self.assertIsNone(owner.state_close_return)
                        self.assertIs(owner.status()['state_close_verified'], False)
                        self.assertTrue(owner.status()['resource_pending'])

                    elif name == 'server_ctor_failure':
                        original_init = fixture.service.Server.__init__
                        failure = OSError(errno.EIO, 'HOST70 constructor after actual socket')
                        calls = []
                        def initialized_then_failed(server, *args, **kwargs):
                            result = original_init(server, *args, **kwargs)
                            calls.append(server)
                            self.assertGreater(server.socket.fileno(), -1)
                            raise failure
                        with mock.patch.object(fixture.service.Server, '__init__',
                                               initialized_then_failed):
                            with self.assertRaises(OSError) as caught:
                                owner.start()
                        self.assertIs(caught.exception, failure)
                        self.assertIs(owner.failure, failure)
                        self.assertEqual(calls, [owner.server])
                        self.assertIs(type(owner.server), fixture.service.Server)
                        self.assertTrue(owner.state_complete)
                        self.assertFalse(owner.server_complete)
                        self.assertIs(owner.listener['socket'], owner.server.socket)
                        self.assertFalse(owner.listener['unknown'])
                        self.assertEqual(owner.threads, [])
                        self.assertFalse(owner.close())
                        self.assertTrue(owner.listener['closed'])
                        self.assertTrue(owner.status()['resource_pending'])
                        fixture.actual_sockets_closed()

                    elif name in ('thread_before_start', 'thread_after_start'):
                        original_start = threading.Thread.start
                        failure = RuntimeError('HOST70 exact thread start uncertainty')
                        starts = []
                        def start_failed(thread):
                            starts.append(thread)
                            self.assertIs(owner.threads[-1]['thread'], thread)
                            if name == 'thread_after_start':
                                original_start(thread)
                            raise failure
                        with mock.patch.object(threading.Thread, 'start', start_failed):
                            with self.assertRaises(RuntimeError) as caught:
                                owner.start()
                        self.assertIs(caught.exception, failure)
                        self.assertIs(owner.failure, failure)
                        self.assertEqual(starts, [owner.thread])
                        self.assertEqual(len(owner.threads), 1)
                        ticket = owner.threads[0]
                        self.assertIs(ticket['thread'], owner.thread)
                        self.assertIs(ticket['failure'], failure)
                        self.assertIs(ticket['called'], True)
                        self.assertIs(ticket['returned'], False)
                        self.assertIs(ticket['unknown'], True)
                        self.assertFalse(owner.close())
                        self.assertIs(ticket['unknown'], True)
                        self.assertFalse(owner.thread.is_alive())
                        self.assertTrue(owner.status()['resource_pending'])
                        fixture.actual_sockets_closed()

                    else:
                        self.assertIs(owner.start(), owner)
                        self.assertTrue(owner.start_complete)
                        self.assertIs(type(owner.state), fixture.service.State)
                        self.assertIs(type(owner.server), fixture.service.Server)
                        self.assertIs(owner.probe_rows, owner.state.probe_actors)
                        self.assertEqual(len(owner.probe_rows), 2)
                        self.assertTrue(owner.state._probes_closed())
                        self.assertEqual(len(fixture.probe.processes), 2)
                        self.assertTrue(all(process.communications == 1 and
                            process.stdout.closed and process.stderr.closed
                            for process in fixture.probe.processes))
                        self.assertEqual(owner.state.registry.root,
                                         os.path.abspath(fixture.files.user))
                        self.assertTrue(os.path.isdir(owner.state.received_root))
                        port, token = fixture.endpoint()

                        if name == 'active_request_expiry':
                            client = socket.create_connection(('127.0.0.1', port), timeout=3)
                            try:
                                client.sendall(b'GET /v1/status HTTP/1.1\r\nHost: ')  # real incomplete headers.
                                self.assertTrue(_eventually(lambda: bool(owner.requests) and
                                    bool(owner.server.workers), seconds=1.0))
                                before_requests = tuple(owner.requests)
                                owner.thread.join(max(0, original_until - time.monotonic()) + 1.0)
                                self.assertFalse(owner.thread.is_alive())
                                self.assertTrue(owner.stop_called)
                                self.assertGreaterEqual(time.monotonic(), original_until)
                                with self.assertRaises(module.ServiceOwnerError) as caught:
                                    owner.endpoint()
                                self.assertEqual(caught.exception.code, 'deadline')
                                with self.assertRaises(OSError):
                                    socket.create_connection(('127.0.0.1', port), timeout=.5)
                                self.assertEqual(tuple(owner.requests), before_requests)
                                self.assertTrue(owner.close())
                                # Physical peer EOF/reset is actual HOST TCP.
                                try:
                                    self.assertEqual(client.recv(4096), b'')
                                except (ConnectionResetError, ConnectionAbortedError):
                                    pass
                                self.assertEqual(owner.server.workers, {})
                                self.assertTrue(all(row['ended'] for row in owner.requests))
                                self.assertFalse(any(method in ('recv', 'sendall', 'accept') and
                                    started >= original_until
                                    for method, raw, started in fixture.socket_events))
                                fixture.actual_sockets_closed()
                            finally:
                                client.close()

                        elif name == 'listener_close_unknown':
                            self.assertEqual(_http(port, token=token)[0], 200)
                            failure = OSError(errno.EIO, 'HOST70 close returned physical closure then uncertainty')
                            fixture.listener_close_error = failure
                            self.assertFalse(owner.close())
                            row = owner.listener
                            self.assertIs(row['failure'], failure)
                            self.assertIs(row['attempted'], True)
                            self.assertIs(row['unknown'], True)
                            self.assertIs(row['closed'], False)
                            self.assertEqual(row['socket'].fileno(), -1)
                            before = dict(fixture.socket_closes)
                            self.assertFalse(owner.close())
                            with self.assertRaises(module.ServiceOwnerError) as caught:
                                row['proxy'].close()
                            self.assertEqual(caught.exception.code, 'socket_close_unknown')
                            self.assertEqual(fixture.socket_closes, before)
                            self.assertEqual(before[id(row['socket'])], 1)
                            self.assertTrue(owner.status()['resource_pending'])
                            fixture.actual_sockets_closed()

                        elif name == 'state_close_false':
                            # The actual original State close algorithm runs
                            # once and returns True for this no-operation
                            # State. A transparent private return fixture then
                            # presents False to the owner; that return must
                            # stay False, not borrow physical socket closure
                            # or State.closed() as a replacement receipt.
                            self.assertEqual(_http(port, token=token)[0], 200)
                            original_close = fixture.service.State.close
                            close_calls = []
                            def close_returned_false(state):
                                result = original_close(state)
                                close_calls.append((state, result))
                                return False
                            with mock.patch.object(fixture.service.State, 'close', close_returned_false):
                                self.assertFalse(owner.close())
                                self.assertEqual(len(close_calls), 1)
                                self.assertIs(close_calls[0][0], owner.state)
                                self.assertIs(close_calls[0][1], True)
                                self.assertTrue(owner.state.closed())
                                self.assertIs(owner.state_close_called, True)
                                self.assertIs(owner.state_close_return, False)
                                self.assertFalse(owner.close_complete)
                                self.assertIs(owner.status()['state_close_verified'], False)
                                self.assertTrue(owner.status()['resource_pending'])
                                first_cap = owner.cleanup_until
                                self.assertFalse(owner.close())
                                self.assertIs(owner.cleanup_until, first_cap)
                                self.assertEqual(len(close_calls), 1)
                            self.assertEqual(owner.server.workers, {})
                            fixture.actual_sockets_closed()

                    fixture.assets_closed()
                    fixture.unavailable()
                    fixture.domain.boot_closed(self)
                    self.assertIs(owner.until, original_until)
                    self.assertIs(fixture.domain.loader.deadline, original_boot_deadline)
                    first_cleanup_until = owner.cleanup_until
                    self.assertLessEqual(first_cleanup_until, original_until + 60.0)
                    first_result = owner.close_complete
                    self.assertIs(owner.close(), first_result)
                    self.assertIs(owner.cleanup_until, first_cleanup_until)
                    completed.append(name)
                finally:
                    fixture.teardown()
        self.assertEqual(completed, list(names))
        print(MARKER)


if __name__ == '__main__':
    unittest.main()
