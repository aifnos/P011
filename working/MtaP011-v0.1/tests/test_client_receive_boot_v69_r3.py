# -*- coding: utf-8 -*-
"""One new fixed State-side boot method in an explicit HOST in-memory FS.

The actual new boot loads fixed source definitions. No State, Handoff, Parent,
DeploymentLoader, publication, service, subprocess, socket or radio is started.
The model's validate(), PID and root ownership are synthetic read-only facts;
the actual LinuxIo flag syscall is not exercised. Production partial module and FD
inventory is inspected before fixture-only sys.modules teardown.

The reviewed boot identity below is fixed before candidate definition loading;
its literal 22-source pins must match all snapshotted raw bytes and sizes.
No old TestCase or old test helper is loaded or executed.
"""
import builtins
import errno
import hashlib
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BOOT_PATH = 'candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_boot.py'
BOOT_SHA = '1c3d05c3bf588aa2b6438e6d940fd5e36e467860c1b183305566a18ed69695aa'
BOOT_BYTES = 17973
SOURCE_NAMES = ('mta_client_executor', 'p011_json', 'mta_protocol',
    'mta_storage', 'mta_files', 'mta_crypto', 'mta_transfer_session',
    'mta_dhcp', 'mta_dhcp_server', 'mta_scoped_sockets', 'mta_transport',
    'mta_sender', 'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff',
    'mta_client_tmp_alias', 'mta_client_receive_factory',
    'mta_client_state_bridge', 'mta_service')
SPECIAL = {
    'mta_client_executor': 'candidate/client-integrated-v37/runtime/mta_client_executor.py',
    'mta_client_control_frame': 'candidate/client-integrated-v37/runtime/mta_client_control_frame.py',
    'mta_client_connect_handoff': 'candidate/client-connect-v13/runtime/mta_client_connect_handoff.py',
    'mta_client_tmp_alias': 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py',
    'mta_service': 'candidate/client-state-integration-v32/runtime/mta_service.py',
    'mta_client_receive_factory': 'candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_factory.py',
    'mta_client_state_bridge': 'candidate/client-receive-factory-v69/runtime/mta_client_state_bridge.py',
}
MARKER = ('HOST69_RECEIVE_BOOT new_methods=1 old_methods=0 '
          'host_model=true device=false phone=false')


def _read_fixed(path, pin, size):
    if type(pin) is not str or len(pin) != 64 or type(size) is not int:
        raise AssertionError('v69 final SOURCE identity not bound')
    raw = (ROOT / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('v69 fixed input changed: ' + path)
    return raw


def _inputs():
    boot = _read_fixed(BOOT_PATH, BOOT_SHA, BOOT_BYTES)
    sources = []
    for name in SOURCE_NAMES:
        raw = (ROOT / SPECIAL.get(name, 'runtime/' + name + '.py')).read_bytes()
        sources.append((name, hashlib.sha256(raw).hexdigest(), len(raw), raw))
    # The fixed boot's actual literal pins are checked after definition loading,
    # before any model/source load. The checker snapshots exactly these 22 paths.
    return boot, tuple(sources)


class _Clock(object):
    def __init__(self):
        self.value = 1.0
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.value


class _Node(object):
    def __init__(self, ino, mode, raw=b'', target=None):
        self.ino = ino
        self.mode = mode
        self.raw = raw
        self.target = target

    def metadata(self):
        size = len(self.target.encode('ascii')) if self.target is not None else len(self.raw)
        return types.SimpleNamespace(st_dev=7, st_ino=self.ino,
            st_mode=self.mode, st_uid=0, st_gid=0,
            st_nlink=2 if stat.S_ISDIR(self.mode) else 1, st_size=size,
            st_mtime_ns=1000000000 + self.ino, st_ctime_ns=2000000000 + self.ino)


class _ReadonlyModelIo(object):
    """Synthetic fixed alias/root metadata and actual source bytes, no OS FD."""
    def __init__(self, sources):
        self.nodes = {}
        self.live = {}
        self.history = []
        self.closed = []
        self.close_calls = {}
        self.events = []
        self.validate_calls = 0
        self.next_fd = 100
        self.close_after_error = False
        self._close_error_used = False
        self.root = '/tmp/p011-mta-state-v69'
        self.physical_root = '/var/volatile/tmp/p011-mta-state-v69'
        for path, mode, target in (
                ('/', stat.S_IFDIR | 0o755, None),
                ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                (self.physical_root, stat.S_IFDIR | 0o700, None),
                (self.physical_root + '/runtime', stat.S_IFDIR | 0o700, None)):
            self.add(path, mode, target=target)
        for name, unused_pin, unused_size, raw in sources:
            self.add(self.physical_root + '/runtime/' + name + '.py',
                     stat.S_IFREG | 0o400, raw)

    def add(self, path, mode, raw=b'', target=None):
        node = _Node(len(self.nodes) + 10, mode, raw, target)
        self.nodes[path] = node
        return node

    def physical(self, path):
        if path == self.root or path.startswith(self.root + '/'):
            return self.physical_root + path[len(self.root):]
        return path

    def validate(self):
        self.validate_calls += 1
        self.events.append(('model_validate_not_arm',))

    def pid(self):
        self.events.append(('model_pid',))
        return 6901

    def stat(self, path):
        self.events.append(('stat', path))
        node = self.nodes.get(self.physical(path))
        if node is None:
            raise OSError(errno.ENOENT, 'HOST model absent')
        return node.metadata()

    def readlink(self, path):
        self.events.append(('readlink', path))
        node = self.nodes.get(path)
        if node is None or node.target is None:
            raise OSError(errno.EINVAL, 'HOST model not a link')
        return node.target

    def open(self, path):
        # The actual boot's LinuxIo hardcodes ARM_READ inside this API; this
        # synthetic I/O boundary cannot prove the real Linux syscall flags.
        self.events.append(('open', path))
        node = self.nodes.get(self.physical(path))
        if node is None or not stat.S_ISREG(node.mode):
            raise OSError(errno.ENOENT, 'HOST model source absent')
        fd = self.next_fd
        self.next_fd += 1
        row = {'fd': fd, 'path': path, 'node': node, 'offset': 0}
        self.live[fd] = row
        self.history.append(row)
        return fd

    def fstat(self, fd):
        self.events.append(('fstat', fd))
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST model closed descriptor')
        return self.live[fd]['node'].metadata()

    def read(self, fd, count):
        self.events.append(('read', fd, count))
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST model closed descriptor')
        if type(count) is not int or not 0 < count <= 65536:
            raise AssertionError('invalid model read bound')
        row = self.live[fd]
        start = row['offset']
        raw = row['node'].raw[start:start + count]
        row['offset'] += len(raw)
        return raw

    def close(self, fd):
        self.events.append(('close', fd))
        self.close_calls[fd] = self.close_calls.get(fd, 0) + 1
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST model double close')
        self.closed.append(self.live.pop(fd))
        if self.close_after_error and not self._close_error_used:
            self._close_error_used = True
            raise OSError(errno.EIO, 'HOST model close returned uncertain')
        return None


class _Fixture(object):
    """Only teardown restores sys.modules; the candidate never erases partials."""
    def __init__(self, testcase, raw_boot, sources, original_until=30.0):
        self.testcase = testcase
        self.sources = sources
        self.names = tuple(row[0] for row in sources) + ('mta_client_receive_boot',)
        self.saved = dict((name, sys.modules.get(name)) for name in self.names)
        for name in self.names:
            sys.modules.pop(name, None)
        testcase.addCleanup(self.teardown)
        self.io = _ReadonlyModelIo(sources)
        self.clock = _Clock()
        self.boot = types.ModuleType('mta_client_receive_boot')
        self.boot.__file__ = '/HOST69/model-definition/mta_client_receive_boot.py'
        sys.modules['mta_client_receive_boot'] = self.boot
        exec(compile(raw_boot, self.boot.__file__, 'exec'), self.boot.__dict__)
        testcase.assertEqual(tuple(self.boot.MODULES), tuple(row[0] for row in sources))
        testcase.assertEqual(tuple(self.boot.SOURCE_PINS),
            tuple((name, size, pin) for name, pin, size, unused_raw in sources))
        self.loader = self.boot.BootSourceLoader(original_until,
                                                _io=self.io, _clock=self.clock)
        self.initial_until = original_until
        self.constructor_events = tuple(self.io.events)

    def teardown(self):
        for name in self.names:
            if self.saved[name] is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = self.saved[name]

    def closed_known(self):
        case = self.testcase
        case.assertFalse(self.io.live)
        case.assertTrue(all(count == 1 for count in self.io.close_calls.values()))
        case.assertEqual(len(self.io.close_calls), len(self.io.history))
        for row in self.loader.rows:
            if row['fd'] is not None:
                case.assertIs(row['closed'], True)
                case.assertIs(row['attempted'], True)
                case.assertIs(row['unknown'], False)
                case.assertEqual(self.io.close_calls[row['fd']], 1)
                with case.assertRaises(OSError) as caught:
                    self.io.fstat(row['fd'])
                case.assertEqual(caught.exception.errno, errno.EBADF)

    def loaded(self):
        result = self.loader.load()
        self.testcase.assertIs(result, self.loader)
        return result


class ReceiveBoot69Test(unittest.TestCase):
    def test_actual_fixed_boot_definitions_and_refusals(self):
        raw_boot, sources = _inputs()
        completed = []
        # Standard-library source definition imports are permitted. Any actual
        # service/network/process construction remains a tripwire, not a model.
        with mock.patch('subprocess.Popen', side_effect=AssertionError('HOST69 no process')) as spawn, \
                mock.patch('socket.socket', side_effect=AssertionError('HOST69 no socket')) as socket_ctor, \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('HOST69 no crypto')) as crypto_ctor:
            for name in ('normal', 'foreign_f', 'pin_changed', 'mode_changed',
                         'original_expired', 'close_unknown', 'import_absent', 'two_attempts'):
                with self.subTest(case=name):
                    fixture = _Fixture(self, raw_boot, sources,
                                       0.5 if name == 'original_expired' else 30.0)
                    try:
                        loader, boot, io = fixture.loader, fixture.boot, fixture.io
                        self.assertEqual(fixture.constructor_events, ())
                        self.assertEqual(io.history, [])
                        if name == 'foreign_f':
                            foreign = types.ModuleType('mta_client_executor')
                            sys.modules['mta_client_executor'] = foreign
                            with self.assertRaises(boot.ReceiveBootError) as caught:
                                fixture.loaded()
                            self.assertEqual(caught.exception.code, 'canonical_namespace_busy')
                            self.assertIs(loader.failure, caught.exception)
                            self.assertIs(sys.modules['mta_client_executor'], foreign)
                        elif name == 'pin_changed':
                            node = io.nodes[io.physical_root + '/runtime/p011_json.py']
                            node.raw = bytes((node.raw[0] ^ 1,)) + node.raw[1:]
                            with self.assertRaises(boot.ReceiveBootError) as caught:
                                fixture.loaded()
                            self.assertEqual(caught.exception.code, 'source_changed')
                            self.assertIs(loader.failure, caught.exception)
                            self.assertTrue(loader.module_originals)
                            self.assertIs(loader.module_originals[0][1], sys.modules['mta_client_executor'])
                        elif name == 'mode_changed':
                            io.nodes[io.physical_root + '/runtime/p011_json.py'].mode = stat.S_IFREG | 0o600
                            with self.assertRaises(boot.ReceiveBootError) as caught:
                                fixture.loaded()
                            self.assertEqual(caught.exception.code, 'source_shape')
                            self.assertIs(loader.failure, caught.exception)
                            self.assertTrue(loader.module_originals)
                        elif name == 'original_expired':
                            with self.assertRaises(boot.ReceiveBootError) as caught:
                                fixture.loaded()
                            self.assertEqual(caught.exception.code, 'deadline')
                            self.assertIs(loader.failure, caught.exception)
                            self.assertEqual(io.history, [])
                        elif name == 'close_unknown':
                            io.close_after_error = True
                            with self.assertRaises(boot.ReceiveBootError) as caught:
                                fixture.loaded()
                            self.assertEqual(caught.exception.code, 'close_unknown')
                            self.assertIs(loader.failure, caught.exception)
                            self.assertIs(loader.pending, True)
                            self.assertEqual(len(loader.rows), 1)
                            row = loader.rows[0]
                            self.assertIs(row['unknown'], True)
                            self.assertIs(row['attempted'], True)
                            self.assertIs(row['closed'], False)
                            self.assertEqual(row['close_failure'].errno, errno.EIO)
                            self.assertEqual(loader.module_originals, [])
                            before = dict(io.close_calls)
                            # Failure is retained. load() is the original no-retry
                            # entry; invoking it again cannot close the FD again.
                            with self.assertRaises(boot.ReceiveBootError) as repeated:
                                loader.load()
                            self.assertEqual(repeated.exception.code, 'already_attempted')
                            self.assertEqual(io.close_calls, before)
                            self.assertTrue(all(count == 1 for count in before.values()))
                            self.assertFalse(io.live)
                        else:
                            fixture.loaded()
                            self.assertEqual(loader.until, fixture.initial_until)
                            self.assertIs(loader.until, loader._original_until)
                            self.assertEqual(loader.deadline, min(fixture.initial_until, 11.0))
                            self.assertIs(loader.deadline, loader._original_deadline)
                            self.assertEqual(set(loader.modules), set(boot.MODULES))
                            self.assertEqual(len(loader.module_originals), 22)
                            self.assertEqual(tuple(row[0] for row in loader.module_originals),
                                             tuple(boot.MODULES))
                            self.assertEqual(len(loader.rows), 22)
                            self.assertIs(loader.modules['mta_client_executor'], sys.modules['mta_client_executor'])
                            self.assertIs(loader.modules['mta_client_state_bridge'], sys.modules['mta_client_state_bridge'])
                            self.assertIs(loader.pending, False)
                            self.assertIs(loader.failure, None)
                            fixture.closed_known()
                            if name == 'normal':
                                # Factory constructor is production code, but no
                                # Handoff is invented to enter its publisher.
                                factory = loader.create_fixed_factory()
                                factory_module = loader.modules['mta_client_receive_factory']
                                self.assertIs(type(factory), factory_module.FixedReceiveDeploymentFactory)
                                self.assertEqual(factory._attempts, [])
                                self.assertIs(factory._active, None)
                                self.assertIs(loader.factory_returned, factory)
                                self.assertIs(loader.factory_attempted, True)
                                before = tuple(io.events)
                                with self.assertRaises(factory_module.ReceivePublicationError) as caught:
                                    factory(object())
                                self.assertEqual(caught.exception.args, ('publication_handoff',))
                                self.assertEqual(factory._attempts, [])
                                self.assertIs(factory._active, None)
                                self.assertEqual(tuple(io.events), before)
                                state_raw = next(raw for module, unused_pin, unused_size, raw in sources
                                                 if module == 'mta_service')
                                self.assertIn(b'self.receive_available=False', state_raw)
                            elif name == 'import_absent':
                                importer = loader.modules['mta_service'].__dict__['__builtins__']['__import__']
                                with self.assertRaises(boot.ReceiveBootError) as caught:
                                    importer('mta_host69_unlisted', {}, {}, (), 0)
                                self.assertEqual(caught.exception.code, 'source_import')
                                self.assertNotIn('mta_host69_unlisted', sys.modules)
                            elif name == 'two_attempts':
                                before_rows = tuple(loader.rows)
                                before_modules = tuple(loader.module_originals)
                                before = tuple(io.events)
                                with self.assertRaises(boot.ReceiveBootError) as caught:
                                    loader.load()
                                self.assertEqual(caught.exception.code, 'already_attempted')
                                self.assertEqual(tuple(io.events), before)
                                self.assertEqual(tuple(loader.rows), before_rows)
                                self.assertEqual(tuple(loader.module_originals), before_modules)
                        self.assertEqual(fixture.initial_until,
                                         0.5 if name == 'original_expired' else 30.0)
                        if name != 'close_unknown':
                            fixture.closed_known()
                        completed.append(name)
                    finally:
                        fixture.teardown()
            self.assertEqual(len(completed), 8)
            self.assertEqual(len(set(completed)), 8)
            self.assertEqual(spawn.call_count, 0)
            self.assertEqual(socket_ctor.call_count, 0)
            self.assertEqual(crypto_ctor.call_count, 0)
        print(MARKER)


if __name__ == '__main__':
    unittest.main()
