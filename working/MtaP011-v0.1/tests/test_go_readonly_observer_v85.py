# -*- coding: utf-8 -*-
"""One new HOST85 method / eight readonly-loader and body boundary domains.

The actual frozen Loader executes all 38 fixed definitions and authenticates
their original bytes/modules/once-close inventory in an isolated fixture domain.
Only filesystem, FD/EBADF, PID, clock and helper-process interfaces are explicit
HOST models. The actual body constructors, _open/_helper/_current/_close_file
and _close_probe algorithms execute; production methods are not success stubs.
No real target path, lock, helper executable, process, Collector, State, Server,
F main, network, RF, restoration or production admission executes here.

Original helper binaries are read as pinned workspace BYTES for the body's
real hash gate, not executed. Known no-return open failure is not a physical
close certificate. Duplicate pipe FD remains unknown even after the model has
no live numeric FD. Fixture namespace teardown removes only retained exact
fixture modules; it is not a production rollback or foreign namespace adopt.
No old TestCase/helper/test method is imported or replayed.
"""
import ctypes
import errno
import hashlib
import json
from pathlib import Path
import socket
import stat
import subprocess
import sys
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ('host/go_readonly_observer_v85_definition_manifest.json', 8983,
            'e6098e979b7f311defdea64f6934f38857488a930ca6337b091f12852a41dc78')
NATIVE_INPUTS = (
    ('out/native/mta-bluez-helper', 65832,
     '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('out/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
)
MARKER = ('HOST85_READONLY_OBSERVER new_methods=1 old_methods=0 cases=8 '
          'filesystem_model=true process_model=true device=false phone=false\n')
LOADER_NAME = 'mta_go_readonly_loader'
PHYSICAL = '/var/volatile/tmp/p011-mta-go-observer-v85'
ALIAS = '/tmp/p011-mta-go-observer-v85'
STATE = '/var/volatile/tmp/p011-mta-state-v69'


def _fixed(path, size, pin):
    value = (ROOT / path).read_bytes()
    if len(value) != size or hashlib.sha256(value).hexdigest() != pin:
        raise AssertionError('fixed HOST85 source input changed')
    return value


def _inputs():
    path, size, pin = MANIFEST
    value = json.loads(_fixed(path, size, pin).decode('ascii'))
    if (type(value) is not dict or set(value) != {'schema', 'sources'} or
            value['schema'] != 'go-readonly-observer-v85-definitions' or
            type(value['sources']) is not list or len(value['sources']) != 39):
        raise AssertionError('HOST85 fixed definition manifest shape')
    sources = []
    for row in value['sources']:
        if type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'}:
            raise AssertionError('HOST85 fixed definition row shape')
        sources.append((row['module'], row['path'], row['bytes'], row['sha256'],
                        _fixed(row['path'], row['bytes'], row['sha256'])))
    names = tuple(row[0] for row in sources)
    if (len(set(names)) != 39 or names[-4:] != ('mta_client_readonly_baseline',
            'mta_snapshot_data', 'mta_go_readonly_preflight', LOADER_NAME)):
        raise AssertionError('HOST85 fixed definition roles/order')
    native = tuple(_fixed(path, size, pin) for path, size, pin in NATIVE_INPUTS)
    return tuple(sources[:-1]), sources[-1][4], native


class _Clock(object):
    def __init__(self):
        self.value, self.calls = 1.0, 0
    def __call__(self):
        self.calls += 1
        return self.value


class _Node(object):
    def __init__(self, ino, mode, raw=b'', target=None):
        self.ino, self.mode, self.raw, self.target = ino, mode, raw, target
    def metadata(self):
        size = len(self.target) if self.target is not None else len(self.raw)
        return types.SimpleNamespace(st_dev=85, st_ino=self.ino, st_mode=self.mode,
            st_uid=0, st_gid=0, st_nlink=2 if stat.S_ISDIR(self.mode) else 1,
            st_size=size, st_rdev=0, st_mtime_ns=1000000000 + self.ino,
            st_ctime_ns=2000000000 + self.ino)


class _ModelIo(object):
    """Original source bytes with explicit, non-kernel descriptor/clock model."""
    def __init__(self, clock, sources=(), native=()):
        self.clock = clock
        self.nodes, self.live, self.history, self.events, self.close_calls = {}, {}, [], [], {}
        self.next_fd, self.open_error = 8500, None
        self.late_anchor = self.late_open = self.late_read = False
        self.late_helper_current = self.arm_late_current = False
        self.duplicate_pipes = False
        self.spawned = []
        for path, mode, target in (
                ('/', stat.S_IFDIR | 0o755, None),
                ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                (PHYSICAL, stat.S_IFDIR | 0o700, None),
                (PHYSICAL + '/runtime', stat.S_IFDIR | 0o700, None),
                (STATE, stat.S_IFDIR | 0o700, None),
                (STATE + '/native', stat.S_IFDIR | 0o700, None)):
            self.add(path, mode, target=target)
        for name, unused_path, unused_size, unused_pin, raw in sources:
            self.add(PHYSICAL + '/runtime/' + name + '.py', stat.S_IFREG | 0o400, raw)
        self.add('/var/volatile/tmp/p011-mta-p2p-device.lock', stat.S_IFREG | 0o600)
        for name, raw in zip(('mta-bluez-helper', 'mta-network-helper'), native):
            self.add(STATE + '/native/' + name, stat.S_IFREG | 0o500, raw)
    def add(self, path, mode, raw=b'', target=None):
        node = _Node(len(self.nodes) + 100, mode, raw, target)
        self.nodes[path] = node
        return node
    def physical(self, path):
        if path == ALIAS or path.startswith(ALIAS + '/'):
            return PHYSICAL + path[len(ALIAS):]
        return path
    def validate(self):
        self.events.append(('model_validate_not_arm',))
    def pid(self):
        self.events.append(('model_pid',))
        return 8501
    def stat(self, path):
        self.events.append(('stat', path))
        node = self.nodes.get(self.physical(path))
        if node is None:
            raise OSError(errno.ENOENT, 'HOST85 model absent')
        value = node.metadata()
        if path == STATE + '/native' and (self.late_anchor or self.arm_late_current):
            self.clock.value = 30.0
        return value
    def readlink(self, path):
        self.events.append(('readlink', path))
        node = self.nodes.get(path)
        if node is None or node.target is None:
            raise OSError(errno.EINVAL, 'HOST85 model link absent')
        return node.target
    def open(self, path):
        self.events.append(('open', path))
        if self.open_error is not None:
            raise self.open_error
        node = self.nodes.get(self.physical(path))
        if node is None or not stat.S_ISREG(node.mode):
            raise OSError(errno.ENOENT, 'HOST85 model source absent')
        fd = self._register(path, node)
        if self.late_open:
            self.clock.value = 30.0
        return fd
    def _register(self, path, node):
        fd = self.next_fd
        self.next_fd += 1
        row = {'fd': fd, 'path': path, 'node': node, 'offset': 0}
        self.live[fd] = row
        self.history.append(row)
        return fd
    def fstat(self, fd):
        self.events.append(('fstat', fd))
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST85 model original FD closed')
        return self.live[fd]['node'].metadata()
    def read(self, fd, count):
        self.events.append(('read', fd, count))
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST85 model original FD closed')
        if type(count) is not int or not 0 < count <= 65536:
            raise AssertionError('HOST85 bounded original read')
        row = self.live[fd]
        start = row['offset']
        raw = row['node'].raw[start:start + count]
        row['offset'] += len(raw)
        if self.late_read:
            self.clock.value = 11.0
        if self.late_helper_current and not raw:
            self.arm_late_current = True
        return raw
    def close(self, fd):
        self.events.append(('close', fd))
        self.close_calls[fd] = self.close_calls.get(fd, 0) + 1
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST85 model duplicate close')
        del self.live[fd]
        return None
    def flock(self, fd):
        self.events.append(('model_flock_not_kernel', fd))
        return 0, 0
    def spawn(self, fd, argv):
        self.events.append(('model_spawn_not_helper_execution', fd, argv))
        if fd not in self.live:
            raise AssertionError('model executable original FD')
        out_node = self.add('/HOST85/stdout/' + str(len(self.spawned)),
                             stat.S_IFIFO | 0o600, b'{"event":"capabilities"}\n')
        err_node = self.add('/HOST85/stderr/' + str(len(self.spawned)), stat.S_IFIFO | 0o600)
        out_fd = self._register('/HOST85/stdout', out_node)
        err_fd = out_fd if self.duplicate_pipes else self._register('/HOST85/stderr', err_node)
        process = _Process(self, _Pipe(self, out_fd), _Pipe(self, err_fd))
        self.spawned.append(process)
        return process
    def readable(self, fds, timeout):
        self.events.append(('model_readable', tuple(fds), timeout))
        return list(fds)


class _Pipe(object):
    def __init__(self, io, fd):
        self.io, self.fd, self.closed, self.close_count = io, fd, False, 0
    def fileno(self):
        return self.fd
    def close(self):
        self.close_count += 1
        self.io.close(self.fd)
        self.closed = True
        return None


class _Process(object):
    """Explicit process fixture; no Popen, PID, kernel wait or native helper."""
    def __init__(self, io, stdout, stderr):
        self.io, self.stdout, self.stderr = io, stdout, stderr
        self.code, self.kill_count, self.wait_count = None, 0, 0
    def poll(self):
        return self.code
    def wait(self, timeout):
        self.wait_count += 1
        self.code = 0
        return 0
    def kill(self):
        self.kill_count += 1
        self.code = 0
        return None


class _Domain(object):
    def __init__(self, case, sources, loader_raw, load=True, late_read=False):
        self.case, self.sources = case, sources
        self.names = tuple(row[0] for row in sources) + (LOADER_NAME,)
        self.before = dict((name, sys.modules.get(name)) for name in self.names)
        case.assertTrue(all(value is None for value in self.before.values()))
        self.module = types.ModuleType(LOADER_NAME)
        self.module.__file__ = PHYSICAL + '/runtime/' + LOADER_NAME + '.py'
        self.clock = _Clock()
        self.io = _ModelIo(self.clock, sources=sources)
        self.loader = None
        sys.modules[LOADER_NAME] = self.module
        try:
            exec(compile(loader_raw, self.module.__file__, 'exec'), self.module.__dict__)
            case.assertEqual(self.module.LOAD_COUNT, 38)
            case.assertEqual(self.module.SOURCE_PINS,
                tuple((name, size, pin) for name, path, size, pin, raw in sources))
            self.loader = self.module.ReadonlySourceLoader(30.0, _io=self.io, _clock=self.clock)
            case.assertEqual(self.io.events, [])
            case.assertEqual(self.clock.calls, 0)
            self.io.late_read = late_read
            if load:
                case.assertIs(self.loader.load(), self.loader)
                case.assertIs(self.loader.authenticate(), self.loader)
        except BaseException:
            self.teardown()
            raise
    def teardown(self):
        originals = () if self.loader is None else self.loader.module_originals
        for name, module, namespace in reversed(originals):
            if sys.modules.get(name) is module and module.__dict__ is namespace:
                del sys.modules[name]
        if sys.modules.get(LOADER_NAME) is self.module:
            del sys.modules[LOADER_NAME]
        for name, value in self.before.items():
            self.case.assertIs(sys.modules.get(name), value)
    def body(self, native):
        module = self.loader.modules['mta_go_readonly_preflight']
        clock = _Clock()
        io = _ModelIo(clock, native=native)
        binding = dict(nonce='a' * 32, task_id='b' * 32, native_epoch=1, operation_epoch=1,
                       until=self.loader.until, cleanup_until=35.0)
        value = module.ReadonlyPreflight(self.loader, binding, _io=io, _clock=clock)
        self.case.assertEqual(io.events, [])
        self.case.assertEqual(clock.calls, 0)
        return module, value, io, clock
    def source_closed(self):
        self.case.assertFalse(self.io.live)
        self.case.assertTrue(all(count == 1 for count in self.io.close_calls.values()))
        for row in self.loader.rows:
            if row['fd'] is None:
                continue
            self.case.assertIs(row['unknown'], False)
            self.case.assertIs(row['closed'], True)
            self.case.assertEqual(self.io.close_calls[row['fd']], 1)


class GoReadonlyObserver85Test(unittest.TestCase):
    def test_fixed_definitions_and_preflight_boundaries(self):
        sources, loader_raw, native = _inputs()
        completed = []
        with mock.patch('subprocess.Popen', side_effect=AssertionError('HOST85 no real process')) as popen, \
                mock.patch('socket.socket', side_effect=AssertionError('HOST85 no socket/RF')) as network, \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('HOST85 no native library')) as library, \
                mock.patch('threading.Thread.start', side_effect=AssertionError('HOST85 no worker')) as thread, \
                mock.patch('os.mkdir', side_effect=AssertionError('HOST85 no target directory')) as mkdir:
            tripwires = (popen, network, library, thread, mkdir)
            domain = _Domain(self, sources, loader_raw)
            try:
                loader = domain.loader
                self.assertEqual(len(loader.modules), 38)
                self.assertEqual(len(loader.raw), 38)
                self.assertEqual(loader.deadline, 11.0)
                self.assertEqual(loader.until, 30.0)
                self.assertEqual(loader._manifest_raw,
                    (ROOT / 'host/client_readonly_proc_vanish_v51_source_manifest.json').read_bytes())
                self.assertIs(loader.modules['mta_client_readonly_baseline'].baseline,
                              loader.modules['mta_client_baseline'])
                self.assertIs(loader.modules['mta_snapshot_data'].core,
                              loader.modules['mta_p2p_client_init'])
                for name, module in loader.modules.items():
                    self.assertEqual(module.__file__, PHYSICAL + '/runtime/' + name + '.py')
                    self.assertIs(sys.modules[name], module)
                before = tuple(domain.io.events)
                before_clock = domain.clock.calls
                self.assertEqual(domain.module.main([]), 0)
                self.assertEqual(tuple(domain.io.events), before)
                self.assertEqual(domain.clock.calls, before_clock)
                domain.source_closed()
                completed.append('actual_38_definitions')

                readonly = loader.modules['mta_client_readonly_baseline']
                with mock.patch.object(readonly.ReadonlyBaselineOwner, 'collect',
                        side_effect=AssertionError('HOST85 no baseline collection')) as collect:
                    for name in ('anchors_late_zero_open', 'returned_fd_late_close_only',
                                 'helper_current_late_zero_spawn', 'duplicate_pipe_fd_unknown',
                                 'open_enoent_known_no_fd', 'open_errno_none_unknown'):
                        with self.subTest(case=name):
                            module, body, io, clock = domain.body(native)
                            original_until, original_cleanup = body.until, body.cleanup_until
                            try:
                                if name == 'anchors_late_zero_open':
                                    io.late_anchor = True
                                    with self.assertRaises(module.ReadonlyPreflightError) as caught:
                                        body._open(module.DEVICE_LOCK)
                                    self.assertEqual(str(caught.exception), 'readonly_expired')
                                    self.assertEqual(body.rows, [])
                                    self.assertFalse(any(event[0] == 'open' for event in io.events))
                                    self.assertEqual(io.spawned, [])
                                elif name == 'returned_fd_late_close_only':
                                    io.late_open = True
                                    with self.assertRaises(module.ReadonlyPreflightError) as caught:
                                        body._open(module.DEVICE_LOCK)
                                    self.assertEqual(str(caught.exception), 'readonly_expired')
                                    self.assertEqual(len(body.rows), 1)
                                    row = body.rows[0]
                                    self.assertIs(row['unknown'], False)
                                    self.assertIsNotNone(row['metadata'])
                                    self.assertEqual(clock.value, original_until)
                                    body._close_file(row)
                                    self.assertIs(row['closed'], True)
                                    self.assertIs(row['close_called'], True)
                                    count = dict(io.close_calls)
                                    body._close_file(row)
                                    self.assertEqual(io.close_calls, count)
                                    self.assertEqual(io.close_calls[row['fd']], 1)
                                    self.assertFalse(io.live)
                                elif name == 'helper_current_late_zero_spawn':
                                    io.late_helper_current = True
                                    with self.assertRaises(module.ReadonlyPreflightError) as caught:
                                        body._helper(module.HELPERS[0])
                                    self.assertEqual(str(caught.exception), 'readonly_expired')
                                    self.assertEqual(len(body.rows), 1)
                                    self.assertEqual(body.probes, [])
                                    self.assertEqual(io.spawned, [])
                                    row = body.rows[0]
                                    self.assertEqual(row['raw'], native[0])
                                    body._close_file(row)
                                    self.assertTrue(row['closed'])
                                    self.assertFalse(io.live)
                                    self.assertEqual(io.close_calls[row['fd']], 1)
                                elif name == 'duplicate_pipe_fd_unknown':
                                    io.duplicate_pipes = True
                                    with self.assertRaises(module.ReadonlyPreflightError) as caught:
                                        body._helper(module.HELPERS[0])
                                    self.assertEqual(str(caught.exception), 'readonly_helper_pipe')
                                    self.assertEqual(len(body.probes), 1)
                                    probe = body.probes[0]
                                    self.assertEqual(len(probe['pipes']), 2)
                                    first, second = probe['pipes']
                                    self.assertEqual(first['fd'], second['fd'])
                                    self.assertIs(first['unknown'], False)
                                    self.assertIs(second['unknown'], True)
                                    self.assertIsNone(second['metadata'])
                                    body._close_probe(probe)
                                    body._close_file(body.rows[0])
                                    self.assertIs(first['closed'], True)
                                    self.assertIs(second['closed'], False)
                                    self.assertTrue(body.unknown)
                                    self.assertIs(probe['closed'], False)
                                    self.assertTrue(body.status()['resource_pending'])
                                    self.assertEqual(io.spawned[0].kill_count, 1)
                                    self.assertEqual(io.spawned[0].wait_count, 1)
                                    self.assertEqual(io.spawned[0].stdout.close_count, 1)
                                    self.assertEqual(io.spawned[0].stderr.close_count, 0)
                                    counts = (dict(io.close_calls), io.spawned[0].kill_count,
                                              io.spawned[0].wait_count)
                                    body._close_probe(probe)
                                    body._close_file(body.rows[0])
                                    self.assertEqual(counts, (io.close_calls, io.spawned[0].kill_count,
                                                             io.spawned[0].wait_count))
                                    self.assertFalse(io.live)  # Numeric absence never clears unknown.
                                else:
                                    error = (OSError(errno.ENOENT, 'HOST85 known unopened') if
                                             name == 'open_enoent_known_no_fd' else OSError('HOST85 unknown return'))
                                    io.open_error = error
                                    with self.assertRaises(OSError) as caught:
                                        body._open(module.DEVICE_LOCK)
                                    self.assertIs(caught.exception, error)
                                    row = body.rows[0]
                                    self.assertIs(row['open_error'], error)
                                    self.assertIsNone(row['fd'])
                                    self.assertIsNone(row['metadata'])
                                    known = name == 'open_enoent_known_no_fd'
                                    self.assertIs(row['closed'], known)
                                    self.assertIs(row['unknown'], not known)
                                    self.assertIs(body.unknown, not known)
                                    body._close_file(row)
                                    body._close_file(row)
                                    self.assertEqual(io.close_calls, {})
                                    self.assertFalse(io.live)
                                self.assertIs(body.until, original_until)
                                self.assertIs(body.cleanup_until, original_cleanup)
                                self.assertFalse(body.called)
                                self.assertFalse(body.ended)
                                self.assertIsNone(body.owner)
                                self.assertIsNone(body.snapshot)
                                self.assertIsNone(body.result)
                                self.assertFalse(body.status()['rf_requested'])
                                self.assertFalse(body.status()['restoration_verified'])
                                self.assertFalse(body.status()['production_admitted'])
                                self.assertEqual(collect.call_count, 0)
                                self.assertTrue(all(wire.call_count == 0 for wire in tripwires))
                                completed.append(name)
                            finally:
                                # Independent original cleanup attempts; keep primary errors.
                                for probe in reversed(body.probes):
                                    body._close_probe(probe)
                                for row in reversed(body.rows):
                                    body._close_file(row)
                domain.source_closed()
            finally:
                domain.teardown()

            with self.subTest(case='loader_late_read_retained'):
                domain = _Domain(self, sources, loader_raw, load=False, late_read=True)
                try:
                    original = domain.loader.until
                    with self.assertRaises(domain.module.ReadonlyLoaderError) as caught:
                        domain.loader.load()
                    self.assertEqual(caught.exception.code, 'deadline')
                    self.assertIs(domain.loader.failure, caught.exception)
                    self.assertEqual(domain.loader.deadline, 11.0)
                    self.assertIs(domain.loader.until, original)
                    self.assertEqual(len(domain.loader.rows), 1)
                    self.assertEqual(domain.loader.modules, {})
                    row = domain.loader.rows[0]
                    self.assertEqual(row['name'], 'p011_json')
                    self.assertEqual(row['read_values'], [sources[0][4]])
                    self.assertIsNone(row['raw'])
                    self.assertIs(row['read_error'], caught.exception)
                    domain.source_closed()
                    self.assertFalse(domain.loader.pending)
                    with self.assertRaises(domain.module.ReadonlyLoaderError) as unavailable:
                        domain.loader.authenticate()
                    self.assertEqual(unavailable.exception.code, 'source_unavailable')
                    completed.append('loader_late_read_retained')
                finally:
                    domain.teardown()
            self.assertTrue(all(wire.call_count == 0 for wire in tripwires))
        self.assertEqual(completed, ['actual_38_definitions', 'anchors_late_zero_open',
            'returned_fd_late_close_only', 'helper_current_late_zero_spawn',
            'duplicate_pipe_fd_unknown', 'open_enoent_known_no_fd',
            'open_errno_none_unknown', 'loader_late_read_retained'])
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
