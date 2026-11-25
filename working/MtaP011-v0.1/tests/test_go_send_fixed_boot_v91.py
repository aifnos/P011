# -*- coding: utf-8 -*-
"""HOST91 only: changed 27-role graph and new Parent role identity.

Actual Boot91 load/authenticate and original Owner91 _boot_roles execute.
All ordinary source bytes are fixed inputs; FS/FD/PID/clock are explicit models.
The Owner constructor/start/State/Server/Parent collector are NOT executed:
a pre-construction role-only object binds the actual loaded Boot definitions.
No old TestCase is imported; no old83 refusal/FD domains are redispatched.
"""
import ctypes
import ctypes.util
import errno
import hashlib
import json
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import threading
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BOOT_NAME = 'mta_client_receive_boot_v91_fixture'
DEFINITION_MANIFEST = ('host/go_send_fixed_boot_v91_definition_manifest.json',
                       6336, '85db83d08153a8ca001d5f9d54b9a838b6bd4ed79e6dd2b1fa0da7291c9a14db')
MARKER = ('HOST91_FIXED_BOOT new_methods=1 old_methods=0 cases=2 roles=27 '
          'filesystem_model=true owner_roles_only=true device=false phone=false\n')

def _inputs():
    path, size, pin = DEFINITION_MANIFEST
    raw = (ROOT / path).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, pin):
        raise AssertionError('fixed definition map changed')
    plan = json.loads(raw.decode('ascii'))
    if (set(plan) != {'schema', 'sources'} or
            plan['schema'] != 'go-send-fixed-boot-v91-definitions' or
            type(plan['sources']) is not list or len(plan['sources']) != 29):
        raise AssertionError('fixed definition map shape')
    rows, names = [], []
    for item in plan['sources']:
        if set(item) != {'module', 'path', 'bytes', 'sha256'}:
            raise AssertionError('definition map row shape')
        name, source = item['module'], item['path']
        if (type(name) is not str or type(source) is not str or source.startswith('/') or
                ':' in source or '\\' in source or '..' in source.split('/') or name in names):
            raise AssertionError('definition map path changed')
        value = (ROOT / source).read_bytes()
        if (len(value), hashlib.sha256(value).hexdigest()) != (item['bytes'], item['sha256']):
            raise AssertionError('fixed definition SOURCE changed')
        names.append(name)
        rows.append((name, source, item['bytes'], item['sha256'], value))
    if names[-2:] != ['mta_client_receive_boot', 'mta_client_service_owner']:
        raise AssertionError('fixed owner/boot roles changed')
    return rows[-2][4], tuple(rows[:-2]), rows[-1][4], (rows[-2][2], rows[-2][3])

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
        return types.SimpleNamespace(st_dev=83, st_ino=self.ino, st_mode=self.mode,
            st_uid=0, st_gid=0, st_nlink=2 if stat.S_ISDIR(self.mode) else 1,
            st_size=size, st_mtime_ns=1000000000 + self.ino,
            st_ctime_ns=2000000000 + self.ino)


class _FixedModelIo(object):
    """No target filesystem syscall: actual pinned bytes + explicit FD model."""
    def __init__(self, sources):
        self.nodes, self.live, self.history, self.events, self.close_calls = {}, {}, [], [], {}
        self.next_fd, self.validate_calls = 8300, 0
        self.state_root = '/tmp/p011-mta-state-v69'
        self.physical_root = '/var/volatile/tmp/p011-mta-state-v69'
        self.asset_root = '/var/volatile/tmp/p011-mta-go-send-v76-assets'
        for path, mode, target in (
                ('/', stat.S_IFDIR | 0o755, None),
                ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                (self.physical_root, stat.S_IFDIR | 0o700, None),
                (self.physical_root + '/runtime', stat.S_IFDIR | 0o700, None),
                (self.asset_root, stat.S_IFDIR | 0o700, None),
                (self.asset_root + '/runtime', stat.S_IFDIR | 0o700, None)):
            self.add(path, mode, target=target)
        for name, unused_path, unused_size, unused_pin, raw in sources:
            root = self.asset_root if name == 'mta_go_deployment' else self.physical_root
            self.add(root + '/runtime/' + name + '.py', stat.S_IFREG | 0o400, raw)
    def add(self, path, mode, raw=b'', target=None):
        value = _Node(len(self.nodes) + 100, mode, raw, target)
        self.nodes[path] = value
        return value
    def physical(self, path):
        if path == self.state_root or path.startswith(self.state_root + '/'):
            return self.physical_root + path[len(self.state_root):]
        return path
    def validate(self):
        self.validate_calls += 1
        self.events.append(('model_validate_not_arm',))
    def pid(self):
        self.events.append(('model_pid',))
        return 8301
    def stat(self, path):
        self.events.append(('stat', path))
        value = self.nodes.get(self.physical(path))
        if value is None: raise OSError(errno.ENOENT, 'HOST91 model source absent')
        return value.metadata()
    def readlink(self, path):
        self.events.append(('readlink', path))
        value = self.nodes.get(path)
        if value is None or value.target is None:
            raise OSError(errno.EINVAL, 'HOST91 model link absent')
        return value.target
    def open(self, path):
        self.events.append(('open', path))
        value = self.nodes.get(self.physical(path))
        if value is None or not stat.S_ISREG(value.mode):
            raise OSError(errno.ENOENT, 'HOST91 model source absent')
        fd = self.next_fd
        self.next_fd += 1
        row = {'fd': fd, 'path': path, 'node': value, 'offset': 0}
        self.live[fd] = row
        self.history.append(row)
        return fd
    def fstat(self, fd):
        self.events.append(('fstat', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST91 model original FD closed')
        return self.live[fd]['node'].metadata()
    def read(self, fd, count):
        self.events.append(('read', fd, count))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST91 model original FD closed')
        if type(count) is not int or not 0 < count <= 65536:
            raise AssertionError('model bounded source read')
        row = self.live[fd]
        start = row['offset']
        value = row['node'].raw[start:start + count]
        row['offset'] += len(value)
        return value
    def close(self, fd):
        self.events.append(('close', fd))
        self.close_calls[fd] = self.close_calls.get(fd, 0) + 1
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST91 model original double close')
        del self.live[fd]
        return None


class _Fixture(object):
    def __init__(self, case, raw_boot, sources):
        self.case, self.sources = case, sources
        self.names = tuple(r[0] for r in sources) + (BOOT_NAME,)
        self.before = dict((name, sys.modules.get(name)) for name in self.names)
        # Never erase/adopt a foreign ordinary definition to make Boot succeed.
        case.assertTrue(all(value is None for value in self.before.values()))
        self.boot = types.ModuleType(BOOT_NAME)
        self.boot.__file__ = '/HOST91/fixture-only/mta_client_receive_boot.py'
        self.io, self.clock = _FixedModelIo(sources), _Clock()
        self.loader = None
        sys.modules[BOOT_NAME] = self.boot
        try:
            exec(compile(raw_boot, self.boot.__file__, 'exec'), self.boot.__dict__)
            case.assertEqual(self.boot.MODULES, tuple(r[0] for r in sources))
            case.assertEqual(self.boot.SOURCE_PINS,
                             tuple((name, size, pin) for name, path, size, pin, raw in sources))
            self.loader = self.boot.BootSourceLoader(30.0, _io=self.io, _clock=self.clock)
            case.assertEqual(self.io.events, []) # Actual constructor does no IO/clock.
        except BaseException:
            self.teardown()
            raise
    def teardown(self):
        installed = [] if self.loader is None else self.loader.module_originals
        for name, module, original_dict in reversed(installed):
            if sys.modules.get(name) is module and module.__dict__ is original_dict:
                del sys.modules[name]
        if sys.modules.get(BOOT_NAME) is self.boot: del sys.modules[BOOT_NAME]
        # Check only retained fixture names; never remove a foreign replacement.
        for name, value in self.before.items():
            self.case.assertIs(sys.modules.get(name), value)
    def closed_returned_fds(self):
        case = self.case
        case.assertFalse(self.io.live)
        case.assertEqual(len(self.io.close_calls), len(self.io.history))
        case.assertTrue(all(count == 1 for count in self.io.close_calls.values()))
        for row in self.loader.rows:
            if row['fd'] is None: continue
            case.assertIs(row['closed'], True)
            case.assertIs(row['unknown'], False)
            case.assertIs(row['attempted'], True)
            case.assertIs(row['close_return'], None)
            case.assertEqual(self.io.close_calls[row['fd']], 1)
            with case.assertRaises(OSError) as caught: self.io.fstat(row['fd'])
            case.assertEqual(caught.exception.errno, errno.EBADF)



class GoSendFixedBoot91Test(unittest.TestCase):
    def test_changed_graph_and_parent_role_identity(self):
        raw_boot, sources, raw_owner, boot_pin = _inputs()
        completed = []
        with mock.patch('subprocess.Popen', side_effect=AssertionError('HOST91 no process')) as spawn, \
                mock.patch('socket.socket', side_effect=AssertionError('HOST91 no socket')) as socket_ctor, \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('HOST91 no native crypto')) as crypto, \
                mock.patch('threading.Thread.start', side_effect=AssertionError('HOST91 no worker')) as worker, \
                mock.patch('os.mkdir', side_effect=AssertionError('HOST91 no directory')) as mkdir:
            for case in ('changed_27_role_graph', 'new_parent_role_file_changed'):
                with self.subTest(case=case):
                    fixture = _Fixture(self, raw_boot, sources)
                    try:
                        boot, loader = fixture.boot, fixture.loader
                        self.assertIs(loader.load(), loader)
                        self.assertIs(loader.authenticate(), loader)
                        self.assertEqual(len(loader.modules), 27)
                        self.assertEqual(len(loader.rows), 27)
                        owner_module = types.ModuleType('mta_client_service_owner_v91_fixture')
                        owner_module.__file__ = '/HOST91/fixture-only/mta_client_service_owner.py'
                        exec(compile(raw_owner, owner_module.__file__, 'exec'), owner_module.__dict__)
                        self.assertEqual(owner_module.BOOT_PIN, boot_pin)
                        self.assertEqual(owner_module.BOOT_SCHEMA, boot.SOURCE_SCHEMA)
                        self.assertEqual(owner_module.BOOT_MODULES, boot.MODULES)
                        # Explicit DATA-only pre-construction model. No owner.start/constructor.
                        role_owner = owner_module.FixedStateServiceOwner.__new__(
                            owner_module.FixedStateServiceOwner)
                        role_owner.boot, role_owner.loader = boot, loader
                        self.assertIsNone(owner_module.FixedStateServiceOwner._boot_roles(role_owner))
                        parent = loader.modules['mta_go_readonly_parent']
                        pub = loader.modules['mta_go_send_publication']
                        go = loader.modules['mta_go_deployment']
                        self.assertIs(pub.observer, parent)
                        self.assertIs(pub._OBSERVER_ORIGINAL[0], parent)
                        self.assertIs(pub._OBSERVER_ORIGINAL[1], parent.ReadonlyDataParent)
                        self.assertIs(pub.sources, go)
                        self.assertIsNone(pub.BUNDLE_MANIFEST_SHA)
                        self.assertEqual(go.__file__, boot.GO_ASSET_RUNTIME + '/mta_go_deployment.py')
                        self.assertEqual(len(go.MODULES), 25)
                        self.assertIn('mta_snapshot_data', go.MODULES)
                        self.assertIs(loader.modules['mta_service'].TransferSession,
                                      loader.modules['mta_transfer_session'].TransferSession)
                        self.assertEqual(boot.MODULES.index('mta_go_readonly_parent') + 1,
                                         boot.MODULES.index('mta_go_send_publication'))
                        for private in ('mta_go_executor', 'mta_go_native', 'mta_go_bootstrap',
                                        'mta_snapshot_data', 'mta_client_store', 'mta_observer_packet'):
                            self.assertNotIn(private, sys.modules)
                        if case == 'new_parent_role_file_changed':
                            parent.__file__ = '/HOST91/foreign-parent.py'
                            with self.assertRaises(boot.ReceiveBootError) as caught:
                                loader.authenticate()
                            self.assertEqual(caught.exception.code, 'source_changed')
                            with self.assertRaises(owner_module.ServiceOwnerError) as caught:
                                owner_module.FixedStateServiceOwner._boot_roles(role_owner)
                            self.assertEqual(caught.exception.code, 'boot_roles_changed')
                        fixture.closed_returned_fds()
                        self.assertFalse(loader.pending)
                        self.assertEqual(tuple(p.call_count for p in
                            (spawn, socket_ctor, crypto, worker, mkdir)), (0, 0, 0, 0, 0))
                        completed.append(case)
                    finally:
                        fixture.teardown()
        self.assertEqual(completed, ['changed_27_role_graph', 'new_parent_role_file_changed'])
        sys.stdout.write(MARKER)

if __name__ == '__main__':
    unittest.main()

