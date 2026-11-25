# -*- coding: utf-8 -*-
"""One new Boot83 method / four affected definition-only HOST domains.

Actual frozen Boot83 load/authenticate and all 26 ordinary definitions execute
in a fixture-only canonical namespace. Fixed source bytes are real workspace
inputs; filesystem metadata, source FD/EBADF, PID and clock are explicit models.
No State, helper, Server, Parent, private CLIENT35/GO24 Loader or RF is run.
Fixture teardown removes ONLY its retained exact installed module objects;
this is test isolation, not a candidate/production namespace rollback.
No previous TestCase/helper/method is imported or replayed.
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
SOURCE_INPUTS = (
    ("boot", "candidate/go-send-fixed-boot-v83/runtime/mta_client_receive_boot.py", 18910, "43c095f8bf78cf7fff493f76645a700c67a9c278a423ab531b1954109a6bc1b1"),
    ("mta_client_executor", "candidate/client-integrated-v37/runtime/mta_client_executor.py", 105182, "f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e"),
    ("p011_json", "runtime/p011_json.py", 8061, "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88"),
    ("mta_protocol", "runtime/mta_protocol.py", 17958, "4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57"),
    ("mta_storage", "runtime/mta_storage.py", 14335, "3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6"),
    ("mta_files", "runtime/mta_files.py", 10267, "c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae"),
    ("mta_crypto", "runtime/mta_crypto.py", 15274, "6fde6a60ec327895938a59990c4734a923dd5ff68bd5ee6979791df9a607e516"),
    ("mta_transfer_session", "candidate/go-send-state-v78/runtime/mta_transfer_session.py", 20633, "e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859"),
    ("mta_dhcp", "runtime/mta_dhcp.py", 15719, "631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176"),
    ("mta_dhcp_server", "runtime/mta_dhcp_server.py", 20515, "a34fdbc07a96f2ed3337872612510aa2a8b72b970a193f58b8045c0653b8d8bc"),
    ("mta_scoped_sockets", "runtime/mta_scoped_sockets.py", 26339, "b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8"),
    ("mta_transport", "runtime/mta_transport.py", 31883, "29e5ea6bf8f5de9ddae33824c158f4e401bab391d51b18dc0b8a1ab2cbc2dc72"),
    ("mta_sender", "runtime/mta_sender.py", 33949, "da25d3359d0759f71d8a4483680e3a3d5376c9e745e85224dbaee2a672f0670a"),
    ("mta_send_worker", "runtime/mta_send_worker.py", 43252, "de0dd8c2c0fb3b45923199ccc987ae057046fa0244c6a405c3a254850f7e68e7"),
    ("mta_scan_handoff", "runtime/mta_scan_handoff.py", 11515, "51af67e80cf64038160cf420ad08f4f255a15dd9577e14fdcdb44fc26711046a"),
    ("mta_wifi", "runtime/mta_wifi.py", 28459, "62322b09fe4fd96bf6d49d8a2f7ac416e9a9d4dadcb3df23a6330e3205bcd017"),
    ("minhttp", "runtime/minhttp.py", 9305, "582ab73570e37bb67422bf2b216374ec290a038ce726c015af60e0e12d647dde"),
    ("mta_client_control_frame", "candidate/client-integrated-v37/runtime/mta_client_control_frame.py", 20942, "d1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278"),
    ("mta_client_connect_handoff", "candidate/client-connect-v13/runtime/mta_client_connect_handoff.py", 10533, "aeade54eac7ed055936d7004087aa2a30a731ee7742365080cbd037264a58cc4"),
    ("mta_client_tmp_alias", "candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py", 8827, "1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f"),
    ("mta_client_receive_factory", "candidate/client-receive-factory-v69-r3/runtime/mta_client_receive_factory.py", 54158, "29265227937c2191e8af7a90a25ee518c87e6cb2a28162a99f883196bd9d7329"),
    ("mta_client_state_bridge", "candidate/client-receive-factory-v69/runtime/mta_client_state_bridge.py", 21283, "17d3c5339c1e68bf5eb68308858144d687b1b17616cbeaa0817bad91bd33b8fd"),
    ("mta_go_deployment", "candidate/go-send-transport-v76/runtime/mta_go_deployment.py", 26113, "3abac40ec1fc0a6d223a7238cd10eb86fd2942407ec26156484826021eb161e8"),
    ("mta_send_preparation", "runtime/mta_send_preparation.py", 28532, "0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814"),
    ("mta_go_send_publication", "candidate/go-send-preflight-v82-r2/runtime/mta_go_send_publication.py", 34324, "ce61cc7a3b59f1e311078ccd590e1af001ffb95c378008767778f047ca8e38e2"),
    ("mta_go_send_bridge", "candidate/go-send-key-close-v79/runtime/mta_go_send_bridge.py", 63045, "49d4a28c2156b8b99d0ac5965ec4f3cd4bdf617dddfbfcca90073e08e6a50cb4"),
    ("mta_service", "candidate/go-send-state-v78/runtime/mta_service.py", 84637, "b7729b6d0272b83a9c2af9e7b3003b97f68bc0fa15038c214ec8e04b7bb41998"),
)
BOOT_NAME = 'mta_client_receive_boot_v83_fixture'
DEFINITION_MANIFEST = ('host/go_send_fixed_boot_v83_definition_manifest.json', 5830,
                       'aa566a842378082c53b762c30cf6cbc30c2345e60d11107a3fb5a32e9108f945')
MARKER = ('HOST83_FIXED_BOOT new_methods=1 old_methods=0 cases=4 '
          'filesystem_model=true device=false phone=false\n')


def _inputs():
    result = []
    for name, path, size, pin in SOURCE_INPUTS:
        raw = (ROOT / path).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
            raise AssertionError('fixed Boot83 SOURCE changed: ' + path)
        result.append((name, path, size, pin, raw))
    if len(result) != 27 or result[0][0] != 'boot':
        raise AssertionError('fixed Boot83 source input count')
    path, size, pin = DEFINITION_MANIFEST
    raw = (ROOT / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('fixed Boot83 definition manifest changed')
    expected = [dict(module=name, path=source_path, bytes=source_size, sha256=source_pin)
                for name, source_path, source_size, source_pin in SOURCE_INPUTS[1:]]
    unused_name, source_path, source_size, source_pin = SOURCE_INPUTS[0]
    expected.append(dict(module='mta_client_receive_boot', path=source_path,
                         bytes=source_size, sha256=source_pin))
    if json.loads(raw.decode('ascii')) != {
            'schema': 'go-send-fixed-boot-v83-definitions', 'sources': expected}:
        raise AssertionError('fixed Boot83 definition manifest source order/roles')
    return result[0][4], tuple(result[1:])


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
        if value is None: raise OSError(errno.ENOENT, 'HOST83 model source absent')
        return value.metadata()
    def readlink(self, path):
        self.events.append(('readlink', path))
        value = self.nodes.get(path)
        if value is None or value.target is None:
            raise OSError(errno.EINVAL, 'HOST83 model link absent')
        return value.target
    def open(self, path):
        self.events.append(('open', path))
        value = self.nodes.get(self.physical(path))
        if value is None or not stat.S_ISREG(value.mode):
            raise OSError(errno.ENOENT, 'HOST83 model source absent')
        fd = self.next_fd
        self.next_fd += 1
        row = {'fd': fd, 'path': path, 'node': value, 'offset': 0}
        self.live[fd] = row
        self.history.append(row)
        return fd
    def fstat(self, fd):
        self.events.append(('fstat', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST83 model original FD closed')
        return self.live[fd]['node'].metadata()
    def read(self, fd, count):
        self.events.append(('read', fd, count))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST83 model original FD closed')
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
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST83 model original double close')
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
        self.boot.__file__ = '/HOST83/fixture-only/mta_client_receive_boot.py'
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


class GoSendFixedBoot83Test(unittest.TestCase):
    def test_fixed_ordinary_roles_and_asset_refusals(self):
        raw_boot, sources = _inputs()
        completed = []
        with mock.patch('subprocess.Popen', side_effect=AssertionError('HOST83 no process')) as spawn, \
                mock.patch('socket.socket', side_effect=AssertionError('HOST83 no socket')) as socket_ctor, \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('HOST83 no native crypto')) as native_crypto, \
                mock.patch('threading.Thread.start', side_effect=AssertionError('HOST83 no worker')) as worker, \
                mock.patch('os.mkdir', side_effect=AssertionError('HOST83 no target directory')) as mkdir:
            for name in ('normal_26_roles', 'unsafe_asset_directory', 'wrong_loader_state_path',
                         'loaded_loader_file_changed'):
                with self.subTest(case=name):
                    before_calls = tuple(p.call_count for p in (spawn, socket_ctor, native_crypto, worker, mkdir))
                    fixture = _Fixture(self, raw_boot, sources)
                    try:
                        boot, loader, io = fixture.boot, fixture.loader, fixture.io
                        asset_file = io.asset_root + '/runtime/mta_go_deployment.py'
                        state_file = io.physical_root + '/runtime/mta_go_deployment.py'
                        if name == 'unsafe_asset_directory':
                            io.nodes[io.asset_root].mode = stat.S_IFDIR | 0o755
                            with self.assertRaises(boot.ReceiveBootError) as caught: loader.load()
                            self.assertEqual(caught.exception.code, 'unsafe_root')
                            self.assertIs(loader.failure, caught.exception)
                            self.assertEqual(io.history, [])
                            self.assertFalse(any(e[0] == 'open' for e in io.events))
                            self.assertEqual(loader.module_originals, [])
                            self.assertFalse(loader.pending)
                        elif name == 'wrong_loader_state_path':
                            misplaced = io.nodes.pop(asset_file)
                            io.nodes[state_file] = misplaced
                            with self.assertRaises(OSError) as caught: loader.load()
                            self.assertEqual(caught.exception.errno, errno.ENOENT)
                            self.assertIs(loader.failure, caught.exception)
                            self.assertTrue(loader.pending) # Original no-return ticket is retained.
                            self.assertEqual(len(loader.modules), 21)
                            self.assertEqual(len(loader.rows), 22)
                            original = loader.rows[-1]
                            self.assertEqual(original['path'], asset_file)
                            self.assertIs(original['fd'], None)
                            self.assertIs(original['unknown'], True)
                            self.assertIs(original['open_error'], caught.exception)
                            self.assertFalse(any(e[0] == 'open' and e[1] == state_file for e in io.events))
                            self.assertNotIn('mta_go_deployment', sys.modules)
                            self.assertIs(sys.modules['mta_client_executor'], loader.modules['mta_client_executor'])
                        else:
                            self.assertIs(loader.load(), loader)
                            self.assertIs(loader.authenticate(), loader)
                            self.assertEqual(len(loader.rows), 26)
                            self.assertEqual(len(loader.modules), 26)
                            self.assertFalse(loader.pending)
                            go = loader.modules['mta_go_deployment']
                            self.assertEqual(go.__file__, asset_file)
                            self.assertEqual(boot._source_paths('mta_go_deployment'), (asset_file, asset_file))
                            self.assertEqual(go.GoDeploymentLoader.__init__.__globals__['ROOT'],
                                             '/var/volatile/tmp/p011-mta-go-session')
                            self.assertIs(loader.modules['mta_go_send_publication'].sources, go)
                            self.assertIsNone(loader.modules['mta_go_send_publication'].BUNDLE_MANIFEST_SHA)
                            self.assertIs(loader.modules['mta_send_preparation'].files, loader.modules['mta_files'])
                            self.assertIs(loader.modules['mta_service'].TransferSession,
                                          loader.modules['mta_transfer_session'].TransferSession)
                            self.assertIn('absolute_until', loader.modules['mta_transfer_session']
                                          .TransferSession.__init__.__code__.co_varnames)
                            self.assertIs(sys.modules['mta_client_executor'], loader.modules['mta_client_executor'])
                            for modname, module in loader.modules.items():
                                expected = asset_file if modname == 'mta_go_deployment' else (
                                    '/tmp/p011-mta-state-v69/runtime/' + modname + '.py')
                                self.assertEqual(module.__file__, expected)
                                self.assertIs(sys.modules[modname], module)
                            # The actual private F graphs are declared but not loaded here.
                            for private in ('mta_go_executor', 'mta_go_native', 'mta_go_bootstrap',
                                            'mta_client_linux_provider', 'mta_client_store', 'mta_client_proc'):
                                self.assertNotIn(private, sys.modules)
                            self.assertIn('mta_go_executor', go.MODULES)
                            self.assertEqual(len(go.MODULES), 24)
                            if name == 'loaded_loader_file_changed':
                                go.__file__ = '/tmp/p011-mta-state-v69/runtime/mta_go_deployment.py'
                                with self.assertRaises(boot.ReceiveBootError) as caught: loader.authenticate()
                                self.assertEqual(caught.exception.code, 'source_changed')
                                self.assertIs(loader.modules['mta_go_deployment'], go)
                                self.assertFalse(loader.pending) # Closed source FDs remain known.
                        fixture.closed_returned_fds()
                        self.assertEqual(tuple(p.call_count for p in
                            (spawn, socket_ctor, native_crypto, worker, mkdir)), before_calls)
                        completed.append(name)
                    finally:
                        fixture.teardown()
        self.assertEqual(completed, ['normal_26_roles', 'unsafe_asset_directory',
                                     'wrong_loader_state_path', 'loaded_loader_file_changed'])
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
