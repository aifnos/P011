"""One new HOST actual-Loader definition test; no lifecycle or device approval.

The frozen 35-source manifest supplies original source bytes. The original
DeploymentLoader.load, ProviderManifest, file ledger, pinned imports and codec
run in this one method. The executing F module is registered in sys.modules;
it must remain the SAME module/classes after all later DHCP/receive definitions
load. No earlier lifecycle TestCase or collaborator is imported/executed.

The filesystem, root metadata, fixed /tmp alias and preparation clock below
are explicitly in-memory HOST models. Python ELF bytes are fictional. WPA ELF
bytes are the real locally pinned artifact, read/hashed only and never executed.
Neither model validation nor ELF magic proves P011 ABI, Linux permissions,
real elapsed time, native executable compatibility, RF, transfer or restoration.

Only this new source is delivered. Root owns its sole first execution.
"""
import base64
import builtins
from contextlib import ExitStack
import contextlib
import ctypes
import errno
import hashlib
import hmac
import json as host_json
import math
import os
from pathlib import Path
import re
import select
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import zipfile
import zlib


BASE = Path(__file__).resolve().parents[1]
MANIFEST = 'host/client_transfer_executor_v31_source_manifest.json'
MANIFEST_SHA = '35e6f1ba210f9fbd476f866c35e66b01c8d707dea017beae067c6f75d4b2fc9a'
MANIFEST_BYTES = 8081
F_PIN = 'f499f897a15b8c4e26e9a30fb093f5632bcdc800af97397a473f0afcd3467682'
F_PATH = 'candidate/client-transfer-executor-v31/runtime/mta_client_executor.py'
WPA_PATH = 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant'
WPA_PIN = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
RUNNING_F_NAME = 'host_actual_deployment_loader_v31_f'
STOCK_PINS = (
    ('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'),
)


def frozen_inputs():
    """Read PC source/artifact bytes before live-IO tripwires are installed."""
    manifest_raw = (BASE / MANIFEST).read_bytes()
    if len(manifest_raw) != MANIFEST_BYTES or hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_SHA:
        raise ValueError('HOST Loader fixed source map changed')
    tree = host_json.loads(manifest_raw.decode('utf-8'))
    if tree.get('schema') != 'client-transfer-executor-v31-host' or type(tree.get('sources')) is not list:
        raise ValueError('HOST Loader fixed source map schema changed')
    rows = tree['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST Loader fixed graph changed')
    sources = {}
    for row in rows:
        raw = (BASE / row['path']).read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('HOST Loader fixed source bytes changed')
        sources[row['module']] = raw
    f_row = next(row for row in rows if row['module'] == 'mta_client_executor')
    if f_row['path'] != F_PATH or f_row['sha256'] != F_PIN:
        raise ValueError('HOST Loader fixed F source changed')
    wpa = (BASE / WPA_PATH).read_bytes()
    if len(wpa) != WPA_BYTES or hashlib.sha256(wpa).hexdigest() != WPA_PIN or not wpa.startswith(b'\x7fELF'):
        raise ValueError('HOST Loader pinned local WPA ELF bytes changed')
    return rows, sources, wpa


class HostPreparationClock(object):
    """Zero-cost HOST preparation model, not a real 10-second timing result."""
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class HostLoaderFileMap(object):
    """Only the explicit model paths below exist; descriptors are fictional.

    stat/readlink never consult Windows or Linux. All metadata is modeled root
    metadata, not observed P011 ownership. Logical /tmp file paths and their
    physical /var/volatile/tmp pairs share the same modeled original inode.
    """
    def __init__(self, files, private_root, physical_root, receive_root):
        self.files, self.private_root = {}, private_root
        self.physical_root, self.receive_root = physical_root, receive_root
        self.descriptors, self.opens, self.reads, self.closes = {}, [], [], []
        self.stat_calls, self.readlink_calls, self.validations = [], [], []
        self.machine_model = ('HOST-memory-map', 'modeled-linux', 'modeled-armv7l', 'modeled-root')
        self.links = {'/tmp': '/var/tmp', '/var/tmp': '/var/volatile/tmp'}
        self.directories = {'/', '/var', '/var/volatile', '/var/volatile/tmp', '/usr', '/usr/bin'}
        for name, raw in files.items():
            physical = self.canonical(name)
            if physical in self.files and self.files[physical] != raw:
                raise ValueError('HOST Loader duplicate modeled file mismatch')
            self.files[physical] = raw
            pieces = physical[1:].split('/')
            self.directories.update('/' + '/'.join(pieces[:at]) for at in range(1, len(pieces)))
        pieces = receive_root[1:].split('/')
        self.directories.update('/' + '/'.join(pieces[:at]) for at in range(1, len(pieces) + 1))

    def canonical(self, path):
        if path.startswith('/tmp/'): return '/var/volatile/tmp/' + path[len('/tmp/'):]
        if path.startswith('/var/tmp/'): return '/var/volatile/tmp/' + path[len('/var/tmp/'):]
        return path

    def validate(self):
        # This is the private IO seam. It does not call actual _LinuxIo.validate
        # or assert anything about the host OS/target platform.
        self.validations.append(self.machine_model)
        return None

    def stat(self, path):
        self.stat_calls.append(path)
        link = self.links.get(path)
        canonical = self.canonical(path)
        if link is not None:
            mode, count, size = stat.S_IFLNK | 0o777, 1, len(link)
        elif canonical in self.files:
            private = canonical == self.physical_root or canonical.startswith(self.physical_root + '/')
            executable = canonical.endswith('/native/mta-wpa-supplicant') or canonical == '/usr/bin/python-fixture'
            permissions = 0o500 if executable and private else 0o555 if executable else 0o400
            mode, count, size = stat.S_IFREG | permissions, 1, len(self.files[canonical])
        elif canonical in self.directories:
            permissions = 0o1777 if canonical in ('/var/volatile', '/var/volatile/tmp') else \
                0o700 if canonical == self.physical_root or canonical.startswith(self.physical_root + '/') or \
                canonical in ('/mnt/data/p011-toolbox/user', self.receive_root) else 0o755
            mode, count, size = stat.S_IFDIR | permissions, 2, 4096
        else:
            raise AssertionError('unmapped path cannot reach a real filesystem: ' + path)
        inode = int.from_bytes(hashlib.sha256(canonical.encode('ascii')).digest()[:8], 'little') or 1
        return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode,
            st_uid=0, st_gid=0, st_nlink=count, st_size=size,
            st_mtime_ns=1000000000, st_ctime_ns=1000000000)

    def readlink(self, path):
        self.readlink_calls.append(path)
        if path not in self.links: raise AssertionError('unmapped link cannot reach an OS')
        return self.links[path]

    def open(self, path):
        canonical = self.canonical(path)
        if canonical not in self.files: raise AssertionError('unmapped open cannot reach an OS')
        fd = 10000 + len(self.opens)
        self.descriptors[fd] = {'path': path, 'raw': self.files[canonical], 'at': 0, 'closed': False}
        self.opens.append((fd, path))
        return fd

    def _descriptor(self, fd):
        row = self.descriptors.get(fd)
        if row is None or row['closed']: raise OSError(errno.EBADF, 'HOST fictional descriptor closed')
        return row

    def read(self, fd, count):
        row = self._descriptor(fd)
        raw = row['raw'][row['at']:row['at'] + count]
        row['at'] += len(raw); self.reads.append((fd, count, len(raw)))
        return raw

    def fstat(self, fd): return self.stat(self._descriptor(fd)['path'])

    def close(self, fd):
        row = self._descriptor(fd)
        if fd in self.closes: raise AssertionError('HOST Loader raw close must not be retried')
        row['closed'] = True; self.closes.append(fd)
        return None


class DeploymentLoaderV31Tests(unittest.TestCase):
    def test_actual_loader35_retains_running_f_and_later_dhcp_codec_definitions(self):
        rows, sources, wpa_raw = frozen_inputs()
        running_f = types.ModuleType(RUNNING_F_NAME)
        running_f.__file__ = str(BASE / F_PATH)
        exec(sources['mta_client_executor'], running_f.__dict__)
        self.assertEqual(tuple(row['module'] for row in rows), running_f.MODULES)
        original_executor, original_loader = running_f.ClientExecutor, running_f.DeploymentLoader
        token, candidate = 'a' * 32, 'b' * 64
        run = running_f.ROOT + '/client-' + token
        wpa_path = running_f.PHYSICAL_ROOT + '/client-' + token + '/native/mta-wpa-supplicant'
        # Arbitrary fake Python ELF is allowed by the existing manifest only
        # because its real hash matches these exact fictional bytes. No pinned
        # WPA/source authority constant or hashlib function is modified.
        python_raw = b'\x7fELFHOST-fictional-python-not-executable\n'
        binding_fields = {'version': 1, 'run_token': token, 'candidate_sha': candidate,
            'operation_id': 'HOST-loader-only', 'native_epoch': 8,
            'operation_epoch': 9, 'gatt_session': 12, 'nonce': 'c' * 32,
            'receive_consent': True}
        provider_fields = {'version': 1, 'run_token': token, 'candidate_sha': candidate,
            'ifname': 'mta01234567',
            'baseline_manifest': [list(row) for row in STOCK_PINS] + [['/usr/sbin/wpa_cli', 'd' * 64]],
            'status_manifest': {'daemon_exe': '/usr/bin/wpa_supplicant',
                'daemon_sha256': 'e' * 64, 'endpoint': '/var/run/wpa_supplicant/wlan0',
                'real_uid': 0, 'real_gid': 0, 'namespace_kind': 'full4_present', 'config_sha256': None},
            'wpa_exe': wpa_path, 'wpa_sha': WPA_PIN,
            'python_exe': '/usr/bin/python-fixture', 'python_sha': hashlib.sha256(python_raw).hexdigest(),
            'executor_path': run + '/runtime/mta_client_executor.py', 'executor_sha': F_PIN}
        tree = {'version': 3, 'provider': provider_fields,
            'sources': [[row['module'], row['sha256']] for row in rows],
            'connect_binding': binding_fields, 'receive_root': running_f.RECEIVE_ROOT}
        deployment_raw = host_json.dumps(tree, ensure_ascii=True, sort_keys=True).encode('ascii')
        deployment_sha = hashlib.sha256(deployment_raw).hexdigest()
        model_files = {run + '/runtime/' + name + '.py': raw for name, raw in sources.items()}
        model_files.update({run + '/deployment.json': deployment_raw,
            provider_fields['python_exe']: python_raw, wpa_path: wpa_raw})
        model_io = HostLoaderFileMap(model_files, running_f.ROOT, running_f.PHYSICAL_ROOT, running_f.RECEIVE_ROOT)
        clock = HostPreparationClock()
        live_calls = []
        def forbidden_live_call(*unused_args, **unused_kwargs):
            live_calls.append('unexpected actual OS/network/process IO')
            raise AssertionError(live_calls[-1])

        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {RUNNING_F_NAME: running_f}))
            # These guards protect omitted actual IO, not a substitute native
            # socket/process type or an admission proof. No owner constructor,
            # ClientExecutor.run, Parent.start or RF algorithm is invoked.
            for name in ('validate', 'stat', 'readlink', 'open', 'read', 'write',
                         'fstat', 'close', 'ready', 'ready_write', 'pipe_buf', 'popen'):
                stack.enter_context(mock.patch.object(running_f._LinuxIo, name,
                    side_effect=forbidden_live_call))
            for target in ('subprocess.Popen', 'socket.socket', 'os.fork', 'os.kill',
                           'os.waitpid', 'os.open', 'os.read', 'os.write', 'os.close',
                           'os.stat', 'os.lstat', 'os.readlink', 'os.urandom'):
                stack.enter_context(mock.patch(target, side_effect=forbidden_live_call, create=True))
            loader = original_loader(token, deployment_sha, _io=model_io, _clock=clock)
            loaded = loader.load()  # actual frozen Loader; all 35 definitions
            self.assertIs(type(loaded), running_f.LoadedDeployment)
            self.assertIs(loaded.loader, loader); self.assertIs(loader.value, loaded)
            self.assertIsNone(loader.authenticate(loaded))
            self.assertEqual(set(loaded.modules), set(running_f.MODULES))
            self.assertEqual(len(loaded.modules), 35)
            self.assertTrue(all(type(value) is types.ModuleType for value in loaded.modules.values()))
            self.assertIs(loaded.modules['mta_client_executor'], running_f)
            self.assertIs(loaded.modules['mta_client_executor'], sys.modules[RUNNING_F_NAME])
            self.assertIs(loaded.modules['mta_client_executor'].ClientExecutor, original_executor)
            self.assertIs(loaded.modules['mta_client_executor'].DeploymentLoader, original_loader)
            self.assertEqual(loader.owner.deadline, 110.0)
            self.assertEqual(clock.value, 100.0)
            self.assertEqual(model_io.validations, [model_io.machine_model])
            self.assertIsNone(loader.failure); self.assertFalse(loader.owner.pending)
            self.assertEqual(len(loader.owner.rows), 39)
            self.assertEqual(len(model_io.opens), 39); self.assertEqual(len(model_io.closes), 39)
            self.assertEqual(len(set(model_io.closes)), 39)
            self.assertTrue(all(row['attempted'] and row['closed'] and not row['unknown'] for row in loader.owner.rows))
            self.assertTrue(all(row['closed'] for row in model_io.descriptors.values()))
            self.assertEqual(sum(path == run + '/runtime/mta_client_executor.py' for fd, path in model_io.opens), 1)
            self.assertEqual(sum(path == run + '/runtime/p011_json.py' for fd, path in model_io.opens), 2)
            self.assertTrue(model_io.readlink_calls)
            self.assertEqual(set(model_io.readlink_calls), {'/tmp', '/var/tmp'})
            self.assertEqual(loaded.receive_root, running_f.RECEIVE_ROOT)
            self.assertEqual(tuple(name for name, metadata in loaded.receive_metadata),
                ('/', '/mnt', '/mnt/data', '/mnt/data/p011-toolbox', '/mnt/data/p011-toolbox/user', running_f.RECEIVE_ROOT))
            self.assertEqual(loaded.manifest.wpa_sha, loaded.modules['mta_p2p_client_init'].WPA_SHA)
            self.assertEqual(tuple(sorted(STOCK_PINS)), tuple(sorted(loaded.modules['mta_p2p_client_init'].STOCK_PINS)))

            # Original ordered import loop must not stop at F. Actual class
            # bodies and import relationships after that position are present.
            modules = loaded.modules
            after_f = running_f.MODULES[running_f.MODULES.index('mta_client_executor') + 1:]
            self.assertEqual(len(after_f), 10)
            for name in after_f:
                self.assertEqual(modules[name].__file__, run + '/runtime/' + name + '.py')
                self.assertIs(modules[name].__dict__['__builtins__']['__import__']('mta_client_executor'), running_f)
            self.assertIs(modules['mta_dhcp_client'].wire, modules['mta_dhcp'])
            self.assertIs(modules['mta_dhcp_client'].core, modules['mta_dhcp_client_core'])
            self.assertIs(modules['mta_client_dora'].dhcp, modules['mta_dhcp_client'])
            self.assertIs(modules['mta_client_dora'].exchange, modules['mta_dhcp_client_core'])
            self.assertIs(modules['mta_client_dora'].frame, modules['mta_client_control_frame'])
            self.assertIs(modules['mta_client_dora'].linux, modules['mta_client_linux_provider'])
            self.assertIs(modules['mta_client_peer'].dynamic, modules['mta_client_dynamic_ip'])
            self.assertIs(modules['mta_client_transfer'].transport, modules['mta_transport'])
            self.assertIs(modules['mta_client_transfer'].storage, modules['mta_storage'])
            self.assertIs(modules['mta_client_transfer'].ClientTransferOwner.__init__.__globals__, modules['mta_client_transfer'].__dict__)
            # Pure in-memory wire generation proves the later DHCP definitions
            # are executable definitions. It does not send a packet or run DORA.
            mac = b'\x02\x11\x22\x33\x44\x55'
            exchange = modules['mta_dhcp_client_core'].DynamicClientExchange(mac, 200.0, xid=123)
            discover = modules['mta_dhcp'].decode(exchange.start(100.0))
            self.assertEqual((discover['op'], discover['xid'], discover['chaddr'], discover['type']),
                (1, 123, mac, modules['mta_dhcp'].DISCOVER))
            codec, protocol = modules['mta_client_control_frame'], modules['mta_protocol']
            self.assertIs(type(loaded.connect_binding), codec.ControlBinding)
            info = protocol.P2pInfo('HOST-Synthetic', 'HOST-synthetic-secret',
                '02:11:22:33:44:55', 3345, sender_id='HOST-model-only')
            decoder = codec.ControlFrameDecoder(loaded.connect_binding)
            decoder.feed(codec.encode_connect(loaded.connect_binding, info))
            request = decoder.take_connect()
            self.assertIs(type(request), codec.ConnectRequest)
            self.assertEqual(request.private_info().port, 3345)
            before = len(model_io.opens)
            with self.assertRaises(running_f.ExecutorError) as error: loader.load()
            self.assertEqual(error.exception.code, 'already_attempted')
            self.assertEqual(len(model_io.opens), before)
            self.assertEqual(live_calls, [])

        print('HOST_LOADER_V31 ' + host_json.dumps({
            'scope': 'HOST actual frozen Loader/35 definitions; modeled file IO only',
            'source_manifest_sha256': MANIFEST_SHA, 'loaded_definitions': 35,
            'same_running_f_classes': True, 'definitions_after_f': list(after_f),
            'fictional_fd_open_count': len(model_io.opens), 'fictional_fd_once_close_count': len(model_io.closes),
            'modeled_platform_validation_count': len(model_io.validations),
            'clock': 'fixed HOST preparation 100; not elapsed-cost proof',
            'tmp': 'modeled exact /tmp->/var/tmp->/var/volatile/tmp',
            'wpa_elf': 'fixed local e069 bytes read/hashed; never executed',
            'python_elf': 'fictional bytes with matching hash; never executed',
            'actual_device_platform': False, 'rf': False, 'transfer': False,
            'restore': False, 'phone_compatible': False}, sort_keys=True))


if __name__ == '__main__': unittest.main()
