"""One new HOST method for the frozen fixed-35 private source importer.

The 34 unchanged definitions come from the pinned original private manifest;
only its executor row is explicitly overridden by the new frozen SOURCE.
All input paths are relative to this file's copied private-inputs root.
This suite does not load any old TestCase or test helper.

Actual Python definitions/import relationships run, not RF, Store operations,
Parent, service or owner scopes. The small Loader read map is an explicit HOST
source-only model; it stops immediately after actual importing, before any
ProviderManifest, binding or LoadedDeployment is constructed. It proves no
device file ownership, FD closure, networking, elapsed deadline or phone use.
The poisoned-source/unknown-import cases are labelled malicious HOST models:
their test-only supplied hashes do not approve those bytes for deployment.
"""
import base64
import builtins
from contextlib import ExitStack
import ctypes
import errno
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
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


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = 'host/client_receive_directory_auth_clock_v2_private_source_manifest.json'
MANIFEST_BYTES = 8144
MANIFEST_SHA = 'bbd5362d9d8ca5598b504a6ba3cbd4cf56f92af2f714d34b806c4e660f342941'
EXECUTOR_PATH = 'candidate/receive-startup-readonly-v1/runtime/mta_client_executor.py'
OLD_EXECUTOR_ROW = {
    'module': 'mta_client_executor',
    'path': 'candidate/receive-directory-auth-clock-v2/runtime/mta_client_executor.py',
    'bytes': 114074,
    'sha256': '01dfd6295f2ac06464e7d7b0de1d99aa1ec97bef25f95222efa346609f25ecfb',
}
NAMES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_caps',
    'mta_client_caps_transport', 'mta_client_baseline', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending',
    'mta_client_store', 'mta_client_process_owner', 'mta_client_launch_registration',
    'mta_client_two_phase_lease', 'mta_p2p_client_ctrl', 'mta_client_wpa_status',
    'mta_protocol', 'mta_client_control_frame', 'mta_client_kernel_proof',
    'mta_client_connection', 'mta_client_linux_provider', 'mta_client_executor',
    'mta_dhcp', 'mta_dhcp_client_core', 'mta_dhcp_client', 'mta_client_dora',
    'mta_client_dynamic_ip', 'mta_client_peer', 'mta_scoped_sockets', 'mta_storage',
    'mta_transport', 'mta_client_transfer')
RUNTIME_DIRECTORY = '/var/volatile/tmp/p011-mta-state-startup-v1/runtime35'
RUNNING_NAME = '_host_receive_startup_importer_v1_executor'
UNKNOWN_NAME = 'mta_host_unknown_importer_model_v1'
MARKER = ('HOST_RECEIVE_STARTUP_IMPORTER new_methods=1 cases=6 private_modules=35 '
          'old_methods=0 live_io_calls=0 host=true device=false phone=false rf=false\n')


def _read_fixed(path, size, pin):
    if (type(path) is not str or not path or path.startswith('/') or
            '\\' in path or ':' in path or
            any(part in ('', '.', '..') for part in path.split('/')) or
            type(size) is not int or size < 1 or
            type(pin) is not str or re.fullmatch('[0-9a-f]{64}', pin) is None):
        raise AssertionError('fixed HOST input shape changed')
    raw = (ROOT / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('fixed HOST input bytes changed')
    return raw


def frozen_inputs():
    """No dynamic graph discovery: one frozen table and one explicit F override."""
    table_raw = _read_fixed(MANIFEST_PATH, MANIFEST_BYTES, MANIFEST_SHA)
    tree = json.loads(table_raw.decode('utf-8'))
    if (type(tree) is not dict or
            set(tree) != {'schema', 'sources', 'previous_manifest_sha256'} or
            tree['schema'] != 'client-receive-directory-v1-private-source' or
            type(tree['sources']) is not list or len(tree['sources']) != 35):
        raise AssertionError('fixed private35 manifest changed')
    # ROOT's external HOST checker pins this exact copied SOURCE before running
    # the suite. Its final F pin follows the reviewed startup-root literal change;
    # the test does not invent a self-referential release/manifest checksum.
    executor_raw = (ROOT / EXECUTOR_PATH).read_bytes()
    if type(executor_raw) is not bytes or not 1 <= len(executor_raw) <= 2097152:
        raise AssertionError('new fixed executor source size changed')
    executor_pin = hashlib.sha256(executor_raw).hexdigest()
    source_rows, pins = [], []
    for name, row in zip(NAMES, tree['sources']):
        if (type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or
                type(row['module']) is not str or row['module'] != name):
            raise AssertionError('fixed private35 order changed')
        path, size, pin = row['path'], row['bytes'], row['sha256']
        if name == 'mta_client_executor':
            if row != OLD_EXECUTOR_ROW:
                raise AssertionError('original private35 executor row changed')
            raw, size, pin = executor_raw, len(executor_raw), executor_pin
        else:
            raw = _read_fixed(path, size, pin)
        source_rows.append((name, raw))
        pins.append((name, size, pin))
    paths = tuple((name, RUNTIME_DIRECTORY + '/' + name + '.py') for name in NAMES)
    return tuple(source_rows), paths, tuple(pins)


class _StopAfterImport(Exception):
    """Fixed HOST-only boundary: no subsequent deployment constructor runs."""


class _LoaderSourceMap(object):
    """In-memory source read model, with no real or fictional FD authority."""
    def __init__(self, files):
        self.files, self.reads = files, []
        self.close_calls = 0

    def read_file(self, path, limit, expected, private):
        if path not in self.files or private is not True:
            raise AssertionError('HOST source model unmapped input')
        raw = self.files[path]
        if len(raw) > limit or hashlib.sha256(raw).hexdigest() != expected:
            raise AssertionError('HOST source model input mismatch')
        self.reads.append(path)
        return raw, None

    def close(self):
        self.close_calls += 1
        return True  # Model callback only; no FD or device close evidence.


class _LoaderModelIo(object):
    def __init__(self): self.validate_calls = 0
    def validate(self): self.validate_calls += 1  # Not _LinuxIo validation.


class ReceiveStartupImporterTests(unittest.TestCase):
    def _assert_preexec_rejection(self, running, sources, paths, pins,
                                  supplied_running=None):
        retained = {}
        actual = running if supplied_running is None else supplied_running
        with mock.patch.object(builtins, 'exec',
                side_effect=AssertionError('invalid graph reached exec')) as execute:
            with self.assertRaises(running.ExecutorError) as failure:
                running._import_verified_sources(sources, paths, pins, actual,
                                                _retained_modules=retained)
            self.assertEqual('source_invalid', failure.exception.code)
            self.assertEqual(0, execute.call_count)
        self.assertEqual({}, retained)

    def test_fixed_private35_importer_and_preexec_rejection(self):
        sources, paths, pins = frozen_inputs()  # All PC reads precede IO guards.
        running = types.ModuleType(RUNNING_NAME)
        running.__file__ = str(ROOT / EXECUTOR_PATH)
        canonical = {name: types.ModuleType(name) for name in NAMES}
        canonical[UNKNOWN_NAME] = types.ModuleType(UNKNOWN_NAME)
        completed, live_calls = [], []
        def reject_live_io(*unused_args, **unused_kwargs):
            live_calls.append('HOST forbidden actual IO')
            raise AssertionError('HOST import unexpectedly requested actual IO')
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules,
                dict(canonical, **{RUNNING_NAME: running})))
            exec(compile(dict(sources)['mta_client_executor'], running.__file__, 'exec'),
                 running.__dict__)
            self.assertEqual(NAMES, running.MODULES)
            original_executor, original_loader = running.ClientExecutor, running.DeploymentLoader
            original_importer = running._import_verified_sources
            for target in ('subprocess.Popen', 'socket.socket', 'os.fork', 'os.kill',
                           'os.waitpid', 'os.open', 'os.read', 'os.write', 'os.close',
                           'os.stat', 'os.lstat', 'os.readlink', 'os.urandom',
                           'os.system', 'threading.Thread.start'):
                stack.enter_context(mock.patch(target, side_effect=reject_live_io,
                                               create=True))

            # 1. The actual fixed35 realm, original dict/F, canonical non-write,
            # and every post-F DHCP/receive definition; no constructors/actions.
            retained = {}
            modules = original_importer(sources, paths, pins, running,
                                        _retained_modules=retained)
            self.assertIs(modules, retained)
            self.assertEqual(set(NAMES), set(modules))
            self.assertEqual(35, len(modules))
            self.assertTrue(all(type(value) is types.ModuleType for value in modules.values()))
            self.assertIs(modules['mta_client_executor'], running)
            self.assertIs(running.ClientExecutor, original_executor)
            self.assertIs(running.DeploymentLoader, original_loader)
            self.assertIs(sys.modules[RUNNING_NAME], running)
            for name, original in canonical.items(): self.assertIs(sys.modules[name], original)
            after_f = NAMES[NAMES.index('mta_client_executor') + 1:]
            self.assertEqual(10, len(after_f))
            for name in after_f:
                self.assertEqual(dict(paths)[name], modules[name].__file__)
                self.assertIs(modules[name].__dict__['__builtins__']['__import__'](
                    'mta_client_executor'), running)
            for owner, attr, dependency in (
                    ('mta_client_baseline', 'proc', 'mta_client_proc'),
                    ('mta_client_baseline', 'core', 'mta_p2p_client_init'),
                    ('mta_client_wpa_status', 'proc', 'mta_client_proc'),
                    ('mta_client_wpa_status', 'core', 'mta_p2p_client_init'),
                    ('mta_client_wpa_status', 'baseline', 'mta_client_baseline'),
                    ('mta_client_store', 'proc', 'mta_client_proc'),
                    ('mta_client_store', 'core', 'mta_p2p_client_init'),
                    ('mta_client_store', 'resources', 'mta_client_resource_budget'),
                    ('mta_dhcp_client', 'wire', 'mta_dhcp'),
                    ('mta_dhcp_client', 'core', 'mta_dhcp_client_core'),
                    ('mta_client_dora', 'dhcp', 'mta_dhcp_client'),
                    ('mta_client_dora', 'exchange', 'mta_dhcp_client_core'),
                    ('mta_client_dora', 'linux', 'mta_client_linux_provider'),
                    ('mta_client_peer', 'dynamic', 'mta_client_dynamic_ip'),
                    ('mta_client_transfer', 'storage', 'mta_storage'),
                    ('mta_client_transfer', 'transport', 'mta_transport')):
                self.assertIs(getattr(modules[owner], attr), modules[dependency])
            self.assertIs(modules['mta_client_store'].DurableClientInitStore.__init__.__globals__,
                          modules['mta_client_store'].__dict__)
            completed.append('actual35_private_realm_same_f_and_all_later_roles')

            # 2. A foreign module cannot borrow the original class attributes.
            foreign = types.ModuleType(RUNNING_NAME)
            foreign.ClientExecutor, foreign.DeploymentLoader = original_executor, original_loader
            self._assert_preexec_rejection(running, sources, paths, pins, foreign)
            completed.append('foreign_running_rejected_before_exec')

            # 3. Fixed named order, exact tuple types and fixed runtime paths.
            for arguments in (
                    ((sources[1], sources[0]) + sources[2:], paths, pins),
                    (sources, (paths[1], paths[0]) + paths[2:], pins),
                    (sources, paths, (pins[1], pins[0]) + pins[2:]),
                    (list(sources), paths, pins),
                    (sources, tuple((name, '/tmp/foreign-runtime/' + name + '.py')
                                    for name in NAMES), pins)):
                self._assert_preexec_rejection(running, *arguments)
            completed.append('order_shape_and_fixed_paths_rejected_before_exec')

            # 4. Late-row size/SHA failures cannot execute an earlier source.
            last_name, last_size, last_sha = pins[-1]
            for bad_last in ((last_name, last_size + 1, last_sha),
                             (last_name, last_size, '0' * 64),
                             (last_name, True, last_sha)):
                self._assert_preexec_rejection(running, sources, paths, pins[:-1] + (bad_last,))
            # Explicit malicious HOST model: early code is supplied a matching
            # test-only pin, while the last original source's pin is wrong.
            poison = b'raise AssertionError("HOST poison must never execute")\n'
            poisoned_sources = sources[:1] + (('mta_ip', poison),) + sources[2:]
            poisoned_pins = pins[:1] + (('mta_ip', len(poison),
                hashlib.sha256(poison).hexdigest()),) + pins[2:-1] + (
                    (last_name, last_size, '0' * 64),)
            self._assert_preexec_rejection(running, poisoned_sources, paths, poisoned_pins)
            completed.append('whole_graph_size_and_sha_firstpass')

            # 5. A caller's fake JSON cannot become the imported codec. Keep
            # its original identity intact but replace it with actual fixed bytes.
            fake_json = types.ModuleType('p011_json')
            fake_json.loads = object()
            fake_loads = fake_json.loads
            seeded = {'p011_json': fake_json}
            fresh = original_importer(sources, paths, pins, running,
                                     _retained_modules=seeded)
            self.assertIs(fresh, seeded)
            self.assertIsNot(fresh['p011_json'], fake_json)
            self.assertIs(fake_json.loads, fake_loads)
            self.assertEqual({'verified': True}, fresh['p011_json'].loads('{"verified":true}'))
            self.assertIs(fresh['p011_json'].loads.__globals__, fresh['p011_json'].__dict__)
            token = '1' * 32
            run = running.ROOT + '/client-' + token
            tree = {'version': 4, 'provider': {}, 'connect_binding': {},
                    'receive_root': running.RECEIVE_ROOT, 'receive_identity_rows': [],
                    'sources': [[name, pin] for name, unused_size, pin in pins]}
            deployment_raw = json.dumps(tree, sort_keys=True).encode('ascii')
            deployment_sha = hashlib.sha256(deployment_raw).hexdigest()
            model_files = {run + '/runtime/' + name + '.py': raw for name, raw in sources}
            model_files[run + '/deployment.json'] = deployment_raw
            model_reader, model_io = _LoaderSourceMap(model_files), _LoaderModelIo()
            called = []
            def import_then_stop(*args, **kwargs):
                actual = original_importer(*args, **kwargs)
                called.append(actual)
                raise _StopAfterImport()
            with mock.patch.object(running, '_ReadOwner', return_value=model_reader), \
                    mock.patch.object(running, '_import_verified_sources', side_effect=import_then_stop):
                loader = original_loader(token, deployment_sha, _io=model_io,
                                         _clock=lambda: 1.0, _parent_until_v33=20.0)
                with self.assertRaises(_StopAfterImport): loader.load()
            self.assertEqual(1, len(called))
            self.assertIs(called[0], loader.modules)
            self.assertIsNot(loader._manifest_codec_original, loader.modules['p011_json'])
            self.assertIs(loader._manifest_codec_original.loads.__globals__,
                          loader._manifest_codec_original.__dict__)
            self.assertEqual(tree, loader._manifest_codec_original.loads(deployment_raw.decode('ascii')))
            self.assertIs(type(loader.failure), _StopAfterImport)
            self.assertIsNone(loader.value)
            self.assertIsNone(loader._connect_binding)
            self.assertIsNone(loader.directory_binding)
            self.assertEqual(37, len(model_reader.reads))
            self.assertEqual(1, model_reader.close_calls)
            self.assertEqual(1, model_io.validate_calls)
            self.assertIs(running._import_verified_sources, original_importer)
            completed.append('fixed_json_reexec_and_actual_loader_parse_identity')

            # 6. Explicit malicious HOST model, not an approved graph: the
            # unknown module exists canonically, but private fallback is forbidden.
            malicious = ('import ' + UNKNOWN_NAME + '\n').encode('ascii')
            model_sources = sources[:1] + (('mta_ip', malicious),) + sources[2:]
            model_pins = pins[:1] + (('mta_ip', len(malicious),
                hashlib.sha256(malicious).hexdigest()),) + pins[2:]
            partial = {}
            with self.assertRaises(running.ExecutorError) as failure:
                original_importer(model_sources, paths, model_pins, running,
                                  _retained_modules=partial)
            self.assertEqual('source_invalid', failure.exception.code)
            self.assertEqual({'p011_json', 'mta_client_executor', 'mta_ip'}, set(partial))
            self.assertIs(partial['mta_client_executor'], running)
            self.assertIs(type(partial['mta_ip']), types.ModuleType)
            self.assertIs(sys.modules[UNKNOWN_NAME], canonical[UNKNOWN_NAME])
            for name, original in canonical.items(): self.assertIs(sys.modules[name], original)
            completed.append('malicious_host_unknown_private_no_fallback_partial_retained')
            self.assertEqual([], live_calls)

        self.assertEqual([
            'actual35_private_realm_same_f_and_all_later_roles',
            'foreign_running_rejected_before_exec',
            'order_shape_and_fixed_paths_rejected_before_exec',
            'whole_graph_size_and_sha_firstpass',
            'fixed_json_reexec_and_actual_loader_parse_identity',
            'malicious_host_unknown_private_no_fallback_partial_retained',
        ], completed)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    suite = unittest.TestSuite([ReceiveStartupImporterTests(
        'test_fixed_private35_importer_and_preexec_rejection')])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
