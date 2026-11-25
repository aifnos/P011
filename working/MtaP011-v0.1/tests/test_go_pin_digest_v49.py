"""One unique v49 same-read digest causal HOST pin-stage method.

The fixed GO17 Loader/F45 Entry/neutral accounting/GO Bootstrap constructor and
Native49 file/pin/fresh-Proc algorithms execute without Bootstrap.run or RF.
The six old helper FunctionDefs and explicit d8c07 Linux/Proc/FD/clock model are
definitions only; no old TestCase/baseline/AP/refusal method is loaded/run.
A transparent Native-only hashlib proxy returns genuine stdlib SHA objects.
Two pin rounds each read all six original pathname/process images and compute
six SHA values, never caching across reads. Default two-value file returns,
same-retained-digest identity, wrong pin, changed FD metadata/path inode and
uncertain close return are checked in separate fresh modeled runtimes.
OS replies, Python/CLI identities and physical close are modeled, not P011
performance/physical/resource-restoration evidence. An uncertain close remains
pending and is not retried or cleared. Original quotas and caps are unchanged.
"""
import ast
import builtins
import errno
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import socket
import stat
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/go_pin_digest_v49_source_manifest.json'
PLAN_SHA = '4b1f0322295f5612f70ddca4797d223b919e775a4b23a4218cbe48c66451a110'
PLAN_BYTES = 3951
HELPER = 'tests/test_go_bootstrap_native_v34_r4.py'
HELPER_SHA = '3574ad5f729162ef6a26e8f4f133210bcec6bcc8e2f74c99d1355b67974cd8ef'
HELPER_BYTES = 32468
MODEL = 'tests/go_bootstrap_host_model_v34_r3.py'
MODEL_SHA = 'd8c07c9aa2e5e7c7c009f9411d7cb6ad3f820b12273639aad96526738dc6358f'
MODEL_BYTES = 25155
STOCK = (
    ('/usr/bin/Z03', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/Z03',
        'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a', 4103844),
    ('/usr/bin/control_engine', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/control_engine',
        '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d', 163184),
    ('/usr/bin/zyb_z03_launch.sh', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/zyb_z03_launch.sh',
        '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b', 1913))
WPA = ('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
    'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 1351192)
FUNCTIONS = ('fixed', 'tripwires', 'load_model', 'failure_code', 'failure_frames', 'diagnostic')


def _fixed(path, sha, size):
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('HOST fixed input changed')
    return raw


def _definitions():
    """Load no old imports/module body/ClassDef/TestCase/method."""
    raw = _fixed(HELPER, HELPER_SHA, HELPER_BYTES)
    tree = ast.parse(raw, filename=HELPER)
    chosen = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    if tuple(node.name for node in chosen) != FUNCTIONS:
        raise ValueError('HOST helper definition inventory')
    domain = dict(globals())
    exec(compile(ast.Module(body=chosen, type_ignores=[]), HELPER, 'exec'), domain)
    return domain


def _inputs():
    tree = json.loads(_fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    if (type(tree) is not dict or set(tree) != {'schema', 'sources'} or
            tree['schema'] != 'go-frequency-v46-host' or len(tree['sources']) != 17 or
            len({row['module'] for row in tree['sources']}) != 17):
        raise ValueError('HOST new graph')
    rows = tree['sources']
    source = {row['module']: _fixed(row['path'], row['sha256'], row['bytes']) for row in rows}
    source['HOST_WPA'] = _fixed(*WPA)
    stock = {path: _fixed(relative, sha, size) for path, relative, sha, size in STOCK}
    model = types.ModuleType('HOST_go_pin_digest_v49_syscall_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(_fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return rows, source, stock, model


class _TransparentHashlib(object):
    """HOST counting only: no digest/result substitution or source gate change."""
    def __init__(self):
        self.calls = []
    def sha256(self, raw=b'', *args, **kwargs):
        actual = hashlib.sha256(raw, *args, **kwargs)
        self.calls.append((raw, actual))
        return actual
    def __getattr__(self, name):
        return getattr(hashlib, name)


def _runtime(definitions, rows, source, stock, model, stack):
    definitions['tripwires'](stack)
    io, modules, deployment, loader, executor, created = definitions['load_model'](
        rows, source, stock, model, None, stack)
    entry = executor._entry(deployment, model.UNTIL, repr(model.UNTIL),
        '--go-bootstrap', io.clock, io)
    runtime = modules['mta_go_bootstrap'].GoBootstrap(deployment, entry, clock=io.clock)
    if created != [runtime]: raise AssertionError('HOST original constructor inventory')
    return io, modules, deployment, loader, runtime


class GoPinDigestV49Tests(unittest.TestCase):
    def test_same_read_digest_two_pin_rounds_and_file_refusals_without_radio(self):
        definitions = _definitions()
        rows, source, stock, model = _inputs()
        cases = ('two_pin_rounds', 'default_pair', 'same_digest_triple',
            'wrong_pin', 'fd_metadata_changed', 'pathname_inode_changed', 'close_return_unknown')
        completed, pin_reads, pin_hashes, refusals, close_attempts = [], 0, 0, 0, 0
        for case in cases:
            with self.subTest(case=case), ExitStack() as stack:
                io, modules, deployment, loader, runtime = _runtime(
                    definitions, rows, source, stock, model, stack)
                native, store, entry = runtime.native, runtime.store, runtime.entry
                proxy = _TransparentHashlib()
                stack.enter_context(mock.patch.object(modules['mta_go_native'], 'hashlib', proxy))
                self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
                self.assertIs(type(runtime), modules['mta_go_bootstrap'].GoBootstrap)
                self.assertIs(type(store), modules['mta_go_bootstrap_store'].GoBootstrapStore)
                self.assertIs(loader.runtime, runtime)
                self.assertIs(store._native_original, native)
                self.assertEqual(tuple(row['module'] for row in rows),
                    tuple(name for name, value in loader.original_modules))
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in loader.owner.rows))
                self.assertIs(entry.accounting._proc_reader, entry.reader)
                self.assertIs(entry.budget._store, entry.accounting)
                self.assertIs(entry.budget._profile, modules['mta_client_resource_budget'].FORMAL_PROFILE)
                self.assertIs(entry.budget._session_profile, modules['mta_p2p_client_init'].FORMAL_SESSION_PROFILE)
                self.assertFalse(entry.accounting._attempted)
                self.assertFalse(entry.accounting._opened)
                self.assertEqual(model.UNTIL, loader.original_until)
                self.assertEqual(repr(model.UNTIL), loader.original_until_text)
                self.assertTrue(entry.reader.history_closed())
                with native.mutex:
                    original_end = runtime._stage(10)
                    native._begin(original_end)
                    self.assertEqual(11.0, original_end)
                    self.assertEqual(original_end, native._scope)
                    self.assertEqual(original_end, entry.accounting._io_deadline)
                    path = '/usr/bin/zyb_z03_launch.sh'
                    if case == 'two_pin_rounds':
                        actors = native._actors()
                        self.assertEqual([], proxy.calls)
                        self.assertEqual(1, sum(a.exe == '/usr/bin/Z03' for a in actors))
                        self.assertEqual(1, sum(a.exe == '/usr/bin/control_engine' for a in actors))
                        paths = [p for p, pin in deployment.manifest.baseline_manifest] + [
                            '/proc/' + str(a.pid) + '/exe' for a in actors
                            if a.exe in ('/usr/bin/Z03', '/usr/bin/control_engine')]
                        self.assertEqual(6, len(paths))
                        first_digests, first_hash_inputs = None, None
                        for round_number in (1, 2):
                            before_calls, before_raw, before_hashes = len(io.calls), len(native.raw), len(proxy.calls)
                            before_rows, before_proc = len(native.rows), len(native.proc_observations)
                            actual = native._pins(actors)
                            self.assertEqual(tuple((p, sha) for p, relative, sha, size in STOCK), actual)
                            opens = [call[1] for call in io.calls[before_calls:]
                                if call[0] == 'open' and call[1] in paths]
                            self.assertEqual(paths, opens)
                            self.assertEqual(6, len(native.rows) - before_rows)
                            self.assertEqual(6, len(proxy.calls) - before_hashes)
                            retained = native.raw[before_raw:]
                            self.assertEqual(6, len(retained))
                            round_hash_inputs = proxy.calls[before_hashes:]
                            for expected_path, record, (raw, actual_hash) in zip(paths, retained, round_hash_inputs):
                                self.assertEqual(('file', expected_path), record[:2])
                                self.assertIs(type(raw), bytes)
                                self.assertIs(type(record[2]), bytes)
                                self.assertEqual(32, len(record[2]))
                                self.assertEqual(hashlib.sha256(raw).digest(), record[2])
                                self.assertEqual(actual_hash.digest(), record[2])
                            self.assertEqual(2, len(native.proc_observations) - before_proc)
                            self.assertTrue(all(value.kind == 'live_actor' and value.passes == 2
                                and value.resource_pending is False
                                for value in native.proc_observations[before_proc:]))
                            self.assertTrue(entry.reader.history_closed())
                            if round_number == 1:
                                first_digests = tuple(record[2] for record in retained)
                                first_hash_inputs = tuple(raw for raw, actual_hash in round_hash_inputs)
                            else:
                                self.assertEqual(first_digests, tuple(record[2] for record in retained))
                                self.assertEqual(first_hash_inputs, tuple(raw for raw, actual_hash in round_hash_inputs))
                                # Equal content is still separately read and hashed this round.
                                self.assertTrue(all(old is not record[2]
                                    for old, record in zip(first_digests, retained)))
                            self.assertEqual(original_end, native._scope)
                            self.assertEqual(model.UNTIL, native.until)
                            pin_reads += len(opens)
                            pin_hashes += len(proxy.calls) - before_hashes
                        self.assertEqual(12, len(proxy.calls))
                    elif case in ('default_pair', 'same_digest_triple'):
                        before_raw = len(native.raw)
                        if case == 'default_pair':
                            returned = native._file(path, 67108864)
                            self.assertEqual(2, len(returned))
                        else:
                            returned = native._file(path, 67108864, _same_read_digest=True)
                            self.assertEqual(3, len(returned))
                            self.assertIs(returned[2], native.raw[-1][2])
                        self.assertIs(type(returned), tuple)
                        self.assertEqual(stock[path], returned[0])
                        self.assertEqual(1, len(proxy.calls))
                        self.assertIs(proxy.calls[0][0], returned[0])
                        self.assertEqual(1, len(native.raw) - before_raw)
                        self.assertEqual(('file', path), native.raw[-1][:2])
                        self.assertEqual(hashlib.sha256(returned[0]).digest(), native.raw[-1][2])
                        self.assertEqual(32, len(native.raw[-1][2]))
                        self.assertEqual(1, sum(call[0] == 'open' and call[1] == path for call in io.calls))
                    elif case == 'wrong_pin':
                        actors = native._actors()
                        original_read, changed = io.read, []
                        def corrupt_read(fd, count):
                            raw = original_read(fd, count)
                            if io.live[fd]['path'] == '/usr/bin/Z03' and raw and not changed:
                                changed.append(fd)
                                raw = raw[:-1] + bytes((raw[-1] ^ 1,))
                            return raw
                        stack.enter_context(mock.patch.object(io, 'read', corrupt_read))
                        returned = []
                        with self.assertRaises(modules['mta_go_deployment'].GoSourceError) as caught:
                            returned.append(native._pins(actors))
                        self.assertEqual('native_stock_pin_changed', caught.exception.code)
                        self.assertEqual([], returned)
                        self.assertEqual(1, len(changed))
                        self.assertEqual(1, len(proxy.calls))
                        self.assertNotEqual(hashlib.sha256(stock['/usr/bin/Z03']).digest(), native.raw[-1][2])
                        refusals += 1
                    elif case in ('fd_metadata_changed', 'pathname_inode_changed'):
                        original_read, changed = io.read, []
                        original_node = io.nodes[path]
                        def change_read(fd, count):
                            raw = original_read(fd, count)
                            if io.live[fd]['path'] == path and raw and not changed:
                                changed.append(fd)
                                if case == 'fd_metadata_changed':
                                    original_node.revision += 1
                                else:
                                    replacement = io.add(path, original_node.mode, original_node.data,
                                        original_node.nlink, original_node.target, original_node.rdev)
                                    if replacement.inode == original_node.inode:
                                        raise AssertionError('HOST pathname replacement not distinct')
                            return raw
                        stack.enter_context(mock.patch.object(io, 'read', change_read))
                        returned = []
                        with self.assertRaises(modules['mta_go_deployment'].GoSourceError) as caught:
                            returned.append(native._file(path, 67108864, _same_read_digest=True))
                        self.assertEqual('native_file_changed', caught.exception.code)
                        self.assertEqual([], returned)
                        self.assertEqual(1, len(changed))
                        self.assertEqual(1, len(proxy.calls))
                        self.assertTrue(native.rows[-1].closed)
                        self.assertFalse(native.rows[-1].unknown)
                        refusals += 1
                    else:
                        original_close, closed = io.close, []
                        close_error = OSError(errno.EIO, 'HOST same original FD close returned uncertain')
                        def close_then_error(fd):
                            if io.live[fd]['path'] == path:
                                closed.append(fd)
                                original_close(fd)
                                raise close_error
                            return original_close(fd)
                        stack.enter_context(mock.patch.object(io, 'close', close_then_error))
                        returned = []
                        with self.assertRaises(OSError) as caught:
                            returned.append(native._file(path, 67108864, _same_read_digest=True))
                        self.assertIs(close_error, caught.exception)
                        self.assertEqual([], returned)
                        self.assertEqual(1, len(closed))
                        self.assertEqual(1, len(proxy.calls))
                        row = native.rows[-1]
                        self.assertEqual(closed, [row.fd])
                        self.assertTrue(row.returned)
                        self.assertTrue(row.attempted)
                        self.assertFalse(row.closed)
                        self.assertIs(row.close_failure, close_error)
                        self.assertEqual(1, io.closed.count(row.fd))
                        self.assertNotIn(row.fd, io.live)
                        with self.assertRaises(modules['mta_go_deployment'].GoSourceError) as retry:
                            native._close(row)
                        self.assertEqual('native_close_pending', retry.exception.code)
                        self.assertEqual(1, len(closed))
                        self.assertEqual(1, io.closed.count(row.fd))
                        self.assertFalse(all(a and b for a, b in native.closed_facts()))
                        close_attempts += len(closed)
                        refusals += 1
                self.assertEqual(original_end, native._scope)
                self.assertEqual(model.UNTIL, runtime.until)
                self.assertEqual(model.UNTIL, store.until)
                self.assertEqual(model.UNTIL, native.until)
                self.assertEqual(model.UNTIL, entry.until)
                self.assertEqual(0, io.create_count)
                self.assertEqual(0, io.delete_count)
                self.assertEqual([], io.sockets)
                self.assertEqual([], runtime.launcher._tickets)
                self.assertIsNone(store.current)
                self.assertEqual((), store._canonical_history)
                self.assertFalse(store.attempted)
                self.assertFalse(store.restore_attempted)
                self.assertFalse(store.logical_restored)
                self.assertFalse(store.marker_cleared)
                self.assertFalse(runtime.restore_attempted)
                self.assertTrue(entry.reader.history_closed())
                self.assertFalse(io.live)
                self.assertEqual(len(io.closed), len(set(io.closed)))
                self.assertLessEqual(len(native.rows), modules['mta_go_native']._MAX_FDS)
                self.assertLessEqual(native._raw_bytes, modules['mta_go_native']._MAX_RAW)
                self.assertEqual(0, native._packets)
                self.assertEqual(0, store._fd_attempts)
                if case != 'close_return_unknown':
                    self.assertTrue(all(a and b for a, b in native.closed_facts()))
                    self.assertTrue(all(row.closed and not row.unknown for row in native.rows))
                else:
                    # Kernel model closed the descriptor, but the native return
                    # is uncertain. No resource proof/pending state is washed.
                    self.assertFalse(native.rows[-1].closed)
                    self.assertTrue(native.rows[-1].attempted)
                    self.assertIs(native.rows[-1].close_failure, close_error)
                completed.append(case)
        self.assertEqual(list(cases), completed)
        self.assertEqual((12, 12, 4, 1), (pin_reads, pin_hashes, refusals, close_attempts))
        print('GO_PIN_DIGEST_V49_HOST_PASS cases=7 pin_rounds=2 pin_reads=%d pin_sha256=%d refusals=%d uncertain_close_attempts=%d rf_calls=0' %
            (pin_reads, pin_hashes, refusals, close_attempts))


if __name__ == '__main__':
    unittest.main()
