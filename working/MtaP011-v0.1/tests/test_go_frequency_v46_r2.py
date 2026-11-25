"""Four new first-baseline refusal checks on the fixed v46 GO17 HOST graph.

The original seven-case method remains FAIL at an empty-list versus immutable
empty-tuple HOST expectation; its completed positive and two AP cases are not
replayed here. This unique method executes only present kernel-frequency
conflict, missing ASSOCIATED, wrong associated-BSS frequency and missing BI.
The actual Loader/F45/Entry/GO Store/Native46/Bootstrap algorithms and original
quotas/caps are unchanged. Only the pinned OS-model syscall replies vary.
Failure before reservation must not create a reconciled journal or radio
resources, but all known local resource inventories must close. This is HOST
model evidence, never P011/RF/phone/physical closure evidence. The exact six old
helper FunctionDefs are selected; no old TestCase or method executes.
"""
import ast
import builtins
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
PLAN = 'host/go_frequency_v46_source_manifest.json'
PLAN_SHA = '090392942b3472e45b1eb5f3ccf8b06a236b273255ce510fe52efc0fd20bcc7e'
PLAN_BYTES = 3950
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
    model = types.ModuleType('HOST_go_frequency_v46_r2_syscall_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(_fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return rows, source, stock, model


def _reply_case(model, case, stack):
    """Change only frozen OS-model netlink/Unix reply bytes, not native code."""
    origin = model.Netlink.origin
    sendto = model.Netlink.sendto
    send = model.Unix.send

    def interface_reply(raw, owned=False):
        value = origin(raw, owned)
        old = model.u32(38, 2412)
        if value.count(old) != 1:
            raise AssertionError('HOST fixed interface reply shape')
        if case == 'present38_conflict':
            return value.replace(old, model.u32(38, 2437), 1)
        return value.replace(old, b'', 1)

    def kernel_reply(raw, request, target):
        at = len(raw.queue)
        result = sendto(raw, request, target)
        family = model.NL.unpack_from(request)[1]
        command = model.GH.unpack_from(request, 16)[0] if raw.protocol == 16 else None
        if raw.protocol == 16 and family != 16 and command == 32:
            raw.io.v46_scan_requests = getattr(raw.io, 'v46_scan_requests', 0) + 1
            if case in ('associated_missing', 'bss_wrong_frequency', 'beacon_missing'):
                bss = model.attr(1, b'\x02\x11\x22\x33\x44\x55')
                bss += model.u32(2, 2437 if case == 'bss_wrong_frequency' else 2412)
                if case != 'beacon_missing':
                    bss += model.attr(4, model.struct.pack('<H', 100))
                if case != 'associated_missing': bss += model.u32(9, 1)
                body = model.GH.pack(34, 1, 0) + model.u32(3, 3) + model.nest(47, bss)
                changed = 0
                for i in range(at, len(raw.queue)):
                    packet, ancillary, flags, peer = raw.queue[i]
                    kind = model.NL.unpack_from(packet)[1]
                    if kind == family:
                        raw.queue[i] = (model.reply(request, family, body, 2), ancillary, flags, peer)
                        changed += 1
                if changed != 1: raise AssertionError('HOST fixed BSS reply inventory')
                raw.io.v46_fault_hits = getattr(raw.io, 'v46_fault_hits', 0) + 1
        return result

    def control_reply(raw, wire):
        at = len(raw.queue)
        result = send(raw, wire)
        if (case in ('ap_no_freq', 'ap_wrong_freq') and wire == b'STATUS' and
                raw.peer != '/run/wpa_supplicant/wlan0'):
            if len(raw.queue) != at + 1: raise AssertionError('HOST fixed AP reply inventory')
            packet, ancillary, flags, peer = raw.queue[at]
            if packet.count(b'freq=2412\n') != 1: raise AssertionError('HOST fixed AP status shape')
            replacement = b'' if case == 'ap_no_freq' else b'freq=2437\n'
            raw.queue[at] = (packet.replace(b'freq=2412\n', replacement, 1), ancillary, flags, peer)
            raw.io.v46_fault_hits = getattr(raw.io, 'v46_fault_hits', 0) + 1
        return result

    stack.enter_context(mock.patch.object(model.Netlink, 'origin', interface_reply))
    stack.enter_context(mock.patch.object(model.Netlink, 'sendto', kernel_reply))
    stack.enter_context(mock.patch.object(model.Unix, 'send', control_reply))


class GoFrequencyV46R2Tests(unittest.TestCase):
    def test_four_first_baseline_refusals_keep_zero_radio_mutations_and_known_inventory_closed(self):
        definitions = _definitions()
        rows, source, stock, model = _inputs()
        cases = ('present38_conflict', 'associated_missing', 'bss_wrong_frequency', 'beacon_missing')
        baseline_errors = {'present38_conflict': 'native_station_channel_changed',
            'associated_missing': 'native_station_beacon_unavailable',
            'bss_wrong_frequency': 'native_station_beacon_unavailable',
            'beacon_missing': 'native_station_beacon_unavailable'}
        completed, totals = [], [0, 0, 0, 0]
        for case in cases:
            with self.subTest(case=case), ExitStack() as stack:
                definitions['tripwires'](stack)
                _reply_case(model, case, stack)
                io, modules, deployment, loader, executor, created = definitions['load_model'](
                    rows, source, stock, model, None, stack)
                # This value is a HOST model class used only for counting its
                # syscall transcript, never an additional production module.
                unix_model = model.Unix
                result = executor.bootstrap(deployment, model.UNTIL, repr(model.UNTIL),
                    _clock=io.clock, _proc_fs=io)
                self.assertEqual(1, len(created))
                runtime = created[0]
                store, native, launcher, entry = runtime.store, runtime.native, runtime.launcher, runtime.entry
                context = definitions['diagnostic'](runtime)
                self.assertIs(type(runtime), modules['mta_go_bootstrap'].GoBootstrap)
                self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
                self.assertIs(type(store), modules['mta_go_bootstrap_store'].GoBootstrapStore)
                self.assertIs(loader.runtime, runtime)
                self.assertIs(loader._runtime_store, store)
                self.assertIs(store._native_original, native)
                self.assertIs(store._launcher_original, launcher)
                self.assertIs(type(launcher), modules['mta_go_process_owner'].GoDirectChildOwner)
                self.assertEqual(tuple(row['module'] for row in rows), tuple(n for n, value in loader.original_modules))
                self.assertEqual(21, len(loader.owner.rows))
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in loader.owner.rows))
                for actual in (runtime.until, store.until, native.until, entry.until, loader.original_until):
                    self.assertEqual(model.UNTIL, actual)
                self.assertEqual(repr(model.UNTIL), loader.original_until_text)
                self.assertEqual(model.UNTIL,
                    modules['mta_go_deployment'].canonical_until(loader.original_until_text))
                self.assertIs(entry.accounting._proc_reader, entry.reader)
                self.assertIs(entry.accounting._resource_budget_v23, entry.budget)
                self.assertIs(entry.budget._profile, modules['mta_client_resource_budget'].FORMAL_PROFILE)
                self.assertIs(entry.budget._session_profile, modules['mta_p2p_client_init'].FORMAL_SESSION_PROFILE)
                self.assertIs(entry.budget._store, entry.accounting)
                self.assertTrue(entry.reader.history_closed())
                self.assertFalse(entry.accounting._attempted)
                self.assertFalse(entry.accounting._opened)
                self.assertTrue(runtime.restore_attempted, context)
                self.assertEqual(len(io.closed), len(set(io.closed)))
                self.assertLessEqual(len(native.rows), modules['mta_go_native']._MAX_FDS)
                self.assertLessEqual(native._packets, 1024)
                self.assertLessEqual(native._raw_bytes, modules['mta_go_native']._MAX_RAW)
                self.assertLessEqual(store._fd_attempts, modules['mta_go_bootstrap_store']._STORE_OPEN_BOUND)
                group_commands = [wire for raw in io.sockets if isinstance(raw, unix_model)
                    for wire in raw.sent if wire.startswith(b'P2P_GROUP_ADD ')]
                self.assertFalse(runtime.status()['go_ready'])
                self.assertFalse(store.status()['device_tested'])
                self.assertFalse(native.status()['phone_tested'])
                self.assertEqual(1, result, context)
                self.assertEqual(baseline_errors[case], definitions['failure_code'](runtime.failure), context)
                self.assertFalse(runtime.group_confirmed)
                self.assertEqual(0, io.create_count)
                self.assertEqual(0, io.delete_count)
                self.assertEqual([], group_commands)
                self.assertFalse(store.logical_restored)
                self.assertFalse(store.marker_cleared)
                self.assertIsNone(store.current)
                self.assertIs(type(store._canonical_history), tuple)
                self.assertEqual((), store._canonical_history)
                self.assertEqual('reservation_or_publication_pending',
                    definitions['failure_code'](runtime.restore_failure), context)
                self.assertEqual(0, len(launcher._tickets))
                if case == 'present38_conflict':
                    self.assertEqual(0, getattr(io, 'v46_scan_requests', 0))
                else:
                    self.assertEqual(1, io.v46_scan_requests)
                    self.assertEqual(1, io.v46_fault_hits)
                self.assertTrue(all(a and b for a, b in native.closed_facts()), context)
                self.assertFalse(io.live, context)
                totals[0] += io.create_count
                totals[1] += len(group_commands)
                totals[2] += 1
                totals[3] += getattr(io, 'v46_scan_requests', 0)
                completed.append(case)
        self.assertEqual(list(cases), completed)
        self.assertEqual([0, 0, 4, 3], totals)
        print('GO_FREQUENCY_V46_R2_BASELINE_REFUSALS_PASS cases=4 creates=%d group_adds=%d closed_cases=%d scan_requests=%d' % tuple(totals))


if __name__ == '__main__':
    unittest.main()


