"""Only two affected domains from original HOST63 FAIL; ROOT first execution.

Frozen original63 whole method remains FAIL. Its completed ten domains are
not loaded or replayed, and this method does not synthesize a twelve-domain
PASS. Actual same GO62 Loader/Entry/Store/Native/Bootstrap algorithms run in
the original explicit Linux/FD/Proc/netlink/Unix/clock model. The interface
reply mutation is now gated by actual Native interface_current/fresh/snapshot
stack before CREATE, leaving earlier channel/caps checks untouched. Known
modeled close returns EIO after once physical-model close; original error/
attempted/closedFalse, pending and no retry are mandatory. Private FD2 output
is best effort, never a business or closure requirement. Actual sources,
periods, budgets, Native methods and producer/canonical gates stay unchanged.
Only six fixed FunctionDefs load; no old TestCase/method/checker executes.
No physical device/RF/FD3/OFD/phone/full restoration evidence is claimed.
"""
import ast
import builtins
import copy
import errno
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import socket
import stat
import struct
import sys
import threading
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PLAN = 'host/go_fresh_boundary_v62_source_manifest.json'
PLAN_SHA = 'b959ae92e6ef048b3724e716e09503a7607f0b07e6eef5f4e14be71bd545e842'
PLAN_BYTES = 3955
PARENT_PLAN = 'host/go_proc_diagnostic_v60_source_manifest.json'
PARENT_PLAN_SHA = 'c2be8155c68594d2baa863c5ff6a99b38f6e231c32eb79bb2f94aeac77a210cf'
PARENT_PLAN_BYTES = 3956
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
    """No old imports/module body/ClassDef/TestCase/method is executed."""
    tree = ast.parse(_fixed(HELPER, HELPER_SHA, HELPER_BYTES), filename=HELPER)
    chosen = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    if tuple(node.name for node in chosen) != FUNCTIONS:
        raise ValueError('HOST helper definition inventory')
    domain = dict(globals())
    exec(compile(ast.Module(body=chosen, type_ignores=[]), HELPER, 'exec'), domain)
    return domain



def _fresh_source_bounds(old_raw, new_raw):
    """Only helper addition/four middle substitutions; no old algorithm runs."""
    trees = [ast.parse(raw) for raw in (old_raw, new_raw)]
    for tree in trees:
        if not tree.body or not isinstance(tree.body[0], ast.Expr) or not isinstance(tree.body[0].value, ast.Constant):
            raise ValueError('HOST documentation shape')
        tree.body.pop(0)
    classes = [[n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'NativeGoResources'] for tree in trees]
    if any(len(rows) != 1 for rows in classes): raise ValueError('HOST native class changed')
    added = [n for n in classes[1][0].body if isinstance(n, ast.FunctionDef) and n.name == '_fresh_boundary_snapshot_v62']
    exact = ast.parse('def _fresh_boundary_snapshot_v62(self):\n'
        '    if self._scope_cleanup is not False: return self._stable_snapshot()\n'
        '    value=self._snapshot_once()\n'
        '    self.observations.append(value)\n'
        '    self._check(); return value\n').body[0]
    if len(added) != 1 or ast.dump(added[0], include_attributes=False) != ast.dump(exact, include_attributes=False):
        raise ValueError('HOST exact fresh helper changed')
    classes[1][0].body.remove(added[0])
    for name in ('baseline_current', 'interface_current', 'origin_current', '_group_status'):
        methods = [n for n in classes[1][0].body if isinstance(n, ast.FunctionDef) and n.name == name]
        calls = [n for n in ast.walk(methods[0]) if isinstance(n, ast.Call) and
            isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and
            n.func.value.id == 'self' and n.func.attr == '_fresh_boundary_snapshot_v62'] if len(methods) == 1 else []
        if len(calls) != 1 or calls[0].args or calls[0].keywords:
            raise ValueError('HOST exact middle callsite changed')
        calls[0].func.attr = '_stable_snapshot'
    if ast.dump(trees[0], include_attributes=False) != ast.dump(trees[1], include_attributes=False):
        raise ValueError('HOST other Native algorithms changed')


def _inputs():
    parent = json.loads(_fixed(PARENT_PLAN, PARENT_PLAN_SHA, PARENT_PLAN_BYTES))
    current = json.loads(_fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    for tree in (parent, current):
        if (type(tree) is not dict or set(tree) != {'schema', 'sources'} or
                tree['schema'] != 'go-frequency-v46-host' or len(tree['sources']) != 17 or
                len({r['module'] for r in tree['sources']}) != 17):
            raise ValueError('HOST fixed graph')
    if any(a['module'] != b['module'] for a, b in zip(parent['sources'], current['sources'])):
        raise ValueError('HOST graph order changed')
    changes = [b['module'] for a, b in zip(parent['sources'], current['sources']) if a != b]
    if changes != ['mta_go_native']: raise ValueError('HOST lineage changed')
    rows = current['sources']
    source = {r['module']: _fixed(r['path'], r['sha256'], r['bytes']) for r in rows}
    before = next(r for r in parent['sources'] if r['module'] == 'mta_go_native')
    _fresh_source_bounds(_fixed(before['path'], before['sha256'], before['bytes']), source['mta_go_native'])
    source['HOST_WPA'] = _fixed(*WPA)
    stock = {path: _fixed(relative, sha, size) for path, relative, sha, size in STOCK}
    model = types.ModuleType('HOST_go_fresh_boundary_v63_r2_syscall_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(_fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return rows, source, stock, model


class SyscallScenario:
    """Two affected domains, original-forward OS replies/FD calls only.

    The extra interface is introduced only while actual Native stack contains
    interface_current -> fresh helper -> snapshot. Earlier channel_current
    remains unaltered, including its original caps/topology validation.
    No Native method/producer/canonical or success return is substituted.
    """
    def __init__(self, model, mode):
        self.model, self.mode, self.io, self.runtime = model, mode, None, None
        self.samples, self.triggered, self.extra = [], False, False
        self.close_error, self.close_fd, self.activation_frames = None, None, None
    def attach(self, io, runtime=None):
        self.io, self.runtime = io, runtime
    def current(self):
        if self.runtime is None and self.io.owner is not None:
            self.runtime = self.io.owner.runtime
        return self.runtime
    def install(self, stack):
        model, scenario = self.model, self
        validate, sendto, close = model.LinuxModel.validate, model.Netlink.sendto, model.LinuxModel.close
        def modeled_validate(io):
            result = validate(io)
            runtime = scenario.current()
            frame = sys._getframe(1)
            if (io is scenario.io and runtime is not None and
                    frame.f_globals is runtime.deployment.modules['mta_go_native'].__dict__ and
                    frame.f_code.co_name == '_snapshot_once'):
                scenario.samples.append(runtime.native._scope_cleanup)
            return result
        def modeled_sendto(raw, request, target):
            first = len(raw.queue)
            returned = sendto(raw, request, target)
            runtime = scenario.current()
            if raw.io is not scenario.io or runtime is None: return returned
            native = runtime.native
            size, family, flags, sequence, port = model.NL.unpack_from(request)
            command = model.GH.unpack_from(request, 16)[0] if raw.protocol != 0 else None
            if (scenario.mode == 'interface_extra' and raw.protocol == 16 and
                    family != 16 and command == 5 and native.interface_ticket is not None and
                    native._create_called is False and not scenario.extra):
                frame, names = sys._getframe(1), []
                for unused in range(32):
                    if frame is None: break
                    if (frame.f_globals is runtime.deployment.modules['mta_go_native'].__dict__ and
                            frame.f_locals.get('self') is native):
                        names.append(frame.f_code.co_name)
                    frame = frame.f_back
                path = ('_snapshot_once', '_fresh_boundary_snapshot_v62', 'interface_current')
                if (all(name in names for name in path) and
                        names.index(path[0]) < names.index(path[1]) < names.index(path[2])):
                    scenario.activation_frames = tuple(names)
                    scenario.extra = scenario.triggered = True
            if (scenario.extra and raw.protocol == 16 and family != 16 and command == 5):
                packets = raw.queue[first:]
                extra = (model.u32(1, 0) + model.attr(153, struct.pack('<Q', 100)) +
                    model.u32(3, 8) + model.attr(4, b'foreign0\0') + model.u32(5, 2) +
                    model.u32(38, 2412) + model.attr(6, b'\x02\x99\x88\x77\x66\x55'))
                packet = model.reply(request, family, model.GH.pack(7, 1, 0) + extra, 2)
                # Same original sequence/port and real typed interface bytes;
                # the changed modeled kernel remains visible during cleanup.
                packets.insert(1, (packet, [], 0, (0, 0)))
                raw.queue[first:] = packets
            return returned
        def modeled_close(io, fd):
            runtime = scenario.current()
            row = next((r for r in runtime.native.rows if r.fd == fd), None) if runtime is not None else None
            inject = (io is scenario.io and scenario.mode == 'close_unknown' and
                len(scenario.samples) == 3 and scenario.close_error is None and
                row is not None and row.kind == 'file' and row.returned is True)
            returned = close(io, fd)  # Actual shared model FD table removes it ONCE.
            if inject:
                scenario.close_fd = fd
                scenario.close_error = OSError(errno.EIO, 'HOST known close return uncertain')
                scenario.triggered = True
                raise scenario.close_error
            return returned
        stack.enter_context(mock.patch.object(model.LinuxModel, 'validate', modeled_validate))
        stack.enter_context(mock.patch.object(model.Netlink, 'sendto', modeled_sendto))
        stack.enter_context(mock.patch.object(model.LinuxModel, 'close', modeled_close))


class GoFreshBoundaryV63R2Tests(unittest.TestCase):
    def fixture(self, definitions, rows, source, stock, model, stack, mode):
        definitions['tripwires'](stack)
        io, modules, deployment, loader, executor, created = definitions['load_model'](
            rows, source, stock, model, None, stack)
        scenario = SyscallScenario(model, mode)
        scenario.attach(io); scenario.install(stack)
        private_writes = []
        def capture_private(fd, raw):
            self.assertEqual(2, fd); self.assertIs(type(raw), bytes)
            self.assertLessEqual(len(raw), 16384)
            private_writes.append(raw)
            return len(raw)
        stack.enter_context(mock.patch.object(executor.os, 'write', capture_private))
        return io, modules, deployment, loader, executor, created, scenario, private_writes

    def construct(self, fixture, model):
        io, modules, deployment, loader, executor, created, scenario, writes = fixture
        entry = executor._entry(deployment, model.UNTIL, repr(model.UNTIL),
            '--go-bootstrap', io.clock, io)
        self.assertEqual(4.0, entry.accounting._io_deadline)
        runtime = modules['mta_go_bootstrap'].GoBootstrap(deployment, entry, clock=io.clock)
        self.assertEqual([runtime], created)
        scenario.attach(io, runtime)
        return runtime

    def inventory(self, fixture, runtime, model):
        io, modules, deployment, loader, executor, created, scenario, writes = fixture
        native, store, entry = runtime.native, runtime.store, runtime.entry
        self.assertIs(type(runtime), modules['mta_go_bootstrap'].GoBootstrap)
        self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
        self.assertIs(type(store), modules['mta_go_bootstrap_store'].GoBootstrapStore)
        self.assertIs(store._native_original, native)
        self.assertIs(store._launcher_original, runtime.launcher)
        self.assertIs(store.owner, runtime)
        self.assertIs(deployment.loader.runtime, runtime)
        self.assertIs(loader.value, deployment)
        self.assertEqual(model.UNTIL, runtime.until)
        self.assertEqual(model.UNTIL, entry.until)
        self.assertEqual(repr(model.UNTIL), entry.until_text)
        self.assertEqual(model.UNTIL, native.until)
        self.assertEqual(model.UNTIL, store.until)
        self.assertIs(entry.accounting._resource_budget_v23, entry.budget)
        self.assertIs(entry.reader._bound_budget_v24, entry.budget)
        self.assertFalse(entry.accounting._attempted)
        self.assertFalse(entry.accounting._opened)
        self.assertTrue(entry.reader.history_closed())
        self.assertTrue(all(row['closed'] and not row['unknown'] for row in loader.owner.rows))
        self.assertEqual(len(io.closed), len(set(io.closed)))
        self.assertFalse(runtime.status()['go_ready'])
        self.assertFalse(store.status()['device_tested'])
        self.assertFalse(native.status()['phone_tested'])
        for canonical in store._canonical_history:
            self.assertIs(type(canonical), modules['mta_go_bootstrap_store'].GoCanonical)
            self.assertIs(canonical.issuer, store.issuer)
            self.assertEqual(model.UNTIL, canonical.record.until)
            self.assertEqual(canonical.record.key(), modules['mta_go_bootstrap_store'].decode(canonical.raw).key())
            self.assertNotIn(b'HOST_PRIVATE_NOT_A_CREDENTIAL', canonical.raw)
        for ticket in runtime.launcher._tickets:
            self.assertEqual(model.UNTIL, ticket.deadline)
            self.assertIs(ticket.owner, runtime.launcher)
        return [row for row in native.observations if type(row) is modules['mta_p2p_client_init'].Snapshot]

    def closed(self, fixture, runtime):
        io, modules, deployment, loader, executor, created, scenario, writes = fixture
        self.assertTrue(all(a and b for a, b in runtime.native.closed_facts()))
        self.assertTrue(all(a and b for a, b in runtime.store.closed_facts()))
        self.assertFalse(io.live)

    def full(self, fixture, model):
        io, modules, deployment, loader, executor, created, scenario, writes = fixture
        answer = executor.bootstrap(deployment, model.UNTIL, repr(model.UNTIL),
            _clock=io.clock, _proc_fs=io)
        self.assertEqual(1, len(created))
        runtime = created[0]
        self.assertIs(scenario.current(), runtime)
        return answer, runtime

    def test_only_interface_fresh_extra_and_uncertain_close_affected_denials(self):
        rows, source, stock, model = _inputs()
        definitions = _definitions()
        names, complete, refusals, calls, close_once = ('interface_extra', 'close_unknown'), [], 0, 0, 0
        for name in names:
            with self.subTest(case=name), ExitStack() as stack:
                fixture = self.fixture(definitions, rows, source, stock, model, stack, name)
                io, modules, deployment, loader, executor, created, scenario, writes = fixture
                sources, core = modules['mta_go_deployment'], modules['mta_p2p_client_init']
                answer, runtime = self.full(fixture, model)
                calls += 1
                snapshots = self.inventory(fixture, runtime, model)
                native, store = runtime.native, runtime.store
                context = definitions['diagnostic'](runtime)
                self.assertEqual(1, answer, context)
                self.assertTrue(scenario.triggered, context)
                self.assertFalse(runtime.group_confirmed)
                self.assertFalse(store.logical_restored)
                self.assertFalse(store.marker_cleared)
                self.assertEqual('restore_pending', runtime.phase)
                self.assertIsNotNone(runtime.restore_failure)
                self.assertIsNone(runtime.restore_observation)
                self.assertIsNone(native.restored)
                self.assertEqual(0, io.create_count)
                self.assertEqual(0, io.delete_count)
                self.assertFalse(native._create_called)
                self.assertIsNone(native.owned)
                self.assertFalse(native._group_submit_called)
                self.assertIsNone(runtime.controller)
                self.assertEqual(model.UNTIL, runtime.until)
                self.assertEqual(model.UNTIL, runtime.entry.until)
                self.assertEqual(model.UNTIL, native.until)
                self.assertEqual(model.UNTIL, store.until)
                # Diagnostics are best effort. If actual F emitted anything,
                # original capture still enforces FD2/byte type/16KiB; missing
                # private output is NOT a changed business or closure result.
                self.assertTrue(all(type(raw) is bytes and len(raw) <= 16384 for raw in writes))
                if name == 'interface_extra':
                    self.assertIs(type(runtime.failure), sources.GoSourceError)
                    self.assertEqual('native_baseline_changed', runtime.failure.code)
                    self.assertIsNotNone(native.interface_ticket)
                    self.assertIsNotNone(native.channel)
                    self.assertEqual(2412, native.channel.frequency)
                    self.assertIsNone(native.create_request)
                    self.assertIsNotNone(scenario.activation_frames)
                    path = ('_snapshot_once', '_fresh_boundary_snapshot_v62', 'interface_current')
                    self.assertTrue(all(v in scenario.activation_frames for v in path))
                    self.assertLess(scenario.activation_frames.index(path[0]), scenario.activation_frames.index(path[1]))
                    self.assertLess(scenario.activation_frames.index(path[1]), scenario.activation_frames.index(path[2]))
                    self.assertIn('interface_intent', store._calls)
                    self.assertEqual(5, len(store._canonical_history))
                    self.assertEqual(list(modules['mta_go_bootstrap_store']._ACTIVE_PHASES[:4]) +
                        ['restore_intent'], [c.record.phase for c in store._canonical_history])
                    self.assertIs(store.current, store._canonical_history[-1])
                    self.assertEqual('watchdog_live', store._canonical_history[-2].record.phase)
                    self.assertEqual('restore_intent', store.current.record.phase)
                    self.assertEqual(4, store.current.record.generation)
                    self.assertTrue(any(row.name == 'foreign0' for snap in snapshots for row in snap.interfaces))
                    self.assertIs(type(runtime.restore_failure), sources.GoSourceError)
                    self.assertEqual('native_baseline_changed', runtime.restore_failure.code)
                    self.assertIn('/var/volatile/tmp/p011-mta-p2p-device.pending', io.nodes)
                    self.assertEqual(1, len(runtime.launcher._tickets))
                    self.assertTrue(runtime.watchdog.waited)
                    self.assertTrue(runtime.watchdog.exit_verified)
                    self.assertEqual([200], io.stopped)
                    self.assertEqual([200], io.reaped)
                    self.assertTrue(all(row.closed and not row.unknown for row in runtime.watchdog.fds))
                    self.assertTrue(all(a and b for a, b in native.closed_facts()))
                    self.assertTrue(all(a and b for a, b in store.closed_facts()))
                    self.assertFalse(io.live)
                else:
                    self.assertIsNotNone(scenario.close_error)
                    self.assertIs(runtime.failure, scenario.close_error)
                    self.assertIs(type(runtime.failure), OSError)
                    self.assertEqual(errno.EIO, runtime.failure.errno)
                    row = next(r for r in native.rows if r.fd == scenario.close_fd)
                    self.assertIs(row.close_failure, scenario.close_error)
                    self.assertIs(row.native, native)
                    self.assertIs(type(row), modules['mta_go_native']._Resource)
                    self.assertIs(row, native._history[native.rows.index(row)])
                    self.assertTrue(row.returned)
                    self.assertTrue(row.attempted)
                    self.assertFalse(row.closed)
                    self.assertFalse(row.unknown)
                    self.assertEqual(1, io.closed.count(scenario.close_fd))
                    self.assertNotIn(scenario.close_fd, io.live)
                    self.assertFalse(all(a and b for a, b in native.closed_facts()))
                    before_closed, before_calls = list(io.closed), list(io.calls)
                    with native.mutex, self.assertRaises(sources.GoSourceError) as caught:
                        native._close(row)
                    self.assertEqual('native_close_pending', caught.exception.code)
                    self.assertIs(row.close_failure, scenario.close_error)
                    self.assertTrue(row.attempted)
                    self.assertFalse(row.closed)
                    self.assertFalse(row.unknown)
                    self.assertEqual(before_closed, io.closed)
                    self.assertEqual(before_calls, io.calls)
                    self.assertIsNone(store.current)
                    self.assertEqual((), store._canonical_history)
                    self.assertIs(type(runtime.restore_failure), sources.GoSourceError)
                    self.assertEqual('reservation_or_publication_pending', runtime.restore_failure.code)
                    self.assertEqual([], runtime.launcher._tickets)
                    self.assertTrue(all(a and b for a, b in store.closed_facts()))
                    self.assertFalse(io.live)
                    # Missing marker is merely actual zero-publication data;
                    # it does not erase retained uncertain Native closure.
                    self.assertNotIn('/var/volatile/tmp/p011-mta-p2p-device.pending', io.nodes)
                    close_once += 1
                refusals += 1
                complete.append(name)
        self.assertEqual(list(names), complete)
        self.assertEqual((2, 2, 1), (refusals, calls, close_once))
        print('GO_FRESH_BOUNDARY_V63_R2_HOST_PASS domains=2 refusals=2 full_runs=2 '
            'interface_fresh=1 uncertain_close_once=1 old10_replayed=0 rf_physical=0')


if __name__ == '__main__': unittest.main()
