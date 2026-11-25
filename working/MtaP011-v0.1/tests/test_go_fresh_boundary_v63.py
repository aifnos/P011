"""One new v63 affected fresh-boundary HOST method; ROOT alone executes.

Actual fixed GO62 Loader/Entry/neutral Store/bound ProcReader/GO Store/
Native/ProcessOwner/Bootstrap algorithms run in explicit Linux/FD/Proc/
netlink/Unix/clock models. One unwrapped normal full run retains 21 actual
Snapshots: initial2 + active11 + cleanup8. Only model syscalls/reply bytes
change in fault domains; Native methods, observations, canonical issuers,
budgets and success results are never substituted. Twelve fresh domains
cover each changed callsite, retained initial/restore double samples, an
uncertain close and final helper deadline/cancel. Actual cleanup fallback
is observed after the normal run; unknown scope is deny-only model data.
Terminal clock hooks run only the first actual snapshot diagnostic tail,
then original append/_check refuses; this is not a baseline grant.
Only six fixed FunctionDefs load, never any prior TestCase/method/checker.
No device, physical RF/FD3/watchdog/OFD, phone or performance PASS exists.
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
    model = types.ModuleType('HOST_go_fresh_boundary_v63_syscall_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(_fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return rows, source, stock, model


class SyscallScenario:
    """Reply/FD/clock hooks forward the original explicit OS model only.

    No Native function is patched. validate() is an OS validation event, not a
    successful Snapshot/grant. Counts also require exact actual retained data.
    The constructor's model fork executes its original parent branch only.
    """
    def __init__(self, model, mode):
        self.model, self.mode, self.io, self.runtime = model, mode, None, None
        self.samples, self.cleanup_samples, self.triggered = [], 0, False
        self.route_changed = self.extra = self.owned_changed = False
        self.close_error, self.close_fd, self.clock_fired = None, None, False
        self.ap_statuses = 0
    def attach(self, io, runtime=None):
        self.io, self.runtime = io, runtime
    def current(self):
        if self.runtime is None and self.io.owner is not None:
            self.runtime = self.io.owner.runtime
        return self.runtime
    def install(self, stack):
        model, scenario = self.model, self
        validate, sendto, unix_send, close, clock = (
            model.LinuxModel.validate, model.Netlink.sendto, model.Unix.send,
            model.LinuxModel.close, model.Clock.__call__)
        def modeled_validate(io):
            result = validate(io)
            runtime = scenario.current()
            frame = sys._getframe(1)
            if (io is scenario.io and runtime is not None and
                    frame.f_globals is runtime.deployment.modules['mta_go_native'].__dict__ and
                    frame.f_code.co_name == '_snapshot_once'):
                flag = runtime.native._scope_cleanup
                scenario.samples.append(flag)
                if flag is True: scenario.cleanup_samples += 1
                if scenario.mode == 'initial_second' and len(scenario.samples) == 2:
                    scenario.route_changed = scenario.triggered = True
                if scenario.mode == 'restore_second' and flag is True and scenario.cleanup_samples == 2:
                    scenario.route_changed = scenario.triggered = True
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
                    native._create_called is False):
                scenario.extra = scenario.triggered = True
            if (scenario.mode == 'origin_identity' and raw.protocol == 16 and
                    family != 16 and command == 5 and native.owned is not None and
                    raw.io.netdev == 8 and native._scope_cleanup is False):
                scenario.owned_changed = scenario.triggered = True
            if (scenario.mode == 'group_kernel' and raw.protocol == 16 and family != 16 and
                    command == 5 and raw.io.netdev == 9):
                scenario.owned_changed = scenario.triggered = True
            packets = raw.queue[first:]
            if raw.protocol == 0 and family == 26 and scenario.route_changed:
                rewritten = []
                for packet, ancillary, msgflags, peer in packets:
                    n, kind, bits, seq, pid = model.NL.unpack_from(packet)
                    body = packet[16:n]
                    if kind == 24:
                        body += model.u32(6, 1)  # Actual modeled RTA_PRIORITY, not a Snapshot.
                        packet = model.reply(request, kind, body, bits)
                    rewritten.append((packet, ancillary, msgflags, peer))
                raw.queue[first:] = rewritten
            if raw.protocol == 16 and family != 16 and command == 5:
                rewritten = []
                for packet, ancillary, msgflags, peer in packets:
                    n, kind, bits, seq, pid = model.NL.unpack_from(packet)
                    body = packet[16:n]
                    if kind == family and len(body) >= 4:
                        fields, at = [], 4
                        while at < len(body):
                            length, attrtype = struct.unpack_from('<HH', body, at)
                            value = body[at + 4:at + length]
                            fields.append((attrtype, value)); at += (length + 3) & ~3
                        owned = any(k == 3 and v == struct.pack('<I', 7) for k, v in fields)
                        if owned and scenario.owned_changed:
                            if scenario.mode == 'origin_identity':
                                fields = [(k, struct.pack('<Q', 100) if k == 153 else v) for k, v in fields]
                            elif scenario.mode == 'group_kernel' and any(
                                    k == 5 and v == struct.pack('<I', 9) for k, v in fields):
                                fields = [(k, struct.pack('<I', 2417) if k == 38 else v) for k, v in fields]
                            packet = model.reply(request, family,
                                body[:4] + b''.join(model.attr(k, v) for k, v in fields), bits)
                    rewritten.append((packet, ancillary, msgflags, peer))
                if scenario.extra:
                    extra = (model.u32(1, 0) + model.attr(153, struct.pack('<Q', 100)) +
                        model.u32(3, 8) + model.attr(4, b'foreign0\0') + model.u32(5, 2) +
                        model.u32(38, 2412) + model.attr(6, b'\x02\x99\x88\x77\x66\x55'))
                    packet = model.reply(request, family, model.GH.pack(7, 1, 0) + extra, 2)
                    rewritten.insert(1, (packet, [], 0, (0, 0)))
                raw.queue[first:] = rewritten
            return returned
        def modeled_unix_send(raw, wire):
            returned = unix_send(raw, wire)
            if raw.io is scenario.io and raw.peer != '/run/wpa_supplicant/wlan0' and wire == b'STATUS':
                scenario.ap_statuses += 1
            return returned
        def modeled_close(io, fd):
            runtime = scenario.current()
            row = next((r for r in runtime.native.rows if r.fd == fd), None) if runtime is not None else None
            inject = (io is scenario.io and scenario.mode == 'close_unknown' and
                len(scenario.samples) == 3 and scenario.close_error is None and
                row is not None and row.kind == 'file' and row.returned is True)
            returned = close(io, fd)  # The modeled FD physically closes once.
            if inject:
                scenario.close_fd = fd
                scenario.close_error = OSError(errno.EIO, 'HOST known close return uncertain')
                scenario.triggered = True
                raise scenario.close_error
            return returned
        def modeled_clock(value):
            answer = clock(value)
            runtime = scenario.current()
            if (value is getattr(scenario.io, 'clock', None) and runtime is not None and
                    scenario.mode in ('terminal_deadline', 'terminal_cancel') and not scenario.clock_fired):
                frame = sys._getframe(1)
                native_module = runtime.deployment.modules['mta_go_native']
                # Explicit HOST clock/frame hook, not altered production code:
                # first real snapshot's final diagnostic read returns its old
                # value, then original append/_check observes the changed clock
                # or caller stop. This does not test baseline_current/authority.
                if (frame.f_globals is native_module.__dict__ and
                        frame.f_code.co_name == '_timing_mark_v55' and
                        frame.f_locals.get('index') == 4 and
                        frame.f_locals.get('row') is runtime.native._snapshot_timing_v55[0]):
                    scenario.clock_fired = scenario.triggered = True
                    if scenario.mode == 'terminal_deadline': value.value = runtime.native._scope
                    else: runtime.stop_requested = True
            return answer
        stack.enter_context(mock.patch.object(model.LinuxModel, 'validate', modeled_validate))
        stack.enter_context(mock.patch.object(model.Netlink, 'sendto', modeled_sendto))
        stack.enter_context(mock.patch.object(model.Unix, 'send', modeled_unix_send))
        stack.enter_context(mock.patch.object(model.LinuxModel, 'close', modeled_close))
        stack.enter_context(mock.patch.object(model.Clock, '__call__', modeled_clock))


class GoFreshBoundaryV63Tests(unittest.TestCase):
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

    def test_actual_single_fresh_boundaries_and_retained_double_restore_gates(self):
        rows, source, stock, model = _inputs()
        definitions = _definitions()
        names = ('normal', 'baseline_stock', 'baseline_routes', 'interface_extra',
            'origin_identity', 'group_kernel', 'initial_second', 'restore_second',
            'close_unknown', 'terminal_deadline', 'terminal_cancel', 'unknown_scope')
        complete, refusals, full_runs, fallback_pairs = [], 0, 0, 0
        normal_counts = None
        for name in names:
            with self.subTest(case=name), ExitStack() as stack:
                fixture = self.fixture(definitions, rows, source, stock, model, stack, name)
                io, modules, deployment, loader, executor, created, scenario, writes = fixture
                sources, core = modules['mta_go_deployment'], modules['mta_p2p_client_init']
                if name in ('normal', 'interface_extra', 'origin_identity', 'group_kernel',
                        'restore_second', 'close_unknown'):
                    answer, runtime = self.full(fixture, model)
                    full_runs += 1
                    snapshots = self.inventory(fixture, runtime, model)
                    context = definitions['diagnostic'](runtime)
                    if name == 'normal':
                        self.assertEqual(0, answer, context)
                        self.assertIsNone(runtime.failure)
                        self.assertIsNone(runtime.restore_failure)
                        self.assertTrue(runtime.group_confirmed)
                        self.assertEqual('restored', runtime.phase)
                        self.assertTrue(runtime.store.logical_restored)
                        self.assertTrue(runtime.store.marker_cleared)
                        self.assertEqual('reconciled', runtime.store.current.record.phase)
                        self.assertEqual(12, runtime.store.current.record.generation)
                        self.assertIs(runtime.store.current, runtime.store._canonical_history[-1])
                        self.assertEqual(13, len(runtime.store._canonical_history))
                        self.assertEqual({'prepare': 4, 'positive': 7, 'cleanup': 2}, runtime.store._publication_counts)
                        self.assertEqual(list(modules['mta_go_bootstrap_store']._ACTIVE_PHASES) +
                            ['restore_intent', 'reconciled'], [c.record.phase for c in runtime.store._canonical_history])
                        self.assertEqual(21, len(snapshots))
                        self.assertEqual([False] * 13 + [True] * 8, scenario.samples)
                        self.assertIs(runtime.native.baseline.snapshot, snapshots[1])
                        self.assertEqual(snapshots[0].key(), snapshots[1].key())
                        self.assertIs(runtime.native.restored.snapshot, snapshots[-3])
                        self.assertEqual(runtime.native.restored.snapshot.key(), snapshots[-1].key())
                        self.assertEqual(snapshots[-2].key(), snapshots[-1].key())
                        self.assertEqual(runtime.native.baseline.snapshot.key(), runtime.native.restored.snapshot.key())
                        self.assertEqual(3, scenario.ap_statuses)  # wait2 + durable confirm1, not one STATUS.
                        self.assertIs(type(runtime.native.group), modules['mta_go_native'].GoGroupObservation)
                        self.assertEqual(2412, runtime.native.group.frequency)
                        self.assertEqual(9, runtime.native.group.observed_origin.iftype)
                        self.assertEqual(8, runtime.native.owned.iftype)
                        self.assertEqual([8, 9, 8], io.iftypes)
                        self.assertEqual(1, io.create_count); self.assertEqual(1, io.delete_count)
                        self.assertIsNone(io.netdev)
                        echo = runtime.native._create_echo_original
                        self.assertIs(type(echo), tuple)
                        self.assertIs(echo[1], runtime.native.interface_ticket)
                        self.assertIs(echo[2], runtime.native.owned)
                        self.assertEqual(echo[0], runtime.native.create_request)
                        create = [raw for raw in io.sockets if isinstance(raw, model.Netlink)
                            and any(model.GH.unpack_from(wire, 16)[0] == 7 for wire in raw.sent if raw.protocol == 16)]
                        self.assertEqual(1, len(create))
                        returned = [item[1] for item in runtime.native.raw if type(item) is tuple and
                            item[0] == 'kernel_raw' and type(item[1]) is bytes]
                        self.assertTrue(any(model.NL.unpack_from(raw)[1] == 2 and raw[16:20] == b'\0' * 4 and
                            raw[20:36] == runtime.native.create_request[:16] for raw in returned))
                        self.assertEqual([300, 200], io.stopped)
                        self.assertEqual([300, 200], io.reaped)
                        self.assertTrue(all(t.waited and t.exit_verified for t in runtime.launcher._tickets))
                        self.assertTrue(all(r.closed and not r.unknown for t in runtime.launcher._tickets for r in t.fds))
                        self.assertNotIn('/var/volatile/tmp/p011-mta-p2p-device.pending', io.nodes)
                        self.assertEqual([], writes)
                        self.closed(fixture, runtime)
                        normal_counts = (21, 2, 11, 8, 3, 13)
                        # Actual cleanup source (original once period and lane)
                        # still selects stable double samples. This observation
                        # is separate from the completed 21-snapshot full run.
                        count, observations = len(scenario.samples), len(snapshots)
                        with runtime.native.mutex:
                            runtime.native._begin(runtime.cleanup_until, True)
                            observed = runtime.native._fresh_boundary_snapshot_v62()
                        later = self.inventory(fixture, runtime, model)
                        self.assertEqual(count + 2, len(scenario.samples))
                        self.assertEqual(observations + 2, len(later))
                        self.assertIs(observed, later[-1])
                        self.assertEqual(later[-2].key(), later[-1].key())
                        self.assertEqual([True, True], scenario.samples[-2:])
                        self.assertEqual(13, len(runtime.store._canonical_history))
                        self.closed(fixture, runtime); fallback_pairs += 1
                    else:
                        self.assertEqual(1, answer, context)
                        self.assertTrue(scenario.triggered, context)
                        self.assertEqual(name == 'restore_second', runtime.group_confirmed)
                        if name != 'group_kernel':
                            self.assertFalse(runtime.store.logical_restored)
                            self.assertFalse(runtime.store.marker_cleared)
                            self.assertEqual('restore_pending', runtime.phase)
                            self.assertIsNotNone(runtime.restore_failure)
                        if name == 'interface_extra':
                            self.assertIs(type(runtime.failure), sources.GoSourceError)
                            self.assertEqual('native_baseline_changed', runtime.failure.code)
                            self.assertIsNotNone(runtime.native.interface_ticket)
                            self.assertFalse(runtime.native._create_called)
                            self.assertIsNone(runtime.native.owned)
                            self.assertEqual(0, io.create_count)
                        elif name == 'origin_identity':
                            self.assertIs(type(runtime.failure), sources.GoSourceError)
                            self.assertEqual('native_origin_changed', runtime.failure.code)
                            self.assertEqual(1, io.create_count)
                            self.assertEqual(8, runtime.native.owned.iftype)
                            self.assertIs(runtime.native._create_echo_original[2], runtime.native.owned)
                            self.assertIsNotNone(runtime.native.create_request)
                            self.assertEqual(0, io.delete_count)
                        elif name == 'group_kernel':
                            # Only GO9 kernel frequency is changed; immutable
                            # actual event and AP STATUS both still report2412.
                            self.assertIs(type(runtime.failure), sources.GoSourceError)
                            self.assertEqual('native_go_origin_changed', runtime.failure.code)
                            self.assertTrue(runtime.native._group_submit_called)
                            self.assertIsNone(runtime.native.group)
                            self.assertEqual(1, scenario.ap_statuses)
                            self.assertEqual(1, io.delete_count)
                            self.assertIsNone(io.netdev)
                            # The original failed business path may reconcile
                            # known resources. This is not successful group/whole
                            # operation: answer1 and original failure persist.
                            self.assertTrue(runtime.store.logical_restored)
                            self.assertTrue(runtime.store.marker_cleared)
                            self.assertEqual('restored', runtime.phase)
                            self.assertIsNone(runtime.restore_failure)
                            self.closed(fixture, runtime)
                        elif name == 'restore_second':
                            self.assertIsNone(runtime.failure)
                            self.assertTrue(runtime.group_confirmed)
                            self.assertIs(type(runtime.restore_failure), sources.GoSourceError)
                            self.assertEqual('native_baseline_unstable', runtime.restore_failure.code)
                            self.assertEqual(2, scenario.cleanup_samples)
                            self.assertEqual(0, io.delete_count)
                            self.assertEqual('restore_intent', runtime.store.current.record.phase)
                            self.assertEqual(11, runtime.store.current.record.generation)
                            self.assertIsNone(runtime.native.restored)
                            self.assertEqual([300, 200], io.reaped)
                        elif name == 'close_unknown':
                            self.assertIsNotNone(scenario.close_error)
                            row = next(r for r in runtime.native.rows if r.fd == scenario.close_fd)
                            self.assertIs(row.close_failure, scenario.close_error)
                            self.assertTrue(row.attempted)
                            self.assertFalse(row.closed)
                            self.assertEqual(1, io.closed.count(scenario.close_fd))
                            self.assertFalse(all(a and b for a, b in runtime.native.closed_facts()))
                            before = len(io.closed)
                            with runtime.native.mutex, self.assertRaises(sources.GoSourceError) as caught:
                                runtime.native._close(row)
                            self.assertEqual('native_close_pending', caught.exception.code)
                            self.assertEqual(before, len(io.closed))
                            self.assertEqual(0, io.create_count)
                        if name != 'group_kernel':
                            self.assertFalse(all(a and b for a, b in runtime.native.closed_facts()) and
                                runtime.store.logical_restored)
                        self.assertTrue(writes)
                        self.assertTrue(all(len(raw) <= 16384 for raw in writes))
                        refusals += 1
                else:
                    runtime = self.construct(fixture, model)
                    with runtime.native.mutex:
                        end = runtime._stage(15)
                        runtime.native._begin(end)
                        self.assertEqual(16.0, end)
                        if name == 'initial_second':
                            with self.assertRaises(sources.GoSourceError) as caught:
                                runtime.native.observe_baseline(end)
                            self.assertEqual('native_baseline_unstable', caught.exception.code)
                            self.assertEqual(2, len(scenario.samples))
                            snapshots = self.inventory(fixture, runtime, model)
                            self.assertEqual(2, len(snapshots))
                            self.assertNotEqual(snapshots[0].key(), snapshots[1].key())
                            self.assertIsNone(runtime.native.baseline)
                            refusals += 1
                        elif name in ('baseline_stock', 'baseline_routes'):
                            original = runtime.native.observe_baseline(end)
                            if name == 'baseline_stock':
                                node = io.nodes['/usr/bin/Z03']
                                node.data = node.data[:-1] + bytes([node.data[-1] ^ 1])
                                expected = 'native_stock_pin_changed'
                                scenario.triggered = True
                            else:
                                scenario.route_changed = scenario.triggered = True
                                expected = 'native_baseline_changed'
                            with self.assertRaises(sources.GoSourceError) as caught:
                                runtime.native.baseline_current(original, end)
                            self.assertEqual(expected, caught.exception.code)
                            self.assertIs(runtime.native.baseline, original)
                            self.assertEqual(3, len(scenario.samples))
                            snapshots = self.inventory(fixture, runtime, model)
                            self.assertEqual(2 if name == 'baseline_stock' else 3, len(snapshots))
                            refusals += 1
                        elif name in ('terminal_deadline', 'terminal_cancel'):
                            with self.assertRaises(sources.GoSourceError) as caught:
                                runtime.native._fresh_boundary_snapshot_v62()
                            self.assertEqual('deadline' if name == 'terminal_deadline' else 'stop_requested', caught.exception.code)
                            self.assertTrue(scenario.clock_fired)
                            snapshots = self.inventory(fixture, runtime, model)
                            self.assertEqual(1, len(snapshots))
                            self.assertEqual([False], scenario.samples)
                            self.assertEqual(1, len(runtime.native._snapshot_timing_v55))
                            self.assertIsNotNone(runtime.native._snapshot_timing_v55[0][4][4])
                            self.assertEqual(16.0, runtime.native._scope)
                            self.assertEqual(16.0, runtime.entry.accounting._io_deadline)
                            self.assertEqual(16.0 if name == 'terminal_deadline' else 1.0, io.clock.value)
                            self.assertIsNone(runtime.native.baseline)
                            refusals += 1
                        elif name == 'unknown_scope':
                            # Deny-only unknown flag: it is not a cleanup source,
                            # grant or current durable fact. Exact is-False
                            # dispatch must preserve old two-read behavior.
                            runtime.native._scope_cleanup = None
                            observed = runtime.native._fresh_boundary_snapshot_v62()
                            snapshots = self.inventory(fixture, runtime, model)
                            self.assertEqual(2, len(snapshots))
                            self.assertEqual([None, None], scenario.samples)
                            self.assertIs(observed, snapshots[-1])
                            self.assertEqual(snapshots[0].key(), snapshots[1].key())
                            self.assertIsNone(runtime.native._scope_cleanup)
                            self.assertFalse(runtime.restore_attempted)
                            fallback_pairs += 1
                    self.assertEqual((), runtime.store._canonical_history)
                    self.assertIsNone(runtime.store.current)
                    self.assertFalse(runtime.store.restore_attempted)
                    self.assertEqual(0, io.create_count); self.assertEqual(0, io.delete_count)
                    self.assertEqual([], runtime.launcher._tickets)
                    self.assertEqual([], writes)
                    self.closed(fixture, runtime)
                self.assertEqual(301.0, runtime.until)
                self.assertEqual(301.0, runtime.entry.until)
                self.assertEqual(301.0, runtime.native.until)
                self.assertEqual(301.0, runtime.store.until)
                complete.append(name)
        self.assertEqual(list(names), complete)
        self.assertEqual(10, refusals)
        self.assertEqual(6, full_runs)
        self.assertEqual(2, fallback_pairs)
        self.assertEqual((21, 2, 11, 8, 3, 13), normal_counts)
        print('GO_FRESH_BOUNDARY_V63_HOST_PASS domains=12 refusals=10 full_runs=6 '
            'snapshots=21 initial=2 active=11 restore=8 ap_status=3 journal=13 fallback_pairs=2 rf_physical=0')


if __name__ == '__main__': unittest.main()
