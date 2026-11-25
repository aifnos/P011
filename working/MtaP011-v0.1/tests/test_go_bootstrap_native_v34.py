"""One new fixed GO17 full algorithm HOST model; ROOT first execution only.

ROOT alone performs the first fixed-source execution after final r5 review.
The actual Loader/F Entry/neutral budget/GO Store/ProcessOwner/Native/Bootstrap
definitions run; no native producer, canonical, grant or restored flag is faked.
Linux files, FD/OFD, Proc, fork/exec, netlink, Unix credentials and clock are
explicit models. Python/CLI bytes are HOST fixtures, not device identities.
WPA/stock-three bytes are actual archived PC inputs. No device/phone/RF proof.
No old TestCase, old checker, archived START or production preparer runs.
"""
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
PLAN = 'host/go_bootstrap_native_v34_source_manifest.json'
PLAN_SHA = '491b08d4754fcbf5d3dc203c48cf73a5d274bf5fc4da7d46fbb41a3af55ea296'
PLAN_BYTES = 3952
MODEL = 'tests/go_bootstrap_host_model_v34.py'
MODEL_SHA = '97bb530656aa569f3677c66c24c3109651b7bfa5284c3de67459926ac5cf6155'
MODEL_BYTES = 25092
STOCK = (
    ('/usr/bin/Z03', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/Z03',
        'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a', 4103844),
    ('/usr/bin/control_engine', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/control_engine',
        '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d', 163184),
    ('/usr/bin/zyb_z03_launch.sh', '../../06_Firmware/backups/v2.4.0-20260923-162730/files/zyb_z03_launch.sh',
        '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b', 1913))
WPA = ('native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
    'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301', 1351192)


def fixed(path, sha, size):
    raw = (BASE / path).read_bytes()
    if type(sha) is not str or type(size) is not int or len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('HOST input identity changed or draft unpinned')
    return raw


def source_inputs():
    plan = json.loads(fixed(PLAN, PLAN_SHA, PLAN_BYTES))
    if type(plan) is not dict or set(plan) != {'schema', 'sources'} or plan['schema'] != 'go-bootstrap-native-v34-host':
        raise ValueError('HOST graph changed')
    rows = plan['sources']
    if len(rows) != 17 or len({row['module'] for row in rows}) != 17:
        raise ValueError('HOST graph changed')
    source = {row['module']: fixed(row['path'], row['sha256'], row['bytes']) for row in rows}
    source['HOST_WPA'] = fixed(*WPA)
    stock = {path: fixed(relative, sha, size) for path, relative, sha, size in STOCK}
    model = types.ModuleType('HOST_go17_model')
    model.__file__ = str(BASE / MODEL)
    exec(compile(fixed(MODEL, MODEL_SHA, MODEL_BYTES), model.__file__, 'exec'), model.__dict__)
    return rows, source, stock, model


def tripwires(stack):
    for name in ('socket.socket', 'socket.create_connection', 'subprocess.Popen', 'ctypes.CDLL',
            'os.open', 'os.read', 'os.write', 'os.close', 'os.fstat', 'os.stat', 'os.lstat',
            'os.listdir', 'os.readlink', 'os.fork', 'os.execve', 'os.kill', 'os.waitpid',
            'os.system', 'os.urandom', 'os.mkdir', 'os.unlink', 'os.rename', 'os.fsync',
            'threading.Thread.start', 'time.sleep'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('HOST actual platform forbidden'), create=True))
    # Windows ancillary size availability is a pure ABI model, not socket IO.
    stack.enter_context(mock.patch.object(socket, 'CMSG_SPACE', lambda n: 16 + ((n + 7) // 8) * 8, create=True))


def load_model(rows, source, stock, model, fault, stack):
    """Actual Loader loads one original graph; F/Loader are not exec'd twice."""
    io = model.LinuxModel(rows, source, stock, fault)
    schema = {'schema': 'p011-go-bootstrap-v33', 'go': {
        'version': 1, 'run_token': model.TOKEN, 'candidate_sha': 'a' * 64, 'task_id': 'HOST_GO17',
        'ifname': 'mta66666666', 'python_sha': hashlib.sha256(model.arm_python_fixture()).hexdigest(),
        'sources': [[row['module'], row['sha256']] for row in rows],
        'baseline_manifest': [[path, sha] for path, relative, sha, size in STOCK] +
            [['/usr/sbin/wpa_cli', hashlib.sha256(model.CLI).hexdigest()]]}}
    manifest_raw = json.dumps(schema, ensure_ascii=True, sort_keys=True).encode('ascii')
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    io.add(io.run + '/deployment.json', stat.S_IFREG | 0o400, manifest_raw)
    modules, original_import = {}, builtins.__import__
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules or level: raise ImportError('HOST unlisted boot source')
            return modules[name]
        return original_import(name, globals, locals, fromlist, level)
    for name in ('mta_go_deployment', 'mta_go_executor'):
        module = types.ModuleType(name); module.__file__ = io.run + '/runtime/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        stack.enter_context(mock.patch.dict(sys.modules, {name: module}))
        exec(compile(source[name], module.__file__, 'exec'), module.__dict__)
    sources, executor = modules['mta_go_deployment'], modules['mta_go_executor']
    if tuple(row['module'] for row in rows) != sources.MODULES: raise ValueError('HOST module graph changed')
    stack.enter_context(mock.patch.object(executor.os, 'getpid', io.getpid))
    stack.enter_context(mock.patch.object(threading, 'active_count', lambda: 1))
    loader = sources.GoDeploymentLoader(model.TOKEN, manifest_sha, model.UNTIL, repr(model.UNTIL),
        _io=io, _clock=io.clock)
    deployment = loader.load()
    modules = deployment.modules
    io.modules = modules
    argv = (model.PYTHON, '-B', deployment.manifest.executor, '--go-bootstrap', '--run-token',
        model.TOKEN, '--manifest-sha256', manifest_sha, '--until', repr(model.UNTIL))
    io.install_actor(100, 100, model.PYTHON, b''.join(v.encode('ascii') + b'\0' for v in argv))
    native_creator = modules['mta_go_bootstrap'].GoBootstrap
    original_init = native_creator.__init__
    created = []
    def modeled_init(value, deployed, entry, clock=None):
        # Only existing trusted HOST injection points are supplied. The actual
        # class, original ctor, bound parent and all creator tickets remain.
        original_init(value, deployed, entry, clock=clock, _store_io=io, _native_io=io,
            _launcher_os=io, _launcher_flags=io.flags)
        created.append(value)
        io.attach(modules, value.launcher)
    stack.enter_context(mock.patch.object(native_creator, '__init__', modeled_init))
    return io, modules, deployment, loader, executor, created


def failure_code(value):
    if value is None: return 'none'
    code = getattr(value, 'code', None)
    return code if type(code) is str and code.replace('_', '').isalnum() else type(value).__name__


class GoBootstrapNativeV34Tests(unittest.TestCase):
    def test_actual_go17_loader_entry_store_native_bootstrap_originals_faults_and_single_restore(self):
        rows, source, stock, model = source_inputs()
        cases = ('positive', 'missing_ack', 'first_child_stop', 'unlink_precheck',
            'unlink_unknown', 'foreign_endpoint', 'publication_unknown',
            'publication_unknown_ticket_unknown', 'publication_unknown_no_preexec',
            'publication_unknown_changed_start', 'publication_unknown_changed_exe')
        completed = []
        for case in cases:
            with self.subTest(case=case), ExitStack() as stack:
                tripwires(stack)
                io, modules, deployment, loader, executor, created = load_model(rows, source, stock, model,
                    None if case == 'positive' else case, stack)
                result = executor.bootstrap(deployment, model.UNTIL, repr(model.UNTIL),
                    _clock=io.clock, _proc_fs=io)
                self.assertEqual(1, len(created))
                runtime = created[0]
                store, native, launcher, entry = runtime.store, runtime.native, runtime.launcher, runtime.entry
                context = 'HOST first=' + failure_code(runtime.failure) + ' restore=' + failure_code(runtime.restore_failure)
                self.assertIs(type(runtime), modules['mta_go_bootstrap'].GoBootstrap)
                self.assertIs(type(store), modules['mta_go_bootstrap_store'].GoBootstrapStore)
                self.assertIs(type(native), modules['mta_go_native'].NativeGoResources)
                self.assertIs(type(launcher), modules['mta_go_process_owner'].GoDirectChildOwner)
                self.assertIs(loader.runtime, runtime)
                self.assertIs(loader._runtime_store, store)
                self.assertIs(loader.launcher, launcher)
                self.assertIs(deployment, loader.value)
                self.assertEqual(tuple(n for n, value in loader.original_modules), tuple(row['module'] for row in rows))
                self.assertEqual(21, len(loader.owner.rows))
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in loader.owner.rows))
                self.assertEqual(model.UNTIL, runtime.until)
                self.assertEqual(model.UNTIL, store.until)
                self.assertEqual(model.UNTIL, native.until)
                self.assertEqual(model.UNTIL, entry.until)
                self.assertEqual(repr(model.UNTIL), loader.original_until_text)
                self.assertEqual(model.UNTIL, sources_until(deployment))
                self.assertTrue(runtime.restore_attempted)
                uncertain = case.startswith('publication_unknown')
                self.assertEqual(not uncertain, store.restore_attempted)
                self.assertEqual(None if uncertain else runtime.cleanup_until, store.restore_until)
                self.assertLessEqual(runtime.cleanup_until - store.current.record.issued_at, 61.0)
                self.assertIs(entry.accounting_ticket['returned'], entry.accounting)
                self.assertIs(entry.accounting._resource_budget_v23, entry.budget)
                self.assertIs(entry.reader, entry.accounting._proc_reader)
                self.assertTrue(entry.reader.history_closed())
                self.assertFalse(entry.accounting._attempted)
                self.assertFalse(entry.accounting._opened)
                self.assertEqual(len(io.closed), len(set(io.closed)))
                self.assertEqual(1, io.create_count)
                self.assertEqual(8, io.iftypes[0])
                self.assertIsNotNone(native.interface_ticket)
                self.assertEqual(1, sum(r is native.interface_ticket for r in (native.interface_ticket,)))
                self.assertEqual(model.BOOT, native.interface_ticket.boot)
                self.assertEqual(100, native.channel.beacon_interval)
                self.assertEqual(100, native.channel.go_beacon_interval)
                self.assertEqual(2412, native.channel.frequency)
                self.assertIsNotNone(native._create_echo_original)
                echo = native._create_echo_original
                self.assertIs(echo[1], native.interface_ticket)
                self.assertEqual(8, echo[2].iftype)
                self.assertIs(store._native_original, native)
                self.assertIs(store._launcher_original, launcher)
                self.assertLessEqual(store._fd_attempts, modules['mta_go_bootstrap_store']._STORE_OPEN_BOUND)
                self.assertEqual(store._temporary, sum(store._publication_counts.values()))
                self.assertFalse(runtime.status()['go_ready'])
                self.assertFalse(store.status()['device_tested'])
                self.assertFalse(native.status()['phone_tested'])
                # The actual encoded journal must contain only digest facts,
                # never the model's private WPA event credentials/SSID bytes.
                for canonical in store._canonical_history:
                    self.assertEqual(model.UNTIL, canonical.record.until)
                    self.assertIs(type(canonical), modules['mta_go_bootstrap_store'].GoCanonical)
                    self.assertEqual(canonical.record.key(), modules['mta_go_bootstrap_store'].decode(canonical.raw).key())
                    self.assertNotIn(b'HOST_PRIVATE_NOT_A_CREDENTIAL', canonical.raw)
                for ticket in launcher._tickets:
                    self.assertEqual(model.UNTIL, ticket.deadline)
                    self.assertIs(ticket.owner, launcher)
                    self.assertIs(ticket.spec, deployment.watchdog_spec if ticket.spec.role == 'watchdog' else deployment.controller_spec)
                    if case == 'publication_unknown_no_preexec' and ticket is runtime.controller:
                        self.assertIsNone(ticket.preexec)
                    else: self.assertIsNotNone(ticket.preexec)
                    self.assertIsNotNone(ticket.postexec)
                    self.assertIsNotNone(ticket.persist_receipt)
                    self.assertIs(ticket.persist_receipt.ticket, ticket)
                    if case != 'publication_unknown_no_preexec' or ticket is not runtime.controller:
                        self.assertIs(ticket.persist_receipt.actor, ticket.preexec)
                if case in ('positive', 'unlink_precheck'):
                    self.assertEqual(0, result, context)
                    self.assertIsNone(runtime.failure)
                    self.assertIsNone(runtime.restore_failure)
                    self.assertTrue(runtime.group_confirmed)
                    self.assertEqual('restored', runtime.phase)
                    self.assertEqual('reconciled', store.current.record.phase)
                    self.assertTrue(store.marker_cleared)
                    self.assertTrue(store.logical_restored)
                    self.assertEqual(1, io.delete_count)
                    self.assertIsNone(io.netdev)
                    self.assertIn(9, io.iftypes)
                    self.assertEqual(2, len(launcher._tickets))
                    self.assertEqual([300, 200], io.stopped)
                    self.assertEqual([300, 200], io.reaped)
                    self.assertTrue(all(ticket.waited and ticket.exit_verified for ticket in launcher._tickets))
                    self.assertTrue(all(a and b for a, b in store.closed_facts()))
                    self.assertTrue(all(a and b for a, b in native.closed_facts()))
                    self.assertTrue(all(r.closed and not r.unknown for t in launcher._tickets for r in t.fds))
                    self.assertNotIn('/var/volatile/tmp/p011-mta-p2p-device.pending', io.nodes)
                    self.assertEqual(native.baseline.snapshot.key(), native.restored.snapshot.key())
                    self.assertGreaterEqual(io.absent_reads, 1)
                    self.assertGreaterEqual(io.clock.value, 1.025)
                    self.assertEqual({'prepare': 4, 'positive': 7, 'cleanup': 2}, store._publication_counts)
                    self.assertEqual(13, len(store._canonical_history))
                    self.assertEqual(list(modules['mta_go_bootstrap_store']._ACTIVE_PHASES) + ['restore_intent', 'reconciled'],
                        [c.record.phase for c in store._canonical_history])
                    self.assertFalse(io.live)
                    if case == 'unlink_precheck':
                        self.assertEqual(1, io.endpoint_early_failures)
                        self.assertTrue(io.fault_used)
                        self.assertEqual(len(io.unlink_calls), len(set(io.unlink_calls)))
                        self.assertTrue(any(r.endpoint_failure is not None and r.endpoint_closed for r in native.rows))
                    if case == 'positive':
                        # Passive path refusal happens BEFORE native _record;
                        # it must not fabricate a returned/unknown file ticket.
                        io.add('/HOST-unowned', stat.S_IFDIR | 0o777)
                        rows_before, opens_before = len(native.rows), sum(e[0] == 'open' for e in io.calls)
                        native._begin(runtime.cleanup_until, True)
                        with self.assertRaises(BaseException): native._file('/HOST-unowned/input')
                        self.assertEqual(rows_before, len(native.rows))
                        self.assertEqual(opens_before, sum(e[0] == 'open' for e in io.calls))
                        self._cleanup_denials(runtime, io, modules)
                else:
                    self.assertEqual(1, result)
                    self.assertFalse(store.marker_cleared)
                    self.assertFalse(store.logical_restored)
                    self.assertEqual('restore_pending', runtime.phase)
                    self.assertIsNotNone(runtime.restore_failure)
                    self.assertIn('/var/volatile/tmp/p011-mta-p2p-device.pending', io.nodes)
                    self.assertEqual(0, io.delete_count)
                    if case == 'missing_ack':
                        self.assertIsNone(native.owned)
                        self.assertIsNone(native.create_request)
                        self.assertFalse(native.status()['interface_echo_ack'])
                        self.assertEqual(8, io.netdev)
                        self.assertEqual([200], io.stopped)
                        self.assertIsNotNone(runtime.failure)
                    elif case == 'first_child_stop':
                        self.assertEqual([200], io.stopped)
                        self.assertEqual([200], io.reaped)
                        self.assertTrue(runtime.watchdog.waited)
                        self.assertFalse(runtime.controller.waited)
                        self.assertTrue(all(r.closed and not r.unknown for r in runtime.watchdog.fds))
                        self.assertTrue(native._termination[runtime.controller]['unknown'])
                        self.assertTrue(any(step[0] == 'child_stop' for step in runtime.cleanup_steps))
                    elif case == 'unlink_unknown':
                        self.assertTrue(io.fault_used)
                        pending = [r for r in native.rows if r.unlink_called and not r.endpoint_closed]
                        self.assertEqual(1, len(pending))
                        self.assertTrue(pending[0].closed)
                        self.assertEqual(1, io.unlink_calls.count(pending[0].path))
                        self.assertTrue(pending[0].endpoint_failure is not None)
                        self.assertFalse(all(a and b for a, b in native.closed_facts()))
                    elif case == 'foreign_endpoint':
                        self.assertIsNone(native._server_original)
                        self.assertIsNone(native.command_row)
                        self.assertIsNone(native.event_row)
                        self.assertNotIn(io.run + '/ctrl/mta66666666', io.unlink_calls)
                        self.assertEqual([300, 200], io.stopped)
                    elif uncertain:
                        self.assertTrue(io.fault_used)
                        self.assertTrue(store.publication_unknown)
                        self.assertEqual([200, 300] if case == 'publication_unknown' else [200], io.stopped)
                        self.assertEqual([200, 300] if case == 'publication_unknown' else [200], io.reaped)
                        self.assertTrue(runtime.watchdog.waited and runtime.watchdog.exit_verified)
                        self.assertEqual(case == 'publication_unknown', runtime.controller.waited)
                        if case == 'publication_unknown_ticket_unknown': self.assertTrue(runtime.controller.unknown)
                        if case == 'publication_unknown_no_preexec': self.assertIsNone(runtime.controller.preexec)
                        if case != 'publication_unknown':
                            self.assertTrue(any(ticket is runtime.controller for ticket, failure in native._stop_only_failures))
                        self.assertFalse(native._group_submit_called)
                        # Reusing an original completed stop-only call must not
                        # produce a second TERM or borrow a new cleanup period.
                        term_before = sum(event[0] == 'kill_term' for event in io.calls)
                        with self.assertRaises(BaseException): native.stop_child_only(runtime.watchdog)
                        self.assertEqual(term_before, sum(event[0] == 'kill_term' for event in io.calls))
                completed.append(case)
        self.assertEqual(list(cases), completed)
        print('GO17_FULL_HOST_MODEL_OK')

    def _cleanup_denials(self, runtime, io, modules):
        """Deny-only mutations after positive closure; no grant, no field repair.

        Temporary parent-reference denial inputs are restored by mock context,
        not native unknown flags/counters. No syscall or producer is permitted.
        A budget's native sticky cancellation remains true throughout.
        """
        native, entry = runtime.native, runtime.entry
        original = runtime._cleanup_original
        before = len(io.calls)
        deny = (
            (runtime, '_cleanup_original', tuple(list(original))),
            (runtime, 'cleanup_until', runtime.cleanup_until + 1),
            (entry, 'cleanup_until', entry.cleanup_until + 1),
            (entry, 'budget', object()), (entry, 'reader', object()),
            (entry.accounting, '_epoch', object()),
            (entry.accounting, '_mutex', threading.RLock()),
            (entry.accounting, '_resource_lane_v23', modules['mta_client_resource_budget'].PREPARATION_NETWORK),
            (entry.budget, '_cancelled', False))
        for obj, field, invalid in deny:
            with self.subTest(cleanup_denial=field), mock.patch.object(obj, field, invalid):
                with self.assertRaises(BaseException): runtime._cleanup_period_current(native)
        with self.assertRaises(BaseException): runtime._cleanup_period_current(object())
        with self.assertRaises(BaseException): native.stop_child_only(object())
        self.assertEqual(before, len(io.calls))
        self.assertIs(runtime._cleanup_original, runtime._cleanup_registered)
        self.assertTrue(entry.budget._cancelled)
        row = native.command_row
        before = len(io.calls)
        with mock.patch.object(row, 'cleanup_until', row.cleanup_until + 1):
            with self.assertRaises(BaseException): native._unlink_endpoint(row, row._cleanup_until_original)
        with self.assertRaises(BaseException): native._unlink_endpoint(row, row._cleanup_until_original + 1)
        with self.assertRaises(BaseException): native._unlink_endpoint(row, runtime.cleanup_until + 1)
        self.assertEqual(before, len(io.calls))
        # An expired native operation rejects before any signal or unlink. This
        # advances model time only; the original end/tuple is NOT extended.
        io.clock.value = runtime.cleanup_until
        before = len(io.calls)
        with self.assertRaises(BaseException): native.stop_child_only(runtime.controller)
        with self.assertRaises(BaseException): native._unlink_endpoint(row, runtime.cleanup_until)
        self.assertEqual(before, len(io.calls))
        self.assertEqual(original[1], runtime.cleanup_until)


def sources_until(deployment):
    # Actual canonical parser consumes the original issued full-precision text.
    return deployment.modules['mta_go_deployment'].canonical_until(deployment.loader.original_until_text)


if __name__ == '__main__': unittest.main()
