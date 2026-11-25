"""HOST71: new lifecycle split only; SOURCE authored, not self-executed.

The complete fixed Bootstrap71 module is compiled in the future HOST child.
Its ctor, _owner, _stage, _cancelled, prepare_live and run are real definitions.
Imported Deployment/Entry/Store/Native/Launcher classes are INERT MODELS;
_start_child and restore are explicitly modeled bound-method seams. They do
not mint a GoCanonical, a child receipt, a native observation or RF authority.
No old TestCase or old test method, device path or native graph is executed.

Clock=1 and until=301 describe this lifecycle model, not a P011 session.
No real fork, FS, socket, Loader authentication, Store publication, Native GO,
restoration, phone or production admission is proved by a passing method.
"""
import builtins
import hashlib
import io
import math
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import types
import unittest
from contextlib import ExitStack
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('candidate/go-live-owner-v71/runtime/mta_go_bootstrap.py',
          'e15a99747fc6b3fd47a0c714fdec45dd815ad377737183078fbc9809d041a442',
          18394)
MARKER = ('HOST71_GO_LIVE new_methods=1 old_methods=0 '
          'lifecycle_model=true device=false phone=false\n')


def _source_bytes():
    raw = (ROOT / SOURCE[0]).read_bytes()
    if len(raw) != SOURCE[2] or hashlib.sha256(raw).hexdigest() != SOURCE[1]:
        raise AssertionError('HOST71 fixed Bootstrap source changed')
    return raw


class _Clock(object):
    def __init__(self):
        self.value = 1.0
    def __call__(self):
        return self.value


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST71 platform/RF IO forbidden')


def _tripwires(stack):
    """Counters prove none was called, even if production catches an error."""
    targets = [(builtins, 'open'), (io, 'open'), (socket, 'socket'),
               (subprocess, 'Popen'), (select, 'select'),
               (threading.Thread, 'start')]
    for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'mkdir',
                 'unlink', 'rename', 'fork', 'execve', 'kill'):
        if hasattr(os, name):
            targets.append((os, name))
    return [stack.enter_context(mock.patch.object(owner, name,
            side_effect=_forbidden)) for owner, name in targets]


def _model(raw, fault=None, restore_fault=False):
    """Construct real Bootstrap definitions with no native success producer.

    The inert imports deliberately satisfy the ctor's class/reference shape.
    They are NOT the fixed GO17 Loader/Entry/Store/Native implementations.
    Sentinels and _ModelCanonical are test data, never production receipts.
    """
    events, stages = [], []
    clock = _Clock()
    sources = types.ModuleType('mta_go_deployment')
    stores = types.ModuleType('mta_go_bootstrap_store')
    native = types.ModuleType('mta_go_native')
    launch = types.ModuleType('mta_go_process_owner')
    executor = types.ModuleType('HOST71_inert_executor')

    class GoSourceError(Exception):
        def __init__(self, code):
            self.code = code
            Exception.__init__(self, code)
    class LoadedGoDeployment(object):
        pass
    class _ModelCanonical(object):
        def __init__(self, phase):
            self.phase = phase
    class GoEntrySource(object):
        def _context(self):
            if self.worker is not threading.current_thread():
                raise GoSourceError('model_entry_worker_changed')
            return self.accounting
    class _Loader(object):
        def __init__(self):
            self.runtime = None
            self.auth_calls = 0
        def authenticate(self, value):
            self.auth_calls += 1
            if value is not deployment:
                raise GoSourceError('model_deployment_changed')
        def bind_runtime(self, value, owner, until, until_text):
            if value is not deployment or until != 301.0 or until_text != '301.0':
                raise GoSourceError('model_runtime_changed')
            self.runtime = owner

    originals = {name: object() for name in
                 ('baseline', 'channel', 'interface_ticket', 'owned',
                  'group_source', 'group_observation')}
    primary = GoSourceError('model_' + (fault or 'no_failure'))
    secondary = GoSourceError('model_restore_unknown')

    class GoBootstrapStore(object):
        def __init__(self, value, until, _io=None, _clock=None):
            self.deployment, self.until = value, until
            self.current = None
            self.history = []
            self.publication_unknown = False
            self.logical_restored = False
            self.owner = self._native_original = self._launcher_original = None
        def bind(self, owner):
            self.owner = owner
        def bind_native(self, value):
            self._native_original = value
        def bind_launcher(self, value):
            self._launcher_original = value
        def _save_model(self, phase):
            value = _ModelCanonical(phase)
            self.history.append(value)
            self.current = value
            return value
        def reserve(self, value):
            if value is not originals['baseline']:
                raise GoSourceError('model_foreign_baseline')
            events.append(('reserve', value))
            return self._save_model('reserved')
        def prepare_interface(self, ticket, channel):
            if ticket is not originals['interface_ticket'] or channel is not originals['channel']:
                raise GoSourceError('model_foreign_interface')
            events.append(('prepare_interface', ticket, channel))
            return self._save_model('interface_intent')
        def confirm_interface(self, value):
            if value is not originals['owned']:
                raise GoSourceError('model_foreign_owned')
            events.append(('confirm_interface', value))
            return self._save_model('interface_owned')
        def prepare_group_add(self, value):
            if value is not originals['group_source']:
                raise GoSourceError('model_foreign_group_source')
            events.append(('prepare_group_add', value))
            return self._save_model('group_add_intent')
        def confirm_group(self, value):
            if value is not originals['group_observation']:
                raise GoSourceError('model_foreign_group_observation')
            events.append(('confirm_group', value))
            self.received_group = value
            if fault == 'publication_unknown':
                self.publication_unknown = True
                raise primary
            return self._save_model('group_started')

    class NativeGoResources(object):
        def __init__(self, owner, _io=None):
            self.owner = owner
            self.rows = []
            self.baseline = None
            self.group_until = None
        def observe_baseline(self, end):
            events.append(('observe_baseline', end))
            self.baseline = originals['baseline']
            return self.baseline
        def validate_config(self, end):
            events.append(('validate_config', end))
            if fault == 'config_failure':
                raise primary
        def observe_channel(self, end):
            events.append(('observe_channel', end))
            return originals['channel']
        def reserve_interface(self, end):
            events.append(('reserve_interface', end))
            return originals['interface_ticket']
        def create_interface(self, end):
            events.append(('create_interface', end))
            self.rows.append({'original': originals['owned'],
                              'unknown': fault == 'create_unknown'})
            if fault == 'create_unknown':
                raise primary
            return originals['owned']
        def open_control(self, end):
            events.append(('open_control', end))
            self.group_until = end
        def observe_group_source(self, end):
            events.append(('observe_group_source', end))
            return originals['group_source']
        def submit_group_add(self, end):
            events.append(('submit_group_add', end))
        def wait_group(self, end):
            events.append(('wait_group', end))
            if fault == 'final_expiry':
                # Actual _cancelled must reject the SAME issued group_until.
                clock.value = end
            return originals['group_observation']

    class GoDirectChildOwner(object):
        def __init__(self, value, _os=None, _flags=None):
            self.runtime = value.loader.runtime
            self._tickets = []
        def read_requests_passive_v30(self, ticket, end):
            return _forbidden()

    def model_time(value):
        if type(value) not in (int, float) or not math.isfinite(value):
            raise GoSourceError('model_invalid_clock')
        return float(value)

    sources.GoSourceError = GoSourceError
    sources.LoadedGoDeployment = LoadedGoDeployment
    sources._time = model_time
    stores.GoBootstrapStore = GoBootstrapStore
    # These types only make unused complete definitions resolvable. No receipt
    # of either type is constructed or claimed by this lifecycle model.
    stores.GoCanonical = type('UnusedGoCanonical', (), {})
    stores.GoChildIntent = type('UnusedGoChildIntent', (), {})
    native.NativeGoResources = NativeGoResources
    native.GoNativeRestoreObservation = type('UnusedGoNativeRestoreObservation', (), {})
    launch.GoDirectChildOwner = GoDirectChildOwner
    launch.PersistReceipt = type('UnusedPersistReceipt', (), {})
    executor.GoEntrySource = GoEntrySource
    deployment = LoadedGoDeployment()
    deployment.loader = _Loader()
    deployment.modules = {'mta_go_executor': executor}
    entry = GoEntrySource()
    entry.deployment, entry.actor = deployment, object()
    entry.mode, entry.worker = '--go-bootstrap', threading.current_thread()
    entry.clock, entry.until, entry.until_text = clock, 301.0, '301.0'
    # The prepare/observe-self ctor seam of older HOST fixtures ended at 4,
    # not 11. This fixture's accounting is inert and makes no Proc claim.
    entry.accounting = types.SimpleNamespace(_io_deadline=4.0)
    module = types.ModuleType('HOST71_complete_bootstrap_definition')
    imported = {x.__name__: x for x in (sources, stores, native, launch)}
    with mock.patch.dict(sys.modules, imported):
        exec(compile(raw, 'HOST71_fixed_bootstrap.py', 'exec'), module.__dict__)
        runtime = module.GoBootstrap(deployment, entry)
    restore_calls = []

    def model_start_child(owner, role):
        # Deliberately NOT the native _start_child algorithm or a real actor.
        owner._owner()
        end = owner._stage(10)
        ticket = types.SimpleNamespace(role=role, released=False, waited=False)
        owner.launcher._tickets.append(ticket)
        if role == 'watchdog':
            owner.watchdog = ticket
        else:
            owner.controller = ticket
        events.append(('start_child_model', role, end, ticket))
        owner.phase = role + '_live'
        return ticket

    def model_restore(owner):
        # Deliberately NOT original restore or proof of physical closure.
        owner._owner()
        if owner.restore_attempted:
            raise GoSourceError('model_restore_repeated')
        owner.restore_attempted = True
        owner.stop_requested = True
        owner.cleanup_until = clock.value + 60.0
        restore_calls.append(owner)
        events.append(('restore_model', owner))
        if restore_fault:
            owner.restore_failure = secondary
            owner.phase = 'restore_pending'
            raise secondary
        owner.store.logical_restored = True  # INERT model return predicate only.
        owner.phase = 'restored'
        return owner.store.current

    original_stage = runtime._stage
    def stage_forward(owner, seconds):
        result = original_stage(seconds)  # Actual fixed _stage, no fake cap.
        stages.append((seconds, result))
        return result

    runtime._stage = types.MethodType(stage_forward, runtime)
    runtime._start_child = types.MethodType(model_start_child, runtime)
    runtime.restore = types.MethodType(model_restore, runtime)
    return types.SimpleNamespace(module=module, runtime=runtime, entry=entry,
        originals=originals, events=events, stages=stages, clock=clock,
        primary=primary, secondary=secondary, restore_calls=restore_calls,
        error=GoSourceError, initial_accounting_deadline=4.0)


class GoLiveOwner71Test(unittest.TestCase):
    def test_prepare_live_and_default_restore(self):
        raw = _source_bytes()  # Fixed file IO precedes all platform tripwires.
        completed = []
        cases = ('prepare_success', 'duplicate', 'wrong_worker', 'final_expiry',
                 'create_unknown', 'publication_unknown', 'default_success',
                 'default_primary', 'default_secondary', 'default_both')
        with ExitStack() as stack:
            probes = _tripwires(stack)
            for case in cases:
                with self.subTest(case=case):
                    fault = {'final_expiry': 'final_expiry',
                        'create_unknown': 'create_unknown',
                        'publication_unknown': 'publication_unknown',
                        'default_primary': 'config_failure',
                        'default_both': 'config_failure'}.get(case)
                    f = _model(raw, fault, case in ('default_secondary', 'default_both'))
                    r = f.runtime
                    retained = r._originals
                    self.assertEqual(4.0, f.entry.accounting._io_deadline)
                    self.assertIs(r.entry, f.entry)
                    self.assertIs(r.deployment.loader.runtime, r)
                    self.assertIs(r.store.owner, r)
                    self.assertIs(r.native.owner, r)
                    self.assertIs(r.launcher.runtime, r)
                    self.assertFalse(r.started)
                    self.assertIsNone(r.failure)
                    self.assertIsNone(r.restore_failure)
                    if case == 'wrong_worker':
                        r.worker = object()
                        with self.assertRaises(f.error) as caught:
                            r.prepare_live()
                        self.assertEqual('bootstrap_owner_changed', caught.exception.code)
                        self.assertFalse(r.started)
                        self.assertFalse(r.stop_requested)
                        self.assertIsNone(r.failure)
                        self.assertEqual([], f.events)
                        self.assertEqual([], f.stages)
                        self.assertEqual([], f.restore_calls)
                        self.assertEqual(4.0, f.entry.accounting._io_deadline)
                    elif case.startswith('default_'):
                        result = r.run()  # Actual default orchestration.
                        self.assertEqual(0 if case == 'default_success' else 1, result)
                        self.assertEqual([r], f.restore_calls)
                        self.assertTrue(r.restore_attempted)
                        self.assertIs(f.events[-1][1], r)
                        self.assertEqual('restore_model', f.events[-1][0])
                        if case in ('default_primary', 'default_both'):
                            self.assertIs(r.failure, f.primary)
                            self.assertFalse(r.group_confirmed)
                            self.assertEqual(['observe_baseline', 'reserve',
                                'start_child_model', 'validate_config', 'restore_model'],
                                [x[0] for x in f.events])
                        else:
                            self.assertIsNone(r.failure)
                            self.assertTrue(r.group_confirmed)
                        if case in ('default_secondary', 'default_both'):
                            self.assertIs(r.restore_failure, f.secondary)
                            self.assertFalse(r.store.logical_restored)
                            self.assertEqual('restore_pending', r.phase)
                        else:
                            self.assertIsNone(r.restore_failure)
                            self.assertTrue(r.store.logical_restored)
                        # A repeated default run rejects before another restore.
                        before = tuple(f.events)
                        first_failure, first_restore = r.failure, r.restore_failure
                        with self.assertRaises(f.error) as caught:
                            r.run()
                        self.assertEqual('already_started', caught.exception.code)
                        self.assertEqual(before, tuple(f.events))
                        self.assertEqual([r], f.restore_calls)
                        self.assertIs(r.failure, first_failure)
                        self.assertIs(r.restore_failure, first_restore)
                    elif case in ('final_expiry', 'create_unknown', 'publication_unknown'):
                        with self.assertRaises(f.error) as caught:
                            r.prepare_live()
                        self.assertIs(r.failure, caught.exception)
                        self.assertTrue(r.started)
                        self.assertTrue(r.stop_requested)
                        self.assertFalse(r.restore_attempted)
                        self.assertEqual([], f.restore_calls)
                        self.assertFalse(r.store.logical_restored)
                        if case == 'final_expiry':
                            self.assertEqual('stop_requested', caught.exception.code)
                            self.assertTrue(r.group_confirmed)
                            self.assertEqual(21.0, r.native.group_until)
                            self.assertEqual(r.native.group_until, f.clock.value)
                            self.assertEqual('group_started', r.phase)
                            self.assertEqual('group_started', r.store.current.phase)
                            self.assertEqual('confirm_group', f.events[-1][0])
                        elif case == 'create_unknown':
                            self.assertIs(caught.exception, f.primary)
                            self.assertFalse(r.group_confirmed)
                            self.assertEqual('interface_intent', r.store.current.phase)
                            self.assertEqual(1, len(r.native.rows))
                            self.assertIs(r.native.rows[0]['original'], f.originals['owned'])
                            self.assertTrue(r.native.rows[0]['unknown'])
                            self.assertIsNone(r.controller)
                            self.assertEqual('create_interface', f.events[-1][0])
                        else:
                            self.assertIs(caught.exception, f.primary)
                            self.assertFalse(r.group_confirmed)
                            self.assertTrue(r.store.publication_unknown)
                            self.assertIs(r.store.received_group, f.originals['group_observation'])
                            self.assertIs(r.store.current, r.store.history[-1])
                            self.assertEqual('group_add_intent', r.store.current.phase)
                            self.assertEqual('confirm_group', f.events[-1][0])
                        # The repeated-call guard is outside prepare's catch:
                        # it must not replace a real retained primary failure.
                        first_failure = r.failure
                        before, issued = tuple(f.events), tuple(f.stages)
                        deadline = f.entry.accounting._io_deadline
                        with self.assertRaises(f.error) as duplicate:
                            r.prepare_live()
                        self.assertEqual('already_started', duplicate.exception.code)
                        self.assertIs(r.failure, first_failure)
                        self.assertTrue(r.stop_requested)
                        self.assertEqual(before, tuple(f.events))
                        self.assertEqual(issued, tuple(f.stages))
                        self.assertEqual(deadline, f.entry.accounting._io_deadline)
                        self.assertEqual([], f.restore_calls)
                    else:
                        self.assertIs(r.prepare_live(), r)
                        self.assertTrue(r.started)
                        self.assertTrue(r.group_confirmed)
                        self.assertFalse(r.stop_requested)
                        self.assertFalse(r.restore_attempted)
                        self.assertFalse(r.store.logical_restored)
                        self.assertEqual([], f.restore_calls)
                        self.assertIsNone(r.failure)
                        self.assertIsNone(r.restore_failure)
                        self.assertEqual('group_started', r.phase)
                        self.assertEqual(['observe_baseline', 'reserve',
                            'start_child_model', 'validate_config', 'observe_channel',
                            'reserve_interface', 'prepare_interface', 'create_interface',
                            'confirm_interface', 'start_child_model', 'open_control',
                            'observe_group_source', 'prepare_group_add', 'submit_group_add',
                            'wait_group', 'confirm_group'], [x[0] for x in f.events])
                        self.assertEqual([(15, 16.0), (10, 11.0), (5, 6.0),
                            (10, 11.0), (20, 21.0), (10, 11.0), (20, 21.0)], f.stages)
                        self.assertEqual(21.0, r.native.group_until)
                        group_events = [x for x in f.events if x[0] in
                            ('open_control', 'observe_group_source', 'submit_group_add', 'wait_group')]
                        self.assertTrue(all(x[1] == r.native.group_until for x in group_events))
                        self.assertIs(r.native.baseline, f.originals['baseline'])
                        self.assertIs(r.store.received_group, f.originals['group_observation'])
                        if case == 'duplicate':
                            before, issued = tuple(f.events), tuple(f.stages)
                            current, first_failure = r.store.current, r.failure
                            with self.assertRaises(f.error) as caught:
                                r.prepare_live()
                            self.assertEqual('already_started', caught.exception.code)
                            self.assertEqual(before, tuple(f.events))
                            self.assertEqual(issued, tuple(f.stages))
                            self.assertIs(r.store.current, current)
                            self.assertIs(r.failure, first_failure)
                            self.assertFalse(r.stop_requested)
                            self.assertEqual([], f.restore_calls)
                    self.assertIs(r._originals, retained)
                    self.assertEqual(301.0, r.until)
                    self.assertEqual(301.0, r.entry.until)
                    self.assertEqual('301.0', r.entry.until_text)
                    self.assertIs(r.entry.clock, f.clock)
                    self.assertIs(r.store, retained[5])
                    self.assertIs(r.native, retained[6])
                    self.assertIs(r.launcher, retained[7])
                    self.assertTrue(all(probe.call_count == 0 for probe in probes))
                    completed.append(case)
            self.assertEqual(list(cases), completed)
            self.assertEqual(10, len(completed))
            for probe in probes:
                self.assertEqual(0, probe.call_count)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
