"""HOST72: affected typed-L3 orchestration only; not self-executed.

The future isolated HOST child loads the COMPLETE pinned Bootstrap72 module.
Its constructor, owner/time/stage/cancel gates, prepare_live, poll_dhcp,
restore and run are actual definitions. Deployment/Entry/Loader/Store/Native/
Launcher/DHCP imports are explicitly INERT dependency models; _start_child is
the sole modeled Bootstrap bound method. No old TestCase/method is imported.

The dependency models expose original-reference shape and ordered events, NOT
real GO/IP observations, canonical publications, sockets, child receipts,
NetworkReceipt, readiness, restoration or a production admission producer.
Actual restore below means the Bootstrap's orchestration definition executes;
it does NOT mean native/kernel/physical recovery has been demonstrated.

Clock=1/until=301, modeled canonical phases, constructor tickets and all closed
facts are HOST data. Each affected case forbids platform IO, including calls
caught by production, and verifies zero tripwire calls. No GO20 source graph,
actual Loader authentication, Proc, publication, RF, phone or device is run.
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
SOURCE = ('candidate/go-typed-live-v72/runtime/mta_go_bootstrap.py',
          '1db6bcea1aab324ae7c21eb5d116d77728e73de01865c64a4a8fc778481b40e3',
          22707)
MARKER = ('HOST72_GO_TYPED_LIVE new_methods=1 old_methods=0 '
          'orchestration_model=true device=false phone=false\n')


def _source_bytes():
    raw = (ROOT / SOURCE[0]).read_bytes()
    if len(raw) != SOURCE[2] or hashlib.sha256(raw).hexdigest() != SOURCE[1]:
        raise AssertionError('HOST72 fixed Bootstrap source changed')
    return raw


class _Clock(object):
    def __init__(self):
        self.value = 1.0
    def __call__(self):
        return self.value


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST72 platform/RF IO forbidden')


def _tripwires(stack):
    """Count even forbidden calls caught by the actual Bootstrap definition."""
    targets = [(builtins, 'open'), (io, 'open'), (socket, 'socket'),
               (subprocess, 'Popen'), (select, 'select'),
               (threading.Thread, 'start')]
    for name in ('open', 'read', 'write', 'close', 'stat', 'lstat', 'mkdir',
                 'unlink', 'rename', 'fork', 'execve', 'kill'):
        if hasattr(os, name):
            targets.append((os, name))
    return [stack.enter_context(mock.patch.object(owner, name,
            side_effect=_forbidden)) for owner, name in targets]


def _model(raw, fault=None, finished_first=False):
    """Use real Bootstrap algorithms and inert, explicitly non-authority deps.

    Model methods check their own original sentinels and phase order. These
    assertions establish the orchestration test's shape, not Native validity.
    In particular _durable and closed_facts below are MODEL counters/data.
    """
    events, stages, constructor_tickets = [], [], []
    clock = _Clock()
    sources = types.ModuleType('mta_go_deployment')
    stores = types.ModuleType('mta_go_bootstrap_store')
    native = types.ModuleType('mta_go_native')
    launch = types.ModuleType('mta_go_process_owner')
    dhcp = types.ModuleType('mta_go_dhcp')
    executor = types.ModuleType('HOST72_inert_executor')
    resources = types.ModuleType('HOST72_inert_resource_budget')

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
    class ResourceBudget(object):
        def __init__(self):
            self._cancelled = False
        def cancel(self):
            events.append(('accounting_cancel_model', self))
            self._cancelled = True
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
                  'group_source', 'group_observation', 'ip_intent',
                  'ip_receipt', 'dhcp_intent', 'dhcp_listening',
                  'dhcp_closed', 'ip_delete_intent', 'ip_restored')}
    primary = GoSourceError('model_' + (fault or 'no_failure'))
    secondary = GoSourceError('model_l3_restore_unknown')

    class GoBootstrapStore(object):
        def __init__(self, value, until, _io=None, _clock=None):
            self.deployment, self.until = value, until
            self.current = None
            self.history = []
            self.publication_unknown = False
            self.logical_restored = False
            self.owner = self._native_original = self._launcher_original = None
            self.mutex = threading.RLock()
            self.durable_calls = 0
            self.restore_until = None
        def bind(self, owner):
            self.owner = owner
        def bind_native(self, value):
            self._native_original = value
        def bind_launcher(self, value):
            self._launcher_original = value
        def _durable(self, phase):
            # MODEL publication counter: no FS, Store CAS or grant is minted.
            self.durable_calls += 1
            value = _ModelCanonical(phase)
            self.history.append(value)
            self.current = value
            return value
        def _phase(self, expected):
            if self.current is None or self.current.phase != expected:
                raise GoSourceError('model_phase_changed')
        def _original(self, value, name):
            if value is not originals[name]:
                raise GoSourceError('model_foreign_' + name)
        def reserve(self, value):
            self._original(value, 'baseline')
            events.append(('reserve', value))
            return self._durable('reserved')
        def prepare_interface(self, ticket, channel):
            self._original(ticket, 'interface_ticket')
            self._original(channel, 'channel')
            events.append(('prepare_interface', ticket, channel))
            return self._durable('interface_intent')
        def confirm_interface(self, value):
            self._original(value, 'owned')
            events.append(('confirm_interface', value))
            return self._durable('interface_owned')
        def prepare_group_add(self, value):
            self._original(value, 'group_source')
            events.append(('prepare_group_add', value))
            return self._durable('group_add_intent')
        def confirm_group(self, value):
            self._original(value, 'group_observation')
            events.append(('confirm_group', value))
            return self._durable('group_started')
        def prepare_ip(self, value):
            self._phase('group_started')
            self._original(value, 'ip_intent')
            events.append(('store_prepare_ip', value))
            return self._durable('ip_intent')
        def persist_ip_receipt(self, value):
            self._phase('ip_intent')
            self._original(value, 'ip_receipt')
            events.append(('store_persist_ip_receipt', value))
            return self._durable('ip_receipt')
        def confirm_ip(self, value):
            self._phase('ip_receipt')
            self._original(value, 'ip_receipt')
            events.append(('store_confirm_ip', value))
            return self._durable('ip_confirmed')
        def prepare_dhcp(self, value):
            self._phase('ip_confirmed')
            self._original(value, 'dhcp_intent')
            events.append(('store_prepare_dhcp', value))
            result = self._durable('dhcp_intent')
            # Explicitly model the real publication's shorter local IO lane.
            # The ACTUAL Bootstrap must restore only its SAME once-issued end.
            self.owner.native._scope = min(self.owner.service_until, clock() + 10.0)
            self.owner.entry.accounting._io_deadline = self.owner.native._scope
            events.append(('model_publication_narrowed_scope', self.owner.native._scope))
            return result
        def confirm_dhcp(self, value):
            self._phase('dhcp_intent')
            self._original(value, 'dhcp_listening')
            events.append(('store_confirm_dhcp', value))
            return self._durable('dhcp_listening')
        def begin_restore(self, end):
            self.restore_until = end
            events.append(('store_begin_restore', end))
            return self._durable('restore_intent')
        def close_dhcp(self, value):
            self._phase('restore_intent')
            self._original(value, 'dhcp_closed')
            events.append(('store_close_dhcp', value))
            return self._durable('dhcp_closed')
        def prepare_ip_delete(self, value):
            self._phase('dhcp_closed')
            self._original(value, 'ip_delete_intent')
            events.append(('store_prepare_ip_delete', value))
            return self._durable('ip_delete_intent')
        def confirm_ip_restored(self, value):
            self._phase('ip_delete_intent')
            self._original(value, 'ip_restored')
            events.append(('store_confirm_ip_restored', value))
            return self._durable('ip_restored')
        def finish_restore(self, value):
            self._phase('ip_restored')
            if (type(value) is not module.GoRestoreObservation or
                    value.owner is not self.owner or
                    value.native_observation is not self.owner.native.restored):
                raise GoSourceError('model_foreign_restore_observation')
            events.append(('store_finish_restore', value))
            self.logical_restored = True  # MODEL only; never native recovery.
            return self._durable('reconciled')
        def closed_facts(self):
            return ((True, True),)  # Inert closed data, not a kernel proof.
        def close_pending(self):
            events.append(('store_close_pending_model', self.current))

    class GoNativeRestoreObservation(object):
        def __init__(self, owner):
            self.owner = owner

    class NativeGoResources(object):
        def __init__(self, owner, _io=None):
            self.owner = owner
            self.rows = []
            self.baseline = None
            self.group_until = self._scope = self.restored = None
            self.binding = self.service_scope = None
            self.begin_calls = []
            self.ip_receipt = None
        def observe_baseline(self, end):
            events.append(('observe_baseline', end))
            self.baseline = originals['baseline']
            return self.baseline
        def validate_config(self, end):
            events.append(('validate_config', end))
        def observe_channel(self, end):
            events.append(('observe_channel', end))
            return originals['channel']
        def reserve_interface(self, end):
            events.append(('reserve_interface', end))
            return originals['interface_ticket']
        def create_interface(self, end):
            events.append(('create_interface', end))
            self.rows.append(originals['owned'])
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
            return originals['group_observation']
        def prepare_ip(self, end):
            events.append(('native_prepare_ip', end))
            if fault == 'early_no_l3':
                raise primary
            return originals['ip_intent']
        def create_ip(self, end):
            self.owner.store._phase('ip_intent')
            events.append(('native_create_ip', end))
            self.ip_receipt = originals['ip_receipt']
            return self.ip_receipt
        def issue_dhcp_binding(self, end):
            self.owner.store._phase('ip_confirmed')
            if end is not self.owner._service_until_original:
                raise GoSourceError('model_service_end_not_original')
            self.binding = types.SimpleNamespace(owner=self.owner, native=self,
                store=self.owner.store, until=self.owner.until, service_until=end)
            events.append(('native_issue_dhcp_binding', end, self.binding))
            self._scope = end
            return self.binding
        def prepare_dhcp(self, binding, server, end):
            if (binding is not self.binding or server is not self.owner.dhcp or
                    end is not self.owner._service_until_original or
                    self.owner.dhcp_ticket.returned is not server or
                    self.owner.dhcp_ticket.unknown is not False):
                raise GoSourceError('model_dhcp_sources_changed')
            events.append(('native_prepare_dhcp', end, server))
            return originals['dhcp_intent']
        def _begin(self, end):
            if end is not self.owner._service_until_original:
                raise GoSourceError('model_scope_renewed')
            self.begin_calls.append(end)
            events.append(('native_begin_same_scope_model', end))
            if fault != 'scope_reset_failure':
                self._scope = end
                self.owner.entry.accounting._io_deadline = end
        def observe_dhcp(self, server, end):
            if server is not self.owner.dhcp or server.socket is None or self._scope != end:
                raise GoSourceError('model_dhcp_not_open')
            events.append(('native_observe_dhcp', end, server))
            return originals['dhcp_listening']
        def begin_dhcp_service(self, server, end):
            self.owner.store._phase('dhcp_listening')
            if server is not self.owner.dhcp or end is not self.owner._service_until_original:
                raise GoSourceError('model_service_sources_changed')
            self.service_scope = end
            self._scope = end
            events.append(('native_begin_dhcp_service', end))
        def _cleanup(self, end):
            if self.owner._cleanup_period_current(self) != end:
                raise GoSourceError('model_cleanup_end_changed')
        def close_dhcp(self, end):
            self._cleanup(end)
            self.owner.store._phase('restore_intent')
            events.append(('native_close_dhcp_model', end))
            if fault in ('restore_dhcp_failure', 'constructor_failure'):
                raise secondary
            return originals['dhcp_closed']
        def prepare_ip_cleanup(self, end):
            self._cleanup(end)
            self.owner.store._phase('dhcp_closed')
            events.append(('native_prepare_ip_cleanup', end))
            return originals['ip_delete_intent']
        def restore_ip(self, end):
            self._cleanup(end)
            self.owner.store._phase('ip_delete_intent')
            events.append(('native_restore_ip_model', end))
            if fault == 'restore_ip_failure':
                raise secondary
            return originals['ip_restored']
        def prepare_cleanup(self, end):
            self._cleanup(end)
            self.owner.store._phase('ip_restored')
            events.append(('native_prepare_group_cleanup_model', end))
        def stop_child(self, ticket, end):
            self._cleanup(end)
            self.owner.store._phase('ip_restored')
            if not any(value is ticket for value in self.owner.launcher._tickets):
                raise GoSourceError('model_foreign_child')
            events.append(('native_stop_child_model', ticket.role, end, ticket))
            ticket.waited = True
            ticket.exit_verified = True
        def stop_child_only(self, ticket):
            if not any(value is ticket for value in self.owner.launcher._tickets):
                raise GoSourceError('model_foreign_stop_only_child')
            self._cleanup(self.owner.cleanup_until)
            events.append(('native_stop_child_only_model', ticket.role, ticket))
            ticket.waited = True  # MODEL local stop result, never native absence.
        def close_known_inventory(self, end):
            self._cleanup(end)
            events.append(('native_close_inventory_model', end))
        def delete_interface(self, end):
            self._cleanup(end)
            self.owner.store._phase('ip_restored')
            events.append(('native_delete_interface_model', end))
        def observe_restore(self, end):
            self._cleanup(end)
            self.owner.store._phase('ip_restored')
            events.append(('native_observe_restore_model', end))
            self.restored = GoNativeRestoreObservation(self.owner)
            return self.restored
        def closed_facts(self):
            if fault == 'default_restore_failure':
                return ((True, False),)  # Unknown MODEL inventory cannot pass.
            return ((True, True),)  # Never a native/socket/FD closure producer.

    class GoDirectChildOwner(object):
        def __init__(self, value, _os=None, _flags=None):
            self.runtime = value.loader.runtime
            self._tickets = []
        def read_requests_passive_v30(self, ticket, end):
            return _forbidden()
        def close_inventory(self, ticket, _absolute_deadline=None):
            events.append(('launcher_close_inventory_model', ticket, _absolute_deadline))
            return True

    class GoDhcpServer(object):
        def __init__(self, binding):
            owner = binding.owner
            ticket = owner.dhcp_ticket
            if (ticket is not owner._dhcp_ticket_original or
                    type(ticket) is not module._DhcpConstructor or
                    ticket.owner is not owner or ticket.binding is not binding or
                    ticket.creator is not GoDhcpServer or ticket.returned is not None or
                    ticket.unknown is not True or owner.dhcp is not None):
                raise GoSourceError('model_constructor_inventory_missing')
            constructor_tickets.append(ticket)
            events.append(('dhcp_ctor_model', ticket, binding))
            if fault == 'constructor_failure':
                raise primary
            self.binding = binding
            self.socket = None
            self.serve_calls = 0
        def open(self):
            owner = self.binding.owner
            if (self.binding is not owner.native.binding or
                    owner.native._scope != owner._service_until_original):
                raise primary
            events.append(('dhcp_open_model', owner.native._scope, self))
            self.socket = object()  # Explicit inert socket sentinel, no IO.
        def serve_once(self):
            owner = self.binding.owner
            if (self.binding is not owner.native.binding or
                    owner.native._scope != owner._service_until_original or
                    owner.native.service_scope is not owner._service_until_original or
                    self.socket is None):
                raise GoSourceError('model_service_source_changed')
            self.serve_calls += 1
            events.append(('dhcp_serve_once_model', self.serve_calls, clock.value))
            if fault == 'poll_error':
                raise primary
            if clock.value >= owner._service_until_original or finished_first:
                return {'event': 'finished'}  # MODEL stop-only expiry/result.
            return {'event': 'idle'}

    def model_time(value):
        if type(value) not in (int, float) or not math.isfinite(value):
            raise GoSourceError('model_invalid_clock')
        return float(value)

    sources.GoSourceError = GoSourceError
    sources.LoadedGoDeployment = LoadedGoDeployment
    sources._time = model_time
    stores.GoBootstrapStore = GoBootstrapStore
    stores.GoCanonical = _ModelCanonical
    stores.GoChildIntent = type('UnusedGoChildIntent', (), {})
    native.NativeGoResources = NativeGoResources
    native.GoNativeRestoreObservation = GoNativeRestoreObservation
    launch.GoDirectChildOwner = GoDirectChildOwner
    launch.PersistReceipt = type('UnusedPersistReceipt', (), {})
    dhcp.GoDhcpServer = GoDhcpServer
    executor.GoEntrySource = GoEntrySource
    resources.ResourceBudget = ResourceBudget
    resources.CLEANUP = 'model_cleanup'
    deployment = LoadedGoDeployment()
    deployment.loader = _Loader()
    deployment.modules = {'mta_go_executor': executor,
        'mta_client_resource_budget': resources}
    entry = GoEntrySource()
    entry.deployment, entry.actor = deployment, object()  # NOT a real Actor.
    entry.mode, entry.worker = '--go-bootstrap', threading.current_thread()
    entry.clock, entry.until, entry.until_text = clock, 301.0, '301.0'
    entry.budget = ResourceBudget()
    entry.reader = types.SimpleNamespace(_bound_budget_v24=entry.budget,
        _resource_budget_v24=entry.budget)
    entry.accounting = types.SimpleNamespace(_io_deadline=4.0,
        _mutex=threading.RLock(), _epoch=object(),
        _resource_lane_v23='model_network', _resource_budget_v23=entry.budget)
    entry.cleanup_until = None
    module = types.ModuleType('HOST72_complete_bootstrap_definition')
    imported = {value.__name__: value for value in (sources, stores, native, launch, dhcp)}
    with mock.patch.dict(sys.modules, imported):
        exec(compile(raw, 'HOST72_fixed_bootstrap.py', 'exec'), module.__dict__)
        runtime = module.GoBootstrap(deployment, entry)

    def model_start_child(owner, role):
        # Only this Bootstrap method is modeled. No actual launch/receipt/FD.
        owner._owner()
        end = owner._stage(10)
        ticket = types.SimpleNamespace(role=role, released=False, waited=False,
            fork_negative=False, exit_verified=False)
        owner.launcher._tickets.append(ticket)
        if role == 'watchdog':
            owner.watchdog = ticket
        else:
            owner.controller = ticket
        events.append(('start_child_model', role, end, ticket))
        owner.phase = role + '_live'
        return ticket

    original_stage = runtime._stage
    def stage_forward(owner, seconds):
        result = original_stage(seconds)  # Real stage/cancel/owner algorithm.
        stages.append((seconds, result))
        return result

    runtime._stage = types.MethodType(stage_forward, runtime)
    runtime._start_child = types.MethodType(model_start_child, runtime)
    # IMPORTANT: do not replace restore/poll/prepare_live/run with model seams.
    return types.SimpleNamespace(module=module, runtime=runtime, entry=entry,
        originals=originals, events=events, stages=stages, clock=clock,
        primary=primary, secondary=secondary, constructor_tickets=constructor_tickets,
        error=GoSourceError, resources=resources)


def _event_names(fixture):
    return [value[0] for value in fixture.events]


class GoTypedLive72Test(unittest.TestCase):
    def test_typed_l3_same_owner_poll_and_restore(self):
        raw = _source_bytes()  # Only fixed source IO; before any tripwire.
        cases = ('prepare_poll_restore', 'constructor_failure',
            'scope_reset_failure', 'poll_scope_changed', 'poll_until_identity',
            'poll_ticket_changed', 'poll_binding_changed', 'poll_error',
            'expired_poll', 'restore_dhcp_failure', 'restore_ip_failure',
            'early_no_l3', 'default_success', 'default_restore_failure')
        completed = []
        with ExitStack() as stack:
            probes = _tripwires(stack)
            for case in cases:
                with self.subTest(case=case):
                    fault = case if case in ('constructor_failure',
                        'scope_reset_failure', 'poll_error', 'restore_dhcp_failure',
                        'restore_ip_failure', 'early_no_l3',
                        'default_restore_failure') else None
                    f = _model(raw, fault, finished_first=case.startswith('default_'))
                    r = f.runtime
                    original_owner = r._originals
                    self.assertIs(r.deployment.loader.runtime, r)
                    self.assertIs(r.store.owner, r)
                    self.assertIs(r.native.owner, r)
                    self.assertIs(r.launcher.runtime, r)
                    self.assertFalse(r.started)
                    self.assertIsNone(r.service_until)
                    self.assertIsNone(r.dhcp_ticket)
                    self.assertIsNone(r.restore_failure)
                    # Default is the actual default orchestration, not a call
                    # to the old71 restore seam or any old lifecycle method.
                    if case.startswith('default_'):
                        if case == 'default_restore_failure':
                            r.store.logical_restored = True  # Stale model fact.
                        code = r.run()
                        self.assertEqual(0 if case == 'default_success' else 1, code)
                        self.assertIsNone(r.failure)
                        self.assertTrue(r.restore_attempted)
                        self.assertTrue(r.group_confirmed)
                        self.assertTrue(r.ip_confirmed)
                        self.assertTrue(r.dhcp_listening)
                        self.assertEqual(1, r.dhcp.serve_calls)
                        self.assertTrue(r.store.logical_restored)
                        self.assertEqual(1, _event_names(f).count('store_begin_restore'))
                        self.assertEqual(1, _event_names(f).count('native_delete_interface_model'))
                        self.assertEqual(1, _event_names(f).count('store_finish_restore'))
                        if case == 'default_restore_failure':
                            self.assertIsNotNone(r.restore_failure)
                            self.assertEqual('restoration_pending', r.restore_failure.code)
                            self.assertEqual('restore_pending', r.phase)
                            self.assertEqual(((True, False),), r.native.closed_facts())
                            self.assertEqual(1, _event_names(f).count('store_close_pending_model'))
                        else:
                            self.assertIsNone(r.restore_failure)
                            self.assertEqual('restored', r.phase)
                        self._assert_restore_order(f, complete=True)
                    elif case in ('constructor_failure', 'scope_reset_failure', 'early_no_l3'):
                        with self.assertRaises(f.error) as caught:
                            r.prepare_live()
                        self.assertIs(caught.exception, f.primary)
                        self.assertIs(r.failure, f.primary)
                        self.assertTrue(r.stop_requested)
                        self.assertFalse(r.restore_attempted)
                        self.assertFalse(r.store.logical_restored)
                        self.assertTrue(r.group_confirmed)
                        if case == 'constructor_failure':
                            self.assertTrue(r.ip_confirmed)
                            self.assertIs(r.dhcp_ticket, f.constructor_tickets[0])
                            self.assertIs(r.dhcp_ticket, r._dhcp_ticket_original)
                            self.assertIsNone(r.dhcp_ticket.returned)
                            self.assertTrue(r.dhcp_ticket.unknown)
                            self.assertIsNone(r.dhcp)
                            self.assertNotIn('dhcp_open_model', _event_names(f))
                            with self.assertRaises(f.error) as restore:
                                r.restore()
                            self.assertIs(restore.exception, f.secondary)
                            self._assert_l3_failure_only_stop(f, 'native_close_dhcp_model')
                        elif case == 'scope_reset_failure':
                            self.assertTrue(r.ip_confirmed)
                            self.assertFalse(r.dhcp_listening)
                            self.assertIs(r.dhcp_ticket.returned, r.dhcp)
                            self.assertFalse(r.dhcp_ticket.unknown)
                            self.assertIsNone(r.dhcp.socket)
                            self.assertEqual(11.0, r.native._scope)
                            self.assertEqual(21.0, r.service_until)
                            self.assertEqual([r.service_until], r.native.begin_calls)
                            self.assertNotIn('dhcp_open_model', _event_names(f))
                        else:
                            self.assertFalse(r.ip_confirmed)
                            self.assertIsNone(r.dhcp_ticket)
                            self.assertIsNone(r.dhcp)
                            self.assertIsNone(r.service_until)
                            self.assertIsNone(r.native.ip_receipt)
                            self.assertNotIn('store_prepare_ip', _event_names(f))
                            # Early absent L3 facts still traverse the ORIGINAL
                            # cleanup phases before the modeled group removal.
                            result = r.restore()
                            self.assertIs(result, r.store.current)
                            self.assertIs(r.failure, f.primary)
                            self.assertIsNone(r.restore_failure)
                            self.assertTrue(r.store.logical_restored)
                            self._assert_restore_order(f, complete=True)
                    else:
                        self.assertIs(r.prepare_live(), r)
                        self._assert_prepared_l3(f)
                        issued = r.service_until
                        original_binding = r.dhcp_ticket.binding
                        stages_before = tuple(f.stages)
                        begins_before = tuple(r.native.begin_calls)
                        durable_before = r.store.durable_calls
                        if case.startswith('poll_') and case != 'poll_error':
                            if case == 'poll_scope_changed':
                                r.native._scope = issued - 1.0
                            elif case == 'poll_until_identity':
                                changed = float(str(issued))
                                self.assertEqual(issued, changed)
                                self.assertIsNot(issued, changed)
                                r.service_until = changed
                            elif case == 'poll_ticket_changed':
                                ticket = f.module._DhcpConstructor(r, original_binding)
                                ticket.returned, ticket.unknown = r.dhcp, False
                                r.dhcp_ticket = ticket
                            elif case == 'poll_binding_changed':
                                r.dhcp.binding = object()
                            before = tuple(f.events)
                            with self.assertRaises(f.error) as caught:
                                r.poll_dhcp()
                            self.assertEqual('dhcp_live_owner_changed', caught.exception.code)
                            self.assertEqual(before, tuple(f.events))
                            self.assertEqual(0, r.dhcp.serve_calls)
                            self.assertIsNone(r.failure)  # Guard is before catch.
                            self.assertFalse(r.stop_requested)
                        elif case == 'poll_error':
                            with self.assertRaises(f.error) as caught:
                                r.poll_dhcp()
                            self.assertIs(caught.exception, f.primary)
                            self.assertIs(r.failure, f.primary)
                            self.assertTrue(r.stop_requested)
                            self.assertEqual(1, r.dhcp.serve_calls)
                        elif case in ('prepare_poll_restore', 'expired_poll'):
                            if case == 'prepare_poll_restore':
                                for now in (2.0, 3.0):
                                    f.clock.value = now
                                    self.assertEqual({'event': 'idle'}, r.poll_dhcp())
                            f.clock.value = issued
                            self.assertEqual({'event': 'finished'}, r.poll_dhcp())
                            self.assertIs(r.service_until, issued)
                            self.assertFalse(r.restore_attempted)
                            self.assertFalse(r.stop_requested)
                            self.assertEqual(3 if case == 'prepare_poll_restore' else 1,
                                             r.dhcp.serve_calls)
                        # Polls cannot reprepare, renew or republish. These are
                        # model counters, not claims about production budgets.
                        self.assertEqual(stages_before, tuple(f.stages))
                        self.assertEqual(begins_before, tuple(r.native.begin_calls))
                        self.assertEqual(durable_before, r.store.durable_calls)
                        self.assertIs(r._service_until_original, issued)
                        self.assertIs(r._dhcp_ticket_original.binding, original_binding)
                        if case in ('restore_dhcp_failure', 'restore_ip_failure'):
                            with self.assertRaises(f.error) as caught:
                                r.restore()
                            self.assertIs(caught.exception, f.secondary)
                            failed_at = ('native_close_dhcp_model' if case == 'restore_dhcp_failure'
                                         else 'native_restore_ip_model')
                            self._assert_l3_failure_only_stop(f, failed_at)
                        elif case == 'prepare_poll_restore':
                            result = r.restore()  # Real orchestration; model deps.
                            self.assertIs(result, r.store.current)
                            self.assertIsNone(r.failure)
                            self.assertIsNone(r.restore_failure)
                            self.assertEqual('restored', r.phase)
                            self._assert_restore_order(f, complete=True)
                    self.assertIs(r._originals, original_owner)
                    self.assertEqual(301.0, r.until)
                    self.assertEqual(301.0, r.entry.until)
                    self.assertEqual('301.0', r.entry.until_text)
                    self.assertIs(r.entry.clock, f.clock)
                    self.assertIs(r.worker, threading.current_thread())
                    self.assertIs(r.store, original_owner[5])
                    self.assertIs(r.native, original_owner[6])
                    self.assertIs(r.launcher, original_owner[7])
                    if r.restore_attempted:
                        self.assertIs(r._cleanup_original, r._cleanup_registered)
                        self.assertEqual(60.0, r.cleanup_until - r._cleanup_original[0])
                        self.assertEqual(r.cleanup_until, r.entry.cleanup_until)
                        self.assertEqual(r.cleanup_until, r.store.restore_until)
                        self.assertIs(r.entry.budget._cancelled, True)
                        self.assertEqual(f.resources.CLEANUP,
                                         r.entry.accounting._resource_lane_v23)
                        cleanup = r._cleanup_original
                        before = tuple(f.events)
                        with self.assertRaises(f.error) as duplicate:
                            r.restore()
                        self.assertEqual('restore_already_attempted', duplicate.exception.code)
                        self.assertIs(r._cleanup_original, cleanup)
                        self.assertEqual(before, tuple(f.events))
                    status = r.status()
                    self.assertIs(status['go_ready'], False)
                    self.assertIs(status['ip_ready'], False)
                    self.assertIs(status['dhcp_ready'], False)
                    self.assertIs(status['send_ready'], False)
                    self.assertIs(status['device_tested'], False)
                    self.assertIs(status['phone_tested'], False)
                    for probe in probes:
                        self.assertEqual(0, probe.call_count)
                    completed.append(case)
            self.assertEqual(list(cases), completed)
            self.assertEqual(14, len(completed))
            for probe in probes:
                self.assertEqual(0, probe.call_count)
        sys.stdout.write(MARKER)

    def _assert_prepared_l3(self, f):
        r = f.runtime
        self.assertTrue(r.started)
        self.assertTrue(r.group_confirmed)
        self.assertTrue(r.ip_confirmed)
        self.assertTrue(r.dhcp_listening)
        self.assertFalse(r.restore_attempted)
        self.assertFalse(r.store.logical_restored)
        self.assertIsNone(r.failure)
        self.assertEqual('dhcp_listening', r.phase)
        self.assertIs(r.dhcp_ticket, r._dhcp_ticket_original)
        self.assertIs(r.dhcp_ticket, f.constructor_tickets[0])
        self.assertIs(r.dhcp_ticket.returned, r.dhcp)
        self.assertIs(r.dhcp_ticket.binding, r.dhcp.binding)
        self.assertIs(r.dhcp_ticket.creator, f.module.dhcp.GoDhcpServer)
        self.assertIs(r.dhcp_ticket.unknown, False)
        self.assertIs(r.service_until, r._service_until_original)
        self.assertEqual(21.0, r.service_until)
        self.assertEqual(301.0, r.dhcp.binding.until)  # Not a renewed20 TTL.
        self.assertIs(r.dhcp.binding.service_until, r.service_until)
        self.assertEqual([(15, 16.0), (10, 11.0), (5, 6.0), (10, 11.0),
            (20, 21.0), (10, 11.0), (20, 21.0), (20, 21.0), (20, 21.0)], f.stages)
        names = _event_names(f)
        first = names.index('native_prepare_ip')
        self.assertEqual(['native_prepare_ip', 'store_prepare_ip',
            'native_create_ip', 'store_persist_ip_receipt', 'store_confirm_ip',
            'native_issue_dhcp_binding', 'dhcp_ctor_model', 'native_prepare_dhcp',
            'store_prepare_dhcp', 'model_publication_narrowed_scope',
            'native_begin_same_scope_model', 'dhcp_open_model',
            'native_observe_dhcp', 'store_confirm_dhcp',
            'native_begin_dhcp_service'], names[first:])
        narrowed = next(value for value in f.events
                        if value[0] == 'model_publication_narrowed_scope')
        opened = next(value for value in f.events if value[0] == 'dhcp_open_model')
        self.assertEqual(11.0, narrowed[1])
        self.assertIs(opened[1], r._service_until_original)
        self.assertIs(opened[2], r.dhcp)
        self.assertEqual([r._service_until_original], r.native.begin_calls)
        self.assertEqual(r.service_until, r.entry.accounting._io_deadline)

    def _assert_restore_order(self, f, complete):
        # All named Native/Store operations are dependency MODELS. Only their
        # ordering and actual Bootstrap failure/owner lifecycle are under test.
        names = _event_names(f)
        first = names.index('accounting_cancel_model')
        expected = ['accounting_cancel_model', 'store_begin_restore',
            'native_close_dhcp_model', 'store_close_dhcp',
            'native_prepare_ip_cleanup', 'store_prepare_ip_delete',
            'native_restore_ip_model', 'store_confirm_ip_restored',
            'native_prepare_group_cleanup_model', 'native_stop_child_model',
            'native_stop_child_model', 'native_close_inventory_model',
            'native_delete_interface_model', 'native_observe_restore_model',
            'store_finish_restore']
        self.assertEqual(expected, names[first:first + len(expected)])
        stops = [value for value in f.events if value[0] == 'native_stop_child_model']
        self.assertEqual(['controller', 'watchdog'], [value[1] for value in stops])
        self.assertIs(stops[0][3], f.runtime.controller)
        self.assertIs(stops[1][3], f.runtime.watchdog)
        self.assertIs(f.runtime.restore_observation.native_observation,
                      f.runtime.native.restored)
        self.assertIs(f.runtime.restore_observation.owner, f.runtime)
        if complete:
            self.assertTrue(f.runtime.restore_attempted)

    def _assert_l3_failure_only_stop(self, f, failed_at):
        r = f.runtime
        self.assertTrue(r.restore_attempted)
        self.assertIs(r.restore_failure, f.secondary)
        self.assertEqual('restore_pending', r.phase)
        self.assertFalse(r.store.logical_restored)
        self.assertIsNone(r.native.restored)
        self.assertIsNone(r.restore_observation)
        names = _event_names(f)
        self.assertEqual(1, names.count(failed_at))
        for name in ('native_prepare_group_cleanup_model', 'native_stop_child_model',
                     'native_delete_interface_model', 'native_observe_restore_model',
                     'store_finish_restore'):
            self.assertNotIn(name, names)
        stop_only = [value for value in f.events
                     if value[0] == 'native_stop_child_only_model']
        self.assertEqual(['watchdog', 'controller'], [value[1] for value in stop_only])
        self.assertIs(stop_only[0][2], r.watchdog)
        self.assertIs(stop_only[1][2], r.controller)
        self.assertEqual(1, names.count('native_close_inventory_model'))
        self.assertEqual(1, names.count('store_close_pending_model'))
        self.assertEqual('restore_intent' if failed_at == 'native_close_dhcp_model'
                         else 'ip_delete_intent', r.store.current.phase)


if __name__ == '__main__':
    unittest.main()
