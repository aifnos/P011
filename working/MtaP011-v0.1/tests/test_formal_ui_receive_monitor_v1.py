"""One new HOST method, six domains, for the passive receive UI predicate.

Only the complete pinned new helper executes. All Owner/Boot/State/Directory/
Operation/Session/handoff/Bridge roles below are explicitly in-memory scope
models, not the deployed definitions or actual admission/FD/restore evidence.
The model creates real bound Python methods and creator-local lambda closures
to exercise the helper's provenance checks; those methods are never called.
No old test is imported or run. Read the sole frozen SOURCE before installing
tripwires for open/stat/read/write, socket, process, thread and clock actions.
Paths are relative to this copied test's private-inputs root. ROOT alone runs.
"""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = 'candidate/formal-ui-receive-monitor-v1/runtime/receive_monitor.py'
SOURCE_BYTES = 13963
SOURCE_SHA = 'fe2a8bab0db21c45c6fe3d0a4733029492c8617d57ddbc9f296888c8c6837e36'
MARKER = ('HOST_FORMAL_UI_RECEIVE_MONITOR_V1 new_methods=1 cases=6 '
          'scope_model=true runtime=false old_methods=0 device=false phone=false rf=false\n')


class _ActionForbidden(BaseException):
    pass


def _forbidden(*args, **kwargs):
    raise _ActionForbidden('HOST passive-predicate action tripwire')


class _LockModel(object):
    """Only records lock order; no thread or real synchronization exists."""
    def __init__(self, name, stack):
        self.name, self.stack = name, stack

    def __enter__(self):
        required = [] if self.name == 'state' else ['state']
        if self.stack != required:
            raise _ActionForbidden('HOST model lock-order violation')
        self.stack.append(self.name)
        return self

    def __exit__(self, kind, value, traceback):
        if not self.stack or self.stack.pop() != self.name:
            raise _ActionForbidden('HOST model lock-order violation')
        return False


def _role(name, *classes):
    module = types.ModuleType('_host_receive_monitor_model_' + name)
    for class_name in classes:
        module.__dict__[class_name] = type(class_name, (object,), {})
    return module


def _scope_model(helper):
    """No actual constructor, Event, lock, thread, FD, process or clock runs."""
    service = _role('service', 'Operation', 'PrivateHelper')
    service.__dict__['_forbidden'] = _forbidden
    exec('''class State(object):
    def _new_operation_locked(self, op):
        return lambda session: self._run_operation(op, session)
    def _run_operation(self, op, session):
        return _forbidden()
    def _restore_owner(self, op):
        return _forbidden()
    def _close_extra(self, op):
        return _forbidden()
''', service.__dict__)
    storage = _role('storage', 'DirectoryBinding')
    factory_module = _role('factory', 'FixedReceiveDeploymentFactory')
    crypto = _role('crypto', 'OpenSslCrypto', 'KeyPair')
    sessions = _role('session', 'TransferSession')
    handoffs = _role('handoff', 'ReceiveConnectHandoff')
    bridges = _role('bridge', 'StateClientBridge')
    owner_module = _role('owner', 'FixedStateServiceOwner')
    modules = dict(mta_service=service, mta_storage=storage,
        mta_client_receive_factory=factory_module, mta_crypto=crypto,
        mta_transfer_session=sessions, mta_client_connect_handoff=handoffs,
        mta_client_state_bridge=bridges)
    service.TransferSession = sessions.TransferSession
    cap, stack = float('500.0'), []
    loader = types.SimpleNamespace(modules=modules, _original_until=cap,
        module_originals=[(name, module, module.__dict__) for name, module in modules.items()])
    owner = owner_module.FixedStateServiceOwner()
    state = service.State()
    op, session = service.Operation(), sessions.TransferSession()
    factory = factory_module.FixedReceiveDeploymentFactory()
    directory = storage.DirectoryBinding()
    owner.loader, owner.service = loader, service
    owner.state = owner._state_original = state
    owner.factory = owner._startup_factory_original = factory
    owner.until = owner.original_until = cap
    owner.clock = _forbidden
    owner.received_directory = owner._received_directory_original = directory
    owner.directory_type = storage.DirectoryBinding
    scope = types.SimpleNamespace(owner=owner, factory=factory, state=state,
        loader=loader, service=service, until=cap, original_until=cap,
        received_directory=directory)
    owner.startup_scope = owner._startup_scope_original = factory._startup_scope = scope
    directory._root, directory._until, directory.clock = helper.RECEIVED_ROOT, cap, owner.clock
    directory._period = (cap, owner.clock)
    directory._close_called = directory._closed = False
    directory.failure, directory.cleanup_errors, directory.rows = None, [], []
    for index, component in enumerate(('/', 'mnt', 'data', 'p011-toolbox', 'user', 'Received')):
        fd = 100 + index  # HOST integer only; never open or pretend to verify it.
        directory.rows.append(dict(role='directory', component=component,
            parent=None if index == 0 else directory.rows[index - 1],
            fd=fd, fd_original=fd, called=True, returned=True, closed=False,
            unknown=False, close_called=False))
    directory._row_originals = tuple(directory.rows)
    state.lock = _LockModel('state', stack)
    state.operation, state.session = op, session
    state._trusted_receive_deployment_factory = factory
    state._original_service_until = state._service_until_original = cap
    state._original_received_binding = state._received_binding_original = directory
    state.native_epoch, state.scanning = 7, False
    state.send_available = state.scan_available = False
    state.receive_available = False  # Not read as an admission receipt.
    state.wifi_restore_pending = state.radio_restore_pending = False
    state.discoverable, state.closing = False, False
    for name in ('helper', 'key', 'crypto', 'lease', 'transport'):
        setattr(state, name, None)
        setattr(op, name, None)
    op.kind, op.backend, op.consent, op.actor_unknown = 'receive', None, True, False
    op.epoch, op.stage, op.session = 7, 'connecting', session
    op.receive_factory = factory
    op.cancelled = state.cancelled = session.cancelled = object()
    for name in helper._OTHER_NONE:
        setattr(op, name, None)
    for name in helper._OTHER_FALSE:
        setattr(op, name, False)
    for name in helper._OTHER_EMPTY:
        setattr(op, name, [])
    op.client_handoff = op.client_bridge = None
    op.receive_bridge_ticket = {'started': False, 'returned': None}
    session._lock = _LockModel('session', stack)
    session._lease_owner, session._direction = op, 'receive'
    session._scoped_owner = session._release = None
    session._absolute_until = session._absolute_until_original = cap
    session._worker_start_unknown, session._phase = False, 'prepared'
    session._unknown, session._transports, session._handoffs = [], [], []
    session._attempts = [{'unknown_start': False, 'thread': object()}]
    session._restore, session._extra = state._restore_owner, state._close_extra
    session._task = state._new_operation_locked(op)
    session._worker = state.worker = object()
    session._task_deadline = None
    component = types.SimpleNamespace(owner=owner, owner_module=owner_module,
        loader=loader, until=cap)
    # Deliberately no idle(), status(), close(), check(), poll() or is_alive().
    return component


def _publish(model, name, both=True):
    state, modules = model.owner.state, model.loader.modules
    op = state.operation
    creator = {'crypto': modules['mta_crypto'].OpenSslCrypto,
               'key': modules['mta_crypto'].KeyPair,
               'helper': modules['mta_service'].PrivateHelper}[name]
    value = creator()
    if name == 'helper':
        value.spawn_unknown = value.reader_unknown = False
        value.spawn_claimed, value.spawn_resolved = True, False
        value.reader_claimed, value.reader_resolved = False, False
        value.thread = object()
    setattr(op, name, value)
    if both:
        setattr(state, name, value)


def _handoff_model(model):
    state, modules = model.owner.state, model.loader.modules
    op, session = state.operation, state.session
    for name in ('crypto', 'key', 'helper'):
        _publish(model, name)
    handoff = modules['mta_client_connect_handoff'].ReceiveConnectHandoff()
    bridge = modules['mta_client_state_bridge'].StateClientBridge()
    op.client_handoff, op.client_bridge = handoff, bridge
    op.receive_bridge_ticket = {'started': True, 'returned': bridge}
    op.stage, session._phase, session._task_deadline = 'advertising', 'running', float('490.0')
    handoff.state, handoff.operation, handoff.session = state, op, session
    handoff.worker, handoff.epoch = session._worker, op.epoch
    handoff.clock, handoff.deadline = model.owner.clock, session._task_deadline
    handoff.reader = op.helper.thread
    for name in ('helper', 'key', 'crypto'):
        setattr(handoff, name, getattr(op, name))
    bridge.state, bridge.operation, bridge.handoff = state, op, handoff
    bridge.session, bridge.worker, bridge.cancelled = session, session._worker, op.cancelled
    bridge.epoch, bridge._factory = op.epoch, model.owner.factory
    bridge.clock = bridge._clock_original = handoff.clock
    state.discoverable = state.radio_restore_pending = True
    state.receive_available = True  # Still only model input, never enabled on device.
    return model


class FormalUiReceiveMonitorV1Tests(unittest.TestCase):
    def test_original_receive_scope_and_rejected_busy_models(self):
        raw = (ROOT / SOURCE_PATH).read_bytes()
        self.assertEqual(len(raw), SOURCE_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SOURCE_SHA)
        helper = types.ModuleType('_host_formal_ui_receive_monitor_v1_definition')
        helper.__file__ = str(ROOT / SOURCE_PATH)
        exec(compile(raw, helper.__file__, 'exec'), helper.__dict__)
        canonical = {name: value for name, value in sys.modules.items()
                     if name.startswith(('mta_', 'p011_'))}

        def observe(model, expected):
            self.assertIs(helper.owned_receive_monitor_allowed(model), expected)
            self.assertEqual(model.owner.state.lock.stack, [])

        with ExitStack() as guards:
            for module, name in ((os, 'open'), (os, 'stat'), (os, 'fstat'), (os, 'listdir'),
                    (os, 'read'), (os, 'write'), (socket, 'socket'), (subprocess, 'Popen'),
                    (threading, 'Thread'), (time, 'monotonic')):
                guards.enter_context(mock.patch.object(module, name, _forbidden))
            guards.enter_context(mock.patch('builtins.open', _forbidden))

            # Domain 1: creator-bound prepared/running; no receive gate is granted.
            model = _scope_model(helper)
            observe(model, True)
            model.owner.state.session._phase = 'running'
            observe(model, True)
            model.owner.state.receive_available = True
            observe(model, True)

            # Domain 2: all three exact op-only pre-State publication windows.
            for name in ('crypto', 'key', 'helper'):
                with self.subTest(domain=2, actor=name):
                    model = _scope_model(helper)
                    _publish(model, name, both=False)
                    observe(model, True)
                    setattr(model.owner.state, name, getattr(model.owner.state.operation, name))
                    observe(model, True)
                    setattr(model.owner.state.operation, name, None)
                    observe(model, False)

            # Domain 3: original handoff/Bridge, cancellation and known finalizers.
            for phase in ('running', 'transport_close', 'extra', 'restore',
                          'awaiting_finalizer_exit', 'pending'):
                with self.subTest(domain=3, phase=phase):
                    model = _handoff_model(_scope_model(helper))
                    model.owner.state.session._phase = phase
                    model.owner.state.closing = True
                    model.owner.state.wifi_restore_pending = True
                    observe(model, True)  # Not a restoration/closed receipt.
            for stage in ('listen_pending', 'listen_ready', 'advert_pending', 'advertising'):
                model = _handoff_model(_scope_model(helper))
                model.owner.state.operation.stage = stage
                observe(model, True)

            # Domain 4: original realm, Factory, directory, cap, epoch and workers.
            changes = (
                ('owner_original', lambda m: setattr(m.owner, '_state_original', object())),
                ('owner_loader', lambda m: setattr(m.owner, 'loader', object())),
                ('owner_factory', lambda m: setattr(m.owner, '_startup_factory_original', object())),
                ('scope', lambda m: setattr(m.owner, '_startup_scope_original', object())),
                ('scope_factory', lambda m: setattr(m.owner.startup_scope, 'factory', object())),
                ('role_namespace', lambda m: m.loader.module_originals.clear()),
                ('directory', lambda m: setattr(m.owner, '_received_directory_original', object())),
                ('directory_cap', lambda m: setattr(m.owner.received_directory, '_until', 501.0)),
                ('directory_period', lambda m: setattr(m.owner.received_directory, '_period', (501.0, m.owner.clock))),
                ('directory_row', lambda m: m.owner.received_directory.rows.__setitem__(0, dict(m.owner.received_directory.rows[0]))),
                ('directory_fd', lambda m: m.owner.received_directory.rows[0].__setitem__('fd', 999)),
                ('directory_unknown', lambda m: m.owner.received_directory.rows[0].__setitem__('unknown', True)),
                ('directory_closed', lambda m: m.owner.received_directory.rows[0].__setitem__('closed', True)),
                ('component_cap', lambda m: setattr(m, 'until', 501.0)),
                ('state_cap', lambda m: setattr(m.owner.state, '_service_until_original', 501.0)),
                ('session_cap', lambda m: setattr(m.owner.state.session, '_absolute_until', 501.0)),
                ('epoch', lambda m: setattr(m.owner.state, 'native_epoch', 8)),
                ('bool_epoch', lambda m: setattr(m.owner.state.operation, 'epoch', True)),
                ('op_factory', lambda m: setattr(m.owner.state.operation, 'receive_factory', object())),
                ('state_factory', lambda m: setattr(m.owner.state, '_trusted_receive_deployment_factory', object())),
                ('op_session', lambda m: setattr(m.owner.state.operation, 'session', object())),
                ('state_worker', lambda m: setattr(m.owner.state, 'worker', object())),
                ('cancel_event', lambda m: setattr(m.owner.state, 'cancelled', object())),
            )
            for label, change in changes:
                with self.subTest(domain=4, change=label):
                    model = _scope_model(helper)
                    change(model)
                    observe(model, False)

            # Domain 5: exact callbacks and creator lambda closure, not kind-only.
            model = _scope_model(helper)
            model.owner.state.session._restore = lambda op: True
            observe(model, False)
            model = _scope_model(helper)
            model.owner.state.session._extra = lambda op: True
            observe(model, False)
            model = _scope_model(helper)
            model.owner.state.session._task = lambda session: None
            observe(model, False)
            model = _scope_model(helper)
            state = model.owner.state
            state.session._task = state._new_operation_locked(object())
            observe(model, False)
            model = _scope_model(helper)
            state = model.owner.state
            foreign = model.loader.modules['mta_service'].State()
            state.session._task = foreign._new_operation_locked(state.operation)
            observe(model, False)
            model = _scope_model(helper)
            foreign = model.loader.modules['mta_service'].State()
            model.owner.state.session._restore = foreign._restore_owner
            observe(model, False)

            # Domain 6: foreign kinds/scopes/unknown actors and broken handoffs.
            changes = (
                ('send', lambda m: setattr(m.owner.state.operation, 'kind', 'send')),
                ('go_send', lambda m: setattr(m.owner.state.operation, 'kind', 'go_send')),
                ('scan', lambda m: setattr(m.owner.state.operation, 'kind', 'scan')),
                ('consent', lambda m: setattr(m.owner.state.operation, 'consent', False)),
                ('actor_unknown', lambda m: setattr(m.owner.state.operation, 'actor_unknown', True)),
                ('send_scope', lambda m: setattr(m.owner.state.operation, 'send_worker', object())),
                ('go_scope', lambda m: setattr(m.owner.state.operation, 'go_worker', object())),
                ('scan_scope', lambda m: setattr(m.owner.state.operation, 'scan', object())),
                ('go_started', lambda m: setattr(m.owner.state.operation, 'go_started', True)),
                ('foreign_state_crypto', lambda m: setattr(m.owner.state, 'crypto', object())),
                ('foreign_op_crypto', lambda m: setattr(m.owner.state.operation, 'crypto', object())),
                ('lease', lambda m: setattr(m.owner.state, 'lease', object())),
                ('transport', lambda m: setattr(m.owner.state.operation, 'transport', object())),
                ('session_owner', lambda m: setattr(m.owner.state.session, '_lease_owner', object())),
                ('session_direction', lambda m: setattr(m.owner.state.session, '_direction', 'send')),
                ('session_scoped', lambda m: setattr(m.owner.state.session, '_scoped_owner', object())),
                ('session_release', lambda m: setattr(m.owner.state.session, '_release', _forbidden)),
                ('worker_unknown', lambda m: setattr(m.owner.state.session, '_worker_start_unknown', True)),
                ('session_unknown', lambda m: m.owner.state.session._unknown.append(object())),
                ('session_transport', lambda m: m.owner.state.session._transports.append(object())),
                ('session_handoff', lambda m: m.owner.state.session._handoffs.append(object())),
                ('finalizer_unknown', lambda m: m.owner.state.session._attempts[0].__setitem__('unknown_start', True)),
                ('scanning', lambda m: setattr(m.owner.state, 'scanning', True)),
                ('foreign_stage', lambda m: setattr(m.owner.state.operation, 'stage', 'go_scanning')),
            )
            for label, change in changes:
                with self.subTest(domain=6, change=label):
                    model = _scope_model(helper)
                    change(model)
                    observe(model, False)
            for field in ('spawn_unknown', 'reader_unknown'):
                model = _scope_model(helper)
                _publish(model, 'helper')
                setattr(model.owner.state.operation.helper, field, True)
                observe(model, False)
            for target, field in (('handoff', 'worker'), ('handoff', 'operation'),
                    ('handoff', 'clock'), ('handoff', 'key'), ('bridge', '_factory'),
                    ('bridge', 'session'), ('bridge', 'cancelled'), ('bridge', '_clock_original')):
                model = _handoff_model(_scope_model(helper))
                op = model.owner.state.operation
                actor = op.client_handoff if target == 'handoff' else op.client_bridge
                setattr(actor, field, object())
                observe(model, False)
            model = _handoff_model(_scope_model(helper))
            model.owner.state.operation.receive_bridge_ticket['returned'] = object()
            observe(model, False)
            model = _handoff_model(_scope_model(helper))
            model.owner.state.operation.client_handoff.deadline = 501.0
            observe(model, False)

        self.assertEqual(canonical, {name: value for name, value in sys.modules.items()
                                    if name.startswith(('mta_', 'p011_'))})
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main(verbosity=2)
