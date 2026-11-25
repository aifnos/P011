# -*- coding: utf-8 -*-
"""Passive formal-UI observation of an original owned receive operation.

This predicate grants neither RF admission nor restoration/close authority.
The first startup strict-idle gate and the original Owner.close remain intact.
The caller must already own its authenticated component/Boot/Owner originals.
No clock, descriptor, process, thread, callback or network action runs here;
directory rows are continuity observations, not fresh filesystem evidence.
Python 3.5-compatible SOURCE; the new HOST test is explicitly a scope model.
"""
import math
import types


RECEIVED_ROOT = '/mnt/data/p011-toolbox/user/Received'
_RECEIVE_STAGES = ('connecting', 'listen_pending', 'listen_ready',
                   'advert_pending', 'advertising')
_SESSION_PHASES = ('prepared', 'running', 'transport_close', 'extra',
                   'restore', 'awaiting_finalizer_exit', 'pending')
_OTHER_NONE = ('scan', 'send_intent', 'send_worker', 'send_provider',
               'send_lease', 'send_result', 'send_factory', 'send_restore_receipt',
               'send_restore_readback', '_send_skip', 'send_file_ids', 'send_task_id',
               'send_selection', 'send_prepared', 'send_publication', 'send_bridge',
               'go_selection_original', 'go_helper_original', 'go_modules',
               'go_source_dicts', 'go_creators', 'go_originals', 'go_worker',
               'go_until', 'go_cleanup_until', 'go_closed_facts',
               'go_helper_close_ticket', 'go_gatt_teardown_original',
               'go_terminal_source', 'go_terminal_parent', 'go_terminal_original',
               'go_terminal_ticket', 'go_terminal_facts', 'go_terminal_result',
               'go_terminal_error')
_OTHER_FALSE = ('send_construct_pending', 'send_construct_unknown',
                'send_bytes_observed', 'go_started', 'go_returned',
                'go_cleanup_unknown', 'go_helper_close_called', 'go_helper_closed',
                'go_radio_verified', 'go_child_called', 'go_native_restore_verified',
                'go_terminal_attempted', 'go_terminal_unavailable')
_OTHER_EMPTY = ('send_tickets', 'go_tickets', 'go_errors', 'go_gatt_events')


def _bound(method, instance, function):
    return (type(method) is types.MethodType and method.__self__ is instance and
            method.__func__ is function)


def _task_original(task, service, state, operation):
    creator = service.State._new_operation_locked
    if (type(task) is not types.FunctionType or type(creator) is not types.FunctionType or
            task.__globals__ is not service.__dict__ or
            creator.__globals__ is not service.__dict__ or
            not any(task.__code__ is code for code in creator.__code__.co_consts
                    if type(code) is types.CodeType) or
            task.__code__.co_freevars != ('op', 'self') or
            task.__closure__ is None or len(task.__closure__) != 2):
        return False
    return (task.__closure__[0].cell_contents is operation and
            task.__closure__[1].cell_contents is state)


def _directory_original(directory, owner, state, storage, cap):
    if (type(directory) is not storage.DirectoryBinding or
            owner.directory_type is not storage.DirectoryBinding or
            directory is not owner._received_directory_original or
            directory is not state._original_received_binding or
            directory is not state._received_binding_original or
            directory._root != RECEIVED_ROOT or directory._until is not cap or
            directory.clock is not owner.clock or
            type(directory._period) is not tuple or len(directory._period) != 2 or
            directory._period[0] is not cap or directory._period[1] is not owner.clock or
            directory._close_called is not False or directory._closed is not False or
            directory.failure is not None or directory.cleanup_errors != [] or
            type(directory.rows) is not list or type(directory._row_originals) is not tuple or
            len(directory.rows) != 6 or len(directory._row_originals) != 6):
        return False
    components = ('/', 'mnt', 'data', 'p011-toolbox', 'user', 'Received')
    for index, row in enumerate(directory.rows):
        if (row is not directory._row_originals[index] or type(row) is not dict or
                row['role'] != 'directory' or row['component'] != components[index] or
                row['parent'] is not (None if index == 0 else directory.rows[index - 1]) or
                type(row['fd_original']) is not int or row['fd_original'] < 0 or
                row['fd'] is not row['fd_original'] or row['called'] is not True or
                row['returned'] is not True or row['closed'] is not False or
                row['unknown'] is not False or row['close_called'] is not False):
            return False
    return True


def owned_receive_monitor_allowed(component):
    """Allow observation only; unknown/foreign actors fail closed, not to idle.

    State.lock then Session._lock matches the actual State status/action order.
    Known cancellation or pending restoration remains visible; it is not PASS.
    The worker publishes crypto/key/helper on op before taking State.lock.
    That exact typed op-only connecting window is legal, never a State-only one.
    """
    try:
        owner, loader = component.owner, component.loader
        if (type(component.owner_module) is not types.ModuleType or
                type(owner) is not component.owner_module.FixedStateServiceOwner or
                owner.loader is not loader or type(loader.modules) is not dict):
            return False
        modules = loader.modules
        service, storage = modules['mta_service'], modules['mta_storage']
        factory_module = modules['mta_client_receive_factory']
        roles = ('mta_service', 'mta_storage', 'mta_client_receive_factory',
                 'mta_crypto', 'mta_transfer_session', 'mta_client_connect_handoff',
                 'mta_client_state_bridge')
        if (any(type(modules[name]) is not types.ModuleType for name in roles) or
                any(not any(name == n and modules[name] is original and
                            original.__dict__ is namespace
                            for n, original, namespace in loader.module_originals)
                    for name in roles) or
                owner.service is not service or type(owner.state) is not service.State or
                owner.state is not owner._state_original or
                type(owner.factory) is not factory_module.FixedReceiveDeploymentFactory or
                owner.factory is not owner._startup_factory_original):
            return False
        state, factory, cap = owner.state, owner.factory, component.until
        scope = owner.startup_scope
        if (type(cap) is not float or not math.isfinite(cap) or not 0 < cap < 2 ** 53 or
                owner.until is not cap or owner.original_until is not cap or
                loader._original_until is not cap or
                scope is None or scope is not owner._startup_scope_original or
                scope is not factory._startup_scope or scope.owner is not owner or
                scope.factory is not factory or scope.state is not state or
                scope.loader is not loader or scope.service is not service or
                scope.until is not cap or scope.original_until is not cap or
                scope.received_directory is not owner.received_directory):
            return False
        with state.lock:
            op, session = state.operation, state.session
            if (type(op) is not service.Operation or op.kind != 'receive' or
                    op.backend is not None or op.consent is not True or
                    op.actor_unknown is not False or type(op.epoch) is not int or
                    not 1 <= op.epoch <= 9007199254740991 or
                    type(state.native_epoch) is not int or op.epoch != state.native_epoch or
                    state._trusted_receive_deployment_factory is not factory or
                    op.receive_factory is not factory or
                    state._original_service_until is not cap or
                    state._service_until_original is not cap or
                    state.scanning is not False or
                    state.send_available is not False or state.scan_available is not False or
                    any(getattr(op, name) is not None for name in _OTHER_NONE) or
                    any(getattr(op, name) is not False for name in _OTHER_FALSE) or
                    any(type(getattr(op, name)) is not list or getattr(op, name) != []
                        for name in _OTHER_EMPTY) or
                    any(getattr(value, name) is not None for value in (state, op)
                        for name in ('lease', 'transport')) or
                    not _directory_original(owner.received_directory, owner, state, storage, cap) or
                    type(session) is not service.TransferSession or
                    service.TransferSession is not modules['mta_transfer_session'].TransferSession or
                    op.session is not session or state.worker is not session._worker or
                    session._worker is None or session.cancelled is not op.cancelled or
                    state.cancelled is not op.cancelled or op.stage not in _RECEIVE_STAGES):
                return False
            with session._lock:
                if (session._lease_owner is not op or session._direction != 'receive' or
                        session._scoped_owner is not None or session._release is not None or
                        session._absolute_until is not session._absolute_until_original or
                        type(session._absolute_until) is not float or session._absolute_until != cap or
                        session._worker_start_unknown is not False or session._phase not in _SESSION_PHASES or
                        any(type(value) is not list or value != [] for value in
                            (session._unknown, session._transports, session._handoffs)) or
                        type(session._attempts) is not list or not session._attempts or
                        any(type(row) is not dict or row['unknown_start'] is not False
                            for row in session._attempts) or
                        not _bound(session._restore, state, service.State._restore_owner) or
                        not _bound(session._extra, state, service.State._close_extra) or
                        not _task_original(session._task, service, state, op)):
                    return False
                handoff, bridge = op.client_handoff, op.client_bridge
                ticket = op.receive_bridge_ticket
                if type(ticket) is not dict or set(ticket) != {'started', 'returned'}:
                    return False
                for name, creator in (('crypto', modules['mta_crypto'].OpenSslCrypto),
                                      ('key', modules['mta_crypto'].KeyPair),
                                      ('helper', service.PrivateHelper)):
                    value, published = getattr(op, name), getattr(state, name)
                    if value is None:
                        if published is not None:
                            return False
                    elif (type(value) is not creator or
                          (published is not value and not
                           (published is None and handoff is None and bridge is None and
                            op.stage == 'connecting'))):
                        return False
                if op.helper is not None and (op.helper.spawn_unknown is not False or
                                              op.helper.reader_unknown is not False):
                    return False
                if handoff is None:
                    return (bridge is None and ticket['started'] is False and
                            ticket['returned'] is None and op.stage == 'connecting')
                if (type(handoff) is not modules['mta_client_connect_handoff'].ReceiveConnectHandoff or
                        type(bridge) is not modules['mta_client_state_bridge'].StateClientBridge or
                        ticket['started'] is not True or ticket['returned'] is not bridge or
                        handoff.state is not state or handoff.operation is not op or
                        handoff.session is not session or handoff.worker is not session._worker or
                        type(handoff.epoch) is not int or handoff.epoch != op.epoch or
                        handoff.clock is not owner.clock or
                        type(session._task_deadline) is not float or
                        not 0 < session._task_deadline <= cap or
                        type(handoff.deadline) is not float or handoff.deadline != session._task_deadline or
                        any(getattr(op, name) is None or getattr(state, name) is not getattr(op, name) or
                            getattr(handoff, name) is not getattr(op, name)
                            for name in ('helper', 'key', 'crypto')) or
                        handoff.reader is not op.helper.thread or
                        bridge.state is not state or bridge.operation is not op or
                        bridge.handoff is not handoff or bridge.session is not session or
                        bridge.worker is not session._worker or bridge.cancelled is not op.cancelled or
                        type(bridge.epoch) is not int or bridge.epoch != op.epoch or
                        bridge._factory is not factory or bridge.clock is not handoff.clock or
                        bridge._clock_original is not handoff.clock):
                    return False
                return True
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
        # Fixed finite outcome, never exception text/identifiers or a fake idle.
        return False
