"""One bounded real phone-discovery opportunity; no accept/send/UI.

Derives only the v3 advertisement envelope. Original 75-role business sources
remain fixed. The existing receive-interactive-v1 constructor selects 600+60,
without renewal. Actual advertising must occur in 15 seconds, then one fixed
120-second phone discovery window. Peer activity gets at most 15 seconds of
original-worker progress observation, then the original cancel/close path.
"""
import time

PREPARE_SECONDS = 15.0
PHONE_SECONDS = 120.0
OBSERVE_SECONDS = PREPARE_SECONDS + PHONE_SECONDS
_PHONE_WINDOW = None
_HANDSHAKE_WINDOW = None
HANDSHAKE_SECONDS = 15.0
_RETAINED = None
_OBSERVATION_BUSY_COUNT = 0
COMMON = ('platform_validated', 'payload_validated', 'before_baseline_observed',
          'after_baseline_observed', 'stock_hashes_match', 'stock_processes_match',
          'baseline_unchanged', 'preflight_complete', 'runner_fds_closed',
          'client_sockets_closed')
SERVICE = ('stage_verified', 'boot_loaded', 'owner_started', 'operation_inventory_idle',
           'capability_actors_closed', 'owner_close_called', 'owner_resources_closed',
           'private_assets_verified', 'startup_readonly_called', 'startup_readonly_verified',
           'startup_baseline_collected', 'startup_status_verified', 'startup_resources_closed')


def observe(component, observation_until=None):
    """Bounded local read of original actors; never supplies native events."""
    component.check()
    owner = component.owner
    state, service = owner.state, owner.service
    cap = component.until if observation_until is None else min(component.until, observation_until)
    remaining = cap - time.monotonic()
    if remaining <= 0:
        return None
    if not state.lock.acquire(timeout=min(.1, remaining)):
        # Busy is not an identity/field failure and never advertising evidence.
        # The original outer observation/window cap controls the next attempt.
        return None
    try:
        op, session = state.operation, state.session
        if (state is not owner._state_original or type(state) is not service.State or
                type(op) is not service.Operation or op.kind != 'receive' or
                type(session) is not service.TransferSession or session is not op.session or
                state.worker is not session._worker or op.epoch != state.native_epoch):
            raise ValueError('original_receive_inventory_unknown')
        handoff, bridge, helper = op.client_handoff, op.client_bridge, op.helper
        if handoff is not None and type(handoff) is not service.ReceiveConnectHandoff:
            raise ValueError('original_handoff_unknown')
        if bridge is not None and type(bridge) is not service.StateClientBridge:
            raise ValueError('original_bridge_unknown')
        data = handoff.status() if handoff is not None else None
        names = ('received', 'decrypt_attempted', 'frame_claimed', 'failed')
        if data is not None and (type(data) is not dict or any(
                name not in data or type(data[name]) is not bool for name in names)):
            raise ValueError('original_handoff_fields_unknown')
        handoff_received = data is not None and data['received'] is True
        bridge_started = bridge is not None and bridge.started is True
        counts = tuple(state.event_counts.get(name, 0) for name in ('listen', 'advert', 'p2p', 'error', 'closed', 'stop'))
        if any(type(value) is not int or not 0 <= value <= 1000000 for value in counts):
            raise ValueError('native_counts_unknown')
        # State begins as connecting before listen. That initial state is not a
        # phone handoff; actual input/Bridge/request is what requires cancel.
        peer_activity = handoff_received or bridge_started or state.request is not None or counts[2] > 0
        native_failure = counts[3] > 0 or op.cancelled.is_set() or op.actor_unknown
        advertising = (state.state == 'advertising' and state.discoverable is True and
                       op.stage == 'advertising' and helper is not None and
                       helper is state.helper and counts[0] > 0 and counts[1] > 0 and
                       not native_failure and not peer_activity)
        row = dict(stage=op.stage, state=state.state, discoverable=state.discoverable is True,
                    advertising=advertising, handoff_received=handoff_received,
                    bridge_started=bridge_started, request_present=state.request is not None,
                    peer_activity=peer_activity, native_failure=bool(native_failure),
                    worker_alive=session._worker is not None and session._worker.is_alive(),
                    helper_retained=helper is not None, event_counts=counts)
        parent = bridge.parent if bridge is not None else None
        row.update(decrypt_attempted=data is not None and data['decrypt_attempted'] is True,
                   frame_claimed=data is not None and data['frame_claimed'] is True,
                   handoff_failed=data is not None and data['failed'] is True,
                   bridge_running=bridge is not None and bridge.running is True,
                   parent_present=parent is not None,
                   deployment_present=bridge is not None and bridge.deployment is not None,
                   f_process_retained=False, progress_unknown=False)
    finally:
        state.lock.release()
    return parent_progress(component, cap, row, op, bridge, parent)


def parent_progress(component, until, row, op, bridge, parent):
    """Passive original Parent inventory only; never poll/authenticate/IO.

    Parent mutex is taken after releasing State.lock, then released before the
    State identity readback. A failed acquire/readback stays None+unknown.
    Process retained is not process alive, connection, radio or restore proof.
    """
    if parent is None:
        return row
    owner, state = component.owner, component.owner.state
    executor = owner.loader.modules.get('mta_client_executor')
    if (executor is None or bridge is None or bridge._executor is not executor or
            type(parent) is not executor.ParentExecutor):
        row.update(f_process_retained=None, progress_unknown=True)
        return row
    remaining = until - time.monotonic()
    if remaining <= 0 or not parent._mutex.acquire(timeout=min(.1, remaining)):
        row.update(f_process_retained=None, progress_unknown=True)
        return row
    try:
        process, ticket = parent.process, parent.spawn_ticket
        if process is None:
            if ticket is not None:
                row.update(f_process_retained=None, progress_unknown=True)
        elif (type(ticket) is dict and ticket.get('returned') is process and
                ticket.get('unknown') is False and type(process) is parent.io.process_type and
                parent.attempted is True and parent.actor is not None):
            row['f_process_retained'] = True
        else:
            row.update(f_process_retained=None, progress_unknown=True)
    finally:
        parent._mutex.release()
    remaining = until - time.monotonic()
    if remaining <= 0 or not state.lock.acquire(timeout=min(.1, remaining)):
        row.update(f_process_retained=None, progress_unknown=True)
        return row
    try:
        if (state is not owner._state_original or state.operation is not op or
                op.client_bridge is not bridge or bridge.parent is not parent):
            row.update(f_process_retained=None, progress_unknown=True)
    finally:
        state.lock.release()
    return row


def progress_decision(row):
    """Finite DATA decision only, not authorization or a success result."""
    if row['native_failure']:
        return 'native_failure'
    if row['handoff_failed']:
        return 'handoff_failed'
    if not row['worker_alive']:
        return 'worker_ended'
    if row['request_present']:
        return 'request_seen'
    # Attempted alone is set before crypto returns; never cancel on that flag.
    if row['frame_claimed'] and row['f_process_retained'] is True and not row['progress_unknown']:
        return 'claimed_with_f'
    return None


def observe_window(component, started, observe_until, rows, flags):
    """Only actual advertising starts the one-shot phone opportunity."""
    global _OBSERVATION_BUSY_COUNT, _PHONE_WINDOW, _HANDSHAKE_WINDOW
    reason = 'advert_not_observed'
    prepare_until = min(component.until, started + PREPARE_SECONDS)
    ready_at = peer_at = None
    until = prepare_until
    _PHONE_WINDOW = dict(ready=False, completed=False, ready_elapsed=None,
                         opportunity_seconds=PHONE_SECONDS, elapsed=None)
    _HANDSHAKE_WINDOW = dict(peer_seen=False, phase_seconds=HANDSHAKE_SECONDS,
        started_elapsed=None, elapsed=None, outcome='not_seen')
    while time.monotonic() < until and len(rows) < 320:
        row = observe(component, until)
        if row is None:
            _OBSERVATION_BUSY_COUNT += 1
            time.sleep(min(.01, max(0.0, until - time.monotonic())))
            continue
        now = time.monotonic()
        if now >= until:
            # A lock obtained at the boundary is not timely READY evidence.
            # Still preserve actual peer/native flags for original cancellation.
            if row['peer_activity']:
                flags['peer_activity_seen'] = True
                reason = 'peer_activity_cancelled'
            if row['native_failure']:
                flags['native_failure_seen'] = True
                reason = 'native_operation_failed'
            break
        row['elapsed_seconds'] = now - started
        rows.append(row)
        flags['listen_seen'] = flags['listen_seen'] or row['event_counts'][0] > 0
        flags['advertising_seen'] = flags['advertising_seen'] or row['advertising']
        if row['peer_activity']:
            flags['peer_activity_seen'] = True
            reason = 'peer_activity_cancelled'
            if peer_at is None:
                peer_at = now
                until = min(until, peer_at + HANDSHAKE_SECONDS)
                _HANDSHAKE_WINDOW.update(peer_seen=True, started_elapsed=peer_at - started,
                                         outcome='waiting')
            decision = progress_decision(row)
            if decision is not None:
                if row['native_failure']:
                    flags['native_failure_seen'] = True
                _HANDSHAKE_WINDOW['outcome'] = decision
                break
        if row['native_failure']:
            flags['native_failure_seen'] = True
            reason = 'native_operation_failed'
            break
        if ready_at is None and row['advertising']:
            ready_at = now
            until = min(component.until, ready_at + PHONE_SECONDS)
            _PHONE_WINDOW['ready'] = True
            _PHONE_WINDOW['ready_elapsed'] = ready_at - started
            print('PHONE_DISCOVERY_READY=' + repr(dict(
                ready=True, opportunity_seconds=PHONE_SECONDS,
                accept_allowed=False, send_allowed=False)), flush=True)
        time.sleep(min(.5, max(0.0, until - time.monotonic())))
    if peer_at is not None:
        _HANDSHAKE_WINDOW['elapsed'] = max(0.0, time.monotonic() - peer_at)
        if _HANDSHAKE_WINDOW['outcome'] == 'waiting':
            _HANDSHAKE_WINDOW['outcome'] = 'phase_deadline'
    if ready_at is not None:
        _PHONE_WINDOW['elapsed'] = max(0.0, time.monotonic() - ready_at)
        _PHONE_WINDOW['completed'] = (
            _PHONE_WINDOW['elapsed'] >= PHONE_SECONDS and
            not flags['peer_activity_seen'] and not flags['native_failure_seen'] and
            time.monotonic() >= until and until == ready_at + PHONE_SECONDS)
    if flags['advertising_seen'] and not flags['peer_activity_seen'] and not flags['native_failure_seen']:
        # Advertising alone cannot pass an interrupted/truncated phone window.
        reason = 'advertising_observed' if _PHONE_WINDOW['completed'] else 'advert_not_observed'
    return reason


def terminal(component):
    """Passive retained inventory after the original Owner close; no new IO."""
    owner = component.owner
    if owner is None or owner.state is None:
        return None
    state, service = owner.state, owner.service
    if not state.lock.acquire(False):
        raise ValueError('terminal_lock_unknown')
    try:
        op, session = state.operation, state.session
        if (op is None or session is None or op.kind != 'receive' or
                op.session is not session or state.worker is not session._worker):
            return None
        helper, bridge, key = op.helper, op.client_bridge, op.key
        return dict(operation_retained=True, session_retained=True,
                    worker_alive=session._worker is not None and session._worker.is_alive(),
                    helper_retained=helper is not None,
                    helper_reader_alive=helper is not None and helper._reader_original.is_alive(),
                    helper_reaped=helper is not None and type(helper.returncode) is int,
                    helper_closed=helper is not None and helper.closure_verified() is True,
                    key_retained=key is not None, key_closed=key is not None and key.closed is True,
                    bridge_retained=bridge is not None,
                    bridge_started=bridge is not None and bridge.started is True,
                    handoff_received=op.client_handoff is not None and op.client_handoff.status()['received'] is True,
                    parent_retained=bridge is not None and bridge.parent is not None,
                    deployment_retained=bridge is not None and bridge.deployment is not None,
                    network_before_present=op.receive_network_before is not None,
                    network_after_present=op.receive_network_after is not None,
                    network_zero_known=op.receive_network_zero_known is True,
                    network_verified=op.receive_network_verified is True,
                    receive_extra_verified=op.receive_extra_verified is True,
                    radio_restore_pending=state.radio_restore_pending is True,
                    wifi_restore_pending=state.wifi_restore_pending is True,
                    event_counts=tuple(state.event_counts.get(name, 0) for name in
                                       ('listen', 'advert', 'p2p', 'error', 'closed', 'stop')))
    finally:
        state.lock.release()


def run_fixed(runner, artifacts):
    global _RETAINED, _OBSERVATION_BUSY_COUNT, _PHONE_WINDOW, _HANDSHAKE_WINDOW
    _OBSERVATION_BUSY_COUNT = 0
    _PHONE_WINDOW = _HANDSHAKE_WINDOW = None
    component = runner.FixedSession(artifacts, False, receive_trial_requested=True,
                                    profile='receive-interactive-v1')
    _RETAINED = component
    flags = dict(start_called=False, start_returned=False, receive_ready=False,
                 advertising_seen=False, listen_seen=False, peer_activity_seen=False,
                 stop_called=False, stop_returned=False, native_failure_seen=False,
                 late_peer_activity_seen=False,
                 closure_verified=False, baseline_verified=False, resource_pending=True)
    rows = []
    reason = 'not_started'
    end_inventory = None
    try:
        component.platform(); component.validate_payload()
        component.before = component.snapshot()
        component.result['before_baseline_observed'] = True
        component.result['stock_hashes_match'] = (
            dict((path, row[1]) for path, row in component.before['stock']) == dict(runner.STOCK_PINS))
        processes = component.before['processes']
        component.result['stock_processes_match'] = all(
            sum(row[0][3] == name for row in processes) == 1
            for name in (b'Z03', b'control_engine', b'weston')) and all(
                row[0][4] == '/usr/bin/' + row[0][3].decode('ascii') for row in processes
                if row[0][3] in (b'Z03', b'control_engine', b'weston'))
        if not component.result['stock_hashes_match'] or not component.result['stock_processes_match']:
            runner.fail('stock_baseline')
        component.preflight(); component.stage(); component.load_owner()
        facts = component.trial_start_facts
        flags['receive_ready'] = (type(facts) is dict and facts['available'] is True and
                                  facts['reason'] == 'ready' and facts['claim_count'] == 0)
        if not flags['receive_ready']:
            reason = 'receive_refused'
        else:
            component.check()
            owner = component.owner
            flags['start_called'] = True
            owner.service.State.action(owner.state, {'action': 'discover_start'})
            flags['start_returned'] = True
            started = time.monotonic()
            observe_until = min(component.until, started + OBSERVE_SECONDS)
            reason = observe_window(component, started, observe_until, rows, flags)
    except BaseException as error:
        component.first_error = error
        component.failures.append(error)
        reason = 'operation_unknown'
    finally:
        if flags['start_called'] and component.owner is not None:
            flags['stop_called'] = True
            try:
                owner = component.owner
                action = 'cancel' if flags['peer_activity_seen'] else 'discover_stop'
                owner.service.State.action(owner.state, {'action': action})
                flags['stop_returned'] = True
            except BaseException as error:
                component.failures.append(error)
        # This is the original finalizer/used-network path, including real
        # Parent/F cleanup if a phone races our observation. No zero shortcut.
        component.finish_owner()
        try:
            component.after = component.snapshot()
            component.result['after_baseline_observed'] = True
            component.result['baseline_unchanged'] = (
                component.before is not None and component.before == component.after)
            if not component.result['baseline_unchanged']:
                runner.fail('baseline_changed')
        except BaseException as error:
            component.failures.append(error)
        for row in reversed(component.rows):
            try:
                component.close_fd(row)
            except BaseException as error:
                component.failures.append(error)
        component.result['runner_opened_fd_count'] = sum(type(row['fd']) is int for row in component.rows)
        component.result['runner_closed_fd_count'] = sum(
            type(row['fd']) is int and row['closed'] and not row['unknown'] for row in component.rows)
        component.result['runner_fds_closed'] = all(row['closed'] and not row['unknown'] for row in component.rows)
        component.result['client_socket_count'] = len(component.clients)
        component.result['client_sockets_closed'] = all(row['closed'] and not row['unknown'] for row in component.clients)
        component.result['resource_pending'] = (
            not component.result['runner_fds_closed'] or not component.result['client_sockets_closed'] or
            component.owner is not None and not component.result['owner_resources_closed'] or
            component.loader is not None and (getattr(component.loader, 'pending', True) or
                type(getattr(component.loader, 'rows', None)) is not list or
                any(row['unknown'] or not row['closed'] for row in getattr(component.loader, 'rows', ()))))
        component.result['staging_pending'] = bool(component.creations and not component.result['stage_verified'])
        try:
            end_inventory = terminal(component)
        except BaseException as error:
            component.failures.append(error)
    if end_inventory is not None and (end_inventory['bridge_started'] or end_inventory['handoff_received']):
        flags['late_peer_activity_seen'] = not flags['peer_activity_seen']
        reason = 'peer_activity_cancelled'
    flags['resource_pending'] = bool(component.result['resource_pending'] or component.result['staging_pending'] or
                                     flags['start_called'] and end_inventory is None)
    flags['closure_verified'] = (component.result['owner_resources_closed'] is True and
                                 not flags['resource_pending'])
    flags['baseline_verified'] = component.result['baseline_unchanged'] is True
    complete = (reason == 'advertising_observed' and not component.failures and
                flags['start_returned'] and flags['stop_returned'] and flags['closure_verified'] and
                end_inventory is not None and end_inventory['helper_closed'] and
                end_inventory['network_zero_known'] and not end_inventory['bridge_started'] and
                all(component.result[key] is True for key in COMMON + SERVICE))
    # Raw old component remains complete=False: its closed-policy run() was not
    # called or falsified. This new smoke has an explicitly different result.
    return dict(scope='receive-advertise-cancel-only-v1', complete=bool(complete), reason=reason,
                flags=flags, observations=tuple(rows), terminal=end_inventory,
                trials=dict(start=component.trial_start_facts, end=component.trial_end_facts),
                component=component.result)
