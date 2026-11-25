"""Finite exception/terminal DATA around the unchanged original phone envelope.

No frames, tracebacks, exceptions, locals, payloads or peer identifiers retained.
No callback/admission/cancel/clock/finalizer changes. Default main is SOURCE.
"""
import sys
import threading
import types

MAX_EVENTS = 24
MAX_PROBES = 8
_RETAINED = None
FAILURES = ('existing_trace', 'install_failed', 'hook_changed', 'current_hook_changed',
            'projection_failed', 'source_changed', 'event_overflow', 'event_contended', 'terminal_unknown')
ROLE_NAMES = ('mta_client_connect_handoff', 'mta_protocol', 'mta_service',
              'mta_receive_radio_baseline')
SELECTED = (('mta_client_connect_handoff', None, '_check'),
            ('mta_client_connect_handoff', None, 'capture'),
            ('mta_protocol', None, 'decode_json'),
            ('mta_protocol', None, '_base64'),
            ('mta_protocol', None, '_integer'),
            ('mta_protocol', None, 'validate_task_id'),
            ('mta_protocol', 'P2pInfo', '__init__'),
            ('mta_protocol', 'P2pInfo', 'from_dict'))
RADIO_CODES = ('radio_schema', 'radio_unknown', 'radio_fields', 'radio_inconsistent',
               'radio_instances', 'radio_peers')


def selected_source(frame, modules):
    """Exact live code+namespace only; never reads or retains frame locals."""
    for role, cls, name in SELECTED:
        module = modules.get(role)
        if type(module) is not types.ModuleType or frame.f_globals is not module.__dict__:
            continue
        container = getattr(module, cls, None) if cls else (
            getattr(module, 'ReceiveConnectHandoff', None)
            if role == 'mta_client_connect_handoff' else module)
        function = getattr(container, name, None)
        function = getattr(function, '__func__', function)
        if (type(function) is types.FunctionType and function.__globals__ is module.__dict__
                and function.__code__ is frame.f_code):
            return (role, (cls + '.' if cls else '') + name)
    return None


def finite_error(error, modules):
    """No exception text/args, errno, traceback or object in the returned DATA."""
    handoff = modules.get('mta_client_connect_handoff')
    protocol = modules.get('mta_protocol')
    radio = modules.get('mta_receive_radio_baseline')
    code = None
    if handoff is not None and type(error) is getattr(handoff, 'HandoffError', None):
        kind = 'HandoffError'
        value = getattr(error, 'code', None)
        if type(value) is str and value in handoff._CODES:
            code = value
    elif protocol is not None and type(error) is getattr(protocol, 'ProtocolError', None):
        kind = 'ProtocolError'
    elif radio is not None and type(error) is getattr(radio, 'RadioObservationError', None):
        kind = 'RadioObservationError'
        value = getattr(error, 'code', None)
        if type(value) is str and value in RADIO_CODES:
            code = value
    else:
        names = {ValueError: 'ValueError', TypeError: 'TypeError', UnicodeError: 'UnicodeError',
                 UnicodeDecodeError: 'UnicodeDecodeError', UnicodeEncodeError: 'UnicodeEncodeError',
                 RuntimeError: 'RuntimeError', OverflowError: 'OverflowError'}
        kind = names.get(type(error), 'OtherError')
    return dict(kind=kind, code=code)


class TraceOwner(object):
    def __init__(self, phone):
        self.phone = phone
        self.hook = self.dispatch
        self.modules = None
        self.installed = self.restored = self.accepting = False
        self.unknown = self.overflow = False
        self.events, self.failures = [], []
        self.event_lock = threading.Lock()
        self.terminal = None

    def unknown_failure(self, code):
        self.unknown = True
        if code in FAILURES and code not in self.failures:
            self.failures.append(code)

    def original_modules(self):
        component = self.phone._RETAINED
        if component is None or component.owner is None:
            return None
        owner, loader = component.owner, component.loader
        if loader is None or owner.loader is not loader or type(loader.modules) is not dict:
            self.unknown_failure('source_changed')
            return None
        selected = {}
        for role in ROLE_NAMES:
            module = loader.modules.get(role)
            if type(module) is not types.ModuleType or sys.modules.get(role) is not module:
                self.unknown_failure('source_changed')
                return None
            selected[role] = module
        if owner.service is not selected['mta_service']:
            self.unknown_failure('source_changed')
            return None
        if self.modules is None:
            self.modules = selected
        elif any(self.modules[name] is not selected[name] for name in ROLE_NAMES):
            self.unknown_failure('source_changed')
            return None
        return self.modules

    def dispatch(self, frame, event, argument):
        # Trace failures must not propagate into the original application.
        # The original exception tuple/frame is used only during this callback.
        try:
            if not self.accepting:
                if sys.gettrace() is self.hook:
                    sys.settrace(None)
                elif sys.gettrace() is not None:
                    self.unknown_failure('current_hook_changed')
                return None
            # Unrelated thread frames receive no local trace and require no
            # partially initialized Owner inspection.
            if frame.f_globals.get('__name__') not in ('mta_client_connect_handoff', 'mta_protocol'):
                return None
            modules = self.original_modules()
            source = selected_source(frame, modules) if modules is not None else None
            if source is None:
                return None
            if event == 'exception':
                if not self.event_lock.acquire(False):
                    self.unknown_failure('event_contended')
                    return self.hook
                try:
                    if len(self.events) >= MAX_EVENTS:
                        self.overflow = True
                        self.unknown_failure('event_overflow')
                    else:
                        projected = finite_error(argument[1], modules)
                        projected.update(module=source[0], function=source[1], line=frame.f_lineno)
                        self.events.append(projected)
                finally:
                    self.event_lock.release()
            return self.hook
        except BaseException:
            self.unknown_failure('projection_failed')
            return None

    def install(self):
        if sys.gettrace() is not None or getattr(threading, '_trace_hook', object()) is not None:
            self.unknown_failure('existing_trace')
            raise ValueError('existing_trace')
        try:
            threading.settrace(self.hook)
            self.installed = getattr(threading, '_trace_hook', None) is self.hook
            if not self.installed:
                raise ValueError('install_failed')
            self.accepting = True
        except BaseException:
            self.unknown_failure('install_failed')
            raise

    def close_trace(self):
        self.accepting = False
        if self.installed:
            if getattr(threading, '_trace_hook', object()) is self.hook:
                try:
                    threading.settrace(None)
                except BaseException:
                    self.unknown_failure('install_failed')
            else:
                self.unknown_failure('hook_changed')
            self.restored = getattr(threading, '_trace_hook', object()) is None
            if not self.restored:
                self.unknown_failure('hook_changed')
        if sys.gettrace() is not None:
            self.unknown_failure('current_hook_changed')

    def public(self):
        return dict(schema='receive-handoff-trace-v1', thread_trace_installed=self.installed,
                    thread_trace_hook_restored=self.restored, trace_unknown=self.unknown,
                    overflow_unknown=self.overflow, failure_codes=tuple(sorted(set(self.failures))),
                    events=tuple(dict(row) for row in self.events), terminal=self.terminal)


def actor_projection(actor, state, service, parsed):
    """Retained provenance/closed fields only; no poll, read, reap or close."""
    if type(actor) is not dict:
        return dict(source=False, actors_closed=False, failure=None)
    process = actor.get('process')
    source = (actor.get('creator') is service._CAPABILITY_CREATOR and
        actor.get('creator') is actor.get('_creator_original') and
        actor.get('actors') is state.probe_actors and
        any(actor is row for row in state.probe_actors) and
        actor.get('process') is actor.get('_process_original') and
        actor.get('parsed') is parsed and actor.get('parsed') is actor.get('_parsed_original') and
        actor.get('returned') is parsed and actor.get('returned') is actor.get('_returned_original'))
    closed = (actor.get('closed') is True and actor.get('spawn_pending') is False and
        actor.get('spawn_unknown') is False and type(actor.get('returncode')) is int and
        process is not None and process.returncode == actor['returncode'] and
        actor.get('stdout') is getattr(process, 'stdout', None) and
        actor.get('stderr') is getattr(process, 'stderr', None) and
        getattr(actor.get('stdout'), 'closed', None) is True and
        getattr(actor.get('stderr'), 'closed', None) is True)
    return dict(source=bool(source), actors_closed=bool(closed),
                failure=None if actor.get('failure') is None else 'present')


def radio_projection(probe, state, modules):
    service, radio = modules['mta_service'], modules['mta_receive_radio_baseline']
    if type(probe) is not dict:
        raise ValueError('terminal_unknown')
    if type(probe.get('call_returned')) is not bool:
        raise ValueError('terminal_unknown')
    before, after = probe.get('before'), probe.get('current')
    source = (probe.get('creator') is service._CAPABILITY_CREATOR and
              probe.get('actors') is state.probe_actors and
              probe.get('before_actor') is state._bluetooth_probe_actor_original and
              before is state._bluetooth_caps_original)
    before_actor = actor_projection(probe.get('before_actor'), state, service, before)
    after_actor = actor_projection(probe.get('current_actor'), state, service, after)
    normalized = []
    errors = []
    for observed in (before, after):
        try:
            normalized.append(radio.normalize(observed))
            errors.append(None)
        except BaseException as error:
            normalized.append(None)
            errors.append(finite_error(error, modules))
    valid = all(value is not None for value in normalized)
    equal = None
    counts = None
    if valid:
        fields = ('bluez_owner', 'current_settings') + radio._BOOL_FIELDS + radio._BYTE_FIELDS
        equal = dict((key, before[key] == after[key]) for key in fields)
        equal.update(active_instance_ids=normalized[0][5] == normalized[1][5],
                     connected_devices=normalized[0][6] == normalized[1][6])
        counts = dict(connected_before=len(normalized[0][6]), connected_after=len(normalized[1][6]),
                      adv_before=len(normalized[0][5]), adv_after=len(normalized[1][5]))
    return dict(source=bool(source), call_returned=probe.get('call_returned') is True,
                error_present=probe.get('error') is not None,
                before_actor=before_actor, current_actor=after_actor,
                before_normalized=normalized[0] is not None,
                current_normalized=normalized[1] is not None,
                normalization_errors=tuple(errors), field_equal=equal, counts=counts,
                comparison_matches=(normalized[0] == normalized[1]) if valid else None)


def project_terminal(trace):
    component = trace.phone._RETAINED
    modules = trace.original_modules()
    if component is None or modules is None or component.owner.state is None:
        return None
    owner, state = component.owner, component.owner.state
    service = modules['mta_service']
    if state is not owner._state_original or type(state) is not service.State:
        raise ValueError('terminal_unknown')
    if not state.lock.acquire(False):
        raise ValueError('terminal_unknown')
    try:
        op = state.operation
        if op is None:
            return None
        if type(op) is not service.Operation or op.kind != 'receive':
            raise ValueError('terminal_unknown')
        if any(type(value) is not bool for value in (op.actor_unknown, state.radio_restore_pending,
                state.wifi_restore_pending, op.receive_extra_verified)):
            raise ValueError('terminal_unknown')
        handoff = op.client_handoff
        if handoff is not None and type(handoff) is not modules['mta_client_connect_handoff'].ReceiveConnectHandoff:
            raise ValueError('terminal_unknown')
        flags = None
        if handoff is not None:
            flags = {}
            for name in ('_failed', '_cancelled', '_received', '_decrypt_attempted', '_claimed'):
                value = getattr(handoff, name, None)
                if type(value) is not bool:
                    raise ValueError('terminal_unknown')
                flags[name[1:]] = value
        probes = state.radio_restore_probes
        if type(probes) is not list or len(probes) > MAX_PROBES:
            raise ValueError('terminal_unknown')
        return dict(handoff_flags=flags, actor_unknown=op.actor_unknown is True,
                    cancel_requested=op.cancelled.is_set(), input_ready=op.input_ready.is_set(),
                    radio_restore_pending=state.radio_restore_pending is True,
                    wifi_restore_pending=state.wifi_restore_pending is True,
                    receive_extra_verified=op.receive_extra_verified is True,
                    radio_probes=tuple(radio_projection(row, state, modules) for row in probes))
    finally:
        state.lock.release()


def run_fixed(runner, artifacts, phone):
    global _RETAINED
    trace = TraceOwner(phone)
    _RETAINED = trace
    try:
        trace.install()
        return phone.run_fixed(runner, artifacts)
    finally:
        trace.close_trace()
        try:
            trace.terminal = project_terminal(trace)
        except BaseException:
            trace.unknown_failure('terminal_unknown')


def public_result():
    return None if _RETAINED is None else _RETAINED.public()


if __name__ == '__main__':
    print('SOURCE_RECEIVE_HANDOFF_TRACE_V1 no_runtime no_rf')
