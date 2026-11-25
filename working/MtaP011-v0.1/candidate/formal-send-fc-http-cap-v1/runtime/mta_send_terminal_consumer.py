"""Consume the original GO terminal ledgers as DATA, never a restore grant.

The actual State worker must retain its original Bridge FinishReport and the
same-worker TerminalParent constructor/collect/close tickets first. This module
does no IO, clock read, Proc observation, decoding of a replacement packet,
Parent close/reaping or RF action. The existing State96 pure identity checker
is reused as its canonical function, not a caller callback. Its original
Parent._closed_facts is NOT called here: that method observes io.pid().

Even accepted DATA leaves native_restore_verified, restoration_verified,
independent_restore_verified and production_admitted False. F93's GOFINISH was
captured before inherited channel close; the actual F reap/EOF and all parent
FD ledgers below therefore remain separate requirements. A later independent
restoration issuer must consume actual original observations, not this DATA.
Default main performs no observation and no sender admission.
Python 3.5 compatible; no injectable IO, path, factory, source flag or clock.
"""
import hashlib
import errno
import sys
import threading
import types


SCHEMA = 'p011-formal-send-terminal-consumption-v1'
ROOT = '/tmp/p011-mta-formal-send-filecenter-httpcp-v1/runtime'
MAX_ROWS = 10
MAX_ABSENCE = 3
_ISSUER = object()
_ATTEMPTS = []
_FALSE_FIELDS = ('rf_requested', 'native_restore_verified',
                 'restoration_verified', 'independent_restore_verified',
                 'production_admitted')


class TerminalConsumptionError(ValueError):
    pass


def _fail(code):
    raise TerminalConsumptionError(code) from None


class TerminalConsumptionData(object):
    """Immutable retained original references; DATA acceptance only."""
    __slots__ = ('schema', 'state', 'operation', 'bridge', 'parent', 'finish',
                 'terminal', 'originals', 'f_exit_code', 'source_count',
                 'rf_requested', 'native_restore_verified',
                 'restoration_verified', 'independent_restore_verified',
                 'production_admitted')

    def __init__(self, refs, f_exit_code, _issuer=None):
        if _issuer is not _ISSUER or type(refs) is not tuple or len(refs) != 9:
            _fail('terminal_consumer_issuer')
        values = (('schema', SCHEMA), ('state', refs[0]),
                  ('operation', refs[1]), ('bridge', refs[2]),
                  ('parent', refs[3]), ('finish', refs[4]),
                  ('terminal', refs[5]), ('originals', refs),
                  ('f_exit_code', f_exit_code), ('source_count', 38))
        for name, value in values:
            object.__setattr__(self, name, value)
        for name in _FALSE_FIELDS:
            object.__setattr__(self, name, False)

    def __setattr__(self, *unused):
        raise AttributeError('immutable terminal consumption DATA')

    def __delattr__(self, *unused):
        raise AttributeError('immutable terminal consumption DATA')

    def __repr__(self):
        return '<original terminal ledgers consumed; restoration unissued>'


def consume_terminal_data(state, operation):
    """One original State/Bridge/Parent DATA consumption; no success flag."""
    module = sys.modules.get('mta_service')
    own = sys.modules.get('mta_send_terminal_consumer')
    if (type(module) is not types.ModuleType or
            module.__file__ != ROOT + '/mta_service.py' or
            type(own) is not types.ModuleType or own.__dict__ is not globals() or
            own.__file__ != ROOT + '/mta_send_terminal_consumer.py' or
            own.consume_terminal_data is not consume_terminal_data or
            own.TerminalConsumptionData is not TerminalConsumptionData or
            type(state) is not module.State or
            type(operation) is not module.Operation):
        _fail('terminal_consumer_source')
    if len(_ATTEMPTS) >= 1:
        _fail('terminal_consumer_already_attempted')
    ticket = dict(state=state, operation=operation, called=True, returned=None,
                  ended=False, failure=None, unknown=True)
    _ATTEMPTS.append(ticket)  # Retain before any lookup/late refusal.
    try:
        worker = threading.current_thread()
        if (operation is not state.operation or operation.kind != 'go_send' or
                operation.session is not state.session or
                worker is not operation.go_worker or
                worker is not operation.session._worker or
                operation.go_until is not operation.session._task_deadline or
                operation.epoch != state.native_epoch):
            _fail('terminal_consumer_original_worker')
        names = ('_go_terminal_closed', '_go_terminal_source_current', '_go_bridge')
        functions = tuple(getattr(module.State, name, None) for name in names)
        if any(type(value) is not types.FunctionType or
               value.__globals__ is not module.__dict__ for value in functions):
            _fail('terminal_consumer_state_definitions')
        # State's retained original identity/close-ledger checker is pure.
        # Do not call terminal Parent._closed_facts/_context or a status flag.
        if functions[0](state, operation) is not True:
            _fail('terminal_consumer_parent_pending')
        source = functions[1](state, operation)
        bridge_type, bridge = functions[2](state, operation)
        facts = operation.go_terminal_facts
        if (type(facts) is not tuple or len(facts) != 9 or facts[0] is not source or
                facts[1] is not bridge or facts[8] is not True or
                operation.go_terminal_error is not None):
            _fail('terminal_consumer_facts')
        finish_refs, args, snapshots, row, parent_refs, rows = facts[2:8]
        finish, parent, data = finish_refs[0], parent_refs[0], operation.go_terminal_result
        if (type(finish) is not source[6] or
                source[3][5](bridge) is not finish or
                type(data) is not parent.packet_functions_original[4] or
                parent.result is not data or parent.report is not data or
                parent.result_original is not data or row['collect_return'] is not data or
                parent.reader is not parent.reader_original or parent.reader.value is not data or
                parent.reader.ended is not True or parent.reader.failure is not None or
                parent.failure is not None or parent.ended is not True or
                parent.close_attempted is not True or parent.closed is not True or
                parent.unknown is not False or len(rows) != MAX_ROWS or
                parent._request_complete.__func__.__globals__ is not source[1]):
            _fail('terminal_consumer_actual_return')
        # The actual terminal producer must have delivered its whole bounded
        # request and then once-closed the original stdin. Preserve the saved
        # EBADF proof; do not call _request_complete/_input_closed (context IO).
        written, inp, closed = parent.write_ticket, parent.input_row, parent.input_close_ticket
        if (written is not parent.write_ticket_original or inp is not parent.input_row_original or
                closed is not parent.input_close_ticket_original or
                parent.request_raw is not parent.request_raw_original or
                type(parent.request_raw) is not bytes or written['attempted'] is not True or
                written['completed'] is not True or written['unknown'] is not False or
                type(written['offset']) is not int or written['offset'] != len(parent.request_raw) or
                inp['bytes'] != written['offset'] or written['close_ticket'] is not closed or
                type(closed) is not tuple or len(closed) != 8 or closed[0] is not parent.process or
                closed[1] is not parent.process_pid or closed[2] is not inp or
                closed[3] is not inp['raw_original'] or closed[4] is not inp['fd_original'] or
                closed[5] is not inp['metadata_original'] or closed[6] is not None or
                closed[6] is not inp['close_return'] or closed[7] is not inp['close_error'] or
                type(closed[7].errno) is not int or closed[7].errno != errno.EBADF or
                inp['closed'] is not True or inp['unknown'] is not False or
                inp['close_failure'] is not None or inp['raw_original'].closed is not True):
            _fail('terminal_consumer_request_close')
        # No freshly decoded copy, reconstructed Actor or ProcGeneration.
        if (data.source_count != 38 or data.source_manifest_sha256 !=
                '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60' or
                data.snapshot_round_count != 2 or
                any(getattr(data, name, None) is not False for name in _FALSE_FIELDS) or
                data.private_finish_ascii() != finish.raw or
                hashlib.sha256(finish.raw).hexdigest() != data.finish_sha256 or
                data.launch_binding != snapshots[0] or
                data.cleanup_limits != snapshots[1] or
                parent.request_data is not parent.request_data_original or
                parent.request_data.finish_sha256 != data.finish_sha256 or
                parent.request_data.launch_binding != data.launch_binding or
                parent.request_data.cleanup_limits != data.cleanup_limits or
                data.binding != parent.binding_original or
                type(data.active_until) is not float or data.active_until != parent.active_until or
                type(data.cleanup_until) is not float or data.cleanup_until != parent.cleanup_until):
            _fail('terminal_consumer_bound_data')
        # Canonical numeric copies in a packet need equality, never borrowed
        # object identity or authority. Constructor caps retain original refs.
        if (args[3] is not operation.go_until or
                args[4] is not state._service_until_original or
                args[7]['go_cleanup_until'] is not operation.go_cleanup_until or
                args[7]['service_cleanup_until'] is not state._service_cleanup_until_original or
                args[8] is not finish.data['cleanup_until'] or
                min(parent.cleanup_until, args[3] + 60.0, args[4] + 60.0,
                    args[7]['go_cleanup_until'], args[7]['service_cleanup_until'], args[8])
                    != parent.cleanup_until):
            _fail('terminal_consumer_caps')
        reap = finish.reap
        if (bridge_type is not source[5] or bridge.closed is not True or
                bridge.close_called is not True or bridge.process_unknown is not False or
                bridge.process_reaped is not True or type(reap) is not tuple or len(reap) != 3 or
                reap is not bridge._finish_reap_v86 or reap[0] is not bridge._process_original or
                reap[0] is not bridge.process or reap[1] != bridge._process_pid or
                type(reap[2]) is not int or not -(1 << 31) <= reap[2] < (1 << 31) or
                reap[2] is not bridge.returncode):
            _fail('terminal_consumer_f_reap')
        for value, eof in ((bridge.output, finish.stdout_eof),
                           (bridge.error_pipe, finish.stderr_eof)):
            if (type(eof) is not tuple or len(eof) != 5 or eof[0] is not value or
                    eof[1] is not value.fd or eof[2] is not value.value or
                    eof[3] is not value.metadata or eof[4] != b'' or
                    value.closed is not True or value.unknown is not False):
                _fail('terminal_consumer_f_eof')
        if any(value.closed is not True or value.unknown is not False for value in bridge.rows):
            _fail('terminal_consumer_bridge_inventory')
        absence = data.absence_facts
        if (type(absence) is not tuple or not 1 <= len(absence) <= MAX_ABSENCE or
                absence[0][:3] != ('f', finish.data['f_actor'][0], finish.data['f_actor'][1]) or
                any(type(item) is not tuple or len(item) != 6 or item[3] != 2 or
                    item[4] != item[5] for item in absence)):
            _fail('terminal_consumer_absence_data')
        # These absence rows remain DATA from the independently authenticated
        # observer. They are not materialized as new ProcObservation objects.
        refs = (state, operation, bridge, parent, finish, data,
                source, facts, functions)
        result = TerminalConsumptionData(refs, reap[2], _ISSUER)
        ticket['returned'] = result
        ticket['unknown'] = False
        return result
    except BaseException as error:
        ticket['failure'] = error
        raise
    finally:
        ticket['ended'] = True


def main():
    print('SOURCE_SEND_TERMINAL consumer=false restoration=false admission=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
