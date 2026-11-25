"""Explicit fixed-program bootstrap; imports/default main never stage.

Only the three original pinned programs are executable. Standard input belongs
to their original fixed wire reader, not to a source loader or a command API.
One original 180-second absolute outer period covers the unchanged inner120.
An unknown original stage inventory cannot be hidden by cancelling that timer.
"""
import base64
import errno
import hashlib
import math
import os
import signal
import sys
import threading
import time
import types
import zlib
import formal_send_stage_bootstrap_programs as programs

DATA_PIN = (69849, 'f2c1e165a4e4394365d30ffac9d7fc28d3ab03f4573cbbfba5ec98424ebf93c1')
STAGE_PIN = (37382, 'cdb73ecb883ee72a3cb8e45726987b3da2fc7d92fe1cb8c73a0b2de82f743806')
PROGRAM_PINS = (
    ('sender', 23954, 'c5171604bbc3e58ee73a317d3d6e76e7338d7140cbed610322aff7cfc87cd36f'),
    ('observer', 25816, 'a650fe89312d9a3cad60a8a7802f4d88218813183d7547b1721383af5589d953'),
    ('ordinary', 25230, 'a79ef9f3be2f50fb74e9e260a08cdb2f98d7a028aa2f485763baee28990c4bb7'),
)
WIRE_PINS = (
    ('sender', 1218562, '7658efbe12a20b7fecb1302e90659cf64cab5157fb6268cb2cbd126a9a718ed0'),
    ('observer', 475365, '569af62782d444ff2be330000d7f0f85ce1c5b30698e767ba6bef3d7797aabb7'),
    ('ordinary', 468929, '1a92780f8673a8dd52cc51a240e882a3208559eee518ea628e7f38235c53aaec'),
)
MAX_PROGRAM = 2097152
MAX_WIRE = MAX_RAW = 4194304
OUTER_SECONDS = 180.0
INNER_SECONDS = 120.0
DATA_MODULE = 'formal_send_stage_bootstrap_programs'
DATA_FILE = '<formal-send-stage-bootstrap-programs-v1>'
_DATA_ORIGINAL = programs
_DATA_NAMESPACE_ORIGINAL = programs.__dict__
_DATA_TABLE_ORIGINAL = programs.PROGRAM_ROWS
_DATA_SOURCE_ORIGINAL = getattr(programs, '_fixed_source_raw', None)
_RETAINED = None


class BootstrapError(ValueError):
    def __init__(self, code):
        ValueError.__init__(self, code)
        self.code = code


def need(value, code):
    if not value:
        raise BootstrapError(code)


def program_source(profile):
    need(type(profile) is str and profile in ('sender', 'observer', 'ordinary'), 'profile')
    need(programs is _DATA_ORIGINAL and type(programs) is types.ModuleType and
         programs.__dict__ is _DATA_NAMESPACE_ORIGINAL and
         sys.modules.get(DATA_MODULE) is programs and programs.__file__ == DATA_FILE and
         programs.PROGRAM_ROWS is _DATA_TABLE_ORIGINAL and type(_DATA_TABLE_ORIGINAL) is tuple and
         getattr(programs, '_fixed_source_raw', None) is _DATA_SOURCE_ORIGINAL and
         type(_DATA_SOURCE_ORIGINAL) is bytes and len(_DATA_SOURCE_ORIGINAL) == DATA_PIN[0] and
         hashlib.sha256(_DATA_SOURCE_ORIGINAL).hexdigest() == DATA_PIN[1], 'data_original')
    need(len(_DATA_TABLE_ORIGINAL) == 3 and
         tuple(row[:3] for row in _DATA_TABLE_ORIGINAL) == PROGRAM_PINS and
         all(type(row) is tuple and len(row) == 4 and type(row[3]) is str for row in _DATA_TABLE_ORIGINAL),
         'data_table')
    selected = [row for row in _DATA_TABLE_ORIGINAL if row[0] == profile]
    need(len(selected) == 1, 'profile')
    row = selected[0]
    encoded = row[3].encode('ascii')
    decoder = zlib.decompressobj()
    raw = decoder.decompress(base64.b64decode(encoded, validate=True), row[1] + 1)
    need(len(raw) == row[1] <= MAX_PROGRAM and decoder.eof and not decoder.unused_data and
         not decoder.unconsumed_tail and hashlib.sha256(raw).hexdigest() == row[2] and
         all(len(line) <= 256 for line in raw.splitlines()), 'program_pin')
    raw.decode('ascii')
    return row, raw


def original_stage_closed(ticket):
    """Actual retained stage inventory plus original descriptor EBADF readback.

    No close/retry/restore/clock is issued here. A pure pre-exec failure is the
    sole known-zero path; a partial program or constructor is not adopted.
    """
    if ticket['exec_called'] is False:
        return True
    namespace = ticket['namespace']
    if (type(namespace) is not dict or namespace is not ticket['namespace_original'] or
            namespace.get('PROFILE') != ticket['profile'] or namespace.get('STAGE_PIN') != STAGE_PIN or
            namespace.get('_constructor_complete') is not True):
        return False
    module = namespace.get('_module')
    original = namespace.get('_RETAINED')
    source = namespace.get('source')
    if (type(module) is not types.ModuleType or module.__file__ != '<fixed-stdin-stage>' or
            type(source) is not bytes or len(source) != STAGE_PIN[0] or
            hashlib.sha256(source).hexdigest() != STAGE_PIN[1] or
            type(original) is not module.FixedStage or
            module.FixedStage.__init__.__globals__ is not module.__dict__):
        return False
    ticket['stage_module'], ticket['stage'], ticket['stage_source'] = module, original, source
    if (original.worker is not ticket['worker'] or original.pid != ticket['pid'] or
            original.profile != ticket['profile'] or original.close_called is not True or
            original.closed is not True or original.rows is not original._rows_original or
            type(original._rows_original) is not list or original.edges is not original._edges_original or
            original.creations is not original._creations_original or
            type(original._creations_original) is not list or
            any(type(row) is not dict or row.get('unknown') is not False for row in original._creations_original)):
        return False
    result = namespace.get('_result')
    if (type(result) is not dict or result.get('resource_pending') is not False or
            any(result.get(name) is not False for name in
                ('boot', 'owner', 'helper', 'receive', 'send', 'rf', 'restoration', 'phone'))):
        return False
    for row in original._rows_original:
        if type(row) is not dict or row.get('unknown') is not False or row.get('closed') is not True:
            return False
        if row.get('no_fd') is True:
            if row.get('returned') is not False or row.get('fd') is not None:
                return False
            continue
        if (row.get('returned') is not True or type(row.get('fd')) is not int or
                row.get('fd') is not row.get('original_fd') or row.get('close_called') is not True or
                row.get('close_return') is not None or row.get('close_error') is not None or
                row.get('ebadf') is not True):
            return False
        try:
            os.fstat(row['original_fd'])
        except OSError as closed_error:
            if closed_error.errno != errno.EBADF:
                return False
        else:
            return False
    return True


def public_result(ticket):
    namespace = ticket['namespace']
    original = namespace.get('_result') if type(namespace) is dict else None
    timer_closed = (not ticket['timer_called'] or ticket['timer_returned'] and
                    ticket['timer_released'] and not ticket['timer_unknown'])
    return dict(profile=ticket['profile'], program_verified=ticket['source_verified'],
        program_exec_called=ticket['exec_called'], program_returned=ticket['exec_returned'],
        original_stage_complete=type(original) is dict and original.get('stage_complete') is True,
        original_stage_resources_closed=ticket['stage_closed'],
        resource_pending=not ticket['stage_closed'] or not timer_closed,
        outer_timer_installed=ticket['timer_returned'], outer_timer_released=ticket['timer_released'],
        outer_timer_unknown=ticket['timer_unknown'], inner_seconds=120, outer_seconds=180,
        payload_framed_end_verified=type(namespace) is dict and namespace.get('_payload_framed_end_verified') is True,
        physical_stdin_eof_verified=False, error_kind=ticket['error_kind'])


def run_fixed(profile):
    """Explicit trusted one-batch call. No source/path/deadline input exists."""
    global _RETAINED
    need(_RETAINED is None, 'once')
    namespace = dict(__name__='formal_send_stage_fixed_program', __file__='<fixed-original-stage-program>')
    ticket = dict(profile=profile, namespace=namespace, namespace_original=namespace,
        source=None, source_row=None, source_verified=False, exec_called=False, exec_returned=False,
        worker=threading.current_thread(), pid=os.getpid(), started=None, original_until=None,
        original_handler=None, original_timer=None, timer_called=False, timer_returned=False,
        timer_return=None, timer_unknown=False, timer_release_called=False, timer_released=False,
        timer_release_return=None, stage_module=None, stage=None, stage_source=None, stage_closed=False,
        first_error=None, exec_error=None, errors=[], error_kind=None)
    _RETAINED = ticket
    try:
        need(type(profile) is str and profile in ('sender', 'observer', 'ordinary'), 'profile')
        need(threading.current_thread() is threading.main_thread(), 'worker')
        ticket['started'] = time.monotonic()
        need(type(ticket['started']) is float and math.isfinite(ticket['started']) and
             0 <= ticket['started'] < 1e12, 'clock')
        ticket['original_until'] = ticket['started'] + OUTER_SECONDS
        ticket['original_handler'] = signal.getsignal(signal.SIGALRM)
        ticket['original_timer'] = signal.getitimer(signal.ITIMER_REAL)
        need(ticket['original_handler'] == signal.SIG_DFL and
             ticket['original_timer'] == (0.0, 0.0), 'timer_busy')
        remaining = ticket['original_until'] - time.monotonic()
        need(math.isfinite(remaining) and INNER_SECONDS < remaining <= OUTER_SECONDS, 'deadline')
        ticket['timer_called'] = ticket['timer_unknown'] = True
        ticket['timer_return'] = signal.setitimer(signal.ITIMER_REAL, remaining, 0.0)
        need(ticket['timer_return'] == (0.0, 0.0), 'timer_unknown')
        ticket['timer_returned'], ticket['timer_unknown'] = True, False
        row, source = program_source(profile)
        ticket['source_row'], ticket['source'], ticket['source_verified'] = row, source, True
        remaining = ticket['original_until'] - time.monotonic()
        need(math.isfinite(remaining) and INNER_SECONDS < remaining <= OUTER_SECONDS and
             signal.getsignal(signal.SIGALRM) == signal.SIG_DFL, 'deadline')
        ticket['exec_called'] = True
        exec(compile(source, '<fixed-original-stage-program>', 'exec'), namespace)
        ticket['exec_returned'] = True
    except BaseException as exec_error:
        ticket['exec_error'] = ticket['first_error'] = exec_error
        ticket['errors'].append(exec_error)
        ticket['error_kind'] = type(exec_error).__name__
    finally:
        try:
            ticket['stage_closed'] = original_stage_closed(ticket) is True
        except BaseException as inventory_error:
            ticket['errors'].append(inventory_error)
            if ticket['first_error'] is None:
                ticket['first_error'] = inventory_error
                ticket['error_kind'] = type(inventory_error).__name__
            ticket['stage_closed'] = False
        # No deadline renewal, extra stage.close or cleanup retry occurs here.
        # Keep a timer with unknown ownership or unresolved original stage IO.
        if ticket['timer_returned'] and not ticket['timer_unknown'] and ticket['stage_closed']:
            try:
                current = signal.getitimer(signal.ITIMER_REAL)
                remaining = ticket['original_until'] - time.monotonic()
                need(signal.getsignal(signal.SIGALRM) == signal.SIG_DFL and
                     type(current) is tuple and len(current) == 2 and current[1] == 0.0 and
                     0 < current[0] <= OUTER_SECONDS and math.isfinite(remaining) and
                     0 < remaining <= OUTER_SECONDS, 'timer_unknown')
                ticket['timer_release_called'] = ticket['timer_unknown'] = True
                ticket['timer_release_return'] = signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
                need(type(ticket['timer_release_return']) is tuple and len(ticket['timer_release_return']) == 2 and
                     0 < ticket['timer_release_return'][0] <= OUTER_SECONDS and
                     ticket['timer_release_return'][1] == 0.0 and
                     signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and
                     signal.getsignal(signal.SIGALRM) == signal.SIG_DFL, 'timer_unknown')
                ticket['timer_released'], ticket['timer_unknown'] = True, False
            except BaseException as timer_error:
                ticket['errors'].append(timer_error)
                if ticket['first_error'] is None:
                    ticket['first_error'] = timer_error
                    ticket['error_kind'] = type(timer_error).__name__
                ticket['timer_unknown'] = True
        elif ticket['timer_called']:
            ticket['timer_unknown'] = True
        print('BOOTSTRAP_RESULT=' + repr(public_result(ticket)))
    if ticket['exec_error'] is not None:
        raise ticket['exec_error']
    if ticket['first_error'] is not None:
        raise ticket['first_error']
    return ticket


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    return 0 if not args else 2


if __name__ == '__main__':
    raise SystemExit(main())
