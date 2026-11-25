"""Fixed Receive UI-v1; one original 600-second service window.

Derived from formal-ui-startup-v4 ui_session.py: 42259 bytes, SHA256
f84eaa6b7cebf542fa2cedbaf8290d6d3eb0e7c2a8b8943e3d0ad2093ca7ff7d.
The original copied UI/guardian/Owner-close chain remains. The fixed profile
creates one 600-second service cap at construction, with startup deducted.
Individual Session task (300s), Factory preparation (120s), Owner cleanup (60s)
and guardian recovery (+68/+135s) keep their original bounds. Expiry or manual
exit closes the original Owner; a pending finalizer is never signed successful.
Only the fixed runner/assets/session references and an explicit smoke display
exit are adapted from the original interactive receive worker. smoke_only=True
requires the original idle inventory and the real unclaimed/unattached trial;
it exits at min(the original display cap, launched + 20s), not READY + 20s.
This is only a shorter copied-UI display interval: the original 600+60 service,
guardian +68/+135, finalizer and completeness predicate are unchanged.
Smoke idle observations and radio_admission qualification are not physical RF
absence/output, phone success or a restoration receipt.
Unlike the separately preserved V2 closed-policy UI, this trusted fixed entry
requests the original once-owned receive trial. An empty original inventory
may hold an unclaimed ready trial or an explicit refusal. No UI startup code
issues discover_start, scan or send; user action still owns that transition.
Observing a trial/operation is not evidence of RF output, phone reception,
network restoration, elapsed budget or original resource closure.
The monitor is a finite extra artifact, not a Boot/canonical module. Its bytes
are read from the original held runtime directory through FixedSession FDs,
authenticated and closed before private exec/fork/Owner/credentials. No unknown
sys.modules import fallback, alternate path, CLI launcher or old pending edit.
"""
import ctypes
import errno
import hashlib
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import types


# ROOT seals this new immutable runner identity after composition is complete.
# Deliberately invalid until sealed; never inherit the V2 diagnostic pin.
RUNNER_PIN = (79215, '8fc39ae5ab2f4219f4bece327f87ff0bfb0158619386fd00a3bac9b24170139c')
VALIDATOR_PIN = (10447, '570400c728e2ddeb3993d571f27fb941a7833b43db8183c9d0e588997ddef33d')
SESSION = '2c3d526c2d034da16e6c4a61'
ASSETS = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
CANDIDATE = ASSETS + '/Z03.mta-ui-candidate'
CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-receive-ui-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-ui-v1'
STATE_ALIAS = '/tmp/p011-mta-formal-receive-ui-v1'
MONITOR_PIN = ('receive_monitor', 13963,
               'fe2a8bab0db21c45c6fe3d0a4733029492c8617d57ddbc9f296888c8c6837e36')
CONTROL = '/var/volatile/tmp/' + CONTROL_NAME
READY_SECONDS = 10.0
SMOKE_DISPLAY_SECONDS = 20.0
INTERACTIVE_PROFILE = 'receive-interactive-v1'
INTERACTIVE_SECONDS = 600.0
EXIT_MARGIN_SECONDS = 1.0
STARTUP_BOOL_FIELDS = ('startup_readonly_called', 'startup_readonly_verified',
                       'startup_baseline_collected', 'startup_status_verified',
                       'startup_resources_closed')
STARTUP_COUNT_FIELDS = ('startup_status_count', 'startup_proc_reader_count')
TRIAL_BOOL_FIELDS = ('requested', 'available', 'claimed', 'session_attached', 'revoked',
                     'expired', 'startup_verified', 'probe_verified', 'radio_known',
                     'barrier_clear', 'network_spec_verified', 'restoration_verified',
                     'phone_verified')
_RETAINED = None


class UiSessionError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def need(condition, code):
    if not condition:
        raise UiSessionError(code)


def _receive_interactive_window(component):
    """Retain the constructor's single original period; never change a cap.

    The sealed runner creates this fixed profile before Boot/Owner/Gate/State.
    There is no renewal, fallback diagnostic period or supplied duration.
    This tuple is an observation guard, not a radio or closure receipt.
    """
    cap, cleanup = component.until, component.cleanup_until
    need(component.profile == INTERACTIVE_PROFILE and
         component._window_original is component._window_retained and
         component.receive_trial_requested is True and
         component._receive_trial_requested_original is True and
         component.preflight_only is False and
         type(cap) is float and math.isfinite(cap) and 0 < cap < 2 ** 53 and
         type(cleanup) is float and math.isfinite(cleanup) and
         cleanup == cap + 60.0, 'interactive_window_changed')
    period = component._window_original
    need(type(period) is tuple and len(period) == 4 and
         period[0] is component.profile and
         type(period[1]) is float and math.isfinite(period[1]) and
         component.window_started_at is period[1] and
         0 < period[1] < cap and period[2] is cap and period[3] is cleanup and
         cap - period[1] == INTERACTIVE_SECONDS, 'interactive_window_changed')
    return (component, component.profile, period, cap, cleanup, cap - EXIT_MARGIN_SECONDS)


def _receive_interactive_originals(component, window):
    """Pure identity continuity after the real Owner startup; no IO or renewal."""
    need(type(window) is tuple and len(window) == 6 and window[0] is component and
         component.profile is window[1] and
         component._window_original is window[2] and
         component._window_retained is window[2] and
         component.window_started_at is window[2][1] and
         component.until is window[3] and component.cleanup_until is window[4] and
         component.receive_trial_requested is True and
         component._receive_trial_requested_original is True and
         component.preflight_only is False, 'interactive_window_changed')
    cap = window[3]
    owner, loader = component.owner, component.loader
    if owner is None or loader is None:
        return False
    state, gate, directory = owner.state, owner.receive_trial, owner.received_directory
    return (owner.until is cap and owner.original_until is cap and
            loader._original_until is cap and state is owner._state_original and
            gate is owner._receive_trial_original and
            gate.until is cap and gate._until_original is cap and
            state._original_service_until is cap and state._service_until_original is cap and
            directory is owner._received_directory_original and
            directory.absolute_until is cap)


def _receive_interactive_expired(component, window, now):
    """Use the original absolute end, including startup time already consumed.

    A late/expired result requests the original close path. It grants no new
    task time and says nothing about RF, network restore or phone success.
    """
    need(_receive_interactive_originals(component, window), 'interactive_window_changed')
    need(type(now) is float and math.isfinite(now) and
         now >= window[2][1] and now < 2 ** 53, 'interactive_clock_unknown')
    return now >= window[5]


def _receive_ui_display_allowed(component, observe_receive):
    """Observe only the original empty inventory or exact owned receive.

    A ready but unclaimed Gate is not a live radio/transfer actor. The runner's
    original inventory predicate does not turn that state into closed-policy
    admission. The historical monitor remains an observation-only predicate.
    """
    return ((component.original_receive_ui_idle() is True or
             observe_receive(component) is True) and
            component.owner.thread.is_alive() is True)


def _copy_receive_ui_trial(component, facts, initial=False, terminal=False):
    """Project only the retained original Gate, never HTTP/UI status DATA.

    radio_admission means a receive qualification was observed in this bounded
    UI session, not that listening/advertising/transfer physically succeeded.
    Revocation and resource/network restoration remain independent facts.
    """
    need(type(initial) is bool and type(terminal) is bool and
         not (initial and terminal), 'receive_trial_observation')
    owner, loader = component.owner, component.loader
    module = loader.modules.get('mta_receive_trial')
    need(type(module) is types.ModuleType and type(owner.receive_trial) is module.FixedReceiveTrial and
         owner.receive_trial is owner._receive_trial_original and
         owner.state is owner._state_original and owner.receive_trial.state is owner.state,
         'receive_trial_observation')
    observed = module.FixedReceiveTrial.public_facts(owner.receive_trial)
    need(type(observed) is dict and
         set(observed) == set(TRIAL_BOOL_FIELDS) | {'reason', 'claim_count'} and
         all(type(observed[key]) is bool for key in TRIAL_BOOL_FIELDS) and
         type(observed['claim_count']) is int and observed['claim_count'] in (0, 1) and
         observed['claimed'] is (observed['claim_count'] == 1) and
         type(observed['reason']) is str and observed['reason'] in module.REASONS and
         observed['requested'] is True and observed['restoration_verified'] is False and
         observed['phone_verified'] is False, 'receive_trial_observation')
    # Count/attachment can only increase in the exact original single trial.
    need(observed['claim_count'] >= facts['receive_trial_claim_count'] and
         (not facts['receive_trial_session_attached'] or observed['session_attached']),
         'receive_trial_observation')
    facts['receive_trial_claim_count'] = observed['claim_count']
    facts['receive_trial_claimed'] = observed['claimed']
    facts['receive_trial_session_attached'] = observed['session_attached']
    facts['radio_admission'] = (facts['radio_admission'] or observed['available'] or observed['claimed'])
    if initial:
        need(not facts['receive_trial_initial_observed'] and not observed['claimed'] and
             not observed['session_attached'], 'receive_trial_observation')
        facts['receive_trial_initial_observed'] = True
        facts['receive_trial_initial_available'] = observed['available']
        facts['receive_trial_initial_reason'] = observed['reason']
    if terminal:
        facts['receive_trial_terminal_observed'] = True
        facts['receive_trial_terminal_revoked'] = observed['revoked']
        facts['receive_trial_terminal_reason'] = observed['reason']
    return observed


def _read(path, limit):
    with open(path, 'rb') as source:
        raw = source.read(limit + 1)
    need(len(raw) <= limit, 'read_budget')
    return raw


def _boot():
    value = _read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
    need(re.fullmatch(r'[0-9a-f-]{36}', value) is not None, 'boot')
    return value


def _proc(pid):
    need(type(pid) is int and 1 < pid <= 0x7fffffff, 'pid')
    try:
        raw = _read('/proc/%d/stat' % pid, 8192).decode('ascii')
        fields = raw[raw.rindex(')') + 2:].split()
        need(raw[:raw.index('(')] == str(pid) + ' ' and len(fields) >= 20 and
             all(fields[index].isdigit() for index in (1, 3, 6, 17, 19)), 'process_stat')
        row = dict(pid=pid, start=fields[19], parent=int(fields[1]), sid=int(fields[3]),
                   state=fields[0], threads=int(fields[17]), flags=int(fields[6]),
                   exe=None, args=(), comm=raw[raw.index('(') + 1:raw.rindex(')')].encode('ascii'))
        if row['state'] in ('Z', 'X') and row['threads'] == 1:
            return row
        # PF_KTHREAD has no executable; do not count stable kernel tasks as
        # vanished-process races or silently accept a live user task without exe.
        if not row['flags'] & 0x200000:
            row['exe'] = os.readlink('/proc/%d/exe' % pid)
            row['args'] = tuple(os.fsdecode(part) for part in
                                _read('/proc/%d/cmdline' % pid, 16384).split(b'\0') if part)
        again = _read('/proc/%d/stat' % pid, 8192).decode('ascii')
        repeated = again[again.rindex(')') + 2:].split()
        need(len(repeated) >= 20 and repeated[19] == row['start'] and
             int(repeated[6]) & 0x200000 == row['flags'] & 0x200000, 'pid_changed')
        return row
    except OSError as error:
        if type(error.errno) is not int or error.errno not in (errno.ENOENT, errno.ESRCH):
            raise
        try:
            _read('/proc/%d/stat' % pid, 8192)
        except OSError as vanished:
            if type(vanished.errno) is int and vanished.errno in (errno.ENOENT, errno.ESRCH):
                return None
        raise UiSessionError('process_unknown') from None


def _alive(row):
    return row is not None and (row['state'] not in ('Z', 'X') or row['threads'] > 1)


def _refresh(original):
    if original is None:
        return None
    row = _proc(original['pid'])
    if row is None or row['start'] != original['start']:
        return None
    if _alive(row):
        need(row['exe'] == original['exe'], 'process_exec_changed')
    return row


def _signal(original, number, boot):
    need(_boot() == boot, 'boot_changed')
    row = _refresh(original)
    if not _alive(row):
        return False
    need(row['pid'] != os.getpid(), 'self_signal')
    os.kill(row['pid'], number)
    return True


def _terminate(original, boot, candidate=False):
    if original is None:
        return

    def exited_after_signal(until):
        while True:
            try:
                row = _proc(original['pid'])
                if row is not None:
                    need(row['start'] == original['start'], 'pid_changed')
                    if _alive(row):
                        need(row['exe'] == original['exe'], 'process_exec_changed')
                if not _alive(row):
                    return True
            except UiSessionError as error:
                # During exit, exe can be ENOENT while this same task's stat
                # briefly remains. Retry only this exact unknown observation
                # after an actual signal, within its existing wait deadline.
                if error.code != 'process_unknown' or time.monotonic() >= until:
                    raise
                time.sleep(min(.05, max(0.0, until - time.monotonic())))
                continue
            remaining = until - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(.05, remaining))

    # The original PID/start/exe/boot signal gate remains unchanged. Unknown
    # state at that gate is never permission to signal or escalate to KILL.
    if not _signal(original, signal.SIGTERM, boot):
        return
    if exited_after_signal(time.monotonic() + 5.0):
        return
    if candidate:
        need(original['exe'] == CANDIDATE, 'candidate_identity')
        if not _signal(original, signal.SIGKILL, boot):
            return
        if exited_after_signal(time.monotonic() + 3.0):
            return
    raise UiSessionError('process_did_not_exit')


def _scan(names=None, candidate_parent=None):
    output = []
    pids = sorted(int(name) for name in os.listdir('/proc') if name.isdigit())
    need(len(pids) <= 512, 'process_budget')
    races = 0
    for pid in pids:
        if pid <= 1:
            continue
        try:
            if names is not None:
                comm = _read('/proc/%d/comm' % pid, 128).strip()
                if comm not in names:
                    continue
            row = _proc(pid)
            if not _alive(row) or row['flags'] & 0x200000:
                continue
            if names is None:
                if row['exe'] != CANDIDATE:
                    continue
                need(row['exe'] == CANDIDATE and row['parent'] in (candidate_parent, 1) and
                     row['sid'] == row['pid'], 'foreign_candidate')
            output.append(row)
        except OSError as error:
            if type(error.errno) is not int or error.errno not in (errno.ENOENT, errno.ESRCH):
                raise
            races += 1
            need(races <= 32, 'process_race_budget')
    return output


def _hash(path, limit, expected):
    digest = hashlib.sha256()
    def metadata(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    original = metadata(os.lstat(path))
    need(original == expected and stat.S_ISREG(original[2]) and original[3] == 0 and
         original[5] == 1 and 0 < original[6] <= limit, 'stock_file_identity')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(metadata(os.fstat(fd)) == original, 'stock_file_identity')
        count = 0
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                break
            count += len(raw)
            need(count <= limit, 'hash_budget')
            digest.update(raw)
        need(count == original[6] and metadata(os.fstat(fd)) == original == metadata(os.lstat(path)), 'hash_changed')
    finally:
        _child_close(fd, original[:2])
    return digest.hexdigest()


def _pipe_write(fd, line):
    raw = line.encode('ascii')
    need(len(raw) <= 128 and raw.endswith(b'\n'), 'pipe_frame')
    # Frames fit PIPE_BUF and these private pipes carry at most four frames.
    need(os.write(fd, raw) == len(raw), 'pipe_write')


def _pipe_read(fd, pending):
    try:
        raw = os.read(fd, 1024)
    except OSError as error:
        if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return pending, (), False
        raise
    if not raw:
        return pending, (), True
    pending += raw
    need(len(pending) <= 2048, 'pipe_budget')
    pieces = pending.split(b'\n')
    return pieces[-1], tuple(value.decode('ascii') for value in pieces[:-1]), False


def _no_core():
    class Limit(ctypes.Structure):
        _fields_ = [('cur', ctypes.c_ulong), ('max', ctypes.c_ulong)]
    libc = ctypes.CDLL(None, use_errno=True)
    need(libc.setrlimit(4, ctypes.byref(Limit(0, 0))) == 0, 'private_core_limit')


def _child_close(fd, metadata):
    current = os.fstat(fd)
    need((current.st_dev, current.st_ino) == metadata[:2], 'inherited_fd_changed')
    need(os.close(fd) is None, 'inherited_fd_close')
    try:
        os.fstat(fd)
    except OSError as error:
        need(type(error.errno) is int and error.errno == errno.EBADF, 'inherited_fd_close')
        return
    raise UiSessionError('inherited_fd_close')


def _guardian_fd_gate(read_fd, write_fd):
    # Independently opened scanner FD, not an inherited parent OFD.
    scan_fd = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        need(os.lseek(scan_fd, 0, os.SEEK_SET) == 0, 'guardian_fd_offset')
        observed = {int(name) for name in os.listdir(scan_fd) if name.isdigit()}
        expected = {0, 1, 2, read_fd, write_fd, scan_fd}
        need(expected.issubset(observed), 'guardian_inherited_fd')
        for fd in observed - expected:
            # listdir(fd) may expose its short-lived fdopendir duplicate in
            # /proc/self/fd. It must already be EBADF, never an inherited OFD.
            try:
                os.fstat(fd)
            except OSError as error:
                need(type(error.errno) is int and error.errno == errno.EBADF, 'guardian_inherited_fd')
            else:
                raise UiSessionError('guardian_inherited_fd')
        for fd in expected:
            os.fstat(fd)
    finally:
        meta = os.fstat(scan_fd)
        _child_close(scan_fd, (meta.st_dev, meta.st_ino))


def _guardian_error_code(error):
    # Finite source constants only. Never stringify arbitrary exception args,
    # filenames, frame contents, locals or any credential-bearing object.
    allowed = ('boot', 'boot_changed', 'read_budget', 'pid', 'process_stat',
               'process_unknown', 'pid_changed', 'process_exec_changed',
               'self_signal', 'candidate_identity', 'process_did_not_exit',
               'process_budget', 'process_race_budget', 'foreign_candidate',
               'stock_file_identity', 'hash_budget', 'hash_changed',
               'pipe_frame', 'pipe_write', 'pipe_budget', 'guardian_stdio',
               'inherited_fd_changed', 'inherited_fd_close',
               'inherited_fd_unknown', 'inherited_fd_duplicate',
               'guardian_fd_offset', 'guardian_inherited_fd',
               'duplicate_close_frame', 'restore_without_close_report',
               'duplicate_candidate_frame', 'candidate_frame', 'guardian_frame',
               'worker_not_stopped', 'candidate_inventory', 'candidate_remains',
               'launcher_missing', 'stock_pins_changed', 'control_changed',
               'guardian_after_write')
    if type(error) is UiSessionError:
        return error.code if error.code in allowed else 'guardian_validation'
    return 'guardian_io' if type(error) is OSError else 'guardian_exception'


def _guardian(component, read_fd, write_fd, logs, baseline, worker):
    """No Owner/token exists when this fork happens; never signs Owner close."""
    try:
        os.setsid()
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            signal.signal(number, signal.SIG_IGN)
        null_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        need(null_fd > 2, 'guardian_stdio')
        os.dup2(null_fd, 0)
        os.dup2(logs[0]['fd'], 1)
        os.dup2(logs[1]['fd'], 2)
        _child_close(null_fd, (os.fstat(null_fd).st_dev, os.fstat(null_fd).st_ino))
        live = {}
        for row in component.rows:
            if row['fd'] is not None and not row['closed']:
                need(not row['unknown'] and row['metadata'] is not None and row['fd'] > 2, 'inherited_fd_unknown')
                need(row['fd'] not in live, 'inherited_fd_duplicate')
                live[row['fd']] = row['metadata']
        for fd, metadata in live.items():
            if fd not in (read_fd, write_fd):
                _child_close(fd, metadata)
        _guardian_fd_gate(read_fd, write_fd)
        print('GUARD_INHERITED_FDS_CLOSED', flush=True)
        _pipe_write(write_fd, 'ARMED\n')
        pending = b''
        reported = False
        restore = False
        announced = None
        stopped_worker = False
        protocol_failed = False
        recover_at = component.until + 68.0
        end = component.until + 135.0
        while not restore and time.monotonic() < recover_at:
            try:
                pending, frames, eof = _pipe_read(read_fd, pending)
                for frame in frames:
                    if frame == 'OWNER_CLOSED_REPORTED':
                        need(not reported, 'duplicate_close_frame')
                        reported = True
                    elif frame == 'RESTORE':
                        need(reported, 'restore_without_close_report')
                        restore = True
                    elif re.fullmatch(r'CAND [1-9][0-9]{0,9} [0-9]{1,20}', frame):
                        need(announced is None, 'duplicate_candidate_frame')
                        unused, pid, start = frame.split(' ')
                        announced = (int(pid), start)
                        row = _proc(announced[0])
                        # Qt can have exited before its launch frame is read.
                        # Never infer absence from this: inventory below still
                        # re-enumerates the fixed executable/worker ancestry.
                        if row is not None and row['start'] == start and _alive(row):
                            need(row['exe'] == CANDIDATE and row['parent'] == worker['pid'] and
                                 row['sid'] == row['pid'], 'candidate_frame')
                    else:
                        raise UiSessionError('guardian_frame')
                if eof:
                    restore = True
            except BaseException as error:
                # Malformed/missing protocol is not permission to resume the
                # launcher while a live worker can still spawn an application.
                protocol_failed, reported, restore = True, False, False
                print('GUARD_PROTOCOL_FAILED code=' + _guardian_error_code(error), flush=True)
                break
            if not _alive(_refresh(worker)):
                restore = True
            time.sleep(.05)
        if protocol_failed:
            while time.monotonic() < recover_at and _alive(_refresh(worker)):
                time.sleep(.1)
            restore = not _alive(_refresh(worker))
        if not restore:
            _signal(worker, signal.SIGTERM, baseline['boot'])
            wait = time.monotonic() + 3.0
            while _alive(_refresh(worker)) and time.monotonic() < wait:
                if not protocol_failed:
                    try:
                        pending, frames, eof = _pipe_read(read_fd, pending)
                        need(all(frame in ('OWNER_CLOSED_REPORTED', 'RESTORE') for frame in frames), 'guardian_frame')
                        if 'OWNER_CLOSED_REPORTED' in frames:
                            reported = True
                        if 'RESTORE' in frames:
                            need(reported, 'restore_without_close_report')
                            restore = True
                        if eof:
                            restore = True
                        if restore:
                            break
                    except BaseException as error:
                        protocol_failed, reported = True, False
                        print('GUARD_PROTOCOL_FAILED code=' + _guardian_error_code(error), flush=True)
                time.sleep(.05)
        if _alive(_refresh(worker)) and not restore:
            # The original close window has expired. Preserve the unknown
            # Owner instead of killing/resetting it; prevent any late UI spawn.
            _signal(worker, signal.SIGSTOP, baseline['boot'])
            wait = time.monotonic() + 2.0
            while time.monotonic() < wait:
                row = _refresh(worker)
                if not _alive(row) or row['state'] in ('T', 't'):
                    stopped_worker = _alive(row)
                    break
                time.sleep(.05)
            row = _refresh(worker)
            need(not _alive(row) or row['state'] in ('T', 't'), 'worker_not_stopped')
        if not reported:
            print('GUARD_OWNER_UNKNOWN', flush=True)
        if stopped_worker:
            print('GUARD_WORKER_STOPPED_PENDING', flush=True)
        need(_boot() == baseline['boot'], 'boot_changed')
        # Includes Popen-to-CAND message loss; no absent-message absence claim.
        candidates = _scan(candidate_parent=worker['pid'])
        need(len(candidates) <= 1, 'candidate_inventory')
        for row in candidates:
            _terminate(row, baseline['boot'], candidate=True)
        need(not _scan(candidate_parent=worker['pid']), 'candidate_remains')
        parent = _refresh(baseline['launcher'])
        need(_alive(parent), 'launcher_missing')
        _signal(baseline['launcher'], signal.SIGCONT, baseline['boot'])
        names = tuple(row['comm'] for row in baseline['tracked'])
        stable, since, after = None, 0.0, None
        restored = False
        until = min(end, time.monotonic() + 60.0)
        while time.monotonic() < until:
            actual = _scan(names=names)
            z03 = [row for row in actual if row['exe'] == '/usr/bin/Z03' and row['parent'] == parent['pid'] and
                   row['state'] not in ('T', 't', 'D')]
            peers = [row for row in actual if row['exe'] != '/usr/bin/Z03']
            expected = [row for row in baseline['tracked'] if row['exe'] != '/usr/bin/Z03']
            same = len(peers) == len(expected) and all(any(
                value['pid'] == row['pid'] and value['start'] == row['start'] and
                value['parent'] == row['parent'] and value['exe'] == row['exe'] for value in peers) for row in expected)
            if len(z03) == 1 and len(actual) == len(baseline['tracked']) and same:
                key = (z03[0]['pid'], z03[0]['start'])
                if key != stable:
                    stable, since = key, time.monotonic()
                if time.monotonic() - since >= 3.0:
                    # Pins are explicitly retained from the authenticated runner.
                    hashes = tuple((path, _hash(path, 8388608, dict(baseline['stock_metadata'])[path]))
                                   for path, pin in baseline['pins'])
                    need(hashes == baseline['pins'] and _boot() == baseline['boot'], 'stock_pins_changed')
                    after = dict(boot=baseline['boot'], processes=actual, hashes=hashes,
                                 routes=_read('/proc/net/route', 1048576))
                    restored = True
                    break
            else:
                stable = None
            time.sleep(.2)
        # Fresh FD, never a retained parent's anchor/OFD.
        control_fd = os.open(CONTROL, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            meta = os.fstat(control_fd)
            need((meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid) == baseline['control_meta'], 'control_changed')
            fd = os.open('guardian-after.raw', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=control_fd)
            try:
                raw = repr(after).encode('utf-8')
                need(len(raw) <= 1048576 and os.write(fd, raw) == len(raw), 'guardian_after_write')
                os.fsync(fd)
            finally:
                _child_close(fd, (os.fstat(fd).st_dev, os.fstat(fd).st_ino))
        finally:
            _child_close(control_fd, (meta.st_dev, meta.st_ino))
        print('GUARD_STOCK_RESTORED' if restored else 'GUARD_STOCK_FAILED', flush=True)
        try:
            _pipe_write(write_fd, 'RESTORED\n' if restored and not protocol_failed else 'FAILED\n')
        except OSError as error:
            if error.errno not in (errno.EPIPE, errno.EBADF):
                raise
        for fd in (read_fd, write_fd):
            meta = os.fstat(fd)
            _child_close(fd, (meta.st_dev, meta.st_ino))
        os._exit(0 if restored and not protocol_failed else 1)
    except BaseException as error:
        # No exception args, paths, locals or credentials enter raw guardian IO.
        print('GUARD_FAILED_OWNER_UNKNOWN code=' + _guardian_error_code(error), flush=True)
        os._exit(2)


def _load_monitor(component, runner):
    """Authenticate the actual fixed source FD; never a supplied getter/model."""
    need(component.owner is None and component.boot is None and
         threading.active_count() == 1, 'fork_boundary')
    component.anchors_current()
    root = component.roots['state']
    runtime = root['runtime']
    expected = tuple(meta for name, meta in root['files'] if name == MONITOR_PIN[0])
    need(root['present'] is True and len(expected) == 1 and
         runtime is not None and not runtime['closed'] and not runtime['unknown'], 'asset_binding')
    initial = expected[0]
    need(type(initial) is tuple and len(initial) == 9 and
         initial[2:7] == (stat.S_IFREG | 0o400, 0, 0, 1, MONITOR_PIN[1]), 'source_pin')
    row = component.open_fd('receive_monitor.py', os.O_RDONLY | os.O_NONBLOCK,
                            parent=runtime['fd'])
    _RETAINED['monitor_row'] = row
    try:
        need(row['metadata'] == initial and
             runner.metadata(os.stat('receive_monitor.py', dir_fd=runtime['fd'],
                                     follow_symlinks=False)) == initial, 'source_pin')
        parts, count = [], 0
        while count <= MONITOR_PIN[1]:
            component.check()
            block = os.read(row['fd'], min(65536, MONITOR_PIN[1] + 1 - count))
            need(type(block) is bytes, 'source_pin')
            if not block:
                break
            parts.append(block)
            count += len(block)
        raw = b''.join(parts)
        need(count == MONITOR_PIN[1] and raw == component.artifacts[MONITOR_PIN[0]] and
             hashlib.sha256(raw).hexdigest() == MONITOR_PIN[2] and
             runner.metadata(os.fstat(row['fd'])) == initial and
             runner.metadata(os.stat('receive_monitor.py', dir_fd=runtime['fd'],
                                     follow_symlinks=False)) == initial, 'source_pin')
        component.anchors_current()
        _RETAINED['monitor_raw'] = raw
    except BaseException as error:
        # Preserve the actual read/identity failure even if original FD close
        # also fails; neither is replaced by a fabricated source receipt.
        _RETAINED['failures'].append(error)
        raise
    finally:
        need(component.close_fd(row), 'raw_close')
    module = types.ModuleType('fixed_formal_receive_monitor')
    module.__file__ = STATE_ROOT + '/runtime/receive_monitor.py'
    _RETAINED['monitor'] = module
    _RETAINED['monitor_namespace'] = module.__dict__
    exec(raw, module.__dict__)
    creator = module.owned_receive_monitor_allowed
    need(type(creator) is types.FunctionType and creator.__globals__ is module.__dict__, 'source_pin')
    _RETAINED['monitor_creator'] = creator
    return creator


def run_fixed(runner_raw, artifacts, validator_raw, smoke_only=False):
    """HOST-only explicit injection entry; the function runs on the P011."""
    global _RETAINED
    need(type(smoke_only) is bool, 'smoke_profile')
    need(_RETAINED is None and not any(type(name) is str and name.startswith(('mta_', 'p011_'))
                                     for name in sys.modules), 'fresh_worker')
    need(threading.active_count() == 1, 'worker_threads')
    need(type(RUNNER_PIN) is tuple and len(RUNNER_PIN) == 2, 'source_pin')
    for raw, pin in ((runner_raw, RUNNER_PIN), (validator_raw, VALIDATOR_PIN)):
        need(type(raw) is bytes and len(raw) == pin[0] and hashlib.sha256(raw).hexdigest() == pin[1], 'source_pin')
    need(type(artifacts) is tuple, 'artifacts')
    os.umask(0o077)
    sys.dont_write_bytecode = True
    runner = types.ModuleType('fixed_formal_ui_runner')
    runner.__file__ = '<fixed-formal-ui-runner>'
    exec(runner_raw, runner.__dict__)
    need(runner.STATE_ROOT == STATE_ROOT and runner.STATE_ALIAS == STATE_ALIAS and
         runner.MONITOR_PIN == MONITOR_PIN and
         len(artifacts) == len(runner.ROLE_PINS + runner.HELPER_PINS +
                              runner.PRIVATE_PAYLOAD_PINS + (runner.WPA_PIN, runner.MONITOR_PIN)), 'artifacts')
    assets = types.ModuleType('fixed_formal_ui_assets')
    assets.__file__ = '<fixed-formal-ui-assets>'
    exec(validator_raw, assets.__dict__)
    need(assets.SESSION == SESSION and assets.REMOTE == ASSETS, 'assets_identity')
    component = runner.FixedSession(artifacts, False, receive_trial_requested=True,
                                    profile=INTERACTIVE_PROFILE)
    window = _receive_interactive_window(component)
    _RETAINED = dict(component=component, assets=None, ui=None, guardian=None, failures=[], credentials=None,
                     monitor=None, monitor_namespace=None, monitor_creator=None,
                     monitor_row=None, monitor_raw=None, receive_window=window)
    facts = dict(complete=False, ui_ready=False, ui_http_observed=False, owner_close_verified=False,
                 credentials_removed=False, candidate_exited=False, stock_restored=False,
                 guardian_exited=False, worker_fds_closed=False, radio_admission=False,
                 original_ui_exited=False, physical_ui_verified=False,
                 resource_pending=True, reason='not_started')
    facts.update(receive_trial_policy_requested=True, auto_receive_action_issued=False,
                 receive_trial_initial_observed=False, receive_trial_initial_available=False,
                 receive_trial_initial_reason='not_started', receive_trial_claimed=False,
                 receive_trial_claim_count=0, receive_trial_session_attached=False,
                 receive_trial_terminal_observed=False, receive_trial_terminal_revoked=False,
                 receive_trial_terminal_reason='not_started',
                 interactive_window_requested=True, interactive_window_expired=False,
                 interactive_window_bound=False)
    facts.update(smoke_requested=smoke_only, smoke_display_seconds=20 if smoke_only else 0,
                 smoke_display_finished=False, smoke_idle_observed=False)
    facts.update((key, False) for key in STARTUP_BOOL_FIELDS)
    facts.update((key, 0) for key in STARTUP_COUNT_FIELDS)
    stopped = [False]
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(number, lambda unused, frame: stopped.__setitem__(0, True))
    guard_pid = None
    control_fd = None
    write_fd = read_fd = None
    candidate_row = None
    credentials_row = None
    platform_verified = False
    asset_edges = []
    log_readers = []

    def check():
        component.check()
        need(not stopped[0], 'stop_requested')

    def copy_startup_facts():
        # Passive copies of the original runner's authenticated collection.
        # These are startup observations, never RF admission or restore proof.
        # load_owner() retains/validates exact Factory scope, collector ticket,
        # private 35-module realm, actual baseline and both STATUS observations.
        for key in STARTUP_BOOL_FIELDS:
            value = component.result[key]
            need(type(value) is bool, 'startup_observation')
            facts[key] = value
        for key in STARTUP_COUNT_FIELDS:
            value = component.result[key]
            need(type(value) is int and 0 <= value <= 512, 'startup_observation')
            facts[key] = value

    def raw_file(name, raw=None):
        row = component.open_fd(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, parent=control_fd)
        need(row['metadata'][2:6] == (stat.S_IFREG | 0o600, 0, 0, 1), 'raw_file')
        if raw is not None:
            need(type(raw) is bytes and len(raw) <= 1048576 and os.write(row['fd'], raw) == len(raw), 'raw_write')
            os.fsync(row['fd'])
            need(component.close_fd(row), 'raw_close')
        return row

    def pipe_row(fd):
        row = dict(fd=fd, metadata=runner.metadata(os.fstat(fd)), unknown=False,
                   closed=False, attempted=False, no_fd=False, error=None)
        need(fd > 2 and stat.S_ISFIFO(row['metadata'][2]), 'pipe_fd')
        component.rows.append(row)
        return row

    def asset_bindings():
        for parent, name, row in asset_edges:
            actual = runner.metadata(os.stat(name, follow_symlinks=False,
                                             **({} if parent is None else {'dir_fd': parent})))
            need(runner.metadata(os.fstat(row['fd']))[:5] == row['metadata'][:5] == actual[:5], 'asset_directory_changed')

    def remove_credentials():
        if credentials_row is None:
            return
        asset_bindings()
        actual = runner.metadata(os.stat('credentials.json', dir_fd=asset_edges[-1][2]['fd'], follow_symlinks=False))
        need(actual == credentials_row['metadata'], 'credentials_changed')
        os.unlink('credentials.json', dir_fd=asset_edges[-1][2]['fd'])
        try:
            os.stat('credentials.json', dir_fd=asset_edges[-1][2]['fd'], follow_symlinks=False)
        except OSError as error:
            need(error.errno == errno.ENOENT, 'credentials_remove')
        else:
            raise UiSessionError('credentials_remove')
        facts['credentials_removed'] = True

    try:
        component.platform()
        platform_verified = True
        component.validate_payload()
        component.before = component.snapshot()
        need(tuple((path, value[1]) for path, value in component.before['stock']) == runner.STOCK_PINS, 'stock_pins')
        component.preflight()
        need(component.result['private_assets_verified'], 'private_assets_required')
        component.stage()
        check()
        observe_receive = _load_monitor(component, runner)
        _RETAINED['assets'] = assets.validate_assets(component.until)
        parent_fd = None
        for name, metadata in _RETAINED['assets']['directory_bindings'][:-1]:
            row = component.open_fd(name, os.O_RDONLY | os.O_DIRECTORY, parent=parent_fd)
            need(row['metadata'][:5] == metadata, 'asset_binding')
            asset_edges.append((parent_fd, name, row))
            parent_fd = row['fd']
        for path in ('/mnt/data/p011-toolbox/native.lock', '/mnt/data/p011-toolbox/bili-awake.lock',
                     '/tmp/p011-menutest.lock', '/mnt/data/p011-menu'):
            need(not os.path.lexists(path), 'other_ui_trial')
        tracked = []
        for original, parent in component.before['processes']:
            row = _proc(original[0])
            need(_alive(row) and row['start'] == str(original[2]) and row['parent'] == original[1] and
                 row['exe'] == original[4], 'stock_identity')
            row['comm'] = original[3]
            tracked.append(row)
        originals = [row for row in tracked if row['comm'] == b'Z03']
        need(len(originals) == 1 and all(sum(row['comm'] == name for row in tracked) == 1
             for name in (b'control_engine', b'weston')), 'stock_topology')
        original = originals[0]
        need(original['exe'] == '/usr/bin/Z03' and original['args'][1:] == ('-platform', 'wayland') and
             original['state'] not in ('T', 't', 'D'), 'stock_ui')
        launcher = _proc(original['parent'])
        original_parent = next(parent for row, parent in component.before['processes'] if row[0] == original['pid'])
        need(_alive(launcher) and '/usr/bin/zyb_z03_launch.sh' in launcher['args'][:3] and
             launcher['state'] not in ('T', 't', 'D') and launcher['start'] == str(original_parent[2]) and
             launcher['parent'] == original_parent[1] and launcher['exe'] == original_parent[4], 'stock_launcher')
        env = dict(os.fsdecode(part).split('=', 1) for part in
                   _read('/proc/%d/environ' % original['pid'], 131072).split(b'\0') if b'=' in part)
        need(env.get('XDG_RUNTIME_DIR') == '/run/user/0' and
             env.get('WAYLAND_DISPLAY', 'wayland-0') == 'wayland-0' and
             stat.S_ISSOCK(os.stat('/run/user/0/wayland-0').st_mode), 'wayland')
        cwd = os.readlink('/proc/%d/cwd' % original['pid'])
        _no_core()
        control = component.new_directory(component.anchor_fd, CONTROL_NAME)
        control_fd = control['fd']
        raw_file('before.raw', repr(component.before).encode('utf-8'))
        guard_logs = (raw_file('guardian.stdout.raw'), raw_file('guardian.stderr.raw'))
        ui_logs = (raw_file('candidate.stdout.raw'), raw_file('candidate.stderr.raw'))
        to_guard = tuple(pipe_row(fd) for fd in os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        from_guard = tuple(pipe_row(fd) for fd in os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK))
        worker = _proc(os.getpid())
        raw_file('worker.ident', ('%d %s\n' % (worker['pid'], worker['start'])).encode('ascii'))
        baseline = dict(boot=_boot(), original=original, launcher=launcher, tracked=tracked,
                        pins=runner.STOCK_PINS, control_meta=control['metadata'][:5],
                        stock_metadata=tuple((path, value[2]) for path, value in component.before['stock']))
        need(baseline['boot'] == component.before['boot'].decode('ascii').strip(), 'boot_changed')
        need(threading.active_count() == 1 and component.owner is None and component.boot is None, 'fork_boundary')
        sys.stdout.flush()
        sys.stderr.flush()
        guard_pid = os.fork()
        if guard_pid == 0:
            _guardian(component, to_guard[0]['fd'], from_guard[1]['fd'], guard_logs, baseline, worker)
            os._exit(3)
        write_fd, read_fd = to_guard[1]['fd'], from_guard[0]['fd']
        _RETAINED['guardian'] = _proc(guard_pid)
        for row in (to_guard[0], from_guard[1]) + guard_logs:
            need(component.close_fd(row), 'guardian_parent_fd_close')
        pending = b''
        armed = False
        until = min(component.until, time.monotonic() + 5.0)
        while time.monotonic() < until:
            check()
            pending, frames, eof = _pipe_read(read_fd, pending)
            need(not eof and all(frame == 'ARMED' for frame in frames), 'guardian_not_armed')
            if frames:
                need(len(frames) == 1, 'guardian_armed_frame')
                armed = True
                break
            time.sleep(.05)
        need(armed, 'guardian_not_armed')
        component.load_owner()
        copy_startup_facts()
        need(_receive_interactive_originals(component, window), 'interactive_window_changed')
        facts['interactive_window_bound'] = True
        need(all(facts[key] is True for key in STARTUP_BOOL_FIELDS), 'startup_observation')
        need(component.original_receive_ui_idle(), 'receive_ui_inventory')
        _copy_receive_ui_trial(component, facts, initial=True)
        endpoint = component.owner.endpoint()
        need(set(endpoint) == {'endpoint', 'token'} and re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', endpoint['endpoint']) is not None and
             1 <= int(endpoint['endpoint'].rsplit(':', 1)[1]) <= 65535 and
             type(endpoint['token']) is str and re.fullmatch(r'[0-9a-f]{64}', endpoint['token']) is not None, 'credential_pair')
        asset_bindings()
        credentials_row = component.open_fd('credentials.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                            0o600, parent=asset_edges[-1][2]['fd'])
        _RETAINED['credentials'] = credentials_row
        need(credentials_row['metadata'][2:7] == (stat.S_IFREG | 0o600, 0, 0, 1, 0), 'credential_file')
        private = component.codec.dumps(dict(session=SESSION, endpoint=endpoint['endpoint'], token=endpoint['token'])).encode('utf-8')
        try:
            need(len(private) <= 1024 and os.write(credentials_row['fd'], private) == len(private), 'credential_write')
            os.fsync(credentials_row['fd'])
        finally:
            # Even a short write belongs to this original creation FD. Retain
            # its real metadata, close it once, then exact-inode withdrawal is
            # possible without deleting an unrecognised replacement file.
            current = runner.metadata(os.fstat(credentials_row['fd']))
            need(current[:6] == credentials_row['metadata'][:6], 'credential_identity')
            credentials_row['metadata'] = current
            private = endpoint = None
            need(component.close_fd(credentials_row), 'credential_close')
        check()
        need(_alive(_refresh(_RETAINED['guardian'])), 'guardian_missing')
        asset_bindings()
        _signal(launcher, signal.SIGSTOP, baseline['boot'])
        until = time.monotonic() + 2.0
        while time.monotonic() < until and _refresh(launcher)['state'] not in ('T', 't'):
            time.sleep(.05)
        need(_refresh(launcher)['state'] in ('T', 't'), 'launcher_not_stopped')
        _terminate(original, baseline['boot'], candidate=False)
        facts['original_ui_exited'] = True
        check()
        env = dict(env, QML_DISABLE_DISK_CACHE='1', QT_LOGGING_TO_CONSOLE='1')
        env.pop('QML_FORCE_DISK_CACHE', None)
        with open(os.devnull, 'rb') as stdin:
            ui = subprocess.Popen([CANDIDATE, '-platform', 'wayland'], stdin=stdin,
                                  stdout=ui_logs[0]['fd'], stderr=ui_logs[1]['fd'],
                                  env=env, cwd=cwd, close_fds=True, start_new_session=True)
        _RETAINED['ui'] = ui
        until = time.monotonic() + 2.0
        while time.monotonic() < until:
            candidate_row = _proc(ui.pid)
            if _alive(candidate_row) and candidate_row['exe'] == CANDIDATE and candidate_row['parent'] == worker['pid']:
                break
            need(ui.poll() is None, 'candidate_start')
            time.sleep(.02)
        need(_alive(candidate_row) and candidate_row['exe'] == CANDIDATE and candidate_row['sid'] == candidate_row['pid'], 'candidate_start')
        _pipe_write(write_fd, 'CAND %d %s\n' % (candidate_row['pid'], candidate_row['start']))
        for name, row in zip(('candidate.stdout.raw', 'candidate.stderr.raw'), ui_logs):
            reader = component.open_fd(name, os.O_RDONLY, parent=control_fd)
            need(reader['metadata'][:6] == row['metadata'][:6], 'ui_log_identity')
            log_readers.append(reader)
            need(component.close_fd(row), 'ui_writer_close')
        tails = [b'', b'']
        launched = time.monotonic()
        display_until = min(window[5], launched + SMOKE_DISPLAY_SECONDS) if smoke_only else window[5]
        ready_at = None
        while True:
            if smoke_only:
                facts['smoke_idle_observed'] = False
            check()
            need(_receive_ui_display_allowed(component, observe_receive), 'closed_service_changed')
            trial_observed = _copy_receive_ui_trial(component, facts)
            if smoke_only:
                need(component.original_receive_ui_idle() is True and
                     trial_observed['claimed'] is False and trial_observed['claim_count'] == 0 and
                     trial_observed['session_attached'] is False, 'smoke_receive_activity')
                facts['smoke_idle_observed'] = True
            need(_alive(_refresh(_RETAINED['guardian'])), 'guardian_missing')
            leave = False
            for index, reader in enumerate(log_readers):
                need(os.fstat(reader['fd']).st_size <= 4194304, 'ui_log_budget')
                for unused in range(64):
                    raw = os.read(reader['fd'], 65536)
                    if not raw:
                        break
                    value = tails[index] + raw
                    if b'P011_MTA FORMAL_UI_FAILED' in value or b'P011_MTA FORMAL_SCENE_FAILED' in value:
                        raise UiSessionError('qml_failed')
                    if b'P011_MTA FORMAL_UI_READY' in value:
                        facts['ui_ready'] = True
                    if b'P011_MTA FORMAL_UI_EXIT_REQUESTED' in value:
                        leave = True
                    tails[index] = value[-256:]
            if facts['ui_ready'] and ready_at is None:
                ready_at = time.monotonic()
                remove_credentials()
                _RETAINED['assets_after_ready'] = assets.validate_assets(component.until)
                print('MTA_FORMAL_UI_READY', flush=True)
            facts['ui_http_observed'] = len(component.owner.requests) > 0
            now = time.monotonic()
            facts['interactive_window_expired'] = _receive_interactive_expired(component, window, now)
            if smoke_only and now >= display_until:
                facts['smoke_display_finished'] = True
            if ui.poll() is not None or leave or facts['interactive_window_expired'] or facts['smoke_display_finished']:
                break
            need(facts['ui_ready'] or time.monotonic() - launched < READY_SECONDS, 'qml_ready_timeout')
            time.sleep(.1)
        facts['reason'] = ('interactive_window_expired' if facts['interactive_window_expired'] else
                           'receive_ui_smoke_finished' if facts['smoke_display_finished'] else 'ui_finished')
    except BaseException as error:
        if smoke_only:
            facts['smoke_idle_observed'] = False
        _RETAINED['failures'].append(error)
        facts['reason'] = error.code if type(error) is UiSessionError else 'session_failed'
    finally:
        try:
            if credentials_row is not None and not facts['credentials_removed']:
                remove_credentials()
        except BaseException as error:
            _RETAINED['failures'].append(error)
        # First stop the copied application/request producer, then original
        # same-worker close; the guardian independently confirms absence later.
        try:
            if candidate_row is not None:
                _terminate(candidate_row, baseline['boot'], candidate=True)
            ui = _RETAINED['ui']
            if ui is not None:
                ui.wait(timeout=3.0)
            facts['candidate_exited'] = not _scan(candidate_parent=os.getpid()) if platform_verified else True
        except BaseException as error:
            _RETAINED['failures'].append(error)
        try:
            component.finish_owner()
            copy_startup_facts()
            facts['owner_close_verified'] = component.owner is not None and component.result['owner_resources_closed'] is True
            if component.owner is not None and component.owner.receive_trial is not None:
                _copy_receive_ui_trial(component, facts, terminal=True)
        except BaseException as error:
            _RETAINED['failures'].append(error)
        if guard_pid is not None and guard_pid > 0:
            try:
                if facts['owner_close_verified'] and facts['candidate_exited']:
                    _pipe_write(write_fd, 'OWNER_CLOSED_REPORTED\n')
                    _pipe_write(write_fd, 'RESTORE\n')
                else:
                    # EOF is an explicit unknown-owner recovery request, not
                    # an authenticated close. The worker will spawn no more UI.
                    row = next(row for row in component.rows if row['fd'] == write_fd and not row['closed'])
                    need(component.close_fd(row), 'guardian_eof_close')
                pending = b''
                until = min(component.cleanup_until + 75.0, time.monotonic() + 65.0)
                while time.monotonic() < until:
                    pending, frames, eof = _pipe_read(read_fd, pending)
                    need(all(frame in ('RESTORED', 'FAILED') for frame in frames), 'guardian_result_frame')
                    if frames:
                        need(len(frames) == 1, 'guardian_result_frame')
                        facts['stock_restored'] = frames[0] == 'RESTORED'
                        break
                    if eof:
                        break
                    time.sleep(.1)
                wait_until = time.monotonic() + 3.0
                while time.monotonic() < wait_until:
                    got, status = os.waitpid(guard_pid, os.WNOHANG)
                    if got == guard_pid:
                        facts['guardian_exited'] = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
                        break
                    time.sleep(.05)
            except BaseException as error:
                _RETAINED['failures'].append(error)
        for row in reversed(component.rows):
            component.close_fd(row)
        facts['worker_fds_closed'] = all(row['closed'] and not row['unknown'] for row in component.rows)
        failed_assets_pending = any(type(error) is assets.AssetsError and error.facts['resource_pending']
                                   for error in _RETAINED['failures'])
        facts['resource_pending'] = (not facts['worker_fds_closed'] or component.owner is not None and
                                     not facts['owner_close_verified'] or guard_pid is not None and not facts['guardian_exited'] or
                                     credentials_row is not None and not facts['credentials_removed'] or
                                     not facts['candidate_exited'] or failed_assets_pending or
                                     guard_pid is not None and not facts['stock_restored'])
    facts['complete'] = (not _RETAINED['failures'] and not component.failures and not facts['resource_pending'] and
                         facts['ui_ready'] and facts['ui_http_observed'] and facts['credentials_removed'] and
                          facts['owner_close_verified'] and facts['candidate_exited'] and facts['stock_restored'] and
                          facts['guardian_exited'] and facts['original_ui_exited'] and
                          facts['receive_trial_initial_observed'] and facts['receive_trial_terminal_observed'] and
                          facts['receive_trial_terminal_revoked'] and not facts['auto_receive_action_issued'] and
                          facts['interactive_window_requested'] and facts['interactive_window_bound'] and
                          all(facts[key] is True for key in STARTUP_BOOL_FIELDS))
    if smoke_only:
        # This is original-inventory/Trial DATA only, never physical no-RF proof.
        facts['smoke_idle_observed'] = (facts['complete'] and facts['smoke_idle_observed'] and
                                         facts['receive_trial_claimed'] is False and
                                         facts['receive_trial_claim_count'] == 0 and
                                         facts['receive_trial_session_attached'] is False)
    # Only this scalar allowlist returns. Original failures/objects stay private.
    return facts


if __name__ == '__main__':
    print('SOURCE_MTA_FORMAL_RECEIVE_UI_V1 worker=false guardian=false service=false auto_receive=false smoke_display=20')
