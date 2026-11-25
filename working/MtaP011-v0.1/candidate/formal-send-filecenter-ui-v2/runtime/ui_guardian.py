"""Fixed sender UI-v2 guardian, mechanically selected from the frozen receive UI.

Source: receive-filecenter-archive-v1/runtime/ui_session.py, 104680 bytes,
SHA256 04d3bbbbda2bccf67b29154a5b481d70cecb17647dc8cec51eb045c679d24a7c.
Only original guardian/audio/PID/pipe definitions are reused. No receiver
Owner, archive consumer, constructor or run_fixed is carried into this module.
No main, RF, credentials or UI startup occurs merely by defining this source.
The parent UI supplies a real held FD scope; this guardian does not sign Owner
closure, Native restoration or phone success. Its original +68/+135 caps remain.
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

SESSION = '75ff78ef1ee74591a1a39501'
ASSETS = '/mnt/data/p011-toolbox/mta-ui/' + SESSION
CANDIDATE = ASSETS + '/Z03.mta-ui-candidate'
CONTROL_NAME = 'p011-mta-ui-session-' + SESSION + '-formal-send-filecenter-ui-v2'
CONTROL = '/var/volatile/tmp/' + CONTROL_NAME
AUDIO_WRAPPER = ('import os,signal,sys;'
    'os.kill(os.getpid(),signal.SIGSTOP);'
    'os.execve(sys.argv[1],sys.argv[1:],os.environ)')
AUDIO_PROGRAMS = ('/usr/bin/gst-play-1.0', '/bin/gst-play-1.0')
AUDIO_MAX = 32
AUDIO_ACK_SECONDS = 2.0

class UiSessionError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def need(condition, code):
    if not condition:
        raise UiSessionError(code)


class _FileCenterGuardianChannel(object):
    """One bounded original pipe conversation, shared with terminal restore.

    Handler threads may observe their actual stopped child and obtain an ACK;
    they never call the original Owner's worker-only context or resource gate.
    No PID, command or callback is accepted from the HTTP request payload.
    """
    def __init__(self, component, write_row, read_row, pending, baseline, worker,
                 guardian, stopped):
        self.component, self.until = component, component.until
        self.cleanup_until = component.cleanup_until
        self.write_fd, self.read_fd = write_row['fd'], read_row['fd']
        self.pipe_originals = ((write_row, write_row['fd'], write_row['metadata']),
                               (read_row, read_row['fd'], read_row['metadata']))
        self.pending = pending
        self.boot, self.worker, self.guardian = baseline['boot'], worker, guardian
        self.worker_thread, self.clock = threading.current_thread(), time.monotonic
        self.stopped, self.lock, self.last = stopped, threading.RLock(), None
        self.audio = self.module = self.audio_type = self.notify = self.companion = None
        self.audio_tickets = None
        self.methods, self.rows = {}, []
        self.bound = self.closing = self.terminal = False
        self.failure = None

    def bind(self, audio, module, companion):
        need(threading.current_thread() is self.worker_thread and not self.bound and
             type(module) is types.ModuleType and module.GUARDIAN_WRAPPER == AUDIO_WRAPPER and
             type(audio) is module.FileCenterAudio and not audio.tickets and
             audio._guardian_original is None, 'audio_guardian_source')
        methods = {}
        for name in ('__init__', 'bind_guardian', '_notify_guardian', 'play',
                     'stop_audio', 'actors_closed'):
            method = getattr(module.FileCenterAudio, name)
            need(type(method) is types.FunctionType and method.__globals__ is module.__dict__,
                 'audio_guardian_source')
            methods[name] = method
        self.audio, self.module, self.audio_type, self.methods = audio, module, module.FileCenterAudio, methods
        self.audio_tickets = audio.tickets
        self.companion = companion
        def notify(phase, ticket):
            return self.report(phase, ticket)
        self.notify = notify  # Hold the exact callback before registration.
        need(methods['bind_guardian'](audio, notify) is None, 'audio_guardian_source')
        self.bound = True
        need(self.current(), 'audio_guardian_source')

    def current(self):
        return (self.bound and type(self.audio) is self.audio_type and
                self.companion.audio is self.audio and self.companion.state.audio is self.audio and
                self.module.FileCenterAudio is self.audio_type and
                self.module.GUARDIAN_WRAPPER == AUDIO_WRAPPER and
                self.audio.guardian_notify is self.notify and
                self.audio._guardian_original is self.notify and
                self.audio.tickets is self.audio_tickets and type(self.audio_tickets) is list and
                all(getattr(self.audio_type, name) is original for name, original in self.methods.items()))

    def now(self, cleanup=False):
        need(os.getpid() == self.worker['pid'] and self.component.until is self.until and
             self.component.cleanup_until is self.cleanup_until and self.current() and
             self.component.owner.clock is self.clock and not self.terminal,
             'audio_guardian_source')
        for row, fd, metadata in self.pipe_originals:
            need(any(row is original for original in self.component.rows) and
                 row['fd'] == fd and row['metadata'] is metadata and
                 row['closed'] is False and row['unknown'] is False,
                 'audio_guardian_pipe')
            actual = os.fstat(fd)
            need((actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid,
                  actual.st_gid, actual.st_nlink) == metadata[:6] and stat.S_ISFIFO(actual.st_mode),
                 'audio_guardian_pipe')
        value = self.clock()
        need(type(value) is float and math.isfinite(value) and
             (self.last is None or value >= self.last), 'audio_guardian_clock')
        self.last = value
        need(value < (self.cleanup_until if cleanup else self.until), 'audio_guardian_deadline')
        return value

    def exchange(self, row, message, expected, cleanup=False):
        start = self.now(cleanup)
        end = min(self.cleanup_until if cleanup else self.until, start + AUDIO_ACK_SECONDS)
        need(_boot() == self.boot and _alive(_refresh(self.guardian)), 'audio_guardian_missing')
        _pipe_write(self.write_fd, message)
        while self.now(cleanup) < end:
            self.pending, frames, eof = _pipe_read(self.read_fd, self.pending)
            need(not eof, 'audio_guardian_eof')
            if frames:
                need(len(frames) == 1 and frames[0] == expected, 'audio_guardian_ack')
                return True
            time.sleep(min(.02, max(0.0, end - self.clock())))
        raise UiSessionError('audio_guardian_ack_timeout')

    def report(self, phase, ticket):
        with self.lock:
            try:
                self.now(phase == 'cancel')
                need(phase in ('prepare', 'register', 'cancel') and type(ticket) is dict and
                     any(ticket is original for original in self.audio.tickets) and
                     ticket['guardian_required'] is True, 'audio_guardian_ticket')
                if phase == 'prepare':
                    need(not self.closing and not self.stopped[0] and len(self.rows) < AUDIO_MAX and
                         not any(row['ticket'] is ticket for row in self.rows) and
                         ticket['spawn_called'] is False and ticket['process'] is None,
                         'audio_guardian_ticket')
                    command, wrapper = ticket['command'], ticket['spawn_command']
                    fd = ticket['source_fd']
                    need(type(fd) is int and 2 < fd <= 0x7fffffff and type(command) is tuple and
                         len(command) == 5 and command[0] in AUDIO_PROGRAMS and
                         command[1:3] == ('--no-interactive', '--audiosink=pulsesink') and
                         re.fullmatch(r'--volume=(?:0\.[0-9]{2}|1\.00)', command[3]) is not None and
                         command[4] == 'file:///proc/%d/fd/%d' % (self.worker['pid'], fd) and
                         wrapper == (sys.executable, '-c', AUDIO_WRAPPER) + command,
                         'audio_guardian_command')
                    volume = 100 if command[3] == '--volume=1.00' else int(command[3][-2:])
                    row = dict(ticket=ticket, number=len(self.rows) + 1, fd=fd,
                               program=AUDIO_PROGRAMS.index(command[0]), volume=volume,
                               wrapper=wrapper, command=command, actor=None,
                               prepare_called=False, prepared=False,
                               register_called=False, registered=False,
                               cancel_called=False, cancelled=False, failure=None)
                    self.rows.append(row)  # Before even the original pipe write.
                    row['prepare_called'] = True
                    self.exchange(row, 'AUDIO_PREPARE %d %d %d %d\n' %
                                  (row['number'], fd, row['program'], volume),
                                  'AUDIO_PREPARED %d' % row['number'])
                    row['prepared'] = True
                    return True
                values = [row for row in self.rows if row['ticket'] is ticket]
                need(len(values) == 1 and values[0]['prepared'], 'audio_guardian_ticket')
                row = values[0]
                if phase == 'cancel':
                    need(not row['cancel_called'] and not row['register_called'] and
                         ticket['spawn_called'] is False and ticket['process'] is None,
                         'audio_guardian_cancel')
                    row['cancel_called'] = True
                    self.exchange(row, 'AUDIO_CANCEL %d\n' % row['number'],
                                  'AUDIO_CANCELLED %d' % row['number'], True)
                    row['cancelled'] = True
                    return True
                need(not row['register_called'] and not row['cancel_called'] and
                     ticket['spawn_called'] is True and ticket['spawn_returned'] is True and
                     type(ticket['process']) is subprocess.Popen and
                     tuple(ticket['process'].args) == row['wrapper'], 'audio_guardian_ticket')
                row['register_called'] = True
                proc = ticket['process']
                end = min(self.until, self.now() + AUDIO_ACK_SECONDS)
                actor = None
                while self.now() < end:
                    need(proc.poll() is None, 'audio_wrapper_exited')
                    actor = _proc(proc.pid)
                    if _alive(actor):
                        need(actor['parent'] == self.worker['pid'] and actor['sid'] == self.worker['sid'] and
                             actor['exe'] == self.worker['exe'] and actor['args'] == row['wrapper'],
                             'audio_guardian_actor')
                        if actor['state'] in ('T', 't'):
                            break
                    time.sleep(min(.02, max(0.0, end - self.clock())))
                need(_alive(actor) and actor['state'] in ('T', 't'), 'audio_wrapper_not_stopped')
                row['actor'] = actor  # Exact native observation before announcement.
                self.exchange(row, 'AUDIO %d %d %s\n' %
                              (row['number'], actor['pid'], actor['start']),
                              'AUDIO_ACK %d %d %s' % (row['number'], actor['pid'], actor['start']))
                row['registered'] = True
                return True
            except BaseException as error:
                if self.failure is None:
                    self.failure = error
                for original in self.rows:
                    if original['ticket'] is ticket and original['failure'] is None:
                        original['failure'] = error
                raise

    def prevent_new(self):
        need(threading.current_thread() is self.worker_thread, 'audio_guardian_source')
        with self.lock:
            self.closing = True

    def settled(self):
        # This is original caller/ACK continuity plus actual Audio actor closure,
        # not the guardian's later independent kernel-absence observation.
        with self.lock:
            return (self.closing and self.current() and self.failure is None and
                    self.methods['actors_closed'](self.audio) is True and
                    all(row['failure'] is None and
                        ((row['registered'] and row['ticket']['guardian_registered']) or
                         (row['cancelled'] and row['ticket']['guardian_cancelled'] and
                          row['ticket']['spawn_called'] is False)) for row in self.rows))


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
    # Frames fit PIPE_BUF. Each of at most 32 audio registrations is ACKed
    # synchronously; the final original restore frames share its channel lock.
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


def _guardian_audio_frame(frame, rows, worker, baseline, write_fd, reported):
    """Retain an exact real self-stopped child before permitting audio exec.

    An intent is not an actor or an absence proof. A lost registration leaves
    that intent pending and forbids a complete guardian restoration result.
    This parser accepts no executable path, shell, URI or caller argv.
    """
    if not frame.startswith(('AUDIO ', 'AUDIO_')):
        return False
    need(not reported and _boot() == baseline['boot'], 'audio_guardian_frame')
    prepare = re.fullmatch(r'AUDIO_PREPARE ([1-9][0-9]?) ([1-9][0-9]{0,9}) ([01]) ([0-9]{1,3})', frame)
    if prepare:
        number, fd, program, volume = (int(value) for value in prepare.groups())
        need(number == len(rows) + 1 and number <= AUDIO_MAX and 2 < fd <= 0x7fffffff and
             0 <= volume <= 100 and _alive(_refresh(worker)), 'audio_guardian_frame')
        gst = AUDIO_PROGRAMS[program]
        gst_exe = os.path.realpath(gst)
        metadata = os.stat(gst_exe, follow_symlinks=False)
        need(gst_exe.startswith('/') and stat.S_ISREG(metadata.st_mode) and
             metadata.st_uid == 0 and metadata.st_gid == 0 and
             not metadata.st_mode & 0o022 and metadata.st_mode & 0o111,
             'audio_guardian_program')
        command = (gst, '--no-interactive', '--audiosink=pulsesink',
                   '--volume=%.2f' % (volume / 100.0),
                   'file:///proc/%d/fd/%d' % (worker['pid'], fd))
        row = dict(number=number, command=command,
                   wrapper=(sys.executable, '-c', AUDIO_WRAPPER) + command,
                   gst_exe=gst_exe,
                   gst_metadata=(metadata.st_dev, metadata.st_ino, metadata.st_mode,
                                 metadata.st_uid, metadata.st_gid),
                   actor=None, registered=False, cancelled=False,
                   prepare_ack_called=False, prepare_ack_returned=False,
                   register_ack_called=False, register_ack_returned=False,
                   cancel_ack_called=False, cancel_ack_returned=False,
                   term_called=False, kill_called=False, observations=[],
                   no_live_producer=False, failure=None)
        rows.append(row)  # Original intent before ACK, never silently removed.
        print('GUARD_AUDIO_INTENT ' + repr((number, fd, program, volume)), flush=True)
        row['prepare_ack_called'] = True
        _pipe_write(write_fd, 'AUDIO_PREPARED %d\n' % number)
        row['prepare_ack_returned'] = True
        return True
    registered = re.fullmatch(r'AUDIO ([1-9][0-9]?) ([1-9][0-9]{0,9}) ([0-9]{1,20})', frame)
    cancel = re.fullmatch(r'AUDIO_CANCEL ([1-9][0-9]?)', frame)
    need(registered is not None or cancel is not None, 'audio_guardian_frame')
    number = int((registered or cancel).group(1))
    values = [row for row in rows if row['number'] == number]
    need(len(values) == 1 and not values[0]['registered'] and not values[0]['cancelled'] and
         values[0]['actor'] is None, 'audio_guardian_frame')
    row = values[0]
    if cancel:
        # The sealed caller emits this only before its original Popen call.
        row['cancelled'] = True
        row['cancel_ack_called'] = True
        _pipe_write(write_fd, 'AUDIO_CANCELLED %d\n' % number)
        row['cancel_ack_returned'] = True
        return True
    pid, start = int(registered.group(2)), registered.group(3)
    actor = _proc(pid)
    need(_alive(_refresh(worker)) and _alive(actor) and actor['start'] == start and
         actor['parent'] == worker['pid'] and actor['sid'] == worker['sid'] and
         actor['exe'] == worker['exe'] and actor['args'] == row['wrapper'] and
         actor['state'] in ('T', 't') and
         not any(value['actor'] is not None and
                 (value['actor']['pid'], value['actor']['start']) == (pid, start) for value in rows),
         'audio_guardian_actor')
    row['actor'] = actor  # Actual original before the native ACK write.
    row['registered'] = True
    # Private original inventory contains only authenticated fixed argv and a
    # /proc FD URI, never the user's filename, request data or credentials.
    print('GUARD_AUDIO_ORIGINAL ' + repr((number, baseline['boot'], actor,
          row['command'], row['wrapper'], row['gst_metadata'])), flush=True)
    row['register_ack_called'] = True
    _pipe_write(write_fd, 'AUDIO_ACK %d %d %s\n' % (number, pid, start))
    row['register_ack_returned'] = True
    return True


def _guardian_audio_current(row, worker, boot):
    need(_boot() == boot and row['registered'] and row['actor'] is not None,
         'audio_guardian_actor')
    original = row['actor']
    # /proc exe and cmdline are separate reads. One immediate second read may
    # resolve the known wrapper->gst exec transition, never adopt another PID
    # or signal an unidentified executable. Both reads keep original ancestry.
    for unused in range(2):
        actual = _proc(original['pid'])
        if actual is None:
            return None
        need(actual['start'] == original['start'] and actual['sid'] == original['sid'],
             'audio_guardian_pid_changed')
        need(actual['parent'] == worker['pid'] or
             actual['parent'] == 1 and not _alive(_refresh(worker)), 'audio_guardian_parent')
        if not _alive(actual):
            return actual
        wrapper = actual['exe'] == original['exe'] and actual['args'] == row['wrapper']
        gst = actual['exe'] == row['gst_exe'] and actual['args'] == row['command']
        if wrapper or gst:
            return actual
    raise UiSessionError('audio_guardian_exec_changed')


def _guardian_stop_audio(rows, worker, boot, end):
    """Finite signals only to retained PID/start/argv/worker originals.

    Two actual terminal/absent observations mean no live audio producer. A
    terminal zombie is recorded separately, not fabricated as wait/reap or
    the old Proc25/Owner/Native closure receipt. Unknown originals remain so.
    """
    failures = []
    for row in rows:
        try:
            if row['cancelled']:
                row['no_live_producer'] = True
                continue
            need(row['registered'] and row['actor'] is not None,
                 'audio_guardian_registration_pending')
            def terminal_twice():
                need(time.monotonic() < end, 'audio_guardian_deadline')
                first = _guardian_audio_current(row, worker, boot)
                row['observations'].append(first)
                if _alive(first):
                    return False
                time.sleep(min(.02, max(0.0, end - time.monotonic())))
                need(time.monotonic() < end, 'audio_guardian_deadline')
                second = _guardian_audio_current(row, worker, boot)
                row['observations'].append(second)
                return not _alive(second)

            def wait_terminal(until):
                while time.monotonic() < until:
                    if terminal_twice():
                        return True
                    time.sleep(min(.05, max(0.0, until - time.monotonic())))
                return False

            if terminal_twice():
                row['no_live_producer'] = True
                continue
            actual = _guardian_audio_current(row, worker, boot)
            need(time.monotonic() < end and _alive(actual) and
                 actual['pid'] != os.getpid(), 'audio_guardian_actor')
            row['term_called'] = True
            os.kill(actual['pid'], signal.SIGTERM)
            if wait_terminal(min(end, time.monotonic() + 2.0)):
                row['no_live_producer'] = True
                continue
            actual = _guardian_audio_current(row, worker, boot)
            if not _alive(actual):
                row['no_live_producer'] = terminal_twice()
                continue
            need(time.monotonic() < end and actual['pid'] != os.getpid(), 'audio_guardian_deadline')
            row['kill_called'] = True
            os.kill(actual['pid'], signal.SIGKILL)
            row['no_live_producer'] = wait_terminal(min(end, time.monotonic() + 1.0))
            need(row['no_live_producer'], 'audio_guardian_stop_pending')
        except BaseException as error:
            row['failure'] = error; failures.append(error)
        finally:
            # Original register inventory was logged once above. Retain the
            # last two real terminal/absent observations and exact signal/ACK
            # facts without dumping an unbounded polling history or exception.
            try:
                print('GUARD_AUDIO_END ' + repr((row['number'],
                      row['prepare_ack_called'], row['prepare_ack_returned'],
                      row['register_ack_called'], row['register_ack_returned'],
                      row['cancel_ack_called'], row['cancel_ack_returned'],
                      row['term_called'], row['kill_called'],
                      tuple(row['observations'][-2:]), row['no_live_producer'],
                      None if row['failure'] is None else _guardian_error_code(row['failure']))), flush=True)
            except BaseException as error:
                if row['failure'] is None:
                    row['failure'] = error
                failures.append(error)  # Still close the other known actors.
    # Do not skip the remaining known originals after a failure on one actor.
    if failures:
        raise failures[0]
    need(all(row['no_live_producer'] for row in rows), 'audio_guardian_stop_pending')
    print('GUARD_AUDIO_NO_LIVE_PRODUCERS count=%d terminal=%d' %
          (sum(row['registered'] for row in rows),
           sum(bool(row['observations']) and row['observations'][-1] is not None for row in rows)), flush=True)


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
               'guardian_after_write', 'audio_guardian_frame', 'audio_guardian_program',
               'audio_guardian_actor', 'audio_guardian_pid_changed', 'audio_guardian_parent',
               'audio_guardian_exec_changed', 'audio_guardian_registration_pending',
               'audio_guardian_deadline', 'audio_guardian_stop_pending')
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
        audio_rows = []
        stopped_worker = False
        protocol_failed = False
        recover_at = component.until + 68.0
        end = component.until + 135.0
        while not restore and time.monotonic() < recover_at:
            try:
                pending, frames, eof = _pipe_read(read_fd, pending)
                for frame in frames:
                    if _guardian_audio_frame(frame, audio_rows, worker, baseline, write_fd, reported):
                        continue
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
                        for frame in frames:
                            if _guardian_audio_frame(frame, audio_rows, worker, baseline, write_fd, reported):
                                continue
                            need(frame in ('OWNER_CLOSED_REPORTED', 'RESTORE'), 'guardian_frame')
                            if frame == 'OWNER_CLOSED_REPORTED':
                                need(not reported, 'duplicate_close_frame')
                                reported = True
                            if frame == 'RESTORE':
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
        recovery_failures = []
        try:
            candidates = _scan(candidate_parent=worker['pid'])
            need(len(candidates) <= 1, 'candidate_inventory')
            for row in candidates:
                _terminate(row, baseline['boot'], candidate=True)
            need(not _scan(candidate_parent=worker['pid']), 'candidate_remains')
        except BaseException as error:
            recovery_failures.append(error)
        try:
            _guardian_stop_audio(audio_rows, worker, baseline['boot'], end)
        except BaseException as error:
            recovery_failures.append(error)
        if recovery_failures:
            raise recovery_failures[0]  # No resume/RESTORED with unknown audio.
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

