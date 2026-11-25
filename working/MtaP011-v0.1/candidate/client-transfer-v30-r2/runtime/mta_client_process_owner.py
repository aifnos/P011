"""Private Linux F -> direct C/D owner. Not a CLIENT Provider/Store or RF gate.

Construction/register are pure. Explicit launch performs actual fd/fork work;
HOST _os/_reader seams never establish Linux evidence. V26 forwards each
original/caller absolute observation cap; fixed quotas and close contracts stay.
No signals, restore,
subprocess preexec_fn, orphan adoption or public arbitrary-command interface.
"""
import errno
import ctypes
import hashlib
import math
import os
import stat
import sys
import threading
import time

from mta_client_proc import ProcReader, ProcObservation
from mta_p2p_client_init import Actor

MAX_FDS = 16
MAX_BINARY = 67108864
_CODES = frozenset(('invalid_input', 'unsupported', 'busy_or_pending', 'wrong_owner',
    'multithreaded', 'deadline', 'clock_unknown', 'fd_unknown', 'binary_invalid',
    'creation_unknown', 'fork_unknown', 'identity_unknown', 'persist_unknown',
    'gate_unknown', 'exec_unknown', 'wait_unknown', 'exit_unknown', 'close_unknown'))


class ProcessOwnerError(ValueError):
    def __init__(self, code):
        ValueError.__init__(self, code if code in _CODES else 'creation_unknown')


def _fail(code):
    raise ProcessOwnerError(code)


def _int(value, low=0, high=0x7fffffff):
    return type(value) is int and low <= value <= high


def _time(value):
    if type(value) not in (int, float) or not 0 <= value <= 1e12 or not math.isfinite(value):
        _fail('invalid_input')
    return float(value)


class LaunchSpec(object):
    """Trusted fixed platform manifest input ONLY; no HTTP/CLI command parser."""
    __slots__ = ('role', 'exe', 'argv', 'env', 'sha', 'argv_sha')

    def __init__(self, role, exe, argv, env, sha):
        if (type(role) is not str or role not in ('controller', 'watchdog') or
            type(exe) is not str or not 1 <= len(exe) <= 256 or not exe.startswith('/') or
            any(part in ('', '.', '..') for part in exe[1:].split('/')) or
            any(ord(c) < 32 or ord(c) > 126 for c in exe) or
            type(argv) is not tuple or not 1 <= len(argv) <= 32 or argv[0] != exe or
            any(type(v) is not str or not 1 <= len(v) <= 512 or
                any(ord(c) < 32 or ord(c) > 126 for c in v) for v in argv) or
            sum(len(v) + 1 for v in argv) > 4096 or type(env) is not tuple or len(env) > 4 or
            any(type(p) is not tuple or len(p) != 2 or type(p[0]) is not str or p[0] not in ('PATH', 'LANG', 'MTA_PRIVATE_P2P') or
                type(p[1]) is not str or not 1 <= len(p[1]) <= 256 or
                any(ord(c) < 32 or ord(c) > 126 for c in p[1]) for p in env) or
            len(set(p[0] for p in env)) != len(env) or type(sha) is not str or len(sha) != 64 or
            any(c not in '0123456789abcdef' for c in sha)):
            _fail('invalid_input')
        for name, value in (('role', role), ('exe', exe), ('argv', argv), ('env', env), ('sha', sha),
            ('argv_sha', hashlib.sha256(b''.join(v.encode('ascii') + b'\0' for v in argv)).hexdigest())):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError('private immutable launch spec')

    def __repr__(self):
        return '<CLIENT private launch spec>'


class _FD(object):
    def __init__(self, role, creator):
        self.role, self.creator = role, creator
        self.fd = None
        self.metadata = None
        self.returned = self.unknown = self.attempted = self.closed = False

    def __repr__(self):
        return '<CLIENT private descriptor record>'


class ChildTicket(object):
    """Strong registry record installed before ANY fd creation or fork."""
    def __init__(self, owner, spec, device_fd, deadline):
        self.owner, self.spec, self.original_device_fd, self.deadline = owner, spec, device_fd, deadline
        self.fds = []
        self.started = self.fork_requested = self.fork_returned = self.fork_negative = False
        self.pid = self.parent = self.boot = self.preexec = self.postexec = None
        self.unknown = False
        self.persist_requested = self.persist_returned = False
        self.persist_receipt = None
        self.release_requested = self.released = False
        self.wait_requested = self.waited = False
        self.wait_status = self.exit_code = None
        self.exit_observation = None
        self.exit_verified = False
        self.notify_requests = 0
        self.notify_eof_v30 = False
        self.notify_last_v30 = None
        self.notify_failure_v30 = None  # Stop-only observation failure, never physical closure proof.
        self.reason, self.stage = '', 'registered'

    def __repr__(self):
        return '<CLIENT private direct child ticket>'


class PersistReceipt(object):
    """Only binds this callback result. NOT proof of Store/flock/fsync."""
    __slots__ = ('ticket', 'actor')
    def __init__(self, ticket, actor):
        if type(ticket) is not ChildTicket or type(actor) is not Actor:
            _fail('invalid_input')
        object.__setattr__(self, 'ticket', ticket)
        object.__setattr__(self, 'actor', actor)
    def __setattr__(self, *unused):
        raise AttributeError('private immutable persist receipt')
    def __repr__(self):
        return '<CLIENT private persist receipt>'


def _meta(value):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
    row = tuple(getattr(value, n, None) for n in names)
    if any(type(v) is not int or v < 0 for v in row):
        _fail('fd_unknown')
    return row


class DirectChildOwner(object):
    def __init__(self, _os=None, _reader=None, _clock=None, _threads=None, _flags=None):
        self._os = _os if _os is not None else os
        self._reader = _reader if _reader is not None else ProcReader()
        self._clock = _clock if _clock is not None else time.monotonic
        self._threads = _threads if _threads is not None else threading.active_count
        self._sleep = getattr(_os, 'sleep', time.sleep) if _os is not None else time.sleep
        self._flags, self._libc = _flags, None
        if not callable(self._clock) or not callable(self._threads) or (_flags is not None and not callable(_flags)):
            _fail('invalid_input')
        self._host_seam = _os is not None
        self._worker_v30 = threading.current_thread()
        self._pid_v30 = self._os.getpid()  # Same original OS seam, never a separate global PID oracle.
        if not _int(self._pid_v30, 1): _fail('wrong_owner')
        self._tickets, self._active, self._last = [], False, None

    def __repr__(self):
        return '<CLIENT private direct child owner>'

    def register(self, spec, original_device_fd, deadline):
        if (type(spec) is not LaunchSpec or not _int(original_device_fd, 3) or
            self._active or len(self._tickets) >= 2 or
            any(t.spec.role == spec.role for t in self._tickets)):
            _fail('invalid_input')
        ticket = ChildTicket(self, spec, original_device_fd, _time(deadline))
        self._tickets.append(ticket)
        return ticket

    def _exact(self, ticket):
        if type(ticket) is not ChildTicket or ticket.owner is not self or not any(t is ticket for t in self._tickets):
            _fail('wrong_owner')

    def _now(self, deadline=None):
        try:
            now = _time(self._clock())
        except BaseException:
            _fail('clock_unknown')
        if self._last is not None and now < self._last:
            _fail('clock_unknown')
        self._last = now
        if deadline is not None and now >= deadline:
            _fail('deadline')
        return now

    def _bounded_deadline(self, local, absolute):
        """Trusted caller cap only tightens an existing phase; no lease renewal."""
        if absolute is None: return local
        cap = _time(absolute)
        return cap if local is None else min(local, cap)

    def _single(self, ticket, starting=False, deadline=None, _absolute_deadline=None):
        end = self._bounded_deadline(ticket.deadline if starting else deadline, _absolute_deadline)
        if not self._host_seam and sys.platform != 'linux':
            _fail('unsupported')
        self._now(end)
        count = self._threads()
        if type(count) is not int or count != 1:
            _fail('multithreaded')
        observed = self._reader.read_self(_absolute_deadline=end)
        self._now(end)
        if (type(observed) is not ProcObservation or observed.kind != 'live_actor' or
            observed.resource_pending is not False or observed.same_boot is not True or
            type(observed.passes) is not int or observed.passes != 2 or type(observed.actor) is not Actor or
            not observed.actor.live() or observed.actor.pid != self._os.getpid() or len(observed.actor.tasks) != 1):
            _fail('multithreaded')
        if starting:
            ticket.parent, ticket.boot = observed.actor, observed.boot
        elif (ticket.parent is None or observed.actor.key() != ticket.parent.key() or observed.boot != ticket.boot):
            _fail('wrong_owner')
        self._now(end)

    def _nonblocking(self, fd):
        # P011 Python 3.5 has no get_blocking/fcntl module. Linux F_GETFL=3;
        # bind actual libc fcntl, never a guessed syscall or public command.
        if self._flags is not None:
            result = self._flags(fd)
        else:
            if self._libc is None:
                self._libc = ctypes.CDLL(None, use_errno=True)
                self._libc.fcntl.argtypes = (ctypes.c_int, ctypes.c_int)
                self._libc.fcntl.restype = ctypes.c_int
            ctypes.set_errno(0)
            result = self._libc.fcntl(fd, 3)
        if type(result) is not int or result < 0:
            _fail('fd_unknown')
        return bool(result & self._os.O_NONBLOCK)

    def _new_fd(self, ticket, role, creator):
        if len(ticket.fds) >= MAX_FDS:
            _fail('creation_unknown')
        record = _FD(role, creator)
        ticket.fds.append(record)
        return record

    def _fd_return(self, ticket, record, fd):
        record.fd, record.returned = fd, True
        if not _int(fd, 3):
            record.unknown = ticket.unknown = True
            _fail('fd_unknown')
        try:
            record.metadata = _meta(self._os.fstat(fd))
            if any(r is not record and r.fd == fd for r in ticket.fds):
                _fail('fd_unknown')
            self._os.set_inheritable(fd, False)
            if self._os.get_inheritable(fd) is not False:
                _fail('fd_unknown')
        except BaseException:
            record.unknown = ticket.unknown = True
            raise
        return record

    def _open(self, ticket, role, path, flags):
        record = self._new_fd(ticket, role, self._os.open)
        try:
            fd = self._os.open(path, flags)
        except OSError:
            record.closed = True # Direct POSIX open negative return: no FD.
            raise
        except BaseException:
            record.unknown = ticket.unknown = True
            raise
        return self._fd_return(ticket, record, fd)

    def _pipe(self, ticket, role):
        a = self._new_fd(ticket, role + '_read', self._os.pipe2)
        b = self._new_fd(ticket, role + '_write', self._os.pipe2)
        try:
            result = self._os.pipe2(self._os.O_CLOEXEC)
        except OSError:
            a.closed = b.closed = True
            raise
        except BaseException:
            a.unknown = b.unknown = ticket.unknown = True
            raise
        # Save both returned values before any metadata/readback can fail.
        if type(result) is not tuple or len(result) != 2:
            a.fd = result; a.unknown = b.unknown = ticket.unknown = True
            _fail('fd_unknown')
        a.fd, b.fd = result
        a.returned = b.returned = True
        self._fd_return(ticket, a, a.fd)
        self._fd_return(ticket, b, b.fd)
        return a, b

    def _close_fd(self, ticket, record):
        if record.closed:
            return True
        if record.attempted or record.unknown or not record.returned or record.metadata is None:
            return False
        record.attempted = True
        try:
            if _meta(self._os.fstat(record.fd)) != record.metadata:
                _fail('fd_unknown')
            result = self._os.close(record.fd)
            if result is not None:
                _fail('close_unknown')
            try:
                self._os.fstat(record.fd)
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.EBADF:
                    record.closed = True
            if not record.closed:
                _fail('close_unknown')
        except BaseException:
            record.unknown = ticket.unknown = True
        return record.closed and not record.unknown

    def _binary(self, ticket, _absolute_deadline=None):
        end = self._bounded_deadline(ticket.deadline, _absolute_deadline)
        self._now(end)
        fs = self._os
        record = self._open(ticket, 'executable', ticket.spec.exe, fs.O_RDONLY | fs.O_NOFOLLOW | fs.O_CLOEXEC)
        meta = record.metadata
        before = fs.fstat(record.fd)
        if (not stat.S_ISREG(meta[2]) or meta[2] & 0o022 or meta[3] not in (0, fs.getuid()) or
            # Only the observed root-owned canonical system watchdog Python may be nlink2.
            meta[5] != 1 and not (ticket.spec.role == 'watchdog' and
                ticket.spec.exe == '/usr/bin/python3.5' and meta[3:5] == (0, 0) and meta[5] == 2) or
            not _int(before.st_size, 4, MAX_BINARY)):
            _fail('binary_invalid')
        expected = before.st_size
        digest, prefix, length = hashlib.sha256(), b'', 0
        while True:
            self._now(end)
            chunk = fs.read(record.fd, min(65536, expected + 1 - length))
            if type(chunk) is not bytes:
                _fail('binary_invalid')
            if not chunk:
                break
            length += len(chunk)
            if length > expected:
                _fail('binary_invalid')
            prefix = (prefix + chunk)[:4]
            digest.update(chunk)
        self._now(end)
        after = fs.fstat(record.fd)
        self._now(end)
        if (length != expected or prefix != b'\x7fELF' or digest.hexdigest() != ticket.spec.sha or
            _meta(after) != meta or any(getattr(after, k) != getattr(before, k) for k in
                ('st_size', 'st_mtime_ns', 'st_ctime_ns'))):
            _fail('binary_invalid')
        return record

    def launch(self, ticket, _absolute_deadline=None):
        self._exact(ticket)
        if self._active or ticket.started or ticket.unknown or any(t.unknown for t in self._tickets):
            _fail('busy_or_pending')
        end = self._bounded_deadline(ticket.deadline, _absolute_deadline)
        ticket.started = self._active = True
        fs = self._os
        try:
            if fs.execve not in fs.supports_fd or not all(callable(getattr(fs, n, None)) for n in
                    ('pipe2', 'fork', 'set_blocking')):
                _fail('unsupported')
            self._single(ticket, True, _absolute_deadline=end)
            binary = self._binary(ticket, _absolute_deadline=end)
            source = _meta(fs.fstat(ticket.original_device_fd))
            if not stat.S_ISREG(source[2]) or source[5] != 1 or source[2] & 0o077:
                _fail('fd_unknown')
            device = self._new_fd(ticket, 'inherited_device', fs.dup)
            try:
                returned = fs.dup(ticket.original_device_fd)
            except OSError:
                device.closed = True
                raise
            except BaseException:
                device.unknown = ticket.unknown = True
                raise
            self._fd_return(ticket, device, returned)
            if device.metadata != source:
                _fail('fd_unknown')
            gate_r, gate_w = self._pipe(ticket, 'gate')
            error_r, error_w = self._pipe(ticket, 'error')
            notify_r, notify_w = self._pipe(ticket, 'notify')
            null = self._open(ticket, 'null', '/dev/null', fs.O_RDWR | fs.O_NOFOLLOW | fs.O_CLOEXEC)
            if not stat.S_ISCHR(null.metadata[2]) or (fs.major(null.metadata[6]), fs.minor(null.metadata[6])) != (1, 3):
                _fail('fd_unknown')
            for r in (error_r, notify_r):
                fs.set_blocking(r.fd, False)
                if self._nonblocking(r.fd) is not True:
                    _fail('fd_unknown')
            inherited = fs.listdir('/proc/self/fd')
            if type(inherited) is not list or len(inherited) > 256 or any(type(n) is not str or not n.isdigit() for n in inherited):
                _fail('fd_unknown')
            inherited = tuple(int(n) for n in inherited)
            self._single(ticket, deadline=end)
            ticket.fork_requested = True
            try:
                pid = fs.fork()
            except OSError:
                ticket.fork_negative = True
                raise
            except BaseException:
                ticket.unknown = True
                raise
            ticket.fork_returned = True
            if pid == 0 and type(pid) is int:
                self._child(ticket, binary, device, gate_r, error_w, notify_w, null, inherited)
                fs._exit(126)
            ticket.pid = pid # Keep even malformed/late return, never refork.
            if not _int(pid, 1):
                ticket.unknown = True
                _fail('fork_unknown')
            for r in (gate_r, error_w, notify_w):
                self._close_fd(ticket, r)
            self._now(end)
            observed = self._reader.read_actor(pid, _absolute_deadline=end)
            if (type(observed) is not ProcObservation or observed.kind != 'live_actor' or
                observed.boot != ticket.boot or observed.resource_pending is not False or
                observed.same_boot is not True or type(observed.passes) is not int or observed.passes != 2 or type(observed.actor) is not Actor or
                not observed.actor.live() or observed.actor.pid != pid or len(observed.actor.tasks) != 1 or
                observed.actor.exe != ticket.parent.exe or observed.actor.argv_sha != ticket.parent.argv_sha):
                _fail('identity_unknown')
            ticket.preexec = observed.actor
            ticket.stage = 'pre_exec_saved'
            self._now(end)
            if ticket.unknown:
                _fail('creation_unknown')
            return ticket
        except BaseException as error:
            ticket.reason = str(error) if type(error) is ProcessOwnerError else 'creation_unknown'
            if ticket.fork_requested and not ticket.fork_negative and ticket.preexec is None:
                ticket.unknown = True
            raise ProcessOwnerError(ticket.reason)
        finally:
            self._active = False

    def _child(self, ticket, binary, device, gate, error, notify, null, inherited):
        fs = self._os
        try:
            keep = {binary.fd, device.fd, gate.fd, error.fd, notify.fd, null.fd, 0, 1, 2}
            for fd in inherited:
                if fd not in keep:
                    try: fs.close(fd)
                    except OSError as e:
                        if e.errno != errno.EBADF: raise
            token = fs.read(gate.fd, 1)
            fs.close(gate.fd)
            if token != b'1':
                fs._exit(125)
            for fd in (0, 1, 2):
                fs.dup2(null.fd, fd)
            fs.close(null.fd)
            fs.set_inheritable(device.fd, True)
            fs.set_inheritable(notify.fd, True)
            env = dict(ticket.spec.env)
            env['P011_CLIENT_DEVICE_FD'] = str(device.fd)
            env['P011_CLIENT_NOTIFY_FD'] = str(notify.fd)
            # fexecve exact opened/hashed ELF; NEVER pathname exec fallback.
            fs.execve(binary.fd, ticket.spec.argv, env)
        except BaseException:
            try: fs.write(error.fd, b'E')
            except BaseException: pass
            fs._exit(126)

    def release(self, ticket, persist, _absolute_deadline=None):
        self._exact(ticket)
        if self._active or ticket.unknown or ticket.preexec is None or ticket.persist_requested or not callable(persist):
            _fail('busy_or_pending')
        end = self._bounded_deadline(ticket.deadline, _absolute_deadline)
        self._active = True
        try:
            self._single(ticket, deadline=end)
            observed = self._reader.read_actor(ticket.pid, ticket.preexec, _absolute_deadline=end)
            self._now(end)
            if (type(observed) is not ProcObservation or type(observed.actor) is not Actor or observed.kind != 'live_actor' or
                observed.actor.key() != ticket.preexec.key() or not observed.actor.live() or observed.boot != ticket.boot or
                observed.resource_pending is not False or observed.same_boot is not True or
                type(observed.passes) is not int or observed.passes != 2):
                _fail('identity_unknown')
            ticket.persist_requested = True
            receipt = persist(ticket, ticket.preexec)
            ticket.persist_receipt = receipt
            if type(receipt) is not PersistReceipt or receipt.ticket is not ticket or receipt.actor is not ticket.preexec:
                _fail('persist_unknown')
            ticket.persist_returned = True
            self._single(ticket, deadline=end)
            gate = next(r for r in ticket.fds if r.role == 'gate_write')
            if gate.closed or gate.unknown or _meta(self._os.fstat(gate.fd)) != gate.metadata:
                _fail('gate_unknown')
            ticket.release_requested = True
            written = self._os.write(gate.fd, b'1')
            if type(written) is not int or written != 1:
                _fail('gate_unknown')
            ticket.released = True
            if not self._close_fd(ticket, gate):
                _fail('gate_unknown')
            ticket.stage = 'exec_released'
            return True
        except BaseException as error:
            ticket.unknown = True
            ticket.reason = str(error) if type(error) is ProcessOwnerError else 'persist_unknown'
            raise ProcessOwnerError(ticket.reason)
        finally:
            self._active = False

    def resolve(self, ticket, _absolute_deadline=None):
        self._exact(ticket)
        if self._active:
            _fail('busy_or_pending')
        end = self._bounded_deadline(min(self._now() + 3, ticket.deadline), _absolute_deadline)
        self._single(ticket, deadline=end)
        if not ticket.released or ticket.waited:
            return None
        observed = self._reader.read_actor(ticket.pid, _absolute_deadline=end)
        self._now(end)
        if (type(observed) is not ProcObservation or observed.kind != 'live_actor' or
            observed.boot != ticket.boot or observed.resource_pending is not False or type(observed.actor) is not Actor or
            observed.same_boot is not True or type(observed.passes) is not int or observed.passes != 2 or
            not observed.actor.live() or observed.actor.pid != ticket.pid or observed.actor.start != ticket.preexec.start):
            ticket.reason = 'exec_unknown'
            return None
        actor = observed.actor
        if (actor.exe, actor.argv_sha) == (ticket.spec.exe, ticket.spec.argv_sha):
            ticket.postexec = actor
            ticket.stage = 'post_exec_observed'
            return actor
        if actor.key() != ticket.preexec.key():
            ticket.unknown = True
        return None

    def wait_reap(self, ticket, timeout=1, _absolute_deadline=None):
        self._exact(ticket)
        if self._active:
            _fail('busy_or_pending')
        seconds = _time(timeout)
        if not 0 < seconds <= 20:
            _fail('invalid_input')
        end = self._bounded_deadline(self._now() + seconds, _absolute_deadline)
        self._single(ticket, deadline=end)
        if ticket.waited:
            return True
        if not _int(ticket.pid, 1) or not ticket.fork_returned or ticket.fork_negative:
            return False
        ticket.wait_requested = True
        while True:
            self._now(end)
            try:
                result = self._os.waitpid(ticket.pid, self._os.WNOHANG)
            except BaseException:
                ticket.unknown = True; ticket.reason = 'wait_unknown'
                return False
            if type(result) is not tuple or len(result) != 2 or not _int(result[0]) or not _int(result[1], 0, 65535):
                ticket.unknown = True; ticket.reason = 'wait_unknown'
                return False
            if result[0] == ticket.pid:
                ticket.wait_status = result[1]
                if self._os.WIFEXITED(result[1]):
                    ticket.exit_code = self._os.WEXITSTATUS(result[1])
                elif self._os.WIFSIGNALED(result[1]):
                    ticket.exit_code = -self._os.WTERMSIG(result[1])
                else:
                    ticket.unknown = True; ticket.reason = 'wait_unknown'
                    return False
                ticket.waited = True
                ticket.stage = 'direct_child_reaped'
                self._now(end)  # Preserve actual reap before rejecting a late return.
                return True
            if result != (0, 0):
                ticket.unknown = True; ticket.reason = 'wait_unknown'
                return False
            self._now(end)
            self._sleep(.01)

    def fresh_exit(self, ticket, _absolute_deadline=None):
        self._exact(ticket)
        if self._active:
            _fail('busy_or_pending')
        end = self._bounded_deadline(self._now() + 3, _absolute_deadline)
        self._single(ticket, deadline=end)
        if not ticket.waited or ticket.preexec is None:
            return False
        observed = self._reader.read_absence(ticket.postexec or ticket.preexec, ticket.boot, _absolute_deadline=end)
        ticket.exit_observation = observed
        self._now(end)  # Cleanup cap is independent of the old association deadline.
        ticket.exit_verified = (type(observed) is ProcObservation and observed.kind == 'absence' and
            observed.boot == ticket.boot and observed.same_boot is True and type(observed.passes) is int and observed.passes == 2 and
            observed.pid_path_absent is True and observed.remaining_tasks == () and observed.resource_pending is False)
        return ticket.exit_verified

    def read_requests(self, ticket, _absolute_deadline=None):
        self._exact(ticket)
        if self._active:
            _fail('busy_or_pending')
        end = self._bounded_deadline(self._now() + 3, _absolute_deadline)
        self._single(ticket, deadline=end)
        if ticket.spec.role != 'watchdog' or not ticket.released or ticket.unknown:
            _fail('wrong_owner')
        record = next(r for r in ticket.fds if r.role == 'notify_read')
        self._now(end)
        if record.closed or record.unknown or _meta(self._os.fstat(record.fd)) != record.metadata:
            _fail('fd_unknown')
        self._now(end)
        try: data = self._os.read(record.fd, 17)
        except OSError as error:
            if error.errno == errno.EAGAIN:
                self._now(end)
                return False
            raise ProcessOwnerError('fd_unknown')
        if type(data) is not bytes or any(c != 82 for c in data) or ticket.notify_requests + len(data) > 16:
            ticket.unknown = True
            _fail('fd_unknown')
        ticket.notify_requests += len(data)
        self._now(end)  # Preserve the consumed request count before postcheck.
        return bool(data) # Passive request only; NEVER restore/close/signals.

    def read_requests_passive_v30(self, ticket, _absolute_deadline):
        """Stop requests only from the original nonblocking watchdog pipe.

        No _single/Proc read, signal, descriptor close or RF/recovery permission.
        The full phase already established the actual parent; same worker/PID
        and exact retained ticket/FD remain mandatory on every passive read.
        """
        self._exact(ticket)
        record = None
        observed = None
        site = 'owner'
        try:
            current_pid = self._os.getpid()
            if (self._active or threading.current_thread() is not self._worker_v30 or
                    type(current_pid) is not int or current_pid != self._pid_v30 or type(ticket.parent) is not Actor or
                    not ticket.parent.live() or ticket.parent.pid != self._pid_v30 or len(ticket.parent.tasks) != 1 or
                    ticket.boot is None or ticket.spec.role != 'watchdog' or not ticket.released or
                    ticket.waited or ticket.unknown or type(ticket.notify_requests) is not int or
                    not 0 <= ticket.notify_requests <= 16 or type(ticket.notify_eof_v30) is not bool or
                    ticket.notify_failure_v30 is not None and (type(ticket.notify_failure_v30) is not str or
                        ticket.notify_failure_v30 not in ('invalid_data', 'deadline', 'observation_failed'))):
                _fail('wrong_owner')
            site = 'scope'
            cap = _time(_absolute_deadline)
            now = self._now()
            if not now < cap <= ticket.deadline: _fail('deadline')
            end = min(cap, ticket.deadline, now + .2)
            site = 'fd'
            records = tuple(r for r in ticket.fds if r.role == 'notify_read')
            if len(records) != 1 or type(records[0]) is not _FD: _fail('fd_unknown')
            record = records[0]
            def exact_fd():
                nonlocal site
                site = 'clock'
                self._now(end)
                site = 'fd'
                if (not record.returned or record.unknown or record.closed or record.attempted or
                        not _int(record.fd, 3) or type(record.metadata) is not tuple or len(record.metadata) != 7 or
                        not stat.S_ISFIFO(record.metadata[2]) or
                        _meta(self._os.fstat(record.fd)) != record.metadata or
                        self._os.get_inheritable(record.fd) is not False or self._nonblocking(record.fd) is not True):
                    _fail('fd_unknown')
                site = 'clock'
                self._now(end)
            exact_fd()
            # A past incomplete observation can only stop the task. Its original
            # worker/ticket/FD are still actually checked while this cap permits.
            if ticket.notify_failure_v30 is not None: return True
            if ticket.notify_eof_v30: return True  # Historical EOF is stop-only, never child-exit proof.
            observed = {'deadline': end, 'fd_record': record, 'read_started': True,
                'returned': False, 'data': None, 'eagain': None, 'unknown': True}
            ticket.notify_last_v30 = observed  # Before the actual original read.
            site = 'read'
            try:
                data = self._os.read(record.fd, 17)
            except OSError as error:
                observed['eagain'] = error
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    exact_fd(); observed['unknown'] = False
                    return False
                _fail('fd_unknown')
            observed['data'], observed['returned'] = data, True
            site = 'data'
            if type(data) is not bytes or any(c != 82 for c in data) or ticket.notify_requests + len(data) > 16:
                _fail('fd_unknown')
            ticket.notify_requests += len(data)  # Retain consumed R count before any late postcheck.
            if not data: ticket.notify_eof_v30 = True
            exact_fd()
            observed['unknown'] = False
            return ticket.notify_eof_v30 or bool(data)
        except BaseException as failure:
            if site in ('scope', 'clock', 'data'):
                # Invalid payload/late clock do not themselves change the
                # original child or FD identity. Abort all network use, but let
                # existing cleanup freshly verify/reap/close those originals.
                ticket.notify_failure_v30 = ('invalid_data' if site == 'data' else
                    'deadline' if type(failure) is ProcessOwnerError and str(failure) == 'deadline' else
                    'observation_failed')
                if observed is not None: observed['unknown'] = True
            else:
                # Owner/FD mismatch and an unknown actual read still prohibit
                # native recovery; never reinterpret them as mere cancellation.
                ticket.unknown = True
                if record is not None: record.unknown = True
            raise

    def close_inventory(self, ticket, _absolute_deadline=None):
        self._exact(ticket)
        if self._active:
            return False
        if _absolute_deadline is not None: _time(_absolute_deadline)
        if ticket.parent is not None:
            try:
                end = self._bounded_deadline(self._now() + 3, _absolute_deadline)
                self._single(ticket, deadline=end)
            except BaseException:
                ticket.unknown = True
                return False
        good = True
        for record in ticket.fds:
            good = self._close_fd(ticket, record) and good
        return good and not ticket.unknown

    def status(self):
        """Passive fixed counts/enums only; no fs/clock/reader/close/callback."""
        return {'evidence': 'DIRECT_CHILD_OWNER_COMPONENT_ONLY', 'active': self._active,
            'ticket_count': len(self._tickets), 'fd_count': sum(len(t.fds) for t in self._tickets),
            'fd_closed_count': sum(r.closed for t in self._tickets for r in t.fds),
            'unknown_count': sum(t.unknown for t in self._tickets),
            'fork_claimed_count': sum(t.fork_requested for t in self._tickets),
            'pre_exec_count': sum(t.preexec is not None for t in self._tickets),
            'post_exec_count': sum(t.postexec is not None for t in self._tickets),
            'waited_count': sum(t.waited for t in self._tickets),
            'exit_observed_count': sum(t.exit_verified for t in self._tickets),
            'complete': False, 'provider_ready': False, 'orphan_recovery': False}
