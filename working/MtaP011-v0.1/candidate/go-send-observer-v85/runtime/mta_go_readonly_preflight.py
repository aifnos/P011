"""Fixed same-worker readonly preflight body; no network or restore grant.

Loaded only in the isolated v85 observer definition graph. Construction is
pure; collect() reads the existing device lock, two fixed helper capabilities
and the actual ReadonlyBaselineOwner51 double snapshot. The existing lock is
opened without O_CREAT and held by its original file description. No Store
acquire/reserve, Journal change, staging, adapter toggle, scan or pairing is
performed. Output is private DATA; Parent process/reap/binding/readback and
F fresh baseline still have to be implemented before production admission.

Original active and cleanup absolute caps come from the retained Parent
binding; no poll or error creates a new TTL. Unknown spawn/FD/close states
remain unknown. The caller cannot choose paths, executables or command flags.
"""
import ctypes
import errno
import hashlib
import math
import os
import re
import select
import stat
import subprocess
import sys
import threading
import time

import p011_json as json
import mta_client_readonly_baseline as readonly
import mta_snapshot_data as snapshots

ROOT = '/var/volatile/tmp/p011-mta-go-observer-v85'
STATE_ROOT = '/var/volatile/tmp/p011-mta-state-v69'
DEVICE_LOCK = '/var/volatile/tmp/p011-mta-p2p-device.lock'
PENDING = '/var/volatile/tmp/p011-mta-p2p-device.pending'
HELPERS = (
    (STATE_ROOT + '/native/mta-bluez-helper', 65832,
     '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363',
     ('--capabilities', 'hci0')),
    (STATE_ROOT + '/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6',
     ('--capabilities',)),
)
KEYS = frozenset(('nonce', 'task_id', 'native_epoch', 'operation_epoch',
                  'until', 'cleanup_until'))
MAX_PROBE_OUT, MAX_PROBE_ERR = 8192, 4096
MAX_ROWS, MAX_ACTIVE_SECONDS, MAX_CLEANUP_SECONDS = 3, 30.0, 5.0
ARM_READ = 0x88000


class ReadonlyPreflightError(ValueError):
    pass


def _fail(code): raise ReadonlyPreflightError(code) from None
def _sha(raw): return hashlib.sha256(raw).hexdigest()
def _finite(value): return type(value) is float and math.isfinite(value) and 0 < value < 1e12
def _meta(value):
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
            'st_size', 'st_mtime_ns', 'st_ctime_ns')
    result = tuple(getattr(value, key, None) for key in keys)
    if any(type(item) is not int or not 0 <= item < 1 << 64 for item in result):
        _fail('readonly_metadata')
    return result


def _descriptor_meta(value):
    # Child pipe writes legitimately change timestamps/size. Preserve the
    # original descriptor identity, not a file-content/timestamp snapshot.
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
    result = tuple(getattr(value, key, None) for key in keys)
    if any(type(item) is not int or not 0 <= item < 1 << 64 for item in result):
        _fail('readonly_descriptor_metadata')
    return result


def _binding(value):
    if type(value) is not dict or set(value) != KEYS:
        _fail('readonly_binding')
    if any(type(value[name]) is not str or re.fullmatch('[0-9a-f]{32}', value[name]) is None
           for name in ('nonce', 'task_id')):
        _fail('readonly_binding')
    if any(type(value[name]) is not int or not 1 <= value[name] < 1 << 53
           for name in ('native_epoch', 'operation_epoch')) or (
           value['native_epoch'] != value['operation_epoch']):
        _fail('readonly_binding')
    if not _finite(value['until']) or not _finite(value['cleanup_until']) or not (
            value['until'] <= value['cleanup_until'] <= value['until'] + MAX_CLEANUP_SECONDS):
        _fail('readonly_binding')
    return tuple((key, value[key]) for key in sorted(KEYS))


class _LinuxIo(object):
    def __init__(self): self.libc = None
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or
            os.geteuid() != 0 or os.uname()[4] != 'armv7l' or
            tuple(sys.version_info[:3]) != (3, 5, 5) or
            os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('readonly_platform')
        # Bind before later active-cap checks; flock itself must not perform
        # first-use library loading between its tight precheck and syscall.
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.flock.argtypes = (ctypes.c_int, ctypes.c_int)
        self.libc.flock.restype = ctypes.c_int
    def pid(self): return os.getpid()
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, ARM_READ)
    def read(self, fd, count): return os.read(fd, count)
    def fstat(self, fd): return os.fstat(fd)
    def close(self, fd): return os.close(fd)
    def flock(self, fd):
        if self.libc is None: _fail('readonly_platform_unvalidated')
        ctypes.set_errno(0)
        value = self.libc.flock(fd, 2 | 4)  # LOCK_EX|LOCK_NB; no explicit unlock/relock.
        return value, ctypes.get_errno()
    def spawn(self, fd, argv):
        return subprocess.Popen(argv, executable='/proc/self/fd/' + str(fd),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=(fd,), env={'LC_ALL': 'C'}, shell=False)
    def readable(self, fds, timeout): return select.select(fds, (), (), timeout)[0]


class ReadonlyPreflight(object):
    """Private original observer lifetime; not a receipt accepted by State."""
    def __init__(self, loader, binding, _io=None, _clock=None):
        # A source-defined class in the exact canonical loader module is needed;
        # paths, classes and callable admission flags are not supplied by the UI.
        module = sys.modules.get('mta_go_readonly_loader')
        cls = None if module is None else getattr(module, 'ReadonlySourceLoader', None)
        if (cls is None or type(loader) is not cls or
            getattr(module, 'ROOT', None) != ROOT):
            _fail('readonly_loader')
        self.loader, self.loader_module, self.loader_class = loader, module, cls
        self.binding, self.binding_original = binding, _binding(binding)
        self.until, self.cleanup_until = binding['until'], binding['cleanup_until']
        self.worker = threading.current_thread()
        self.io = self.io_original = _LinuxIo() if _io is None else _io
        self.clock = self.clock_original = time.monotonic if _clock is None else _clock
        if not callable(self.clock): _fail('readonly_clock')
        self.pid, self.last, self.roots = None, None, None
        self.rows, self.probes, self.pending_observations = [], [], []
        self.owner = self.owner_original = self.snapshot = self.result = None
        self.called = self.ended = self.closed = False
        self.unknown = False
        self.failure, self.close_errors = None, []
        self.flock_return = self.flock_errno = self.lock_metadata = None

    def _context(self):
        if (self.io is not self.io_original or self.clock is not self.clock_original or
            threading.current_thread() is not self.worker or
            sys.modules.get('mta_go_readonly_loader') is not self.loader_module or
            getattr(self.loader_module, 'ReadonlySourceLoader', None) is not self.loader_class or
            type(self.loader) is not self.loader_class or _binding(self.binding) != self.binding_original or
            self.until is not self.binding['until'] or self.cleanup_until is not self.binding['cleanup_until']):
            _fail('readonly_owner_changed')
        if self.pid is not None and self.io.pid() != self.pid: _fail('readonly_owner_changed')

    def _now(self, cleanup=False):
        self._context()
        now = self.clock()
        if type(now) not in (int, float) or not math.isfinite(float(now)) or not 0 <= now < 1e12:
            _fail('readonly_clock')
        if self.last is not None and now < self.last: _fail('readonly_clock')
        self.last = float(now)
        if now >= (self.cleanup_until if cleanup else self.until): _fail('readonly_expired')
        return float(now)

    def _anchors(self):
        result = []
        for path, mode, link in (
                ('/', None, None), ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                (ROOT, stat.S_IFDIR | 0o700, None),
                (ROOT + '/runtime', stat.S_IFDIR | 0o700, None),
                (STATE_ROOT, stat.S_IFDIR | 0o700, None),
                (STATE_ROOT + '/native', stat.S_IFDIR | 0o700, None)):
            self._now(); meta = _meta(self.io.stat(path))
            if (meta[3:5] != (0, 0) or meta[5] < 1 or
                mode is None and (not stat.S_ISDIR(meta[2]) or meta[2] & 0o022) or
                mode is not None and meta[2] != mode):
                _fail('readonly_root')
            if link is not None and (meta[5] != 1 or meta[6] != len(link) or
                                     self.io.readlink(path) != link):
                _fail('readonly_alias')
            result.append((path, meta if link is not None else meta[:5], link))
        value = tuple(result)
        if self.roots is None: self.roots = value
        elif value != self.roots: _fail('readonly_root_changed')
        return value

    def _pending_absent(self):
        self._now()
        try: self.io.stat(PENDING)
        except OSError as error:
            self.pending_observations.append(error)
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self._now(); return
            raise
        _fail('readonly_previous_restore_pending')

    def _open(self, path):
        if path not in (DEVICE_LOCK,) + tuple(row[0] for row in HELPERS) or len(self.rows) >= MAX_ROWS:
            _fail('readonly_fixed_path')
        self._now(); self._anchors(); self._now()
        row = dict(path=path, fd=None, metadata=None, unknown=True, open_called=True,
                   closed=False, close_called=False, close_return=None, close_error=None, raw=None)
        self.rows.append(row)
        try: row['fd'] = self.io.open(path)
        except OSError as error:
            row['open_error'] = error
            known = type(error.errno) is int and 1 <= error.errno <= 4095
            row['closed'], row['unknown'] = known, not known
            if not known: self.unknown = True
            raise
        except BaseException as error:
            row['open_error'] = error
            self.unknown = True; raise
        if type(row['fd']) is not int or row['fd'] < 0 or any(
                other is not row and not other['closed'] and other['fd'] == row['fd'] for other in self.rows):
            self.unknown = True; _fail('readonly_fd')
        row['metadata'] = _meta(self.io.fstat(row['fd']))
        row['unknown'] = False
        self._now()  # retain the returned descriptor before rejecting late IO
        return row

    def _current(self, row):
        self._now()
        if (row['unknown'] or row['closed'] or row['close_called'] or
            _meta(self.io.fstat(row['fd'])) != row['metadata'] or
            _meta(self.io.stat(row['path'])) != row['metadata']):
            _fail('readonly_file_changed')
        self._anchors()

    def _close_file(self, row):
        self._context()
        if row['close_called'] or row['closed']: return
        if row['unknown'] or type(row['fd']) is not int:
            self.unknown = True; return
        row['close_called'] = True
        try:
            if _meta(self.io.fstat(row['fd'])) != row['metadata']:
                _fail('readonly_close_identity_changed')
            row['close_return'] = self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = (row['close_return'] is None and
                    type(error.errno) is int and error.errno == errno.EBADF)
        except BaseException as error:
            row['close_failure'] = error
            self.close_errors.append(error); row['unknown'] = True
        if row['closed'] is not True: self.unknown = True

    def _helper(self, spec):
        path, size, pin, flags = spec
        row = self._open(path)
        meta = row['metadata']
        if (not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != 0o500 or
            meta[3:7] != (0, 0, 1, size)): _fail('readonly_helper_source')
        parts, total = [], 0
        while total <= size:
            self._now()
            count = min(65536, size + 1 - total)
            raw = self.io.read(row['fd'], count)
            if type(raw) is not bytes or len(raw) > count: _fail('readonly_helper_source')
            parts.append(raw); total += len(raw)
            if not raw: break
        raw = b''.join(parts); row['raw'] = raw
        if len(raw) != size or _sha(raw) != pin: _fail('readonly_helper_source')
        self._current(row); self._now()
        probe = dict(spec=spec, file=row, process=None, unknown=True, spawn_called=True,
                     waited=False, exit=None, pipes=[], eof=[], closed=False, close_called=False,
                     stdout=b'', stderr=b'', failure=None, capabilities=None)
        self.probes.append(probe)  # before actual spawn, including unknown return
        try: process = self.io.spawn(row['fd'], (path,) + flags)
        except BaseException as error:
            probe['failure'] = error; self.unknown = True; raise
        probe['process'] = process
        if not all(callable(getattr(process, name, None)) for name in ('poll', 'wait', 'kill')):
            self.unknown = True; _fail('readonly_helper_process')
        for name, maximum in (('stdout', MAX_PROBE_OUT), ('stderr', MAX_PROBE_ERR)):
            pipe = getattr(process, name, None)
            ticket = dict(name=name, maximum=maximum, pipe=pipe, fd=None, metadata=None, unknown=True,
                          closed=False, close_called=False, raw=b'')
            probe['pipes'].append(ticket)
            if not all(callable(getattr(pipe, item, None)) for item in ('fileno', 'close')):
                _fail('readonly_helper_pipe')
            ticket['fd'] = pipe.fileno()
            if type(ticket['fd']) is not int or ticket['fd'] < 0 or any(
                    ticket['fd'] == other['fd'] for old in self.probes for other in old['pipes']
                    if other is not ticket and not other['closed']):
                _fail('readonly_helper_pipe')
            ticket['metadata'] = _descriptor_meta(self.io.fstat(ticket['fd']))
            if not stat.S_ISFIFO(ticket['metadata'][2]):
                _fail('readonly_helper_pipe')
            ticket['unknown'] = False
        probe['unknown'] = False
        self._now()  # process and both original pipe tickets are retained first
        active = list(probe['pipes'])
        try:
            while active:
                ready = self.io.readable([ticket['fd'] for ticket in active], self.until - self._now())
                self._now()
                if type(ready) not in (list, tuple) or len(set(ready)) != len(ready) or any(
                        type(fd) is not int or fd not in [ticket['fd'] for ticket in active] for fd in ready):
                    _fail('readonly_helper_pipe')
                for ticket in tuple(active):
                    if ticket['fd'] not in ready: continue
                    self._pipe_current(probe, ticket)
                    count = min(4096, ticket['maximum'] + 1 - len(ticket['raw']))
                    self._now()
                    chunk = self.io.read(ticket['fd'], count)
                    if type(chunk) is not bytes or len(chunk) > count: _fail('readonly_helper_budget')
                    ticket['raw'] += chunk
                    self._now()  # preserve original read bytes, never renew the cap
                    if len(ticket['raw']) > ticket['maximum']: _fail('readonly_helper_budget')
                    if not chunk:
                        probe['eof'].append(ticket)
                        active.remove(ticket)
            code = process.wait(timeout=self.until - self._now())
            probe['exit'] = code
            polled = process.poll()
            probe['waited'] = type(code) is int and type(polled) is int and polled == code
            if not probe['waited'] or code != 0: _fail('readonly_helper_exit')
            probe['stdout'], probe['stderr'] = tuple(ticket['raw'] for ticket in probe['pipes'])
            if probe['stderr']: _fail('readonly_helper_stderr')
            value = json.loads(probe['stdout'].decode('utf-8'))
            if type(value) is not dict or value.get('event') != 'capabilities':
                _fail('readonly_helper_capabilities')
            probe['capabilities'] = value  # factual raw report, never GO permission
            self._current(row)
        except BaseException as error:
            probe['failure'] = error; raise
        finally:
            self._close_probe(probe)
            self._close_file(row)
        if not probe['closed'] or row['closed'] is not True or self.unknown:
            _fail('readonly_helper_unclosed')

    def _pipe_current(self, probe, ticket):
        if (ticket['unknown'] or getattr(probe['process'], ticket['name'], None) is not ticket['pipe'] or
            getattr(ticket['pipe'], 'closed', None) is True):
            _fail('readonly_pipe_changed')
        descriptor = ticket['pipe'].fileno()
        if (type(descriptor) is not int or descriptor != ticket['fd'] or
            _descriptor_meta(self.io.fstat(descriptor)) != ticket['metadata']):
            _fail('readonly_pipe_changed')

    def _close_probe(self, probe):
        self._context()
        if probe['close_called']: return
        probe['close_called'] = True
        process = probe['process']
        process_closed = False
        if process is not None and all(callable(getattr(process, name, None)) for name in ('poll', 'wait', 'kill')):
            try:
                code = process.poll()
                if type(code) is int and probe['waited'] is True and code == probe['exit']:
                    # Retain the actual earlier wait/reap; do not call wait again
                    # merely to manufacture a fresh cleanup-time success.
                    probe['cleanup_exit'] = code
                    process_closed = True
                else:
                    if code is None:
                        self._now(cleanup=True)
                        probe['kill_called'] = True
                        probe['kill_return'] = process.kill()
                    elif type(code) is not int:
                        _fail('readonly_helper_process')
                    code = process.wait(timeout=self.cleanup_until - self._now(cleanup=True))
                    probe['cleanup_exit'] = code
                    polled = process.poll()
                    process_closed = type(code) is int and type(polled) is int and polled == code
            except BaseException as error:
                self.close_errors.append(error); probe['close_failure'] = error
        for ticket in probe['pipes']:
            if ticket['close_called'] or ticket['closed']: continue
            ticket['close_called'] = True
            if ticket['unknown'] or getattr(process, ticket['name'], None) is not ticket['pipe']:
                self.unknown = True; continue
            try:
                self._pipe_current(probe, ticket)
                returned = ticket['pipe'].close()
                try: self.io.fstat(ticket['fd'])
                except OSError as error:
                    ticket['closed'] = (returned is None and
                        getattr(ticket['pipe'], 'closed', None) is True and
                        type(error.errno) is int and error.errno == errno.EBADF)
            except BaseException as error:
                self.close_errors.append(error)
            if ticket['closed'] is not True: self.unknown = True
        probe['closed'] = (not probe['unknown'] and process_closed and len(probe['pipes']) == 2 and
                           all(ticket['closed'] and not ticket['unknown'] for ticket in probe['pipes']))
        if not probe['closed']: self.unknown = True

    def collect(self):
        if self.called: _fail('readonly_already_called')
        self.called = True
        try:
            self._context()
            self.loader_class.authenticate(self.loader)
            if self.loader.until != self.until: _fail('readonly_cap_changed')
            issued = self._now()
            if not 0 < self.until - issued <= MAX_ACTIVE_SECONDS: _fail('readonly_cap')
            self.io.validate(); self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid < 1 << 31: _fail('readonly_pid')
            self._anchors(); self._pending_absent()
            lock = self._open(DEVICE_LOCK)
            meta = lock['metadata']
            if (not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != 0o600 or
                meta[3:7] != (0, 0, 1, 0)): _fail('readonly_existing_lock')
            self._now()
            self.flock_return, self.flock_errno = self.io.flock(lock['fd'])
            if type(self.flock_return) is not int or self.flock_return != 0 or (
                    type(self.flock_errno) is not int or self.flock_errno != 0):
                _fail('readonly_lock_busy_or_unknown')
            self.lock_metadata = meta
            self._current(lock); self._pending_absent()
            for spec in HELPERS: self._helper(spec)
            self._current(lock); self._pending_absent()
            # The actual collector requires single-thread self Proc. This body
            # is never inserted into the multi-thread State worker.
            self.owner = readonly.ReadonlyBaselineOwner(self.binding['nonce'], self.until, _clock=self._now)
            self.owner_original = self.owner
            self.snapshot = self.owner.collect()
            if (self.owner is not self.owner_original or self.owner.result is not self.snapshot or
                not self.owner.read_success or self.owner.resource_pending):
                _fail('readonly_snapshot_unclosed')
            raw = snapshots.encode_snapshot(self.snapshot)
            key_sha = snapshots.key_digest(self.snapshot)
            self._current(lock); self._pending_absent()
            self.loader_class.authenticate(self.loader)
            self._now()
            self.result = dict(schema='p011-go-preflight-data-v85', binding=self.binding_original,
                snapshot_raw=raw, stable_key_sha256=key_sha,
                helper_raw=tuple((probe['spec'][0], probe['stdout'], probe['stderr']) for probe in self.probes),
                lock_metadata=self.lock_metadata,
                source_manifest_sha256=readonly.SOURCE_MANIFEST_SHA,
                source_count=len(self.loader.module_originals), active_until=self.until,
                cleanup_until=self.cleanup_until,
                rf_requested=False, restoration_verified=False, production_admitted=False)
        except BaseException as error:
            self.failure = error; raise
        finally:
            for probe in reversed(self.probes):
                try: self._close_probe(probe)
                except BaseException as error: self.close_errors.append(error); self.unknown = True
            for row in reversed(self.rows):
                try: self._close_file(row)
                except BaseException as error: self.close_errors.append(error); self.unknown = True
            self.ended = True
            self.closed = (not self.unknown and not self.close_errors and
                all(row['closed'] and not row['unknown'] for row in self.rows) and
                all(probe['closed'] and not probe['unknown'] for probe in self.probes) and
                (self.owner is None or self.owner is self.owner_original and
                 self.owner.ended and not self.owner.resource_pending))
        try:
            if not self.closed: _fail('readonly_preflight_unclosed')
            self._now()
        except BaseException as error:
            if self.failure is None: self.failure = error
            raise
        return self.result

    def status(self):
        return dict(called=self.called, ended=self.ended, local_inventory_closed=self.closed,
            resource_pending=self.unknown or not self.closed,
            failed=self.failure is not None, helper_process_count=len(self.probes),
            observer_source_count=len(self.loader.module_originals),
            actual_snapshot_retained=self.snapshot is not None,
            rf_requested=False, restoration_verified=False, production_admitted=False,
            send_available=False, receive_available=False)
