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

ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
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


# v94 terminal observer SOURCE candidate, cleanup-only fixed limits. The entire v85 body above is retained
# verbatim, including MAX_ROWS=3 and its helper-capability path. This separate
# class does NOT call that path. Loader38/Entry/Parent still need a new source
# binding before this terminal class can be launched; no default entry is added.
import mta_client_journal_codec as terminal_facts
import mta_client_proc as terminal_proc
import mta_p2p_client_init as terminal_core

TERMINAL_MAX_ROWS = 4  # Existing device lock + journal lock + two journal reads.
TERMINAL_MAX_JOURNAL = 131072
TERMINAL_MAX_FINISH = 4096
TERMINAL_GO_ROOT = '/var/volatile/tmp/p011-mta-go-session'
TERMINAL_GO_SCHEMA = 'p011-go-typed-live-v72'
_TERMINAL_LAUNCH_KEYS = frozenset(('run', 'manifest', 'task', 'nonce',
    'native_epoch', 'operation_epoch', 'until', 'candidate_sha', 'child_pid'))
_TERMINAL_FINISH_KEYS = frozenset(('schema', 'provenance', 'binding', 'journal',
    'cleanup_until', 'finished_at', 'device_lock_metadata', 'f_actor', 'f_actor_data',
    'children', 'children_outcomes', 'inventory_counts', 'business_failed_at_capture',
    'native_full_inventory_export', 'independent_restore_verified', 'production_admitted'))
_TERMINAL_JOURNAL_KEYS = frozenset(('schema', 'run_token', 'candidate_sha',
    'task_id', 'boot_id', 'issued_at', 'until', 'phase', 'generation', 'baseline',
    'interface_intent', 'owned', 'watchdog', 'controller', 'group_add',
    'group_observed', 'cleanup_until', 'restored', 'ip', 'dhcp'))
_TERMINAL_DEFINITIONS = (
    readonly, readonly.ReadonlyBaselineOwner, readonly.ReadonlyBaselineOwner.collect,
    readonly.ReadonlyBaselineOwner._closed, terminal_facts, terminal_facts._actor,
    terminal_facts._snapshot, terminal_core, terminal_core.Actor, terminal_core.Snapshot,
    terminal_proc, terminal_proc.ProcReader, terminal_proc.ProcGeneration,
    terminal_proc.ProcObservation, terminal_proc.ProcReader.read_absence,
    terminal_proc.ProcReader.owns_generation, terminal_proc.ProcReader.history_closed,
    terminal_proc.ProcReader.closed_open_ticket, snapshots, snapshots.encode_snapshot,
    snapshots.key_digest,
)


def _terminal_uint(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def _terminal_hex(value, width):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(width) + '}', value) is not None


def _terminal_number(value):
    return type(value) is float and math.isfinite(value) and 0 <= value < 1e12


def _terminal_time_text(value):
    if type(value) is not str or not 1 <= len(value) <= 32:
        _fail('terminal_launch_time')
    try: parsed = float(value)
    except ValueError: _fail('terminal_launch_time')
    if not _finite(parsed) or repr(parsed) != value:
        _fail('terminal_launch_time')
    return parsed


def _terminal_metadata(value):
    return (type(value) is list and len(value) == 9 and
            all(_terminal_uint(item) for item in value))


def _terminal_launch(value):
    # These nine DATA facts must be exported from original Bridge/Publisher
    # objects by the future caller, not inferred from finish itself.
    if (type(value) is not dict or set(value) != _TERMINAL_LAUNCH_KEYS or
        any(not _terminal_hex(value[name], 32) for name in ('run', 'task', 'nonce')) or
        any(not _terminal_hex(value[name], 64) for name in ('manifest', 'candidate_sha')) or
        any(not _terminal_uint(value[name], 1, (1 << 53) - 1) for name in
            ('native_epoch', 'operation_epoch')) or
        value['native_epoch'] != value['operation_epoch'] or
        not _terminal_uint(value['child_pid'], 1, 0x7fffffff)):
        _fail('terminal_launch_binding')
    _terminal_time_text(value['until'])
    return tuple((name, value[name]) for name in sorted(_TERMINAL_LAUNCH_KEYS))


def _terminal_cleanup_limits(value, launch):
    # Four fixed parent-origin cleanup DATA, never a renewed sending period.
    # The same-worker caller must bind them to original State/Bridge objects.
    keys = {'task_until', 'service_until', 'go_cleanup_until', 'service_cleanup_until'}
    if (type(value) is not dict or set(value) != keys or
        any(not _terminal_number(value[name]) or value[name] <= 0 for name in keys) or
        value['task_until'] != _terminal_time_text(launch['until']) or
        value['task_until'] > value['service_until'] or
        value['go_cleanup_until'] > value['task_until'] + 60.0 or
        value['service_cleanup_until'] != value['service_until'] + 60.0):
        _fail('terminal_cleanup_limits')
    return tuple((name, value[name]) for name in sorted(keys))


def _terminal_actor(value):
    # Pure expected identity DATA. No live/read/absence/reap fact is created.
    # Proc DATA can contain P, but existing Core.Actor rejects it: that branch
    # remains unavailable rather than changing the original Core state gate.
    actor = terminal_facts._actor(value)
    if tuple(task[0] for task in actor.tasks) != tuple(sorted(task[0] for task in actor.tasks)):
        _fail('terminal_actor_tasks_order')
    return actor


def _terminal_finish(raw, launch):
    if (type(raw) is not bytes or not 1 <= len(raw) <= TERMINAL_MAX_FINISH or
            not raw.startswith(b'GOFINISH84=') or not raw.endswith(b'\n')):
        _fail('terminal_finish_format')
    try: value = json.loads(raw[len(b'GOFINISH84='):-1].decode('ascii'))
    except (UnicodeError, ValueError): _fail('terminal_finish_format')
    if (type(value) is not dict or set(value) != _TERMINAL_FINISH_KEYS or
        ('GOFINISH84=' + json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii') != raw):
        _fail('terminal_finish_canonical')
    binding, journal = value['binding'], value['journal']
    bind_keys = _TERMINAL_LAUNCH_KEYS - {'candidate_sha', 'child_pid'}
    journal_keys = {'schema', 'phase', 'generation', 'sha256', 'bytes', 'metadata', 'facts_key'}
    if (value['schema'] != 'p011-go-finish-data-v93' or value['provenance'] != 'returned_restore' or
        type(binding) is not dict or set(binding) != bind_keys or any(
            type(binding[name]) is not type(launch[name]) or binding[name] != launch[name] for name in bind_keys) or
        type(journal) is not dict or set(journal) != journal_keys or
        journal['schema'] != TERMINAL_GO_SCHEMA or journal['phase'] != 'reconciled' or
        not _terminal_uint(journal['generation'], 1, 25) or
        not _terminal_hex(journal['sha256'], 64) or
        not _terminal_uint(journal['bytes'], 1, TERMINAL_MAX_JOURNAL) or
        not _terminal_metadata(journal['metadata'])):
        _fail('terminal_finish_binding')
    meta, key = journal['metadata'], journal['facts_key']
    if (not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != 0o600 or
        meta[3:6] != [0, 0, 1] or meta[6] != journal['bytes'] or
        type(key) is not list or len(key) != 7 or
        key[:4] != [TERMINAL_GO_SCHEMA, launch['run'], launch['candidate_sha'], launch['task']] or
        type(key[4]) is not str or
        re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', key[4]) is None or
        not _terminal_number(key[5]) or not _terminal_number(key[6]) or
        key[6] != _terminal_time_text(launch['until']) or not 0 < key[6] - key[5] <= 300 or
        not _terminal_number(value['cleanup_until']) or
        not _terminal_number(value['finished_at']) or
        value['finished_at'] >= value['cleanup_until']):
        _fail('terminal_finish_journal')
    lock, actor, children, outcomes, counts = (value[name] for name in
        ('device_lock_metadata', 'f_actor', 'children', 'children_outcomes', 'inventory_counts'))
    if (not _terminal_metadata(lock) or not stat.S_ISREG(lock[2]) or
        stat.S_IMODE(lock[2]) != 0o600 or lock[3:7] != [0, 0, 1, 0] or
        type(actor) is not list or len(actor) != 3 or
        not _terminal_uint(actor[0], 1, 0x7fffffff) or actor[0] != launch['child_pid'] or
        not _terminal_uint(actor[1], 1) or not _terminal_hex(actor[2], 64) or
        type(children) is not list or len(children) > 2 or
        type(outcomes) is not list or len(outcomes) != len(children) or
        type(counts) is not list or len(counts) != 2 or
        not _terminal_uint(counts[0], 8, 256) or not _terminal_uint(counts[1], 0, 8192) or
        type(value['business_failed_at_capture']) is not bool or any(value[name] is not False for name in
            ('native_full_inventory_export', 'independent_restore_verified', 'production_admitted'))):
        _fail('terminal_finish_inventory')
    factor = _terminal_actor(value['f_actor_data'])
    if (type(factor) is not terminal_core.Actor or factor.exe != '/usr/bin/python3.5' or
            [factor.pid, factor.start, factor.argv_sha] != actor):
        _fail('terminal_finish_actor')
    roles = []
    outcome_keys = {'role', 'fork_requested', 'fork_negative', 'waited', 'exit_verified', 'actor_present'}
    for child, outcome in zip(children, outcomes):
        if (type(child) is not list or len(child) != 3 or type(child[0]) is not str or
            child[0] not in ('controller', 'watchdog') or child[0] in roles or
            not (child[1] is None and child[2] is None or
                 _terminal_uint(child[1], 1, 0x7fffffff) and _terminal_uint(child[2], 1)) or
            type(outcome) is not dict or set(outcome) != outcome_keys or
            type(outcome['role']) is not str or outcome['role'] != child[0] or
            any(type(outcome[name]) is not bool for name in outcome_keys - {'role'}) or
            outcome['actor_present'] is not (child[1] is not None) or
            outcome['fork_negative'] and not outcome['fork_requested']):
            _fail('terminal_finish_children')
        if not outcome['fork_requested'] or outcome['fork_negative']:
            if outcome['actor_present'] or outcome['waited'] or outcome['exit_verified']:
                _fail('terminal_finish_children')
        elif not (outcome['actor_present'] and outcome['waited'] and outcome['exit_verified']):
            _fail('terminal_finish_children')
        roles.append(child[0])
    return value, factor


class ReadonlyTerminalObserver(ReadonlyPreflight):
    """Independent readonly terminal DATA producer, not a recovery receipt.

    Original absolute observer caps and original launch facts are required.
    Two existing flock descriptions remain held over journal read1, actual
    double Snapshot, all newly issued Proc absence operations, and read2.
    Exactly four file tickets are allowed. No helper, GO Store, pending delete,
    acquire, adapter/GATT/WiFi action, Parent wait or reap occurs in this class.
    """

    def __init__(self, loader, observer_binding, finish_raw, launch_binding, cleanup_limits):
        ReadonlyPreflight.__init__(self, loader, observer_binding)
        self.launch = launch_binding
        self.launch_original = _terminal_launch(launch_binding)
        self.launch_raw = json.dumps(launch_binding, ensure_ascii=True, sort_keys=True).encode('ascii')
        self.finish_raw = self.finish_raw_original = finish_raw
        self.finish, self.expected_f_actor = _terminal_finish(finish_raw, launch_binding)
        self.expected_f_actor_original = self.expected_f_actor
        self.finish_original = self.finish
        self.finish_sha256 = _sha(finish_raw)
        self.launch_until = _terminal_time_text(launch_binding['until'])
        self.cleanup_limits = cleanup_limits
        self.cleanup_limits_original = _terminal_cleanup_limits(cleanup_limits, launch_binding)
        self.cleanup_limits_raw = json.dumps(cleanup_limits, ensure_ascii=True, sort_keys=True).encode('ascii')
        if (observer_binding['nonce'] == launch_binding['nonce'] or
            observer_binding['task_id'] != launch_binding['task'] or
            observer_binding['native_epoch'] != launch_binding['native_epoch'] or
            observer_binding['operation_epoch'] != launch_binding['operation_epoch'] or
            self.cleanup_until > min(cleanup_limits['go_cleanup_until'],
                cleanup_limits['service_cleanup_until'], self.finish['cleanup_until'])):
            _fail('terminal_observer_binding')
        self.run_path = TERMINAL_GO_ROOT + '/go-' + launch_binding['run']
        self.journal_path = self.run_path + '/go-journal.json'
        self.journal_lock_path = self.run_path + '/go-journal.lock'
        self.paths_original = (self.run_path, self.journal_path, self.journal_lock_path)
        self.definitions_original = _TERMINAL_DEFINITIONS
        self.rows_original, self.row_history = self.rows, ()
        self.locks, self.journal_reads, self.absences = [], [], []
        self.owner_attempt = None
        self.owner_facts_original = None
        self.expected_baseline = self.expected_restored = None
        self.expected_snapshot_originals = None
        self.snapshot_rounds = self.snapshot_rounds_original = ()
        self.journal_data = self.journal_data_original = None
        self.pending_result = None
        self.local_closed = False
        self.source_authenticated = False

    def _context(self):
        ReadonlyPreflight._context(self)
        current = (
            readonly, readonly.ReadonlyBaselineOwner, readonly.ReadonlyBaselineOwner.collect,
            readonly.ReadonlyBaselineOwner._closed, terminal_facts, terminal_facts._actor,
            terminal_facts._snapshot, terminal_core, terminal_core.Actor, terminal_core.Snapshot,
            terminal_proc, terminal_proc.ProcReader, terminal_proc.ProcGeneration,
            terminal_proc.ProcObservation, terminal_proc.ProcReader.read_absence,
            terminal_proc.ProcReader.owns_generation, terminal_proc.ProcReader.history_closed,
            terminal_proc.ProcReader.closed_open_ticket, snapshots, snapshots.encode_snapshot,
            snapshots.key_digest,
        )
        if (self.definitions_original is not _TERMINAL_DEFINITIONS or
            any(a is not b for a, b in zip(current, self.definitions_original)) or
            self.rows is not self.rows_original or type(self.rows) is not list or
            type(self.row_history) is not tuple or len(self.rows) != len(self.row_history) or
            len(self.rows) > TERMINAL_MAX_ROWS or
            any(a is not b for a, b in zip(self.rows, self.row_history)) or
            _terminal_launch(self.launch) != self.launch_original or
            _terminal_cleanup_limits(self.cleanup_limits, self.launch) != self.cleanup_limits_original or
            json.dumps(self.cleanup_limits, ensure_ascii=True, sort_keys=True).encode('ascii') != self.cleanup_limits_raw or
            self.cleanup_until > min(self.cleanup_limits['go_cleanup_until'],
                self.cleanup_limits['service_cleanup_until'], self.finish['cleanup_until']) or
            json.dumps(self.launch, ensure_ascii=True, sort_keys=True).encode('ascii') != self.launch_raw or
            self.finish_raw is not self.finish_raw_original or
            self.finish is not self.finish_original or _sha(self.finish_raw) != self.finish_sha256 or
            self.expected_f_actor is not self.expected_f_actor_original or
            self.snapshot_rounds is not self.snapshot_rounds_original or
            self.expected_snapshot_originals is not None and (
                self.expected_baseline is not self.expected_snapshot_originals[0] or
                self.expected_restored is not self.expected_snapshot_originals[1]) or
            ('GOFINISH84=' + json.dumps(self.finish, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii') != self.finish_raw or
            (self.run_path, self.journal_path, self.journal_lock_path) != self.paths_original):
            _fail('terminal_original_changed')
        for name, module in (('mta_client_readonly_baseline', readonly),
                ('mta_client_journal_codec', terminal_facts), ('mta_client_proc', terminal_proc),
                ('mta_p2p_client_init', terminal_core), ('mta_snapshot_data', snapshots)):
            if self.loader.modules.get(name) is not module or sys.modules.get(name) is not module:
                _fail('terminal_source_domain')

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
                (TERMINAL_GO_ROOT, stat.S_IFDIR | 0o700, None),
                (self.run_path, stat.S_IFDIR | 0o700, None)):
            self._now()
            meta = _meta(self.io.stat(path))
            if (meta[3:5] != (0, 0) or meta[5] < 1 or
                mode is None and (not stat.S_ISDIR(meta[2]) or meta[2] & 0o022) or
                mode is not None and meta[2] != mode):
                _fail('terminal_root')
            if link is not None and (meta[5] != 1 or meta[6] != len(link) or self.io.readlink(path) != link):
                _fail('terminal_alias')
            result.append((path, meta if link is not None else meta[:5], link))
        value = tuple(result)
        if self.roots is None: self.roots = value
        elif self.roots != value: _fail('terminal_root_changed')
        self._now()
        return value

    def _open(self, path):
        if (path not in (DEVICE_LOCK, self.journal_lock_path, self.journal_path) or
            len(self.rows) >= TERMINAL_MAX_ROWS or
            path != self.journal_path and any(row['path'] == path for row in self.rows) or
            path == self.journal_path and sum(row['path'] == path for row in self.rows) >= 2):
            _fail('terminal_fixed_path')
        self._now(); self._anchors(); self._now()
        row = dict(path=path, fd=None, fd_original=None, metadata=None,
            metadata_original=None, unknown=True, open_called=True, returned=False,
            closed=False, close_called=False, close_return=None, close_error=None,
            raw=None, reads=[], open_error=None)
        self.rows.append(row)
        self.row_history += (row,)  # Pre-factory original ticket.
        try: fd = self.io.open(path)
        except OSError as error:
            row['open_error'] = error
            known = type(error.errno) is int and 1 <= error.errno <= 4095
            row['closed'], row['unknown'] = known, not known
            if not known: self.unknown = True
            raise
        except BaseException as error:
            row['open_error'] = error; self.unknown = True; raise
        row['fd'] = row['fd_original'] = fd
        row['returned'] = True  # Retain before metadata/active deadline checks.
        if (not _terminal_uint(fd, 0, 0x7fffffff) or any(
                old is not row and not old['closed'] and old['fd'] == fd for old in self.rows)):
            self.unknown = True; _fail('terminal_fd')
        row['metadata'] = row['metadata_original'] = _meta(self.io.fstat(fd))
        row['unknown'] = False
        self._now()
        return row

    def _current(self, row):
        self._now()
        if (not any(row is original for original in self.row_history) or
            row['unknown'] is not False or row['closed'] is not False or row['close_called'] is not False or
            row['returned'] is not True or row['fd'] is not row['fd_original'] or
            row['metadata'] is not row['metadata_original'] or
            _meta(self.io.fstat(row['fd'])) != row['metadata'] or
            _meta(self.io.stat(row['path'])) != row['metadata']):
            _fail('terminal_file_changed')
        self._anchors(); self._now()

    def _close_file(self, row):
        # No active/cleanup deadline gate here: known original once-close is
        # permitted after expiry. Unknown identity is never retried or washed.
        self._context()
        if not any(row is original for original in self.row_history):
            _fail('terminal_close_row')
        if row['closed'] or row['close_called']: return
        if (row['unknown'] or row['returned'] is not True or row['fd'] is not row['fd_original'] or
                row['metadata'] is not row['metadata_original']):
            self.unknown = True; return
        row['close_called'] = True
        try:
            if _meta(self.io.fstat(row['fd'])) != row['metadata']:
                _fail('terminal_close_identity')
            row['close_return'] = self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = (row['close_return'] is None and type(error.errno) is int and
                                 error.errno == errno.EBADF)
        except BaseException as error:
            row['close_failure'] = error
            self.close_errors.append(error)
            row['unknown'] = True
        if row['closed'] is not True:
            row['unknown'] = self.unknown = True

    def _lock(self, path, expected=None):
        row = self._open(path)
        self.locks.append(row)  # Retain original lock before permission/flock.
        meta = row['metadata']
        if (not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != 0o600 or
                meta[3:7] != (0, 0, 1, 0) or expected is not None and tuple(expected) != meta):
            _fail('terminal_existing_lock')
        self._current(row); self._now()
        row['flock_called'] = True
        row['flock_return'] = self.io.flock(row['fd'])
        returned = row['flock_return']
        if (type(returned) is not tuple or len(returned) != 2 or
                type(returned[0]) is not int or returned[0] != 0 or
                type(returned[1]) is not int or returned[1] != 0):
            _fail('terminal_lock_busy_or_unknown')
        row['flock_original'] = returned
        self._now(); self._current(row)
        return row

    def _locks_current(self):
        if len(self.locks) != 2 or tuple(row['path'] for row in self.locks) != (
                DEVICE_LOCK, self.journal_lock_path):
            _fail('terminal_locks')
        for row in self.locks:
            if (row.get('flock_called') is not True or
                    row.get('flock_return') is not row.get('flock_original')):
                _fail('terminal_locks')
            self._current(row)
        self._pending_absent()

    def _journal_read(self):
        self._locks_current()
        row = self._open(self.journal_path)
        self.journal_reads.append(row)
        expected = self.finish['journal']
        if row['metadata'] != tuple(expected['metadata']):
            _fail('terminal_journal_metadata')
        parts, size = [], 0
        while size <= expected['bytes']:
            self._current(row); self._now()
            count = min(65536, expected['bytes'] + 1 - size)
            raw = self.io.read(row['fd'], count)
            row['reads'].append(raw)  # Original returned bytes before postcheck.
            if type(raw) is not bytes or len(raw) > count: _fail('terminal_journal_read')
            parts.append(raw); size += len(raw)
            row['raw'] = b''.join(parts)
            self._now()
            if not raw: break
        if size != expected['bytes'] or _sha(row['raw']) != expected['sha256']:
            _fail('terminal_journal_sha')
        self._current(row); self._locks_current()
        self._close_file(row)
        if row['closed'] is not True or row['unknown'] is not False:
            _fail('terminal_journal_unclosed')
        return row['raw']

    def _journal_decode(self, raw):
        # Narrow primitive GO journal consumer, NOT CLIENT decode_journal and
        # NOT GoRecord/GoStore construction or durable canonical authority.
        try: value = json.loads(raw.decode('ascii'))
        except (UnicodeError, ValueError): _fail('terminal_journal_format')
        if (type(value) is not dict or set(value) != _TERMINAL_JOURNAL_KEYS or
                json.dumps(value, ensure_ascii=True, sort_keys=True).encode('ascii') != raw):
            _fail('terminal_journal_canonical')
        key = [value[name] for name in ('schema', 'run_token', 'candidate_sha',
                'task_id', 'boot_id', 'issued_at', 'until')]
        if (key != self.finish['journal']['facts_key'] or
            any(type(a) is not type(b) for a, b in zip(key, self.finish['journal']['facts_key'])) or
            value['phase'] != 'reconciled' or
            type(value['generation']) is not int or
            value['generation'] != self.finish['journal']['generation'] or
            not _terminal_number(value['cleanup_until']) or
            value['cleanup_until'] != self.finish['cleanup_until']):
            _fail('terminal_journal_facts')
        expected, restored = (terminal_facts._snapshot(value[name]) for name in ('baseline', 'restored'))
        if (type(expected) is not terminal_core.Snapshot or type(restored) is not terminal_core.Snapshot or
            expected.boot != key[4] or restored.boot != key[4] or
            expected.key() != restored.key()):
            _fail('terminal_journal_snapshot')
        # Terminal phase DATA only. The actual kernel/whole inventory claim is
        # not inferred from a restored/closed word in this JSON.
        if value['ip'] is not None and (type(value['ip']) is not dict or
                set(value['ip']) != {'phase', 'origin', 'spec', 'request', 'address'} or
                value['ip']['phase'] != 'restored'):
            _fail('terminal_journal_ip')
        if value['dhcp'] is not None and (type(value['dhcp']) is not dict or
                set(value['dhcp']) != {'phase', 'origin', 'server_ip', 'client_ip', 'prefix', 'until'} or
                value['dhcp']['phase'] != 'closed' or type(value['dhcp']['until']) is not float or
                value['dhcp']['until'] != key[6]):
            _fail('terminal_journal_dhcp')
        children = dict((row[0], (row, outcome)) for row, outcome in
                        zip(self.finish['children'], self.finish['children_outcomes']))
        actors = [('f', self.expected_f_actor)]
        child_keys = {'phase', 'spec_sha', 'argv_sha', 'until', 'actor'}
        for role in ('controller', 'watchdog'):
            child = value[role]
            if child is not None and (type(child) is not dict or set(child) != child_keys or
                type(child['phase']) is not str or child['phase'] not in ('intent', 'preexec', 'live') or
                not _terminal_hex(child['spec_sha'], 64) or not _terminal_hex(child['argv_sha'], 64) or
                not _terminal_number(child['until']) or child['until'] != key[6] or
                (child['phase'] == 'intent') is not (child['actor'] is None)):
                _fail('terminal_journal_child')
            pair = children.get(role)
            if pair is None:
                # A missing F role is not a never-fork certificate.
                if child is not None: _fail('terminal_child_outcome_missing')
                continue
            row, outcome = pair
            if not outcome['fork_requested'] or outcome['fork_negative']:
                if child is not None and child['actor'] is not None:
                    _fail('terminal_child_negative_conflict')
                continue  # Only explicit original ticket outcome DATA permits this.
            if child is None or child['actor'] is None:
                _fail('terminal_child_actor_unavailable')
            actor = _terminal_actor(child['actor'])
            if type(actor) is not terminal_core.Actor or (actor.pid, actor.start) != tuple(row[1:]):
                _fail('terminal_child_actor_mismatch')
            # A live Journal actor is postexec; the F triple is preexec.
            # Compare PID/start only, then sample ALL tasks from the full actor.
            if child['phase'] == 'live' and actor.argv_sha != child['argv_sha']:
                _fail('terminal_child_live_argv')
            actors.append((role, actor))
        if len({actor.pid for role, actor in actors}) != len(actors):
            _fail('terminal_actor_duplicate')
        self.expected_baseline, self.expected_restored = expected, restored
        self.expected_snapshot_originals = (expected, restored)
        return value, tuple(actors)

    def _owner_current(self):
        original = self.owner_facts_original
        owner = self.owner
        if (type(original) is not tuple or len(original) != 6 or type(owner) is not readonly.ReadonlyBaselineOwner or
            owner is not self.owner_original or original[0] is not owner or
            owner.reader is not original[1] or owner.store is not original[2] or
            owner.budget is not original[3] or owner.io is not original[4] or
            owner.identity is not original[5] or type(owner.reader) is not terminal_proc.ProcReader or
            owner.until != self.until or owner.ended is not True or owner.read_success is not True or
            owner.result is not self.snapshot):
            _fail('terminal_readonly_owner')
        owner._neutral()
        if owner._closed() is not True or owner.reader.history_closed() is not True:
            _fail('terminal_readonly_unclosed')
        budget = owner.budget.status()  # Fresh AFTER every new absence, not cached collect().
        if (type(budget) is not dict or budget['resource_pending'] is not False or
            budget['active_producers'] != 0 or budget['owner_changed'] is not False or
            budget['payload_overrun'] is not False):
            _fail('terminal_readonly_budget')
        for row in self.absences:
            if row['closed'] is True and (row['reader'] is not owner.reader or
                    owner.reader.owns_generation(row['generation']) is not True or
                    row['generation'].observation is not row['value']):
                _fail('terminal_proc_original_changed')
        return owner.reader

    def _absence(self, role, actor, boot):
        reader = self._owner_current()
        self._locks_current(); self._now()
        if type(reader._history) is not list: _fail('terminal_proc_history')
        prior = tuple(reader._history)
        row = dict(role=role, actor=actor, boot=boot, reader=reader, prior=prior,
            until=self.until, called=True, returned=False, value=None, generation=None,
            error=None, closed=False)
        self.absences.append(row)  # Before actual reader operation.
        try:
            value = reader.read_absence(actor, boot, _absolute_deadline=self.until)
            row['value'], row['returned'] = value, True  # Same original before checking/late clock.
            history = reader._history
            if (type(history) is not list or len(history) != len(prior) + 1 or
                    any(a is not b for a, b in zip(prior, history))):
                _fail('terminal_proc_generation')
            generation = history[-1]
            row['generation'] = generation
            if (type(generation) is not terminal_proc.ProcGeneration or generation.reader is not reader or
                generation._issuer is not reader._issuer or generation.ordinal != len(prior) or
                generation.budget is not self.owner.budget or generation.absolute_deadline is not self.until or
                generation.observation is not value or generation.ended is not True or
                generation.active is not False or generation.unknown is not False or generation.late is not False or
                reader.owns_generation(generation) is not True or
                any(reader.closed_open_ticket(ticket) is not True for ticket in generation.tickets)):
                _fail('terminal_proc_generation')
            if (type(value) is not terminal_proc.ProcObservation or value.kind != 'absence' or
                value.reason != 'absence_observed' or value.boot != boot or value.same_boot is not True or
                type(value.passes) is not int or value.passes != 2 or value.pid_path_absent is not True or
                type(value.remaining_tasks) is not tuple or value.remaining_tasks != () or
                value.resource_pending is not False or value.reap_complete is not False or
                type(value.file_count) is not int or type(value.closed_count) is not int or
                value.file_count != value.closed_count):
                _fail('terminal_proc_absence')
            self._owner_current()
            row['closed'] = True
            self._locks_current(); self._now()
        except BaseException as error:
            row['error'] = error
            # Retain all generations appended even when no successful value
            # returned; no rebuild, close retry, or discarded partial history.
            row['after'] = tuple(reader._history)
            raise
        return value

    def _terminal_inventory(self):
        self._context()
        local = (not self.unknown and not self.close_errors and
            all(row['closed'] is True and row['unknown'] is False for row in self.row_history))
        self.local_closed = local
        if self.owner_attempt is None:
            return local
        if self.owner is None or self.owner_attempt['returned'] is not True:
            return False
        try:
            self._owner_current()
            return local and all(row['closed'] is True for row in self.absences)
        except BaseException as error:
            self.inventory_error = error
            return False

    def collect(self):
        if self.called: _fail('terminal_already_called')
        self.called = True
        try:
            self._context(); self.loader_class.authenticate(self.loader)
            if self.loader.until != self.until: _fail('terminal_cap_changed')
            issued = self._now()
            if not 0 < self.until - issued <= MAX_ACTIVE_SECONDS: _fail('terminal_cap')
            self.io.validate(); self.pid = self.io.pid()
            if not _terminal_uint(self.pid, 1, 0x7fffffff): _fail('terminal_pid')
            self._anchors(); self._pending_absent()
            device = self._lock(DEVICE_LOCK, self.finish['device_lock_metadata'])
            self.lock_metadata = device['metadata']
            self._lock(self.journal_lock_path)
            raw1 = self._journal_read()
            self.journal_data, actors = self._journal_decode(raw1)
            self.journal_data_original = self.journal_data
            self._locks_current(); self._now()
            attempt = dict(called=True, owner=None, returned=False, error=None)
            self.owner_attempt = attempt
            try:
                owner = readonly.ReadonlyBaselineOwner(self.binding['nonce'], self.until, _clock=self._now)
                attempt['owner'] = owner
                self.owner = self.owner_original = owner
                attempt['returned'] = True
                self.owner_facts_original = (owner, owner.reader, owner.store, owner.budget, owner.io, owner.identity)
                self.snapshot = owner.collect()  # Actual double Snapshot and actual finally closures.
            except BaseException as error:
                attempt['error'] = error
                raise
            self._owner_current()
            if type(owner.collector_rows) is not list or len(owner.collector_rows) != 1:
                _fail('terminal_snapshot_inventory')
            collector = owner.collector_rows[0]['collector']
            rounds = tuple(collector._rounds)
            self.snapshot_rounds = self.snapshot_rounds_original = rounds
            if (len(rounds) != 2 or rounds[-1] is not self.snapshot or
                any(type(value) is not terminal_core.Snapshot or
                    value.key() != self.expected_baseline.key() or
                    value.key() != self.expected_restored.key() for value in rounds)):
                _fail('terminal_snapshot_changed')
            for role, actor in actors:
                self._absence(role, actor, self.journal_data['boot_id'])
            self._owner_current(); self._locks_current()
            raw2 = self._journal_read()
            if (raw1 != raw2 or self.journal_data is not self.journal_data_original or
                    json.dumps(self.journal_data, ensure_ascii=True, sort_keys=True).encode('ascii') != raw1):
                _fail('terminal_journal_changed')
            self._locks_current(); self._pending_absent()
            self.loader_class.authenticate(self.loader); self.source_authenticated = True
            self._now()
            self.pending_result = dict(schema='p011-go-terminal-data-v94',
                binding=self.binding_original, launch_binding=self.launch_original,
                cleanup_limits=self.cleanup_limits_original,
                finish_raw=self.finish_raw_original, finish_sha256=self.finish_sha256,
                journal_raw=raw2, journal_sha256=_sha(raw2),
                journal_metadata=self.journal_reads[-1]['metadata'],
                device_lock_metadata=self.lock_metadata,
                journal_lock_metadata=self.locks[-1]['metadata'],
                snapshot_raw=snapshots.encode_snapshot(self.snapshot),
                stable_key_sha256=snapshots.key_digest(self.snapshot),
                snapshot_round_count=2,
                absence_facts=tuple((row['role'], row['actor'].pid, row['actor'].start,
                    row['value'].passes, row['value'].file_count, row['value'].closed_count)
                    for row in self.absences),
                source_manifest_sha256=readonly.SOURCE_MANIFEST_SHA,
                source_count=len(self.loader.module_originals),
                active_until=self.until, cleanup_until=self.cleanup_until,
                rf_requested=False, native_restore_verified=False,
                restoration_verified=False, independent_restore_verified=False,
                production_admitted=False)
            self._now()  # DATA encode still consumes the same original active cap.
        except BaseException as error:
            if self.failure is None: self.failure = error
            raise
        finally:
            for row in reversed(self.rows):
                try: self._close_file(row)
                except BaseException as error:
                    self.close_errors.append(error); self.unknown = True
            self.ended = True
            try: self.closed = self._terminal_inventory()
            except BaseException as error:
                self.inventory_error = error; self.closed = False
        try:
            if not self.closed or self.pending_result is None: _fail('terminal_inventory_pending')
            self._now()
            self.result = self.pending_result  # Only after all ORIGINAL local/Proc facts close.
        except BaseException as error:
            if self.failure is None: self.failure = error
            raise
        return self.result

    def status(self):
        # Passive saved projection: no clock/IO/history query or Parent grant.
        return dict(called=self.called, ended=self.ended,
            local_inventory_closed=self.local_closed,
            readonly_inventory_closed=self.closed,
            resource_pending=self.unknown or not self.closed or self.failure is not None,
            failed=self.failure is not None, file_ticket_count=len(self.row_history),
            helper_process_count=0, journal_read_count=len(self.journal_reads),
            absence_operation_count=len(self.absences),
            snapshot_round_count=len(self.snapshot_rounds),
            source_authenticated=self.source_authenticated,
            terminal_data_returned=self.result is not None,
            rf_requested=False, native_restore_verified=False,
            restoration_verified=False, independent_restore_verified=False,
            production_admitted=False, send_available=False,
            receive_available=False, phone_tested=False)
