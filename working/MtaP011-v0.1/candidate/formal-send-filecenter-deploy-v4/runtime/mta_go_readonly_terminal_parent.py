"""Fixed terminal-only observer DATA Parent, Python 3.5, SOURCE libc-v1 only.

This independent candidate derives from TerminalParent95. Only the private
_LinuxIo fcntl ABI uses libc; original PIPE, cleanup caps and gates stay.

This immutable candidate derives the source/ARM/FD/two-EOF/once-wait ledger
from Parent92. Original task/service fields identify the finished task, not a
new sending lifetime. The first clock sample issues only cleanup observation:
bound=min(original GO cleanup, service cleanup, returned F cleanup),
active=min(now+30,bound-5), cleanup=min(active+5,bound). No cap is renewed.

The five fixed pure definitions are isolated and never installed in
sys.modules. A fixed named Entry94 is invoked with --collect --terminal.
A bounded canonical request is written through the original stdin PIPE while
both original output PIPEs are drained by one nonblocking select pump. Only a
fully sent request and original known-once stdin close, two actual b'' EOFs,
the one original wait, valid bound terminal DATA, and all known FD closes
permit a private report. Packet bytes never prove EOF, reap, restoration or
admission. Failed collection never resumes a request/parser, kills or relaunches
a child. Its first exception stays retained; cleanup may only close known stdin,
drain the two confirmed outputs within remaining original byte/event/cap bounds,
and attempt the original wait once if both EOFs are actually observed.

Sources retain Parent92's fixed root-owned 0400 files/0700 anchors and the
complete same-FD ARM EABI5 hard-float Python image read/FD exec. The script is
a named physical file: this does not defend against concurrent malicious root.
The ninth constructor value is original returned F cleanup DATA, not an
authorized cap from a regex or ordinary JSON import. The future same-worker
State caller is not wired here; it must take that value from its original
Bridge FinishReport. The loaded pinned Packet must fully validate the request
and match that exact numeric value before any Popen. No caller supplies paths,
commands, IO/clock adapters, a Python pin or grant. Default main constructs
nothing and performs no clock or IO.
"""
import builtins
import errno
import hashlib
import math
import os
import re
import select
import stat
import struct
import subprocess
import sys
import threading
import time
import types

ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
RUNTIME = ROOT + '/runtime'
ALIAS = '/tmp/p011-mta-go-observer-libc-v1'
ENTRY_PATH = RUNTIME + '/mta_go_readonly_entry.py'
PYTHON = '/usr/bin/python3.5'
ARM_READ = 0x88000
MAX_ACTIVE = 30.0
MAX_CLEANUP = 5.0
MAX_PACKET = 393216
MAX_REQUEST = 16384
MAX_STDERR = 16384
MAX_PYTHON = 64 * 1024 * 1024
MAX_EVENTS = 4096
MAX_ROWS = 10  # Five pure sources, named entry, Python, three original PIPEs.
SOURCE_PINS = (
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 71315, 'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('mta_snapshot_data', 17217, 'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
    ('mta_observer_packet', 48253, '004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f'),
)
ENTRY_PIN = ('mta_go_readonly_entry', 45310,
             'b97328b01617ce1944d3576bb4c0e22160414120c737b336e2509004d0031ffa')
_SOURCE_PINS_ORIGINAL, _ENTRY_PIN_ORIGINAL = SOURCE_PINS, ENTRY_PIN
_IMPORT_ORIGINAL = builtins.__import__
_BIND_KEYS = ('cleanup_until', 'native_epoch', 'nonce', 'operation_epoch', 'task_id', 'until')
_LAUNCH_KEYS = frozenset(('run', 'manifest', 'task', 'nonce', 'native_epoch',
    'operation_epoch', 'until', 'candidate_sha', 'child_pid'))
_LIMIT_KEYS = frozenset(('task_until', 'service_until', 'go_cleanup_until',
    'service_cleanup_until'))


class ReadonlyParentError(ValueError):
    """Constant reason only; no binding, path, helper or packet raw text."""
    pass


def _fail(reason):
    raise ReadonlyParentError(reason) from None


def _finite(value):
    return type(value) is float and math.isfinite(value) and 0 < value < 1e12


def _terminal_arguments(task_id, native_epoch, operation_epoch, task_until,
                        service_until, launch, finish_raw, limits, finish_cleanup_until):
    # Basic exact primitive DATA is checked before any IO. The pinned Packet's
    # full request validator is still mandatory after its actual source load.
    if (type(task_id) is not str or re.fullmatch('[0-9a-f]{32}', task_id) is None or
            type(native_epoch) is not int or type(operation_epoch) is not int or
            not 1 <= native_epoch < (1 << 53) or operation_epoch != native_epoch or
            not _finite(task_until) or not _finite(service_until) or not _finite(finish_cleanup_until) or
            task_until > service_until or type(launch) is not dict or
            any(type(key) is not str for key in launch) or set(launch) != _LAUNCH_KEYS or
            type(limits) is not dict or any(type(key) is not str for key in limits) or set(limits) != _LIMIT_KEYS or
            any(not _finite(limits[key]) for key in _LIMIT_KEYS)):
        _fail('terminal_task_data')
    if (any(type(launch[key]) is not str or re.fullmatch('[0-9a-f]{32}', launch[key]) is None
            for key in ('run', 'task', 'nonce')) or
            any(type(launch[key]) is not str or re.fullmatch('[0-9a-f]{64}', launch[key]) is None
                for key in ('manifest', 'candidate_sha')) or
            any(type(launch[key]) is not int for key in ('native_epoch', 'operation_epoch', 'child_pid')) or
            not 1 <= launch['child_pid'] < (1 << 31) or
            launch['task'] != task_id or launch['native_epoch'] != native_epoch or
            launch['operation_epoch'] != operation_epoch or
            type(launch['until']) is not str or launch['until'] != repr(task_until) or
            limits['task_until'] != task_until or limits['service_until'] != service_until or
            limits['go_cleanup_until'] > task_until + 60.0 or
            limits['service_cleanup_until'] != service_until + 60.0 or
            type(finish_raw) is not bytes or not 1 <= len(finish_raw) <= 4096 or
            not finish_raw.startswith(b'GOFINISH84=') or not finish_raw.endswith(b'\n') or
            finish_raw.count(b'\n') != 1):
        _fail('terminal_original_data')
    try: finish_raw.decode('ascii')
    except UnicodeError: _fail('terminal_finish_ascii')
    return (tuple((key, launch[key]) for key in sorted(_LAUNCH_KEYS)),
            tuple((key, limits[key]) for key in sorted(_LIMIT_KEYS)), finish_cleanup_until)


def _source_contract():
    if (type(ENTRY_PIN) is not tuple or len(ENTRY_PIN) != 3 or
            ENTRY_PIN[0] != 'mta_go_readonly_entry' or type(ENTRY_PIN[1]) is not int or
            not 1 <= ENTRY_PIN[1] <= 131072 or type(ENTRY_PIN[2]) is not str or
            re.fullmatch('[0-9a-f]{64}', ENTRY_PIN[2]) is None):
        _fail('terminal_entry_source_unavailable')


def _metadata(value, pipe=False):
    names = (('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
             if pipe else ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                           'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    result = tuple(getattr(value, name, None) for name in names)
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        _fail('parent_metadata')
    return result


def _bound_original(current, saved, owner):
    return (type(current) is types.MethodType and type(saved) is types.MethodType and
            current.__self__ is owner and saved.__self__ is owner and
            current.__func__ is saved.__func__)


class _LinuxIo(object):
    def __init__(self):
        self._ctypes = self._libc = self._fcntl = None
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('parent_platform')
        import ctypes
        library = ctypes.CDLL(None, use_errno=True)
        command = library.fcntl
        command.argtypes = (ctypes.c_int, ctypes.c_int)
        command.restype = ctypes.c_int
        # Keep the actual library and its original function strongly retained.
        self._ctypes, self._libc, self._fcntl = ctypes, library, command
    def pid(self): return os.getpid()
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, ARM_READ)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, raw): return os.write(fd, raw)
    def close(self, fd): return os.close(fd)
    def inheritable(self, fd): return os.get_inheritable(fd)
    def flags(self, fd):
        if (self._ctypes is None or self._libc is None or self._fcntl is None or
                self._libc.fcntl is not self._fcntl):
            _fail('parent_unvalidated')
        if type(fd) is not int or not 0 <= fd <= 0x7fffffff:
            _fail('parent_fcntl_input')
        self._ctypes.set_errno(0)
        result = self._fcntl(fd, 3)  # Linux F_GETFL; no retry or FD replacement.
        saved_errno = self._ctypes.get_errno()
        if type(result) is not int: _fail('parent_fcntl_return')
        if result < 0:
            error = (OSError(saved_errno, 'parent_fcntl_failed')
                     if type(saved_errno) is int and 1 <= saved_errno <= 4095
                     else ReadonlyParentError('parent_fcntl_errno'))
            error.fcntl_result, error.fcntl_errno = result, saved_errno
            raise error from None
        if result > 0x7fffffff: _fail('parent_fcntl_return')
        return result
    def set_flags(self, fd, value):
        if (self._ctypes is None or self._libc is None or self._fcntl is None or
                self._libc.fcntl is not self._fcntl):
            _fail('parent_unvalidated')
        if (type(fd) is not int or not 0 <= fd <= 0x7fffffff or
                type(value) is not int or not 0 <= value <= 0x7fffffff):
            _fail('parent_fcntl_input')
        self._ctypes.set_errno(0)
        result = self._fcntl(fd, 4, self._ctypes.c_int(value))  # Linux F_SETFL.
        saved_errno = self._ctypes.get_errno()
        if type(result) is not int: _fail('parent_fcntl_return')
        if result < 0:
            error = (OSError(saved_errno, 'parent_fcntl_failed')
                     if type(saved_errno) is int and 1 <= saved_errno <= 4095
                     else ReadonlyParentError('parent_fcntl_errno'))
            error.fcntl_result, error.fcntl_errno = result, saved_errno
            raise error from None
        if result != 0: _fail('parent_fcntl_return')
        return result
    def nonce(self): return os.urandom(16)
    def spawn(self, argv, pythonfd):
        return subprocess.Popen(argv, executable='/proc/self/fd/' + str(pythonfd),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            close_fds=True, pass_fds=(pythonfd,), shell=False,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
    def readable(self, fds, timeout): return select.select(fds, (), (), timeout)[0]
    def ready(self, reads, writes, timeout):
        value = select.select(reads, writes, (), timeout)
        return value[0], value[1]


class ReadonlyTerminalParent(object):
    """One terminal cleanup-only DATA lifetime; never a native permission issuer."""
    def __init__(self, task_id, native_epoch, operation_epoch, task_until, service_until,
                 launch_binding, finish_raw, cleanup_limits, finish_cleanup_until):
        original = _terminal_arguments(task_id, native_epoch, operation_epoch,
            task_until, service_until, launch_binding, finish_raw, cleanup_limits, finish_cleanup_until)
        self.task_id, self.native_epoch, self.operation_epoch = task_id, native_epoch, operation_epoch
        self.task_until, self.service_until = task_until, service_until
        self.launch_binding, self.finish_raw, self.cleanup_limits = launch_binding, finish_raw, cleanup_limits
        self.arguments_original = (task_id, native_epoch, operation_epoch, task_until, service_until,
                                   launch_binding, finish_raw, cleanup_limits, finish_cleanup_until)
        self.terminal_original = original
        self.finish_cleanup_until = original[2]
        self.worker = threading.current_thread()
        self.io_class_original = _LinuxIo
        self.io = self.io_original = _LinuxIo()
        self.clock = self.clock_original = time.monotonic
        self.pid, self.last, self.roots = None, None, None
        self.active_until = self.cleanup_until = self.period_original = None
        self.binding = self.binding_original = None
        self.rows = self.rows_original = []
        self.row_history = self.row_history_original = []
        self.modules = self.modules_original = {}
        self.module_originals = self.definitions_original = []
        self.packet_functions = self.packet_functions_original = None
        self.python = self.python_original = None
        self.python_sha256 = None
        self.nonce_raw = self.argv = self.argv_original = None
        self.process = self.process_original = self.process_pid = None
        self.process_fields = self.process_fields_original = None
        self.process_methods = self.process_methods_original = None
        self.process_attempt = self.process_attempt_original = None
        self.reader = self.reader_original = None
        self.request_raw = self.request_raw_original = None
        self.request_data = self.request_data_original = None
        self.input_row = self.input_row_original = None
        self.write_ticket = self.write_ticket_original = dict(
            attempted=False, offset=0, completed=False, unknown=False, attempts=[], close_ticket=None)
        self.input_close_ticket = self.input_close_ticket_original = None
        self.stderr_parts, self.stderr_bytes = [], 0
        self.waits, self.read_attempts = [], 0
        self.result = self.report = self.result_original = None
        self.failure, self.close_errors = None, []
        self.cleanup_attempted, self.cleanup_error = False, None
        self.cleanup_ticket = self.cleanup_ticket_original = None
        self.cleanup_methods = self.cleanup_methods_original = (
            self._cleanup_pipe_current, self._read_cleanup, self._cleanup_finalize)
        self.attempted = self.ended = self.closed = self.close_attempted = False
        self.unknown = False

    def _context(self):
        values = (self.task_id, self.native_epoch, self.operation_epoch, self.task_until, self.service_until,
                  self.launch_binding, self.finish_raw, self.cleanup_limits, self.finish_cleanup_until)
        if (any(left is not right for left, right in zip(values, self.arguments_original)) or
                _terminal_arguments(*values) != self.terminal_original or
                self.finish_cleanup_until != self.terminal_original[2] or
                threading.current_thread() is not self.worker or
                _LinuxIo is not self.io_class_original or type(self.io) is not self.io_class_original or
                self.io is not self.io_original or self.clock is not self.clock_original or
                time.monotonic is not self.clock_original or
                SOURCE_PINS is not _SOURCE_PINS_ORIGINAL or ENTRY_PIN is not _ENTRY_PIN_ORIGINAL or
                self.rows is not self.rows_original or self.row_history is not self.row_history_original or
                len(self.rows) != len(self.row_history) or len(self.rows) > MAX_ROWS or
                any(left is not right for left, right in zip(self.rows, self.row_history)) or
                self.modules is not self.modules_original or self.module_originals is not self.definitions_original or
                self.python is not self.python_original or self.process is not self.process_original or
                self.process_attempt is not self.process_attempt_original or
                self.process_fields is not self.process_fields_original or
                self.process_methods is not self.process_methods_original or
                self.binding is not self.binding_original or self.argv is not self.argv_original or
                self.reader is not self.reader_original or self.result is not self.result_original or
                self.request_raw is not self.request_raw_original or
                self.request_data is not self.request_data_original or
                self.input_row is not self.input_row_original or
                self.write_ticket is not self.write_ticket_original or
                self.input_close_ticket is not self.input_close_ticket_original or
                self.report is not self.result_original or
                self.cleanup_ticket is not self.cleanup_ticket_original or
                self.cleanup_methods is not self.cleanup_methods_original or
                type(self.cleanup_methods) is not tuple or len(self.cleanup_methods) != 3 or
                any(not _bound_original(current, saved, self) for current, saved in zip(
                    (self._cleanup_pipe_current, self._read_cleanup, self._cleanup_finalize),
                    self.cleanup_methods))):
            _fail('parent_owner_changed')
        if self.period_original is not None and (
                type(self.period_original) is not tuple or len(self.period_original) != 2 or
                self.active_until is not self.period_original[0] or
                self.cleanup_until is not self.period_original[1]):
            _fail('parent_period_changed')
        if self.cleanup_ticket is not None:
            value = self.cleanup_ticket
            if (type(value) is not tuple or len(value) != 10 or value[0] is not self or
                    value[1] is not self.failure or value[2] is not self.process_attempt or
                    value[3] is not self.process or value[4] is not self.process_pid or
                    value[5] is not self.process_fields or value[6] is not self.process_methods or
                    type(self.process_attempt) is not dict or value[7] is not self.process_attempt['pipes'] or
                    value[8] is not self.period_original or value[9] is not self.cleanup_until):
                _fail('parent_cleanup_changed')
        if self.pid is not None and self.io.pid() != self.pid:
            _fail('parent_owner_changed')

    def _now(self, cleanup=False):
        self._context()
        if type(cleanup) is not bool: _fail('parent_period_changed')
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(float(now)) or
                not 0 <= now < 1e12 or self.last is not None and now < self.last):
            _fail('parent_clock')
        self.last = float(now)
        cap = (min(self.cleanup_limits['go_cleanup_until'],
                   self.cleanup_limits['service_cleanup_until'], self.finish_cleanup_until) if self.period_original is None
               else self.cleanup_until if cleanup else self.active_until)
        if now >= cap: _fail('parent_expired')
        return float(now)

    def _issue_period(self):
        if self.period_original is not None: _fail('parent_period_already_issued')
        now = self._now()
        bound = min(self.cleanup_limits['go_cleanup_until'],
                    self.cleanup_limits['service_cleanup_until'], self.finish_cleanup_until)
        active = min(now + MAX_ACTIVE, bound - MAX_CLEANUP)
        cleanup = min(active + MAX_CLEANUP, bound)
        if not now < active <= cleanup <= bound: _fail('parent_insufficient_period')
        self.active_until, self.cleanup_until = active, cleanup
        self.period_original = (active, cleanup)

    def _anchors(self):
        result = []
        for path, mode, target in (
                ('/', None, None), ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                (ROOT, stat.S_IFDIR | 0o700, None), (RUNTIME, stat.S_IFDIR | 0o700, None),
                ('/usr', None, None), ('/usr/bin', None, None)):
            self._now(); actual = self.io.stat(path)
            meta = _metadata(actual); self._now()
            if (meta[3:5] != (0, 0) or meta[5] < 1 or
                    mode is None and (not stat.S_ISDIR(meta[2]) or meta[2] & 0o022) or
                    mode is not None and meta[2] != mode):
                _fail('parent_root')
            if target is not None:
                if meta[5] != 1 or meta[6] != len(target): _fail('parent_alias')
                self._now(); observed = self.io.readlink(path); self._now()
                if type(observed) is not str or observed != target: _fail('parent_alias')
                result.append((path, meta, target))
            else:
                result.append((path, meta[:5], None))
        for alias, physical in ((ALIAS, ROOT), (ALIAS + '/runtime', RUNTIME)):
            self._now(); left = _metadata(self.io.stat(alias)); self._now()
            right = _metadata(self.io.stat(physical)); self._now()
            if left[:5] != right[:5]: _fail('parent_alias')
        value = tuple(result)
        if self.roots is None: self.roots = value
        elif value != self.roots: _fail('parent_root_changed')
        return value

    def _new_row(self, role, path=None, pipe=False):
        self._context()
        if len(self.rows) >= MAX_ROWS or any(row['role'] == role for row in self.rows):
            _fail('parent_inventory_budget')
        row = dict(role=role, path=path, pipe=pipe, fd=None, fd_original=None,
            metadata=None, metadata_original=None, raw=None, raw_original=None,
            raw_type=None, raw_methods=None, fileno_method=None, close_method=None,
            unknown=False, closed=True, open_called=False, open_error=None,
            close_called=False, close_return=None, close_error=None, close_failure=None,
            read_values=[], read_errors=[], bytes=0, source_raw=None, sha256=None,
            flags=None, nonblock_flags=None, set_flags_return=None, inheritable=None, eof=False, eof_ticket=None,
            failure=None)
        self.rows.append(row); self.row_history.append(row)
        return row

    def _adopt_fd(self, row, fd):
        # The actual returned value is already retained, including invalid/duplicate values.
        row['fd'] = fd
        if (type(fd) is not int or fd <= 2 or any(
                other is not row and not other['closed'] and other['fd'] == fd for other in self.rows)):
            self.unknown = True; _fail('parent_fd')
        row['fd_original'] = fd
        try: row['metadata'] = row['metadata_original'] = _metadata(self.io.fstat(fd), row['pipe'])
        except BaseException as error:
            row['failure'] = error; self.unknown = True; raise
        row['unknown'] = False  # Retained close identity exists even if the next active check is late.

    def _row_original(self, row):
        self._context()
        if (type(row) is not dict or not any(row is item for item in self.rows) or
                row['unknown'] or type(row['fd']) is not int or row['fd'] is not row['fd_original'] or
                row['metadata'] is not row['metadata_original'] or type(row['metadata']) is not tuple):
            _fail('parent_fd_unknown')
        if row['pipe']:
            raw = row['raw']
            if (raw is not row['raw_original'] or type(raw) is not row['raw_type'] or
                    type(row['raw_methods']) is not tuple or len(row['raw_methods']) != 2 or
                    getattr(type(raw), 'fileno', None) is not row['raw_methods'][0] or
                    getattr(type(raw), 'close', None) is not row['raw_methods'][1]):
                _fail('parent_pipe_changed')

    def _close_row(self, row):
        self._context()  # Known close-only is not refused merely because an active cap elapsed.
        if type(row) is not dict or not any(row is item for item in self.rows):
            _fail('parent_close_ticket')
        if row['closed'] or row['close_called']: return
        if row['unknown']:
            self.unknown = True; return
        try:
            self._row_original(row)
            if _metadata(self.io.fstat(row['fd']), row['pipe']) != row['metadata']:
                _fail('parent_close_identity')
            if row['pipe'] and (row['fileno_method']() != row['fd'] or row['raw'].closed is not False):
                _fail('parent_pipe_changed')
        except BaseException as error:
            row['close_failure'] = error; row['unknown'] = True
            self.unknown = True; self.close_errors.append(error); return
        row['close_called'] = True  # Before the one actual close, including a late/error return.
        try:
            row['close_return'] = row['close_method']() if row['pipe'] else self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = (row['close_return'] is None and type(error.errno) is int and
                    error.errno == errno.EBADF and (not row['pipe'] or row['raw'].closed is True))
        except BaseException as error:
            row['close_failure'] = error; self.close_errors.append(error)
        if row['closed'] is not True:
            row['unknown'] = True; self.unknown = True

    def _file_current(self, row):
        self._now(); self._row_original(row)
        if row['closed'] or row['close_called'] or row['pipe']: _fail('parent_file_changed')
        actual_fd = _metadata(self.io.fstat(row['fd'])); self._now()
        actual_path = _metadata(self.io.stat(row['path'])); self._now()
        if actual_fd != row['metadata'] or actual_path != row['metadata']:
            _fail('parent_file_changed')
        if row['path'] != PYTHON:
            alias = ALIAS + '/runtime/' + row['role'] + '.py'
            actual_alias = _metadata(self.io.stat(alias)); self._now()
            if actual_alias != row['metadata']: _fail('parent_file_changed')
        self._anchors(); self._now()

    def _read_file(self, expected=None, python=False):
        if type(python) is not bool: _fail('parent_file_role')
        if python:
            if expected is not None or self.python is not None: _fail('parent_file_role')
            role, path, expected_size, pin = 'python', PYTHON, None, None
        else:
            if not any(expected is item for item in SOURCE_PINS + (ENTRY_PIN,)):
                _fail('parent_file_role')
            role, expected_size, pin = expected
            path = RUNTIME + '/' + role + '.py'
        self._now(); anchors = self._anchors(); self._now()
        row = self._new_row(role, path)
        if python: self.python = self.python_original = row
        complete = False
        try:
            self._now()
            row['open_called'] = True; row['closed'] = False; row['unknown'] = True
            try: returned = self.io.open(path)
            except OSError as error:
                row['open_error'] = error
                known = type(error.errno) is int and 1 <= error.errno <= 4095
                row['closed'], row['unknown'] = known, not known
                if not known: self.unknown = True
                raise
            except BaseException as error:
                row['open_error'] = error; self.unknown = True; raise
            self._adopt_fd(row, returned); self._now()
            meta = row['metadata']
            size = meta[6]
            if python:
                if (not stat.S_ISREG(meta[2]) or meta[2] & 0o022 or not meta[2] & 0o111 or
                        meta[3:5] != (0, 0) or meta[5] not in (1, 2) or not 52 <= size <= MAX_PYTHON):
                    _fail('parent_python_metadata')
            elif meta[2:7] != (stat.S_IFREG | 0o400, 0, 0, 1, expected_size):
                _fail('parent_source_metadata')
            total = 0
            maximum_reads = MAX_PYTHON // 65536 + 2 if python else 64
            while total <= size:
                if len(row['read_values']) >= maximum_reads: _fail('parent_source_read_budget')
                self._now(); count = min(65536, size + 1 - total)
                try: raw = self.io.read(row['fd'], count)
                except BaseException as error:
                    row['read_errors'].append(error); raise
                row['read_values'].append(raw); self._now()
                if type(raw) is not bytes or len(raw) > count: _fail('parent_source_bytes')
                total += len(raw)
                if not raw: break
            raw = b''.join(row['read_values']); row['source_raw'] = raw
            if len(raw) != size: _fail('parent_source_size')
            row['sha256'] = hashlib.sha256(raw).hexdigest(); self._now()
            if python:
                if (raw[:7] != b'\x7fELF\x01\x01\x01' or
                        struct.unpack_from('<H', raw, 16)[0] not in (2, 3) or
                        struct.unpack_from('<H', raw, 18)[0] != 40 or
                        struct.unpack_from('<I', raw, 20)[0] != 1 or
                        struct.unpack_from('<I', raw, 36)[0] & 0xff000600 != 0x05000400 or
                        struct.unpack_from('<H', raw, 40)[0] != 52):
                    _fail('parent_python_elf')
                phoff = struct.unpack_from('<I', raw, 28)[0]
                phsize, phcount = struct.unpack_from('<HH', raw, 42)
                if phsize != 32 or not 1 <= phcount <= 512 or phoff < 52 or phoff + phsize * phcount > size:
                    _fail('parent_python_elf')
                self.python_sha256 = row['sha256']  # Same actual read DATA, not stock authentication.
            elif row['sha256'] != pin:
                _fail('parent_source_pin')
            self._file_current(row)
            if self._anchors() != anchors: _fail('parent_root_changed')
            self._now(); complete = True
        except BaseException as error:
            row['failure'] = error; raise
        finally:
            if not python or not complete:
                try: self._close_row(row)
                except BaseException as error:
                    row['close_failure'] = error; row['unknown'] = True
                    self.close_errors.append(error); self.unknown = True
        if not python and (not row['closed'] or row['unknown'] or self.unknown):
            _fail('parent_source_unclosed')
        return row

    def _definitions_current(self):
        self._context()
        if (len(self.modules) != len(self.module_originals) or
                len(self.module_originals) > len(SOURCE_PINS)):
            _fail('parent_definition_changed')
        for index, original in enumerate(self.module_originals):
            name, module, namespace, raw, functions = original
            if (name != SOURCE_PINS[index][0] or type(module) is not types.ModuleType or
                    self.modules.get(name) is not module or module.__dict__ is not namespace or
                    module.__file__ != RUNTIME + '/' + name + '.py' or type(raw) is not bytes):
                _fail('parent_definition_changed')
            for key, value in functions:
                if namespace.get(key) is not value: _fail('parent_definition_changed')
        if self.packet_functions is not self.packet_functions_original:
            _fail('parent_definition_changed')
        if self.packet_functions is not None:
            packet, cls, feed, finish, data_cls, encode, decode, request_cls, request_raw, finish_raw, data_finish = self.packet_functions
            if (self.modules.get('mta_observer_packet') is not packet or
                    packet.TerminalPacketReader is not cls or cls.feed is not feed or cls.finish is not finish or
                    packet.TerminalPacketData is not data_cls or
                    packet.encode_terminal_request is not encode or packet.decode_terminal_request is not decode or
                    packet.TerminalRequestData is not request_cls or
                    request_cls.private_request_ascii is not request_raw or
                    request_cls.private_finish_ascii is not finish_raw or
                    data_cls.private_finish_ascii is not data_finish or
                    self.reader is not None and type(self.reader) is not cls):
                _fail('parent_definition_changed')

    def _load_definitions(self):
        for expected in SOURCE_PINS:
            row = self._read_file(expected)
            name = expected[0]
            if name in self.modules: _fail('parent_definition_duplicate')
            self._definitions_current(); self._now()
            def pinned_import(import_name, globals=None, locals=None, fromlist=(), level=0):
                if type(import_name) is not str or level: _fail('parent_import')
                if import_name.startswith(('mta_', 'p011_')):
                    self._definitions_current()
                    if import_name not in self.modules: _fail('parent_import')
                    return self.modules[import_name]
                return _IMPORT_ORIGINAL(import_name, globals, locals, fromlist, level)
            module = types.ModuleType(name)
            module.__file__ = row['path']
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
            self.modules[name] = module
            # Retain before exec; a failed definition is never dropped or rolled back.
            record = (name, module, module.__dict__, row['source_raw'], ())
            self.module_originals.append(record)
            exec(row['source_raw'], module.__dict__)
            functions = tuple((key, value) for key, value in module.__dict__.items()
                              if type(value) in (types.FunctionType, type))
            self.module_originals[-1] = record[:4] + (functions,)
            self._now(); self._definitions_current()
        packet = self.modules['mta_observer_packet']
        self.packet_functions = self.packet_functions_original = (
            packet, packet.TerminalPacketReader, packet.TerminalPacketReader.feed,
            packet.TerminalPacketReader.finish, packet.TerminalPacketData,
            packet.encode_terminal_request, packet.decode_terminal_request, packet.TerminalRequestData,
            packet.TerminalRequestData.private_request_ascii, packet.TerminalRequestData.private_finish_ascii,
            packet.TerminalPacketData.private_finish_ascii)
        self.reader = self.reader_original = packet.TerminalPacketReader()
        self._definitions_current(); self._now()

    def _request_current(self):
        self._definitions_current()
        request = self.request_data
        if (type(self.request_raw) is not bytes or not 1 <= len(self.request_raw) <= MAX_REQUEST or
                type(request) is not self.packet_functions[7] or
                self.packet_functions[8](request) is not self.request_raw or
                self.packet_functions[9](request) != self.finish_raw or
                request.binding != self.binding_original or
                request.launch_binding != self.terminal_original[0] or
                request.cleanup_limits != self.terminal_original[1] or
                request.finish_sha256 != hashlib.sha256(self.finish_raw).hexdigest() or
                request.request_sha256 != hashlib.sha256(self.request_raw).hexdigest() or
                dict(request.finish_data)['cleanup_until'] != self.finish_cleanup_until):
            _fail('terminal_request_changed')

    def _prepare_request(self, binding):
        if self.request_raw is not None or self.request_data is not None:
            _fail('terminal_request_already_issued')
        self._definitions_current(); self._now()
        raw = self.packet_functions[5](binding, self.launch_binding, self.finish_raw, self.cleanup_limits)
        self.request_raw = self.request_raw_original = raw  # Before late/shape validation.
        self._now()
        if type(raw) is not bytes or not 1 <= len(raw) <= MAX_REQUEST:
            _fail('terminal_request_budget')
        returned = self.packet_functions[6](raw)
        self.request_data = self.request_data_original = returned
        self._now(); self._request_current()

    def _pipe_adopt(self, row):
        raw = row['raw']
        if raw is None: self.unknown = True; _fail('parent_pipe_missing')
        row['raw_original'], row['raw_type'] = raw, type(raw)
        row['raw_methods'] = (getattr(type(raw), 'fileno', None), getattr(type(raw), 'close', None))
        try:
            row['fileno_method'], row['close_method'] = raw.fileno, raw.close
            if (not callable(row['fileno_method']) or not callable(row['close_method']) or
                    any(item is None for item in row['raw_methods'])):
                _fail('parent_pipe_methods')
            returned = row['fileno_method']()
            self._adopt_fd(row, returned)
            self._now()
            meta = row['metadata']
            if meta[2] != stat.S_IFIFO | 0o600 or meta[3:6] != (0, 0, 1) or raw.closed is not False:
                _fail('parent_pipe_metadata')
            row['flags'] = self.io.flags(row['fd']); self._now()
            access = os.O_WRONLY if row['role'] == 'stdin' else os.O_RDONLY
            if (type(row['flags']) is not int or row['flags'] < 0 or
                    row['role'] not in ('stdin', 'stdout', 'stderr') or
                    row['flags'] & os.O_ACCMODE != access):
                _fail('parent_pipe_access')
            self._now()
            row['set_flags_return'] = self.io.set_flags(row['fd'], row['flags'] | os.O_NONBLOCK)
            self._now()
            row['nonblock_flags'] = self.io.flags(row['fd']); self._now()
            if row['nonblock_flags'] != row['flags'] | os.O_NONBLOCK: _fail('parent_pipe_nonblocking')
            row['inheritable'] = self.io.inheritable(row['fd']); self._now()
            if row['inheritable'] is not False: _fail('parent_pipe_inheritable')
        except BaseException as error:
            row['failure'] = error
            if row['metadata'] is None: self.unknown = True
            raise

    def _process_current(self):
        self._context()
        ticket, process = self.process_attempt, self.process
        if (type(ticket) is not dict or ticket['process'] is not process or
                process is None or ticket['pid'] is not self.process_pid or
                process.pid is not self.process_pid or self.process_fields is None or
                self.process_fields != ('pid', 'stdin', 'stdout', 'stderr') or
                ticket['stdin_row'] is not self.input_row or ticket['stdin'] is not self.input_row['raw_original'] or
                process.stdin is not ticket['stdin'] or
                ticket['stdout'] is not ticket['pipes'][0]['raw_original'] or
                ticket['stderr'] is not ticket['pipes'][1]['raw_original'] or
                process.stdout is not ticket['stdout'] or process.stderr is not ticket['stderr'] or
                not _bound_original(process.poll, self.process_methods[0], process) or
                not _bound_original(process.wait, self.process_methods[1], process)):
            _fail('parent_process_changed')

    def _spawn(self):
        self._definitions_current(); self._file_current(self.python); self._now()
        self.nonce_raw = self.io.nonce(); self._now()
        if type(self.nonce_raw) is not bytes or len(self.nonce_raw) != 16: _fail('parent_nonce')
        nonce = self.nonce_raw.hex()
        if nonce == self.launch_binding['nonce']: _fail('terminal_nonce_issuer_collision')
        binding = dict(nonce=nonce, task_id=self.task_id, native_epoch=self.native_epoch,
                       operation_epoch=self.operation_epoch, until=self.active_until,
                       cleanup_until=self.cleanup_until)
        self.binding = self.binding_original = tuple((key, binding[key]) for key in _BIND_KEYS)
        self._prepare_request(binding)
        argv = (PYTHON, '-I', '-B', ENTRY_PATH, '--collect', '--terminal', '--nonce', nonce, '--task-id', self.task_id,
            '--native-epoch', str(self.native_epoch), '--operation-epoch', str(self.operation_epoch),
            '--until', repr(self.active_until), '--cleanup-until', repr(self.cleanup_until))
        self.argv = self.argv_original = argv
        inp = self._new_row('stdin', pipe=True)
        self.input_row = self.input_row_original = inp
        out = self._new_row('stdout', pipe=True)
        err = self._new_row('stderr', pipe=True)
        ticket = dict(called=False, returned=False, process=None, pid=None, stdin=None, stdin_row=inp, stdout=None, stderr=None,
            pipes=(out, err), failure=None, field_errors=[], unknown=True, waited=False, wait_called=False,
            wait_return=None, wait_error=None, wait_ticket=None, wait_ticket_original=None, reaped=False)
        self.process_attempt = self.process_attempt_original = ticket
        self._anchors(); self._file_current(self.python); self._now()
        ticket['called'] = True
        for row in (inp, out, err):
            row['open_called'] = True; row['closed'] = False; row['unknown'] = True
        try: process = self.io.spawn(argv, self.python['fd'])
        except BaseException as error:
            ticket['failure'] = error; self.unknown = True; raise
        # No check, fileno, stat or field validation intervenes before strong returned-object retention.
        self.process = self.process_original = ticket['process'] = process
        ticket['returned'] = True
        for name in ('pid', 'stdin', 'stdout', 'stderr'):
            try: actual = getattr(process, name)
            except BaseException as error:
                ticket['field_errors'].append(error); continue
            ticket[name] = actual
            if name == 'pid': self.process_pid = actual
            else: {'stdin': inp, 'stdout': out, 'stderr': err}[name]['raw'] = actual
        self.process_fields = self.process_fields_original = ('pid', 'stdin', 'stdout', 'stderr')
        # All THREE raw handles are retained before any field/fileno/fstat/late refusal.
        adoption_errors = []
        for row in (inp, out, err):
            try: self._pipe_adopt(row)
            except BaseException as error: adoption_errors.append(error)
        try: self.process_methods = self.process_methods_original = (process.poll, process.wait)
        except BaseException as error: ticket['field_errors'].append(error)
        if ticket['field_errors'] or adoption_errors:
            ticket['failure'] = (ticket['field_errors'] + adoption_errors)[0]
            if any(row['unknown'] for row in (inp, out, err)): self.unknown = True
            raise ticket['failure']
        if (type(self.process_pid) is not int or not 1 <= self.process_pid < (1 << 31) or
                self.process_pid == self.pid or process is None):
            self.unknown = True; _fail('parent_process_pid')
        ticket['unknown'] = False
        self._process_current(); self._now()

    def _pipe_current(self, row):
        self._now(); self._row_original(row)
        if (row['closed'] or row['close_called'] or not row['pipe'] or row['raw'].closed is not False or
                row['fileno_method']() != row['fd'] or row['nonblock_flags'] is None):
            _fail('parent_pipe_changed')
        meta = _metadata(self.io.fstat(row['fd']), True); self._now()
        flags = self.io.flags(row['fd']); self._now()
        inheritable = self.io.inheritable(row['fd']); self._now()
        if (meta != row['metadata'] or flags != row['nonblock_flags'] or
                row['inheritable'] is not False or inheritable is not False):
            _fail('parent_pipe_changed')

    def _read_ready(self, row):
        if self.read_attempts + len(self.write_ticket['attempts']) >= MAX_EVENTS: _fail('parent_read_budget')
        self._pipe_current(row); self._now()
        maximum = MAX_PACKET if row['role'] == 'stdout' else MAX_STDERR
        count = min(65536, maximum + 1 - row['bytes'])
        if count < 1: _fail('parent_pipe_budget')
        self.read_attempts += 1
        try: raw = self.io.read(row['fd'], count)
        except OSError as error:
            row['read_errors'].append(error)
            if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._now(); return
            raise
        except BaseException as error:
            row['read_errors'].append(error); raise
        row['read_values'].append(raw)
        if type(raw) is bytes:
            row['bytes'] += len(raw)
            if not raw:
                row['eof'] = True
                row['eof_ticket'] = (self.process, self.process_pid, row, row['raw_original'],
                                     row['fd_original'], row['metadata_original'], raw)
        self._now()
        if type(raw) is not bytes or len(raw) > count or row['bytes'] > maximum:
            _fail('parent_pipe_budget')
        if not raw: return
        if row['role'] == 'stdout':
            self._definitions_current()
            self.packet_functions[2](self.reader, raw)
        else:
            self.stderr_parts.append(raw); self.stderr_bytes += len(raw)
        self._now()

    def _eofs_current(self):
        self._process_current()
        for row in self.process_attempt['pipes']:
            value = row['eof_ticket']
            if (row['eof'] is not True or type(value) is not tuple or len(value) != 7 or
                    value[0] is not self.process or value[1] is not self.process_pid or value[2] is not row or
                    value[3] is not row['raw_original'] or value[4] is not row['fd_original'] or
                    value[5] is not row['metadata_original'] or type(value[6]) is not bytes or value[6] != b''):
                _fail('parent_missing_eof')

    def _input_closed(self):
        self._context()
        row, saved = self.input_row, self.input_close_ticket
        if row is None or saved is None: return False
        return (type(saved) is tuple and len(saved) == 8 and
            self.write_ticket['close_ticket'] is saved and saved[0] is self.process and
            saved[1] is self.process_pid and saved[2] is row and saved[3] is row['raw_original'] and
            saved[4] is row['fd_original'] and saved[5] is row['metadata_original'] and
            saved[6] is row['close_return'] and saved[6] is None and saved[7] is row['close_error'] and
            row['closed'] is True and row['unknown'] is False and row['close_called'] is True and
            row['close_failure'] is None and type(row['close_error'].errno) is int and
            row['close_error'].errno == errno.EBADF and row['raw'] is row['raw_original'] and
            row['raw'].closed is True)

    def _close_input(self):
        # Known close-only never writes or reads a clock, even on a failed/late
        # request. An unknown/missing returned handle is never closed by guess.
        self._context()
        row = self.input_row
        if row is None or row['open_called'] is False: return
        self._close_row(row)
        if (row['closed'] is not True or row['unknown'] is not False or
                row['close_called'] is not True or row['close_return'] is not None or
                row['close_failure'] is not None or not isinstance(row['close_error'], OSError) or
                type(row['close_error'].errno) is not int or row['close_error'].errno != errno.EBADF):
            _fail('terminal_stdin_close_pending')
        if self.input_close_ticket is None:
            saved = (self.process, self.process_pid, row, row['raw_original'], row['fd_original'],
                     row['metadata_original'], row['close_return'], row['close_error'])
            self.input_close_ticket = self.input_close_ticket_original = saved
            self.write_ticket['close_ticket'] = saved
        if self._input_closed() is not True: _fail('terminal_stdin_close_changed')

    def _request_complete(self):
        self._request_current()
        row, ticket = self.input_row, self.write_ticket
        return (row is not None and ticket['attempted'] is True and ticket['completed'] is True and
            ticket['unknown'] is False and type(ticket['offset']) is int and
            ticket['offset'] == len(self.request_raw) and row['bytes'] == ticket['offset'] and
            self._input_closed() is True)

    def _write_ready(self):
        self._process_current(); self._request_current()
        row, ticket = self.input_row, self.write_ticket
        if (ticket['unknown'] is not False or ticket['completed'] is not False or
                type(ticket['offset']) is not int or not 0 <= ticket['offset'] < len(self.request_raw) or
                self.read_attempts + len(ticket['attempts']) >= MAX_EVENTS):
            _fail('terminal_write_state_or_budget')
        self._pipe_current(row); self._now()
        raw = self.request_raw[ticket['offset']:ticket['offset'] + 65536]
        attempt = dict(offset=ticket['offset'], raw=raw, called=False, returned=None, error=None)
        ticket['attempts'].append(attempt)
        ticket['attempted'] = True; attempt['called'] = True
        try: returned = self.io.write(row['fd'], raw)
        except OSError as error:
            attempt['error'] = error
            if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._now(); return
            ticket['unknown'] = True; raise
        except BaseException as error:
            attempt['error'] = error; ticket['unknown'] = True; raise
        attempt['returned'] = returned  # Retain a physical partial/late write first.
        if type(returned) is not int or not 1 <= returned <= len(raw):
            ticket['unknown'] = True; _fail('terminal_write_return')
        ticket['offset'] += returned; row['bytes'] += returned
        self._now()
        if ticket['offset'] == len(self.request_raw):
            ticket['completed'] = True
            self._close_input()  # Actual EOF delivered once to the original child.
            self._now()
            if self._request_complete() is not True: _fail('terminal_request_incomplete')

    def _drain_and_wait(self):
        ticket = self.process_attempt
        while not (self._request_complete() and all(row['eof'] for row in ticket['pipes'])):
            if len(self.waits) >= MAX_EVENTS: _fail('parent_select_budget')
            self._process_current(); now = self._now()
            fds = tuple(row['fd'] for row in ticket['pipes'] if not row['eof'])
            writes = () if self.write_ticket['completed'] else (self.input_row['fd'],)
            if not fds and not writes: _fail('terminal_channel_incomplete')
            timeout = min(0.1, self.active_until - now)
            ready = self.io.ready(fds, writes, timeout)
            self.waits.append((fds, writes, timeout, ready)); self._now()
            if type(ready) not in (tuple, list) or len(ready) != 2:
                self.unknown = True; _fail('parent_readiness')
            for actual, expected in zip(ready, (fds, writes)):
                if (type(actual) not in (tuple, list) or len(actual) > len(expected) or
                        any(type(fd) is not int or fd not in expected for fd in actual) or
                        len(set(actual)) != len(actual)):
                    self.unknown = True; _fail('parent_readiness')
            # Drain BOTH outputs while writing stdin; never fill one pipe and
            # wait on a different blocked child/parent endpoint.
            for row in ticket['pipes']:
                if not row['eof'] and row['fd'] in ready[0]: self._read_ready(row)
            if writes and self.input_row['fd'] in ready[1]: self._write_ready()
        if self._request_complete() is not True: _fail('terminal_request_incomplete')
        self._eofs_current(); now = self._now()
        if ticket['wait_called']: _fail('parent_wait_already_attempted')
        ticket['wait_called'] = True
        try: returned = self.process_methods[1](timeout=self.active_until - now)
        except BaseException as error:
            ticket['wait_error'] = error; raise
        ticket['wait_return'] = returned  # Preserve a late actual reap before active rejection.
        if type(returned) is int and -255 <= returned <= 255:
            ticket['waited'] = ticket['reaped'] = True
            ticket['wait_ticket'] = ticket['wait_ticket_original'] = (
                self.process, self.process_pid, self.process_methods[1], returned,
                ticket['pipes'][0]['eof_ticket'], ticket['pipes'][1]['eof_ticket'])
        else:
            ticket['unknown'] = True; self.unknown = True; _fail('parent_wait_return')
        self._now(); self._eofs_current()
        if type(self.process.returncode) is not int or self.process.returncode is not returned:
            _fail('parent_wait_changed')
        if returned != 0: _fail('parent_child_failed')


    def _cleanup_pipe_current(self, row):
        # Cleanup-only period; no relaxation of the original active method.
        self._now(True); self._row_original(row)
        if (row['closed'] or row['close_called'] or row['pipe'] is not True or
                row['raw'].closed is not False or row['fileno_method']() != row['fd'] or
            type(row['flags']) is not int or type(row['nonblock_flags']) is not int or
            row['flags'] < 0 or row['flags'] & os.O_ACCMODE != os.O_RDONLY or
                row['nonblock_flags'] != row['flags'] | os.O_NONBLOCK or row['inheritable'] is not False):
            _fail('parent_pipe_changed')
        meta = _metadata(self.io.fstat(row['fd']), True); self._now(True)
        flags = self.io.flags(row['fd']); self._now(True)
        inheritable = self.io.inheritable(row['fd']); self._now(True)
        if meta != row['metadata'] or flags != row['nonblock_flags'] or inheritable is not False:
            _fail('parent_pipe_changed')

    def _read_cleanup(self, row):
        if self.read_attempts + len(self.write_ticket['attempts']) >= MAX_EVENTS: _fail('parent_read_budget')
        self._cleanup_pipe_current(row); self._now(True)
        maximum = MAX_PACKET if row['role'] == 'stdout' else MAX_STDERR
        count = min(65536, maximum + 1 - row['bytes'])
        if count < 1: _fail('parent_pipe_budget')
        self.read_attempts += 1
        try: raw = self.io.read(row['fd'], count)
        except OSError as error:
            row['read_errors'].append(error)
            if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._now(True); return
            raise
        except BaseException as error:
            row['read_errors'].append(error); raise
        row['read_values'].append(raw)  # Preserve even malformed or late returned DATA.
        if type(raw) is bytes:
            row['bytes'] += len(raw)
            if not raw:
                row['eof'] = True
                row['eof_ticket'] = (self.process, self.process_pid, row, row['raw_original'],
                                     row['fd_original'], row['metadata_original'], raw)
        self._now(True)
        if type(raw) is not bytes or len(raw) > count or row['bytes'] > maximum:
            _fail('parent_pipe_budget')
        # Never feed/finish the parser after collect's first failure, or issue DATA.
        if raw and row['role'] == 'stderr':
            self.stderr_parts.append(raw); self.stderr_bytes += len(raw)
        self._now(True)

    def _cleanup_finalize(self):
        self._context()
        if self.cleanup_attempted is not False: _fail('parent_cleanup_already_attempted')
        self.cleanup_attempted = True
        try:
            if self.failure is None or not self.attempted or self.close_attempted:
                _fail('parent_cleanup_context')
            ticket = self.process_attempt
            if ticket is None:
                return  # No actual child was called; do not create a cleanup period.
            if type(ticket) is not dict: _fail('parent_cleanup_inventory_unknown')
            if ticket['called'] is False and self.process is None: return
            # A failed/partial request is NEVER resumed. Close only the known
            # original input, once, so a well-behaved child can observe its EOF.
            self._close_input()
            if (ticket['returned'] is not True or
                    ticket['unknown'] is not False or type(ticket['field_errors']) is not list or
                    ticket['field_errors'] != [] or type(ticket['pipes']) is not tuple or
                    len(ticket['pipes']) != 2 or type(self.process_methods) is not tuple or
                    len(self.process_methods) != 2 or type(self.process_pid) is not int or
                    not 1 <= self.process_pid < (1 << 31) or self.process_pid == self.pid or
                    self.period_original is None):
                _fail('parent_cleanup_inventory_unknown')
            for row, role in zip(ticket['pipes'], ('stdout', 'stderr')):
                if (type(row) is not dict or row['role'] != role or row['pipe'] is not True or
                        row['unknown'] is not False or row['closed'] is not False or
                        row['close_called'] is not False):
                    _fail('parent_cleanup_inventory_unknown')
            self._process_current()
            self.cleanup_ticket = self.cleanup_ticket_original = (
                self, self.failure, ticket, self.process, self.process_pid, self.process_fields,
                self.process_methods, ticket['pipes'], self.period_original, self.cleanup_until)
            if ticket['wait_called'] is not False:
                return  # Original wait attempted/failed/returned; never retry it.
            self._now(True)
            for row in ticket['pipes']: self._cleanup_pipe_current(row)
            while not all(row['eof'] for row in ticket['pipes']):
                if len(self.waits) >= MAX_EVENTS: _fail('parent_select_budget')
                self._process_current()
                for row in ticket['pipes']: self._cleanup_pipe_current(row)
                now = self._now(True)
                fds = tuple(row['fd'] for row in ticket['pipes'] if not row['eof'])
                timeout = min(0.1, self.cleanup_until - now)
                ready = self.io.readable(fds, timeout)
                self.waits.append((fds, timeout, ready)); self._now(True)
                if (type(ready) not in (tuple, list) or len(ready) > len(fds) or
                        any(type(fd) is not int or fd not in fds for fd in ready) or
                        len(set(ready)) != len(ready)):
                    self.unknown = True; _fail('parent_readiness')
                for row in ticket['pipes']:
                    if not row['eof'] and row['fd'] in ready: self._read_cleanup(row)
            self._eofs_current()
            for row in ticket['pipes']: self._cleanup_pipe_current(row)
            now = self._now(True)
            if ticket['wait_called'] is not False: _fail('parent_wait_already_attempted')
            ticket['wait_called'] = True
            try: returned = self.process_methods[1](timeout=self.cleanup_until - now)
            except BaseException as error:
                ticket['wait_error'] = error; raise
            ticket['wait_return'] = returned  # Retain physical reap before late cleanup rejection.
            if type(returned) is int and -255 <= returned <= 255:
                ticket['waited'] = ticket['reaped'] = True
                ticket['wait_ticket'] = ticket['wait_ticket_original'] = (
                    self.process, self.process_pid, self.process_methods[1], returned,
                    ticket['pipes'][0]['eof_ticket'], ticket['pipes'][1]['eof_ticket'])
            else:
                ticket['unknown'] = True; self.unknown = True; _fail('parent_wait_return')
            self._now(True); self._eofs_current()
            if type(self.process.returncode) is not int or self.process.returncode is not returned:
                _fail('parent_wait_changed')
            # Nonzero business exit is DATA; collect still raises its original failure.
        except BaseException as error:
            if self.cleanup_error is None: self.cleanup_error = error
            self.unknown = True
            raise

    def _closed_facts(self):
        self._context()
        ticket = self.process_attempt
        process_closed = (ticket is None or ticket['called'] is False and self.process is None or
            ticket['returned'] is True and ticket['unknown'] is False and ticket['reaped'] is True and
            ticket['waited'] is True and ticket['wait_called'] is True and
            type(ticket['wait_ticket']) is tuple and len(ticket['wait_ticket']) == 6 and
            ticket['wait_ticket'] is ticket['wait_ticket_original'] and
            ticket['wait_ticket'][0] is self.process and ticket['wait_ticket'][1] is self.process_pid and
            ticket['wait_ticket'][2] is self.process_methods[1] and
            ticket['wait_ticket'][3] is ticket['wait_return'] and
            ticket['wait_ticket'][4] is ticket['pipes'][0]['eof_ticket'] and
            ticket['wait_ticket'][5] is ticket['pipes'][1]['eof_ticket'] and
            ticket['wait_error'] is None and ticket['field_errors'] == [])
        if process_closed and self.process is not None:
            self._eofs_current()
            process_closed = (type(self.process.returncode) is int and
                              self.process.returncode is ticket['wait_return'])
        return (not self.unknown and not self.close_errors and process_closed and
            all(row['closed'] is True and row['unknown'] is False and row['close_failure'] is None
                for row in self.rows))

    def close(self):
        self._context()
        if self.close_attempted: return self.closed is True and self._closed_facts()
        self.close_attempted = True
        # No new clock allocation, wait, poll, kill or source IO on close-only.
        for row in reversed(self.rows):
            try: self._close_row(row)
            except BaseException as error:
                row['close_failure'] = error; row['unknown'] = True
                self.close_errors.append(error); self.unknown = True
        self.closed = self._closed_facts()
        return self.closed

    def collect(self):
        if self.attempted or self.close_attempted: _fail('parent_already_attempted')
        self.attempted = True
        data = None
        try:
            _source_contract()  # An unsealed Entry graph refuses before clock/IO.
            self._issue_period()  # The first actual clock sample precedes every IO/definition.
            self._now(); self.io.validate(); self._now()
            self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid < (1 << 31): _fail('parent_pid')
            self._now(); self._anchors()
            self._load_definitions()
            self._read_file(ENTRY_PIN)
            self._read_file(python=True)
            self._spawn()
            self._drain_and_wait()
            self._definitions_current(); self._now()
            data = self.packet_functions[3](self.reader)
            self._now()
            if (type(data) is not self.packet_functions[4] or data.binding != self.binding_original or
                    data.launch_binding != self.terminal_original[0] or
                    data.cleanup_limits != self.terminal_original[1] or
                    data.finish_sha256 != self.request_data.finish_sha256 or
                    self.packet_functions[10](data) != self.finish_raw or
                    self._request_complete() is not True or
                    self.stderr_bytes != 0 or self.reader.value is not data or
                    self.reader.failure is not None or self.reader.ended is not True):
                _fail('parent_packet_binding_or_stderr')
            self._eofs_current(); self._definitions_current(); self._now()
        except BaseException as error:
            if self.failure is None: self.failure = error
            try: self._cleanup_finalize()
            except BaseException as cleanup_error:
                if self.cleanup_error is None: self.cleanup_error = cleanup_error
                self.unknown = True
            raise  # Preserve the actual first collect exception, never cleanup's error.
        finally:
            try: self.close()
            except BaseException as error:
                self.close_errors.append(error); self.unknown = True; self.closed = False
            self.ended = True
        try:
            self._now(); self._eofs_current(); self._definitions_current()
            if (self.failure is not None or not self._closed_facts() or self.closed is not True or
                    self.process_attempt['wait_return'] != 0 or data is None or
                    self._request_complete() is not True):
                _fail('parent_inventory_pending')
            self.result = self.report = self.result_original = data
        except BaseException as error:
            if self.failure is None: self.failure = error
            raise
        return self.result

    def status(self):
        # No paths, identifiers, packet, helper text, source raw or nonce are projected.
        return dict(attempted=self.attempted, ended=self.ended, local_inventory_closed=self.closed,
            resource_pending=self.unknown or not self.closed, failed=self.failure is not None,
            source_definition_count=len(self.module_originals), inventory_rows=len(self.rows),
            stdout_bytes=0 if self.process_attempt is None else self.process_attempt['pipes'][0]['bytes'],
            stderr_bytes=self.stderr_bytes, child_reaped=self.process_attempt is not None and
            self.process_attempt['reaped'] is True, report_observed=self.result is not None,
            stdin_bytes=self.write_ticket['offset'], request_complete=self.write_ticket['completed'],
            rf_requested=False, native_restore_verified=False, independent_restore_verified=False,
            restoration_verified=False, production_admitted=False,
            source_authenticated_for_state=False)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not args: return 0
    _fail('parent_no_command_entry')  # Standalone component; no arbitrary command/path CLI.


if __name__ == '__main__':
    raise SystemExit(main())
