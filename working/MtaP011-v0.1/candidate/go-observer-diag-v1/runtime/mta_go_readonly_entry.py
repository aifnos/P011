"""Explicit private observer entry with sealed terminal dispatch v94, SOURCE only.

The original r2 preflight definitions and 13 arguments are retained below.
Only --collect --terminal enters the new fixed-FD0 request branch. Its
canonical request is bounded by 16384 bytes and must reach actual pipe EOF;
its independently bounded terminal response is at most 393216 bytes. The
original observer MAX_PACKET remains 262144. Neither stdin DATA nor local
write/exit grants Parent acceptance, reap, native restoration or admission.
The new fixed Loader/Packet pins are definitions, not installation evidence.
No target entry, Parent stdin producer or terminal process is run here.


The frozen original v87 entry is preserved. This SOURCE-only replacement adds
only a once-attempted guard to the private packet writer; no replay can issue
another write budget after invalid DATA, short write, expiry or completion.

Default main has no IO. Only fixed --collect binding DATA starts this lifetime.
The future Parent must exec this exact fixed file with Python -I -B, original
absolute active/cleanup caps and its stdout PIPE. There are no caller paths,
commands or FD selectors. Definitions are bootstrapped from two fixed 0400
source files by retained FD/read/hash/once-close, never through sys.path.
The frozen v85 Loader then loads/authenticates 38 actual definitions; the
frozen body performs its original readonly collection and inventory closure.

The complete private packet is streamed only to original stdout FD 1 after
FIFO identity/access validation and nonblocking readback. Every actual write
return, EAGAIN and short write is retained. Active timeout stops transmission;
known original close still happens once after expiry, with typed EBADF.
No packet/exit-zero grants Parent acceptance, child wait/reap, baseline/source
freshness, RF, restoration or production admission. Stager, actual Parent
launch/wait/reap and the consuming pipe reader remain deliberately unbuilt.
No directory is created/repaired and no failed definition is rolled back.
"""
import builtins
import errno
import hashlib
import math
import os
import re
import select
import stat
import sys
import threading
import time
import types

ROOT = '/var/volatile/tmp/p011-mta-go-observer-diag-v1'
RUNTIME = ROOT + '/runtime'
ALIAS = '/tmp/p011-mta-go-observer-diag-v1'
ENTRY_PATH = RUNTIME + '/mta_go_readonly_entry.py'
STDOUT_FD = 1
ARM_READ = 0x88000
MAX_ACTIVE = 30.0
MAX_SOURCE_READS = 64
MAX_WRITES = 4096
MAX_PACKET = 262144
SOURCE_PINS = (
    ('mta_go_readonly_loader', 36543,
     '18de54e9dd3db344aaff522a873bc1094798eda6766b1a80259a71999dff919d'),
    ('mta_observer_packet', 48253,
     '004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f'),
)
_SOURCE_PINS_ORIGINAL = SOURCE_PINS
_BIND_KEYS = frozenset(('nonce', 'task_id', 'native_epoch', 'operation_epoch',
                       'until', 'cleanup_until'))
_ENTRY_INVENTORY = []


class ReadonlyEntryError(ValueError):
    """Constant code only; never include binding, path or packet contents."""
    pass


def _fail(reason):
    raise ReadonlyEntryError(reason) from None


def _finite(value):
    return type(value) is float and math.isfinite(value) and 0 < value < 1e12


def _binding(value):
    if type(value) is not dict or set(value) != _BIND_KEYS:
        _fail('observer_binding')
    if any(type(value[name]) is not str or re.fullmatch('[0-9a-f]{32}', value[name]) is None
           for name in ('nonce', 'task_id')):
        _fail('observer_binding')
    if (any(type(value[name]) is not int or not 1 <= value[name] < (1 << 53)
            for name in ('native_epoch', 'operation_epoch')) or
            value['native_epoch'] != value['operation_epoch'] or
            not _finite(value['until']) or not _finite(value['cleanup_until']) or
            not value['until'] <= value['cleanup_until'] <= value['until'] + 5.0):
        _fail('observer_binding')
    return tuple((key, value[key]) for key in sorted(_BIND_KEYS))


def _meta(value, descriptor=False):
    names = (('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
             if descriptor else ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    result = tuple(getattr(value, name, None) for name in names)
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        _fail('observer_metadata')
    return result


class _LinuxIo(object):
    def __init__(self):
        self._ctypes = self._libc = self._fcntl = None
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                sys.flags.optimize or sys.flags.isolated != 1 or not sys.dont_write_bytecode or
                os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000 or
                __file__ != ENTRY_PATH or sys.argv[0] != ENTRY_PATH):
            _fail('observer_platform_or_entry')
        # Stripped P011 Python lacks fcntl; retain the actual libc ABI instead.
        import ctypes
        library = ctypes.CDLL(None, use_errno=True)
        command = library.fcntl
        command.argtypes = (ctypes.c_int, ctypes.c_int)
        command.restype = ctypes.c_int
        self._ctypes, self._libc, self._fcntl = ctypes, library, command
    def pid(self): return os.getpid()
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, ARM_READ)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)
    def flags(self, fd):
        if (self._ctypes is None or self._libc is None or self._fcntl is None or
                self._libc.fcntl is not self._fcntl):
            _fail('observer_unvalidated')
        if type(fd) is not int or not 0 <= fd <= 0x7fffffff:
            _fail('observer_fcntl_input')
        self._ctypes.set_errno(0)
        result = self._fcntl(fd, 3)  # Linux F_GETFL; no retry or FD replacement.
        saved_errno = self._ctypes.get_errno()
        if type(result) is not int: _fail('observer_fcntl_return')
        if result < 0:
            error = (OSError(saved_errno, 'observer_fcntl_failed')
                     if type(saved_errno) is int and 1 <= saved_errno <= 4095
                     else ReadonlyEntryError('observer_fcntl_errno'))
            error.fcntl_result, error.fcntl_errno = result, saved_errno
            raise error from None
        if result > 0x7fffffff: _fail('observer_fcntl_return')
        return result
    def set_flags(self, fd, value):
        if (self._ctypes is None or self._libc is None or self._fcntl is None or
                self._libc.fcntl is not self._fcntl):
            _fail('observer_unvalidated')
        if (type(fd) is not int or not 0 <= fd <= 0x7fffffff or
                type(value) is not int or not 0 <= value <= 0x7fffffff):
            _fail('observer_fcntl_input')
        self._ctypes.set_errno(0)
        result = self._fcntl(fd, 4, self._ctypes.c_int(value))  # Linux F_SETFL.
        saved_errno = self._ctypes.get_errno()
        if type(result) is not int: _fail('observer_fcntl_return')
        if result < 0:
            error = (OSError(saved_errno, 'observer_fcntl_failed')
                     if type(saved_errno) is int and 1 <= saved_errno <= 4095
                     else ReadonlyEntryError('observer_fcntl_errno'))
            error.fcntl_result, error.fcntl_errno = result, saved_errno
            raise error from None
        if result != 0: _fail('observer_fcntl_return')
        return result
    def pipe_buf(self, fd): return os.fpathconf(fd, 'PC_PIPE_BUF')
    def writable(self, fd, timeout): return select.select((), (fd,), (), timeout)[1]
    def write(self, fd, raw): return os.write(fd, raw)


class ReadonlyObserverEntry(object):
    """One original worker/cap and private output inventory, not a grant."""
    def __init__(self, binding, _io=None, _clock=None):
        self.binding, self.binding_original = binding, _binding(binding)
        self.until, self.cleanup_until = binding['until'], binding['cleanup_until']
        self.worker = threading.current_thread()
        self.io = self.io_original = _LinuxIo() if _io is None else _io
        self.clock = self.clock_original = time.monotonic if _clock is None else _clock
        if not callable(self.clock): _fail('observer_clock')
        self.pid, self.last, self.roots = None, None, None
        self.rows = self.rows_original = []
        self.modules = self.modules_original = {}
        self.module_originals = self.definitions_original = []
        self.output = self.output_original = None
        self.loader = self.loader_original = self.body = self.body_original = None
        self.result = self.packet = self.packet_original = None
        self.attempted = self.ended = self.closed = self.packet_written = False
        self.write_attempted = False
        self.failure, self.close_errors = None, []
        self.unknown = self.transmission_unknown = False
        self.transmitted_bytes = 0

    def _context(self):
        if (self.io is not self.io_original or self.clock is not self.clock_original or
                threading.current_thread() is not self.worker or
                _binding(self.binding) != self.binding_original or
                self.until is not self.binding['until'] or self.cleanup_until is not self.binding['cleanup_until'] or
                self.rows is not self.rows_original or self.modules is not self.modules_original or
                self.module_originals is not self.definitions_original or
                self.output is not self.output_original or self.packet is not self.packet_original or
                SOURCE_PINS is not _SOURCE_PINS_ORIGINAL):
            _fail('observer_owner_changed')
        if self.pid is not None and self.io.pid() != self.pid:
            _fail('observer_owner_changed')

    def _now(self):
        self._context()
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(float(value)) or
                not 0 <= value < 1e12 or self.last is not None and value < self.last):
            _fail('observer_clock')
        self.last = float(value)
        if value >= self.until: _fail('observer_expired')
        return float(value)

    def _anchors(self):
        result = []
        for path, mode, target in (
                ('/', None, None), ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                (ROOT, stat.S_IFDIR | 0o700, None), (RUNTIME, stat.S_IFDIR | 0o700, None)):
            self._now(); actual = self.io.stat(path); meta = _meta(actual); self._now()
            if (meta[3:5] != (0, 0) or meta[5] < 1 or
                    mode is None and (not stat.S_ISDIR(meta[2]) or meta[2] & 0o022) or
                    mode is not None and meta[2] != mode):
                _fail('observer_root')
            if target is not None:
                times = tuple(getattr(actual, key, None) for key in ('st_mtime_ns', 'st_ctime_ns'))
                if meta[5] != 1 or meta[6] != len(target) or any(
                        type(item) is not int or not 0 <= item < (1 << 64) for item in times):
                    _fail('observer_alias')
                self._now(); observed = self.io.readlink(path); self._now()
                if type(observed) is not str or observed != target: _fail('observer_alias')
                result.append((path, meta + times, target))
            else:
                result.append((path, meta[:5], None))
        for alias, physical in ((ALIAS, ROOT), (ALIAS + '/runtime', RUNTIME)):
            self._now(); left = _meta(self.io.stat(alias)); self._now()
            right = _meta(self.io.stat(physical)); self._now()
            if left[:5] != right[:5]: _fail('observer_alias')
        value = tuple(result)
        if self.roots is None: self.roots = value
        elif value != self.roots: _fail('observer_root_changed')
        return value

    def _close(self, row, descriptor=False):
        self._context()  # Original known close-only is not suppressed by expiry.
        if (type(row) is not dict or row is not self.output and not any(row is item for item in self.rows) or
                type(descriptor) is not bool or descriptor is not (row is self.output)):
            _fail('observer_close_ticket')
        if row['close_called'] or row['closed']: return
        if (row['unknown'] or type(row['fd']) is not int or row['fd'] is not row['fd_original'] or
                row['metadata'] is not row['metadata_original']):
            self.unknown = True; return
        row['close_called'] = True
        try:
            if _meta(self.io.fstat(row['fd']), descriptor) != row['metadata']:
                _fail('observer_close_identity')
            row['close_return'] = self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = (row['close_return'] is None and type(error.errno) is int and
                                 error.errno == errno.EBADF)
        except BaseException as error:
            row['close_failure'] = error
            self.close_errors.append(error); row['unknown'] = True
        if row['closed'] is not True: self.unknown = True

    def _read_source(self, expected):
        if expected not in SOURCE_PINS or len(self.rows) >= 2: _fail('observer_source_role')
        name, size, pin = expected
        self._now(); before = self._anchors(); self._now()
        row = dict(name=name, path=RUNTIME + '/' + name + '.py', fd=None, fd_original=None,
            metadata=None, metadata_original=None,
            unknown=True, closed=False, close_called=False, close_return=None,
            close_error=None, close_failure=None, raw=None, read_values=[], open_error=None)
        self.rows.append(row)
        try:
            try: row['fd'] = self.io.open(row['path'])
            except OSError as error:
                row['open_error'] = error
                known = type(error.errno) is int and 1 <= error.errno <= 4095
                row['closed'], row['unknown'] = known, not known
                if not known: self.unknown = True
                raise
            except BaseException as error:
                row['open_error'] = error; self.unknown = True; raise
            if (type(row['fd']) is not int or row['fd'] <= 2 or
                    any(other is not row and other['fd'] == row['fd'] and not other['closed']
                        for other in self.rows)):
                self.unknown = True; _fail('observer_source_fd')
            row['fd_original'] = row['fd']
            row['metadata'] = row['metadata_original'] = _meta(self.io.fstat(row['fd']))
            row['unknown'] = False
            self._now()  # A returned FD has its original close identity before active rejection.
            meta = row['metadata']
            if meta[2:] != (stat.S_IFREG | 0o400, 0, 0, 1, size): _fail('observer_source_metadata')
            parts, total = [], 0
            while total <= size:
                if len(row['read_values']) >= MAX_SOURCE_READS: _fail('observer_source_budget')
                self._now(); count = min(65536, size + 1 - total)
                raw = self.io.read(row['fd'], count)
                row['read_values'].append(raw)
                self._now()
                if type(raw) is not bytes or len(raw) > count: _fail('observer_source_bytes')
                parts.append(raw); total += len(raw)
                if not raw: break
            raw = b''.join(parts); row['raw'] = raw
            self._now(); after_fd = _meta(self.io.fstat(row['fd'])); self._now()
            after_path = _meta(self.io.stat(row['path'])); self._now()
            after_alias = _meta(self.io.stat(ALIAS + '/runtime/' + name + '.py')); self._now()
            if (len(raw) != size or hashlib.sha256(raw).hexdigest() != pin or
                    after_fd != meta or after_path != meta or after_alias != meta or self._anchors() != before):
                _fail('observer_source_changed')
            self._now()
        except BaseException as error:
            row['failure'] = error
            raise
        finally:
            try: self._close(row)
            except BaseException as error:
                row['close_failure'] = error
                self.close_errors.append(error); self.unknown = True
        if not row['closed'] or row['unknown'] or self.unknown: _fail('observer_source_unclosed')
        return raw

    def _load_module(self, expected):
        name = expected[0]
        if name in sys.modules or name in self.modules: _fail('observer_namespace_busy')
        raw = self._read_source(expected)
        self._now()
        original_import = builtins.__import__

        def pinned_import(import_name, globals=None, locals=None, fromlist=(), level=0):
            if type(import_name) is not str or level: _fail('observer_import')
            if import_name in ('p011_json', 'mta_snapshot_data'):
                if (self.loader is None or self.loader is not self.loader_original or
                        sys.modules.get(import_name) is not self.loader.modules.get(import_name)):
                    _fail('observer_import')
                return self.loader.modules[import_name]
            if import_name.startswith(('mta_', 'p011_')): _fail('observer_import')
            return original_import(import_name, globals, locals, fromlist, level)

        module = types.ModuleType(name)
        module.__file__ = RUNTIME + '/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
        self.modules[name] = module
        self.module_originals.append((name, module, module.__dict__))
        sys.modules[name] = module  # Failure remains retained; no namespace rollback.
        exec(raw, module.__dict__)
        self._now()
        return module

    def _adopt_stdout(self):
        self._now()
        row = dict(fd=STDOUT_FD, fd_original=STDOUT_FD, metadata=None, metadata_original=None,
            unknown=True, closed=False, close_called=False,
            close_return=None, close_error=None, close_failure=None, flags=None,
            nonblock_flags=None, set_flags_return=None, pipe_buf=None,
            write_returns=[], write_errors=[], waits=[])
        self.output = self.output_original = row
        meta = _meta(self.io.fstat(STDOUT_FD), True)
        if meta[2] != stat.S_IFIFO | 0o600 or meta[3:6] != (0, 0, 1):
            _fail('observer_stdout_not_private_pipe')
        row['metadata'] = row['metadata_original'] = meta
        row['unknown'] = False
        self._now()
        flags = self.io.flags(STDOUT_FD)
        if type(flags) is not int or flags < 0 or flags & os.O_ACCMODE != os.O_WRONLY:
            _fail('observer_stdout_access')
        row['flags'] = flags
        self._now()
        row['set_flags_return'] = self.io.set_flags(STDOUT_FD, flags | os.O_NONBLOCK)
        self._now()
        current = self.io.flags(STDOUT_FD)
        if (type(current) is not int or current != flags | os.O_NONBLOCK or
                _meta(self.io.fstat(STDOUT_FD), True) != meta):
            _fail('observer_stdout_nonblocking')
        row['nonblock_flags'] = current
        self._now()
        row['pipe_buf'] = self.io.pipe_buf(STDOUT_FD)
        self._now()
        if type(row['pipe_buf']) is not int or not 512 <= row['pipe_buf'] <= (1 << 20):
            _fail('observer_stdout_atomic_cap')

    def _stdout_current(self):
        row = self.output
        if (row is None or row['unknown'] or row['closed'] or row['close_called'] or
                row['fd'] != STDOUT_FD or row['fd'] is not row['fd_original'] or
                row['metadata'] is not row['metadata_original'] or row['nonblock_flags'] is None or
                type(row['pipe_buf']) is not int or not 512 <= row['pipe_buf'] <= (1 << 20) or
                _meta(self.io.fstat(STDOUT_FD), True) != row['metadata'] or
                self.io.flags(STDOUT_FD) != row['nonblock_flags']):
            _fail('observer_stdout_changed')

    def _write_packet(self):
        if self.write_attempted: _fail('observer_write_already_attempted')
        self.write_attempted = True
        if (self.packet is not self.packet_original or type(self.packet) is not bytes or
                not 1 <= len(self.packet) <= MAX_PACKET):
            _fail('observer_packet_limit')
        row, offset, attempts = self.output, 0, 0
        while offset < len(self.packet):
            if attempts >= MAX_WRITES: _fail('observer_write_budget')
            attempts += 1
            self._now(); self._stdout_current(); now = self._now()
            timeout = min(0.1, self.until - now)
            ready = self.io.writable(STDOUT_FD, timeout)
            row['waits'].append((timeout, ready))
            self._now()
            if (type(ready) not in (tuple, list) or any(type(fd) is not int or fd != STDOUT_FD for fd in ready) or
                    len(ready) > 1):
                self.transmission_unknown = True; _fail('observer_write_ready')
            if not ready: continue
            self._stdout_current(); self._now()
            chunk = self.packet[offset:offset + min(4096, row['pipe_buf'])]
            try: returned = self.io.write(STDOUT_FD, chunk)
            except OSError as error:
                row['write_errors'].append((offset, len(chunk), error))
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    self._now(); continue
                self.transmission_unknown = True; raise
            except BaseException as error:
                row['write_errors'].append((offset, len(chunk), error))
                self.transmission_unknown = True; raise
            row['write_returns'].append((offset, len(chunk), returned))
            if type(returned) is not int or not 0 < returned <= len(chunk):
                self.transmission_unknown = True; _fail('observer_write_unknown')
            offset += returned
            self.transmitted_bytes = offset  # Preserve actual partial/late returns before active check.
            if returned != len(chunk):
                # Each nonblocking chunk is <= original actual PC_PIPE_BUF.
                # A short return is retained, but never resumed or signed complete.
                self.transmission_unknown = True; _fail('observer_short_write')
            self._now()
        self._stdout_current(); self._now()
        self.packet_written = True  # Local transmission only, NOT Parent acceptance/EOF/reap.

    def collect(self):
        if self.attempted: _fail('observer_already_attempted')
        self.attempted = True
        try:
            self.io.validate()
            self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid < (1 << 31): _fail('observer_pid')
            issued = self._now()
            if not 0 < self.until - issued <= MAX_ACTIVE: _fail('observer_active_cap')
            self._adopt_stdout()
            if any(type(name) is str and name.startswith(('mta_', 'p011_')) for name in sys.modules):
                _fail('observer_namespace_busy')
            loader_module = self._load_module(SOURCE_PINS[0])
            self.loader = loader_module.ReadonlySourceLoader(self.until)
            self.loader_original = self.loader
            if self.loader.until is not self.until: _fail('observer_cap_changed')
            self.loader.load()
            self.loader.authenticate()
            self._now()
            packet_module = self._load_module(SOURCE_PINS[1])
            body_module = self.loader.modules['mta_go_readonly_preflight']
            self.body = body_module.ReadonlyPreflight(self.loader, self.binding)
            self.body_original = self.body
            result = self.body.collect()
            self.result = result
            if (self.body is not self.body_original or self.body.result is not result or
                    self.body.failure is not None or self.body.closed is not True or
                    self.body.ended is not True or self.body.unknown is not False):
                _fail('observer_body_unclosed')
            self.loader.authenticate(); self._now()
            self.packet = self.packet_original = packet_module.encode_result(result)
            self._now(); self._write_packet()
        except BaseException as error:
            self.failure = error
            raise
        finally:
            for row in reversed(self.rows):
                try: self._close(row)
                except BaseException as error: self.close_errors.append(error); self.unknown = True
            if self.output is not None:
                try: self._close(self.output, True)
                except BaseException as error: self.close_errors.append(error); self.unknown = True
            self.ended = True
            self.closed = (not self.unknown and not self.close_errors and
                self.output is not None and self.output['closed'] is True and not self.output['unknown'] and
                all(row['closed'] and not row['unknown'] for row in self.rows) and
                (self.loader is None or self.loader is self.loader_original and
                 self.loader.ended and not self.loader.pending) and
                (self.body is None or self.body is self.body_original and self.body.ended and self.body.closed))
        if not self.closed or not self.packet_written:
            error = ReadonlyEntryError('observer_entry_unclosed')
            if self.failure is None: self.failure = error
            raise error
        return self

    def status(self):
        return dict(attempted=self.attempted, ended=self.ended, local_inventory_closed=self.closed,
            resource_pending=self.unknown or not self.closed, failed=self.failure is not None,
            source_bootstrap_count=len(self.module_originals), transmitted_bytes=self.transmitted_bytes,
            packet_written=self.packet_written, transmission_unknown=self.transmission_unknown,
            parent_accepted=False, child_reaped=False, rf_requested=False,
            restoration_verified=False, production_admitted=False)


def _arguments(args):
    flags = ('--nonce', '--task-id', '--native-epoch', '--operation-epoch', '--until', '--cleanup-until')
    if (type(args) not in (list, tuple) or len(args) != 13 or args[0] != '--collect' or
            any(type(arg) is not str or len(arg) > 128 for arg in args) or
            tuple(args[1::2]) != flags):
        _fail('observer_explicit_arguments')
    values = args[2::2]
    if any(re.fullmatch('[1-9][0-9]{0,15}', text) is None for text in values[2:4]):
        _fail('observer_explicit_arguments')
    try:
        until, cleanup = float(values[4]), float(values[5])
        if repr(until) != values[4] or repr(cleanup) != values[5]: _fail('observer_explicit_arguments')
        binding = dict(nonce=values[0], task_id=values[1], native_epoch=int(values[2]),
                       operation_epoch=int(values[3]), until=until, cleanup_until=cleanup)
    except (ValueError, OverflowError):
        _fail('observer_explicit_arguments')
    _binding(binding)
    return binding


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not args: return 0  # No loader, pipe adoption, clock, collector, helper or target IO.
    binding = _arguments(args)
    value = ReadonlyObserverEntry(binding)
    _ENTRY_INVENTORY.append(value)  # Retain creator before any actual collect IO.
    try: value.collect()
    except BaseException as error: _private_failure_diag(value, error); return 1  # Original failure retained.
    return 0



# Terminal dispatch is separate from the unchanged preflight method bodies.
STDIN_FD = 0
TERMINAL_MAX_REQUEST = 16384
TERMINAL_MAX_PACKET = 393216
TERMINAL_MAX_READ_EVENTS = 4096


class _TerminalLinuxIo(_LinuxIo):
    def readable(self, fd, timeout):
        return select.select((fd,), (), (), timeout)[0]


class ReadonlyTerminalEntry(ReadonlyObserverEntry):
    """Fixed request/result pipes and original caps; no restoration grant."""
    def __init__(self, binding):
        ReadonlyObserverEntry.__init__(self, binding, _io=_TerminalLinuxIo())
        self.input = self.input_original = None
        self.request_attempted = self.request_eof = False
        self.request = self.request_original = None
        self.request_raw = self.request_raw_original = None
        self.request_size = 0
        self.request_source = self.request_source_original = None
        self.request_fields_original = None

    def _context(self):
        ReadonlyObserverEntry._context(self)
        if (self.input is not self.input_original or
                self.request is not self.request_original or
                self.request_raw is not self.request_raw_original or
                self.request_source is not self.request_source_original):
            _fail('terminal_entry_original_changed')
        if self.request_source is not None:
            module, namespace, data_class, decode, encode, result_encode = self.request_source
            if (self.modules.get('mta_observer_packet') is not module or
                    sys.modules.get('mta_observer_packet') is not module or
                    module.__dict__ is not namespace or
                    namespace.get('TerminalRequestData') is not data_class or
                    namespace.get('decode_terminal_request') is not decode or
                    namespace.get('encode_terminal_request') is not encode or
                    namespace.get('encode_terminal_result') is not result_encode):
                _fail('terminal_packet_source_changed')

    def _adopt_stdin(self):
        self._now()
        if self.input is not None: _fail('terminal_stdin_already_adopted')
        row = dict(fd=STDIN_FD, fd_original=STDIN_FD, metadata=None, metadata_original=None,
            unknown=True, closed=False, close_called=False, close_return=None,
            close_error=None, close_failure=None, flags=None, nonblock_flags=None,
            set_flags_return=None, read_values=[], read_errors=[], waits=[], eof=False)
        self.input = self.input_original = row  # Strong ticket before the first FD observation.
        meta = _meta(self.io.fstat(STDIN_FD), True)
        row['metadata'] = row['metadata_original'] = meta
        row['unknown'] = False  # Original identity is retained before active rejection.
        self._now()
        if (meta[2] != stat.S_IFIFO | 0o600 or meta[3:6] != (0, 0, 1) or
                self.output is not None and meta[:2] == self.output['metadata'][:2]):
            _fail('terminal_stdin_not_private_pipe')
        flags = self.io.flags(STDIN_FD)
        row['flags'] = flags
        self._now()
        if type(flags) is not int or flags < 0 or flags & os.O_ACCMODE != os.O_RDONLY:
            _fail('terminal_stdin_access')
        row['set_flags_return'] = self.io.set_flags(STDIN_FD, flags | os.O_NONBLOCK)
        self._now()
        current = self.io.flags(STDIN_FD)
        row['nonblock_flags'] = current
        if (type(current) is not int or current != flags | os.O_NONBLOCK or
                _meta(self.io.fstat(STDIN_FD), True) != meta):
            _fail('terminal_stdin_nonblocking')
        self._now()

    def _stdin_current(self):
        row = self.input
        if (row is None or row is not self.input_original or row['unknown'] is not False or
                row['closed'] is not False or row['close_called'] is not False or
                row['fd'] != STDIN_FD or row['fd'] is not row['fd_original'] or
                row['metadata'] is not row['metadata_original'] or
                row['nonblock_flags'] is None or
                _meta(self.io.fstat(STDIN_FD), True) != row['metadata'] or
                self.io.flags(STDIN_FD) != row['nonblock_flags']):
            _fail('terminal_stdin_changed')

    def _close_stdin(self):
        self._context()  # Known original close-only is independent of active expiry.
        row = self.input
        if row is None: return
        if row is not self.input_original or type(row) is not dict:
            _fail('terminal_stdin_close_ticket')
        if row['close_called'] or row['closed']: return
        if (row['unknown'] or type(row['fd']) is not int or row['fd'] != STDIN_FD or
                row['fd'] is not row['fd_original'] or
                row['metadata'] is not row['metadata_original']):
            self.unknown = True; return
        row['close_called'] = True
        try:
            if _meta(self.io.fstat(STDIN_FD), True) != row['metadata']:
                _fail('terminal_stdin_close_identity')
            row['close_return'] = self.io.close(STDIN_FD)
            try: self.io.fstat(STDIN_FD)
            except OSError as error:
                row['close_error'] = error
                row['closed'] = (row['close_return'] is None and type(error.errno) is int and
                                 error.errno == errno.EBADF)
        except BaseException as error:
            row['close_failure'] = error
            self.close_errors.append(error); row['unknown'] = True
        if row['closed'] is not True: self.unknown = True

    def _read_terminal_request(self):
        if self.request_attempted: _fail('terminal_request_already_attempted')
        self.request_attempted = True  # Invalid, late or partial attempts cannot receive a new budget.
        row, parts, size, events = self.input, [], 0, 0
        if row is None: _fail('terminal_request_without_stdin')
        while not self.request_eof:
            if events >= TERMINAL_MAX_READ_EVENTS: _fail('terminal_request_budget')
            events += 1
            self._now(); self._stdin_current(); now = self._now()
            timeout = min(0.1, self.until - now)
            ready = self.io.readable(STDIN_FD, timeout)
            row['waits'].append((timeout, ready))
            self._now()
            if (type(ready) not in (tuple, list) or len(ready) > 1 or
                    any(type(fd) is not int or fd != STDIN_FD for fd in ready)):
                _fail('terminal_request_ready')
            if not ready: continue
            self._stdin_current(); self._now()
            count = min(4096, TERMINAL_MAX_REQUEST + 1 - size)
            try: raw = self.io.read(STDIN_FD, count)
            except OSError as error:
                row['read_errors'].append(error)
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    self._now(); continue
                raise
            except BaseException as error:
                row['read_errors'].append(error); raise
            row['read_values'].append(raw)  # Retain the actual returned value before deadline checks.
            if type(raw) is bytes:
                parts.append(raw); size += len(raw)
                self.request_size = size
                self.request_raw = self.request_raw_original = b''.join(parts)
                if not raw:
                    row['eof'] = self.request_eof = True  # Actual read(b'') only; not a parser assertion.
            self._now()
            if type(raw) is not bytes or len(raw) > count:
                _fail('terminal_request_bytes')
            if size > TERMINAL_MAX_REQUEST: _fail('terminal_request_limit')
        self._stdin_current(); self._now()
        if not 1 <= size <= TERMINAL_MAX_REQUEST: _fail('terminal_request_limit')
        # Keep original FD0 occupied through all fixed source/body opens.
        # Closing it here would let a later actual os.open reuse reserved FD0.
        return self.request_raw

    def _request_current(self):
        self._context()
        if (self.request_source is None or self.request is None or
                type(self.request) is not self.request_source[2] or
                self.request_fields_original is None or
                self.request.binding is not self.request_fields_original[0] or
                self.request.launch_binding is not self.request_fields_original[1] or
                self.request.cleanup_limits is not self.request_fields_original[2] or
                self.request.private_finish_ascii() is not self.request_fields_original[3] or
                self.request.private_request_ascii() is not self.request_raw_original or
                self.request.binding != self.binding_original or
                self.request_source[4](dict(self.request.binding), dict(self.request.launch_binding),
                    self.request.private_finish_ascii(), dict(self.request.cleanup_limits)) != self.request_raw):
            _fail('terminal_request_changed')

    def _write_packet(self):
        if self.write_attempted: _fail('observer_write_already_attempted')
        self.write_attempted = True
        if (self.packet is not self.packet_original or type(self.packet) is not bytes or
                not 1 <= len(self.packet) <= TERMINAL_MAX_PACKET):
            _fail('terminal_packet_limit')
        self._request_current()
        row, offset, attempts = self.output, 0, 0
        while offset < len(self.packet):
            if attempts >= MAX_WRITES: _fail('observer_write_budget')
            attempts += 1
            self._now(); self._stdout_current(); now = self._now()
            timeout = min(0.1, self.until - now)
            ready = self.io.writable(STDOUT_FD, timeout)
            row['waits'].append((timeout, ready))
            self._now()
            if (type(ready) not in (tuple, list) or any(type(fd) is not int or fd != STDOUT_FD for fd in ready) or
                    len(ready) > 1):
                self.transmission_unknown = True; _fail('observer_write_ready')
            if not ready: continue
            self._stdout_current(); self._now()
            chunk = self.packet[offset:offset + min(4096, row['pipe_buf'])]
            try: returned = self.io.write(STDOUT_FD, chunk)
            except OSError as error:
                row['write_errors'].append((offset, len(chunk), error))
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    self._now(); continue
                self.transmission_unknown = True; raise
            except BaseException as error:
                row['write_errors'].append((offset, len(chunk), error))
                self.transmission_unknown = True; raise
            row['write_returns'].append((offset, len(chunk), returned))
            if type(returned) is not int or not 0 < returned <= len(chunk):
                self.transmission_unknown = True; _fail('observer_write_unknown')
            offset += returned
            self.transmitted_bytes = offset
            if returned != len(chunk):
                self.transmission_unknown = True; _fail('observer_short_write')
            self._now()
        self._request_current(); self._stdout_current(); self._now()
        self.packet_written = True  # Local write only: not Parent EOF/reap/restore.

    def collect(self):
        if self.attempted: _fail('observer_already_attempted')
        self.attempted = True
        try:
            self.io.validate()
            self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid < (1 << 31): _fail('observer_pid')
            issued = self._now()
            if not 0 < self.until - issued <= MAX_ACTIVE: _fail('observer_active_cap')
            self._adopt_stdout()
            self._adopt_stdin()
            raw = self._read_terminal_request()
            if any(type(name) is str and name.startswith(('mta_', 'p011_')) for name in sys.modules):
                _fail('observer_namespace_busy')
            loader_module = self._load_module(SOURCE_PINS[0])
            self.loader = loader_module.ReadonlySourceLoader(self.until)
            self.loader_original = self.loader
            if self.loader.until is not self.until: _fail('observer_cap_changed')
            self.loader.load()
            self.loader.authenticate()
            self._now()
            packet_module = self._load_module(SOURCE_PINS[1])
            self.request_source = self.request_source_original = (
                packet_module, packet_module.__dict__, packet_module.TerminalRequestData,
                packet_module.decode_terminal_request, packet_module.encode_terminal_request,
                packet_module.encode_terminal_result)
            self.request = self.request_original = self.request_source[3](raw)
            if type(self.request) is not self.request_source[2]:
                _fail('terminal_request_type')
            self.request_fields_original = (self.request.binding, self.request.launch_binding,
                self.request.cleanup_limits, self.request.private_finish_ascii())
            self._request_current(); self._now()
            body_module = self.loader.modules['mta_go_readonly_preflight']
            self.body = body_module.ReadonlyTerminalObserver(self.loader, self.binding,
                self.request.private_finish_ascii(), dict(self.request.launch_binding),
                dict(self.request.cleanup_limits))
            self.body_original = self.body
            result = self.body.collect()
            self.result = result
            if (self.body is not self.body_original or self.body.result is not result or
                    self.body.failure is not None or self.body.closed is not True or
                    self.body.ended is not True or self.body.unknown is not False):
                _fail('observer_body_unclosed')
            self.loader.authenticate(); self._request_current(); self._now()
            self.packet = self.packet_original = self.request_source[5](result)
            self._now(); self._stdin_current(); self._close_stdin()
            if self.input['closed'] is not True or self.input['unknown'] or self.unknown:
                _fail('terminal_stdin_unclosed')
            self._now(); self._write_packet()
        except BaseException as error:
            self.failure = error
            raise  # Preserve the original primary; close failures remain separate and private.
        finally:
            try: self._close_stdin()
            except BaseException as error: self.close_errors.append(error); self.unknown = True
            for row in reversed(self.rows):
                try: self._close(row)
                except BaseException as error: self.close_errors.append(error); self.unknown = True
            if self.output is not None:
                try: self._close(self.output, True)
                except BaseException as error: self.close_errors.append(error); self.unknown = True
            self.ended = True
            self.closed = (not self.unknown and not self.close_errors and
                self.input is not None and self.input['closed'] is True and not self.input['unknown'] and
                self.output is not None and self.output['closed'] is True and not self.output['unknown'] and
                all(row['closed'] and not row['unknown'] for row in self.rows) and
                (self.loader is None or self.loader is self.loader_original and
                 self.loader.ended and not self.loader.pending) and
                (self.body is None or self.body is self.body_original and self.body.ended and self.body.closed))
        if not self.closed or not self.packet_written:
            error = ReadonlyEntryError('terminal_entry_unclosed')
            if self.failure is None: self.failure = error
            raise error
        return self

    def status(self):
        value = ReadonlyObserverEntry.status(self)
        value.update(terminal_mode=True, request_attempted=self.request_attempted,
            request_bytes=self.request_size, request_eof=self.request_eof,
            request_parsed=self.request is not None,
            native_restore_verified=False, independent_restore_verified=False)
        return value


def _terminal_arguments(args):
    if (type(args) not in (list, tuple) or len(args) != 14 or
            any(type(arg) is not str or len(arg) > 128 for arg in args) or
            args[0:2] not in (['--collect', '--terminal'], ('--collect', '--terminal'))):
        _fail('terminal_explicit_arguments')
    return _arguments([args[0]] + list(args[2:]))


def main94(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not args or type(args) in (list, tuple) and len(args) == 13:
        return main(args)  # Exact original no-IO default and original preflight arguments.
    binding = _terminal_arguments(args)
    value = ReadonlyTerminalEntry(binding)
    _ENTRY_INVENTORY.append(value)  # Original creator retained before any actual IO.
    try: value.collect()
    except BaseException: return 1  # No diagnostic FD write can cover the retained primary.
    return 0



# Private failure DATA only. FD2 identity/nonblocking/closure is NOT certified.
_PRIVATE_DIAG_TYPES = (('builtins', 'AssertionError', 1), ('builtins', 'AttributeError', 2), ('builtins', 'BaseException', 3), ('builtins', 'BlockingIOError', 4), ('builtins', 'Exception', 5), ('builtins', 'FileNotFoundError', 6), ('builtins', 'ImportError', 7), ('builtins', 'IndexError', 8), ('builtins', 'InterruptedError', 9), ('builtins', 'KeyError', 10), ('builtins', 'MemoryError', 11), ('builtins', 'NameError', 12), ('builtins', 'NotImplementedError', 13), ('builtins', 'OSError', 14), ('builtins', 'OverflowError', 15), ('builtins', 'PermissionError', 16), ('builtins', 'RuntimeError', 17), ('builtins', 'StopIteration', 18), ('builtins', 'SyntaxError', 19), ('builtins', 'TimeoutError', 20), ('builtins', 'TypeError', 21), ('builtins', 'UnicodeError', 22), ('builtins', 'ValueError', 23), ('builtins', 'ZeroDivisionError', 24), ('mta_client_baseline', 'BaselineError', 25), ('mta_client_caps', 'CapsDecodeError', 26), ('mta_client_caps_transport', 'CapsTransportError', 27), ('mta_client_connection', 'ConnectionError', 28), ('mta_client_control_frame', 'ControlFrameError', 29), ('mta_client_coordination', 'CoordinationError', 30), ('mta_client_dora', 'DoraError', 31), ('mta_client_dynamic_ip', 'DynamicIpError', 32), ('mta_client_executor', 'ExecutorError', 33), ('mta_client_files', 'ClientFileError', 34), ('mta_client_journal_codec', 'JournalCodecError', 35), ('mta_client_kernel_proof', 'KernelReadError', 36), ('mta_client_launch_registration', 'LaunchRegistrationError', 37), ('mta_client_linux_provider', 'LinuxProviderError', 38), ('mta_client_peer', 'PeerReadError', 39), ('mta_client_pending', 'PendingError', 40), ('mta_client_proc', 'ProcReadError', 41), ('mta_client_process_owner', 'ProcessOwnerError', 42), ('mta_client_readonly_baseline', 'ReadonlyBaselineError', 43), ('mta_client_resource_budget', 'ResourceBudgetError', 44), ('mta_client_store', 'DurableStoreError', 45), ('mta_client_store', 'PreparationError', 46), ('mta_client_tmp_alias', 'TmpAliasError', 47), ('mta_client_transfer', 'ClientTransferError', 48), ('mta_client_wpa_status', 'WpaStatusError', 49), ('mta_dhcp', 'DhcpError', 50), ('mta_dhcp_client', 'DhcpSocketClientError', 51), ('mta_dhcp_client_core', 'DhcpClientError', 52), ('mta_go_readonly_entry', 'ReadonlyEntryError', 53), ('mta_go_readonly_loader', 'ReadonlyLoaderError', 54), ('mta_go_readonly_preflight', 'ReadonlyPreflightError', 55), ('mta_ip', 'IpCoreError', 56), ('mta_observer_packet', 'ObserverPacketError', 57), ('mta_p2p_client_ctrl', 'CtrlCodecError', 58), ('mta_p2p_client_init', 'ClientInitError', 59), ('mta_protocol', 'ProtocolError', 60), ('mta_scoped_sockets', 'ScopedSocketError', 61), ('mta_snapshot_data', 'SnapshotDataError', 62), ('mta_storage', 'StorageError', 63), ('mta_transport', 'TransportError', 64), ('__main__', 'ReadonlyEntryError', 53))
_PRIVATE_DIAG_REASONS = {'ack_address_differs_from_offer': 1, 'ack_drift': 2, 'ack_identity_mismatch': 3, 'ack_in_invalid_state': 4, 'ack_message_count': 5, 'ack_request_mismatch': 6, 'actor_changed': 7, 'actor_limit': 8, 'actor_path_shape': 9, 'actor_reap_unknown': 10, 'actor_task_shape': 11, 'actor_type': 12, 'actor_unknown': 13, 'address_cache_shape': 14, 'address_label_shape': 15, 'address_lifetime': 16, 'address_outside_expected_private_subnet': 17, 'address_readback': 18, 'address_shape': 19, 'address_type': 20, 'alias_changed': 21, 'allocation_expired': 22, 'allocation_invalid': 23, 'allocation_unverified': 24, 'already_attempted': 25, 'already_bound': 26, 'already_claimed': 27, 'already_open': 28, 'already_registered': 29, 'already_started': 30, 'ambiguous_create': 31, 'applied_ip_changed': 32, 'applied_ip_owner_required': 33, 'array_budget_or_index': 34, 'ascii_limit': 35, 'assembly_unknown': 36, 'association_changed': 37, 'association_unverified': 38, 'attribute_budget': 39, 'attribute_duplicate': 40, 'attribute_flags': 41, 'attribute_format': 42, 'attribute_limit': 43, 'automatic_route_delta': 44, 'baseline_changed': 45, 'baseline_owned_l3': 46, 'binary_format': 47, 'binary_invalid': 48, 'binding_attempted': 49, 'binding_mismatch': 50, 'binding_unknown': 51, 'boot_changed': 52, 'boot_shape': 53, 'bound_port': 54, 'busy_or_pending': 55, 'byte_budget': 56, 'bytes_shape': 57, 'callback_unknown': 58, 'cancel_check_failed': 59, 'cancel_check_invalid': 60, 'cancelled': 61, 'candidate_out_of_scope': 62, 'canonical_namespace_busy': 63, 'caps_schema': 64, 'capsule_closed': 65, 'channel_changed': 66, 'child_stop_unknown': 67, 'cleanup_renewal': 68, 'clear_not_authorized': 69, 'clear_unknown': 70, 'client_maximum_message_too_small': 71, 'client_peer_unverified': 72, 'clock_failed': 73, 'clock_moved_backwards': 74, 'clock_regressed': 75, 'clock_unknown': 76, 'close_unknown': 77, 'close_unverified': 78, 'closed': 79, 'command_failed': 80, 'component_error': 81, 'concurrent_operation': 82, 'config_exists': 83, 'config_unknown': 84, 'connect_already_seen': 85, 'connect_failed': 86, 'connect_poll_readback_failed': 87, 'connect_timeout_out_of_scope': 88, 'connector_endpoint_out_of_scope': 89, 'context_changed': 90, 'control_invalid': 91, 'controller_changed': 92, 'create_unknown': 93, 'creation_unknown': 94, 'credential_mismatch': 95, 'ctrl_unknown': 96, 'current_blocked': 97, 'current_changed': 98, 'current_exists': 99, 'current_ip_exists': 100, 'data_constructor': 101, 'data_schema': 102, 'deadline': 103, 'default_rules_shape': 104, 'descriptor_unknown': 105, 'dhcp_cookie_invalid': 106, 'dhcp_exchange_deadline_expired': 107, 'dhcp_lease_missing_or_zero': 108, 'dhcp_message_type_missing_or_invalid': 109, 'dhcp_option_duplicate_or_truncated': 110, 'dhcp_option_end_missing': 111, 'dhcp_option_limit_or_truncated': 112, 'dhcp_packet_size_invalid': 113, 'dhcp_response_identity_mismatch': 114, 'dhcp_response_subnet_mismatch': 115, 'directory_changed': 116, 'discover_in_invalid_state': 117, 'dump_already_complete': 118, 'dump_failed': 119, 'dump_identity_mismatch': 120, 'dump_interrupted': 121, 'dump_limit': 122, 'dump_overrun': 123, 'duplicate_array_index': 124, 'duplicate_attribute': 125, 'duplicate_candidate': 126, 'duplicate_combination': 127, 'duplicate_combination_attribute': 128, 'duplicate_command': 129, 'duplicate_field': 130, 'duplicate_iftype': 131, 'duplicate_limit_attribute': 132, 'duplicate_neighbor': 133, 'duplicate_nonce': 134, 'duplicate_phy_attribute': 135, 'duplicate_record': 136, 'duplicate_task': 137, 'duplicate_top_attribute': 138, 'duplicate_transport_handoff': 139, 'durability_unknown': 140, 'durable_journal_unavailable': 141, 'empty_iftypes': 142, 'empty_limits': 143, 'encoded_packet_limit': 144, 'endpoint_invalid': 145, 'endpoint_is_local_address': 146, 'endpoint_not_on_owned_subnet': 147, 'entropy_unavailable': 148, 'eof': 149, 'event_invalid': 150, 'event_missing': 151, 'event_removed': 152, 'event_stale': 153, 'event_unsupported': 154, 'exec_gate_failed': 155, 'exec_unknown': 156, 'executable_changed': 157, 'executor_role_forbidden': 158, 'exit_unknown': 159, 'expected_ack': 160, 'expected_actor_changed': 161, 'expected_offer': 162, 'expected_server_rejected_request': 163, 'expired': 164, 'external_finalizer_lock_unverified': 165, 'family_abi': 166, 'family_attribute': 167, 'family_group_id': 168, 'family_group_name': 169, 'family_missing_attribute': 170, 'family_name': 171, 'family_nested_attribute': 172, 'family_nested_duplicate': 173, 'family_nested_index': 174, 'family_operation': 175, 'fd_unknown': 176, 'file_budget': 177, 'file_changed': 178, 'file_close_unverified': 179, 'file_identity': 180, 'file_pin': 181, 'file_unknown': 182, 'finish_sealed': 183, 'fixed_domain_changed': 184, 'flock_failed': 185, 'flock_unknown': 186, 'foreign_file': 187, 'foreign_transport_handoff': 188, 'fork_unknown': 189, 'fragment_budget': 190, 'frame_invalid': 191, 'frame_size': 192, 'gate_unknown': 193, 'generic_header': 194, 'global_pending_blocked': 195, 'go_listener_has_no_admitted_endpoint': 196, 'go_listener_not_peer_authority': 197, 'handoff_attempted': 198, 'handoff_changed': 199, 'handoff_unknown': 200, 'hash_shape': 201, 'identity_mismatch': 202, 'identity_unknown': 203, 'ifindex_changed': 204, 'image_invalid': 205, 'incomplete_decoded_schema': 206, 'incomplete_dump': 207, 'incomplete_neighbor_dump': 208, 'inconsistent_dump': 209, 'info_size': 210, 'inheritable_readback': 211, 'input_closed': 212, 'integer_shape': 213, 'interface_changed': 214, 'interface_format': 215, 'interface_identity': 216, 'interface_mismatch': 217, 'interface_unknown': 218, 'interfaces_shape': 219, 'interrupted': 220, 'invalid_ack_length': 221, 'invalid_actor': 222, 'invalid_address': 223, 'invalid_address_header': 224, 'invalid_address_label': 225, 'invalid_address_lifetime': 226, 'invalid_address_spec': 227, 'invalid_allocation': 228, 'invalid_association': 229, 'invalid_attribute_flags': 230, 'invalid_attribute_length': 231, 'invalid_attribute_size': 232, 'invalid_baseline': 233, 'invalid_binding': 234, 'invalid_boot_id': 235, 'invalid_bootp_address_length': 236, 'invalid_bootp_transaction': 237, 'invalid_broadcast_flag': 238, 'invalid_budget': 239, 'invalid_cacheinfo': 240, 'invalid_callbacks': 241, 'invalid_candidate': 242, 'invalid_candidates': 243, 'invalid_caps': 244, 'invalid_cleanup_deadline': 245, 'invalid_client_identifier_length': 246, 'invalid_clock': 247, 'invalid_clock_value': 248, 'invalid_close_proof': 249, 'invalid_close_scope': 250, 'invalid_cmdline': 251, 'invalid_config': 252, 'invalid_context': 253, 'invalid_credentials': 254, 'invalid_credit': 255, 'invalid_critical_option_length': 256, 'invalid_datagram': 257, 'invalid_deadline': 258, 'invalid_descriptor': 259, 'invalid_directory_entry': 260, 'invalid_directory_type': 261, 'invalid_done': 262, 'invalid_dump_done': 263, 'invalid_dump_kind': 264, 'invalid_ethernet_client_address': 265, 'invalid_executable': 266, 'invalid_executable_link': 267, 'invalid_expected': 268, 'invalid_expected_actor': 269, 'invalid_expected_boot': 270, 'invalid_factory': 271, 'invalid_field': 272, 'invalid_file_metadata': 273, 'invalid_flag_payload': 274, 'invalid_fragment': 275, 'invalid_fragments': 276, 'invalid_frame': 277, 'invalid_handoff': 278, 'invalid_identity': 279, 'invalid_info': 280, 'invalid_input': 281, 'invalid_integer': 282, 'invalid_ip_profile': 283, 'invalid_ipv4': 284, 'invalid_ipv4_bytes': 285, 'invalid_journal': 286, 'invalid_json': 287, 'invalid_kernel_errno': 288, 'invalid_kind': 289, 'invalid_lane': 290, 'invalid_length': 291, 'invalid_link_layer': 292, 'invalid_lock': 293, 'invalid_locks': 294, 'invalid_lockset': 295, 'invalid_mac': 296, 'invalid_manifest': 297, 'invalid_message_length': 298, 'invalid_monotonic_time': 299, 'invalid_monotonic_value': 300, 'invalid_nak_address': 301, 'invalid_native_cancel_poll': 302, 'invalid_neighbor_ack': 303, 'invalid_neighbor_attribute': 304, 'invalid_neighbor_done': 305, 'invalid_neighbor_errno': 306, 'invalid_network_id': 307, 'invalid_option_value': 308, 'invalid_options_container': 309, 'invalid_origin': 310, 'invalid_original_port': 311, 'invalid_owned_context': 312, 'invalid_owned_host_address': 313, 'invalid_owned_name': 314, 'invalid_owner': 315, 'invalid_packet': 316, 'invalid_padding': 317, 'invalid_payload': 318, 'invalid_payload_budget': 319, 'invalid_phase': 320, 'invalid_phy': 321, 'invalid_positive_u32': 322, 'invalid_private_ipv4': 323, 'invalid_profile': 324, 'invalid_provider': 325, 'invalid_rapid_commit_option': 326, 'invalid_raw_socket_type': 327, 'invalid_read': 328, 'invalid_read_result': 329, 'invalid_reader': 330, 'invalid_receive': 331, 'invalid_receive_consent': 332, 'invalid_record': 333, 'invalid_regular_file': 334, 'invalid_reply': 335, 'invalid_request': 336, 'invalid_route_header': 337, 'invalid_route_interface': 338, 'invalid_route_table': 339, 'invalid_rule_table': 340, 'invalid_schema': 341, 'invalid_session': 342, 'invalid_snapshot': 343, 'invalid_ssid_encoding': 344, 'invalid_stat': 345, 'invalid_stat_fields': 346, 'invalid_stat_identity': 347, 'invalid_stat_number': 348, 'invalid_stat_state': 349, 'invalid_state': 350, 'invalid_status': 351, 'invalid_store': 352, 'invalid_subnet_mask': 353, 'invalid_terminal': 354, 'invalid_ticket': 355, 'invalid_time': 356, 'invalid_timeout': 357, 'invalid_transport': 358, 'invalid_u32': 359, 'invalid_write': 360, 'io_error': 361, 'io_unknown': 362, 'ipv4_configured': 363, 'ipv4_duplicate': 364, 'ipv4_type': 365, 'ipv6_duplicate': 366, 'ipv6_format': 367, 'ipv6_row_shape': 368, 'journal_changed': 369, 'journal_released': 370, 'json_invalid': 371, 'json_shape': 372, 'json_structure_limit': 373, 'kernel_error': 374, 'kernel_mismatch': 375, 'kernel_peer': 376, 'kernel_rejected': 377, 'kernel_reply': 378, 'kernel_sender': 379, 'kernel_unverified': 380, 'key_mismatch': 381, 'l3_continuity_changed': 382, 'l3_kernel_mismatch': 383, 'l3_readback_changed': 384, 'l3_status_mismatch': 385, 'lease_invalid': 386, 'lease_or_connect_expired': 387, 'lease_timers_invalid': 388, 'linux_socket_api_required': 389, 'listener_endpoint_out_of_scope': 390, 'lock_changed': 391, 'lock_create_race': 392, 'locks_close_unverified': 393, 'manifest_invalid': 394, 'marker_changed': 395, 'message_after_done': 396, 'message_after_terminal': 397, 'message_budget': 398, 'message_flags': 399, 'message_format': 400, 'message_identity': 401, 'message_limit': 402, 'metadata_unknown': 403, 'missing_address': 404, 'missing_caps_fields': 405, 'missing_combination_attribute': 406, 'missing_field': 407, 'missing_limit_attribute': 408, 'missing_neighbor_attribute': 409, 'missing_route_destination': 410, 'missing_wiphy': 411, 'multithreaded': 412, 'mutation_sealed': 413, 'nak_invalid': 414, 'namespace_invalid': 415, 'native_executor_poll_required': 416, 'native_ip_owner_required': 417, 'native_journal_changed': 418, 'native_linux_required': 419, 'native_peer_not_ready': 420, 'native_receive_owners_required': 421, 'native_receiver_required': 422, 'native_restore_scope_required': 423, 'native_route_transport_required': 424, 'native_transfer_owner_changed': 425, 'neighbor_dump_consumed': 426, 'neighbor_dump_identity': 427, 'neighbor_dump_interrupted': 428, 'neighbor_dump_limit': 429, 'neighbor_interface': 430, 'neighbor_kernel_error': 431, 'neighbor_message_after_done': 432, 'neighbor_peer_mismatch': 433, 'neighbor_record_limit': 434, 'neighbor_resource_pending': 435, 'neighbor_state_mismatch': 436, 'netlink_budget': 437, 'netlink_error': 438, 'netlink_format': 439, 'netlink_overrun': 440, 'network_cancelled': 441, 'no_available_subnet': 442, 'nonblocking_readback_failed': 443, 'noncanonical': 444, 'noncanonical_array_index': 445, 'noncanonical_data': 446, 'noncanonical_route': 447, 'noncontiguous_subnet_mask': 448, 'nondefault_policy': 449, 'nonpadding_after_end': 450, 'nonzero_attribute_padding': 451, 'nonzero_padding': 452, 'not_acquired': 453, 'not_bound': 454, 'not_connected': 455, 'not_created': 456, 'not_kernel_peer': 457, 'not_open': 458, 'not_prepared': 459, 'not_recorded': 460, 'not_registered': 461, 'observation_changed': 462, 'observation_unknown': 463, 'observer_active_cap': 464, 'observer_alias': 465, 'observer_already_attempted': 466, 'observer_binding': 467, 'observer_body_unclosed': 468, 'observer_cap_changed': 469, 'observer_clock': 470, 'observer_close_identity': 471, 'observer_close_ticket': 472, 'observer_entry_unclosed': 473, 'observer_expired': 474, 'observer_explicit_arguments': 475, 'observer_fcntl_errno': 476, 'observer_fcntl_input': 477, 'observer_fcntl_return': 478, 'observer_import': 479, 'observer_metadata': 480, 'observer_namespace_busy': 481, 'observer_owner_changed': 482, 'observer_packet_limit': 483, 'observer_pid': 484, 'observer_platform_or_entry': 485, 'observer_root': 486, 'observer_root_changed': 487, 'observer_short_write': 488, 'observer_source_budget': 489, 'observer_source_bytes': 490, 'observer_source_changed': 491, 'observer_source_fd': 492, 'observer_source_metadata': 493, 'observer_source_role': 494, 'observer_source_unclosed': 495, 'observer_stdout_access': 496, 'observer_stdout_atomic_cap': 497, 'observer_stdout_changed': 498, 'observer_stdout_nonblocking': 499, 'observer_stdout_not_private_pipe': 500, 'observer_unvalidated': 501, 'observer_write_already_attempted': 502, 'observer_write_budget': 503, 'observer_write_ready': 504, 'observer_write_unknown': 505, 'offer_in_invalid_state': 506, 'operation_interrupted': 507, 'option_overload_not_supported': 508, 'origin_changed': 509, 'origin_shape': 510, 'origin_type': 511, 'original_ack_changed': 512, 'original_key_changed': 513, 'original_port_changed': 514, 'os_error': 515, 'overlapping_limit_types': 516, 'owned_address_disappeared': 517, 'owned_context_required': 518, 'owned_deadline_out_of_scope': 519, 'owned_l3_changed': 520, 'owned_scope_unverified': 521, 'owner_changed': 522, 'owner_lock_failed': 523, 'owner_lock_pending': 524, 'owner_lock_timeout': 525, 'owner_lock_unknown': 526, 'owner_release_unknown': 527, 'owner_unknown': 528, 'ownership_unknown': 529, 'packet_binding': 530, 'packet_budget': 531, 'packet_data_constructor': 532, 'packet_definition_changed': 533, 'packet_hash': 534, 'packet_header': 535, 'packet_header_limit': 536, 'packet_header_noncanonical': 537, 'packet_helper_data': 538, 'packet_incomplete': 539, 'packet_lengths': 540, 'packet_lock_data': 541, 'packet_payload_changed': 542, 'packet_payload_limit': 543, 'packet_prefix': 544, 'packet_reader_budget': 545, 'packet_reader_ended': 546, 'packet_result': 547, 'packet_stable_key_changed': 548, 'packet_total_limit': 549, 'packet_trailing_data': 550, 'parameter_request_list_limit': 551, 'partial_send': 552, 'payload_overrun': 553, 'peer_association_changed': 554, 'peer_binding_readback_failed': 555, 'peer_close_unknown': 556, 'peer_mapping_changed': 557, 'peer_neighbor_unavailable': 558, 'peer_observation_unknown': 559, 'peer_owner_changed': 560, 'peer_read_deadline': 561, 'peer_read_scope_changed': 562, 'peer_transport_changed': 563, 'pending': 564, 'pending_blocked': 565, 'pending_exists': 566, 'persist_unknown': 567, 'phy_budget': 568, 'pid_identity_changed': 569, 'pid_missing': 570, 'pid_reused': 571, 'pipe_unknown': 572, 'platform': 573, 'prepare_already_attempted': 574, 'prepared_changed': 575, 'prior_blocked': 576, 'proc_budget': 577, 'process_unknown': 578, 'proof_budget': 579, 'protocol_features_format': 580, 'provider_unavailable': 581, 'publish_unknown': 582, 'raw_ipv4_tcp_required': 583, 'reacquire_unknown': 584, 'read_budget': 585, 'read_failed': 586, 'readback_changed': 587, 'reader_pending_or_active': 588, 'reader_unbound': 589, 'readonly_alias': 590, 'readonly_already_attempted': 591, 'readonly_already_called': 592, 'readonly_binding': 593, 'readonly_cap': 594, 'readonly_cap_changed': 595, 'readonly_clock': 596, 'readonly_close_identity_changed': 597, 'readonly_collector': 598, 'readonly_config': 599, 'readonly_descriptor_metadata': 600, 'readonly_existing_lock': 601, 'readonly_expired': 602, 'readonly_fd': 603, 'readonly_file_changed': 604, 'readonly_fixed_path': 605, 'readonly_flags': 606, 'readonly_helper_budget': 607, 'readonly_helper_capabilities': 608, 'readonly_helper_exit': 609, 'readonly_helper_pipe': 610, 'readonly_helper_process': 611, 'readonly_helper_source': 612, 'readonly_helper_stderr': 613, 'readonly_helper_unclosed': 614, 'readonly_loader': 615, 'readonly_lock_busy_or_unknown': 616, 'readonly_metadata': 617, 'readonly_owner': 618, 'readonly_owner_changed': 619, 'readonly_pid': 620, 'readonly_pipe_changed': 621, 'readonly_platform': 622, 'readonly_platform_unvalidated': 623, 'readonly_preflight_unclosed': 624, 'readonly_previous_restore_pending': 625, 'readonly_root': 626, 'readonly_root_changed': 627, 'readonly_snapshot': 628, 'readonly_snapshot_unclosed': 629, 'readonly_unclosed': 630, 'readonly_worker': 631, 'receipt_unverified': 632, 'receive_already_claimed': 633, 'receive_already_seen': 634, 'receive_budget': 635, 'receive_control': 636, 'receive_invalid': 637, 'receive_mismatch': 638, 'receive_not_expected': 639, 'receive_not_startable': 640, 'receive_owner_lock_pending': 641, 'receive_truncated': 642, 'receive_unknown': 643, 'record_disappeared': 644, 'record_limit': 645, 'request_in_invalid_state': 646, 'required_owner_callbacks_missing': 647, 'required_socket_api_unavailable': 648, 'resource_budget': 649, 'resource_close_unknown': 650, 'resource_limit': 651, 'resource_pending': 652, 'resource_unknown': 653, 'restore_readback': 654, 'restore_unknown': 655, 'rights_rejected': 656, 'role_mismatch': 657, 'root_changed': 658, 'route_metrics_shape': 659, 'route_shape': 660, 'route_type': 661, 'row_sort_shape': 662, 'rule_type': 663, 'safe_exhaustion': 664, 'scalar_format': 665, 'scope_readback_budget_exceeded': 666, 'scope_readback_failed': 667, 'security_mismatch': 668, 'self_actor_recovery': 669, 'server_and_client_address_equal': 670, 'server_identifier_invalid': 671, 'server_nak': 672, 'short_send': 673, 'snapshot_changed': 674, 'snapshot_dump_identity': 675, 'snapshot_type': 676, 'socket_already_connected': 677, 'socket_close_unknown': 678, 'socket_close_unverified': 679, 'socket_contract': 680, 'socket_identity': 681, 'socket_identity_already_owned': 682, 'socket_operation_failed': 683, 'socket_option': 684, 'socket_options': 685, 'socket_scope_readback_failed': 686, 'socket_timeout_readback_failed': 687, 'socket_unknown': 688, 'source_authentication': 689, 'source_binding_readback_failed': 690, 'source_changed': 691, 'source_import': 692, 'source_invalid': 693, 'source_only': 694, 'source_port_changed_during_connect': 695, 'source_role_unknown': 696, 'source_seal': 697, 'source_shape': 698, 'source_unavailable': 699, 'source_unknown': 700, 'spawn_unknown': 701, 'split_not_supported': 702, 'ssid_mismatch': 703, 'stable_key_mismatch': 704, 'stage_mismatch': 705, 'stale_current': 706, 'station_changed': 707, 'station_identity': 708, 'station_missing': 709, 'status_failed': 710, 'status_format': 711, 'status_mismatch': 712, 'stock_actors_shape': 713, 'stock_path_shape': 714, 'stock_shape': 715, 'store_finish_incomplete': 716, 'store_finish_unknown': 717, 'store_unavailable': 718, 'store_unknown': 719, 'stream_limit': 720, 'structure_budget': 721, 'subnet_invalid': 722, 'subnet_overlap': 723, 'subnet_prefix_out_of_scope': 724, 'tag_depth': 725, 'tag_shape': 726, 'task_budget': 727, 'task_directory_changed': 728, 'task_kernel_mismatch': 729, 'task_reused': 730, 'task_set_changed': 731, 'task_set_incomplete': 732, 'task_shape': 733, 'tcp_close_identity_unknown': 734, 'tcp_connect_failed': 735, 'tcp_identity_changed': 736, 'tcp_interface_changed': 737, 'tcp_nonblocking_failed': 738, 'tcp_peer_changed': 739, 'tcp_poll_changed': 740, 'tcp_request_out_of_scope': 741, 'tcp_source_changed': 742, 'temp_exists': 743, 'terminal_absence_actor': 744, 'terminal_absence_files': 745, 'terminal_actor_duplicate': 746, 'terminal_actor_exe': 747, 'terminal_actor_leader': 748, 'terminal_actor_tasks': 749, 'terminal_actor_tasks_order': 750, 'terminal_alias': 751, 'terminal_already_called': 752, 'terminal_ascii_limit': 753, 'terminal_boot': 754, 'terminal_cap': 755, 'terminal_cap_changed': 756, 'terminal_child_actor': 757, 'terminal_child_actor_mismatch': 758, 'terminal_child_actor_unavailable': 759, 'terminal_child_live_argv': 760, 'terminal_child_negative_conflict': 761, 'terminal_child_outcome': 762, 'terminal_child_outcome_missing': 763, 'terminal_child_role': 764, 'terminal_cleanup_limits': 765, 'terminal_close_identity': 766, 'terminal_close_row': 767, 'terminal_data_constructor': 768, 'terminal_definition_changed': 769, 'terminal_device_lock': 770, 'terminal_entry_original_changed': 771, 'terminal_entry_unclosed': 772, 'terminal_epoch': 773, 'terminal_existing_lock': 774, 'terminal_explicit_arguments': 775, 'terminal_fd': 776, 'terminal_file_changed': 777, 'terminal_finish_actor': 778, 'terminal_finish_ascii': 779, 'terminal_finish_binding': 780, 'terminal_finish_canonical': 781, 'terminal_finish_changed': 782, 'terminal_finish_children': 783, 'terminal_finish_claim': 784, 'terminal_finish_facts': 785, 'terminal_finish_format': 786, 'terminal_finish_inventory': 787, 'terminal_finish_journal': 788, 'terminal_finish_period': 789, 'terminal_finish_schema': 790, 'terminal_fixed_path': 791, 'terminal_hex': 792, 'terminal_incomplete': 793, 'terminal_integer': 794, 'terminal_inventory_pending': 795, 'terminal_journal_canonical': 796, 'terminal_journal_changed': 797, 'terminal_journal_child': 798, 'terminal_journal_dhcp': 799, 'terminal_journal_facts': 800, 'terminal_journal_format': 801, 'terminal_journal_ip': 802, 'terminal_journal_metadata': 803, 'terminal_journal_read': 804, 'terminal_journal_sha': 805, 'terminal_journal_snapshot': 806, 'terminal_journal_unclosed': 807, 'terminal_json': 808, 'terminal_label': 809, 'terminal_launch_binding': 810, 'terminal_launch_time': 811, 'terminal_lengths': 812, 'terminal_lock_busy_or_unknown': 813, 'terminal_locks': 814, 'terminal_metadata': 815, 'terminal_noncanonical': 816, 'terminal_number': 817, 'terminal_object': 818, 'terminal_observer_binding': 819, 'terminal_original_changed': 820, 'terminal_ownership': 821, 'terminal_packet_limit': 822, 'terminal_packet_source_changed': 823, 'terminal_pairs': 824, 'terminal_payload_changed': 825, 'terminal_payload_limit': 826, 'terminal_pid': 827, 'terminal_prefix': 828, 'terminal_primitive': 829, 'terminal_proc_absence': 830, 'terminal_proc_generation': 831, 'terminal_proc_history': 832, 'terminal_proc_original_changed': 833, 'terminal_reader_budget': 834, 'terminal_reader_ended': 835, 'terminal_readonly_budget': 836, 'terminal_readonly_owner': 837, 'terminal_readonly_unclosed': 838, 'terminal_request_already_attempted': 839, 'terminal_request_budget': 840, 'terminal_request_bytes': 841, 'terminal_request_changed': 842, 'terminal_request_limit': 843, 'terminal_request_ready': 844, 'terminal_request_schema': 845, 'terminal_request_type': 846, 'terminal_request_without_stdin': 847, 'terminal_response_binding': 848, 'terminal_response_schema': 849, 'terminal_result_schema': 850, 'terminal_root': 851, 'terminal_root_changed': 852, 'terminal_sealed': 853, 'terminal_sequence': 854, 'terminal_snapshot_changed': 855, 'terminal_snapshot_inventory': 856, 'terminal_snapshot_key': 857, 'terminal_source_domain': 858, 'terminal_stdin_access': 859, 'terminal_stdin_already_adopted': 860, 'terminal_stdin_changed': 861, 'terminal_stdin_close_identity': 862, 'terminal_stdin_close_ticket': 863, 'terminal_stdin_nonblocking': 864, 'terminal_stdin_not_private_pipe': 865, 'terminal_stdin_unclosed': 866, 'terminal_structure_limit': 867, 'terminal_text': 868, 'terminal_time_text': 869, 'terminal_total_limit': 870, 'terminal_trailing_data': 871, 'text_shape': 872, 'timeout_readback': 873, 'total_budget': 874, 'transfer_close_pending': 875, 'transfer_deadline': 876, 'transfer_grant_changed': 877, 'transfer_scope_changed': 878, 'transport_did_not_adopt_raw': 879, 'transport_unavailable': 880, 'truncated_ack': 881, 'truncated_address': 882, 'truncated_attribute': 883, 'truncated_header': 884, 'truncated_message': 885, 'truncated_neighbor': 886, 'truncated_route': 887, 'truncated_rule': 888, 'tuple_shape': 889, 'unadvertised_iftype': 890, 'unavailable': 891, 'unexpected_ctrl_state': 892, 'unexpected_dump_ack': 893, 'unexpected_dump_message': 894, 'unexpected_message_type': 895, 'unexpected_neighbor_message': 896, 'unexpected_owned_l3': 897, 'unexpected_provider_error': 898, 'unexpected_read_error': 899, 'unknown_address_flags': 900, 'unknown_attribute': 901, 'unknown_combination_constraint': 902, 'unknown_iftype': 903, 'unknown_limit_constraint': 904, 'unknown_projected_attribute': 905, 'unknown_radar_region': 906, 'unknown_radar_width': 907, 'unrepresented_bi_constraint': 908, 'unrepresented_radar_absence': 909, 'unreviewed_top_attribute': 910, 'unsafe_directory': 911, 'unsafe_file': 912, 'unsafe_lock': 913, 'unsafe_root': 914, 'unsupported': 915, 'unsupported_ack_flags': 916, 'unsupported_address_scope': 917, 'unsupported_attribute_flags': 918, 'unsupported_bootp_envelope': 919, 'unsupported_combo': 920, 'unsupported_envelope': 921, 'unsupported_event_field': 922, 'unsupported_io': 923, 'unsupported_kdf': 924, 'unsupported_neighbor': 925, 'unsupported_platform': 926, 'unsupported_policy': 927, 'unsupported_prefix': 928, 'unsupported_route': 929, 'unsupported_status_field': 930, 'verified_client_endpoint_required': 931, 'wait_unknown': 932, 'wiphy_generation_changed': 933, 'wiphy_identity': 934, 'wiphy_name_format': 935, 'wire_budget': 936, 'write_not_authorized': 937, 'write_pending': 938, 'write_unknown': 939, 'wrong_endpoint': 940, 'wrong_family': 941, 'wrong_observation': 942, 'wrong_owner': 943}
_PRIVATE_DIAG_FRAMES = {('mta_client_baseline', '<genexpr>'): 1, ('mta_client_baseline', '<lambda>'): 2, ('mta_client_baseline', '<listcomp>'): 3, ('mta_client_baseline', '<module>'): 4, ('mta_client_baseline', '__init__'): 5, ('mta_client_baseline', '__repr__'): 6, ('mta_client_baseline', '_actor_image'): 7, ('mta_client_baseline', '_actors'): 8, ('mta_client_baseline', '_adopt_fd'): 9, ('mta_client_baseline', '_binary_parents'): 10, ('mta_client_baseline', '_budget_socket'): 11, ('mta_client_baseline', '_close_row'): 12, ('mta_client_baseline', '_fail'): 13, ('mta_client_baseline', '_generic'): 14, ('mta_client_baseline', '_integer'): 15, ('mta_client_baseline', '_interfaces'): 16, ('mta_client_baseline', '_ipv4'): 17, ('mta_client_baseline', '_ipv6'): 18, ('mta_client_baseline', '_metadata'): 19, ('mta_client_baseline', '_next'): 20, ('mta_client_baseline', '_now'): 21, ('mta_client_baseline', '_open'): 22, ('mta_client_baseline', '_proc'): 23, ('mta_client_baseline', '_read_file'): 24, ('mta_client_baseline', '_receive'): 25, ('mta_client_baseline', '_send'): 26, ('mta_client_baseline', '_socket'): 27, ('mta_client_baseline', '_status'): 28, ('mta_client_baseline', '_ticket'): 29, ('mta_client_baseline', 'close'): 30, ('mta_client_baseline', 'collect'): 31, ('mta_client_baseline', 'fstat'): 32, ('mta_client_baseline', 'listdir'): 33, ('mta_client_baseline', 'open'): 34, ('mta_client_baseline', 'read'): 35, ('mta_client_baseline', 'readable'): 36, ('mta_client_baseline', 'socket'): 37, ('mta_client_baseline', 'spawn'): 38, ('mta_client_baseline', 'stat'): 39, ('mta_client_baseline', 'status'): 40, ('mta_client_baseline', 'validate'): 41, ('mta_client_caps', '<genexpr>'): 42, ('mta_client_caps', '<module>'): 43, ('mta_client_caps', '__init__'): 44, ('mta_client_caps', '_array'): 45, ('mta_client_caps', '_attributes'): 46, ('mta_client_caps', '_combination'): 47, ('mta_client_caps', '_commands'): 48, ('mta_client_caps', '_fail'): 49, ('mta_client_caps', '_flag'): 50, ('mta_client_caps', '_limit'): 51, ('mta_client_caps', '_nested'): 52, ('mta_client_caps', '_scalar'): 53, ('mta_client_caps', '_types'): 54, ('mta_client_caps', 'decode_wiphy_projection'): 55, ('mta_client_caps', 'decoded_client_schema'): 56, ('mta_client_caps', 'visit'): 57, ('mta_client_caps_transport', '<genexpr>'): 58, ('mta_client_caps_transport', '<module>'): 59, ('mta_client_caps_transport', '__init__'): 60, ('mta_client_caps_transport', '_attr'): 61, ('mta_client_caps_transport', '_attrs'): 62, ('mta_client_caps_transport', '_budget'): 63, ('mta_client_caps_transport', '_fail'): 64, ('mta_client_caps_transport', '_family'): 65, ('mta_client_caps_transport', '_int'): 66, ('mta_client_caps_transport', '_nested'): 67, ('mta_client_caps_transport', '_now'): 68, ('mta_client_caps_transport', '_projection'): 69, ('mta_client_caps_transport', '_request'): 70, ('mta_client_caps_transport', '_scalar'): 71, ('mta_client_caps_transport', 'raw_datagrams'): 72, ('mta_client_caps_transport', 'raw_requests'): 73, ('mta_client_caps_transport', 'raw_wiphy_messages'): 74, ('mta_client_caps_transport', 'read'): 75, ('mta_client_caps_transport', 'status'): 76, ('mta_client_caps_transport', 'unprojected_attributes'): 77, ('mta_client_connection', '<genexpr>'): 78, ('mta_client_connection', '<listcomp>'): 79, ('mta_client_connection', '<module>'): 80, ('mta_client_connection', '__init__'): 81, ('mta_client_connection', '__repr__'): 82, ('mta_client_connection', '__setattr__'): 83, ('mta_client_connection', '_checkpoint'): 84, ('mta_client_connection', '_drain'): 85, ('mta_client_connection', '_end_receipt_transaction'): 86, ('mta_client_connection', '_event'): 87, ('mta_client_connection', '_exchange'): 88, ('mta_client_connection', '_facts_tree'): 89, ('mta_client_connection', '_fail'): 90, ('mta_client_connection', '_fresh'): 91, ('mta_client_connection', '_info'): 92, ('mta_client_connection', '_kernel_fields'): 93, ('mta_client_connection', '_note_event'): 94, ('mta_client_connection', '_observation_digest'): 95, ('mta_client_connection', '_observe_connection'): 96, ('mta_client_connection', '_ok'): 97, ('mta_client_connection', '_persist_invalidated'): 98, ('mta_client_connection', '_status'): 99, ('mta_client_connection', 'disconnect'): 100, ('mta_client_connection', 'invalidate_receipt'): 101, ('mta_client_connection', 'public_summary'): 102, ('mta_client_connection', 'readback'): 103, ('mta_client_connection', 'run'): 104, ('mta_client_connection', 'status'): 105, ('mta_client_control_frame', '<genexpr>'): 106, ('mta_client_control_frame', '<module>'): 107, ('mta_client_control_frame', '__init__'): 108, ('mta_client_control_frame', '__repr__'): 109, ('mta_client_control_frame', '__setattr__'): 110, ('mta_client_control_frame', '_binding'): 111, ('mta_client_control_frame', '_canonical'): 112, ('mta_client_control_frame', '_connect'): 113, ('mta_client_control_frame', '_display'): 114, ('mta_client_control_frame', '_fail'): 115, ('mta_client_control_frame', '_info_dict'): 116, ('mta_client_control_frame', '_info_object'): 117, ('mta_client_control_frame', '_receive'): 118, ('mta_client_control_frame', '_reject'): 119, ('mta_client_control_frame', '_rx_value'): 120, ('mta_client_control_frame', '_stop'): 121, ('mta_client_control_frame', '_task'): 122, ('mta_client_control_frame', '_uint'): 123, ('mta_client_control_frame', 'binding'): 124, ('mta_client_control_frame', 'cancel'): 125, ('mta_client_control_frame', 'cancelled'): 126, ('mta_client_control_frame', 'decode_receive_event'): 127, ('mta_client_control_frame', 'encode_connect'): 128, ('mta_client_control_frame', 'encode_receive_decision'): 129, ('mta_client_control_frame', 'encode_receive_event'): 130, ('mta_client_control_frame', 'expect_receive'): 131, ('mta_client_control_frame', 'feed'): 132, ('mta_client_control_frame', 'private_data'): 133, ('mta_client_control_frame', 'private_info'): 134, ('mta_client_control_frame', 'private_metadata'): 135, ('mta_client_control_frame', 'public_metadata'): 136, ('mta_client_control_frame', 'status'): 137, ('mta_client_control_frame', 'take_connect'): 138, ('mta_client_control_frame', 'take_receive_decision'): 139, ('mta_client_coordination', '<genexpr>'): 140, ('mta_client_coordination', '<module>'): 141, ('mta_client_coordination', '__enter__'): 142, ('mta_client_coordination', '__exit__'): 143, ('mta_client_coordination', '__init__'): 144, ('mta_client_coordination', '__repr__'): 145, ('mta_client_coordination', '__setattr__'): 146, ('mta_client_coordination', '_anchors_valid'): 147, ('mta_client_coordination', '_begin'): 148, ('mta_client_coordination', '_check'): 149, ('mta_client_coordination', '_close_all'): 150, ('mta_client_coordination', '_close_one'): 151, ('mta_client_coordination', '_directory'): 152, ('mta_client_coordination', '_errno'): 153, ('mta_client_coordination', '_fail'): 154, ('mta_client_coordination', '_flags'): 155, ('mta_client_coordination', '_flock'): 156, ('mta_client_coordination', '_handoff_budget'): 157, ('mta_client_coordination', '_handoff_owned'): 158, ('mta_client_coordination', '_int'): 159, ('mta_client_coordination', '_libc'): 160, ('mta_client_coordination', '_lock_identity'): 161, ('mta_client_coordination', '_lock_valid'): 162, ('mta_client_coordination', '_lock_valid_open_handoff'): 163, ('mta_client_coordination', '_metadata'): 164, ('mta_client_coordination', '_open'): 165, ('mta_client_coordination', '_open_handoff_journal'): 166, ('mta_client_coordination', '_open_lock'): 167, ('mta_client_coordination', '_operation'): 168, ('mta_client_coordination', '_owned'): 169, ('mta_client_coordination', '_pending_absent'): 170, ('mta_client_coordination', '_report'): 171, ('mta_client_coordination', '_tmp_fd'): 172, ('mta_client_coordination', '_tmp_open_dir'): 173, ('mta_client_coordination', 'acquire'): 174, ('mta_client_coordination', 'close'): 175, ('mta_client_coordination', 'close_device_last'): 176, ('mta_client_coordination', 'complete'): 177, ('mta_client_coordination', 'flag'): 178, ('mta_client_coordination', 'flock'): 179, ('mta_client_coordination', 'fstat'): 180, ('mta_client_coordination', 'open_at'): 181, ('mta_client_coordination', 'open_root'): 182, ('mta_client_coordination', 'pause'): 183, ('mta_client_coordination', 'reacquire_journal'): 184, ('mta_client_coordination', 'read_closed'): 185, ('mta_client_coordination', 'read_pending'): 186, ('mta_client_coordination', 'readlink_at'): 187, ('mta_client_coordination', 'release_journal'): 188, ('mta_client_coordination', 'release_journal_handoff'): 189, ('mta_client_coordination', 'stat_at'): 190, ('mta_client_coordination', 'stat_root'): 191, ('mta_client_coordination', 'status'): 192, ('mta_client_coordination', 'validate'): 193, ('mta_client_dora', '<genexpr>'): 194, ('mta_client_dora', '<listcomp>'): 195, ('mta_client_dora', '<module>'): 196, ('mta_client_dora', '__init__'): 197, ('mta_client_dora', '__repr__'): 198, ('mta_client_dora', '__setattr__'): 199, ('mta_client_dora', '_accept_ack'): 200, ('mta_client_dora', '_cancelled'): 201, ('mta_client_dora', '_dispose_socket_v26'): 202, ('mta_client_dora', '_enter'): 203, ('mta_client_dora', '_fail'): 204, ('mta_client_dora', '_live_current'): 205, ('mta_client_dora', '_now'): 206, ('mta_client_dora', '_owner_current'): 207, ('mta_client_dora', '_record_envelope'): 208, ('mta_client_dora', '_revoke'): 209, ('mta_client_dora', '_scope'): 210, ('mta_client_dora', '_socket_factory_v26'): 211, ('mta_client_dora', '_socket_unknown_v26'): 212, ('mta_client_dora', '_validate_receipt'): 213, ('mta_client_dora', 'bind_l3_owner'): 214, ('mta_client_dora', 'candidate'): 215, ('mta_client_dora', 'close'): 216, ('mta_client_dora', 'closed_socket_ticket_v26'): 217, ('mta_client_dora', 'closure_facts_v26'): 218, ('mta_client_dora', 'issue_l3_handoff'): 219, ('mta_client_dora', 'l3_handoff_current'): 220, ('mta_client_dora', 'open'): 221, ('mta_client_dora', 'owns_socket_ticket_v26'): 222, ('mta_client_dora', 'poll'): 223, ('mta_client_dora', 'proof'): 224, ('mta_client_dora', 'run_sync'): 225, ('mta_client_dora', 'status'): 226, ('mta_client_dora', 'stopped'): 227, ('mta_client_dora', 'validate_live'): 228, ('mta_client_dynamic_ip', '<genexpr>'): 229, ('mta_client_dynamic_ip', '<lambda>'): 230, ('mta_client_dynamic_ip', '<listcomp>'): 231, ('mta_client_dynamic_ip', '<module>'): 232, ('mta_client_dynamic_ip', '__init__'): 233, ('mta_client_dynamic_ip', '__new__'): 234, ('mta_client_dynamic_ip', '__repr__'): 235, ('mta_client_dynamic_ip', '__setattr__'): 236, ('mta_client_dynamic_ip', '_budget'): 237, ('mta_client_dynamic_ip', '_current'): 238, ('mta_client_dynamic_ip', '_fail'): 239, ('mta_client_dynamic_ip', '_free_subnet'): 240, ('mta_client_dynamic_ip', '_link_gate'): 241, ('mta_client_dynamic_ip', '_metadata'): 242, ('mta_client_dynamic_ip', '_next'): 243, ('mta_client_dynamic_ip', '_now'): 244, ('mta_client_dynamic_ip', '_number'): 245, ('mta_client_dynamic_ip', '_persist'): 246, ('mta_client_dynamic_ip', '_recv'): 247, ('mta_client_dynamic_ip', '_send'): 248, ('mta_client_dynamic_ip', '_slice'): 249, ('mta_client_dynamic_ip', '_snapshot_data'): 250, ('mta_client_dynamic_ip', '_snapshot_from_data'): 251, ('mta_client_dynamic_ip', '_without_delta'): 252, ('mta_client_dynamic_ip', 'address_ack'): 253, ('mta_client_dynamic_ip', 'cleanup'): 254, ('mta_client_dynamic_ip', 'close'): 255, ('mta_client_dynamic_ip', 'closed_facts'): 256, ('mta_client_dynamic_ip', 'create_gate'): 257, ('mta_client_dynamic_ip', 'delete_gate'): 258, ('mta_client_dynamic_ip', 'encode_address'): 259, ('mta_client_dynamic_ip', 'expected_routes'): 260, ('mta_client_dynamic_ip', 'facts_key'): 261, ('mta_client_dynamic_ip', 'key'): 262, ('mta_client_dynamic_ip', 'open'): 263, ('mta_client_dynamic_ip', 'prepare_address'): 264, ('mta_client_dynamic_ip', 'record_data'): 265, ('mta_client_dynamic_ip', 'record_from_data'): 266, ('mta_client_dynamic_ip', 'replace'): 267, ('mta_client_dynamic_ip', 'row'): 268, ('mta_client_dynamic_ip', 'same_record'): 269, ('mta_client_dynamic_ip', 'snapshot'): 270, ('mta_client_dynamic_ip', 'snapshot_key'): 271, ('mta_client_dynamic_ip', 'stable_snapshot'): 272, ('mta_client_dynamic_ip', 'start'): 273, ('mta_client_dynamic_ip', 'status'): 274, ('mta_client_executor', '<genexpr>'): 275, ('mta_client_executor', '<lambda>'): 276, ('mta_client_executor', '<listcomp>'): 277, ('mta_client_executor', '<module>'): 278, ('mta_client_executor', '__init__'): 279, ('mta_client_executor', '__repr__'): 280, ('mta_client_executor', '_actor'): 281, ('mta_client_executor', '_argv'): 282, ('mta_client_executor', '_binding_for'): 283, ('mta_client_executor', '_cancelled'): 284, ('mta_client_executor', '_capture_parent_cap_v33'): 285, ('mta_client_executor', '_close_inherited_elf'): 286, ('mta_client_executor', '_close_pipe'): 287, ('mta_client_executor', '_complete'): 288, ('mta_client_executor', '_confirm_receive'): 289, ('mta_client_executor', '_diagnostic_error'): 290, ('mta_client_executor', '_diagnostic_sample'): 291, ('mta_client_executor', '_emit_receive'): 292, ('mta_client_executor', '_entry_identity'): 293, ('mta_client_executor', '_fail'): 294, ('mta_client_executor', '_finite'): 295, ('mta_client_executor', '_fixed_tmp_alias'): 296, ('mta_client_executor', '_freeze_complete'): 297, ('mta_client_executor', '_freeze_restore'): 298, ('mta_client_executor', '_freeze_start'): 299, ('mta_client_executor', '_handoff_current'): 300, ('mta_client_executor', '_meta'): 301, ('mta_client_executor', '_now'): 302, ('mta_client_executor', '_observe'): 303, ('mta_client_executor', '_parent_cap_v33'): 304, ('mta_client_executor', '_parent_until_text_v33_value'): 305, ('mta_client_executor', '_path'): 306, ('mta_client_executor', '_pipe_valid'): 307, ('mta_client_executor', '_public'): 308, ('mta_client_executor', '_publish'): 309, ('mta_client_executor', '_pure_proc_store'): 310, ('mta_client_executor', '_reader_closed'): 311, ('mta_client_executor', '_receive_directory'): 312, ('mta_client_executor', '_receive_event'): 313, ('mta_client_executor', '_receive_progress'): 314, ('mta_client_executor', '_receive_terminal'): 315, ('mta_client_executor', '_run_native_receive'): 316, ('mta_client_executor', '_run_private_dora'): 317, ('mta_client_executor', '_serialized'): 318, ('mta_client_executor', '_sha'): 319, ('mta_client_executor', '_token'): 320, ('mta_client_executor', '_uint'): 321, ('mta_client_executor', '_watchdog_until_text_v33'): 322, ('mta_client_executor', '_write_diagnostics'): 323, ('mta_client_executor', 'anchors'): 324, ('mta_client_executor', 'answer_receive'): 325, ('mta_client_executor', 'authenticate'): 326, ('mta_client_executor', 'cancel'): 327, ('mta_client_executor', 'check'): 328, ('mta_client_executor', 'close'): 329, ('mta_client_executor', 'close_row'): 330, ('mta_client_executor', 'emit'): 331, ('mta_client_executor', 'finish'): 332, ('mta_client_executor', 'fstat'): 333, ('mta_client_executor', 'invoke'): 334, ('mta_client_executor', 'load'): 335, ('mta_client_executor', 'main'): 336, ('mta_client_executor', 'observed'): 337, ('mta_client_executor', 'open'): 338, ('mta_client_executor', 'pinned_import'): 339, ('mta_client_executor', 'pipe_buf'): 340, ('mta_client_executor', 'poll'): 341, ('mta_client_executor', 'popen'): 342, ('mta_client_executor', 'read'): 343, ('mta_client_executor', 'read_file'): 344, ('mta_client_executor', 'readlink'): 345, ('mta_client_executor', 'ready'): 346, ('mta_client_executor', 'ready_write'): 347, ('mta_client_executor', 'receive_status'): 348, ('mta_client_executor', 'run'): 349, ('mta_client_executor', 'send_connect'): 350, ('mta_client_executor', 'start'): 351, ('mta_client_executor', 'stat'): 352, ('mta_client_executor', 'status'): 353, ('mta_client_executor', 'take_connect'): 354, ('mta_client_executor', 'validate'): 355, ('mta_client_executor', 'watchdog'): 356, ('mta_client_executor', 'write'): 357, ('mta_client_files', '<genexpr>'): 358, ('mta_client_files', '<module>'): 359, ('mta_client_files', '__enter__'): 360, ('mta_client_files', '__exit__'): 361, ('mta_client_files', '__init__'): 362, ('mta_client_files', '__repr__'): 363, ('mta_client_files', '__setattr__'): 364, ('mta_client_files', '_anchors_valid'): 365, ('mta_client_files', '_begin_budget'): 366, ('mta_client_files', '_cas'): 367, ('mta_client_files', '_check'): 368, ('mta_client_files', '_close_one'): 369, ('mta_client_files', '_complete_credit_v23'): 370, ('mta_client_files', '_dir_identity'): 371, ('mta_client_files', '_ensure_open'): 372, ('mta_client_files', '_err'): 373, ('mta_client_files', '_fail'): 374, ('mta_client_files', '_file_metadata'): 375, ('mta_client_files', '_flags'): 376, ('mta_client_files', '_integer'): 377, ('mta_client_files', '_libc'): 378, ('mta_client_files', '_metadata'): 379, ('mta_client_files', '_open_fd'): 380, ('mta_client_files', '_operation'): 381, ('mta_client_files', '_pending_absent'): 382, ('mta_client_files', '_read_current'): 383, ('mta_client_files', '_reserve_v23'): 384, ('mta_client_files', '_tmp_fd'): 385, ('mta_client_files', '_tmp_open_dir'): 386, ('mta_client_files', 'close'): 387, ('mta_client_files', 'commit'): 388, ('mta_client_files', 'flag'): 389, ('mta_client_files', 'fstat'): 390, ('mta_client_files', 'fsync'): 391, ('mta_client_files', 'open'): 392, ('mta_client_files', 'open_at'): 393, ('mta_client_files', 'open_root'): 394, ('mta_client_files', 'read'): 395, ('mta_client_files', 'read_current'): 396, ('mta_client_files', 'readlink_at'): 397, ('mta_client_files', 'rename_at'): 398, ('mta_client_files', 'stat_at'): 399, ('mta_client_files', 'stat_root'): 400, ('mta_client_files', 'status'): 401, ('mta_client_files', 'validate'): 402, ('mta_client_files', 'write'): 403, ('mta_client_journal_codec', '<genexpr>'): 404, ('mta_client_journal_codec', '<lambda>'): 405, ('mta_client_journal_codec', '<listcomp>'): 406, ('mta_client_journal_codec', '<module>'): 407, ('mta_client_journal_codec', '__init__'): 408, ('mta_client_journal_codec', '_actor'): 409, ('mta_client_journal_codec', '_actor_tree'): 410, ('mta_client_journal_codec', '_association'): 411, ('mta_client_journal_codec', '_association_tree'): 412, ('mta_client_journal_codec', '_bool'): 413, ('mta_client_journal_codec', '_canonical'): 414, ('mta_client_journal_codec', '_client_ip'): 415, ('mta_client_journal_codec', '_client_ip_tree'): 416, ('mta_client_journal_codec', '_decode_document'): 417, ('mta_client_journal_codec', '_document'): 418, ('mta_client_journal_codec', '_fail'): 419, ('mta_client_journal_codec', '_guard'): 420, ('mta_client_journal_codec', '_hash'): 421, ('mta_client_journal_codec', '_identity'): 422, ('mta_client_journal_codec', '_identity_tree'): 423, ('mta_client_journal_codec', '_ipv4'): 424, ('mta_client_journal_codec', '_ipv4_tree'): 425, ('mta_client_journal_codec', '_iticket'): 426, ('mta_client_journal_codec', '_iticket_tree'): 427, ('mta_client_journal_codec', '_label'): 428, ('mta_client_journal_codec', '_label_tree'): 429, ('mta_client_journal_codec', '_mac'): 430, ('mta_client_journal_codec', '_mac_tree'): 431, ('mta_client_journal_codec', '_map_source'): 432, ('mta_client_journal_codec', '_object'): 433, ('mta_client_journal_codec', '_optional'): 434, ('mta_client_journal_codec', '_origin'): 435, ('mta_client_journal_codec', '_origin_tree'): 436, ('mta_client_journal_codec', '_sequence'): 437, ('mta_client_journal_codec', '_snapshot'): 438, ('mta_client_journal_codec', '_snapshot_tree'): 439, ('mta_client_journal_codec', '_text'): 440, ('mta_client_journal_codec', '_ticket'): 441, ('mta_client_journal_codec', '_ticket_tree'): 442, ('mta_client_journal_codec', '_tuple_source'): 443, ('mta_client_journal_codec', '_uint'): 444, ('mta_client_journal_codec', 'charge'): 445, ('mta_client_journal_codec', 'decode_journal'): 446, ('mta_client_journal_codec', 'encode_journal'): 447, ('mta_client_journal_codec', 'visit'): 448, ('mta_client_kernel_proof', '<genexpr>'): 449, ('mta_client_kernel_proof', '<module>'): 450, ('mta_client_kernel_proof', '__init__'): 451, ('mta_client_kernel_proof', '__repr__'): 452, ('mta_client_kernel_proof', '__setattr__'): 453, ('mta_client_kernel_proof', '_budget'): 454, ('mta_client_kernel_proof', '_check'): 455, ('mta_client_kernel_proof', '_checkpoint'): 456, ('mta_client_kernel_proof', '_claim'): 457, ('mta_client_kernel_proof', '_close'): 458, ('mta_client_kernel_proof', '_fail'): 459, ('mta_client_kernel_proof', '_fields'): 460, ('mta_client_kernel_proof', '_ifindex'): 461, ('mta_client_kernel_proof', '_int'): 462, ('mta_client_kernel_proof', '_interface'): 463, ('mta_client_kernel_proof', '_issue_closed'): 464, ('mta_client_kernel_proof', '_metadata'): 465, ('mta_client_kernel_proof', '_query'): 466, ('mta_client_kernel_proof', '_scalar'): 467, ('mta_client_kernel_proof', '_self'): 468, ('mta_client_kernel_proof', '_station'): 469, ('mta_client_kernel_proof', '_ticket'): 470, ('mta_client_kernel_proof', 'authenticate'): 471, ('mta_client_kernel_proof', 'close'): 472, ('mta_client_kernel_proof', 'closed_receipts'): 473, ('mta_client_kernel_proof', 'fstat'): 474, ('mta_client_kernel_proof', 'new_socket'): 475, ('mta_client_kernel_proof', 'open_ifindex'): 476, ('mta_client_kernel_proof', 'original_resources'): 477, ('mta_client_kernel_proof', 'private_fields'): 478, ('mta_client_kernel_proof', 'proc_readers'): 479, ('mta_client_kernel_proof', 'public_summary'): 480, ('mta_client_kernel_proof', 'read'): 481, ('mta_client_kernel_proof', 'status'): 482, ('mta_client_kernel_proof', 'unassessed_attributes'): 483, ('mta_client_launch_registration', '<genexpr>'): 484, ('mta_client_launch_registration', '<lambda>'): 485, ('mta_client_launch_registration', '<listcomp>'): 486, ('mta_client_launch_registration', '<module>'): 487, ('mta_client_launch_registration', '__init__'): 488, ('mta_client_launch_registration', '__repr__'): 489, ('mta_client_launch_registration', '_actor'): 490, ('mta_client_launch_registration', '_begin'): 491, ('mta_client_launch_registration', '_check'): 492, ('mta_client_launch_registration', '_close'): 493, ('mta_client_launch_registration', '_exact'): 494, ('mta_client_launch_registration', '_fail'): 495, ('mta_client_launch_registration', '_failed'): 496, ('mta_client_launch_registration', '_finite'): 497, ('mta_client_launch_registration', '_flags'): 498, ('mta_client_launch_registration', '_guard'): 499, ('mta_client_launch_registration', '_open'): 500, ('mta_client_launch_registration', '_persist'): 501, ('mta_client_launch_registration', '_publish'): 502, ('mta_client_launch_registration', '_read'): 503, ('mta_client_launch_registration', '_tree'): 504, ('mta_client_launch_registration', '_uint'): 505, ('mta_client_launch_registration', 'close'): 506, ('mta_client_launch_registration', 'register'): 507, ('mta_client_launch_registration', 'release'): 508, ('mta_client_launch_registration', 'resolve'): 509, ('mta_client_launch_registration', 'status'): 510, ('mta_client_linux_provider', '<genexpr>'): 511, ('mta_client_linux_provider', '<lambda>'): 512, ('mta_client_linux_provider', '<listcomp>'): 513, ('mta_client_linux_provider', '<module>'): 514, ('mta_client_linux_provider', '__getattribute__'): 515, ('mta_client_linux_provider', '__init__'): 516, ('mta_client_linux_provider', '__repr__'): 517, ('mta_client_linux_provider', '__setattr__'): 518, ('mta_client_linux_provider', '_after'): 519, ('mta_client_linux_provider', '_alias_check'): 520, ('mta_client_linux_provider', '_alias_fd'): 521, ('mta_client_linux_provider', '_alias_identity'): 522, ('mta_client_linux_provider', '_alias_open'): 523, ('mta_client_linux_provider', '_anchors'): 524, ('mta_client_linux_provider', '_append_fd_receipt_v23'): 525, ('mta_client_linux_provider', '_association_receipt_current'): 526, ('mta_client_linux_provider', '_attr'): 527, ('mta_client_linux_provider', '_authenticated_closed'): 528, ('mta_client_linux_provider', '_begin'): 529, ('mta_client_linux_provider', '_bind_proc_v24'): 530, ('mta_client_linux_provider', '_caps_core'): 531, ('mta_client_linux_provider', '_capture_closed'): 532, ('mta_client_linux_provider', '_capture_issued_closed'): 533, ('mta_client_linux_provider', '_capture_kernel'): 534, ('mta_client_linux_provider', '_capture_proc_open_v24'): 535, ('mta_client_linux_provider', '_cleanup_child'): 536, ('mta_client_linux_provider', '_client_ip_closed_v28'): 537, ('mta_client_linux_provider', '_client_ip_facts_v28'): 538, ('mta_client_linux_provider', '_client_peer_facts_v29'): 539, ('mta_client_linux_provider', '_client_transfer_facts_v30'): 540, ('mta_client_linux_provider', '_close_child_inventory'): 541, ('mta_client_linux_provider', '_close_dora_v26'): 542, ('mta_client_linux_provider', '_close_peer_v29'): 543, ('mta_client_linux_provider', '_close_pregate'): 544, ('mta_client_linux_provider', '_close_transfer_v30'): 545, ('mta_client_linux_provider', '_closed_fd'): 546, ('mta_client_linux_provider', '_closed_objects'): 547, ('mta_client_linux_provider', '_connection_caps'): 548, ('mta_client_linux_provider', '_connection_channel_gate'): 549, ('mta_client_linux_provider', '_connection_context'): 550, ('mta_client_linux_provider', '_connection_exchange'): 551, ('mta_client_linux_provider', '_connection_kernel'): 552, ('mta_client_linux_provider', '_connection_open'): 553, ('mta_client_linux_provider', '_connection_receive'): 554, ('mta_client_linux_provider', '_connection_timeout'): 555, ('mta_client_linux_provider', '_control'): 556, ('mta_client_linux_provider', '_ctrl_controls'): 557, ('mta_client_linux_provider', '_diagnostic_error'): 558, ('mta_client_linux_provider', '_dora_facts_v26'): 559, ('mta_client_linux_provider', '_dora_root_v26'): 560, ('mta_client_linux_provider', '_fail'): 561, ('mta_client_linux_provider', '_fd_absent'): 562, ('mta_client_linux_provider', '_handle'): 563, ('mta_client_linux_provider', '_hex'): 564, ('mta_client_linux_provider', '_int'): 565, ('mta_client_linux_provider', '_issue_association_receipt'): 566, ('mta_client_linux_provider', '_kernel_closed_facts'): 567, ('mta_client_linux_provider', '_known_live_fd'): 568, ('mta_client_linux_provider', '_new_proc_v24'): 569, ('mta_client_linux_provider', '_note_restore_diagnostic'): 570, ('mta_client_linux_provider', '_now'): 571, ('mta_client_linux_provider', '_observe'): 572, ('mta_client_linux_provider', '_observe_ctrl_deinit'): 573, ('mta_client_linux_provider', '_open'): 574, ('mta_client_linux_provider', '_origin'): 575, ('mta_client_linux_provider', '_origin_exact'): 576, ('mta_client_linux_provider', '_path'): 577, ('mta_client_linux_provider', '_payload_subset_v23'): 578, ('mta_client_linux_provider', '_peer_io_until_v29'): 579, ('mta_client_linux_provider', '_prepare_config'): 580, ('mta_client_linux_provider', '_private_pids'): 581, ('mta_client_linux_provider', '_proc_history_closed_v24'): 582, ('mta_client_linux_provider', '_proc_history_pending_v24'): 583, ('mta_client_linux_provider', '_proc_namespace_registered_v24'): 584, ('mta_client_linux_provider', '_proc_registered_v24'): 585, ('mta_client_linux_provider', '_proof'): 586, ('mta_client_linux_provider', '_register_alias_directory'): 587, ('mta_client_linux_provider', '_remember'): 588, ('mta_client_linux_provider', '_remember_collector'): 589, ('mta_client_linux_provider', '_remember_proc'): 590, ('mta_client_linux_provider', '_remember_proc_history_v24'): 591, ('mta_client_linux_provider', '_reserve_v23'): 592, ('mta_client_linux_provider', '_restore_slice'): 593, ('mta_client_linux_provider', '_status'): 594, ('mta_client_linux_provider', '_status_exchange_current_v35'): 595, ('mta_client_linux_provider', '_status_exchange_issue_v35'): 596, ('mta_client_linux_provider', '_tracked_v23'): 597, ('mta_client_linux_provider', '_transfer_io_until_v30'): 598, ('mta_client_linux_provider', '_verify_anchors'): 599, ('mta_client_linux_provider', 'adopt'): 600, ('mta_client_linux_provider', 'assemble'): 601, ('mta_client_linux_provider', 'attach'): 602, ('mta_client_linux_provider', 'authenticate_prior'): 603, ('mta_client_linux_provider', 'authenticate_restore'): 604, ('mta_client_linux_provider', 'bind_session'): 605, ('mta_client_linux_provider', 'call'): 606, ('mta_client_linux_provider', 'caps'): 607, ('mta_client_linux_provider', 'cleanup'): 608, ('mta_client_linux_provider', 'cleanup_origin_ready'): 609, ('mta_client_linux_provider', 'close'): 610, ('mta_client_linux_provider', 'close_all'): 611, ('mta_client_linux_provider', 'close_resources'): 612, ('mta_client_linux_provider', 'closed_resources'): 613, ('mta_client_linux_provider', 'commit_client_ip'): 614, ('mta_client_linux_provider', 'component_closed'): 615, ('mta_client_linux_provider', 'connect_p2p'): 616, ('mta_client_linux_provider', 'create_client'): 617, ('mta_client_linux_provider', 'create_private_dora'): 618, ('mta_client_linux_provider', 'creator'): 619, ('mta_client_linux_provider', 'decorate'): 620, ('mta_client_linux_provider', 'delete_client'): 621, ('mta_client_linux_provider', 'disconnect_p2p'): 622, ('mta_client_linux_provider', 'ebadf'): 623, ('mta_client_linux_provider', 'executor'): 624, ('mta_client_linux_provider', 'flag'): 625, ('mta_client_linux_provider', 'fsync'): 626, ('mta_client_linux_provider', 'interfaces'): 627, ('mta_client_linux_provider', 'kill'): 628, ('mta_client_linux_provider', 'launch'): 629, ('mta_client_linux_provider', 'listdir'): 630, ('mta_client_linux_provider', 'live_actor'): 631, ('mta_client_linux_provider', 'new'): 632, ('mta_client_linux_provider', 'new_ctrl'): 633, ('mta_client_linux_provider', 'new_genl'): 634, ('mta_client_linux_provider', 'open'): 635, ('mta_client_linux_provider', 'open_at'): 636, ('mta_client_linux_provider', 'origin_absent'): 637, ('mta_client_linux_provider', 'origin_up'): 638, ('mta_client_linux_provider', 'original_actors'): 639, ('mta_client_linux_provider', 'pid'): 640, ('mta_client_linux_provider', 'poll_executor_stop_v32'): 641, ('mta_client_linux_provider', 'poll_requests'): 642, ('mta_client_linux_provider', 'poll_transfer_requests_v30'): 643, ('mta_client_linux_provider', 'prepare'): 644, ('mta_client_linux_provider', 'private_inventory_counts'): 645, ('mta_client_linux_provider', 'read_association_receipt'): 646, ('mta_client_linux_provider', 'read_connection'): 647, ('mta_client_linux_provider', 'read_prior'): 648, ('mta_client_linux_provider', 'read_restore'): 649, ('mta_client_linux_provider', 'readlink_at'): 650, ('mta_client_linux_provider', 'register'): 651, ('mta_client_linux_provider', 'register_interface'): 652, ('mta_client_linux_provider', 'release'): 653, ('mta_client_linux_provider', 'request'): 654, ('mta_client_linux_provider', 'request_child_stop'): 655, ('mta_client_linux_provider', 'request_stop'): 656, ('mta_client_linux_provider', 'reserve'): 657, ('mta_client_linux_provider', 'resolve'): 658, ('mta_client_linux_provider', 'restore'): 659, ('mta_client_linux_provider', 'same'): 660, ('mta_client_linux_provider', 'seek'): 661, ('mta_client_linux_provider', 'session_specs'): 662, ('mta_client_linux_provider', 'snapshot'): 663, ('mta_client_linux_provider', 'sock'): 664, ('mta_client_linux_provider', 'specs'): 665, ('mta_client_linux_provider', 'stat_at'): 666, ('mta_client_linux_provider', 'stat_root'): 667, ('mta_client_linux_provider', 'status'): 668, ('mta_client_linux_provider', 'validate'): 669, ('mta_client_linux_provider', 'verify_closed'): 670, ('mta_client_linux_provider', 'write'): 671, ('mta_client_peer', '<genexpr>'): 672, ('mta_client_peer', '<module>'): 673, ('mta_client_peer', '__init__'): 674, ('mta_client_peer', '__new__'): 675, ('mta_client_peer', '_association'): 676, ('mta_client_peer', '_error'): 677, ('mta_client_peer', '_fail'): 678, ('mta_client_peer', '_full_link_gate'): 679, ('mta_client_peer', '_gate'): 680, ('mta_client_peer', '_io_until_for_provider'): 681, ('mta_client_peer', '_ip_readback'): 682, ('mta_client_peer', '_neighbors'): 683, ('mta_client_peer', '_scope'): 684, ('mta_client_peer', '_time'): 685, ('mta_client_peer', '_transport_closed_facts'): 686, ('mta_client_peer', 'close'): 687, ('mta_client_peer', 'closed_facts'): 688, ('mta_client_peer', 'decode_neighbor'): 689, ('mta_client_peer', 'encode_neighbor_dump'): 690, ('mta_client_peer', 'feed'): 691, ('mta_client_peer', 'key'): 692, ('mta_client_peer', 'mapping_key'): 693, ('mta_client_peer', 'read'): 694, ('mta_client_peer', 'records'): 695, ('mta_client_peer', 'status'): 696, ('mta_client_pending', '<genexpr>'): 697, ('mta_client_pending', '<module>'): 698, ('mta_client_pending', '__init__'): 699, ('mta_client_pending', '__repr__'): 700, ('mta_client_pending', '__setattr__'): 701, ('mta_client_pending', '_absent'): 702, ('mta_client_pending', '_begin'): 703, ('mta_client_pending', '_binding_inputs'): 704, ('mta_client_pending', '_binding_live'): 705, ('mta_client_pending', '_consume_refusal_coord_v36'): 706, ('mta_client_pending', '_consume_refusal_store_v36'): 707, ('mta_client_pending', '_encode'): 708, ('mta_client_pending', '_fail'): 709, ('mta_client_pending', '_guard'): 710, ('mta_client_pending', '_journal_binding_context'): 711, ('mta_client_pending', '_journal_device_guard'): 712, ('mta_client_pending', '_journal_handoff_live'): 713, ('mta_client_pending', '_now'): 714, ('mta_client_pending', '_observation'): 715, ('mta_client_pending', '_observe_self'): 716, ('mta_client_pending', '_operation'): 717, ('mta_client_pending', '_prepare_journal_handoff'): 718, ('mta_client_pending', '_publish_journal_handoff'): 719, ('mta_client_pending', '_read_owned'): 720, ('mta_client_pending', '_record_error'): 721, ('mta_client_pending', '_refusal_accounting_facts_v36'): 722, ('mta_client_pending', '_refusal_capture_v36'): 723, ('mta_client_pending', '_refusal_current_v36'): 724, ('mta_client_pending', '_refusal_owner_v36'): 725, ('mta_client_pending', '_refusal_reader_facts_v36'): 726, ('mta_client_pending', '_same_refusal_facts_v36'): 727, ('mta_client_pending', '_terminal_absence'): 728, ('mta_client_pending', '_terminal_canonical_readback'): 729, ('mta_client_pending', '_terminal_context'): 730, ('mta_client_pending', '_terminal_error_observation'): 731, ('mta_client_pending', '_terminal_resource_guard'): 732, ('mta_client_pending', '_terminal_segment'): 733, ('mta_client_pending', '_terminal_unlinked_readback'): 734, ('mta_client_pending', '_verify_binding'): 735, ('mta_client_pending', 'bind_files'): 736, ('mta_client_pending', 'clear_status'): 737, ('mta_client_pending', 'clear_terminal'): 738, ('mta_client_pending', 'close'): 739, ('mta_client_pending', 'create'): 740, ('mta_client_pending', 'seek_start'): 741, ('mta_client_pending', 'status'): 742, ('mta_client_pending', 'unlink_at'): 743, ('mta_client_pending', 'verify'): 744, ('mta_client_proc', '<dictcomp>'): 745, ('mta_client_proc', '<genexpr>'): 746, ('mta_client_proc', '<module>'): 747, ('mta_client_proc', '__init__'): 748, ('mta_client_proc', '__repr__'): 749, ('mta_client_proc', '__setattr__'): 750, ('mta_client_proc', '_absence_pass'): 751, ('mta_client_proc', '_actor_pass'): 752, ('mta_client_proc', '_begin'): 753, ('mta_client_proc', '_boot'): 754, ('mta_client_proc', '_check'): 755, ('mta_client_proc', '_directory'): 756, ('mta_client_proc', '_errno_is'): 757, ('mta_client_proc', '_exe'): 758, ('mta_client_proc', '_expected_boot'): 759, ('mta_client_proc', '_fail'): 760, ('mta_client_proc', '_meta'): 761, ('mta_client_proc', '_observe'): 762, ('mta_client_proc', '_observe_body'): 763, ('mta_client_proc', '_path_meta'): 764, ('mta_client_proc', '_pid_text'): 765, ('mta_client_proc', '_read'): 766, ('mta_client_proc', '_read_boot'): 767, ('mta_client_proc', '_record'): 768, ('mta_client_proc', '_retain_return'): 769, ('mta_client_proc', '_tasks'): 770, ('mta_client_proc', '_uint'): 771, ('mta_client_proc', 'closed_open_ticket'): 772, ('mta_client_proc', 'fd'): 773, ('mta_client_proc', 'history_closed'): 774, ('mta_client_proc', 'operation_history'): 775, ('mta_client_proc', 'owns_generation'): 776, ('mta_client_proc', 'owns_open_ticket'): 777, ('mta_client_proc', 'parse_stat'): 778, ('mta_client_proc', 'public_status'): 779, ('mta_client_proc', 'read_absence'): 780, ('mta_client_proc', 'read_actor'): 781, ('mta_client_proc', 'read_self'): 782, ('mta_client_proc', 'stable_key'): 783, ('mta_client_process_owner', '<genexpr>'): 784, ('mta_client_process_owner', '<module>'): 785, ('mta_client_process_owner', '__init__'): 786, ('mta_client_process_owner', '__repr__'): 787, ('mta_client_process_owner', '__setattr__'): 788, ('mta_client_process_owner', '_binary'): 789, ('mta_client_process_owner', '_bounded_deadline'): 790, ('mta_client_process_owner', '_child'): 791, ('mta_client_process_owner', '_close_fd'): 792, ('mta_client_process_owner', '_exact'): 793, ('mta_client_process_owner', '_fail'): 794, ('mta_client_process_owner', '_fd_return'): 795, ('mta_client_process_owner', '_int'): 796, ('mta_client_process_owner', '_meta'): 797, ('mta_client_process_owner', '_new_fd'): 798, ('mta_client_process_owner', '_nonblocking'): 799, ('mta_client_process_owner', '_now'): 800, ('mta_client_process_owner', '_open'): 801, ('mta_client_process_owner', '_pipe'): 802, ('mta_client_process_owner', '_single'): 803, ('mta_client_process_owner', '_time'): 804, ('mta_client_process_owner', 'close_inventory'): 805, ('mta_client_process_owner', 'exact_fd'): 806, ('mta_client_process_owner', 'fresh_exit'): 807, ('mta_client_process_owner', 'launch'): 808, ('mta_client_process_owner', 'read_requests'): 809, ('mta_client_process_owner', 'read_requests_passive_v30'): 810, ('mta_client_process_owner', 'register'): 811, ('mta_client_process_owner', 'release'): 812, ('mta_client_process_owner', 'resolve'): 813, ('mta_client_process_owner', 'status'): 814, ('mta_client_process_owner', 'wait_reap'): 815, ('mta_client_readonly_baseline', '<genexpr>'): 816, ('mta_client_readonly_baseline', '<module>'): 817, ('mta_client_readonly_baseline', '__init__'): 818, ('mta_client_readonly_baseline', '_closed'): 819, ('mta_client_readonly_baseline', '_fail'): 820, ('mta_client_readonly_baseline', '_neutral'): 821, ('mta_client_readonly_baseline', '_pending_absent'): 822, ('mta_client_readonly_baseline', '_platform'): 823, ('mta_client_readonly_baseline', 'close'): 824, ('mta_client_readonly_baseline', 'collect'): 825, ('mta_client_readonly_baseline', 'fstat'): 826, ('mta_client_readonly_baseline', 'listdir'): 827, ('mta_client_readonly_baseline', 'now'): 828, ('mta_client_readonly_baseline', 'open'): 829, ('mta_client_readonly_baseline', 'read'): 830, ('mta_client_readonly_baseline', 'readable'): 831, ('mta_client_readonly_baseline', 'same_worker'): 832, ('mta_client_readonly_baseline', 'socket'): 833, ('mta_client_readonly_baseline', 'spawn'): 834, ('mta_client_readonly_baseline', 'stat'): 835, ('mta_client_readonly_baseline', 'status'): 836, ('mta_client_readonly_baseline', 'validate'): 837, ('mta_client_resource_budget', '<genexpr>'): 838, ('mta_client_resource_budget', '<listcomp>'): 839, ('mta_client_resource_budget', '<module>'): 840, ('mta_client_resource_budget', '__init__'): 841, ('mta_client_resource_budget', '__repr__'): 842, ('mta_client_resource_budget', '__setattr__'): 843, ('mta_client_resource_budget', '_context'): 844, ('mta_client_resource_budget', '_fail'): 845, ('mta_client_resource_budget', '_kind'): 846, ('mta_client_resource_budget', '_lane'): 847, ('mta_client_resource_budget', '_late'): 848, ('mta_client_resource_budget', '_owned'): 849, ('mta_client_resource_budget', 'bind_provider'): 850, ('mta_client_resource_budget', 'bind_reader'): 851, ('mta_client_resource_budget', 'cancel'): 852, ('mta_client_resource_budget', 'count_limit'): 853, ('mta_client_resource_budget', 'mark_unknown'): 854, ('mta_client_resource_budget', 'payload_limit'): 855, ('mta_client_resource_budget', 'reserve'): 856, ('mta_client_resource_budget', 'returned'): 857, ('mta_client_resource_budget', 'settle'): 858, ('mta_client_resource_budget', 'started'): 859, ('mta_client_resource_budget', 'status'): 860, ('mta_client_store', '<genexpr>'): 861, ('mta_client_store', '<lambda>'): 862, ('mta_client_store', '<module>'): 863, ('mta_client_store', '__init__'): 864, ('mta_client_store', '__repr__'): 865, ('mta_client_store', '__setattr__'): 866, ('mta_client_store', '_association_transition'): 867, ('mta_client_store', '_authorize_terminal_clear'): 868, ('mta_client_store', '_begin'): 869, ('mta_client_store', '_begin_disk'): 870, ('mta_client_store', '_begin_io'): 871, ('mta_client_store', '_budget_slice'): 872, ('mta_client_store', '_canonical_valid'): 873, ('mta_client_store', '_check'): 874, ('mta_client_store', '_client_ip_transition_v28'): 875, ('mta_client_store', '_close_components'): 876, ('mta_client_store', '_closed_fixed_alias_registry'): 877, ('mta_client_store', '_component_clock'): 878, ('mta_client_store', '_durable_fail'): 879, ('mta_client_store', '_end_producer'): 880, ('mta_client_store', '_fail'): 881, ('mta_client_store', '_fd_closed'): 882, ('mta_client_store', '_files_closed'): 883, ('mta_client_store', '_fresh_restore'): 884, ('mta_client_store', '_identity_valid'): 885, ('mta_client_store', '_inventory_closed'): 886, ('mta_client_store', '_known_refusal_v36'): 887, ('mta_client_store', '_now'): 888, ('mta_client_store', '_observe_close'): 889, ('mta_client_store', '_owned'): 890, ('mta_client_store', '_parent_issuance_v33'): 891, ('mta_client_store', '_peer_io_until_v29'): 892, ('mta_client_store', '_proc_pending_v24'): 893, ('mta_client_store', '_producer_context'): 894, ('mta_client_store', '_publish'): 895, ('mta_client_store', '_raise_reported'): 896, ('mta_client_store', '_read_exact'): 897, ('mta_client_store', '_record_error'): 898, ('mta_client_store', '_report'): 899, ('mta_client_store', '_retained_marker'): 900, ('mta_client_store', '_same_baseline'): 901, ('mta_client_store', '_same_live_baseline'): 902, ('mta_client_store', '_session_context_v28'): 903, ('mta_client_store', '_transition'): 904, ('mta_client_store', '_trusted_active_deadline_v28'): 905, ('mta_client_store', '_uint'): 906, ('mta_client_store', '_validate'): 907, ('mta_client_store', 'acquire'): 908, ('mta_client_store', 'active_return'): 909, ('mta_client_store', 'authenticate_finish'): 910, ('mta_client_store', 'close'): 911, ('mta_client_store', 'closed_locks'): 912, ('mta_client_store', 'commit'): 913, ('mta_client_store', 'complete'): 914, ('mta_client_store', 'current'): 915, ('mta_client_store', 'finish'): 916, ('mta_client_store', 'lock_valid'): 917, ('mta_client_store', 'open'): 918, ('mta_client_store', 'parent_until_v33'): 919, ('mta_client_store', 'pending_clear'): 920, ('mta_client_store', 'pending_matches'): 921, ('mta_client_store', 'prepare_initial'): 922, ('mta_client_store', 'prior_clear'): 923, ('mta_client_store', 'session_issued_v28'): 924, ('mta_client_store', 'status'): 925, ('mta_client_tmp_alias', '<genexpr>'): 926, ('mta_client_tmp_alias', '<module>'): 927, ('mta_client_tmp_alias', '__init__'): 928, ('mta_client_tmp_alias', '__repr__'): 929, ('mta_client_tmp_alias', '_alias'): 930, ('mta_client_tmp_alias', '_authenticate_prefix'): 931, ('mta_client_tmp_alias', '_directory'): 932, ('mta_client_tmp_alias', '_fail'): 933, ('mta_client_tmp_alias', '_fd'): 934, ('mta_client_tmp_alias', '_guard'): 935, ('mta_client_tmp_alias', '_meta'): 936, ('mta_client_tmp_alias', '_open_prefix'): 937, ('mta_client_tmp_alias', '_uint'): 938, ('mta_client_tmp_alias', 'authenticate'): 939, ('mta_client_tmp_alias', 'bind_tmp'): 940, ('mta_client_tmp_alias', 'prefix_tickets'): 941, ('mta_client_tmp_alias', 'prepare'): 942, ('mta_client_tmp_alias', 'tmp_parent'): 943, ('mta_client_tmp_alias', 'tmp_ticket'): 944, ('mta_client_transfer', '<genexpr>'): 945, ('mta_client_transfer', '<module>'): 946, ('mta_client_transfer', '__init__'): 947, ('mta_client_transfer', '_cancelled'): 948, ('mta_client_transfer', '_close_only_originals'): 949, ('mta_client_transfer', '_dispose'): 950, ('mta_client_transfer', '_fail'): 951, ('mta_client_transfer', '_full'): 952, ('mta_client_transfer', '_io_until_for_provider'): 953, ('mta_client_transfer', '_neighbor'): 954, ('mta_client_transfer', '_originals'): 955, ('mta_client_transfer', '_quick'): 956, ('mta_client_transfer', '_route_closed'): 957, ('mta_client_transfer', '_stage'): 958, ('mta_client_transfer', '_tcp_closed'): 959, ('mta_client_transfer', '_time'): 960, ('mta_client_transfer', 'bounded_confirm'): 961, ('mta_client_transfer', 'close'): 962, ('mta_client_transfer', 'closed_facts'): 963, ('mta_client_transfer', 'run'): 964, ('mta_client_transfer', 'socket_factory'): 965, ('mta_client_transfer', 'status'): 966, ('mta_client_transfer', 'transport_handoff'): 967, ('mta_client_two_phase_lease', '<genexpr>'): 968, ('mta_client_two_phase_lease', '<listcomp>'): 969, ('mta_client_two_phase_lease', '<module>'): 970, ('mta_client_two_phase_lease', '__init__'): 971, ('mta_client_two_phase_lease', '__repr__'): 972, ('mta_client_two_phase_lease', '_cleanup_child'): 973, ('mta_client_two_phase_lease', '_close_child_inventory'): 974, ('mta_client_two_phase_lease', '_close_pregate'): 975, ('mta_client_two_phase_lease', '_closed_fd'): 976, ('mta_client_two_phase_lease', '_exact'): 977, ('mta_client_two_phase_lease', '_role'): 978, ('mta_client_two_phase_lease', '_start_diagnostic'): 979, ('mta_client_two_phase_lease', 'bind_session'): 980, ('mta_client_two_phase_lease', 'cleanup'): 981, ('mta_client_two_phase_lease', 'launch'): 982, ('mta_client_two_phase_lease', 'pause_resolution'): 983, ('mta_client_two_phase_lease', 'prepare'): 984, ('mta_client_two_phase_lease', 'release'): 985, ('mta_client_two_phase_lease', 'request_child_stop'): 986, ('mta_client_two_phase_lease', 'reserve'): 987, ('mta_client_two_phase_lease', 'resolve'): 988, ('mta_client_two_phase_lease', 'restore'): 989, ('mta_client_two_phase_lease', 'start'): 990, ('mta_client_two_phase_lease', 'status'): 991, ('mta_client_two_phase_lease', 'verify_closed'): 992, ('mta_client_wpa_status', '<genexpr>'): 993, ('mta_client_wpa_status', '<module>'): 994, ('mta_client_wpa_status', '__init__'): 995, ('mta_client_wpa_status', '__repr__'): 996, ('mta_client_wpa_status', '_actor'): 997, ('mta_client_wpa_status', '_budget'): 998, ('mta_client_wpa_status', '_close'): 999, ('mta_client_wpa_status', '_controls'): 1000, ('mta_client_wpa_status', '_endpoint'): 1001, ('mta_client_wpa_status', '_fail'): 1002, ('mta_client_wpa_status', '_hash'): 1003, ('mta_client_wpa_status', '_int'): 1004, ('mta_client_wpa_status', '_manifest'): 1005, ('mta_client_wpa_status', '_meta'): 1006, ('mta_client_wpa_status', '_namespaces'): 1007, ('mta_client_wpa_status', '_now'): 1008, ('mta_client_wpa_status', '_number'): 1009, ('mta_client_wpa_status', '_observation'): 1010, ('mta_client_wpa_status', '_open'): 1011, ('mta_client_wpa_status', '_open_socket'): 1012, ('mta_client_wpa_status', '_path'): 1013, ('mta_client_wpa_status', '_resolve_endpoint'): 1014, ('mta_client_wpa_status', '_source_key'): 1015, ('mta_client_wpa_status', '_source_read'): 1016, ('mta_client_wpa_status', '_ticket'): 1017, ('mta_client_wpa_status', 'authenticate_source'): 1018, ('mta_client_wpa_status', 'close'): 1019, ('mta_client_wpa_status', 'cmsg_space'): 1020, ('mta_client_wpa_status', 'new_socket'): 1021, ('mta_client_wpa_status', 'parse_status'): 1022, ('mta_client_wpa_status', 'read_source'): 1023, ('mta_client_wpa_status', 'read_status'): 1024, ('mta_client_wpa_status', 'readlink'): 1025, ('mta_client_wpa_status', 'status'): 1026, ('mta_client_wpa_status', 'token'): 1027, ('mta_client_wpa_status', 'validate'): 1028, ('mta_dhcp', '<genexpr>'): 1029, ('mta_dhcp', '<listcomp>'): 1030, ('mta_dhcp', '<module>'): 1031, ('mta_dhcp', '__init__'): 1032, ('mta_dhcp', '_alive'): 1033, ('mta_dhcp', '_allocation'): 1034, ('mta_dhcp', '_client_key'): 1035, ('mta_dhcp', '_clock'): 1036, ('mta_dhcp', '_integer'): 1037, ('mta_dhcp', '_mac'): 1038, ('mta_dhcp', '_number'): 1039, ('mta_dhcp', '_private'): 1040, ('mta_dhcp', '_reply'): 1041, ('mta_dhcp', '_response'): 1042, ('mta_dhcp', '_subnet'): 1043, ('mta_dhcp', '_validate_options'): 1044, ('mta_dhcp', 'accept_ack'): 1045, ('mta_dhcp', 'accept_offer'): 1046, ('mta_dhcp', 'address'): 1047, ('mta_dhcp', 'decode'): 1048, ('mta_dhcp', 'discover'): 1049, ('mta_dhcp', 'encode'): 1050, ('mta_dhcp', 'handle'): 1051, ('mta_dhcp', 'ipv4'): 1052, ('mta_dhcp', 'prefix'): 1053, ('mta_dhcp', 'remaining'): 1054, ('mta_dhcp', 'request'): 1055, ('mta_dhcp', 'status'): 1056, ('mta_dhcp_client', '<genexpr>'): 1057, ('mta_dhcp_client', '<listcomp>'): 1058, ('mta_dhcp_client', '<module>'): 1059, ('mta_dhcp_client', '__init__'): 1060, ('mta_dhcp_client', '_abort'): 1061, ('mta_dhcp_client', '_basic'): 1062, ('mta_dhcp_client', '_dispose'): 1063, ('mta_dhcp_client', '_envelope'): 1064, ('mta_dhcp_client', '_guard'): 1065, ('mta_dhcp_client', '_integer'): 1066, ('mta_dhcp_client', '_now'): 1067, ('mta_dhcp_client', '_number'): 1068, ('mta_dhcp_client', '_options'): 1069, ('mta_dhcp_client', '_require_producer'): 1070, ('mta_dhcp_client', '_send'): 1071, ('mta_dhcp_client', 'candidate'): 1072, ('mta_dhcp_client', 'close'): 1073, ('mta_dhcp_client', 'confirm_runner_closed'): 1074, ('mta_dhcp_client', 'context'): 1075, ('mta_dhcp_client', 'open'): 1076, ('mta_dhcp_client', 'poll'): 1077, ('mta_dhcp_client', 'reserve_runner'): 1078, ('mta_dhcp_client', 'run'): 1079, ('mta_dhcp_client', 'status'): 1080, ('mta_dhcp_client_core', '<module>'): 1081, ('mta_dhcp_client_core', '__init__'): 1082, ('mta_dhcp_client_core', '_allocation'): 1083, ('mta_dhcp_client_core', '_consume'): 1084, ('mta_dhcp_client_core', '_discover'): 1085, ('mta_dhcp_client_core', '_finish'): 1086, ('mta_dhcp_client_core', '_finite'): 1087, ('mta_dhcp_client_core', '_integer'): 1088, ('mta_dhcp_client_core', '_request'): 1089, ('mta_dhcp_client_core', '_require'): 1090, ('mta_dhcp_client_core', '_server'): 1091, ('mta_dhcp_client_core', '_time'): 1092, ('mta_dhcp_client_core', '_u32'): 1093, ('mta_dhcp_client_core', 'accept_ack'): 1094, ('mta_dhcp_client_core', 'accept_offer'): 1095, ('mta_dhcp_client_core', 'cancel'): 1096, ('mta_dhcp_client_core', 'configuration'): 1097, ('mta_dhcp_client_core', 'start'): 1098, ('mta_dhcp_client_core', 'status'): 1099, ('mta_dhcp_client_core', 'tick'): 1100, ('mta_go_readonly_entry', '<genexpr>'): 1101, ('mta_go_readonly_entry', '<module>'): 1102, ('mta_go_readonly_entry', '__init__'): 1103, ('mta_go_readonly_entry', '_adopt_stdin'): 1104, ('mta_go_readonly_entry', '_adopt_stdout'): 1105, ('mta_go_readonly_entry', '_anchors'): 1106, ('mta_go_readonly_entry', '_arguments'): 1107, ('mta_go_readonly_entry', '_binding'): 1108, ('mta_go_readonly_entry', '_close'): 1109, ('mta_go_readonly_entry', '_close_stdin'): 1110, ('mta_go_readonly_entry', '_context'): 1111, ('mta_go_readonly_entry', '_fail'): 1112, ('mta_go_readonly_entry', '_finite'): 1113, ('mta_go_readonly_entry', '_load_module'): 1114, ('mta_go_readonly_entry', '_meta'): 1115, ('mta_go_readonly_entry', '_now'): 1116, ('mta_go_readonly_entry', '_read_source'): 1117, ('mta_go_readonly_entry', '_read_terminal_request'): 1118, ('mta_go_readonly_entry', '_request_current'): 1119, ('mta_go_readonly_entry', '_stdin_current'): 1120, ('mta_go_readonly_entry', '_stdout_current'): 1121, ('mta_go_readonly_entry', '_terminal_arguments'): 1122, ('mta_go_readonly_entry', '_write_packet'): 1123, ('mta_go_readonly_entry', 'close'): 1124, ('mta_go_readonly_entry', 'collect'): 1125, ('mta_go_readonly_entry', 'flags'): 1126, ('mta_go_readonly_entry', 'fstat'): 1127, ('mta_go_readonly_entry', 'main'): 1128, ('mta_go_readonly_entry', 'main94'): 1129, ('mta_go_readonly_entry', 'open'): 1130, ('mta_go_readonly_entry', 'pid'): 1131, ('mta_go_readonly_entry', 'pinned_import'): 1132, ('mta_go_readonly_entry', 'pipe_buf'): 1133, ('mta_go_readonly_entry', 'read'): 1134, ('mta_go_readonly_entry', 'readable'): 1135, ('mta_go_readonly_entry', 'readlink'): 1136, ('mta_go_readonly_entry', 'set_flags'): 1137, ('mta_go_readonly_entry', 'stat'): 1138, ('mta_go_readonly_entry', 'status'): 1139, ('mta_go_readonly_entry', 'validate'): 1140, ('mta_go_readonly_entry', 'writable'): 1141, ('mta_go_readonly_entry', 'write'): 1142, ('mta_go_readonly_loader', '<genexpr>'): 1143, ('mta_go_readonly_loader', '<module>'): 1144, ('mta_go_readonly_loader', '__init__'): 1145, ('mta_go_readonly_loader', '_anchors'): 1146, ('mta_go_readonly_loader', '_close_row'): 1147, ('mta_go_readonly_loader', '_context'): 1148, ('mta_go_readonly_loader', '_fail'): 1149, ('mta_go_readonly_loader', '_finite'): 1150, ('mta_go_readonly_loader', '_meta'): 1151, ('mta_go_readonly_loader', '_read_source'): 1152, ('mta_go_readonly_loader', '_seal_readonly_manifest'): 1153, ('mta_go_readonly_loader', '_source_path'): 1154, ('mta_go_readonly_loader', '_source_shape'): 1155, ('mta_go_readonly_loader', 'authenticate'): 1156, ('mta_go_readonly_loader', 'check'): 1157, ('mta_go_readonly_loader', 'close'): 1158, ('mta_go_readonly_loader', 'fstat'): 1159, ('mta_go_readonly_loader', 'load'): 1160, ('mta_go_readonly_loader', 'main'): 1161, ('mta_go_readonly_loader', 'open'): 1162, ('mta_go_readonly_loader', 'pid'): 1163, ('mta_go_readonly_loader', 'pinned_import'): 1164, ('mta_go_readonly_loader', 'read'): 1165, ('mta_go_readonly_loader', 'readlink'): 1166, ('mta_go_readonly_loader', 'stat'): 1167, ('mta_go_readonly_loader', 'validate'): 1168, ('mta_go_readonly_preflight', '<genexpr>'): 1169, ('mta_go_readonly_preflight', '<listcomp>'): 1170, ('mta_go_readonly_preflight', '<module>'): 1171, ('mta_go_readonly_preflight', '<setcomp>'): 1172, ('mta_go_readonly_preflight', '__init__'): 1173, ('mta_go_readonly_preflight', '_absence'): 1174, ('mta_go_readonly_preflight', '_anchors'): 1175, ('mta_go_readonly_preflight', '_binding'): 1176, ('mta_go_readonly_preflight', '_close_file'): 1177, ('mta_go_readonly_preflight', '_close_probe'): 1178, ('mta_go_readonly_preflight', '_context'): 1179, ('mta_go_readonly_preflight', '_current'): 1180, ('mta_go_readonly_preflight', '_descriptor_meta'): 1181, ('mta_go_readonly_preflight', '_fail'): 1182, ('mta_go_readonly_preflight', '_finite'): 1183, ('mta_go_readonly_preflight', '_helper'): 1184, ('mta_go_readonly_preflight', '_journal_decode'): 1185, ('mta_go_readonly_preflight', '_journal_read'): 1186, ('mta_go_readonly_preflight', '_lock'): 1187, ('mta_go_readonly_preflight', '_locks_current'): 1188, ('mta_go_readonly_preflight', '_meta'): 1189, ('mta_go_readonly_preflight', '_now'): 1190, ('mta_go_readonly_preflight', '_open'): 1191, ('mta_go_readonly_preflight', '_owner_current'): 1192, ('mta_go_readonly_preflight', '_pending_absent'): 1193, ('mta_go_readonly_preflight', '_pipe_current'): 1194, ('mta_go_readonly_preflight', '_sha'): 1195, ('mta_go_readonly_preflight', '_terminal_actor'): 1196, ('mta_go_readonly_preflight', '_terminal_cleanup_limits'): 1197, ('mta_go_readonly_preflight', '_terminal_finish'): 1198, ('mta_go_readonly_preflight', '_terminal_hex'): 1199, ('mta_go_readonly_preflight', '_terminal_inventory'): 1200, ('mta_go_readonly_preflight', '_terminal_launch'): 1201, ('mta_go_readonly_preflight', '_terminal_metadata'): 1202, ('mta_go_readonly_preflight', '_terminal_number'): 1203, ('mta_go_readonly_preflight', '_terminal_time_text'): 1204, ('mta_go_readonly_preflight', '_terminal_uint'): 1205, ('mta_go_readonly_preflight', 'close'): 1206, ('mta_go_readonly_preflight', 'collect'): 1207, ('mta_go_readonly_preflight', 'flock'): 1208, ('mta_go_readonly_preflight', 'fstat'): 1209, ('mta_go_readonly_preflight', 'open'): 1210, ('mta_go_readonly_preflight', 'pid'): 1211, ('mta_go_readonly_preflight', 'read'): 1212, ('mta_go_readonly_preflight', 'readable'): 1213, ('mta_go_readonly_preflight', 'readlink'): 1214, ('mta_go_readonly_preflight', 'spawn'): 1215, ('mta_go_readonly_preflight', 'stat'): 1216, ('mta_go_readonly_preflight', 'status'): 1217, ('mta_go_readonly_preflight', 'validate'): 1218, ('mta_ip', '<genexpr>'): 1219, ('mta_ip', '<lambda>'): 1220, ('mta_ip', '<module>'): 1221, ('mta_ip', '__init__'): 1222, ('mta_ip', '__new__'): 1223, ('mta_ip', '__repr__'): 1224, ('mta_ip', '_ack_message'): 1225, ('mta_ip', '_address_payload'): 1226, ('mta_ip', '_align'): 1227, ('mta_ip', '_attribute'): 1228, ('mta_ip', '_attributes'): 1229, ('mta_ip', '_bytes'): 1230, ('mta_ip', '_fail'): 1231, ('mta_ip', '_feed'): 1232, ('mta_ip', '_ip'): 1233, ('mta_ip', '_mask'): 1234, ('mta_ip', '_message'): 1235, ('mta_ip', '_messages'): 1236, ('mta_ip', '_number'): 1237, ('mta_ip', '_optional'): 1238, ('mta_ip', '_parse_address'): 1239, ('mta_ip', '_parse_route'): 1240, ('mta_ip', '_parse_rule'): 1241, ('mta_ip', '_private'): 1242, ('mta_ip', '_request_header'): 1243, ('mta_ip', '_uint'): 1244, ('mta_ip', 'decode_ack'): 1245, ('mta_ip', 'encode_del_address'): 1246, ('mta_ip', 'encode_dump'): 1247, ('mta_ip', 'encode_new_address'): 1248, ('mta_ip', 'feed'): 1249, ('mta_ip', 'ipv4_number'): 1250, ('mta_ip', 'ipv4_text'): 1251, ('mta_ip', 'records'): 1252, ('mta_ip', 'require_default_rules'): 1253, ('mta_ip', 'select_subnet'): 1254, ('mta_ip', 'snapshot_from_dumps'): 1255, ('mta_ip', 'structural_key'): 1256, ('mta_ip', 'success'): 1257, ('mta_observer_packet', '<genexpr>'): 1258, ('mta_observer_packet', '<listcomp>'): 1259, ('mta_observer_packet', '<module>'): 1260, ('mta_observer_packet', '__delattr__'): 1261, ('mta_observer_packet', '__init__'): 1262, ('mta_observer_packet', '__repr__'): 1263, ('mta_observer_packet', '__setattr__'): 1264, ('mta_observer_packet', '_binding'): 1265, ('mta_observer_packet', '_canonical'): 1266, ('mta_observer_packet', '_fail'): 1267, ('mta_observer_packet', '_finite'): 1268, ('mta_observer_packet', '_fixed'): 1269, ('mta_observer_packet', '_header'): 1270, ('mta_observer_packet', '_helpers'): 1271, ('mta_observer_packet', '_lock'): 1272, ('mta_observer_packet', '_raw_hex'): 1273, ('mta_observer_packet', '_sha'): 1274, ('mta_observer_packet', '_terminal_actor'): 1275, ('mta_observer_packet', '_terminal_canonical'): 1276, ('mta_observer_packet', '_terminal_finish'): 1277, ('mta_observer_packet', '_terminal_fixed'): 1278, ('mta_observer_packet', '_terminal_freeze'): 1279, ('mta_observer_packet', '_terminal_hex'): 1280, ('mta_observer_packet', '_terminal_int'): 1281, ('mta_observer_packet', '_terminal_journal'): 1282, ('mta_observer_packet', '_terminal_json'): 1283, ('mta_observer_packet', '_terminal_launch'): 1284, ('mta_observer_packet', '_terminal_limits'): 1285, ('mta_observer_packet', '_terminal_metadata'): 1286, ('mta_observer_packet', '_terminal_number'): 1287, ('mta_observer_packet', '_terminal_object'): 1288, ('mta_observer_packet', '_terminal_origin'): 1289, ('mta_observer_packet', '_terminal_pairs'): 1290, ('mta_observer_packet', '_terminal_primitive'): 1291, ('mta_observer_packet', '_terminal_request_fields'): 1292, ('mta_observer_packet', '_terminal_response'): 1293, ('mta_observer_packet', '_terminal_sequence'): 1294, ('mta_observer_packet', '_terminal_snapshot_tree'): 1295, ('mta_observer_packet', '_terminal_time_text'): 1296, ('mta_observer_packet', 'decode_packet'): 1297, ('mta_observer_packet', 'decode_terminal_packet'): 1298, ('mta_observer_packet', 'decode_terminal_request'): 1299, ('mta_observer_packet', 'encode_result'): 1300, ('mta_observer_packet', 'encode_terminal_request'): 1301, ('mta_observer_packet', 'encode_terminal_result'): 1302, ('mta_observer_packet', 'feed'): 1303, ('mta_observer_packet', 'finish'): 1304, ('mta_observer_packet', 'private_finish_ascii'): 1305, ('mta_observer_packet', 'private_header_ascii'): 1306, ('mta_observer_packet', 'private_journal_ascii'): 1307, ('mta_observer_packet', 'private_request_ascii'): 1308, ('mta_observer_packet', 'private_snapshot_ascii'): 1309, ('mta_p2p_client_ctrl', '<genexpr>'): 1310, ('mta_p2p_client_ctrl', '<module>'): 1311, ('mta_p2p_client_ctrl', '__init__'): 1312, ('mta_p2p_client_ctrl', '__repr__'): 1313, ('mta_p2p_client_ctrl', '__setattr__'): 1314, ('mta_p2p_client_ctrl', '_bytes'): 1315, ('mta_p2p_client_ctrl', '_credentials'): 1316, ('mta_p2p_client_ctrl', '_decimal'): 1317, ('mta_p2p_client_ctrl', '_derive'): 1318, ('mta_p2p_client_ctrl', '_fail'): 1319, ('mta_p2p_client_ctrl', '_group_tokens'): 1320, ('mta_p2p_client_ctrl', '_ipv4'): 1321, ('mta_p2p_client_ctrl', '_mac'): 1322, ('mta_p2p_client_ctrl', '_network_id'): 1323, ('mta_p2p_client_ctrl', '_owned_name'): 1324, ('mta_p2p_client_ctrl', '_ssid_decode'): 1325, ('mta_p2p_client_ctrl', '_ssid_text'): 1326, ('mta_p2p_client_ctrl', '_summary'): 1327, ('mta_p2p_client_ctrl', 'add_network_command'): 1328, ('mta_p2p_client_ctrl', 'client_config'): 1329, ('mta_p2p_client_ctrl', 'group_add_command'): 1330, ('mta_p2p_client_ctrl', 'network_commands'): 1331, ('mta_p2p_client_ctrl', 'parse_add_network_reply'): 1332, ('mta_p2p_client_ctrl', 'parse_group_started'): 1333, ('mta_p2p_client_ctrl', 'parse_ok_reply'): 1334, ('mta_p2p_client_ctrl', 'parse_status'): 1335, ('mta_p2p_client_ctrl', 'private_bytes'): 1336, ('mta_p2p_client_ctrl', 'private_fields'): 1337, ('mta_p2p_client_ctrl', 'public_summary'): 1338, ('mta_p2p_client_ctrl', 'status_command'): 1339, ('mta_p2p_client_init', '<genexpr>'): 1340, ('mta_p2p_client_init', '<lambda>'): 1341, ('mta_p2p_client_init', '<listcomp>'): 1342, ('mta_p2p_client_init', '<module>'): 1343, ('mta_p2p_client_init', '__init__'): 1344, ('mta_p2p_client_init', '__repr__'): 1345, ('mta_p2p_client_init', '__setattr__'): 1346, ('mta_p2p_client_init', '_active_return_lock'): 1347, ('mta_p2p_client_init', '_association_binding'): 1348, ('mta_p2p_client_init', '_association_mac'): 1349, ('mta_p2p_client_init', '_baseline'): 1350, ('mta_p2p_client_init', '_boot'): 1351, ('mta_p2p_client_init', '_budget'): 1352, ('mta_p2p_client_init', '_executor'): 1353, ('mta_p2p_client_init', '_fail'): 1354, ('mta_p2p_client_init', '_finish_receipt'): 1355, ('mta_p2p_client_init', '_finite'): 1356, ('mta_p2p_client_init', '_fresh'): 1357, ('mta_p2p_client_init', '_handle'): 1358, ('mta_p2p_client_init', '_hash'): 1359, ('mta_p2p_client_init', '_hex'): 1360, ('mta_p2p_client_init', '_ipv4'): 1361, ('mta_p2p_client_init', '_known_locks_before_acquire'): 1362, ('mta_p2p_client_init', '_locked'): 1363, ('mta_p2p_client_init', '_name'): 1364, ('mta_p2p_client_init', '_now'): 1365, ('mta_p2p_client_init', '_owned_ipv6'): 1366, ('mta_p2p_client_init', '_parent_until_v33'): 1367, ('mta_p2p_client_init', '_pending_admission'): 1368, ('mta_p2p_client_init', '_register'): 1369, ('mta_p2p_client_init', '_rows'): 1370, ('mta_p2p_client_init', '_same_journal'): 1371, ('mta_p2p_client_init', '_save'): 1372, ('mta_p2p_client_init', '_sealed_status'): 1373, ('mta_p2p_client_init', '_session_deadline_v33'): 1374, ('mta_p2p_client_init', '_session_profile'): 1375, ('mta_p2p_client_init', '_uint'): 1376, ('mta_p2p_client_init', 'acquire'): 1377, ('mta_p2p_client_init', 'active_return'): 1378, ('mta_p2p_client_init', 'authenticate_finish'): 1379, ('mta_p2p_client_init', 'binding'): 1380, ('mta_p2p_client_init', 'caps'): 1381, ('mta_p2p_client_init', 'client_combo'): 1382, ('mta_p2p_client_init', 'close_resources'): 1383, ('mta_p2p_client_init', 'closed_locks'): 1384, ('mta_p2p_client_init', 'closed_resources'): 1385, ('mta_p2p_client_init', 'commit'): 1386, ('mta_p2p_client_init', 'complete'): 1387, ('mta_p2p_client_init', 'create_client'): 1388, ('mta_p2p_client_init', 'current'): 1389, ('mta_p2p_client_init', 'delete_client'): 1390, ('mta_p2p_client_init', 'executor'): 1391, ('mta_p2p_client_init', 'exit_proof'): 1392, ('mta_p2p_client_init', 'finish'): 1393, ('mta_p2p_client_init', 'gone'): 1394, ('mta_p2p_client_init', 'invalidated'): 1395, ('mta_p2p_client_init', 'key'): 1396, ('mta_p2p_client_init', 'launch_controller'): 1397, ('mta_p2p_client_init', 'launch_watchdog'): 1398, ('mta_p2p_client_init', 'live'): 1399, ('mta_p2p_client_init', 'live_actor'): 1400, ('mta_p2p_client_init', 'lock_valid'): 1401, ('mta_p2p_client_init', 'origin_absent'): 1402, ('mta_p2p_client_init', 'origin_up'): 1403, ('mta_p2p_client_init', 'original_actors'): 1404, ('mta_p2p_client_init', 'parse_init_status'): 1405, ('mta_p2p_client_init', 'pending_clear'): 1406, ('mta_p2p_client_init', 'pending_matches'): 1407, ('mta_p2p_client_init', 'prior_clear'): 1408, ('mta_p2p_client_init', 'recover_current'): 1409, ('mta_p2p_client_init', 'register'): 1410, ('mta_p2p_client_init', 'register_interface'): 1411, ('mta_p2p_client_init', 'release_exec'): 1412, ('mta_p2p_client_init', 'replace'): 1413, ('mta_p2p_client_init', 'resolve'): 1414, ('mta_p2p_client_init', 'restore'): 1415, ('mta_p2p_client_init', 'session_profile_named'): 1416, ('mta_p2p_client_init', 'snapshot'): 1417, ('mta_p2p_client_init', 'start'): 1418, ('mta_p2p_client_init', 'status'): 1419, ('mta_p2p_client_init', 'stop_and_reap'): 1420, ('mta_protocol', '<genexpr>'): 1421, ('mta_protocol', '<module>'): 1422, ('mta_protocol', '__init__'): 1423, ('mta_protocol', '_ad'): 1424, ('mta_protocol', '_base64'): 1425, ('mta_protocol', '_bounded_tree'): 1426, ('mta_protocol', '_integer'): 1427, ('mta_protocol', '_text'): 1428, ('mta_protocol', 'add_received'): 1429, ('mta_protocol', 'complete'): 1430, ('mta_protocol', 'decode_advertisement'): 1431, ('mta_protocol', 'decode_json'): 1432, ('mta_protocol', 'decode_message'): 1433, ('mta_protocol', 'decode_service_data'): 1434, ('mta_protocol', 'encode_advertisement'): 1435, ('mta_protocol', 'encode_json'): 1436, ('mta_protocol', 'encode_message'): 1437, ('mta_protocol', 'from_bytes'): 1438, ('mta_protocol', 'from_dict'): 1439, ('mta_protocol', 'get_task_id'): 1440, ('mta_protocol', 'make_ack'): 1441, ('mta_protocol', 'parse'): 1442, ('mta_protocol', 'parse_ad_fields'): 1443, ('mta_protocol', 'serialize'): 1444, ('mta_protocol', 'to_bytes'): 1445, ('mta_protocol', 'to_dict'): 1446, ('mta_protocol', 'transition'): 1447, ('mta_protocol', 'validate_send_request'): 1448, ('mta_protocol', 'validate_task_id'): 1449, ('mta_scoped_sockets', '<genexpr>'): 1450, ('mta_scoped_sockets', '<listcomp>'): 1451, ('mta_scoped_sockets', '<module>'): 1452, ('mta_scoped_sockets', '__init__'): 1453, ('mta_scoped_sockets', '_acquire_owner'): 1454, ('mta_scoped_sockets', '_basic'): 1455, ('mta_scoped_sockets', '_begin'): 1456, ('mta_scoped_sockets', '_created'): 1457, ('mta_scoped_sockets', '_dispose'): 1458, ('mta_scoped_sockets', '_handed_contains'): 1459, ('mta_scoped_sockets', '_handoff'): 1460, ('mta_scoped_sockets', '_hash'): 1461, ('mta_scoped_sockets', '_integer'): 1462, ('mta_scoped_sockets', '_ip'): 1463, ('mta_scoped_sockets', '_now'): 1464, ('mta_scoped_sockets', '_number'): 1465, ('mta_scoped_sockets', '_operation'): 1466, ('mta_scoped_sockets', '_proof'): 1467, ('mta_scoped_sockets', '_socket_options'): 1468, ('mta_scoped_sockets', '_source'): 1469, ('mta_scoped_sockets', '_unconnected'): 1470, ('mta_scoped_sockets', 'check'): 1471, ('mta_scoped_sockets', 'close'): 1472, ('mta_scoped_sockets', 'confirm_transport_closed'): 1473, ('mta_scoped_sockets', 'context'): 1474, ('mta_scoped_sockets', 'endpoint'): 1475, ('mta_scoped_sockets', 'listener_factory'): 1476, ('mta_scoped_sockets', 'socket_factory'): 1477, ('mta_scoped_sockets', 'status'): 1478, ('mta_snapshot_data', '<genexpr>'): 1479, ('mta_snapshot_data', '<listcomp>'): 1480, ('mta_snapshot_data', '<module>'): 1481, ('mta_snapshot_data', '__delattr__'): 1482, ('mta_snapshot_data', '__init__'): 1483, ('mta_snapshot_data', '__repr__'): 1484, ('mta_snapshot_data', '__setattr__'): 1485, ('mta_snapshot_data', '_actor'): 1486, ('mta_snapshot_data', '_actor_fields'): 1487, ('mta_snapshot_data', '_address'): 1488, ('mta_snapshot_data', '_address_fields'): 1489, ('mta_snapshot_data', '_bytes_literal'): 1490, ('mta_snapshot_data', '_canonical'): 1491, ('mta_snapshot_data', '_fail'): 1492, ('mta_snapshot_data', '_fields'): 1493, ('mta_snapshot_data', '_fixed_types'): 1494, ('mta_snapshot_data', '_full'): 1495, ('mta_snapshot_data', '_ipv6'): 1496, ('mta_snapshot_data', '_json_budget'): 1497, ('mta_snapshot_data', '_origin'): 1498, ('mta_snapshot_data', '_origin_fields'): 1499, ('mta_snapshot_data', '_original_key'): 1500, ('mta_snapshot_data', '_pack'): 1501, ('mta_snapshot_data', '_route'): 1502, ('mta_snapshot_data', '_route_fields'): 1503, ('mta_snapshot_data', '_row_sort_text'): 1504, ('mta_snapshot_data', '_rule'): 1505, ('mta_snapshot_data', '_rule_fields'): 1506, ('mta_snapshot_data', '_sha'): 1507, ('mta_snapshot_data', '_stable_key'): 1508, ('mta_snapshot_data', '_text'): 1509, ('mta_snapshot_data', '_tuple'): 1510, ('mta_snapshot_data', '_uint'): 1511, ('mta_snapshot_data', '_unpack'): 1512, ('mta_snapshot_data', 'decode_snapshot'): 1513, ('mta_snapshot_data', 'encode_snapshot'): 1514, ('mta_snapshot_data', 'key_ascii'): 1515, ('mta_snapshot_data', 'key_digest'): 1516, ('mta_snapshot_data', 'private_ascii'): 1517, ('mta_snapshot_data', 'private_key_ascii'): 1518, ('mta_storage', '<genexpr>'): 1519, ('mta_storage', '<module>'): 1520, ('mta_storage', '__init__'): 1521, ('mta_storage', '_cancel'): 1522, ('mta_storage', '_check_no_symlinks'): 1523, ('mta_storage', '_check_zip_directory'): 1524, ('mta_storage', '_positive_limit'): 1525, ('mta_storage', '_space'): 1526, ('mta_storage', '_validate_infos'): 1527, ('mta_storage', 'free_bytes'): 1528, ('mta_storage', 'receive'): 1529, ('mta_storage', 'validate_member_name'): 1530, ('mta_transport', '<genexpr>'): 1531, ('mta_transport', '<lambda>'): 1532, ('mta_transport', '<listcomp>'): 1533, ('mta_transport', '<module>'): 1534, ('mta_transport', '__init__'): 1535, ('mta_transport', '_alive'): 1536, ('mta_transport', '_before_io'): 1537, ('mta_transport', '_check'): 1538, ('mta_transport', '_cleanup_temporary'): 1539, ('mta_transport', '_close_unknown'): 1540, ('mta_transport', '_deadline_number'): 1541, ('mta_transport', '_is_cancelled'): 1542, ('mta_transport', '_pending_threads'): 1543, ('mta_transport', '_processes_pending'): 1544, ('mta_transport', '_record'): 1545, ('mta_transport', '_record_closed'): 1546, ('mta_transport', '_run_impl'): 1547, ('mta_transport', 'actors_quiet'): 1548, ('mta_transport', 'adopt'): 1549, ('mta_transport', 'adopt_process'): 1550, ('mta_transport', 'adopt_returned'): 1551, ('mta_transport', 'begin'): 1552, ('mta_transport', 'begin_wrap'): 1553, ('mta_transport', 'check'): 1554, ('mta_transport', 'chunk'): 1555, ('mta_transport', 'cleanup_ready'): 1556, ('mta_transport', 'close'): 1557, ('mta_transport', 'close_socket'): 1558, ('mta_transport', 'closed'): 1559, ('mta_transport', 'closure_snapshot'): 1560, ('mta_transport', 'connect'): 1561, ('mta_transport', 'download_body'): 1562, ('mta_transport', 'end'): 1563, ('mta_transport', 'failed_wrap'): 1564, ('mta_transport', 'finish_wrap'): 1565, ('mta_transport', 'frame'): 1566, ('mta_transport', 'lifecycle_status'): 1567, ('mta_transport', 'line'): 1568, ('mta_transport', 'now'): 1569, ('mta_transport', 'private_ipv4'): 1570, ('mta_transport', 'read'): 1571, ('mta_transport', 'read_headers'): 1572, ('mta_transport', 'receive'): 1573, ('mta_transport', 'remaining'): 1574, ('mta_transport', 'request_close'): 1575, ('mta_transport', 'run'): 1576, ('mta_transport', 'send'): 1577, ('mta_transport', 'snapshot'): 1578, ('mta_transport', 'space'): 1579, ('mta_transport', 'start_thread'): 1580, ('mta_transport', 'websocket_client'): 1581, ('p011_json', '<genexpr>'): 1582, ('p011_json', '<listcomp>'): 1583, ('p011_json', '<module>'): 1584, ('p011_json', 'dumps'): 1585, ('p011_json', 'encode'): 1586, ('p011_json', 'loads'): 1587, ('p011_json', 'quoted'): 1588, ('p011_json', 'string'): 1589, ('p011_json', 'value'): 1590, ('p011_json', 'whitespace'): 1591, ('__main__', '<genexpr>'): 1101, ('__main__', '<module>'): 1102, ('__main__', '__init__'): 1103, ('__main__', '_adopt_stdin'): 1104, ('__main__', '_adopt_stdout'): 1105, ('__main__', '_anchors'): 1106, ('__main__', '_arguments'): 1107, ('__main__', '_binding'): 1108, ('__main__', '_close'): 1109, ('__main__', '_close_stdin'): 1110, ('__main__', '_context'): 1111, ('__main__', '_fail'): 1112, ('__main__', '_finite'): 1113, ('__main__', '_load_module'): 1114, ('__main__', '_meta'): 1115, ('__main__', '_now'): 1116, ('__main__', '_read_source'): 1117, ('__main__', '_read_terminal_request'): 1118, ('__main__', '_request_current'): 1119, ('__main__', '_stdin_current'): 1120, ('__main__', '_stdout_current'): 1121, ('__main__', '_terminal_arguments'): 1122, ('__main__', '_write_packet'): 1123, ('__main__', 'close'): 1124, ('__main__', 'collect'): 1125, ('__main__', 'flags'): 1126, ('__main__', 'fstat'): 1127, ('__main__', 'main'): 1128, ('__main__', 'main94'): 1129, ('__main__', 'open'): 1130, ('__main__', 'pid'): 1131, ('__main__', 'pinned_import'): 1132, ('__main__', 'pipe_buf'): 1133, ('__main__', 'read'): 1134, ('__main__', 'readable'): 1135, ('__main__', 'readlink'): 1136, ('__main__', 'set_flags'): 1137, ('__main__', 'stat'): 1138, ('__main__', 'status'): 1139, ('__main__', 'validate'): 1140, ('__main__', 'writable'): 1141, ('__main__', 'write'): 1142}


def _private_failure_diag(value, caught):
    try:
        if (type(value) is not ReadonlyObserverEntry or not _ENTRY_INVENTORY or
                _ENTRY_INVENTORY[-1] is not value or not isinstance(caught, BaseException)):
            return
        # All reads below are retained Python caches, not current device proofs.
        same = int(caught is object.__getattribute__(value, 'failure'))
        layers, seen, current, edge, chain_cut = [], [], caught, 0, 0
        for unused in range(4):
            seen.append(current)
            current_type, type_code = type(current), 0
            for module_name, class_name, number in _PRIVATE_DIAG_TYPES:
                module = sys.modules.get(module_name)
                if (type(module) is types.ModuleType and
                        module.__dict__.get(class_name) is current_type):
                    type_code = number
                    break
            fields = object.__getattribute__(current, '__dict__')
            code = fields.get('code') if type(fields) is dict else None
            reason = (_PRIVATE_DIAG_REASONS.get(code, 0)
                if type(code) is str and 1 <= len(code) <= 96 else 0)
            if not reason:
                args = BaseException.args.__get__(current, current_type)
                if (type(args) is tuple and len(args) == 1 and type(args[0]) is str
                        and 1 <= len(args[0]) <= 96):
                    reason = _PRIVATE_DIAG_REASONS.get(args[0], 0)
            number = 0
            if isinstance(current, OSError):
                actual = OSError.errno.__get__(current, current_type)
                if type(actual) is int and 1 <= actual <= 4095:
                    number = actual
            trace = BaseException.__traceback__.__get__(current, current_type)
            positions = []
            for unused_frame in range(8):
                if trace is None:
                    break
                namespace, frame_code = trace.tb_frame.f_globals, trace.tb_frame.f_code
                module_name, function_name = namespace.get('__name__'), frame_code.co_name
                canonical = sys.modules.get(module_name) if type(module_name) is str else None
                frame_id = (_PRIVATE_DIAG_FRAMES.get((module_name, function_name), 0)
                    if type(canonical) is types.ModuleType and canonical.__dict__ is namespace
                    and type(function_name) is str else 0)
                line = trace.tb_lineno
                if type(line) is not int or not 1 <= line <= 65535:
                    line = 0
                positions.append(str(frame_id) + ':' + str(line))
                trace = trace.tb_next
            trace_cut = int(trace is not None)
            suppressed = BaseException.__suppress_context__.__get__(current, current_type)
            layers.append(','.join((str(type_code), str(reason), str(number), str(edge),
                str(int(suppressed is True)), str(trace_cut), '|'.join(positions))))
            cause = BaseException.__cause__.__get__(current, current_type)
            context = BaseException.__context__.__get__(current, current_type)
            following, next_edge = ((cause, 1) if isinstance(cause, BaseException)
                else ((context, 2) if isinstance(context, BaseException) else (None, 0)))
            if following is None:
                break
            if any(following is item for item in seen):
                chain_cut = 2
                break
            if len(layers) == 4:
                chain_cut = 1
                break
            current, edge = following, next_edge
        raw = ('PRIVATE_GO_OBSERVER_FAILURE_V1 s=' + str(same) + ' x=' + str(chain_cut)
            + ' e=' + ';'.join(layers) + '\n').encode('ascii')
        if 1 <= len(raw) <= 512:
            # Exactly one attempt; no flag/stat/clock/read/close/retry operation.
            # A failed/short write is not retried and cannot change main return1.
            os.write(2, raw)
    except BaseException:
        pass


if __name__ == '__main__':
    raise SystemExit(main94())
