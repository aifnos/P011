"""Explicit private observer process entry, Python 3.5, SOURCE only.

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

ROOT = '/var/volatile/tmp/p011-mta-go-observer-v85'
RUNTIME = ROOT + '/runtime'
ALIAS = '/tmp/p011-mta-go-observer-v85'
ENTRY_PATH = RUNTIME + '/mta_go_readonly_entry.py'
STDOUT_FD = 1
ARM_READ = 0x88000
MAX_ACTIVE = 30.0
MAX_SOURCE_READS = 64
MAX_WRITES = 4096
MAX_PACKET = 262144
SOURCE_PINS = (
    ('mta_go_readonly_loader', 36535,
     '02235981f6b2b57159c5e3c99209e88ba18b7278b0fc4051a764ae625c1d220d'),
    ('mta_observer_packet', 13223,
     '6f2c882058ee30a630ac30e1a5b4e9277d04ee2e71c108b58966a0574bf74e7a'),
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
    def __init__(self): self._fcntl = None
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                sys.flags.optimize or sys.flags.isolated != 1 or not sys.dont_write_bytecode or
                os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000 or
                __file__ != ENTRY_PATH or sys.argv[0] != ENTRY_PATH):
            _fail('observer_platform_or_entry')
        import fcntl
        self._fcntl = fcntl
    def pid(self): return os.getpid()
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, ARM_READ)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)
    def flags(self, fd):
        if self._fcntl is None: _fail('observer_unvalidated')
        return self._fcntl.fcntl(fd, self._fcntl.F_GETFL)
    def set_flags(self, fd, value):
        if self._fcntl is None: _fail('observer_unvalidated')
        return self._fcntl.fcntl(fd, self._fcntl.F_SETFL, value)
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
    except BaseException: return 1  # Failure/partial inventory stays original and private.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
