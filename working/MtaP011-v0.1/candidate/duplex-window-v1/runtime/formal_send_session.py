"""SOURCE-only default envelope for the once-owned formal-send-v1 service.

This module's name intentionally does not begin with mta_/p011_. The actual
fixed Boot must load first in a clean canonical realm, before the fixed Owner
is executed there. Explicit construction/start is a future runtime interface,
not authorization to deploy or execute this SOURCE candidate. Nothing here
stages assets, selects files, prepares a GO, starts F, advertises or sends.
The original sender25/Observer41/WPA assets remain separate fixed inventories.
One service process permits one trial only. Start/ready time is deducted from
one constructed 60s/600s window; no repeat start, retry, replacement or renewal.
Original Boot 10s, Session 300s, Factory 120s and Owner cleanup 60s stay intact.
No credentials are printed. Closure is reported separately from RF success.
"""
import errno
import hashlib
import math
import os
import stat
import sys
import threading
import time
import types

ROOT = '/tmp/p011-mta-formal-send-v1'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-send-v1'
RUNTIME = ROOT + '/runtime'
PHYSICAL_RUNTIME = PHYSICAL_ROOT + '/runtime'
BOOT_NAME = 'mta_client_receive_boot'
OWNER_NAME = 'mta_client_service_owner'
BOOT_PIN = (19217, 'db3c016b2d4a296b029cf1a7cd41da5595d677dd9ab7aa9fb2a477ba44afb2c4')
OWNER_PIN = (46866, '60a5010c02d9e545b437877a939f73eb93fb1262dfeec37e3bf8d714ecf553bc')
SOURCE_SCHEMA = 'p011-formal-send-v1-source'
MAX_SOURCE = 2 * 1024 * 1024
PROFILES = (('diagnostic', 60.0, False), ('send-interactive-v1', 600.0, True))
_RETAINED = None


class SendSessionError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise SendSessionError(code) from None


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


def _meta(value):
    result = tuple(getattr(value, key, None) for key in
                   ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        _fail('metadata_unknown')
    return result


class FixedSendSession(object):
    """Actual held-source loader and finite Owner lifetime; no HOST seams.

    start() is explicit. main() never calls it. A fixed future UI may retrieve
    credentials privately while ready and send a user-selected HTTP action;
    this envelope itself neither manufactures an action nor claims admission.
    """
    def __init__(self, parent_until, parent_cleanup_until, send_trial_requested=False, profile='diagnostic'):
        match = [row for row in PROFILES if type(profile) is str and row[0] == profile]
        if (len(match) != 1 or type(send_trial_requested) is not bool or
                send_trial_requested is not match[0][2]):
            _fail('profile')
        self.profile = profile
        self.send_trial_requested = self._send_trial_requested_original = send_trial_requested
        self.clock = self._clock_original = time.monotonic
        started = self.clock()
        if not _finite(started): _fail('clock_unknown')
        self.window_started_at = float(started)
        # Parent policy comes only from the fixed once-created UI window, never
        # from browser DATA. Existing Owner until+60 must fit its exact cleanup.
        if (type(parent_until) is not float or type(parent_cleanup_until) is not float or
                not _finite(parent_until) or not _finite(parent_cleanup_until) or
                not 0 < parent_until < parent_cleanup_until < 1e12 or
                not 0 < parent_until - self.window_started_at <= 600.0 or
                parent_cleanup_until != parent_until + 60.0):
            _fail('deadline')
        self.parent_until = self._parent_until_original = parent_until
        self.parent_cleanup_until = self._parent_cleanup_until_original = parent_cleanup_until
        self._parent_window_original = self._parent_window_retained = (parent_until, parent_cleanup_until)
        self.profile_until = self._profile_until_original = self.window_started_at + match[0][1]
        self.until = min(self.profile_until, self.parent_until)
        self.cleanup_until = min(self.until + 60.0, self.parent_cleanup_until)
        self._window_original = self._window_retained = (
            self.profile, self.window_started_at, self.until, self.cleanup_until,
            parent_until, parent_cleanup_until, self.profile_until)
        self.worker = threading.current_thread()
        self.pid = os.getpid()
        self.last = self.window_started_at
        self.stop = threading.Event()
        self.rows, self.modules, self.module_originals, self.failures = [], {}, [], []
        self.anchor_original = None
        self.boot = self.owner_module = self.loader = self.owner = None
        self.loader_ticket = self.owner_ticket = None
        self.start_called = self.start_complete = self.close_called = self.close_complete = False
        self.owner_start_return = self.owner_close_return = None
        self.credentials_original = None
        self.failure = self.close_failure = None
        self.pending = False

    def window_current(self):
        value, parent = self._window_original, self._parent_window_original
        if (type(value) is not tuple or len(value) != 7 or value is not self._window_retained or
                type(parent) is not tuple or len(parent) != 2 or parent is not self._parent_window_retained or
                self.profile is not value[0] or self.window_started_at is not value[1] or
                self.until is not value[2] or self.cleanup_until is not value[3] or
                self.parent_until is not value[4] or self.parent_cleanup_until is not value[5] or
                self.profile_until is not value[6] or self.profile_until is not self._profile_until_original or
                self.parent_until is not parent[0] or self.parent_until is not self._parent_until_original or
                self.parent_cleanup_until is not parent[1] or
                self.parent_cleanup_until is not self._parent_cleanup_until_original or
                type(self.profile) is not str or type(self.send_trial_requested) is not bool or
                self.send_trial_requested is not self._send_trial_requested_original):
            return False
        match = [row for row in PROFILES if row[0] == self.profile]
        return (len(match) == 1 and self.send_trial_requested is match[0][2] and
                all(type(item) is float and _finite(item) for item in value[1:]) and
                0 < self.parent_until - self.window_started_at <= 600.0 and
                self.parent_cleanup_until == self.parent_until + 60.0 and
                self.profile_until == self.window_started_at + match[0][1] and
                self.until == min(self.profile_until, self.parent_until) and
                self.cleanup_until == min(self.until + 60.0, self.parent_cleanup_until))

    def _context(self):
        if (FixedSendSession.window_current(self) is not True or
                self.clock is not self._clock_original or self.clock is not time.monotonic or
                threading.current_thread() is not self.worker or os.getpid() != self.pid):
            _fail('original_owner_changed')
        for name, module, original_dict in self.module_originals:
            if (self.modules.get(name) is not module or sys.modules.get(name) is not module or
                    module.__dict__ is not original_dict or
                    module.__file__ != RUNTIME + '/' + name + '.py'):
                _fail('source_identity_changed')

    def check(self, cleanup=False):
        self._context()
        now = self.clock()
        if not _finite(now) or now < self.last: _fail('clock_unknown')
        self.last = float(now)
        if now >= (self.cleanup_until if cleanup else self.until): _fail('deadline')
        if not cleanup and self.stop.is_set(): _fail('stop_requested')
        return float(now)

    def _platform(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('unsupported_platform')

    def _anchors(self):
        self.check()
        rows = []
        for path, mode, target in (('/', None, None), ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                (PHYSICAL_ROOT, stat.S_IFDIR | 0o700, None),
                (PHYSICAL_RUNTIME, stat.S_IFDIR | 0o700, None)):
            self.check()
            observed = os.lstat(path)
            metadata = _meta(observed)
            if (metadata[3:5] != (0, 0) or metadata[5] < 1 or
                    mode is None and (not stat.S_ISDIR(metadata[2]) or metadata[2] & 0o022) or
                    mode is not None and metadata[2] != mode):
                _fail('unsafe_root')
            if target is not None:
                times = tuple(getattr(observed, key, None) for key in ('st_mtime_ns', 'st_ctime_ns'))
                if (metadata[5] != 1 or metadata[6] != len(target) or os.readlink(path) != target or
                        any(type(item) is not int or not 0 <= item < (1 << 64) for item in times)):
                    _fail('unsafe_root')
                rows.append((path, metadata + times, target))
            else:
                rows.append((path, metadata[:5], None))
        for virtual, physical in ((ROOT, PHYSICAL_ROOT), (RUNTIME, PHYSICAL_RUNTIME)):
            if _meta(os.stat(virtual, follow_symlinks=False))[:5] != _meta(os.lstat(physical))[:5]:
                _fail('root_changed')
        value = tuple(rows)
        if self.anchor_original is None: self.anchor_original = value
        elif value != self.anchor_original: _fail('root_changed')
        return value

    def _close_row(self, row):
        self._context()  # Stop-only close does not renew the original cap.
        if not any(row is original for original in self.rows): return False
        if row['attempted']: return row['closed'] is True and row['unknown'] is False
        if row['unknown'] or type(row['fd']) is not int:
            self.pending = True
            return False
        row['attempted'] = True
        try:
            if _meta(os.fstat(row['fd'])) != row['metadata']: _fail('close_unknown')
            returned = os.close(row['fd'])
            row['close_return'] = returned
            try: os.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException as error:
            row['close_failure'] = error
            row['unknown'] = True
        if row['closed'] is not True: self.pending = True
        return row['closed'] is True and row['unknown'] is False

    def _load_source(self, name, pin):
        if ((name, pin) not in ((BOOT_NAME, BOOT_PIN), (OWNER_NAME, OWNER_PIN)) or
                name in self.modules or name in sys.modules or len(self.rows) >= 2 or
                type(pin) is not tuple or len(pin) != 2 or not 0 < pin[0] <= MAX_SOURCE):
            _fail('source_role')
        before = self._anchors()
        physical, virtual = PHYSICAL_RUNTIME + '/' + name + '.py', RUNTIME + '/' + name + '.py'
        row = {'name': name, 'path': physical, 'fd': None, 'metadata': None, 'raw': None,
               'unknown': True, 'open_called': False, 'attempted': False, 'closed': False,
               'failure': None, 'close_return': None, 'close_error': None, 'close_failure': None,
               'module': None, 'exec_called': False, 'exec_complete': False}
        self.rows.append(row)
        try:
            self.check(); row['open_called'] = True
            row['fd'] = os.open(physical, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            if type(row['fd']) is not int or row['fd'] < 0: _fail('descriptor_unknown')
            row['metadata'] = _meta(os.fstat(row['fd'])); row['unknown'] = False
            metadata = row['metadata']
            if (metadata[2] != stat.S_IFREG | 0o400 or metadata[3:6] != (0, 0, 1) or
                    metadata[6] != pin[0]): _fail('source_shape')
            chunks, total = [], 0
            while total <= pin[0]:
                self.check(); count = min(65536, pin[0] + 1 - total)
                raw = os.read(row['fd'], count); self.check()
                if type(raw) is not bytes or len(raw) > count: _fail('source_shape')
                chunks.append(raw); total += len(raw)
                if not raw: break
            row['raw'] = b''.join(chunks)
            if (len(row['raw']) != pin[0] or hashlib.sha256(row['raw']).hexdigest() != pin[1] or
                    _meta(os.fstat(row['fd'])) != metadata or _meta(os.lstat(physical)) != metadata or
                    _meta(os.stat(virtual, follow_symlinks=False)) != metadata or self._anchors() != before):
                _fail('source_changed')
        except BaseException as error:
            row['failure'] = error
            raise
        finally:
            if self._close_row(row) is not True: self.pending = True
        if self.pending: _fail('source_close_unknown')
        self.check()
        module = types.ModuleType(name)
        module.__file__ = virtual
        row['module'] = module
        self.modules[name] = module
        self.module_originals.append((name, module, module.__dict__))
        sys.modules[name] = module  # Retain actual canonical partial exec on failure.
        row['exec_called'] = True
        try:
            exec(row['raw'], module.__dict__)
            row['exec_complete'] = True
        except BaseException as error:
            row['failure'] = error
            raise
        self.check()
        return module

    def start(self):
        self._context()
        if self.start_called or self.close_called: _fail('already_started')
        self.start_called = True
        try:
            self.check(); self._platform()
            if (__name__.startswith(('mta_', 'p011_')) or
                    any(type(name) is str and name.startswith(('mta_', 'p011_')) for name in sys.modules)):
                _fail('canonical_namespace_busy')
            self.boot = FixedSendSession._load_source(self, BOOT_NAME, BOOT_PIN)
            if self.boot.ROOT != ROOT or self.boot.SOURCE_SCHEMA != SOURCE_SCHEMA:
                _fail('boot_source')
            creator = self.boot.BootSourceLoader
            ticket = {'creator': creator, 'partial': None, 'constructor_called': True,
                      'constructed': False, 'load_called': False, 'load_return': None,
                      'load_complete': False, 'failure': None}
            self.loader_ticket = ticket
            self.loader = ticket['partial'] = object.__new__(creator)
            try:
                creator.__init__(self.loader, self.until)
                ticket['constructed'] = True
                self.check(); ticket['load_called'] = True
                ticket['load_return'] = creator.load(self.loader)
                if ticket['load_return'] is not self.loader: _fail('loader_return')
                creator.authenticate(self.loader)
                ticket['load_complete'] = True
            except BaseException as error:
                ticket['failure'] = error
                raise
            self.check()
            self.owner_module = FixedSendSession._load_source(self, OWNER_NAME, OWNER_PIN)
            if (self.owner_module.ROOT != ROOT or self.owner_module.BOOT_PIN != BOOT_PIN or
                    self.owner_module.BOOT_SCHEMA != SOURCE_SCHEMA): _fail('owner_source')
            creator = self.owner_module.FixedStateServiceOwner
            ticket = {'creator': creator, 'partial': None, 'constructor_called': True,
                      'constructed': False, 'start_called': False, 'start_return': None,
                      'start_complete': False, 'close_called': False, 'close_return': None,
                      'failure': None, 'close_failure': None}
            self.owner_ticket = ticket
            self.owner = ticket['partial'] = object.__new__(creator)
            try:
                creator.__init__(self.owner, self.loader, self.loader._original_until,
                                 send_trial_requested=self.send_trial_requested)
                ticket['constructed'] = True
                if (self.owner.original_until is not self.loader._original_until or
                        self.owner.original_until is not self.until): _fail('original_cap_changed')
                self.check(); ticket['start_called'] = True
                self.owner_start_return = ticket['start_return'] = creator.start(self.owner)
                if self.owner_start_return is not self.owner: _fail('owner_start_return')
                ticket['start_complete'] = True
            except BaseException as error:
                ticket['failure'] = error
                raise
            self.check(); self.start_complete = True
            return self
        except BaseException as error:
            self.failure = error
            self.failures.append(error)
            raise

    def credentials(self):
        """Private local integration only; main/result never serialize this."""
        self.check()
        if not self.start_complete or self.close_called: _fail('service_unavailable')
        value = self.owner_module.FixedStateServiceOwner.endpoint(self.owner)
        if (type(value) is not dict or set(value) != {'endpoint', 'token'} or
                type(value['endpoint']) is not str or not value['endpoint'].startswith('http://127.0.0.1:') or
                type(value['token']) is not str or not value['token']): _fail('credentials_shape')
        if self.credentials_original is None:
            self.credentials_original = (self.owner, value, self.until)
        elif value != self.credentials_original[1]:
            _fail('credentials_changed')
        return self.credentials_original[1]

    def request_stop(self):
        # May be called by a fixed UI thread. It grants no new work or deadline.
        self.stop.set()

    def wait(self):
        self.check()
        if not self.start_complete: _fail('service_unavailable')
        while not self.stop.is_set():
            try: now = self.check()
            except SendSessionError as error:
                if error.code == 'deadline': break
                raise
            self.stop.wait(min(0.2, max(0.0, self.until - now)))

    def close(self):
        self._context()
        if self.close_called: return self.close_complete
        self.close_called = True
        self.stop.set()

        def retain_failure(error):
            if self.close_failure is None: self.close_failure = error
            self.failures.append(error)
            self.pending = True

        # Expiry denies all new work, not stop-only closure of the originals.
        # Keep the cap failure and continue each known inventory independently.
        try: self.check(True)
        except BaseException as error: retain_failure(error)
        if self.owner_ticket is not None:
            ticket = self.owner_ticket
            try:
                if ticket['constructed'] is not True: _fail('owner_constructor_unknown')
                ticket['close_called'] = True
                self.owner_close_return = ticket['close_return'] = (
                    ticket['creator'].close(self.owner))
                if self.owner_close_return is not True: self.pending = True
            except BaseException as error:
                ticket['close_failure'] = error
                retain_failure(error)
        if self.loader_ticket is not None:
            try:
                if self.loader_ticket['constructed'] is not True: _fail('loader_constructor_unknown')
                rows = tuple(self.loader.rows)
            except BaseException as error:
                retain_failure(error)
                rows = ()
            for row in reversed(rows):
                try:
                    if self.boot.BootSourceLoader._close_row(self.loader, row) is not True:
                        self.pending = True
                except BaseException as error: retain_failure(error)
        for row in reversed(self.rows):
            try:
                if FixedSendSession._close_row(self, row) is not True: self.pending = True
            except BaseException as error: retain_failure(error)
        try: self.check(True)
        except BaseException as error: retain_failure(error)
        self.close_complete = FixedSendSession._closed(self)
        return self.close_complete

    def _closed(self):
        if (self.pending or self.close_called is not True or self.close_failure is not None or
                any(row['unknown'] or row['closed'] is not True for row in self.rows)):
            return False
        if self.loader_ticket is not None:
            if (self.loader_ticket['constructed'] is not True or self.loader.pending or
                    any(row['unknown'] or row['closed'] is not True for row in self.loader.rows)):
                return False
        if self.owner_ticket is not None:
            ticket = self.owner_ticket
            if (ticket['constructed'] is not True or ticket['close_called'] is not True or
                    ticket['close_failure'] is not None or ticket['close_return'] is not True or
                    self.owner_close_return is not ticket['close_return'] or
                    self.owner.close_complete is not True):
                return False
        return True

    def result(self):
        """No token, endpoint, selected path, phone identity or exception text."""
        self._context()
        return {'kind': 'formal-send-v1-fixed-envelope', 'profile': self.profile,
                'window_seconds': 600 if self.send_trial_requested else 60,
                'window_renewed': False, 'send_trial_requested': self.send_trial_requested,
                'start_called': self.start_called, 'startup_complete': self.start_complete,
                'startup_failed': self.failure is not None, 'stop_requested': self.stop.is_set(),
                'close_called': self.close_called, 'resources_closed': self.close_complete,
                'resource_pending': not self.close_complete,
                'boot_source_files': len(self.rows),
                'ordinary_source_files': len(self.loader.rows) if self.loader_ticket is not None and
                    self.loader_ticket['constructed'] else 0,
                'asset_payload_inline': False, 'receive_available': False,
                'native_started_verified': False, 'native_restored': False,
                'rf_verified': False, 'phone_tested': False, 'production': False}


def run_fixed(parent_until, parent_cleanup_until, send_trial_requested=False, profile='diagnostic'):
    """Explicit future fixed caller only; this SOURCE task does not invoke it."""
    global _RETAINED
    if _RETAINED is not None: _fail('already_attempted')
    value = object.__new__(FixedSendSession)
    _RETAINED = value  # Preserve even a partially failed constructor.
    FixedSendSession.__init__(value, parent_until, parent_cleanup_until, send_trial_requested, profile)
    try:
        FixedSendSession.start(value)
        FixedSendSession.wait(value)
    finally:
        FixedSendSession.close(value)
    return FixedSendSession.result(value)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args: _fail('source_only_no_device_entry')
    print('SOURCE_FORMAL_SEND_ENVELOPE source_read=false service=false send=false rf=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
