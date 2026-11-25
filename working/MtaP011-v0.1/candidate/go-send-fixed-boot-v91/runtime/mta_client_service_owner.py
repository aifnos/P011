"""Finite fixed State/loopback service owner; not receive/RF admission.

Explicit --serve is a fresh-process entry using the fixed Boot91 definitions
at the existing state-v69 path. Its 27 ordinary roles are checked; State78
receives the SAME original loader service cap, never its 10-second load cap.
Default main performs no IO. All radio policies remain unavailable. This
SOURCE replacement is not staged. Parent89 is only an ordinary definition;
its private observer is not run at start, and Pub90's bundle seal and network
finish admission remain absent. Close retains the original zero-operation policy, not an active
worker restoration producer. Private IO models may map the three fixed path roles for
HOST tests, never issue readiness. Partial objects, original errors, requests
and threads stay retained. No old recovery record or managed tree is removed.
"""
import builtins
import errno
import hashlib
import math
import os
import socket
import stat
import sys
import threading
import time
import types

ROOT = '/tmp/p011-mta-state-v69'
USER_ROOT = '/mnt/data/p011-toolbox/user'
BLUEZ = ROOT + '/native/mta-bluez-helper'
NETWORK = ROOT + '/native/mta-network-helper'
BOOT_PATH = ROOT + '/runtime/mta_client_receive_boot.py'
BOOT_PIN = (18914, '513fb72d3be7d02b483e60b890a66c73f30180ab76228b18b972796b0bd5fb2e')
BOOT_SCHEMA = 'sender-state-boot-v91-source'
BOOT_MODULES = (
    'mta_client_executor', 'p011_json', 'mta_protocol', 'mta_storage',
    'mta_files', 'mta_crypto', 'mta_transfer_session', 'mta_dhcp',
    'mta_dhcp_server', 'mta_scoped_sockets', 'mta_transport', 'mta_sender',
    'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff', 'mta_client_tmp_alias',
    'mta_client_receive_factory', 'mta_client_state_bridge', 'mta_go_deployment',
    'mta_send_preparation', 'mta_go_readonly_parent', 'mta_go_send_publication',
    'mta_go_send_bridge', 'mta_service')
GO_ASSET_RUNTIME = '/var/volatile/tmp/p011-mta-go-send-v76-assets/runtime'
HELPER_PINS = ((65832, '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
               (47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'))
MAX_REQUESTS = 4096
CLEANUP_SECONDS = 60.0
_MAIN = None


class ServiceOwnerError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code): raise ServiceOwnerError(code) from None


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


def _meta(value):
    result = tuple(getattr(value, key, None) for key in
                   ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(v) is not int or not 0 <= v < (1 << 64) for v in result): _fail('metadata_unknown')
    return result


class _LinuxIo(object):
    def _anchors(self):
        rows = []
        physical = '/var/volatile/tmp/p011-mta-state-v69'
        for path, mode, target in (('/', None, None), ('/tmp', stat.S_IFLNK | 0o777, '/var/tmp'),
                ('/var', stat.S_IFDIR | 0o755, None),
                ('/var/tmp', stat.S_IFLNK | 0o777, '/var/volatile/tmp'),
                ('/var/volatile', stat.S_IFDIR | 0o1777, None),
                ('/var/volatile/tmp', stat.S_IFDIR | 0o1777, None),
                (physical, stat.S_IFDIR | 0o700, None),
                (physical + '/runtime', stat.S_IFDIR | 0o700, None),
                (physical + '/native', stat.S_IFDIR | 0o700, None)):
            meta = _meta(os.lstat(path))
            if (meta[3:5] != (0, 0) or meta[5] < 1 or
                    mode is None and (not stat.S_ISDIR(meta[2]) or meta[2] & 0o022) or
                    mode is not None and meta[2] != mode): _fail('unsafe_anchor')
            if target is not None and (meta[5] != 1 or os.readlink(path) != target or meta[6] != len(target)):
                _fail('unsafe_anchor')
            rows.append((path, meta if target is not None else meta[:5], target))
        for path in ('/mnt', '/mnt/data', '/mnt/data/p011-toolbox', USER_ROOT, USER_ROOT + '/Received'):
            meta = _meta(os.lstat(path))
            if not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or meta[2] & 0o022 or meta[5] < 1:
                _fail('unsafe_user_root')
            if path in (USER_ROOT, USER_ROOT + '/Received') and stat.S_IMODE(meta[2]) != 0o700:
                _fail('unsafe_user_root')
            rows.append((path, meta[:5], None))
        for suffix in ('', '/runtime', '/native'):
            if _meta(os.stat(ROOT + suffix))[:5] != _meta(os.lstat(physical + suffix))[:5]:
                _fail('anchor_changed')
        result = tuple(rows)
        if hasattr(self, 'original_anchors') and self.original_anchors != result: _fail('anchor_changed')
        return result
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('unsupported_platform')
        self.original_anchors = self._anchors()
    def state_paths(self): return USER_ROOT, BLUEZ, NETWORK
    def pid(self): return os.getpid()
    def stat(self, path):
        self._anchors()
        return os.stat(path, follow_symlinks=False)
    def open(self, path):
        if path not in (BOOT_PATH, BLUEZ, NETWORK): _fail('fixed_paths_unknown')
        self._anchors()
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)


def _read_asset(io, path, size, pin, mode, rows, check):
    row = {'path': path, 'fd': None, 'metadata': None, 'raw': None, 'attempted': False,
           'closed': False, 'unknown': True, 'failure': None}
    rows.append(row)
    try:
        check(); row['fd'] = io.open(path)  # Retain before any late-cap check.
        if type(row['fd']) is not int or row['fd'] < 0: _fail('descriptor_unknown')
        row['metadata'] = _meta(io.fstat(row['fd'])); row['unknown'] = False
        check(); meta = row['metadata']
        if not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != mode or meta[3:6] != (0, 0, 1) or meta[6] != size:
            _fail('asset_shape')
        parts, count = [], 0
        while count <= size:
            check(); raw = io.read(row['fd'], min(65536, size + 1 - count)); check()
            if type(raw) is not bytes: _fail('asset_shape')
            parts.append(raw); count += len(raw)
            if not raw: break
        row['raw'] = b''.join(parts)
        if (len(row['raw']) != size or hashlib.sha256(row['raw']).hexdigest() != pin or
                _meta(io.fstat(row['fd'])) != meta or _meta(io.stat(path)) != meta): _fail('asset_changed')
        return row['raw']
    except BaseException as error:
        row['failure'] = error
        raise
    finally:
        if row['unknown'] is False:
            row['attempted'] = True
            try:
                if _meta(io.fstat(row['fd'])) != row['metadata']: _fail('close_unknown')
                returned = io.close(row['fd'])
                try: io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException as error:
                row['close_failure'] = error
                row['unknown'] = True


class _SocketRef(object):
    """Original socket byte operations; intercept only its once close proof."""
    def __init__(self, owner, row): self.owner, self.row = owner, row
    def accept(self): return self.row['socket'].accept()
    def _remaining(self):
        now = self.owner.clock()  # Per-request sample; never shared owner.last.
        if not _finite(now) or now >= self.owner.until or self.owner.stop_called: _fail('deadline')
        return self.owner.until - now
    def _clip(self):
        remaining = self._remaining(); current = self.row['socket'].gettimeout()
        self.row['socket'].settimeout(remaining if current is None else min(current, remaining))
    def recv(self, count):
        self._clip(); value = self.row['socket'].recv(count); self._remaining(); return value
    def sendall(self, data):
        self._clip(); value = self.row['socket'].sendall(data); self._remaining(); return value
    def settimeout(self, value):
        if value is None or not _finite(value): _fail('timeout_unknown')
        return self.row['socket'].settimeout(min(value, self._remaining()))
    def shutdown(self, how): return self.row['socket'].shutdown(how)
    def fileno(self): return self.row['socket'].fileno()
    def close(self):
        if not self.owner._close_socket(self.row): _fail('socket_close_unknown')
        return None


class FixedStateServiceOwner(object):
    def __init__(self, loader, original_until, _io=None):
        boot = sys.modules.get('mta_client_receive_boot')
        if (type(boot) is not types.ModuleType or type(loader) is not boot.BootSourceLoader or
                not _finite(original_until) or float(original_until) != loader._original_until or
                loader.clock is not time.monotonic): _fail('invalid_owner')
        self.boot, self.loader = boot, loader
        self.until = self.original_until = loader._original_until
        self.clock = time.monotonic
        self.io = self.original_io = _LinuxIo() if _io is None else _io
        self.worker = threading.current_thread()
        self.pid = None
        self.lock = threading.RLock()
        self.factory = self.state = self.server = self.thread = None
        self.probe_rows = None
        self.service = self.http = None
        self.server_constructor_failure = None
        self.assets, self.requests, self.threads = [], [], []
        self.listener = None
        self.paths = None
        self.started = self.start_complete = self.state_complete = self.server_complete = False
        self.factory_called = self.state_called = self.server_called = False
        self.stop_called = self.close_called = self.close_complete = False
        self.state_close_called = False
        self.state_close_return = None
        self.cleanup_until = None
        self.failure, self.loop_failure, self.failures = None, None, []
        self.last = None

    def _context(self):
        if (self.io is not self.original_io or self.until is not self.original_until or
                self.loader._original_until is not self.original_until or self.loader.clock is not self.clock or
                sys.modules.get('mta_client_receive_boot') is not self.boot or
                self.pid is not None and self.io.pid() != self.pid): _fail('owner_changed')

    def _boot_roles(self):
        # Original authenticate has already checked all fixed bytes, original
        # namespaces and source closes. This pure role contract grants no RF.
        if (self.boot.SOURCE_SCHEMA != BOOT_SCHEMA or self.boot.MODULES != BOOT_MODULES or
                type(self.loader.modules) is not dict or len(self.loader.modules) != len(BOOT_MODULES)):
            _fail('boot_roles_changed')
        for name in BOOT_MODULES:
            module = self.loader.modules.get(name)
            root = GO_ASSET_RUNTIME if name == 'mta_go_deployment' else ROOT + '/runtime'
            if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                    module.__file__ != root + '/' + name + '.py'):
                _fail('boot_roles_changed')

    def _now(self, cleanup=False):
        with self.lock:
            self._context(); now = self.clock()
            if not _finite(now) or self.last is not None and now < self.last: _fail('clock_unknown')
            self.last = now
            cap = self.cleanup_until if cleanup else self.until
            if cap is None or now >= cap: _fail('deadline')
            return now

    def _socket_row(self, raw, row):
        # The caller registers this exact row before fileno/fstat can fail.
        if type(raw) is not socket.socket: _fail('socket_unknown')
        row['fd'] = raw.fileno()
        if type(row['fd']) is not int or row['fd'] < 0: _fail('socket_unknown')
        row['metadata'] = _meta(self.io.fstat(row['fd']))
        if not stat.S_ISSOCK(row['metadata'][2]): _fail('socket_unknown')
        row['unknown'] = False; row['proxy'] = _SocketRef(self, row)
        return row

    def _close_socket(self, row):
        with self.lock:
            self._context()
            if row['attempted']: return row['closed'] is True and row['unknown'] is False
            if row['unknown']: return False
            row['attempted'] = True
            try:
                if row['socket'].fileno() != row['fd'] or _meta(self.io.fstat(row['fd'])) != row['metadata']:
                    _fail('socket_close_unknown')
                returned = row['socket'].close()
                try: self.io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException as error:
                row['failure'] = error; row['unknown'] = True
            return row['closed'] is True and row['unknown'] is False

    def _new_thread(self, target):
        ticket = {'thread': None, 'initialized': False, 'called': False, 'returned': False,
                  'unknown': False, 'ended': False, 'failure': None}
        self.threads.append(ticket)
        value = threading.Thread.__new__(threading.Thread); ticket['thread'] = value
        try:
            threading.Thread.__init__(value, target=target); value.daemon = True
            ticket['initialized'] = True
        except BaseException as error:
            ticket['failure'] = error; ticket['unknown'] = True; raise
        return ticket

    def _start_thread(self, ticket):
        self._now()
        if self.stop_called or self.server.stopping.is_set(): _fail('deadline')
        ticket['called'] = True
        try: ticket['thread'].start(); ticket['returned'] = True
        except BaseException as error:
            ticket['failure'] = error; ticket['unknown'] = True; raise

    def start(self):
        if self.started or self.close_called: _fail('already_started')
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        self.started = True
        try:
            self._now(); self.io.validate(); self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid <= 0x7fffffff: _fail('owner_changed')
            self._now()
            self.boot.BootSourceLoader.authenticate(self.loader)
            self._boot_roles()
            self.factory_called = True
            self.factory = self.boot.BootSourceLoader.create_fixed_factory(self.loader)
            self.service, self.http = self.loader.modules['mta_service'], self.loader.modules['minhttp']
            paths = self.io.state_paths()
            if type(paths) is not tuple or len(paths) != 3 or any(type(p) is not str or not os.path.isabs(p) for p in paths):
                _fail('fixed_paths_unknown')
            if type(self.io) is _LinuxIo and paths != (USER_ROOT, BLUEZ, NETWORK): _fail('fixed_paths_unknown')
            self.paths = paths
            for path, pin in zip(paths[1:], HELPER_PINS):
                _read_asset(self.io, path, pin[0], pin[1], 0o500, self.assets, self._now)
            if any(row['unknown'] or row['closed'] is not True for row in self.assets): _fail('asset_close_unknown')
            self._now(); self.state_called = True
            self.state = self.service.State.__new__(self.service.State)
            try:
                self.service.State.__init__(self.state, paths[0], paths[1], paths[2],
                                           trusted_receive_deployment_factory=self.factory,
                                           original_service_until=self.original_until)
            finally:
                self.probe_rows = getattr(self.state, 'probe_actors', None)
            self.state_complete = True
            self.state.scan_available = False
            if (self.state.receive_available is not False or self.state.send_available is not False or
                    self.state.wifi_restore_pending is not False or self.state.radio_restore_pending is not False or
                    self.state._trusted_receive_deployment_factory is not self.factory or
                    self.state._original_service_until is not self.original_until or
                    self.state._service_until_original is not self.original_until or
                    not self.service.State._probes_closed(self.state)):
                _fail('state_start_pending')
            self._now(); self.server_called = True
            self.server = self.service.Server.__new__(self.service.Server)
            try:
                self.service.Server.__init__(self.server, self.state, 0, True)
                self.server_complete = True
            except BaseException as error:
                self.server_constructor_failure = error
                raise
            finally:
                raw = getattr(self.server, 'socket', None)
                if raw is not None:
                    self.listener = {'socket': raw, 'fd': None, 'metadata': None, 'proxy': None,
                        'attempted': False, 'closed': False, 'unknown': True, 'failure': None}
                    try: self._socket_row(raw, self.listener)
                    except BaseException as error:
                        self.listener['failure'] = error; self.failures.append(error)
            if self.listener is None or self.listener['unknown']: _fail('server_socket_unknown')
            self.server.socket = self.listener['proxy']
            self.server.bootstrap_deadline = min(self.server.bootstrap_deadline, self.until)
            owner, base, http = self, self.service.Handler, self.http
            class FiniteHandler(base):
                def setup(self):
                    self.deadline = min(self.deadline, owner.until)
                    http.BaseHTTPRequestHandler.setup(self)
                def _dispatch(self, method):
                    if owner.clock() >= owner.until or self.server.stopping.is_set(): return
                    return method(self)
                def do_GET(self): return self._dispatch(base.do_GET)
                def do_POST(self): return self._dispatch(base.do_POST)
            self.server.handler = FiniteHandler
            self._now(); ticket = self._new_thread(self._serve)
            self.thread = ticket['thread']; self._start_thread(ticket)
            self._now(); self.start_complete = True
            return self
        except BaseException as error:
            self.failure = error; self.failures.append(error)
            raise

    def _request(self, row, address):
        try: self.http.HTTPServer.process(self.server, row['proxy'], address)
        except BaseException as error: row['failure'] = error; self.failures.append(error)
        finally: row['ended'] = True

    def _serve(self):
        try:
            while not self.server.stopping.is_set():
                self._now()
                if len(self.requests) >= MAX_REQUESTS: _fail('request_budget')
                # Serialize accept+inventory against proxy close/EBADF so our
                # own accept cannot reuse a descriptor before its close proof.
                with self.lock:
                    try: raw, address = self.server.socket.accept()
                    except socket.timeout: continue
                    row = {'socket': raw, 'fd': None, 'metadata': None, 'proxy': None,
                           'attempted': False, 'closed': False, 'unknown': True, 'ended': False, 'failure': None}
                    self.requests.append(row)
                    self._socket_row(raw, row)
                self._now()  # Adopt first; late accept cannot create new work.
                if self.stop_called or self.server.stopping.is_set(): _fail('deadline')
                if not self.server.slots.acquire(False): row['proxy'].close(); row['ended'] = True; continue
                ticket = self._new_thread(lambda r=row, a=address: self._request(r, a))
                row['ticket'] = ticket
                with self.server.worker_lock: self.server.workers[row['proxy']] = ticket['thread']
                self._start_thread(ticket)
        except BaseException as error:
            if not self.stop_called and not (type(error) is ServiceOwnerError and error.code == 'deadline'):
                self.loop_failure = error
                self.failures.append(error)
        finally:
            self._stop_server()

    def _stop_server(self):
        with self.lock:
            if self.stop_called: return
            self.stop_called = True
            if self.server_complete:
                try: self.http.HTTPServer.shutdown(self.server)
                except BaseException as error: self.failures.append(error)
            elif self.listener is not None: self._close_socket(self.listener)
            for row in self.requests:
                try:
                    if row.get('closed') is not True: row['socket'].shutdown(socket.SHUT_RDWR)
                except OSError: pass
                except BaseException as error: self.failures.append(error)

    def endpoint(self):
        self._now()
        if not self.start_complete or self.stop_called: _fail('service_unavailable')
        return {'endpoint': 'http://' + self.server.expected_host, 'token': self.state.token}

    def close(self):
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        if self.close_called: return self.close_complete
        self.close_called = True
        now = self.clock()
        self.cleanup_until = min(now + CLEANUP_SECONDS, self.until + CLEANUP_SECONDS)
        try:
            self._now(True); self._stop_server()
            for ticket in self.threads:
                value = ticket['thread']
                try:
                    if ticket['initialized'] and ticket['called']:
                        value.join(max(0, self.cleanup_until - self._now(True)))
                        ticket['ended'] = value.is_alive() is False
                except BaseException as error: ticket['failure'] = error; self.failures.append(error)
            for row in self.requests:
                if row.get('ticket') is None or row['ticket']['called'] is False or row['ticket']['ended']:
                    self._close_socket(row)
            if self.state is not None and type(self.probe_rows) is list and self.state.probe_actors is self.probe_rows:
                self._now(True); self.service.State._close_probes(self.state); self._now(True)
            if self.state_complete:
                if any(getattr(self.state, key, None) is not None for key in
                       ('operation', 'session', 'helper', 'key', 'crypto', 'lease', 'transport', 'worker')):
                    _fail('state_operation_pending')
                self.state_close_called = True
                self.state_close_return = self.service.State.close(self.state)
                self._now(True)
            self.close_complete = self._closed()
        except BaseException as error:
            self.failures.append(error)
        return self.close_complete

    def _closed(self):
        if self.state_called and not self.state_complete or self.server_called and not self.server_complete: return False
        if any(row['unknown'] or row['closed'] is not True for row in self.assets): return False
        if self.listener is not None and (self.listener['unknown'] or self.listener['closed'] is not True): return False
        if any(row.get('unknown', True) or row.get('closed') is not True for row in self.requests): return False
        if any(t['unknown'] or t['called'] and (not t['returned'] or not t['ended']) for t in self.threads): return False
        if self.state is not None and (type(self.probe_rows) is not list or self.state.probe_actors is not self.probe_rows or
                not self.service.State._probes_closed(self.state)): return False
        if self.state_complete and (not self.state_close_called or self.state_close_return is not True): return False
        return True

    def status(self):
        return {'kind': 'fixed-state-service-owner-v91', 'started': self.started,
                'startup_complete': self.start_complete, 'close_called': self.close_called,
                'service_resources_closed': self.close_complete, 'resource_pending': not self.close_complete,
                'state_constructor_complete': self.state_complete, 'server_constructor_complete': self.server_complete,
                'loop_failed': self.loop_failure is not None, 'startup_failed': self.failure is not None,
                'state_close_called': self.state_close_called, 'state_close_verified': self.state_close_return is True,
                'assets': len(self.assets), 'requests': len(self.requests), 'threads': len(self.threads),
                'receive_available': False, 'send_available': False, 'scan_available': False,
                'native_restored': False, 'phone_tested': False}


def main(argv=None):
    global _MAIN
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print('SOURCE91_SERVICE definitions=false state=false service=false rf=false')
        return 0
    if len(args) != 3 or args[:2] != ['--serve', '--until'] or _MAIN is not None: _fail('fixed_arguments')
    until = float(args[2])
    if not _finite(until) or repr(until) != args[2]: _fail('fixed_arguments')
    io = _LinuxIo(); rows = []
    _MAIN = {'rows': rows, 'boot': None, 'loader': None, 'owner': None, 'failure': None}
    def check():
        if time.monotonic() >= until: _fail('deadline')
    try:
        check(); io.validate()
        raw = _read_asset(io, BOOT_PATH, BOOT_PIN[0], BOOT_PIN[1], 0o400, rows, check)
        if any(row['unknown'] or not row['closed'] for row in rows): _fail('boot_close_unknown')
        if any(type(n) is str and n.startswith(('mta_', 'p011_')) for n in sys.modules): _fail('namespace_busy')
        boot = types.ModuleType('mta_client_receive_boot'); _MAIN['boot'] = boot
        boot.__file__ = BOOT_PATH; sys.modules[boot.__name__] = boot
        exec(raw, boot.__dict__)
        loader = boot.BootSourceLoader(until); _MAIN['loader'] = loader; loader.load()
        owner = FixedStateServiceOwner(loader, until); _MAIN['owner'] = owner; owner.start()
        while owner.thread.is_alive(): owner.thread.join(.2)
        closed = owner.close()
        return 0 if closed and owner.failure is None and owner.loop_failure is None and not owner.failures else 1
    except BaseException as error:
        _MAIN['failure'] = error
        owner = _MAIN['owner']
        if owner is not None: owner.close()
        raise


if __name__ == '__main__':
    raise SystemExit(main())
