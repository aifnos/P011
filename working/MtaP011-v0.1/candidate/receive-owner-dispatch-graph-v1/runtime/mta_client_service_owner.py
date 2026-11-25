"""Receiver/FileCenter SOURCE-only Owner; independent un-packaged adaptation.

The fixed nine FileCenter source pins are retained from the isolated seal source
and are not yet resealed for the new Store/Companion bytes. No deployment root,
Boot/Owner pin closure, UI credentials, audio guardian or device claim is supplied
here. Receiver directories/one-shot Trial/State/RF contracts remain unchanged.

Formal-receive-v2 original Owner: sealed startup window and one-shot trial.

Receive UI v1 root/pin composition reuses the frozen socket-close source patch.
This source graph alone does not establish UI, RF or real-phone acceptance.

Independent SOURCE derived from formal-receive-v1. Fixed roots are versioned;
old graph/results/publications remain untouched. BOOT_PIN seals the new
33-role Boot including barrier/trial before State. Source authentication
does not establish RF restoration or real-phone receive acceptance.

The existing actual readonly collector runs on the original Owner worker before
HTTP. Its original collection resources are checked and its original scope is
closed before the fixed pending/CLIENT publication barrier and requested trial
gate are constructed. Barrier refusal remains local DATA, not an RF permission:
it leaves the interface available with an unavailable gate. Production trial
request is one exact constructor boolean, default False, never an HTTP field.

The original Barrier and FixedReceiveTrial modules, partially constructed
objects, constructor/run/bind/revoke tickets and failures stay retained. No
partial/unknown object can sign close. Stop/close revoke only the original gate,
with no IO/cap renewal/reset; the existing State/Session finalizer still runs.
Gate.closed certifies only its original revocation/claim inventory, never
Session/RF/network restoration. Original startup closed methods retain their
worker rule; external status uses only the new passive gate/barrier projections.
Native paths, user directory identity policy and original resource owners remain
fixed. No pending content is read or removed, no Factory/Provider late gate is
removed, no startup/firmware is changed and no old recovery record is cleared.
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

ROOT = '/tmp/p011-mta-rx-dispatch-v1'
USER_ROOT = '/mnt/data/p011-toolbox/user'
BLUEZ = ROOT + '/native/mta-bluez-helper'
NETWORK = ROOT + '/native/mta-network-helper'
CONNMAN = ROOT + '/mta-connman-observer'
CONNMAN_PIN = (46008, '5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2')
BOOT_PATH = ROOT + '/runtime/mta_client_receive_boot.py'
BOOT_PIN = (19697, 'e5aa90e096bf6c3e560c1435391aed18c7ab76910ff2a02f053959a2903aa262')
BOOT_SCHEMA = 'sender-state-boot-v98-source'
BOOT_MODULES = (
    'mta_client_executor', 'p011_json', 'mta_protocol', 'mta_storage',
    'mta_files', 'mta_crypto', 'mta_transfer_session', 'mta_dhcp',
    'mta_dhcp_server', 'mta_scoped_sockets', 'mta_transport', 'mta_sender',
    'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff', 'mta_client_tmp_alias',
    'mta_client_startup_readonly', 'mta_client_receive_factory', 'mta_client_state_bridge', 'mta_go_deployment',
    'mta_send_preparation', 'mta_go_readonly_parent', 'mta_go_send_publication',
    'mta_go_send_bridge', 'mta_go_readonly_terminal_parent',
    'mta_receive_radio_baseline', 'mta_receive_network',
    'mta_receive_barrier', 'mta_receive_trial', 'mta_service')
GO_ASSET_RUNTIME = '/var/volatile/tmp/p011-mta-go-send-v76-assets/runtime'
HELPER_PINS = ((74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181'),
               (47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'))
MAX_REQUESTS = 4096
CLEANUP_SECONDS = 60.0
STARTUP_READONLY_SCHEMA = 'receive-startup-readonly-v1'
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


FILECENTER_MAX_SOURCE = 131072
FILECENTER_PINS = (
    ('mta_toolbox_json', 3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('mta_toolbox_minhttp', 9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
    ('mta_toolbox_storage', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('mta_toolbox_metrics', 4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('mta_toolbox_audio', 9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('mta_toolbox_server', 19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('mta_filecenter_audio', 15082, '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'),
    ('mta_filecenter_storage', 10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4'),
    ('mta_filecenter_companion', 33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284'),
)


def _held_directory_policy(binding, root):
    """Fixed observed nodes, checked through the retained no-follow FD chain."""
    expected = ('/', 'mnt', 'data', 'p011-toolbox', 'user')
    if root == USER_ROOT + '/Received': expected += ('Received',)
    elif root != USER_ROOT: _fail('unsafe_user_root')
    if binding.root != root or binding.check() is not binding: _fail('unsafe_user_root')
    rows = binding.identity_rows()
    if type(rows) is not tuple or len(rows) != len(expected): _fail('unsafe_user_root')
    for row, name in zip(rows, expected):
        if (type(row) is not tuple or len(row) != 6 or row[0] != name or
                any(type(v) is not int for v in row[1:]) or
                not stat.S_ISDIR(row[3]) or row[3] & 0o022): _fail('unsafe_user_root')
        if name == 'data':
            # The sole observed user-owned mount, not a general UID exception.
            if row[1:] != (66328, 21, stat.S_IFDIR | 0o755, 1000, 1000): _fail('unsafe_user_root')
        elif row[4:6] != (0, 0): _fail('unsafe_user_root')
        if name in ('p011-toolbox', 'user', 'Received') and stat.S_IMODE(row[3]) != 0o700:
            _fail('unsafe_user_root')
    if binding.check() is not binding or binding.identity_rows() != rows: _fail('anchor_changed')
    return rows


class _LinuxIo(object):
    def _anchors(self):
        rows = []
        physical = '/var/volatile/tmp/p011-mta-rx-dispatch-v1'
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
    def _receive_anchors(self):
        binding = getattr(self, 'original_received_binding', None)
        binding_type = getattr(self, 'original_binding_type', None)
        if binding is None or type(binding) is not binding_type: _fail('unsafe_user_root')
        rows = _held_directory_policy(binding, USER_ROOT + '/Received')
        if rows != self.original_receive_anchors: _fail('anchor_changed')
        return rows
    def bind_receive_directory(self, binding, binding_type):
        if hasattr(self, 'original_received_binding') or type(binding) is not binding_type:
            _fail('anchor_changed')
        self.original_received_binding = binding
        self.original_binding_type = binding_type
        self.original_receive_anchors = _held_directory_policy(binding, USER_ROOT + '/Received')
    def state_paths(self): return USER_ROOT, BLUEZ, NETWORK
    def pid(self): return os.getpid()
    def stat(self, path):
        self._anchors()
        if path != BOOT_PATH: self._receive_anchors()
        return os.stat(path, follow_symlinks=False)
    def open(self, path):
        if path not in (BOOT_PATH, BLUEZ, NETWORK, CONNMAN): _fail('fixed_paths_unknown')
        self._anchors()
        if path != BOOT_PATH: self._receive_anchors()
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
    def __init__(self, loader, original_until, _io=None, receive_trial_requested=False):
        if type(receive_trial_requested) is not bool: _fail('receive_trial_request')
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
        self.state_constructor_failure = self.server_constructor_failure = None
        self.assets, self.requests, self.threads = [], [], []
        self.socket_close_receipts = self._socket_close_receipts_original = []
        self.socket_receipt_methods = self._socket_receipt_methods_original = (
            type(self)._socket_receipt, type(self)._socket_receipt_closed)
        self._requests_original, self._threads_original = self.requests, self.threads
        self._state_original = self._server_original = self._listener_original = None
        self._http_stopping_original = self._http_worker_lock_original = self._http_workers_original = None
        self.listener = None
        self.paths = None
        self.started = self.start_complete = self.state_complete = self.server_complete = False
        self.factory_called = self.state_called = self.server_called = False
        self.stop_called = self.close_called = self.close_complete = False
        self.state_close_called = False
        self.state_close_return = None
        self.cleanup_until = self._cleanup_until_original = None
        self.failure, self.loop_failure, self.failures = None, None, []
        self.last = None
        self.directory_type = None
        self.user_directory = self.received_directory = None
        self._user_directory_original = self._received_directory_original = None
        self.directory_close_called = False
        self.directory_close_complete = False
        self.filecenter_ticket = self._filecenter_ticket_original = None
        self.filecenter_owner_module = self._filecenter_owner_module_original = None
        self.filecenter_directory_module = self._filecenter_directory_module_original = None
        self._filecenter_directory_type_original = None
        self.filecenter_directory_methods = self._filecenter_directory_methods_original = None
        self.filecenter_directory_inventory = self._filecenter_directory_inventory_original = None
        self.filecenter_owner_methods = self._filecenter_owner_methods_original = tuple(
            (name, getattr(type(self), name), getattr(type(self), name).__code__) for name in
            ('_seal_filecenter_directories', '_filecenter_directory_current', 'create_filecenter',
             '_filecenter_definitions_current', '_filecenter_current', '_capture_filecenter_partial',
             '_filecenter_partial_current', '_close_filecenter', '_filecenter_closed'))
        self._startup_namespace_original = globals()
        self._startup_owner_type_original = FixedStateServiceOwner
        self.startup_scope = self._startup_scope_original = None
        self._startup_module_original = self._startup_collect_original = None
        self._startup_collection_type_original = self._startup_factory_original = None
        self.startup_called = self.startup_complete = False
        self.startup_result = self.startup_failure = None
        self.network_observer_spec = self._network_observer_spec_original = None
        self._network_observer_asset_original = None
        self.receive_trial_requested = self._receive_trial_requested_original = receive_trial_requested
        self.startup_window_closed = False
        self._startup_window_scope_original = self._startup_window_collection_original = None
        self.receive_barrier = self._receive_barrier_original = None
        self._receive_barrier_module_original = self._receive_barrier_type_original = None
        self._receive_barrier_definitions_original = None
        self._receive_barrier_ticket = self._receive_barrier_ticket_original = None
        self.receive_barrier_called = False
        self.receive_barrier_failure = None
        self.receive_trial = self._receive_trial_original = None
        self._receive_trial_module_original = self._receive_trial_type_original = None
        self._receive_trial_definitions_original = None
        self._receive_trial_ticket = self._receive_trial_ticket_original = None
        self.receive_trial_called = False
        self.receive_trial_failure = None
        self.receive_trial_revoke_rows = self._receive_trial_revoke_rows_original = []

    def _context(self):
        # Guard the actual new helpers before a mutable class attribute can run.
        cls, methods = self._startup_owner_type_original, self.filecenter_owner_methods
        own = self.filecenter_owner_module
        if (type(self) is not cls or cls.__init__.__globals__ is not self._startup_namespace_original or
                own is not self._filecenter_owner_module_original or
                own is not None and (type(own) is not types.ModuleType or
                    own.__dict__ is not self._startup_namespace_original or
                    own.FixedStateServiceOwner is not cls) or
                methods is not self._filecenter_owner_methods_original or
                type(methods) is not tuple or len(methods) != 9):
            _fail('filecenter_original_changed')
        for name, value, code in methods:
            if (type(value) is not types.FunctionType or getattr(type(self), name) is not value or
                    value.__globals__ is not self._startup_namespace_original or value.__code__ is not code):
                _fail('filecenter_original_changed')
        if self.filecenter_ticket is not self._filecenter_ticket_original:
            _fail('filecenter_original_changed')
        if (self.io is not self.original_io or self.until is not self.original_until or
                self.loader._original_until is not self.original_until or self.loader.clock is not self.clock or
                sys.modules.get('mta_client_receive_boot') is not self.boot or
                self.network_observer_spec is not self._network_observer_spec_original or
                type(self.receive_trial_requested) is not bool or
                self.receive_trial_requested is not self._receive_trial_requested_original or
                self.receive_barrier is not self._receive_barrier_original or
                self.receive_trial is not self._receive_trial_original or
                self._receive_barrier_ticket is not self._receive_barrier_ticket_original or
                self._receive_trial_ticket is not self._receive_trial_ticket_original or
                self.receive_trial_revoke_rows is not self._receive_trial_revoke_rows_original or
                self.pid is not None and self.io.pid() != self.pid): _fail('owner_changed')

    def _boot_roles(self):
        # Original authenticate has already checked all fixed bytes, original
        # namespaces and source closes. This pure role contract grants no RF.
        if (type(BOOT_PIN) is not tuple or len(BOOT_PIN) != 2 or
                type(BOOT_PIN[0]) is not int or not 0 < BOOT_PIN[0] <= 2 * 1024 * 1024 or
                type(BOOT_PIN[1]) is not str or len(BOOT_PIN[1]) != 64 or
                any(value not in '0123456789abcdef' for value in BOOT_PIN[1])):
            _fail('boot_roles_changed')  # Explicit draft is unusable until sealed.
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

    def _seal_filecenter_directories(self, module):
        """Seal already verified Receiver bindings; create no new directory."""
        self._context()
        if (self.filecenter_directory_inventory is not None or
                self._filecenter_directory_inventory_original is not None or
                type(module) is not types.ModuleType or
                self.loader.modules.get('mta_storage') is not module or
                sys.modules.get('mta_storage') is not module or
                module.DirectoryBinding is not self.directory_type or
                self.directory_type.__init__.__globals__ is not module.__dict__):
            _fail('filecenter_directory_original')
        cls = self.directory_type
        methods = tuple((name, getattr(cls, name),
                         getattr(cls, name).fget.__code__ if type(getattr(cls, name)) is property
                         else getattr(cls, name).__code__) for name in
                        ('__init__', '_current', '_now', 'check', 'identity_rows',
                         'ensure_private_child', 'close', 'closed', 'root', 'absolute_until'))
        identity_rows = next(value for name, value, code in methods if name == 'identity_rows')
        inventory = tuple((binding, binding.rows, binding._row_originals, identity_rows(binding))
                          for binding in (self.user_directory, self.received_directory))
        if (inventory[0][0] is not self._user_directory_original or
                inventory[1][0] is not self._received_directory_original or
                inventory[1][3][:-1] != inventory[0][3]):
            _fail('filecenter_directory_original')
        self.filecenter_directory_module = self._filecenter_directory_module_original = module
        self._filecenter_directory_type_original = cls
        self.filecenter_directory_methods = self._filecenter_directory_methods_original = methods
        self.filecenter_directory_inventory = self._filecenter_directory_inventory_original = inventory
        if not self._filecenter_directory_current(): _fail('filecenter_directory_original')

    def _filecenter_directory_current(self):
        """Passive sealed identities; no cap renewal, directory IO or RF grant."""
        self._context()
        module, cls = self.filecenter_directory_module, self.directory_type
        methods, inventory = self.filecenter_directory_methods, self.filecenter_directory_inventory
        if (module is not self._filecenter_directory_module_original or
                type(module) is not types.ModuleType or
                self.loader.modules.get('mta_storage') is not module or
                sys.modules.get('mta_storage') is not module or
                module.DirectoryBinding is not cls or cls is not self._filecenter_directory_type_original or
                cls.__init__.__globals__ is not module.__dict__ or
                methods is not self._filecenter_directory_methods_original or
                type(methods) is not tuple or len(methods) != 10 or
                any(getattr(cls, name) is not original or
                    (original.fget.__code__ if type(original) is property else original.__code__) is not code
                    for name, original, code in methods) or
                inventory is not self._filecenter_directory_inventory_original or
                type(inventory) is not tuple or len(inventory) != 2):
            return False
        identity_rows = next(value for name, value, code in methods if name == 'identity_rows')
        originals = (self._user_directory_original, self._received_directory_original)
        current = (self.user_directory, self.received_directory)
        for index, (binding, rows, row_originals, identities) in enumerate(inventory):
            if (binding is not originals[index] or binding is not current[index] or
                    type(binding) is not cls or binding.rows is not rows or
                    binding._row_originals is not row_originals or
                    type(rows) is not list or type(row_originals) is not tuple or
                    len(rows) != len(row_originals) or
                    any(row is not original for row, original in zip(rows, row_originals)) or
                    binding.clock is not self.clock or binding.absolute_until is not self.original_until or
                    binding.root != (USER_ROOT if index == 0 else USER_ROOT + '/Received') or
                    type(identities) is not tuple or len(identities) != (5 if index == 0 else 6) or
                    identity_rows(binding) != identities):
                return False
        return inventory[1][3][:-1] == inventory[0][3]

    def create_filecenter(self, source_rows, owner_module):
        """Single fixed nine-source producer; returns no public credentials.

        A future fixed UI must bind its REAL audio guardian before issuing
        FileCenter credentials. This function does not supply a substitute ACK
        or success callback, invoke audio, or grant Native/RF/restoration.
        """
        self._now()
        if (self.filecenter_ticket is not None or not self.start_complete or
                self.stop_called or self.close_called or not self._filecenter_directory_current()):
            _fail('filecenter_original_required')
        if type(source_rows) is not tuple or len(source_rows) != len(FILECENTER_PINS):
            _fail('filecenter_source_required')
        for row, pin in zip(source_rows, FILECENTER_PINS):
            if (type(row) is not tuple or len(row) != 2 or row[0] != pin[0] or
                    type(row[1]) is not bytes or len(row[1]) != pin[1] or
                    hashlib.sha256(row[1]).hexdigest() != pin[2]):
                _fail('filecenter_source_required')
        if sum(len(raw) for name, raw in source_rows) > FILECENTER_MAX_SOURCE:
            _fail('filecenter_source_required')
        if any(name in sys.modules for name, raw in source_rows):
            _fail('filecenter_namespace_busy')
        own = owner_module
        if (type(own) is not types.ModuleType or own.__dict__ is not self._startup_namespace_original or
                own.FixedStateServiceOwner is not self._startup_owner_type_original or
                type(self) is not own.FixedStateServiceOwner or
                own.FixedStateServiceOwner.__init__.__globals__ is not own.__dict__):
            _fail('filecenter_original_required')
        if (self.filecenter_owner_module is not None or self._filecenter_owner_module_original is not None):
            _fail('filecenter_original_required')
        # FixedSession owns this actual unregistered Receiver module. Never
        # synthesize or register a Sender/canonical-name shadow definition.
        self.filecenter_owner_module = self._filecenter_owner_module_original = own
        ticket = dict(sources=source_rows, modules=[], module=None, namespace=None, cls=None,
                      creator=None, methods=None, original=None, create_called=False, create_returned=False,
                      close_called=False, close_return=None, failure=None, close_failure=None,
                      state=None, server=None, thread=None, media=None, audio=None, audio_tickets=None,
                      owner_module=own, owner_namespace=own.__dict__)
        self.filecenter_ticket = self._filecenter_ticket_original = ticket
        try:
            for name, raw in source_rows:
                self._now()
                module = types.ModuleType(name)
                module.__file__ = '<fixed-receiver-filecenter-memory/'+name+'.py>'
                row = dict(name=name, raw=raw, module=module, namespace=module.__dict__,
                           entered=False, complete=False, definitions=None)
                ticket['modules'].append(row)
                sys.modules[name] = module
                row['entered'] = True
                exec(raw, module.__dict__)
                # Hold actual source definitions, not a user-provided creator.
                row['definitions'] = tuple((key, value, tuple(vars(value).items()) if type(value) is type else None)
                    for key, value in module.__dict__.items()
                    if type(value) in (types.FunctionType, type) and
                    getattr(value, '__module__', None) == name)
                row['complete'] = True
                self._now()
            module = ticket['modules'][-1]['module']
            cls, creator = module._Companion, module.create
            if (type(creator) is not types.FunctionType or creator.__globals__ is not module.__dict__ or
                    type(cls) is not type or cls.__init__.__globals__ is not module.__dict__):
                _fail('filecenter_source_required')
            ticket.update(module=module, namespace=module.__dict__, cls=cls, creator=creator,
                          methods={name: getattr(cls, name) for name in
                                   ('__init__', 'close', 'closed', '_workers_closed', 'check', 'credentials')})
            def retain(original):
                if (ticket is not self._filecenter_ticket_original or not ticket['create_called'] or
                        ticket['original'] is not None or type(original) is not cls):
                    _fail('filecenter_original_required')
                ticket['original'] = original  # Before any Companion child constructor.
            ticket['create_called'] = True
            result = creator(self, own, retain)
            ticket['create_returned'] = True
            if result is not ticket['original']: _fail('filecenter_original_required')
            ticket.update(state=result.state, server=result.server, thread=result.thread, media=result.media,
                          audio=result.audio, audio_tickets=result.audio.tickets)
            # Retain the actual atomic resources before fstat can fail. Current
            # child-object identity alone cannot authorize close of a swapped
            # FileStore or listener hidden inside those original children.
            store, sock = result.state.store, result.server.socket
            ticket.update(store=store, store_fd=store.rootfd, store_metadata=None,
                          socket=sock, socket_fd=None, socket_metadata=None,
                          store_close_original=store._root_close_original,
                          listener_close_original=result.server._listener_close_original)
            if (type(store) is not ticket['modules'][7]['module'].RetainedFileStore or
                    type(sock) is not socket.socket or type(ticket['store_fd']) is not int or
                    ticket['store_fd'] < 0):
                _fail('filecenter_original_changed')
            ticket['store_metadata'] = _meta(os.fstat(ticket['store_fd']))
            ticket['socket_fd'] = sock.fileno()
            if type(ticket['socket_fd']) is not int or ticket['socket_fd'] < 0:
                _fail('filecenter_original_changed')
            ticket['socket_metadata'] = _meta(os.fstat(ticket['socket_fd']))
            if (ticket['store_metadata'][:5] != self._filecenter_directory_inventory_original[0][3][-1][1:] or
                    not stat.S_ISSOCK(ticket['socket_metadata'][2])):
                _fail('filecenter_original_changed')
            if not self._filecenter_current(): _fail('filecenter_original_changed')
            self._now()
            return result  # Intentionally NOT Companion.credentials(result).
        except BaseException as error:
            ticket['failure'] = error
            if ticket['original'] is not None:
                self._capture_filecenter_partial(ticket)
            raise

    def _filecenter_definitions_current(self):
        if not self._filecenter_directory_current(): return False
        ticket = self.filecenter_ticket
        if (type(ticket) is not dict or ticket is not self._filecenter_ticket_original or
                type(ticket['owner_module']) is not types.ModuleType or
                ticket['owner_module'] is not self._filecenter_owner_module_original or
                ticket['owner_module'].__dict__ is not self._startup_namespace_original or
                ticket['owner_module'].FixedStateServiceOwner is not self._startup_owner_type_original or
                ticket['owner_namespace'] is not self._startup_namespace_original or
                len(ticket['modules']) != len(FILECENTER_PINS)):
            return False
        for row, pin in zip(ticket['modules'], FILECENTER_PINS):
            if (row['name'] != pin[0] or row['complete'] is not True or
                    sys.modules.get(row['name']) is not row['module'] or
                    row['module'].__dict__ is not row['namespace']):
                return False
            for name, value, attributes in row['definitions']:
                if row['namespace'].get(name) is not value: return False
                if attributes is not None and any(vars(value).get(key) is not original for key, original in attributes):
                    return False
        module, cls = ticket['module'], ticket['cls']
        return (module is ticket['modules'][-1]['module'] and module.__dict__ is ticket['namespace'] and
                module.create is ticket['creator'] and module._Companion is cls and
                all(getattr(cls, name) is value for name, value in ticket['methods'].items()))

    def _filecenter_current(self):
        if not self._filecenter_definitions_current(): return False
        ticket, value = self.filecenter_ticket, self.filecenter_ticket['original']
        store_original, listener_original = (ticket.get('store_close_original'),
                                             ticket.get('listener_close_original'))
        if (type(store_original) is not tuple or len(store_original) != 4 or
                type(listener_original) is not tuple or len(listener_original) != 4):
            return False
        same = (ticket['create_returned'] is True and type(value) is ticket['cls'] and
                value.owner is self and value.worker is self.worker and value.until is self.original_until and
                value.root == USER_ROOT and value.state is ticket['state'] and
                value.server is ticket['server'] and value.thread is ticket['thread'] and
                value.media is ticket['media'] and value.audio is ticket['audio'] and
                value.audio is value.original_audio and value.state.audio is value.audio and
                value.audio.tickets is ticket['audio_tickets'] and
                value.state.store is ticket['store'] and value.server.socket is ticket['socket'] and
                value.socket_original is ticket['socket'] and
                value.rootfd is ticket['store_fd'] and value.original_rootfd is ticket['store_fd'] and
                value.store_original is ticket['store'] and value.store_close_original is store_original and
                value.listener_close_original is listener_original and
                ticket['store']._root_close_original is store_original and
                ticket['server']._listener_close_original is listener_original and
                store_original[0] is ticket['store'] and store_original[1] is ticket['store_fd'] and
                type(store_original[2]) is tuple and store_original[2][:5] == ticket['store_metadata'][:5] and
                listener_original[0] is ticket['server'] and listener_original[1] is ticket['socket'] and
                type(listener_original[2]) is int and listener_original[2] == ticket['socket_fd'] and
                listener_original[3] == ticket['socket_metadata'])
        if not same: return False
        if value.close_called is True:
            # The same actual Store/listener own the original close events.
            # Consume their immutable seals, never re-check historical numbers.
            return (ticket['modules'][7]['module'].RetainedFileStore.root_closed(ticket['store']) is True and
                    ticket['module']._FileCenterServer.listener_closed(ticket['server']) is True)
        return (value.close_called is False and ticket['store'].rootfd is ticket['store_fd'] and
                ticket['socket'].fileno() == ticket['socket_fd'] and
                _meta(os.fstat(ticket['store_fd']))[:5] == ticket['store_metadata'][:5] and
                _meta(os.fstat(ticket['socket_fd'])) == ticket['socket_metadata'])

    def _capture_filecenter_partial(self, ticket):
        """Retain actual partial children before any cleanup; never a receipt."""
        value = ticket['original']
        partial = dict(value=value, attributes=(), children=(), socket=None, socket_fd=None,
                       socket_metadata=None, store_fd=None, store_metadata=None,
                       captured=False, failure=None)
        ticket['partial_inventory'] = partial
        try:
            if (not self._filecenter_definitions_current() or type(value) is not ticket['cls'] or
                    ticket['create_called'] is not True or ticket['create_returned'] is not False):
                _fail('filecenter_partial_unknown')
            names = ('root', 'until', 'worker', 'owner', 'state', 'server', 'thread', 'audio',
                     'media', 'rootfd', 'original_rootfd', 'socket_original',
                     'state_complete', 'server_complete', 'thread_initialized',
                     'start_called', 'start_returned', 'close_called')
            partial['attributes'] = tuple((name, hasattr(value, name), getattr(value, name, None)) for name in names)
            # Header validation can fail before its resource inventory exists.
            # No missing field is projected to a successful empty constructor.
            if not all(hasattr(value, name) for name in names) or value.owner is not self or value.worker is not self.worker:
                _fail('filecenter_partial_unknown')
            module = ticket['module']
            children = []
            for original, cls, names in (
                    (value.state, module._FileCenterState, ('store', 'audio', 'stop_event')),
                    (value.server, module._FileCenterServer, ('state', 'socket', 'stopping')),
                    (value.thread, threading.Thread, ('_initialized',)),
                    (value.audio, ticket['modules'][6]['module'].FileCenterAudio, ('audio', 'tickets'))):
                children.append((original, cls, tuple((name, hasattr(original, name), getattr(original, name, None))
                                                     for name in names) if original is not None else ()))
                partial['children'] = tuple(children)  # Before subsequent fstat/type checks.
                if original is not None and type(original) is not cls: _fail('filecenter_partial_unknown')
            state, server, audio = value.state, value.server, value.audio
            store = getattr(state, 'store', None)
            children.append((store, ticket['modules'][7]['module'].RetainedFileStore,
                             tuple((name, hasattr(store, name), getattr(store, name, None))
                                   for name in ('root', 'rootfd')) if store is not None else ()))
            partial['children'] = tuple(children)
            if store is not None:
                if type(store) is not children[-1][1]: _fail('filecenter_partial_unknown')
                fd = getattr(store, 'rootfd', None)
                partial['store_fd'] = fd
                if fd is not None:
                    if type(fd) is not int or fd < 0: _fail('filecenter_partial_unknown')
                    partial['store_metadata'] = _meta(os.fstat(fd))[:5]
                    if (getattr(store, 'root', None) != USER_ROOT or
                            partial['store_metadata'] != self._filecenter_directory_inventory_original[0][3][-1][1:]):
                        _fail('filecenter_partial_unknown')
            sock = getattr(server, 'socket', None)
            partial['socket'] = sock
            if sock is not None:
                if type(sock) is not socket.socket: _fail('filecenter_partial_unknown')
                partial['socket_fd'] = sock.fileno()
                if partial['socket_fd'] >= 0:
                    partial['socket_metadata'] = _meta(os.fstat(partial['socket_fd']))
                    if not stat.S_ISSOCK(partial['socket_metadata'][2]): _fail('filecenter_partial_unknown')
                elif partial['socket_fd'] != -1: _fail('filecenter_partial_unknown')
            # A partial creator never issued credentials or invoked audio.play.
            # An unexpected actor cannot be cleaned by guessing its ownership.
            if audio is not None and (getattr(audio, 'audio', None) is not None or getattr(audio, 'tickets', None)):
                _fail('filecenter_partial_unknown')
            partial['captured'] = True
        except BaseException as error:
            partial['failure'] = error  # Strong original failure; no retry/clearing.

    def _filecenter_partial_current(self):
        ticket = self.filecenter_ticket
        partial = ticket.get('partial_inventory')
        if (type(partial) is not dict or not partial['captured'] or partial['failure'] is not None or
                not self._filecenter_definitions_current() or partial['value'] is not ticket['original'] or
                type(ticket['original']) is not ticket['cls'] or ticket['create_returned'] is not False):
            return False
        for original, attributes in [(partial['value'], partial['attributes'])] + [
                (value, attributes) for value, cls, attributes in partial['children']]:
            if any(hasattr(original, name) is not present or present and getattr(original, name) is not retained
                   for name, present, retained in attributes):
                return False
        if any(value is not None and type(value) is not cls for value, cls, attributes in partial['children']):
            return False
        fd = partial['store_fd']
        if fd is not None and _meta(os.fstat(fd))[:5] != partial['store_metadata']: return False
        sock = partial['socket']
        if sock is not None and (sock.fileno() != partial['socket_fd'] or
                partial['socket_fd'] >= 0 and _meta(os.fstat(partial['socket_fd'])) != partial['socket_metadata']):
            return False
        return True


    def _close_filecenter(self):
        self._context()
        if self.cleanup_until is not self._cleanup_until_original: _fail('cleanup_cap_changed')
        ticket = self.filecenter_ticket
        if ticket is None:
            return ticket is self._filecenter_ticket_original
        if ticket is not self._filecenter_ticket_original: _fail('filecenter_original_changed')
        if ticket['close_called']: return self._filecenter_closed()
        if (not self._filecenter_definitions_current() or
                type(ticket['original']) is not ticket['cls']):
            return False  # Partial definitions/unknown creator: preserve originals.
        if ticket['create_returned']:
            if not self._filecenter_current(): return False
        elif not self._filecenter_partial_current():
            return False  # Unknown/changed child: no foreign close or fake absence.
        ticket['close_called'] = True
        try:
            # Original FileCenter close clips all child waits to this Owner's
            # same original absolute cleanup cap; no child renews that cap.
            ticket['close_return'] = ticket['methods']['close'](ticket['original'],
                cleanup_until=self._cleanup_until_original)
        except BaseException as error:
            ticket['close_failure'] = error
            raise
        return self._filecenter_closed()

    def _filecenter_closed(self):
        if self.filecenter_ticket is None:
            return self._filecenter_ticket_original is None
        ticket = self.filecenter_ticket
        try:
            return (ticket is self._filecenter_ticket_original and ticket['create_returned'] is True and
                    ticket['failure'] is None and ticket['close_failure'] is None and
                    ticket['close_called'] is True and ticket['close_return'] is True and
                    self._filecenter_current() and
                    ticket['methods']['closed'](ticket['original']) is True and
                    ticket['audio'].actors_closed() is True)
        except BaseException:
            return False  # A passive failure is never a closure/grant.

    def _socket_row(self, raw, row):
        # The caller registers this exact row before fileno/fstat can fail.
        row['socket_original'] = raw
        if type(raw) is not socket.socket: _fail('socket_unknown')
        row['fd'] = row['fd_original'] = raw.fileno()
        if type(row['fd']) is not int or row['fd'] < 0: _fail('socket_unknown')
        row['metadata'] = row['metadata_original'] = _meta(self.io.fstat(row['fd']))
        if not stat.S_ISSOCK(row['metadata'][2]): _fail('socket_unknown')
        row['unknown'] = False; row['proxy'] = row['proxy_original'] = _SocketRef(self, row)
        original = (self, row, raw, row['fd'], row['metadata'], row['proxy'])
        receipt = dict(original=original, original_retained=original, sealed=None, sealed_retained=None,
            close_return_none=None, post_fileno_minus_one=None, post_outcome='none')
        self.socket_close_receipts.append(receipt)
        row['socket_close_receipt'] = receipt
        return row

    def _socket_receipt(self, row):
        """Resolve only this Owner's retained original row/object tuple."""
        if (type(row) is not dict or
                self.socket_close_receipts is not self._socket_close_receipts_original or
                not (row is self.listener or any(row is value for value in self.requests))):
            return None
        values = [value for value in self.socket_close_receipts if type(value) is dict and
                  type(value.get('original')) is tuple and len(value['original']) == 6 and
                  value['original'][1] is row]
        if len(values) != 1: return None
        value, original = values[0], values[0]['original']
        if (original is not value.get('original_retained') or original[0] is not self or
                row.get('socket_close_receipt') is not value or type(original[2]) is not socket.socket or
                row.get('socket') is not original[2] or row.get('socket_original') is not original[2] or
                type(original[3]) is not int or type(row.get('fd')) is not int or
                type(row.get('fd_original')) is not int or row['fd'] != original[3] or
                row['fd_original'] != original[3] or row.get('metadata') is not original[4] or
                row.get('metadata_original') is not original[4] or
                row.get('proxy') is not original[5] or row.get('proxy_original') is not original[5] or
                type(original[5]) is not _SocketRef or original[5].owner is not self or
                original[5].row is not row):
            return None
        return value

    def _socket_receipt_closed(self, row):
        """Once-sealed original close proof; never close/reopen the old number."""
        methods = self.socket_receipt_methods
        if (type(methods) is not tuple or methods is not self._socket_receipt_methods_original or
                len(methods) != 2 or any(type(value) is not types.FunctionType for value in methods) or
                type(self)._socket_receipt is not methods[0] or
                type(self)._socket_receipt_closed is not methods[1]):
            return False
        value = methods[0](self, row)
        if value is None: return False
        seal = value['sealed']
        if (type(seal) is not tuple or len(seal) != 6 or seal is not value['sealed_retained'] or
                seal[0] is not value['original'] or seal[1] is not True or seal[2] is not True or
                value['close_return_none'] is not True or value['post_fileno_minus_one'] is not True or
                value['post_outcome'] != seal[3] or row.get('attempted') is not True or
                row.get('closed') is not True or row.get('unknown') is not False):
            return False
        after = value['original'][2].fileno()
        if type(after) is not int or after != -1: return False
        if seal[3] == 'badfd':
            return seal[4] is None and type(seal[5]) is int and seal[5] == errno.EBADF
        if seal[3] == 'reused':
            post, original = seal[4], value['original'][4]
            if (type(post) is not tuple or len(post) != 7 or
                    any(type(item) is not int or item < 0 for item in post) or seal[5] is not None):
                return False
            return ((post[0], post[1], stat.S_IFMT(post[2])) !=
                    (original[0], original[1], stat.S_IFMT(original[2])))
        return False

    def _close_socket(self, row):
        with self.lock:
            self._context()
            methods = self.socket_receipt_methods
            if (type(methods) is not tuple or methods is not self._socket_receipt_methods_original or
                    len(methods) != 2 or any(type(value) is not types.FunctionType for value in methods) or
                    type(self)._socket_receipt is not methods[0] or
                    type(self)._socket_receipt_closed is not methods[1]):
                return False
            if row['attempted']: return methods[1](self, row)
            if row['unknown']: return False
            row['attempted'] = True
            receipt = None
            try:
                receipt = methods[0](self, row)
                if receipt is None: _fail('socket_close_unknown')
                original = receipt['original']
                before = original[2].fileno()
                if (type(before) is not int or before != original[3] or
                        _meta(self.io.fstat(original[3])) != original[4]):
                    _fail('socket_close_unknown')
                returned = original[2].close()
                receipt['close_return_none'] = returned is None
                after = original[2].fileno()
                receipt['post_fileno_minus_one'] = type(after) is int and after == -1
                if not receipt['close_return_none'] or not receipt['post_fileno_minus_one']:
                    _fail('socket_close_unknown')
                post, number = None, None
                try:
                    post = _meta(self.io.fstat(original[3]))
                except OSError as error:
                    number = error.errno
                    if type(number) is not int or number != errno.EBADF: raise
                    receipt['post_outcome'] = 'badfd'
                else:
                    if ((post[0], post[1], stat.S_IFMT(post[2])) ==
                            (original[4][0], original[4][1], stat.S_IFMT(original[4][2]))):
                        receipt['post_outcome'] = 'same'
                        _fail('socket_close_unknown')
                    receipt['post_outcome'] = 'reused'
                # Retain the immutable actual post-check; neither True fields
                # nor later absence alone can manufacture this original seal.
                seal = (original, True, True, receipt['post_outcome'], post, number)
                receipt['sealed'] = receipt['sealed_retained'] = seal
                row['closed'] = True
            except BaseException as error:
                row['failure'] = error; row['unknown'] = True
                if receipt is not None and receipt['post_outcome'] != 'same':
                    receipt['post_outcome'] = 'error'
            return methods[1](self, row)

    def _new_thread(self, target):
        ticket = {'thread': None, 'thread_original': None, 'initialized': False,
                  'called': False, 'returned': False, 'unknown': False, 'ended': False,
                  'join_called': False, 'join_returned': False, 'failure': None}
        self.threads.append(ticket)
        value = threading.Thread.__new__(threading.Thread)
        ticket['thread'] = ticket['thread_original'] = value
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
            # Boot needs only fixed /tmp anchors. Initialization holds the user
            # FD under the original cap; no top mkdir/chown/chmod or pending IO.
            storage = self.loader.modules['mta_storage']
            self.directory_type = storage.DirectoryBinding
            self.user_directory = self._user_directory_original = self.directory_type.__new__(self.directory_type)
            self.directory_type.__init__(self.user_directory, USER_ROOT,
                                         self.original_until, clock=self.clock)
            self._now(); user_rows = _held_directory_policy(self.user_directory, USER_ROOT)
            self.received_directory = self._received_directory_original = self.user_directory.ensure_private_child('Received')
            self._now()
            if (type(self.received_directory) is not self.directory_type or
                    _held_directory_policy(self.received_directory, USER_ROOT + '/Received')[:-1] != user_rows):
                _fail('anchor_changed')
            self.io.bind_receive_directory(self.received_directory, self.directory_type)
            self._seal_filecenter_directories(storage)
            self._now()
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
            # The exact fixed observer is read on the same original IO, under
            # the same Owner deadline. _read_asset retains and once-closes its
            # FD; its real closed row stays in assets on every success/failure.
            _read_asset(self.io, CONNMAN, CONNMAN_PIN[0], CONNMAN_PIN[1],
                        0o700, self.assets, self._now)
            self._network_observer_asset_original = self.assets[-1]
            if (len(self.assets) != len(HELPER_PINS) + 1 or
                    self._network_observer_asset_original['path'] != CONNMAN or
                    self._network_observer_asset_original['failure'] is not None or
                    self._network_observer_asset_original['attempted'] is not True or
                    any(row['unknown'] or row['closed'] is not True for row in self.assets)):
                _fail('asset_close_unknown')
            self.network_observer_spec = self._network_observer_spec_original = (
                CONNMAN, CONNMAN_PIN[0], CONNMAN_PIN[1])
            self._now(); self.state_called = True
            self.state = self._state_original = self.service.State.__new__(self.service.State)
            try:
                self.service.State.__init__(self.state, paths[0], paths[1], paths[2],
                                           trusted_receive_deployment_factory=self.factory,
                                           original_service_until=self.original_until,
                                           original_received_binding=self.received_directory,
                                           network_observer_spec=self._network_observer_spec_original)
            except BaseException as error:
                self.state_constructor_failure = error
                raise
            finally:
                self.probe_rows = getattr(self.state, 'probe_actors', None)
            self.state_complete = True
            self.state.scan_available = False
            if (self.state.receive_available is not False or self.state.send_available is not False or
                    self.state.wifi_restore_pending is not False or self.state.radio_restore_pending is not False or
                    self.state._trusted_receive_deployment_factory is not self.factory or
                    self.state._original_service_until is not self.original_until or
                    self.state._service_until_original is not self.original_until or
                    self.state._original_received_binding is not self.received_directory or
                    self.state._received_binding_original is not self.received_directory or
                    self.state._network_observer_spec is not self._network_observer_spec_original or
                    self.state._network_observer_spec_original is not self._network_observer_spec_original or
                    not self.service.State._probes_closed(self.state)):
                _fail('state_start_pending')
            self._startup_readonly()
            self._prepare_receive_trial()
            self._now(); self.server_called = True
            self.server = self._server_original = self.service.Server.__new__(self.service.Server)
            try:
                self.service.Server.__init__(self.server, self.state, 0, True)
                self._http_stopping_original = self.server.stopping
                self._http_worker_lock_original = self.server.worker_lock
                self._http_workers_original = self.server.workers
                self.server_complete = True
            except BaseException as error:
                self.server_constructor_failure = error
                raise
            finally:
                raw = getattr(self.server, 'socket', None)
                if raw is not None:
                    self.listener = self._listener_original = {'socket': raw, 'fd': None, 'metadata': None, 'proxy': None,
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


    def _startup_readonly(self):
        """Synchronous original startup observation; public radio gates stay shut."""
        if self.startup_called or self.close_called:
            _fail('startup_already_attempted')
        self._now()
        if (self.state_complete is not True or self.state is not self._state_original or
                type(self.state) is not self.service.State or
                self.server_called or self.server is not None or self.thread is not None or
                self.state.probe_actors is not self.probe_rows or
                self.service.State._probes_closed(self.state) is not True or
                self.state.receive_available is not False or self.state.send_available is not False):
            _fail('startup_window_changed')
        module = self.loader.modules.get('mta_client_startup_readonly')
        if (type(module) is not types.ModuleType or
                sys.modules.get('mta_client_startup_readonly') is not module or
                type(module.collect) is not types.FunctionType or
                module.collect.__globals__ is not module.__dict__ or
                type(module.StartupCollection) is not type or
                module.StartupCollection.__module__ != module.__name__):
            _fail('startup_source_changed')
        self._startup_module_original = module
        self._startup_collect_original = module.collect
        self._startup_collection_type_original = module.StartupCollection
        self._startup_factory_original = self.factory
        self.startup_called = True
        try:
            scope = self.factory.startup_readonly(self)
            if scope is not self.startup_scope or scope is not self._startup_scope_original:
                _fail('startup_owner_changed')
            scope.collector_called = True
            value = self._startup_collect_original(scope)
            self.startup_result = value
            ticket = scope.collector_ticket
            if (type(ticket) is not dict or ticket.get('creator') is not self._startup_collection_type_original or
                    value is not ticket.get('returned') or type(value) is not self._startup_collection_type_original or
                    getattr(value, 'scope', None) is not scope or ticket.get('ended') is not True or
                    ticket.get('failure') is not None or scope.closed() is not True):
                _fail('startup_readonly_unknown')
            scope.check_active()
            self.startup_complete = True
            return value
        except BaseException as error:
            self.startup_failure = error
            raise

    def _close_startup(self):
        # A partial constructor/failed collect remains in the original scope.
        # Cleanup may not re-enter an active clock or start another observation.
        if self.startup_scope is None:
            return self.startup_called is False and self._startup_scope_original is None
        scope = self.startup_scope
        if scope is not self._startup_scope_original:
            return False
        return scope.close()

    def _startup_closed(self):
        if self.startup_scope is None:
            return self.startup_called is False and self._startup_scope_original is None
        return (self.startup_scope is self._startup_scope_original and
                self.startup_scope.closed() is True)

    def _seal_startup_window(self):
        """Same-worker original observation closure, not an RF certificate."""
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        self._now()
        scope, collection = self.startup_scope, self.startup_result
        creator = self._startup_collection_type_original
        if (self.startup_called is not True or self.startup_complete is not True or
                self.startup_failure is not None or scope is None or scope is not self._startup_scope_original or
                type(creator) is not type or type(collection) is not creator or
                collection.scope is not scope or collection.success is not True or
                collection.ended is not True or collection.failure is not None or
                collection.resources_closed() is not True or scope.closed() is not True or
                type(scope.collector_ticket) is not dict or
                scope.collector_ticket.get('creator') is not creator or
                scope.collector_ticket.get('returned') is not collection or
                scope.collector_ticket.get('ended') is not True or
                scope.collector_ticket.get('failure') is not None or
                self.server_called or self.server is not None or self.thread is not None):
            _fail('startup_window_unknown')
        self._startup_window_scope_original = scope
        self._startup_window_collection_original = collection
        if (self._close_startup() is not True or scope.close_called is not True or
                scope.close_complete is not True or self._startup_closed() is not True or
                self.startup_scope is not scope or self.startup_result is not collection or
                scope.collector_ticket.get('returned') is not collection or
                collection.resources_closed() is not True):
            _fail('startup_window_unknown')
        self.startup_window_closed = True
        self._now()

    def _receive_definitions(self, name, class_name, methods):
        module = self.loader.modules.get(name)
        if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                module.__name__ != name or module.__file__ != ROOT + '/runtime/' + name + '.py'):
            _fail('receive_trial_source_changed')
        creator = module.__dict__.get(class_name)
        if type(creator) is not type or creator.__module__ != name:
            _fail('receive_trial_source_changed')
        definitions = []
        for method_name in methods:
            method = getattr(creator, method_name, None)
            if type(method) is not types.FunctionType or method.__globals__ is not module.__dict__:
                _fail('receive_trial_source_changed')
            definitions.append((method_name, method))
        return module, creator, tuple(definitions)

    def _receive_sources_held(self):
        """Passive source identity only, no Owner clock/collector or IO."""
        for name, module, creator, definitions in (
                ('mta_receive_barrier', self._receive_barrier_module_original,
                 self._receive_barrier_type_original, self._receive_barrier_definitions_original),
                ('mta_receive_trial', self._receive_trial_module_original,
                 self._receive_trial_type_original, self._receive_trial_definitions_original)):
            if module is None:
                if creator is not None or definitions is not None: return False
                continue
            if (type(module) is not types.ModuleType or self.loader.modules.get(name) is not module or
                    sys.modules.get(name) is not module or type(creator) is not type or
                    creator.__module__ != name or type(definitions) is not tuple):
                return False
            class_name = 'Barrier' if name == 'mta_receive_barrier' else 'FixedReceiveTrial'
            if module.__dict__.get(class_name) is not creator: return False
            for method_name, method in definitions:
                if (getattr(creator, method_name, None) is not method or
                        type(method) is not types.FunctionType or method.__globals__ is not module.__dict__):
                    return False
        return True

    def _prepare_receive_trial(self):
        """Pre-listen preparation; expected barrier refusals leave UI usable."""
        if (threading.current_thread() is not self.worker or self.receive_barrier_called or
                self.receive_trial_called or self.close_called):
            _fail('receive_trial_window_changed')
        self._seal_startup_window()
        module, creator, definitions = self._receive_definitions(
            'mta_receive_barrier', 'Barrier', ('__init__', 'run', 'public_facts'))
        self._receive_barrier_module_original, self._receive_barrier_type_original = module, creator
        self._receive_barrier_definitions_original = definitions
        ticket = {'creator': creator, 'partial': None, 'constructor_called': False,
                  'constructed': False, 'constructor_return': None, 'returned': None,
                  'run_called': False, 'run_returned': None, 'ended': False,
                  'failure': None, 'unknown': True}
        self._receive_barrier_ticket = self._receive_barrier_ticket_original = ticket
        self.receive_barrier_called = True
        try:
            value = creator.__new__(creator)
            ticket['partial'] = value
            self.receive_barrier = self._receive_barrier_original = value
            if type(value) is not creator: _fail('receive_barrier_unknown')
            ticket['constructor_called'] = True
            ticket['constructor_return'] = creator.__init__(value, self)
            if ticket['constructor_return'] is not None: _fail('receive_barrier_unknown')
            ticket['constructed'] = True
            ticket['returned'] = value
            ticket['run_called'] = True
            ticket['run_returned'] = creator.run(value)
            if ticket['run_returned'] is not value: _fail('receive_barrier_unknown')
            ticket['unknown'] = False
            self.receive_barrier_failure = value.failure
        except BaseException as error:
            ticket['failure'] = self.receive_barrier_failure = error
        finally:
            ticket['ended'] = True

        # Construct even an unavailable gate against the original refused
        # barrier. Unknown partial originals are not replaced with fake DATA.
        module, creator, definitions = self._receive_definitions(
            'mta_receive_trial', 'FixedReceiveTrial',
            ('__init__', 'binds', 'available', 'revoke', 'closed', 'public_facts'))
        self._receive_trial_module_original, self._receive_trial_type_original = module, creator
        self._receive_trial_definitions_original = definitions
        ticket = {'creator': creator, 'partial': None, 'constructor_called': False,
                  'constructed': False, 'constructor_return': None, 'returned': None,
                  'bind_called': False, 'bind_returned': None, 'ended': False,
                  'failure': None, 'unknown': True}
        self._receive_trial_ticket = self._receive_trial_ticket_original = ticket
        self.receive_trial_called = True
        try:
            value = creator.__new__(creator)
            ticket['partial'] = value
            self.receive_trial = self._receive_trial_original = value
            if type(value) is not creator: _fail('receive_trial_unknown')
            ticket['constructor_called'] = True
            ticket['constructor_return'] = creator.__init__(
                value, self, self._receive_barrier_original, self._receive_trial_requested_original)
            if ticket['constructor_return'] is not None: _fail('receive_trial_unknown')
            ticket['constructed'] = True
            ticket['returned'] = value
            # The original constructor ticket is finalized before State bind.
            ticket['ended'] = True
            ticket['unknown'] = False
            ticket['bind_called'] = True
            ticket['bind_returned'] = self.service.State._bind_receive_trial(self.state, value)
            if (ticket['bind_returned'] is not value or
                    self.state._receive_trial is not value or self.state._receive_trial_original is not value or
                    self.state._receive_trial_module_original is not module or
                    creator.binds(value, self.state) is not True):
                _fail('receive_trial_unknown')
        except BaseException as error:
            ticket['failure'] = self.receive_trial_failure = error
            ticket['unknown'] = True
        finally:
            ticket['ended'] = True

    def _receive_barrier_closed(self):
        """Passive original Barrier resource receipts; refusal may be closed."""
        try:
            if self.receive_barrier_called is False:
                return (self.receive_barrier is None and self._receive_barrier_original is None and
                        self._receive_barrier_ticket is None and self._receive_barrier_ticket_original is None)
            ticket, value = self._receive_barrier_ticket, self._receive_barrier_original
            creator = self._receive_barrier_type_original
            if (not self._receive_sources_held() or ticket is not self._receive_barrier_ticket_original or
                    type(ticket) is not dict or ticket.get('creator') is not creator or
                    type(value) is not creator or self.receive_barrier is not value or
                    ticket.get('partial') is not value or ticket.get('returned') is not value or
                    ticket.get('constructor_called') is not True or ticket.get('constructed') is not True or
                    ticket.get('constructor_return') is not None or ticket.get('run_called') is not True or
                    ticket.get('run_returned') is not value or ticket.get('ended') is not True or
                    ticket.get('failure') is not None or ticket.get('unknown') is not False or
                    value.owner is not self or value._owner_original is not self or
                    value._host_model_original is not False or value.ended is not True or
                    value.close_called is not True or value.resources_closed is not True or
                    value.rows is not value._rows_original or type(value.rows) is not list or
                    value.close_failures is not value._close_failures_original or value.close_failures):
                return False
            for row in value._rows_original:
                if (type(row) is not dict or row.get('owner') is not value or
                        row.get('closed') is not True or row.get('unknown') is not False):
                    return False
                if row.get('known_no_fd') is True:
                    if (row.get('fd') is not None or row.get('fd_original') is not None or
                            row.get('open_returned') is not False or row.get('close_attempted') is not False or
                            not isinstance(row.get('failure'), BaseException)):
                        return False
                    if (row.get('open_started') is not False and not (
                            isinstance(row.get('open_error'), OSError) and
                            type(row['open_error'].errno) is int and 1 <= row['open_error'].errno <= 4095)):
                        return False
                elif (row.get('open_returned') is not True or row.get('close_attempted') is not True or
                        type(row.get('fd')) is not int or row['fd'] < 0 or
                        row['fd'] != row.get('fd_original') or
                        row.get('metadata') is not row.get('metadata_original') or
                        type(row.get('metadata')) is not tuple or row.get('close_return') is not None or
                        row.get('close_error') is not None or not isinstance(row.get('ebadf_error'), OSError) or
                        type(row['ebadf_error'].errno) is not int or row['ebadf_error'].errno != errno.EBADF):
                    return False
            return True
        except BaseException:
            return False

    def _revoke_receive_trial(self, reason):
        """No IO/clock or reset. Original State/Session remains retained."""
        if self.receive_trial_called is False:
            return self.receive_trial is None and self._receive_trial_original is None
        row = {'state': self._state_original, 'gate': self._receive_trial_original,
               'reason': reason, 'called': False, 'returned': None, 'failure': None}
        self._receive_trial_revoke_rows_original.append(row)
        try:
            gate = self._receive_trial_original
            if (not self._receive_sources_held() or self.receive_trial is not gate or
                    type(gate) is not self._receive_trial_type_original or
                    self.state is not self._state_original or self.state_complete is not True or
                    type(self.state) is not self.service.State):
                _fail('receive_trial_unknown')
            row['called'] = True
            row['returned'] = self._receive_trial_type_original.revoke(gate, self.state, reason)
            if row['returned'] is not True: _fail('receive_trial_unknown')
            return True
        except BaseException as error:
            row['failure'] = error
            self.receive_trial_failure = error
            self.failures.append(error)
            return False

    def _receive_trial_closed(self):
        """Gate closure is additive; it never substitutes for State/Session."""
        try:
            if not self._receive_barrier_closed(): return False
            if self.receive_trial_called is False:
                return (self.receive_trial is None and self._receive_trial_original is None and
                        self._receive_trial_ticket is None and self._receive_trial_ticket_original is None)
            ticket, gate = self._receive_trial_ticket, self._receive_trial_original
            if (not self._receive_sources_held() or type(ticket) is not dict or
                    ticket is not self._receive_trial_ticket_original or
                    ticket.get('creator') is not self._receive_trial_type_original or
                    type(gate) is not self._receive_trial_type_original or self.receive_trial is not gate or
                    ticket.get('partial') is not gate or ticket.get('returned') is not gate or
                    ticket.get('constructor_called') is not True or ticket.get('constructed') is not True or
                    ticket.get('constructor_return') is not None or ticket.get('ended') is not True or
                    ticket.get('failure') is not None or ticket.get('unknown') is not False or
                    ticket.get('bind_called') is not True):
                return False
            if any(row.get('failure') is not None or row.get('returned') is not True
                   for row in self._receive_trial_revoke_rows_original):
                return False
            if (ticket.get('bind_returned') is not gate or self.state is not self._state_original or
                    self.state._receive_trial is not gate or self.state._receive_trial_original is not gate or
                    self.state._receive_trial_module_original is not self._receive_trial_module_original):
                return False
            return self._receive_trial_type_original.closed(gate, self._state_original) is True
        except BaseException:
            return False

    def _startup_window_passive_closed(self):
        """Retained sealed-window receipts only; never enter Scope methods off-worker."""
        try:
            scope, collection = self._startup_window_scope_original, self._startup_window_collection_original
            return (self.startup_window_closed is True and self.startup_complete is True and
                    scope is not None and self.startup_scope is scope and self._startup_scope_original is scope and
                    collection is self.startup_result and type(collection) is self._startup_collection_type_original and
                    collection.scope is scope and collection.ended is True and collection.close_attempted is True and
                    collection.success is True and collection.failure is None and
                    scope.close_called is True and scope.close_complete is True and scope.read_ended is True and
                    type(scope.collector_ticket) is dict and
                    scope.collector_ticket.get('creator') is self._startup_collection_type_original and
                    scope.collector_ticket.get('returned') is collection and
                    scope.collector_ticket.get('ended') is True and scope.collector_ticket.get('failure') is None)
        except BaseException:
            return False

    def _receive_status(self):
        """Passive bounded public projection; never call startup_scope here."""
        output = {'receive_trial_requested': self._receive_trial_requested_original,
                  'receive_trial_available': False, 'receive_trial_claimed': False,
                  'receive_trial_revoked': False, 'receive_trial_claim_count': 0,
                  'receive_trial_reason': 'not_started',
                  'receive_barrier_reason': 'not_started',
                  'receive_barrier_resources_closed': False}
        try:
            if self._receive_sources_held() and self._receive_barrier_original is not None:
                facts = self._receive_barrier_type_original.public_facts(self._receive_barrier_original)
                if type(facts) is dict:
                    reason = facts.get('reason')
                    allowed = self._receive_barrier_module_original.REASONS
                    if type(reason) is str and reason in allowed:
                        output['receive_barrier_reason'] = reason
                    output['receive_barrier_resources_closed'] = self._receive_barrier_closed()
            if self._receive_sources_held() and self._receive_trial_original is not None:
                facts = self._receive_trial_type_original.public_facts(self._receive_trial_original)
                if type(facts) is dict:
                    for source, target in (('available', 'receive_trial_available'),
                                           ('claimed', 'receive_trial_claimed'),
                                           ('revoked', 'receive_trial_revoked')):
                        if type(facts.get(source)) is bool: output[target] = facts[source]
                    count = facts.get('claim_count')
                    if type(count) is int and count in (0, 1): output['receive_trial_claim_count'] = count
                    reason = facts.get('reason')
                    if type(reason) is str and reason in self._receive_trial_module_original.REASONS:
                        output['receive_trial_reason'] = reason
                output['receive_trial_available'] = (
                    self.state_complete is True and self.state is self._state_original and
                    type(self.state) is self.service.State and
                    self.service.State._receive_trial_available(self.state) is True)
        except BaseException:
            output['receive_trial_available'] = False
            output['receive_trial_reason'] = 'unknown'
        return output

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
                row['ticket'] = row['ticket_original'] = ticket
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
            self._revoke_receive_trial('owner_stopped')
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
        self._revoke_receive_trial('owner_closed')
        self.close_called = True
        now = self.clock()
        self.cleanup_until = self._cleanup_until_original = min(now + CLEANUP_SECONDS, self.until + CLEANUP_SECONDS)
        # Independent FileCenter close cannot suppress the Receiver finalizer.
        try: self._close_filecenter()
        except BaseException as error: self.failures.append(error)
        try:
            self._now(True); self._stop_server()
            if self.state_complete:
                # Revoke State work before waiting for HTTP workers. An original
                # retained receive operation is a reason to close, not to skip
                # the Session finalizer. Never clear its objects to get None.
                remaining = self.cleanup_until - self._now(True)
                self.state_close_called = True
                try:
                    self.state_close_return = self.service.State.close(
                        self.state, timeout=min(30.0, remaining))
                except BaseException as error:
                    self.failures.append(error)
                self._now(True)
            for ticket in self.threads:
                value = ticket['thread_original']
                try:
                    if ticket['thread'] is not value: _fail('thread_unknown')
                    if ticket['initialized'] and ticket['called'] and not ticket['join_called']:
                        remaining = max(0, self.cleanup_until - self._now(True))
                        ticket['join_called'] = True
                        value.join(remaining)
                        ticket['join_returned'] = True
                        ticket['ended'] = value.is_alive() is False
                except BaseException as error: ticket['failure'] = error; self.failures.append(error)
            for row in self.requests:
                if row.get('ticket') is None or row['ticket']['called'] is False or row['ticket']['ended']:
                    self._close_socket(row)
            if self.state is not None and type(self.probe_rows) is list and self.state.probe_actors is self.probe_rows:
                self._now(True); self.service.State._close_probes(self.state); self._now(True)
            self._close_startup()
            self._close_directories()
            self.close_complete = self._closed()
        except BaseException as error:
            self.failures.append(error)
        finally:
            try: self._close_startup()
            except BaseException as error: self.failures.append(error)
            # Expiry cannot authorize new data operations, but must not skip
            # release of known original directory owners after passive closure.
            # A false State.close still prevents releasing a live borrow.
            try: self._close_directories()
            except BaseException as error: self.failures.append(error)
            try: self.close_complete = self._closed()
            except BaseException as error: self.failures.append(error)
        return self.close_complete

    def _close_directories(self):
        # State/Factory/Parent AND HTTP handlers borrow the retained directory.
        # Passive closure gates only; expiry cannot permit release under users.
        if threading.current_thread() is not self.worker: _fail('wrong_worker')
        self._context()
        if self.directory_close_called: return self.directory_close_complete
        if (not self._filecenter_closed() or not self._http_closed() or not self._state_directory_idle() or
                not self._startup_closed() or not self._receive_trial_closed()): return False
        self.directory_close_called = True
        good = True
        for binding, original in ((self.received_directory, self._received_directory_original),
                                  (self.user_directory, self._user_directory_original)):
            if binding is None:
                if original is not None: good = False
                continue
            try:
                if (binding is not original or type(binding) is not self.directory_type or
                        binding.close() is not True or binding.closed() is not True): good = False
            except BaseException as error:
                self.failures.append(error); good = False
        self.directory_close_complete = good
        return good

    def _http_closed(self):
        """Passive original HTTP borrowers; no clock, wait, close or State call."""
        try:
            methods = self.socket_receipt_methods
            if (type(methods) is not tuple or methods is not self._socket_receipt_methods_original or
                    len(methods) != 2 or any(type(value) is not types.FunctionType for value in methods) or
                    type(self)._socket_receipt is not methods[0] or
                    type(self)._socket_receipt_closed is not methods[1]):
                return False
            if (self.socket_close_receipts is not self._socket_close_receipts_original or
                    self.requests is not self._requests_original or self.threads is not self._threads_original or
                    type(self.requests) is not list or type(self.threads) is not list or
                    self.listener is not self._listener_original or self.server is not self._server_original):
                return False
            for ticket in self.threads:
                if (type(ticket) is not dict or ticket.get('unknown') is not False or
                        ticket.get('initialized') is not True or ticket.get('failure') is not None or
                        type(ticket.get('thread')) is not threading.Thread or
                        ticket['thread'] is not ticket.get('thread_original') or
                        ticket['thread'].is_alive() is not False):
                    return False
                if ticket.get('called') is True:
                    if (ticket.get('returned') is not True or ticket.get('ended') is not True or
                            ticket.get('join_called') is not True or ticket.get('join_returned') is not True):
                        return False
                elif (ticket.get('called') is not False or ticket.get('returned') is not False or
                        ticket.get('join_called') is not False or ticket.get('join_returned') is not False or
                        ticket['thread'].ident is not None):
                    return False
            rows = ([self.listener] if self.listener is not None else []) + self.requests
            if len(self.socket_close_receipts) != len(rows): return False
            for row in rows:
                if (type(row) is not dict or row.get('unknown') is not False or
                        row.get('closed') is not True or row.get('attempted') is not True or
                        row.get('failure') is not None or type(row.get('socket')) is not socket.socket or
                        row['socket'] is not row.get('socket_original') or row['socket'].fileno() != -1 or
                        type(row.get('fd')) is not int or row['fd'] < 0 or
                        row['fd'] != row.get('fd_original') or row.get('metadata') is not row.get('metadata_original') or
                        type(row.get('metadata')) is not tuple or len(row['metadata']) != 7 or
                        type(row.get('proxy')) is not _SocketRef or row['proxy'] is not row.get('proxy_original') or
                        row['proxy'].owner is not self or row['proxy'].row is not row):
                    return False
                if not methods[1](self, row): return False
            for row in self.requests:
                ticket = row.get('ticket')
                if ticket is None:
                    if 'ticket_original' in row: return False
                elif (ticket is not row.get('ticket_original') or
                        not any(ticket is original for original in self.threads) or
                        ticket.get('called') is True and row.get('ended') is not True):
                    return False
            if self.server_called is False:
                return (self.server is None and self.listener is None and not self.requests and not self.threads)
            if (self.server_called is not True or self.server_complete is not True or self.stop_called is not True or
                    type(self.server) is not self.service.Server or self.server.state is not self._state_original or
                    self.listener is None or self.server.socket is not self.listener['proxy_original'] or
                    self.server.stopping is not self._http_stopping_original or
                    self.server.worker_lock is not self._http_worker_lock_original or
                    self.server.workers is not self._http_workers_original or
                    self.server.stopping.is_set() is not True or type(self.server.workers) is not dict):
                return False
            if self._http_worker_lock_original.acquire(False) is not True: return False
            try:
                return not self._http_workers_original
            finally:
                self._http_worker_lock_original.release()
        except BaseException:
            return False

    def _state_directory_idle(self):
        """Complete State uses its original close; only known ctor failure is idle."""
        if self.state_complete is True: return self._state_closed()
        if self.state is None:
            return self.state_called is False and self._state_original is None
        try:
            state = self.state
            if (self.state_called is not True or state is not self._state_original or
                    type(state) is not self.service.State or self.state_complete is not False or
                    not isinstance(self.state_constructor_failure, BaseException) or
                    self.server_called is not False or self.server is not None or
                    self.state_close_called is not False):
                return False
            names = ('operation', 'session', 'worker', 'helper', 'key', 'crypto', 'lease', 'transport')
            present = tuple(hasattr(state, name) for name in names)
            if any(getattr(state, name, None) is not None for name in names): return False
            binding_names = ('_original_received_binding', '_received_binding_original')
            bound = tuple(hasattr(state, name) for name in binding_names)
            if not any(bound):
                # Canonical ctor failed before binding assignment; all activity
                # fields and the probe inventory are still source-order absent.
                return (not any(present) and not hasattr(state, 'probe_actors') and self.probe_rows is None)
            if (not all(bound) or any(getattr(state, name) is not self.received_directory for name in binding_names) or
                    any(present) and not all(present)):
                return False
            if not hasattr(state, 'probe_actors'):
                # Bound-directory checks precede all actor/probe construction.
                return self.probe_rows is None
            return (type(self.probe_rows) is list and state.probe_actors is self.probe_rows and
                    self.service.State._probes_closed(state) is True)
        except BaseException:
            return False

    def _state_closed(self):
        """Passive original receive closure, not a new restore invocation."""
        state = self.state
        if (self.state_complete is not True or state is not self._state_original or
                type(state) is not self.service.State or
                self.state_close_called is not True or self.state_close_return is not True):
            return False
        if (state._original_received_binding is not self.received_directory or
                state._received_binding_original is not self.received_directory or
                state._network_observer_spec is not self._network_observer_spec_original or
                state._network_observer_spec_original is not self._network_observer_spec_original): return False
        with state.lock:
            if state.closing is not True:
                return False
            op, session = state.operation, state.session
            if op is None:
                # State.closed retains the original no-operation inventory and
                # pending/probe checks. Presence is never erased by this owner.
                return self.service.State.closed(state) is True
            if (type(op) is not self.service.Operation or op.kind != 'receive' or
                    type(session) is not self.service.TransferSession or op.session is not session or
                    state.worker is not session._worker or op.epoch != state.native_epoch or
                    op.receive_factory is not self.factory or
                    state._trusted_receive_deployment_factory is not self.factory):
                return False
            originals = (state.operation, state.session, state.worker, state.helper,
                         state.key, state.crypto, state.lease, state.transport)
            epoch = state.native_epoch
        # Only passive closure/receipt reads after the original Session.close.
        # This checks retained Parent wait/reap/absence, EOF and resource facts;
        # never Parent.finish, network restore, recover, kill or reference reset.
        if (self.service.State.closed(state) is not True or
                self.service.State._receive_terminal_closed(state, op) is not True):
            return False
        with state.lock:
            current = (state.operation, state.session, state.worker, state.helper,
                       state.key, state.crypto, state.lease, state.transport)
            return (all(actual is original for actual, original in zip(current, originals)) and
                    state.native_epoch == epoch and state.closing is True and
                    self.service.State.closed(state) is True)

    def _closed(self):
        if not self._filecenter_closed(): return False
        if not self._startup_closed() or not self._receive_trial_closed(): return False
        if self.directory_close_complete is not True: return False
        if any(binding is not None and binding.closed() is not True for binding in
               (self.received_directory, self.user_directory)): return False
        if self.state_called and not self.state_complete or self.server_called and not self.server_complete: return False
        if any(row['unknown'] or row['closed'] is not True for row in self.assets): return False
        if not self._http_closed(): return False
        if self.state is not None and (type(self.probe_rows) is not list or self.state.probe_actors is not self.probe_rows or
                not self.service.State._probes_closed(self.state)): return False
        if self.state_complete and not self._state_closed(): return False
        return True

    def status(self):
        trial = self._receive_status()
        result = {'kind': 'fixed-state-service-owner-formal-receive-v3', 'started': self.started,
                'startup_complete': self.start_complete, 'close_called': self.close_called,
                'startup_readonly_called': self.startup_called,
                'startup_readonly_complete': self.startup_complete,
                'startup_readonly_failed': self.startup_failure is not None,
                'startup_readonly_resources_closed': (
                    self._startup_closed() if threading.current_thread() is self.worker else
                    self._startup_window_passive_closed()),
                'service_resources_closed': self.close_complete, 'resource_pending': not self.close_complete,
                'state_constructor_complete': self.state_complete, 'server_constructor_complete': self.server_complete,
                'loop_failed': self.loop_failure is not None, 'startup_failed': self.failure is not None,
                'state_close_called': self.state_close_called, 'state_close_verified': self.state_close_return is True,
                'assets': len(self.assets), 'requests': len(self.requests), 'threads': len(self.threads),
                'receive_directory_closed': self.directory_close_complete,
                'receive_available': trial['receive_trial_available'],
                'send_available': False, 'scan_available': False,
                'startup_window_closed': self.startup_window_closed,
                'native_restored': False, 'phone_tested': False}
        result.update(trial)
        return result


def main(argv=None):
    global _MAIN
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print('SOURCE_FORMAL_RECEIVE_V2 definitions=false state=false service=false rf=false')
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
