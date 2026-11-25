"""Native GO bootstrap durable intents/CAS/recovery facts, SOURCE v33-r3.

This is not a CLIENT Journal, RF grant, GO-ready proof or send provider. It
performs real native fixed-path flock/CAS/fsync/readback when called explicitly.
Mechanical fixed-path/openat/flock/fsync body cloned from frozen v32
9f5c005b48686b55. Its unmutated-only schema and restore API are NOT retained.
This revision records original native watchdog/interface/controller/GROUP_ADD
intents before IO, then secret-free actual readbacks. No schema object grants
RF: mutation entry points consume original pinned native producer objects.
Before clearing pending, every nonanchor/nonlock original FS ticket must be
physically closed; only the original six directories and two locks may remain.
Complete runtime restoration is issued only AFTER their once-close+EBADF too.
Schema remains v33-r2: a reconciled Journal is a durable baseline fact, NOT an
independent complete-F resource closure permission.
No public entry point, arbitrary path, shell, firmware write or directory maker.
Construction is pure. Default native methods have not been executed on P011.
"""
import ctypes
import errno
import hashlib
import math
import os
import re
import stat
import sys
import threading
import time
import p011_json as json
import mta_client_journal_codec as facts
import mta_p2p_client_init as core
import mta_go_deployment as sources

BASE = 'p011-mta-go-session'
RUN_PREFIX = 'go-'
DEVICE_LOCK = 'p011-mta-p2p-device.lock'
GLOBAL_PENDING = 'p011-mta-p2p-device.pending'
JOURNAL_LOCK, JOURNAL = 'go-journal.lock', 'go-journal.json'
SCHEMA = 'p011-go-bootstrap-v33-r2'
MAX_FDS, MAX_RECORD, MAX_PUBLICATIONS = 256, 131072, 26
# Actual retained-history gates, not a refunded live-FD count. Each _save has
# boot(1), two old marker/journal CAS reads(4), temp(1), new readback(1): <=7.
# Fixed preparation(11), both once launch-source reads(6), final reconcile(3)
# plus 26*7 = 202 <=216 <256. Failed publications consume their slot forever.
_STORE_OPEN_BOUND, _PUBLICATION_OPEN_BOUND = 216, 7
_PUBLICATION_LIMITS = {'prepare': 4, 'positive': 7, 'cleanup': 2}
MAX_ACTIVE_SECONDS, PREPARE_SECONDS, CLEANUP_SECONDS = 300.0, 10.0, 60.0
_ACTIVE_PHASES = ('reserved', 'watchdog_intent', 'watchdog_preexec', 'watchdog_live',
    'interface_intent', 'interface_owned', 'controller_intent', 'controller_preexec',
    'controller_live', 'group_add_intent', 'group_started')
_PHASES = _ACTIVE_PHASES + ('restore_intent', 'reconciled')
_KEYS = frozenset(('schema', 'run_token', 'candidate_sha', 'task_id', 'boot_id',
    'issued_at', 'until', 'phase', 'generation', 'baseline', 'interface_intent',
    'owned', 'watchdog', 'controller', 'group_add', 'group_observed',
    'cleanup_until', 'restored'))


class GoStoreError(RuntimeError):
    def __init__(self, code):
        self.code = code
        RuntimeError.__init__(self, code)


def _fail(code): raise GoStoreError(code) from None


def _uint(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def _number(value):
    if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
        _fail('invalid_time')
    return float(value)


def _hex(value, width):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(width) + '}', value) is not None


def _boot(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None


def _meta(value):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size',
             'st_mtime_ns', 'st_ctime_ns')
    result = tuple(getattr(value, name, None) for name in names)
    if any(not _uint(item) for item in result): _fail('metadata_unknown')
    return result


def _file(value):
    row = _meta(value)
    if not stat.S_ISREG(row[2]) or row[3:5] != (0, 0) or row[5] != 1 or stat.S_IMODE(row[2]) != 0o600 or row[6] > MAX_RECORD:
        _fail('unsafe_file')
    return row


class GoChildFacts(object):
    __slots__ = ('phase', 'spec_sha', 'argv_sha', 'until', 'actor')
    def __init__(self, values):
        if type(values) is not dict or set(values) != set(self.__slots__) or \
                values['phase'] not in ('intent', 'preexec', 'live') or \
                not _hex(values['spec_sha'], 64) or not _hex(values['argv_sha'], 64):
            _fail('invalid_child_facts')
        actor = values['actor']
        if actor is not None and type(actor) is not core.Actor: actor = facts._actor(actor)
        if (values['phase'] == 'intent') != (actor is None): _fail('invalid_child_facts')
        for k in self.__slots__:
            object.__setattr__(self, k, actor if k == 'actor' else _number(values[k]) if k == 'until' else values[k])
    def __setattr__(self, *unused): raise AttributeError('immutable persisted child facts')
    def data(self):
        return {'phase': self.phase, 'spec_sha': self.spec_sha, 'argv_sha': self.argv_sha,
            'until': self.until, 'actor': None if self.actor is None else facts._actor_tree(self.actor)}
    def key(self): return (self.phase, self.spec_sha, self.argv_sha, self.until,
        None if self.actor is None else self.actor.key())
    def source_key(self): return (self.spec_sha, self.argv_sha, self.until)


def _group(values, observed=False):
    if values is None: return None
    keys = {'frequency', 'command_sha256', 'channel_sha256', 'caps_sha256'} if not observed else \
        {'frequency', 'event_sha256', 'status_sha256', 'observed_origin'}
    if type(values) is not dict or set(values) != keys or type(values['frequency']) is not int or \
            values['frequency'] not in range(2412, 2473, 5): _fail('invalid_group_facts')
    result = dict(values)
    for k in keys - {'frequency', 'observed_origin'}:
        if not _hex(values[k], 64): _fail('invalid_group_facts')
    if observed:
        origin = values['observed_origin']
        result['observed_origin'] = origin if type(origin) is core.Origin else facts._origin(origin)
        if result['observed_origin'].iftype != 9: _fail('invalid_group_facts')
    elif values['command_sha256'] != hashlib.sha256(
            ('P2P_GROUP_ADD freq=%d' % values['frequency']).encode('ascii')).hexdigest():
        _fail('invalid_group_facts')
    return tuple(sorted(result.items()))


def _group_data(value):
    if value is None: return None
    result = dict(value)
    if 'observed_origin' in result: result['observed_origin'] = facts._origin_tree(result['observed_origin'])
    return result


class GoRecord(object):
    """Persisted secret-free facts, NOT continuing permission or an RF grant."""
    __slots__ = tuple(_KEYS)
    def __init__(self, values):
        if type(values) is not dict or set(values) != _KEYS or values['schema'] != SCHEMA or \
                not _hex(values['run_token'], 32) or not _hex(values['candidate_sha'], 64) or \
                type(values['task_id']) is not str or re.fullmatch('[A-Za-z0-9_-]{1,96}', values['task_id']) is None or \
                not _boot(values['boot_id']) or values['phase'] not in _PHASES or \
                not _uint(values['generation'], 0, MAX_PUBLICATIONS):
            _fail('invalid_record')
        issued, until = _number(values['issued_at']), _number(values['until'])
        if not 0 < until - issued <= MAX_ACTIVE_SECONDS: _fail('invalid_record')
        normalized = {}
        for k in ('baseline', 'restored'):
            value = values[k]
            normalized[k] = value if value is None or type(value) is core.Snapshot else facts._snapshot(value)
            if normalized[k] is not None and normalized[k].boot != values['boot_id']: _fail('invalid_record')
        for k in ('watchdog', 'controller'):
            value = values[k]
            normalized[k] = value if value is None or type(value) is GoChildFacts else GoChildFacts(value)
            if normalized[k] is not None and normalized[k].until != until: _fail('invalid_record')
        ticket, owned = values['interface_intent'], values['owned']
        normalized['interface_intent'] = ticket if ticket is None or type(ticket) is core.InterfaceTicket else facts._iticket(ticket)
        normalized['owned'] = owned if owned is None or type(owned) is core.Origin else facts._origin(owned)
        normalized['group_add'] = _group(values['group_add'])
        normalized['group_observed'] = _group(values['group_observed'], True)
        normalized['cleanup_until'] = None if values['cleanup_until'] is None else _number(values['cleanup_until'])
        baseline, ticket, owned = (normalized[k] for k in ('baseline', 'interface_intent', 'owned'))
        phase = values['phase']
        if phase in _ACTIVE_PHASES:
            index = _ACTIVE_PHASES.index(phase)
            if values['generation'] != index or normalized['cleanup_until'] is not None or normalized['restored'] is not None:
                _fail('invalid_record')
            needs = {'baseline': True, 'watchdog': index >= 1, 'interface_intent': index >= 4,
                'owned': index >= 5, 'controller': index >= 6, 'group_add': index >= 9, 'group_observed': index >= 10}
            if any((normalized[k] is not None) != needed for k, needed in needs.items()): _fail('invalid_record')
            for role, first in (('watchdog', 1), ('controller', 6)):
                item = normalized[role]
                if item is not None and item.phase != ('intent' if index == first else 'preexec' if index == first + 1 else 'live'):
                    _fail('invalid_record')
        elif baseline is None or normalized['cleanup_until'] is None or \
                (phase == 'reconciled') != (normalized['restored'] is not None) or values['generation'] < 1:
            _fail('invalid_record')
        if ticket is not None and (ticket.boot != values['boot_id'] or baseline is None or \
                ticket.phy != baseline.station.phy): _fail('invalid_record')
        if owned is not None and (ticket is None or owned.iftype != 8 or \
                (owned.phy, owned.name) != (ticket.phy, ticket.name)): _fail('invalid_record')
        if normalized['controller'] is not None and owned is None: _fail('invalid_record')
        if normalized['group_add'] is not None and (normalized['controller'] is None or normalized['watchdog'] is None or \
                normalized['controller'].phase != 'live' or normalized['watchdog'].phase != 'live' or \
                dict(normalized['group_add'])['frequency'] != baseline.station_frequency): _fail('invalid_record')
        if normalized['group_observed'] is not None:
            group = dict(normalized['group_observed'])
            if normalized['group_add'] is None or group['frequency'] != dict(normalized['group_add'])['frequency'] or \
                    group['observed_origin'].key()[:4] != owned.key()[:4]: _fail('invalid_record')
        if normalized['restored'] is not None and (baseline is None or normalized['restored'].key() != baseline.key()):
            _fail('invalid_record')
        for name in _KEYS:
            value = normalized[name] if name in normalized else issued if name == 'issued_at' else until if name == 'until' else values[name]
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('private immutable GO facts')
    def __repr__(self): return '<private persisted GO bootstrap facts; not continuing permission>'
    def data(self):
        result = {name: getattr(self, name) for name in _KEYS}
        for k in ('baseline', 'restored'): result[k] = None if getattr(self, k) is None else facts._snapshot_tree(getattr(self, k))
        for k in ('watchdog', 'controller'): result[k] = None if getattr(self, k) is None else getattr(self, k).data()
        result['interface_intent'] = None if self.interface_intent is None else facts._iticket_tree(self.interface_intent)
        result['owned'] = None if self.owned is None else facts._origin_tree(self.owned)
        for k in ('group_add', 'group_observed'): result[k] = _group_data(getattr(self, k))
        return result
    def facts_key(self):
        return (self.schema, self.run_token, self.candidate_sha, self.task_id,
                self.boot_id, self.issued_at, self.until)
    def key(self): return self.facts_key() + (self.phase, self.generation,
        None if self.baseline is None else self.baseline.key(),
        None if self.interface_intent is None else self.interface_intent.key(),
        None if self.owned is None else self.owned.key(),
        None if self.watchdog is None else self.watchdog.key(),
        None if self.controller is None else self.controller.key(), self.group_add,
        None if self.group_observed is None else (dict(self.group_observed)['frequency'],
            dict(self.group_observed)['event_sha256'], dict(self.group_observed)['status_sha256'],
            dict(self.group_observed)['observed_origin'].key()), self.cleanup_until,
        None if self.restored is None else self.restored.key())
    @property
    def rf_requested(self): return self.interface_intent is not None


def encode(record):
    if type(record) is not GoRecord: _fail('invalid_record')
    raw = json.dumps(record.data(), ensure_ascii=True, sort_keys=True).encode('ascii')
    if len(raw) > MAX_RECORD: _fail('invalid_record')
    return raw


def decode(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RECORD: _fail('invalid_record')
    try: record = GoRecord(json.loads(raw.decode('ascii')))
    except (ValueError, TypeError, UnicodeError, KeyError): _fail('invalid_record')
    if encode(record) != raw: _fail('noncanonical_record')
    return record


class GoCanonical(object):
    __slots__ = ('issuer', 'record', 'raw', 'metadata')
    def __init__(self, issuer, record, raw, metadata):
        for key, value in (('issuer', issuer), ('record', record), ('raw', raw), ('metadata', metadata)):
            object.__setattr__(self, key, value)
    def __setattr__(self, *unused): raise AttributeError('private immutable original GO readback')
    def __repr__(self): return '<private original GO journal readback>'


class GoChildIntent(object):
    """Original same-store launch intent issued AFTER durable native CAS.

    This is not encoded in JSON and is not a standalone caller capability.
    The fixed Loader additionally consumes the actual store/device OFD and
    this original object in the Store's strong issuance inventory.
    """
    __slots__ = ('store', 'owner', 'role', 'device_fd', 'canonical', 'spec', 'until', 'issuer')
    def __init__(self, store, role, canonical, spec):
        for k, v in (('store', store), ('owner', store.owner), ('role', role),
                ('device_fd', store.device.fd), ('canonical', canonical),
                ('spec', spec), ('until', store.until), ('issuer', store.issuer)):
            object.__setattr__(self, k, v)
    def __setattr__(self, *unused): raise AttributeError('private original durable launch intent')
    def __repr__(self): return '<private original durable GO child intent>'


def _field_key(record, name):
    value = getattr(record, name)
    if name == 'group_observed' and value is not None:
        row = dict(value)
        return (row['frequency'], row['event_sha256'], row['status_sha256'], row['observed_origin'].key())
    return value.key() if value is not None and name in (
        'baseline', 'restored', 'interface_intent', 'owned', 'watchdog', 'controller') else value


class _Fd(object):
    def __init__(self, role):
        self.role, self.fd, self.metadata = role, None, None
        self.returned = self.attempted = self.closed = False
        self.unknown = True
    def __repr__(self): return '<private GO original FD ticket>'


class _LinuxIo(object):
    """Fixed native file operations only. No constructor syscall or RF API."""
    def __init__(self): self.library = None
    def validate(self):
        if sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or os.uname()[4] != 'armv7l' or \
                getattr(os, 'O_NOFOLLOW', None) != 0x8000 or getattr(os, 'O_CLOEXEC', None) != 0x80000 or \
                getattr(os, 'O_DIRECTORY', None) != 0x4000:
            _fail('unsupported_platform')
        if os.stat not in getattr(os, 'supports_dir_fd', ()) or os.stat not in getattr(os, 'supports_follow_symlinks', ()):
            _fail('unsupported_fixed_stat')
    def pid(self): return os.getpid()
    def flags(self, *names):
        result = 0
        for name in names:
            value = getattr(os, name, None)
            if not _uint(value, 0, 0x7fffffff): _fail('unsupported_flags')
            result |= value
        return result
    def _libc(self):
        if self.library is None:
            value = ctypes.CDLL(None, use_errno=True)
            value.openat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint)
            value.openat.restype = ctypes.c_int
            # Mechanical reuse of existing FILES' actual renameat ABI, not its
            # CLIENT schema/canonical issuer. P011 need not expose os.rename fd.
            value.renameat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p)
            value.renameat.restype = ctypes.c_int
            value.unlinkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
            value.unlinkat.restype = ctypes.c_int
            value.flock.argtypes = (ctypes.c_int, ctypes.c_int); value.flock.restype = ctypes.c_int
            self.library = value
        return self.library
    def open_root(self, flags): return os.open('/', flags)
    def open_path(self, path, flags): return os.open(path, flags)
    def open_at(self, parent, name, flags, mode=0):
        if os.open in getattr(os, 'supports_dir_fd', ()):
            return os.open(name, flags, mode, dir_fd=parent)
        result = self._libc().openat(parent, name.encode('ascii'), flags, mode)
        if result < 0: raise OSError(ctypes.get_errno(), 'GO fixed open failure')
        return result
    def stat_root(self): return os.stat('/', follow_symlinks=False)
    def stat_path(self, path): return os.stat(path, follow_symlinks=False)
    def stat_at(self, parent, name): return os.stat(name, dir_fd=parent, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, raw): return os.write(fd, raw)
    def fsync(self, fd): return os.fsync(fd)
    def close(self, fd): return os.close(fd)
    def rename_at(self, parent, source, destination):
        if destination != JOURNAL or re.fullmatch('go-journal\\.[0-9]{2}\\.tmp', source) is None: _fail('fixed_name_required')
        ctypes.set_errno(0)
        result = self._libc().renameat(parent, source.encode('ascii'), parent, destination.encode('ascii'))
        if result != 0: raise OSError(ctypes.get_errno(), 'GO fixed rename failure')
    def unlink_at(self, parent, name):
        if name != GLOBAL_PENDING: _fail('fixed_name_required')
        ctypes.set_errno(0)
        result = self._libc().unlinkat(parent, name.encode('ascii'), 0)
        if result != 0: raise OSError(ctypes.get_errno(), 'GO fixed unlink failure')
    def flock(self, fd):
        ctypes.set_errno(0); result = self._libc().flock(fd, 2 | 4)
        return result, ctypes.get_errno()
    def pause(self, seconds): return time.sleep(seconds)


class GoBootstrapStore(object):
    """Actual original GO marker/OFD/journal and native producer transitions.

    No default mutation entry. _io/_clock are trusted internal HOST seams,
    never RF authorization. Existing fixed directories only. Unknown durable
    publication retains pending; it cannot be rebased or silently retried.
    RF and closure methods require the fixed native producers, not JSON facts.
    """
    def __init__(self, deployment, until, _io=None, _clock=None):
        if type(deployment) is not sources.LoadedGoDeployment: _fail('invalid_config')
        deployment.loader.authenticate(deployment)
        manifest = deployment.manifest
        if _number(until) != deployment.loader.original_until: _fail('original_until_invalid')
        self.deployment = self._deployment = deployment
        self.run_token, self.candidate_sha, self.task_id = manifest.run_token, manifest.candidate_sha, manifest.task_id
        self.until = self._original_until = _number(until)
        self.io = self._original_io = _io if _io is not None else _LinuxIo()
        self.clock = self._original_clock = _clock if _clock is not None else deployment.loader.clock
        self.mutex, self.worker, self.issuer = threading.RLock(), threading.current_thread(), object()
        self._mutex, self._worker, self._issuer = self.mutex, self.worker, self.issuer
        self.owner, self.pid, self.last, self.scope_until = None, None, None, None
        self._scope_original, self._cleanup_scope = None, False
        self.rows, self.anchors = [], []
        self._original_rows, self._fd_history, self._fd_attempts = self.rows, (), 0
        self._native_original = self._launcher_original = None
        self.device = self.journal_lock = self.tmp = self.run = None
        self.current = self.marker_raw = self.marker_metadata = self.boot_id = None
        self._canonical_history = ()
        self.attempted = self.restore_attempted = False
        self.publication_unknown = self.observation_failed = False
        self.marker_cleared = self.logical_restored = False
        self.failure, self.restore_failure = None, None
        self.restore_until, self._temporary = None, 0
        self._restore_until_original = None
        self._calls, self._launch_reads, self._child_intents = set(), set(), {}
        self._scope_open_start = self._scope_open_limit = None
        self._publication_counts = {'prepare': 0, 'positive': 0, 'cleanup': 0}
        self._close_called = False
    def __repr__(self): return '<private native durable GO bootstrap store; not ready>'

    def bind(self, owner):
        module = self.deployment.modules['mta_go_bootstrap']
        if type(owner) is not module.GoBootstrap or owner.store is not self or \
                owner.deployment is not self.deployment or self.owner is not None or self.attempted or \
                owner.entry.clock is not self.clock or owner.entry.until != self.until:
            _fail('wrong_owner')
        self.owner = self._original_owner = owner

    def bind_native(self, native):
        """Pure original producer binding, before this Store's first file IO."""
        self._owner()
        module = self.deployment.modules['mta_go_native']
        if self._native_original is not None or self.attempted or self._fd_attempts or \
                type(native) is not module.NativeGoResources or self.owner.native is not native or \
                native.owner is not self.owner or native.store is not self or native.deployment is not self.deployment or \
                native.until != self.until or native.worker is not self.worker or native.mutex is not self.mutex or \
                native.clock is not self.clock:
            _fail('native_source_changed')
        self._native_original = native
        return native

    def bind_launcher(self, launcher):
        """Pure original fixed-launcher binding; no launch or RF permission."""
        self._owner()
        module = self.deployment.modules['mta_go_process_owner']
        if self._launcher_original is not None or self._child_intents or self._launch_reads or \
                type(launcher) is not module.GoDirectChildOwner or self.owner.launcher is not launcher or \
                self.deployment.loader.launcher is not launcher or launcher.deployment is not self.deployment or \
                launcher.entry is not self.owner.entry or launcher._tickets:
            _fail('launcher_source_changed')
        module.GoDirectChildOwner._go_context(launcher)
        self._launcher_original = launcher
        return launcher

    def _now(self, check=True):
        value = _number(self.clock())
        if self.last is not None and value < self.last: _fail('clock_regressed')
        self.last = value
        if check:
            if self.scope_until is None or self.scope_until != self._scope_original or \
                    (self._cleanup_scope and self.scope_until != self._restore_until_original) or \
                    (not self._cleanup_scope and self.scope_until > self._original_until): _fail('scope_changed')
            if value >= self.scope_until: _fail('deadline')
        return value

    def _set_scope(self, end, cleanup=False):
        self.scope_until = self._scope_original = _number(end)
        self._cleanup_scope = cleanup

    def _owner(self):
        self.deployment.loader.authenticate(self.deployment)
        module = self.deployment.modules['mta_go_bootstrap']
        if type(self.owner) is not module.GoBootstrap or self.owner is not self._original_owner or \
                self.owner.store is not self or self.owner.deployment is not self._deployment or \
                self.deployment is not self._deployment or self.until != self._original_until or \
                (self.run_token, self.candidate_sha, self.task_id) != (self.deployment.manifest.run_token,
                    self.deployment.manifest.candidate_sha, self.deployment.manifest.task_id) or \
                self.io is not self._original_io or self.clock is not self._original_clock or \
                self.mutex is not self._mutex or self.worker is not self._worker or self.issuer is not self._issuer or \
                self.rows is not self._original_rows or len(self.rows) != self._fd_attempts or \
                len(self._fd_history) != self._fd_attempts or any(a is not b for a, b in zip(self.rows, self._fd_history)) or \
                self.current is not None and (type(self.current) is not GoCanonical or not self._canonical_history or
                    self.current is not self._canonical_history[-1] or self.current.issuer is not self.issuer) or \
                self.restore_until != self._restore_until_original or \
                self.owner.entry.clock is not self.clock or self.owner.entry.until != self.until or \
                threading.current_thread() is not self.worker or self.worker is not self.deployment.worker or \
                self.pid is not None and self.io.pid() != self.pid:
            _fail('wrong_owner')
        self.owner.entry._context()

    def _open(self, role, parent=None, name=None, path=None, flags=None, mode=0):
        self._now()
        if self._fd_attempts >= MAX_FDS or self._fd_attempts >= _STORE_OPEN_BOUND or \
                self._scope_open_start is not None and self._fd_attempts - self._scope_open_start >= self._scope_open_limit:
            _fail('fd_budget')
        row = _Fd(role); self.rows.append(row)  # BEFORE original creation call.
        self._fd_history += (row,)
        self._fd_attempts += 1
        try:
            fd = self.io.open_path(path, flags) if path is not None else self.io.open_root(flags) if parent is None else self.io.open_at(parent, name, flags, mode)
            row.fd, row.returned = fd, True
            if not _uint(fd, 0, 0x7fffffff) or any(other is not row and other.fd == fd and not other.closed for other in self.rows):
                _fail('fd_unknown')
            row.metadata = _meta(self.io.fstat(fd)); row.unknown = False
            self._now()
            return row
        except OSError as error:
            if not row.returned and type(error.errno) is int and 1 <= error.errno <= 4095:
                row.unknown, row.closed = False, True  # Known negative native open.
            raise

    def _close(self, row):
        if row.attempted or row.closed: return
        if row.unknown or row.metadata is None: return
        # Physical close facts are independent of a late/failed observation.
        # No renewed activity cap, no numeric-FD retry or borrowed-FD close.
        try:
            if _meta(self.io.fstat(row.fd))[:6] != row.metadata[:6]: row.unknown = True; return
        except BaseException: row.unknown = True; return
        row.attempted = True
        result = error = None
        try: result = self.io.close(row.fd)
        except BaseException as value: error = value
        try: self.io.fstat(row.fd)
        except OSError as value:
            row.closed = error is None and result is None and type(value.errno) is int and value.errno == errno.EBADF
        except BaseException: pass

    def _directory(self, value, expected=None):
        row = _meta(value)
        if not stat.S_ISDIR(row[2]) or row[3:5] != (0, 0) or \
                expected is None and row[2] & 0o022 or expected is not None and stat.S_IMODE(row[2]) != expected:
            _fail('unsafe_directory')
        return row[:5]

    def _alias(self):
        paths = (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp'))
        before = []
        for path, target in paths:
            self._now(); row = _meta(self.io.stat_path(path))
            if row[2] != stat.S_IFLNK | 0o777 or row[3:6] != (0, 0, 1) or row[6] != len(target) or self.io.readlink(path) != target:
                _fail('fixed_alias_changed')
            before.append(row)
        for (path, target), previous in zip(paths, before):
            self._now()
            if _meta(self.io.stat_path(path)) != previous or self.io.readlink(path) != target: _fail('fixed_alias_changed')

    def _directories(self):
        flags = self.io.flags('O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC')
        for name, mode in ((None, None), ('var', 0o755), ('volatile', 0o1777), ('tmp', 0o1777),
                           (BASE, 0o700), (RUN_PREFIX + self.run_token, 0o700)):
            parent = None if not self.anchors else self.anchors[-1][0]
            before = self._directory(self.io.stat_root() if parent is None else self.io.stat_at(parent.fd, name), mode)
            row = self._open('directory', parent=None if parent is None else parent.fd, name=name, flags=flags)
            if self._directory(self.io.fstat(row.fd), mode) != before: _fail('directory_changed')
            self.anchors.append((row, parent, name, before, mode))
        self.tmp, self.run = self.anchors[3][0], self.anchors[-1][0]
        self._alias(); self._anchors()

    def _anchors(self):
        for row, parent, name, metadata, mode in self.anchors:
            self._now()
            if row.closed or row.unknown or self._directory(self.io.fstat(row.fd), mode) != metadata or \
                    self._directory(self.io.stat_root() if parent is None else self.io.stat_at(parent.fd, name), mode) != metadata:
                _fail('directory_changed')
        self._alias()

    def _absent(self, parent, name):
        self._now()
        try: self.io.stat_at(parent.fd, name)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT: return
            raise
        _fail('entry_already_exists')

    def _lock(self, parent, name):
        before = None
        try: before = _file(self.io.stat_at(parent.fd, name))
        except OSError as error:
            if type(error.errno) is not int or error.errno != errno.ENOENT: raise
        flags = self.io.flags('O_RDWR', 'O_NONBLOCK', 'O_NOFOLLOW', 'O_CLOEXEC')
        if before is None: flags |= self.io.flags('O_CREAT', 'O_EXCL')
        row = self._open('lock', parent=parent.fd, name=name, flags=flags, mode=0o600 if before is None else 0)
        current = _file(self.io.fstat(row.fd))
        if before is not None and before[:6] != current[:6] or _file(self.io.stat_at(parent.fd, name))[:6] != current[:6]:
            _fail('lock_changed')
        row.parent, row.name = parent, name
        self._lock_current(row)
        return row

    def _lock_current(self, row):
        self._now()
        if row is None or row.closed or row.attempted or row.unknown or \
                _file(self.io.fstat(row.fd))[:6] != row.metadata[:6] or \
                _file(self.io.stat_at(row.parent.fd, row.name))[:6] != row.metadata[:6]:
            _fail('lock_changed')
        while True:
            self._now(); result = self.io.flock(row.fd); self._now()
            if type(result) is not tuple or len(result) != 2 or any(type(v) is not int for v in result): _fail('flock_unknown')
            if result == (0, 0): return
            if result[0] != -1 or result[1] not in (errno.EINTR, errno.EAGAIN, errno.EWOULDBLOCK): _fail('flock_unknown')
            self.io.pause(0.01)

    def _read(self, parent, name):
        before = _file(self.io.stat_at(parent.fd, name))
        row = self._open('read', parent=parent.fd, name=name, flags=self.io.flags('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))
        try:
            if _file(self.io.fstat(row.fd)) != before: _fail('file_changed')
            raw = b''
            while True:
                self._now(); requested = min(4096, before[6] + 1 - len(raw))
                part = self.io.read(row.fd, requested)
                if type(part) is not bytes or len(part) > requested: _fail('invalid_read')
                raw += part
                if len(raw) > before[6]: _fail('file_changed')
                if not part: break
            if len(raw) != before[6] or _file(self.io.fstat(row.fd)) != before or _file(self.io.stat_at(parent.fd, name)) != before:
                _fail('file_changed')
            self._now()
            return raw, before
        finally:
            self._close(row)
            if not row.closed: _fail('close_unknown')

    def _boot_read(self):
        row = self._open('boot', path='/proc/sys/kernel/random/boot_id', flags=self.io.flags('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC'))
        try:
            if not stat.S_ISREG(row.metadata[2]) or row.metadata[3:6] != (0, 0, 1) or row.metadata[2] & 0o022:
                _fail('boot_unknown')
            raw = self.io.read(row.fd, 65); self._now()
            if type(raw) is not bytes or len(raw) != 37 or raw[-1:] != b'\n' or not _boot(raw[:-1].decode('ascii')):
                _fail('boot_unknown')
            if _meta(self.io.fstat(row.fd))[:6] != row.metadata[:6]: _fail('boot_changed')
            return raw[:-1].decode('ascii')
        finally:
            self._close(row)
            if not row.closed: _fail('close_unknown')

    def _sync(self, fd):
        self._now()
        if self.io.fsync(fd) is not None: _fail('fsync_unknown')
        self._now()  # EINVAL/EBADF/late never count as durable publication.

    def _new_file(self, parent, name, raw):
        row = self._open('write', parent=parent.fd, name=name,
            flags=self.io.flags('O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_CLOEXEC'), mode=0o600)
        try:
            created = _file(self.io.fstat(row.fd))
            if created[6] != 0: _fail('file_changed')
            at = 0
            while at < len(raw):
                self._now(); chunk = raw[at:at + 4096]; count = self.io.write(row.fd, chunk)
                if not _uint(count, 1, len(chunk)): _fail('short_write_unknown')
                at += count
            self._sync(row.fd)
            written = _file(self.io.fstat(row.fd))
            if written[:6] != created[:6] or written[6] != len(raw) or _file(self.io.stat_at(parent.fd, name)) != written:
                _fail('file_changed')
            return written
        finally:
            self._close(row)
            if not row.closed: _fail('close_unknown')

    def _fresh(self):
        self._owner(); self._anchors(); self._lock_current(self.device); self._lock_current(self.journal_lock)
        if self.marker_raw is not None:
            raw, metadata = self._read(self.tmp, GLOBAL_PENDING)
            if raw != self.marker_raw or metadata != self.marker_metadata: _fail('marker_changed')
        if self.current is not None:
            raw, metadata = self._read(self.run, JOURNAL)
            if raw != self.current.raw or metadata != self.current.metadata or decode(raw).key() != self.current.record.key():
                _fail('stale_current')

    def _save(self, record):
        if type(record) is not GoRecord or self.publication_unknown: _fail('publication_pending')
        previous = self.current
        if previous is not None:
            old = previous.record
            transitions = {phase: (('restore_intent',) if i == len(_ACTIVE_PHASES) - 1 else
                (_ACTIVE_PHASES[i + 1], 'restore_intent')) for i, phase in enumerate(_ACTIVE_PHASES)}
            transitions.update(restore_intent=('reconciled',), reconciled=())
            if previous.issuer is not self.issuer or record.facts_key() != old.facts_key() or \
                    record.phase not in transitions[old.phase] or record.generation != old.generation + 1:
                _fail('invalid_transition')
            changed = {'watchdog_intent': 'watchdog', 'watchdog_preexec': 'watchdog', 'watchdog_live': 'watchdog',
                'interface_intent': 'interface_intent', 'interface_owned': 'owned',
                'controller_intent': 'controller', 'controller_preexec': 'controller', 'controller_live': 'controller',
                'group_add_intent': 'group_add', 'group_started': 'group_observed',
                'restore_intent': 'cleanup_until', 'reconciled': 'restored'}[record.phase]
            for name in _KEYS - {'phase', 'generation', changed}:
                if _field_key(old, name) != _field_key(record, name): _fail('original_facts_changed')
            if changed in ('watchdog', 'controller') and getattr(old, changed) is not None:
                before, after = getattr(old, changed), getattr(record, changed)
                if before.source_key() != after.source_key() or \
                        before.actor is not None and (before.actor.pid, before.actor.start) != (after.actor.pid, after.actor.start):
                    _fail('original_child_changed')
        elif record.phase != 'reserved' or record.generation != 0: _fail('invalid_transition')
        category = 'cleanup' if record.phase in ('restore_intent', 'reconciled') else \
            'prepare' if record.phase in _ACTIVE_PHASES[:4] else 'positive'
        if self._temporary >= MAX_PUBLICATIONS or self._publication_counts[category] >= _PUBLICATION_LIMITS[category]:
            _fail('publication_limit')
        if self._scope_open_start is not None: _fail('nested_publication')
        # This original slot is consumed even if no temp rename is reached.
        # No later retry, readback, cleanup or closed-history retirement refunds it.
        self._temporary += 1
        self._publication_counts[category] += 1
        self._scope_open_start, self._scope_open_limit = self._fd_attempts, _PUBLICATION_OPEN_BOUND
        try:
            if self._boot_read() != self.boot_id: _fail('boot_changed')
            self._fresh()
            if previous is None: self._absent(self.run, JOURNAL)
            name, raw = 'go-journal.%02d.tmp' % self._temporary, encode(record)
            self.publication_unknown = True
            written = self._new_file(self.run, name, raw)
            self._fresh()
            if _file(self.io.stat_at(self.run.fd, name)) != written: _fail('file_changed')
            if self.io.rename_at(self.run.fd, name, JOURNAL) is not None: _fail('rename_unknown')
            self._sync(self.run.fd)
            observed, metadata = self._read(self.run, JOURNAL)
            if observed != raw or metadata[:7] != written[:7] or decode(observed).key() != record.key():
                _fail('publication_changed')
            self.current = GoCanonical(self.issuer, decode(observed), observed, metadata)
            self._canonical_history += (self.current,)
            self.publication_unknown = False
            return self.current
        finally:
            self._scope_open_start = self._scope_open_limit = None

    def _native(self):
        module = self.deployment.modules['mta_go_native']
        native = self.owner.native
        if type(native) is not module.NativeGoResources or native is not self._native_original or \
                native.owner is not self.owner or native.store is not self or native.deployment is not self.deployment or \
                native.until != self.until or native.worker is not self.worker or native.mutex is not self.mutex or \
                native.clock is not self.clock:
            _fail('native_source_changed')
        return module, native

    def _native_observation(self, kind, observation):
        module, native = self._native()
        classes = {'baseline': 'GoBaselineObservation', 'channel': 'GoChannelObservation',
            'group_source': 'GoGroupSource', 'group': 'GoGroupObservation', 'restore': 'GoNativeRestoreObservation'}
        method_names = {'baseline': 'baseline_current', 'channel': 'channel_current',
            'group_source': 'group_source_current', 'group': 'group_current', 'restore': 'restore_current'}
        expected = getattr(module, classes[kind])
        if type(observation) is not expected or observation.native is not native or \
                observation.owner is not self.owner or observation.until != self.until:
            _fail('native_source_changed')
        # Invoke the actual fixed definition, not a caller-replaced bound callback.
        result = getattr(module.NativeGoResources, method_names[kind])(
            native, observation, _absolute_deadline=self.scope_until)
        if result is not observation: _fail('native_source_not_original')
        return observation

    def _begin_stage(self, name, expected_phase):
        self._owner()
        if name in self._calls or self.restore_attempted or self._close_called or self.current is None or \
                self.current.issuer is not self.issuer or self.current.record.phase != expected_phase or \
                self.failure is not None or self.publication_unknown:
            _fail('stage_unavailable')
        self._calls.add(name)
        self._set_scope(min(self.until, self._now(False) + PREPARE_SECONDS))
        self._now()

    def _commit_phase(self, phase, **fields):
        values = self.current.record.data()
        values.update(fields)
        values.update(phase=phase, generation=self.current.record.generation + 1)
        return self._save(GoRecord(values))

    def _failed(self, error):
        self.failure, self.observation_failed = error, True

    def reserve(self, baseline_observation):
        with self.mutex:
            self._owner()
            if self.attempted: _fail('already_attempted')
            self.attempted = True
            issued = self._now(False)
            if not 0 < self.until - issued <= MAX_ACTIVE_SECONDS: _fail('original_until_invalid')
            self._set_scope(min(self.until, issued + PREPARE_SECONDS))
            try:
                self.io.validate(); self.pid = self.io.pid()
                if not _uint(self.pid, 1, 0x7fffffff): _fail('wrong_owner')
                self._directories(); self._absent(self.tmp, GLOBAL_PENDING)
                self.device = self._lock(self.tmp, DEVICE_LOCK)
                self._absent(self.tmp, GLOBAL_PENDING)
                self.journal_lock = self._lock(self.run, JOURNAL_LOCK)
                self._absent(self.tmp, GLOBAL_PENDING); self._absent(self.run, JOURNAL)
                self.boot_id = self._boot_read()
                observation = self._native_observation('baseline', baseline_observation)
                baseline = observation.snapshot
                if type(baseline) is not core.Snapshot or baseline.boot != self.boot_id or \
                        baseline.station_frequency not in range(2412, 2473, 5): _fail('baseline_unavailable')
                marker = {'schema': SCHEMA, 'run_token': self.run_token, 'candidate_sha': self.candidate_sha,
                    'task_id': self.task_id, 'boot_id': self.boot_id, 'issued_at': issued, 'until': self.until}
                raw = json.dumps(marker, ensure_ascii=True, sort_keys=True).encode('ascii')
                self.publication_unknown = True
                written = self._new_file(self.tmp, GLOBAL_PENDING, raw)
                self._sync(self.tmp.fd)
                current, metadata = self._read(self.tmp, GLOBAL_PENDING)
                if current != raw or metadata[:7] != written[:7]: _fail('marker_changed')
                self.marker_raw, self.marker_metadata = current, metadata
                self.publication_unknown = False
                record = GoRecord(dict(marker, phase='reserved', generation=0, baseline=baseline,
                    interface_intent=None, owned=None, watchdog=None, controller=None,
                    group_add=None, group_observed=None, cleanup_until=None, restored=None))
                result = self._save(record); self._now()
                return result
            except BaseException as error:
                self._failed(error)
                raise

    def prepare_child(self, role, baseline_observation=None):
        with self.mutex:
            if role not in ('watchdog', 'controller'): _fail('invalid_role')
            if self._launcher_original is None or self.owner.launcher is not self._launcher_original:
                _fail('launcher_source_changed')
            self._begin_stage(role + '_intent', 'reserved' if role == 'watchdog' else 'interface_owned')
            try:
                if role == 'watchdog':
                    observation = self._native_observation('baseline', baseline_observation)
                    if observation.snapshot.key() != self.current.record.baseline.key(): _fail('baseline_changed')
                elif baseline_observation is not None: _fail('invalid_input')
                spec = self.deployment.watchdog_spec if role == 'watchdog' else self.deployment.controller_spec
                launch = self.deployment.modules['mta_go_process_owner']
                if type(spec) is not launch.LaunchSpec or spec.role != role or \
                        not any(spec is item for item in self.deployment.specs): _fail('launch_source_changed')
                child = GoChildFacts({'phase': 'intent', 'spec_sha': spec.sha, 'argv_sha': spec.argv_sha,
                    'until': self.until, 'actor': None})
                canonical = self._commit_phase(role + '_intent', **{role: child.data()})
                receipt = GoChildIntent(self, role, canonical, spec)
                self._child_intents[role] = receipt
                return receipt
            except BaseException as error:
                self._failed(error)
                raise

    def launch_source_current(self, owner, role, device_fd, original_until):
        """Actual fixed Loader consumes this once, before registering a child."""
        with self.mutex:
            self._owner()
            if owner is not self.owner or role not in ('watchdog', 'controller') or role in self._launch_reads or \
                    original_until != self.until or self.current is None or self.restore_attempted or \
                    self._close_called or self.failure is not None or self.publication_unknown or \
                    self.current.record.phase != role + '_intent' or self.device is None or device_fd != self.device.fd:
                _fail('launch_source_unavailable')
            receipt = self._child_intents.get(role)
            if type(receipt) is not GoChildIntent or receipt.store is not self or receipt.owner is not owner or \
                    receipt.device_fd != device_fd or receipt.issuer is not self.issuer or \
                    receipt.until != self.until or receipt.canonical is not self.current or \
                    receipt.spec is not (self.deployment.watchdog_spec if role == 'watchdog' else self.deployment.controller_spec):
                _fail('original_child_intent_missing')
            self._launch_reads.add(role)
            self._set_scope(min(self.until, self._now(False) + PREPARE_SECONDS))
            try:
                if self._boot_read() != self.boot_id: _fail('boot_changed')
                self._fresh(); self._now()
                return receipt
            except BaseException as error:
                self._failed(error)
                raise

    def _child_source(self, ticket, actor, postexec):
        launch = self.deployment.modules['mta_go_process_owner']
        launcher = self.owner.launcher
        if type(launcher) is not launch.GoDirectChildOwner or launcher is not self._launcher_original or launcher.deployment is not self.deployment or \
                launcher is not self.deployment.loader.launcher or type(ticket) is not launch.ChildTicket or \
                ticket.owner is not launcher or not any(ticket is item for item in launcher._tickets):
            _fail('child_source_changed')
        launch.GoDirectChildOwner._exact(launcher, ticket)
        intent = self._child_intents.get(ticket.spec.role)
        if type(intent) is not GoChildIntent or ticket.spec is not intent.spec or ticket.original_device_fd != intent.device_fd or \
                ticket.deadline != self.until or type(actor) is not core.Actor or \
                actor is not (ticket.postexec if postexec else ticket.preexec) or actor.pid != ticket.pid or \
                ticket.boot != self.boot_id or ticket.unknown or not actor.live() or ticket.preexec is None or \
                (actor.pid, actor.start) != (ticket.preexec.pid, ticket.preexec.start) or \
                postexec and (not ticket.released or (actor.exe, actor.argv_sha) != (intent.spec.exe, intent.spec.argv_sha)):
            _fail('child_source_changed')
        proc = self.deployment.modules['mta_client_proc']
        if not any(type(row.observation) is proc.ProcObservation and row.observation.actor is actor and
                row.observation.kind == 'live_actor' and row.observation.boot == self.boot_id and
                row.observation.same_boot is True and type(row.observation.passes) is int and
                row.observation.passes == 2 and row.observation.resource_pending is False and
                launcher._reader.owns_generation(row) for row in launcher._reader._history):
            _fail('child_observation_not_original')
        return ticket.spec.role, intent

    def persist_preexec(self, ticket, original_actor):
        with self.mutex:
            role, intent = self._child_source(ticket, original_actor, False)
            self._begin_stage(role + '_preexec', role + '_intent')
            try:
                child = GoChildFacts({'phase': 'preexec', 'spec_sha': intent.spec.sha, 'argv_sha': intent.spec.argv_sha,
                    'until': self.until, 'actor': original_actor})
                return self._commit_phase(role + '_preexec', **{role: child.data()})
            except BaseException as error:
                self._failed(error)
                raise

    def confirm_actor(self, ticket, original_actor):
        with self.mutex:
            role, intent = self._child_source(ticket, original_actor, True)
            self._begin_stage(role + '_live', role + '_preexec')
            try:
                child = GoChildFacts({'phase': 'live', 'spec_sha': intent.spec.sha, 'argv_sha': intent.spec.argv_sha,
                    'until': self.until, 'actor': original_actor})
                return self._commit_phase(role + '_live', **{role: child.data()})
            except BaseException as error:
                self._failed(error)
                raise

    def prepare_interface(self, original_ticket, channel_observation):
        with self.mutex:
            self._begin_stage('interface_intent', 'watchdog_live')
            try:
                observation = self._native_observation('channel', channel_observation)
                module, native = self._native()
                ticket = module.NativeGoResources.interface_current(native, original_ticket,
                    _absolute_deadline=self.scope_until)
                if ticket is not original_ticket or type(ticket) is not core.InterfaceTicket or \
                        ticket is not native.interface_ticket or ticket.boot != self.boot_id or \
                        ticket.phy != self.current.record.baseline.station.phy or ticket.name != self.deployment.manifest.ifname or \
                        observation.frequency != self.current.record.baseline.station_frequency:
                    _fail('interface_source_changed')
                return self._commit_phase('interface_intent', interface_intent=facts._iticket_tree(ticket))
            except BaseException as error:
                self._failed(error)
                raise

    def confirm_interface(self, original_owned):
        with self.mutex:
            self._begin_stage('interface_owned', 'interface_intent')
            try:
                module, native = self._native()
                actual = module.NativeGoResources.origin_current(native, original_owned,
                    _absolute_deadline=self.scope_until)
                if actual is not original_owned or type(actual) is not core.Origin or actual is not native.owned or \
                        actual.iftype != 8 or (actual.phy, actual.name) != (
                            self.current.record.interface_intent.phy, self.current.record.interface_intent.name) or \
                        any(row.wdev == actual.wdev or row.ifindex == actual.ifindex or row.name == actual.name
                            for row in self.current.record.baseline.interfaces): _fail('interface_source_changed')
                return self._commit_phase('interface_owned', owned=facts._origin_tree(actual))
            except BaseException as error:
                self._failed(error)
                raise

    def prepare_group_add(self, group_source):
        """No caller requested frequency; only measured pinned native source."""
        with self.mutex:
            self._begin_stage('group_add_intent', 'controller_live')
            try:
                observation = self._native_observation('group_source', group_source)
                frequency = observation.frequency
                if type(frequency) is not int or frequency not in range(2412, 2473, 5) or \
                        frequency != self.current.record.baseline.station_frequency or \
                        not _hex(observation.channel_sha256, 64) or not _hex(observation.caps_sha256, 64):
                    _fail('group_source_changed')
                return self._commit_phase('group_add_intent', group_add={'frequency': frequency,
                    'command_sha256': hashlib.sha256(('P2P_GROUP_ADD freq=%d' % frequency).encode('ascii')).hexdigest(),
                    'channel_sha256': observation.channel_sha256, 'caps_sha256': observation.caps_sha256})
            except BaseException as error:
                self._failed(error)
                raise

    def confirm_group(self, group_observation):
        with self.mutex:
            self._begin_stage('group_started', 'group_add_intent')
            try:
                observation = self._native_observation('group', group_observation)
                if type(observation.event_raw) is not bytes or type(observation.status_raw) is not bytes or \
                        not 1 <= len(observation.event_raw) <= 8192 or not 1 <= len(observation.status_raw) <= 8192:
                    _fail('group_source_changed')
                return self._commit_phase('group_started', group_observed={'frequency': observation.frequency,
                    'event_sha256': hashlib.sha256(observation.event_raw).hexdigest(),
                    'status_sha256': hashlib.sha256(observation.status_raw).hexdigest(),
                    'observed_origin': facts._origin_tree(observation.observed_origin)})
            except BaseException as error:
                self._failed(error)
                raise

    def begin_restore(self, original_cleanup_until):
        """Once independent cleanup period; never renew original RF activity."""
        with self.mutex:
            self._owner()
            if self.restore_attempted: _fail('restore_already_attempted')
            self.restore_attempted = True
            try:
                now, end = self._now(False), _number(original_cleanup_until)
                if not 0 < end - now <= CLEANUP_SECONDS: _fail('cleanup_until_invalid')
                self.restore_until = self._restore_until_original = end
                self._set_scope(end, True)
                if self.current is None or self.publication_unknown or self._close_called:
                    _fail('publication_pending')
                return self._commit_phase('restore_intent', cleanup_until=end)
            except BaseException as error:
                self.restore_failure = error
                raise

    def _restore_source(self, observation):
        module = self.deployment.modules['mta_go_bootstrap']
        if type(observation) is not module.GoRestoreObservation or observation.owner is not self.owner or \
                observation.store is not self or observation is not self.owner.restore_observation or \
                observation.cleanup_until != self.restore_until:
            _fail('restore_source_changed')
        native = self._native_observation('restore', observation.native_observation)
        if type(native.snapshot) is not core.Snapshot or native.snapshot.key() != self.current.record.baseline.key():
            _fail('baseline_not_restored')
        launch = self.deployment.modules['mta_go_process_owner']
        launcher = self.owner.launcher
        if launcher is not self._launcher_original or launcher is None and self._child_intents:
            _fail('child_restore_pending')
        if launcher is not None:
            if type(launcher) is not launch.GoDirectChildOwner or launcher is not self.deployment.loader.launcher or \
                    launcher.deployment is not self.deployment: _fail('child_source_changed')
            for ticket in launcher._tickets:
                launch.GoDirectChildOwner._exact(launcher, ticket)
                if ticket.unknown or any(not row.closed or row.unknown for row in ticket.fds): _fail('child_restore_pending')
                if ticket.fork_requested and not ticket.fork_negative:
                    absence = ticket.exit_observation
                    proc = self.deployment.modules['mta_client_proc']
                    if not ticket.waited or not ticket.exit_verified or type(absence) is not proc.ProcObservation or \
                            absence.kind != 'absence' or absence.boot != self.boot_id or absence.same_boot is not True or \
                            type(absence.passes) is not int or absence.passes != 2 or absence.resource_pending is not False or \
                            absence.pid_path_absent is not True or absence.remaining_tasks != () or not any(
                                row.observation is absence and launcher._reader.owns_generation(row)
                                for row in launcher._reader._history): _fail('child_restore_pending')
            for role in ('watchdog', 'controller'):
                persisted = getattr(self.current.record, role)
                if persisted is not None and persisted.actor is not None and not any(
                        t.spec.role == role and t.preexec is not None and
                        (t.preexec.pid, t.preexec.start) == (persisted.actor.pid, persisted.actor.start)
                        for t in launcher._tickets): _fail('child_restore_pending')
        native_module, native_owner = self._native()
        closed = native_module.NativeGoResources.closed_facts(native_owner)
        if type(closed) is not tuple or any(type(row) is not tuple or len(row) != 2 or \
                any(type(v) is not bool for v in row) or not all(row) for row in closed): _fail('native_restore_pending')
        return native.snapshot

    def _preclear_inventory(self):
        """No FS producer still in flight; only exact original 6dir+2lock.

        Pure inventory checks followed by original inode/path/OFD checks. No
        new FD, retirement, numeric-FD close or borrowed resource admission.
        Unknown/failed historical opens still block marker deletion even when
        later network observations and a reconciled Journal succeeded.
        """
        self._owner(); self._now()
        if self._scope_open_start is not None or self._scope_open_limit is not None or self._close_called or \
                len(self.anchors) != 6 or self.device is None or self.journal_lock is None:
            _fail('fs_restore_pending')
        directories = tuple(row[0] for row in self.anchors)
        held = directories + (self.device, self.journal_lock)
        if any(type(row) is not _Fd for row in held) or len({id(row) for row in held}) != 8 or \
                any(not any(row is original for original in self._fd_history) for row in held) or \
                any(row.role != 'directory' for row in directories) or \
                self.device.role != 'lock' or self.journal_lock.role != 'lock' or \
                self.device.parent is not self.tmp or self.device.name != DEVICE_LOCK or \
                self.journal_lock.parent is not self.run or self.journal_lock.name != JOURNAL_LOCK:
            _fail('fs_restore_pending')
        for row in self._fd_history:
            if any(row is anchor for anchor in held):
                if row.closed or row.attempted or row.unknown or not row.returned or row.metadata is None:
                    _fail('fs_restore_pending')
            elif not row.closed or row.unknown:
                _fail('fs_restore_pending')
        self._anchors()
        self._lock_current(self.device); self._lock_current(self.journal_lock)
        self._now()

    def finish_restore(self, original_restore_observation):
        """Only full actual native restore plus child/socket closure clears RF pending."""
        with self.mutex:
            self._owner()
            if 'finish_restore' in self._calls or not self.restore_attempted or self.restore_until is None or \
                    self.current is None or self.current.record.phase != 'restore_intent' or self.publication_unknown or self._close_called:
                _fail('restore_unavailable')
            self._calls.add('finish_restore')
            self._set_scope(self.restore_until, True)
            try:
                self._now()
                restored = self._restore_source(original_restore_observation)
                result = self._commit_phase('reconciled', restored=facts._snapshot_tree(restored))
                if self._boot_read() != self.boot_id: _fail('boot_changed')
                self._fresh()
                self._preclear_inventory()
                if self.io.unlink_at(self.tmp.fd, GLOBAL_PENDING) is not None: _fail('unlink_unknown')
                self._sync(self.tmp.fd); self._absent(self.tmp, GLOBAL_PENDING)
                self.marker_cleared = True
            except BaseException as error:
                self.restore_failure = error
                raise
            finally:
                self._close_inventory_once()
            try:
                self._now()  # Late closure facts survive, but cannot issue complete restored.
                if not self.marker_cleared or not all(a and c for a, c in self.closed_facts()):
                    _fail('fs_close_pending')
                self.logical_restored = True
                return result
            except BaseException as error:
                self.restore_failure = error
                raise

    def _close_inventory_once(self):
        if self._close_called: return
        self._close_called = True
        # Device OFD last. Observation errors do not erase actual close+EBADF;
        # unknown original FDs remain retained and never retried by number.
        for row in reversed(self._fd_history):
            if row is not self.device: self._close(row)
        if self.device is not None: self._close(self.device)

    def close_pending(self):
        """Close known original local FS resources ONCE; never clears pending."""
        with self.mutex:
            self._owner()
            self._close_inventory_once()
            return self.closed_facts()

    def closed_facts(self):
        """Actual local FS inventory tuples, not GO network restore permission."""
        return tuple((row.attempted or row.closed, row.closed and not row.unknown) for row in self._fd_history)

    def status(self):
        return {'phase': None if self.current is None else self.current.record.phase,
            'original_until': self.until, 'restore_called': self.restore_attempted,
            'reservation_marker_cleared': self.marker_cleared,
            'journal_and_marker_reconciled': self.logical_restored,
            'native_restore_reconciled': self.logical_restored and all(a and c for a, c in self.closed_facts()),
            'fd_inventory_count': self._fd_attempts,
            'fd_pending_count': sum(not row.closed or row.unknown for row in self._fd_history),
            'publication_unknown': self.publication_unknown,
            'publication_attempt_count': self._temporary,
            'prepare_publications': self._publication_counts['prepare'],
            'positive_publications': self._publication_counts['positive'],
            'cleanup_publications': self._publication_counts['cleanup'],
            'rf_intent_persisted': self.current is not None and self.current.record.rf_requested,
            'native_rf_bootstrap_implemented': False, 'go_ready': False,
            'ip_ready': False, 'dhcp_ready': False, 'send_available': False,
            'receive_available': False, 'stock_restore_verified': False,
            'device_tested': False, 'phone_tested': False}
