"""Pinned HOST Linux isolated durable Store B check, never a P011 entry.

Default source-only. Explicit reviewed execution preserves fixture/journal.
Actual local file/lock/proc calls; stock/network and restore producer synthetic.
No process launch, sockets, RF, or access to the real global pending namespace.
"""
import argparse
import ast
import builtins
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
import traceback
import types

BASE = Path(__file__).absolute().parents[1]
PINS = (
    ('mta_ip', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('p011_json', 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_p2p_client_init', 'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1'),
    ('mta_client_proc', '2f0ef52379be897d47b5cb311ef90f24b5c8a2c283e72780f139a8dd77626591'),
    ('mta_client_journal_codec', '17d362826a90da7fe9d77a82495a34bbc56b4c67aaca608aa5565ee1d3369f73'),
    ('mta_client_coordination', 'ea2f27c6920b4dd2cf47e5f71015382bd08dba65ed7eba9927c16f9a219b408d'),
    ('mta_client_files', 'd95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3'),
    ('mta_client_pending', 'edd6553b847db6dc8e5d2be48256b8e3ee706adca25cbda316bcf28f357ff7cf'),
    ('mta_client_store', 'c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd'))
REFERENCES = (
    ('tests/test_durable_client_store.py', 'c5adeee34196d496f79587ec8662574054ab38b52c04e04aaeca9dfc1f97f1b2'),
    ('docs/DURABLE_CLIENT_STORE_REVIEW.md', '54698c8c66b45b74755248ba241b4754dd708384bbcd27c46913c4d46c97b284'))
MAX_SOURCE = 262144
CODES = frozenset(('source_pin', 'source_shape', 'source_changed', 'reviewed_pin',
    'unsupported_platform', 'unsupported_io', 'already_attempted', 'directory_changed',
    'invalid_descriptor', 'open_unknown', 'close_unknown', 'proc_unknown',
    'actor_changed', 'readback_failed', 'handoff_failed', 'terminal_failed',
    'marker_absence_unknown', 'component_unknown', 'device_last_unknown',
    'producer_unknown', 'io_error', 'interrupted', 'unexpected', 'result_output'))
_EXECUTIONS = []  # Actual once-only owners retained, including unknown resources.


class CheckError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in CODES else 'unexpected'
        ValueError.__init__(self, self.code)


def fail(code):
    raise CheckError(code) from None


def _source(path, pin=None):
    if any(p.is_symlink() for p in (path,) + tuple(path.parents)): fail('source_shape')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_SOURCE: fail('source_shape')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno()); data = handle.read(MAX_SOURCE + 1)
    after = path.stat()
    for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns'):
        if getattr(before, key) != getattr(opened, key) or getattr(before, key) != getattr(after, key): fail('source_changed')
    if len(data) != before.st_size or pin is not None and hashlib.sha256(data).hexdigest() != pin: fail('source_pin')
    return data


def source_check():
    sources = tuple((name, _source(BASE / 'runtime' / (name + '.py'), pin)) for name, pin in PINS)
    for path, pin in REFERENCES: _source(BASE / path, pin)
    own = _source(Path(__file__).absolute())
    for data in (own,) + tuple(data for _, data in sources): ast.parse(data.decode('utf-8'), feature_version=(3, 5))
    return {'source_check_pass': True, 'checker_sha256': hashlib.sha256(own).hexdigest(),
        'source_sha256': dict(PINS), 'reference_sha256': dict(REFERENCES),
        'evidence': 'HOST_SOURCE_ONLY', 'production_provider': False,
        'p011_tested': False, 'phone_tested': False}, sources


def _load(sources):
    loaded, names, original = {}, set(name for name, _ in PINS), builtins.__import__
    if tuple(name for name, _ in sources) != tuple(name for name, _ in PINS): fail('source_shape')
    def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in names:
            if level or name not in loaded: fail('source_shape')
            return loaded[name]
        if name.startswith('mta_') or name.startswith('p011_') or level: fail('source_shape')
        return original(name, globals, locals, fromlist, level)
    for name, data in sources:
        module = types.ModuleType(name); module.__file__ = '<pinned-host-durable-client-store>'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
        exec(compile(data, module.__file__, 'exec'), module.__dict__)
        loaded[name] = module
    return loaded


def _uint(value):
    return type(value) is int and 0 <= value <= 0x7fffffff


def synthetic(modules, boot):
    """Actual boot; all stock/network/interface/process-ticket facts synthetic."""
    core, ip = modules['mta_p2p_client_init'], modules['mta_ip']
    identity = core.Identity(hashlib.sha256(b'HOST_DURABLE_CLIENT_STORE_SYNTHETIC_V1').hexdigest())
    actors = tuple(core.Actor(n, 100, path, '1' * 64, ((n, 100, 'S'),))
        for n, path in enumerate(('/usr/bin/Z03', '/usr/bin/control_engine', '/usr/bin/weston'), 101))
    station = core.Origin(0, 1, 1, 'wlan0', 2)
    ipv4 = ip.IpSnapshot((), (), tuple(ip.RuleRecord(p, t) for p, t in ((0, 255), (32766, 254), (32767, 253))))
    baseline = core.Snapshot(boot, core.STOCK_PINS, actors, station, '2' * 64, 2412, (station,), ipv4, (), (), True)
    owned = core.Origin(0, 2, 2, 'mta12345678', 8)
    interface = core.InterfaceTicket(boot, 0, owned.name, 1, 1)
    watch = core.Ticket('1' * 32, 'watchdog', boot, '/HOST/synthetic-watchdog', '3' * 64)
    ctrl = core.Ticket('2' * 32, 'controller', boot, '/HOST/synthetic-controller', '4' * 64)
    watch_actor = core.Actor(201, 100, watch.exe, watch.argv_sha, ((201, 100, 'S'),))
    ctrl_actor = core.Actor(202, 100, ctrl.exe, ctrl.argv_sha, ((202, 100, 'S'),))
    changes = (dict(stage='watchdog_intent', watchdog_ticket=watch),
        dict(stage='watchdog_saved', watchdog=watch_actor),
        dict(stage='interface_intent', interface_ticket=interface),
        dict(stage='interface_owned', owned=owned),
        dict(stage='controller_intent', controller_ticket=ctrl),
        dict(stage='controller_saved', controller=ctrl_actor),
        dict(stage='client_init_ready', ready=True))
    return identity, baseline, changes


class SyntheticRestoreReader(object):
    """Explicit fixture producer, not actual kernel network/actor restoration."""
    def __init__(self, modules, baseline):
        self.modules, self.baseline, self.issued = modules, baseline, []

    def read_restore(self, store, locks, request, deadline):
        core = self.modules['mta_p2p_client_init']
        old = self.baseline
        snapshot = core.Snapshot(old.boot, old.stock_hashes, old.stock_actors, old.station,
            old.station_state_sha, old.station_frequency, old.interfaces, old.ipv4, old.ipv6_addresses, old.ipv6_routes, True)
        proof = core.CloseProof(2, (True, True), (True, True))
        value = (snapshot, proof); self.issued.append((store, locks, request, value)); return value

    def authenticate_restore(self, store, locks, request, value, deadline):
        if not any(a is store and b is locks and c is request and d is value for a, b, c, d in self.issued): fail('producer_unknown')
        return None


def _proc(modules, value):
    proc, core = modules['mta_client_proc'], modules['mta_p2p_client_init']
    if (type(value) is not proc.ProcObservation or value.kind != 'live_actor' or
            type(value.actor) is not core.Actor or not value.actor.live() or
            type(value.passes) is not int or value.passes != 2 or value.same_boot is not True or
            value.resource_pending is not False or type(value.file_count) is not int or value.file_count <= 0 or
            type(value.closed_count) is not int or value.closed_count != value.file_count or
            type(value.task_count) is not int or value.task_count != 1 or len(value.actor.tasks) != 1): fail('proc_unknown')
    return value.boot, value.actor.key()


def _rows(store):
    result = list(store._coordination._inventory) + list(store._files._inventory)
    if store._marker is not None and store._marker._ticket is not None: result.append(store._marker._ticket)
    return result


class LinuxFixture(object):
    """Pure ctor; open_root mapping and passive actual-close observer only."""
    def __init__(self, modules):
        self.modules, self.rows, self.anchors, self.close_events = modules, [], [], []
        self.fixture, self.token, self.ios, self.reader, self.store = None, None, None, None, None
        self.tmp_fd, self.run_fd, self.attempted, self.unknown = None, None, False, False
        self.close_observation_unknown = False

    def _open(self, call):
        row = {'fd': None, 'unknown': True, 'attempted': False, 'closed': False}
        self.rows.append(row)
        try: fd = call()
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095: row['unknown'], row['closed'] = False, True
            else: self.unknown = True
            raise
        except BaseException: self.unknown = True; raise
        row['fd'] = fd
        if not _uint(fd): self.unknown = True; fail('invalid_descriptor')
        if any(x is not row and x['fd'] == fd and not x['closed'] for x in self.rows): self.unknown = True; fail('open_unknown')
        row['unknown'] = False; return row

    def _anchor(self, fd, path, private=False, temporary=False):
        coord = self.modules['mta_client_coordination']
        identity = coord._directory(os.fstat(fd), private, temporary)
        if coord._directory(os.stat(path, follow_symlinks=False), private, temporary) != identity: fail('directory_changed')
        self.anchors.append((fd, path, identity, private, temporary))

    def initialize(self):
        if self.attempted: fail('already_attempted')
        self.attempted = True
        if sys.platform != 'linux' or os.geteuid() != 0: fail('unsupported_platform')
        if os.mkdir not in getattr(os, 'supports_dir_fd', ()): fail('unsupported_io')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root = self._open(lambda: os.open('/', flags))['fd']; self._anchor(root, '/')
        tmp = self._open(lambda: os.open('tmp', flags, dir_fd=root))['fd']; self._anchor(tmp, '/tmp', temporary=True)
        self.fixture = tempfile.mkdtemp(prefix='p011-mta-durable-client-host-', dir='/tmp')
        isolated = self._open(lambda: os.open(self.fixture, flags))['fd']; self._anchor(isolated, self.fixture, True)
        os.mkdir('tmp', 0o700, dir_fd=isolated)
        self.tmp_fd = self._open(lambda: os.open('tmp', flags, dir_fd=isolated))['fd']
        self._anchor(self.tmp_fd, self.fixture + '/tmp', True)
        os.mkdir('p011-mta-client-rfinit', 0o700, dir_fd=self.tmp_fd)
        base = self._open(lambda: os.open('p011-mta-client-rfinit', flags, dir_fd=self.tmp_fd))['fd']
        self._anchor(base, self.fixture + '/tmp/p011-mta-client-rfinit', True)
        self.token = os.urandom(16).hex()
        if re.fullmatch('[0-9a-f]{32}', self.token) is None: fail('open_unknown')
        name = 'client-' + self.token; os.mkdir(name, 0o700, dir_fd=base)
        self.run_fd = self._open(lambda: os.open(name, flags, dir_fd=base))['fd']
        self._anchor(self.run_fd, self.fixture + '/tmp/p011-mta-client-rfinit/' + name, True)
        self.ios = tuple(self.modules[n]._LinuxIo() for n in ('mta_client_coordination', 'mta_client_files', 'mta_client_pending'))
        for io in self.ios:
            io.open_root = lambda value: os.open(self.fixture, value)
            io.validate()
        self.reader = self.modules['mta_client_proc'].ProcReader(timeout=5.0)
        self.verify(); return self.token, self.ios, self.reader

    def track_store(self, store):
        self.store = store
        seen = []
        for io in self.ios:
            if any(io is old for old in seen): continue
            seen.append(io); original = io.close
            def observed_close(fd, _io=io, _original=original):
                # Passive observer cannot throw before the actual close syscall.
                row = None
                try:
                    candidates = [r for r in _rows(self.store) if r.io is _io and r.fd == fd and r.closed is False]
                    if len(candidates) != 1: self.close_observation_unknown = True
                    else: row = candidates[0]
                    self.close_events.append((row, _io, fd))
                except BaseException: self.close_observation_unknown = True
                return _original(fd)
            io.close = observed_close

    def verify(self, locks=False):
        coord = self.modules['mta_client_coordination']
        for fd, path, identity, private, temporary in self.anchors:
            if coord._directory(os.fstat(fd), private, temporary) != identity or \
                    coord._directory(os.stat(path, follow_symlinks=False), private, temporary) != identity: fail('directory_changed')
        if locks:
            coord._lock_identity(os.stat('p011-mta-p2p-device.lock', dir_fd=self.tmp_fd, follow_symlinks=False))
            coord._lock_identity(os.stat('journal.lock', dir_fd=self.run_fd, follow_symlinks=False))

    def terminal(self, canonical):
        files = self.modules['mta_client_files']
        row = self._open(lambda: os.open('journal.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.run_fd))
        try:
            before = files._file_metadata(os.fstat(row['fd'])); data = b''
            while len(data) <= self.modules['mta_client_journal_codec'].MAX_BYTES:
                chunk = os.read(row['fd'], 4096)
                if not chunk: break
                data += chunk
            if before != canonical.metadata or data != canonical.data or \
                    files._file_metadata(os.fstat(row['fd'])) != before or \
                    files._file_metadata(os.stat('journal.json', dir_fd=self.run_fd, follow_symlinks=False)) != before: fail('readback_failed')
        finally: self._close(row)
        if not row['closed']: fail('close_unknown')
        return True

    def absent(self):
        try: os.stat('p011-mta-p2p-device.pending', dir_fd=self.tmp_fd, follow_symlinks=False)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT: return True
        fail('marker_absence_unknown')

    def component_closure(self, store):
        rows = _rows(store); count = 0
        if self.close_observation_unknown: fail('device_last_unknown')
        for row in rows:
            if row.opening_unknown or row.closed is not True: fail('component_unknown')
            if row.fd is None:
                if row.attempted is not False: fail('component_unknown')
                continue
            if not _uint(row.fd) or row.attempted is not True: fail('component_unknown')
            if sum(event[0] is row for event in self.close_events) != 1: fail('close_unknown')
            try: row.io.fstat(row.fd)
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.EBADF: count += 1; continue
            fail('component_unknown')
        if not count or len(self.close_events) != count or self.close_events[-1][0] is not store._current_locks._device: fail('device_last_unknown')
        return count, count

    def _close(self, row):
        if row['attempted'] or row['closed']: return
        if row['unknown'] or not _uint(row['fd']): self.unknown = True; return
        row['attempted'] = True; returned = False
        try: returned = os.close(row['fd']) is None
        except BaseException: self.unknown = True
        try: os.fstat(row['fd'])
        except OSError as error:
            if returned and type(error.errno) is int and error.errno == errno.EBADF: row['closed'] = True; return
        except BaseException: pass
        self.unknown = True

    def finish(self):
        for row in reversed(self.rows):
            try: self._close(row)
            except BaseException: self.unknown = True
        verified = 0
        for row in self.rows:
            if row['unknown'] or not row['closed']: self.unknown = True; continue
            if row['fd'] is None: continue
            try: os.fstat(row['fd'])
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.EBADF: verified += 1; continue
            except BaseException: pass
            self.unknown = True
        count = sum(row['fd'] is not None for row in self.rows)
        return {'setup_fd_count': count, 'setup_ebadf_count': verified,
            'setup_closed': not self.unknown and bool(self.rows) and verified == count}


class LinuxDurableStoreCheck(object):
    def __init__(self, modules, _fixture=None, _clock=None):
        self.modules, self.fixture = modules, _fixture if _fixture is not None else LinuxFixture(modules)
        self.clock = _clock if _clock is not None else time.monotonic
        self.attempted, self.resources, self.private = False, None, {}

    def execute(self):
        if self.attempted: fail('already_attempted')
        self.attempted = True
        self.resources = {'fixture': self.fixture, 'modules': self.modules, 'store': None}
        report = {'evidence': 'HOST_LINUX_ISOLATED_DURABLE_STORE', 'pass': False,
            'production_provider': False, 'p011_tested': False, 'phone_tested': False, 'rf': False,
            'global_device_namespace_touched': False, 'synthetic_stock_network_baseline': True,
            'synthetic_restore_producer': True, 'network_baseline_authenticated': False,
            'actual_self_proc': False, 'initial_empty': False, 'prepared_verified': False,
            'all_stages_verified': False, 'new_inodes_verified': False, 'handoff_verified': False,
            'same_original_device_verified': False, 'fresh_reacquire_current': False,
            'terminal_durable': False, 'marker_clear_durable': False, 'marker_absence_readback': False,
            'finish_receipt_authenticated': False, 'terminal_readback': False, 'component_closed': False,
            'device_last_verified': False, 'component_fd_count': 0, 'component_ebadf_count': 0,
            'files_history_count': 0, 'coord_history_count': 0,
            'setup_closed': False, 'setup_fd_count': 0, 'setup_ebadf_count': 0,
            'rf_ttl_expiry_actual_tested': False, 'fixture_retained': True,
            'failure_stage': 'not_recorded', 'failure_class': 'not_recorded', 'failure_reason': 'not_recorded', 'errno': 0}
        store, locks, stage = None, None, 'fixture'
        try:
            token, ios, reader = self.fixture.initialize()
            self.resources.update({'ios': ios, 'reader': reader}); self.private['fixture'] = self.fixture.fixture
            stage = 'proc'; before = reader.read_self(); self.private['proc_before'] = before
            actor = _proc(self.modules, before); report['actual_self_proc'] = True
            identity, baseline, changes = synthetic(self.modules, before.boot)
            restore = SyntheticRestoreReader(self.modules, baseline)
            core, codec, module = (self.modules[n] for n in ('mta_p2p_client_init', 'mta_client_journal_codec', 'mta_client_store'))
            store = module.DurableClientInitStore(token, identity, timeout=10.0, _coordination_io=ios[0],
                _files_io=ios[1], _pending_io=ios[2], _proc_reader=reader, _clock=self.clock, _restore_reader=restore)
            self.resources.update({'store': store, 'restore': restore}); self.fixture.track_store(store)
            stage = 'acquire'; locks = store.acquire(identity, self.clock() + 10.0)
            self.resources['initial_locks'] = locks
            if store.current(locks) is not None: fail('readback_failed')
            report['initial_empty'] = True; self.fixture.verify(True)
            stage = 'prepare'; journal = store.commit(locks, core.Journal(identity, 'prepared', baseline, self.clock() + 18.0))
            self.resources['journal'] = journal
            if not store.pending_matches(locks, journal): fail('readback_failed')
            report['prepared_verified'] = True
            current_inode = store._canonical.metadata[:2]
            for fields in changes:
                stage = 'stages'; journal = store.commit(locks, journal.replace(**fields))
                self.resources['journal'] = journal
                if not store.pending_matches(locks, journal) or store._canonical.metadata[:2] == current_inode: fail('readback_failed')
                current_inode = store._canonical.metadata[:2]
            report['all_stages_verified'], report['new_inodes_verified'] = True, True
            stage = 'handoff'; released = store.active_return(locks, journal); self.resources['released'] = released
            if released.expected != 1 or not released.complete(): fail('handoff_failed')
            report['handoff_verified'] = True
            new = store.acquire(identity, self.clock() + 10.0, inherited=locks); self.resources['new_locks'] = new
            if new._device is not locks._device or new is locks or len(store._coordination._inventory) != 7: fail('handoff_failed')
            report['same_original_device_verified'] = True
            actual = store.current(new)
            if not core._same_journal(actual, journal): fail('readback_failed')
            report['fresh_reacquire_current'] = True
            stage = 'cleanup'; journal = store.commit(new, journal.replace(stage='cleanup_intent', ready=False))
            journal = store.commit(new, journal.replace(stage='cleanup_verified')); self.resources['cleanup_journal'] = journal
            stage = 'finish'; receipt = store.finish(new, journal, True, self.clock() + 10.0)
            self.resources['receipt'] = receipt
            if (type(receipt) is not core.FinishReceipt or receipt.complete is not True or
                    receipt.terminal_durable is not True or receipt.record.stage != 'reconciled' or
                    receipt.marker_state != 'absent_observed' or receipt.clear_durability != 'verified'): fail('terminal_failed')
            report['terminal_durable'], report['marker_clear_durable'] = True, True
            if store.authenticate_finish(new, journal, receipt, self.clock() + 10.0) is not True: fail('terminal_failed')
            report['finish_receipt_authenticated'] = True
            stage = 'readback'; self.fixture.verify(True)
            report['marker_absence_readback'] = self.fixture.absent() is True
            report['terminal_readback'] = self.fixture.terminal(store._terminal_canonical) is True
            after = reader.read_self(); self.private['proc_after'] = after
            if _proc(self.modules, after) != actor: fail('actor_changed')
            self.private['journal'] = receipt.record
            stage = 'close'
        except BaseException as error:
            report.update(_failure(stage, error)); self.private['traceback'] = traceback.format_exc()
        finally:
            if store is not None:
                try:
                    store.close()  # Once-only owners; never reclose an earlier unknown.
                    count, verified = self.fixture.component_closure(store)
                    report.update({'component_closed': True, 'device_last_verified': True,
                        'component_fd_count': count, 'component_ebadf_count': verified,
                        'files_history_count': len(store._files._inventory), 'coord_history_count': len(store._coordination._inventory)})
                except BaseException as error:
                    if report['failure_stage'] == 'not_recorded': report.update(_failure('close', error))
                    self.private['close_traceback'] = traceback.format_exc()
            try: report.update(self.fixture.finish())
            except BaseException as error:
                if report['failure_stage'] == 'not_recorded': report.update(_failure('setup_close', error))
                self.private['setup_close_traceback'] = traceback.format_exc()
            if report['component_closed'] and report['setup_closed']: self.resources = None
        required = ('actual_self_proc', 'initial_empty', 'prepared_verified', 'all_stages_verified',
            'new_inodes_verified', 'handoff_verified', 'same_original_device_verified', 'fresh_reacquire_current',
            'terminal_durable', 'marker_clear_durable', 'marker_absence_readback', 'finish_receipt_authenticated',
            'terminal_readback', 'component_closed', 'device_last_verified', 'setup_closed')
        report['pass'] = report['failure_stage'] == 'not_recorded' and all(report[k] is True for k in required)
        return report


def _failure(stage, error):
    number = getattr(error, 'errno', 0)
    return {'failure_stage': stage,
        'failure_class': 'os_error' if isinstance(error, OSError) else 'value_error' if isinstance(error, ValueError) else 'interrupted' if not isinstance(error, Exception) else 'unexpected',
        'failure_reason': error.code if type(error) is CheckError else 'io_error' if isinstance(error, OSError) else 'interrupted' if not isinstance(error, Exception) else 'unexpected',
        'errno': number if type(number) is int and 0 <= number <= 4095 else 0}


def _private_json(value):
    if isinstance(value, bytes): return {'bytes_hex': value.hex()}
    if isinstance(value, tuple): return [_private_json(v) for v in value]
    if isinstance(value, dict): return dict((str(k), _private_json(v)) for k, v in value.items())
    if hasattr(value, '__slots__'): return dict((k, _private_json(getattr(value, k))) for k in value.__slots__ if not k.startswith('_'))
    if value is None or type(value) in (str, int, float, bool): return value
    return '<private unprojected object>'


def _outputs(report, private):
    root = BASE / 'results'
    if any(p.is_symlink() for p in (root,) + tuple(root.parents)): fail('result_output')
    root.mkdir(mode=0o700, exist_ok=True)
    output = root / ('client-durable-store-linux-host-' + datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(8).hex())
    output.mkdir(mode=0o700); hidden = output / 'private-raw'; hidden.mkdir(mode=0o700)
    records = ((output / 'result.json', json.dumps(report, indent=2).encode('utf-8')),
        (output / 'README.txt', b'HOST Linux isolated durable Store B local files/locks only.\nProduction Provider/P011/phone/RF false; stock/network and restore producer synthetic.\nFixture/journal retained; own fixture marker cleared durably only after synthetic restore.\nOriginal-FD proof covers component/setup open epochs, not all process FDs or result writer.\n'),
        (hidden / 'observations.json', json.dumps(_private_json(private), indent=2).encode('utf-8')))
    for path, data in records:
        with path.open('xb') as handle: handle.write(data)


def execute_reviewed(expected):
    checks, sources = source_check()
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}', expected) is None or expected != checks['checker_sha256']: fail('reviewed_pin')
    if _EXECUTIONS: fail('already_attempted')
    owner = LinuxDurableStoreCheck(_load(sources)); _EXECUTIONS.append(owner)
    report = owner.execute()
    report['checker_sha256'], report['source_sha256'], report['reference_sha256'] = checks['checker_sha256'], checks['source_sha256'], checks['reference_sha256']
    _outputs(report, owner.private); return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--source-check-only', action='store_true'); modes.add_argument('--execute-reviewed', action='store_true')
    parser.add_argument('--expected-checker-sha256'); args = parser.parse_args(argv)
    if args.execute_reviewed != (args.expected_checker_sha256 is not None): parser.error('Explicit execution and exact checker SHA required together')
    try:
        report = execute_reviewed(args.expected_checker_sha256) if args.execute_reviewed else source_check()[0]
        print(json.dumps(report, indent=2)); return 0 if report.get('source_check_pass') or report['pass'] else 1
    except Exception as error:
        report = _failure('entry', error); report.update({'pass': False, 'evidence': 'HOST_LINUX_ISOLATED_DURABLE_STORE',
            'production_provider': False, 'p011_tested': False, 'phone_tested': False})
        print(json.dumps(report, indent=2)); return 1


if __name__ == '__main__': sys.exit(main())
