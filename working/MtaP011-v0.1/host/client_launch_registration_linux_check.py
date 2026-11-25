"""Pinned HOST Linux direct-child launch-registration check.

Default source-only; actual execution requires exact reviewed checker SHA.
Only fixed /usr/bin/sleep 4/2 second children, no native RF process/signals.
Stock/network/interface/restore fields remain explicitly synthetic.
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
    ('mta_client_store', 'c6d4c8b7fda8370be83efafe61bfad4a4680ef7a8edba51a89f539c6868594cd'),
    ('mta_client_process_owner', '0a9a02c79e7e6603f86a7d7618f0b030a3c81d3581423801f22790e923839165'),
    ('mta_client_launch_registration', '833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0'))
REFERENCES = (
    ('tests/test_client_launch_registration.py', 'f5a3039c85bc202af06e66c28957d3b14bbd3b8ec4fdabef9b37fa24c21bf8fe'),
    ('docs/CLIENT_LAUNCH_REGISTRATION_REVIEW.md', 'ebf13f386047053992ba2114bb1bf09a83d79632361ac582602dafa293595e39'))
MAX_SOURCE = 262144
CODES = frozenset(('source_pin', 'source_shape', 'source_changed', 'reviewed_pin',
    'unsupported_platform', 'unsupported_io', 'already_attempted', 'directory_changed',
    'invalid_descriptor', 'open_unknown', 'close_unknown', 'proc_unknown',
    'actor_changed', 'readback_failed', 'handoff_failed', 'terminal_failed',
    'marker_absence_unknown', 'component_unknown', 'device_last_unknown',
    'producer_unknown', 'io_error', 'interrupted', 'unexpected', 'result_output',
    'sleep_pin', 'child_unknown', 'gate_unknown', 'exec_unknown', 'reap_unknown',
    'sidecar_unknown', 'child_fd_unknown', 'owner_unknown'))
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
        'evidence': 'HOST_LAUNCH_SOURCE_ONLY', 'production_provider': False,
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
        module = types.ModuleType(name); module.__file__ = '<pinned-host-launch-registration>'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
        exec(compile(data, module.__file__, 'exec'), module.__dict__)
        loaded[name] = module
    return loaded


def _uint(value):
    return type(value) is int and 0 <= value <= 0x7fffffff



SLEEP_PATH = '/usr/bin/sleep'
SLEEP_ARGUMENTS = (('watchdog', '4'), ('controller', '2'))


def _proc(modules, value):
    proc, core = modules['mta_client_proc'], modules['mta_p2p_client_init']
    if (type(value) is not proc.ProcObservation or value.kind != 'live_actor' or
            type(value.actor) is not core.Actor or not value.actor.live() or
            type(value.passes) is not int or value.passes != 2 or value.same_boot is not True or
            value.resource_pending is not False or type(value.file_count) is not int or value.file_count <= 0 or
            type(value.closed_count) is not int or value.closed_count != value.file_count or
            type(value.task_count) is not int or value.task_count != 1 or len(value.actor.tasks) != 1):
        fail('proc_unknown')
    return value.boot, value.actor.key()


def synthetic(modules, boot):
    core, ip = modules['mta_p2p_client_init'], modules['mta_ip']
    identity = core.Identity(hashlib.sha256(b'HOST_DIRECT_CHILD_REGISTRATION_SYNTHETIC_V1').hexdigest())
    actors = tuple(core.Actor(n, 100, path, '1' * 64, ((n, 100, 'S'),))
        for n, path in enumerate(('/usr/bin/Z03', '/usr/bin/control_engine', '/usr/bin/weston'), 101))
    station = core.Origin(0, 1, 1, 'wlan0', 2)
    ipv4 = ip.IpSnapshot((), (), tuple(ip.RuleRecord(p, t) for p, t in ((0, 255), (32766, 254), (32767, 253))))
    base = core.Snapshot(boot, core.STOCK_PINS, actors, station, '2' * 64, 2412, (station,), ipv4, (), (), True)
    owned = core.Origin(0, 2, 2, 'mta12345678', 8)
    interface = core.InterfaceTicket(boot, 0, owned.name, 1, 1)
    return identity, base, owned, interface


def _rows(store, registry=None):
    rows = list(store._coordination._inventory) + list(store._files._inventory)
    if store._marker is not None and store._marker._ticket is not None: rows.append(store._marker._ticket)
    if registry is not None: rows.extend(registry._inventory)
    return rows


def _binary_metadata(value):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev',
             'st_size', 'st_mtime_ns', 'st_ctime_ns')
    result = tuple(getattr(value, name, None) for name in names)
    if (any(type(v) is not int or not 0 <= v <= (1 << 64) - 1 for v in result[:8]) or
            any(type(v) is not int or not -(1 << 63) <= v < (1 << 63) for v in result[8:]) or
            not stat.S_ISREG(result[2]) or result[2] & 0o022 or not result[2] & 0o111 or
            result[3:6] != (0, 0, 1) or not 4 <= result[7] <= 64 * 1024 * 1024):
        fail('sleep_pin')
    return result


class SleepImage(object):
    """Fixed nofollow ELF only; own exact FD/metadata, never a manifest signer."""
    def __init__(self, _fs=None, _clock=None):
        self.fs, self.clock = _fs if _fs is not None else os, _clock if _clock is not None else time.monotonic
        self.fd, self.metadata, self.sha = None, None, None
        self.attempted, self.creation_unknown, self.close_attempted, self.closed = False, False, False, False
        self.last, self.end = None, None

    def _check(self):
        value = self.clock()
        if type(value) not in (int, float) or not 0 <= value < 1e12 or self.last is not None and value < self.last:
            fail('sleep_pin')
        self.last = float(value)
        if self.end is not None and value >= self.end: fail('sleep_pin')

    def open(self):
        if self.attempted: fail('already_attempted')
        self.attempted, self.creation_unknown = True, True
        self._check(); self.end = self.last + 5.0
        try:
            if self.fs.geteuid() != 0: fail('unsupported_platform')
            self.fd = self.fs.open(SLEEP_PATH, self.fs.O_RDONLY | self.fs.O_NOFOLLOW | self.fs.O_CLOEXEC)
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095 and self.fd is None:
                self.creation_unknown, self.closed = False, True
            raise
        if not _uint(self.fd): fail('open_unknown')
        before = _binary_metadata(self.fs.fstat(self.fd)); self.metadata = before
        if _binary_metadata(self.fs.stat(SLEEP_PATH, follow_symlinks=False)) != before: fail('sleep_pin')
        self.creation_unknown = False
        digest, length, prefix = hashlib.sha256(), 0, b''
        while True:
            self._check(); data = self.fs.read(self.fd, 65536)
            if type(data) is not bytes or len(data) > 65536: fail('sleep_pin')
            if not data: break
            prefix = (prefix + data)[:4]; length += len(data)
            if length > before[7]: fail('sleep_pin')
            digest.update(data)
        if (length != before[7] or prefix != b'\x7fELF' or _binary_metadata(self.fs.fstat(self.fd)) != before or
                _binary_metadata(self.fs.stat(SLEEP_PATH, follow_symlinks=False)) != before): fail('sleep_pin')
        self.sha = digest.hexdigest(); self._check()
        return self

    def verify_child_binary(self, owner, child):
        matches = [r for r in child.fds if r.role == 'executable']
        if (self.sha is None or child.spec.sha != self.sha or child.spec.exe != SLEEP_PATH or len(matches) != 1 or
                matches[0].closed or matches[0].unknown or not matches[0].returned or
                _binary_metadata(owner._os.fstat(matches[0].fd)) != self.metadata):
            fail('sleep_pin')
        return True

    def close(self):
        if self.closed or self.close_attempted: return self.closed
        if self.creation_unknown or not _uint(self.fd) or self.metadata is None: return False
        self.close_attempted = True; returned = False
        try:
            if _binary_metadata(self.fs.fstat(self.fd)) != self.metadata: fail('sleep_pin')
            returned = self.fs.close(self.fd) is None
        except BaseException: pass
        try: self.fs.fstat(self.fd)
        except OSError as error:
            if returned and type(error.errno) is int and error.errno == errno.EBADF: self.closed = True
        except BaseException: pass
        return self.closed


class ChildObserver(object):
    """Passive original-row close observations; actual method always runs."""
    def __init__(self, owner):
        self.owner, self.events, self.unknown = owner, [], False
        original = owner._close_fd
        def observed(ticket, row):
            try:
                if row.closed is False and row.attempted is False and row.unknown is False and row.returned is True:
                    if not any(t is ticket for t in owner._tickets) or not any(r is row for r in ticket.fds):
                        self.unknown = True
                    self.events.append((ticket, row))
            except BaseException: self.unknown = True
            return original(ticket, row)
        owner._close_fd = observed

    def closure(self):
        count = 0
        if self.unknown: fail('child_fd_unknown')
        for child in self.owner._tickets:
            if child.unknown: fail('child_unknown')
            for row in child.fds:
                if row.unknown or row.closed is not True: fail('child_fd_unknown')
                if row.fd is None:
                    if row.returned or row.attempted: fail('child_fd_unknown')
                    continue
                if not _uint(row.fd) or row.attempted is not True or sum(t is child and r is row for t, r in self.events) != 1:
                    fail('child_fd_unknown')
                try: self.owner._os.fstat(row.fd)
                except OSError as error:
                    if type(error.errno) is int and error.errno == errno.EBADF: count += 1; continue
                fail('child_fd_unknown')
        return count, count


def _close_pregate(owner, child):
    """Only a known exact original parent gate-write FD; never whole inventory."""
    owner._exact(child)
    if (child.unknown or child.released or child.release_requested or owner._active or
            not child.fork_returned or child.fork_negative or type(child.pid) is not int or child.pid <= 0):
        fail('gate_unknown')
    rows = [r for r in child.fds if r.role == 'gate_write']
    if (len(rows) != 1 or rows[0].unknown or rows[0].attempted or rows[0].closed or
            rows[0].returned is not True or type(rows[0].fd) is not int):
        fail('gate_unknown')
    owner._single(child, deadline=owner._now() + 3.0)
    if owner._close_fd(child, rows[0]) is not True: fail('gate_unknown')
    return True


def _sidecar_closure(fixture, registry):
    if registry._pending: fail('sidecar_unknown')
    count = 0
    for row in registry._inventory:
        if row.opening_unknown or row.closed is not True or row.attempted is not True or not _uint(row.fd):
            fail('sidecar_unknown')
        if sum(event[0] is row for event in fixture.close_events) != 1: fail('sidecar_unknown')
        try: row.io.fstat(row.fd)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.EBADF: count += 1; continue
        fail('sidecar_unknown')
    if count <= 0: fail('sidecar_unknown')
    return count, count

class LinuxFixture(object):
    """Pure ctor; open_root mapping and passive actual-close observer only."""
    def __init__(self, modules):
        self.modules, self.rows, self.anchors, self.close_events = modules, [], [], []
        self.fixture, self.token, self.ios, self.reader, self.store = None, None, None, None, None
        self.tmp_fd, self.run_fd, self.attempted, self.unknown = None, None, False, False
        self.close_observation_unknown, self.registry = False, None

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
        self.fixture = tempfile.mkdtemp(prefix='p011-mta-direct-child-host-', dir='/tmp')
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
                    candidates = [r for r in _rows(self.store, self.registry) if r.io is _io and r.fd == fd and r.closed is False]
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
        if not count or len([e for e in self.close_events if any(e[0] is r for r in rows)]) != count or self.close_events[-1][0] is not store._current_locks._device: fail('device_last_unknown')
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



class SyntheticRestoreReader(object):
    """Synthetic stock/network only; extra owned resources must be actually closed."""
    def __init__(self, modules, baseline, context):
        self.modules, self.baseline, self.context, self.issued = modules, baseline, context, []

    def read_restore(self, store, locks, request, deadline):
        self.context.verify_extra_closed()
        core = self.modules['mta_p2p_client_init']; old = self.baseline
        snapshot = core.Snapshot(old.boot, old.stock_hashes, old.stock_actors, old.station,
            old.station_state_sha, old.station_frequency, old.interfaces, old.ipv4, old.ipv6_addresses, old.ipv6_routes, True)
        value = (snapshot, core.CloseProof(2, (True, True), (True, True)))
        self.issued.append((store, locks, request, value))
        return value

    def authenticate_restore(self, store, locks, request, value, deadline):
        self.context.verify_extra_closed()
        if not any(a is store and b is locks and c is request and d is value for a, b, c, d in self.issued):
            fail('producer_unknown')
        return None


class LinuxLaunchCheck(object):
    def __init__(self, modules, _fixture=None, _clock=None):
        self.modules = modules
        self.fixture = _fixture if _fixture is not None else LinuxFixture(modules)
        self.clock = _clock if _clock is not None else time.monotonic
        self.attempted, self.resources, self.private = False, None, {}
        self.owner, self.registry, self.image, self.observer, self.report = None, None, None, None, None

    def _error(self, stage, error):
        self.private.setdefault('failures', []).append({'stage': stage, 'traceback': traceback.format_exc()})
        if self.report['failure_stage'] == 'not_recorded': self.report.update(_failure(stage, error))

    def verify_extra_closed(self):
        if self.owner is None or self.registry is None or self.image is None or self.observer is None:
            fail('child_unknown')
        for child in self.owner._tickets:
            if (child.unknown or child.waited is not True or child.preexec is None or
                    type(child.pid) is not int or child.pid != child.preexec.pid or child.boot != self.private['proc_before'].boot):
                fail('reap_unknown')
            if self.owner.fresh_exit(child) is not True: fail('reap_unknown')
            self.private.setdefault('fresh_exit_observations', []).append(child.exit_observation)
        self.observer.closure()
        _sidecar_closure(self.fixture, self.registry)
        if self.image.closed is not True: fail('sleep_pin')
        try: self.image.fs.fstat(self.image.fd)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.EBADF: return True
        fail('sleep_pin')

    def _children_cleanup(self):
        if self.owner is None: return
        all_reaped, all_absent, all_success = True, True, True
        for child in self.owner._tickets:
            try:
                if (child.fork_requested is False or child.fork_negative is True) and child.pid is None:
                    # Actual no-fork / known-negative result, not a guessed absence.
                    if self.owner.close_inventory(child) is not True: fail('child_fd_unknown')
                    all_reaped, all_absent, all_success = False, False, False
                    continue
                if not child.released:
                    _close_pregate(self.owner, child)
                if self.owner.wait_reap(child, timeout=10.0) is not True: fail('reap_unknown')
                all_success = all_success and child.exit_code == 0
                if self.owner.fresh_exit(child) is not True: fail('reap_unknown')
                self.private.setdefault('child_exits', []).append({'role': child.spec.role, 'pid': child.pid,
                    'boot': child.boot, 'preexec': child.preexec, 'postexec': child.postexec,
                    'exit_code': child.exit_code, 'wait_status': child.wait_status, 'observation': child.exit_observation})
            except BaseException as error:
                all_reaped, all_absent = False, False
                self._error('child_reap', error)
            finally:
                # Remaining original inventory only after actual wait; a
                # failed/unconfirmed child is never made closed by this call.
                if child.waited:
                    try:
                        if self.owner.close_inventory(child) is not True: fail('child_fd_unknown')
                    except BaseException as error: self._error('child_close', error)
        self.report['children_reaped'] = all_reaped and len(self.owner._tickets) == 2
        self.report['children_absence_verified'] = all_absent and len(self.owner._tickets) == 2
        self.report['children_exit_zero'] = all_success and len(self.owner._tickets) == 2
        try:
            count, verified = self.observer.closure()
            self.report.update(child_fds_closed=True, child_fd_count=count, child_ebadf_count=verified)
        except BaseException as error: self._error('child_close', error)

    def execute(self):
        if self.attempted: fail('already_attempted')
        self.attempted = True
        self.resources = {'fixture': self.fixture, 'modules': self.modules}
        self.report = report = {'evidence': 'HOST_LINUX_ISOLATED_DIRECT_CHILD_REGISTRATION', 'pass': False,
            'production_provider': False, 'p011_tested': False, 'phone_tested': False, 'rf': False,
            'global_device_namespace_touched': False, 'synthetic_stock_network_baseline': True,
            'synthetic_interface': True, 'synthetic_restore_producer': True, 'network_baseline_authenticated': False,
            'production_manifest_authenticated': False, 'sleep_elf_verified': False, 'actual_self_proc': False,
            'initial_empty': False, 'prepared_verified': False, 'preexec_durable': False, 'postexec_durable': False,
            'all_stages_verified': False, 'children_reaped': False, 'children_absence_verified': False,
            'children_exit_zero': False, 'child_fds_closed': False, 'child_fd_count': 0, 'child_ebadf_count': 0,
            'sidecar_fds_closed': False, 'sidecar_fd_count': 0, 'sidecar_ebadf_count': 0, 'sleep_pin_closed': False,
            'terminal_durable': False, 'marker_clear_durable': False, 'marker_absence_readback': False,
            'finish_receipt_authenticated': False, 'terminal_readback': False, 'component_closed': False,
            'device_last_verified': False, 'component_fd_count': 0, 'component_ebadf_count': 0,
            'setup_closed': False, 'setup_fd_count': 0, 'setup_ebadf_count': 0,
            'fixture_retained': True, 'rf_ttl_expiry_actual_tested': False,
            'failure_stage': 'not_recorded', 'failure_class': 'not_recorded', 'failure_reason': 'not_recorded', 'errno': 0}
        store, locks, journal, stage = None, None, None, 'fixture'
        try:
            token, ios, reader = self.fixture.initialize()
            self.resources.update(ios=ios, reader=reader); self.private['fixture'] = self.fixture.fixture
            stage = 'proc'; before = reader.read_self(); self.private['proc_before'] = before
            original_actor = _proc(self.modules, before); report['actual_self_proc'] = True
            stage = 'sleep_pin'
            self.image = self.fixture.sleep_image() if hasattr(self.fixture, 'sleep_image') else SleepImage(_clock=self.clock)
            self.resources['sleep_image'] = self.image
            self.image.open()
            self.private['sleep_image'] = {'sha256': self.image.sha, 'metadata': self.image.metadata}
            report['sleep_elf_verified'] = True
            core, module = self.modules['mta_p2p_client_init'], self.modules['mta_client_store']
            identity, baseline, owned, interface = synthetic(self.modules, before.boot)
            restore = SyntheticRestoreReader(self.modules, baseline, self)
            store = module.DurableClientInitStore(token, identity, timeout=10.0, _coordination_io=ios[0],
                _files_io=ios[1], _pending_io=ios[2], _proc_reader=reader, _clock=self.clock, _restore_reader=restore)
            self.resources.update(store=store, restore=restore); self.fixture.track_store(store)
            stage = 'prepare'; locks = store.acquire(identity, self.clock() + 10.0)
            self.resources['locks'] = locks
            if store.current(locks) is not None: fail('readback_failed')
            report['initial_empty'] = True; self.fixture.verify(True)
            journal = store.commit(locks, core.Journal(identity, 'prepared', baseline, self.clock() + 18.0))
            self.resources['journal'] = journal; report['prepared_verified'] = True
            self.owner = self.fixture.child_owner(reader, self.clock) if hasattr(self.fixture, 'child_owner') else \
                self.modules['mta_client_process_owner'].DirectChildOwner(_reader=reader, _clock=self.clock)
            self.resources['child_owner'] = self.owner
            self.observer = ChildObserver(self.owner); self.resources['child_observer'] = self.observer
            self.registry = self.modules['mta_client_launch_registration'].DurableLaunchRegistry(store, self.owner, timeout=10.0)
            self.resources['registry'] = self.registry; self.fixture.registry = self.registry
            for index, (role, seconds) in enumerate(SLEEP_ARGUMENTS):
                if role == 'controller':
                    journal = store.commit(locks, journal.replace(stage='interface_intent', interface_ticket=interface))
                    journal = store.commit(locks, journal.replace(stage='interface_owned', owned=owned))
                spec = self.modules['mta_client_process_owner'].LaunchSpec(role, SLEEP_PATH, (SLEEP_PATH, seconds), (), self.image.sha)
                target = core.Ticket(('%032x' % (index + 1)), role, before.boot, spec.exe, spec.argv_sha)
                journal = store.commit(locks, journal.replace(stage=role + '_intent', **{role + '_ticket': target}))
                child = self.owner.register(spec, locks._device.fd, journal.deadline)
                self.resources.setdefault('child_tickets', []).append(child)
                record = self.registry.register(target, child)
                self.resources.setdefault('registrations', []).append(record)
                stage = 'child_launch'; self.owner.launch(child)
                self.image.verify_child_binary(self.owner, child)
                stage = 'preexec'; self.registry.release(record)
                stage = 'postexec'; handle = None
                for unused in range(8):
                    handle = self.registry.resolve(record)
                    if handle is not None: break
                    self.owner._sleep(0.025)
                if type(handle) is not core.Handle or handle.resource is not child: fail('exec_unknown')
                self.resources.setdefault('handles', []).append(handle)
                self.private.setdefault('launches', []).append({'role': role, 'preexec': record.preexec,
                    'postexec': record.postexec, 'final_observation': record.final_observation,
                    'sidecar': record.data, 'sidecar_metadata': record.metadata})
                stage = 'stages'; journal = store.commit(locks, journal.replace(stage=role + '_saved', **{role: handle.actor}))
                self.resources['journal'] = journal
            report['preexec_durable'] = self.registry.status()['preexec_durable_count'] == 2
            report['postexec_durable'] = self.registry.status()['postexec_durable_count'] == 2
            report['all_stages_verified'] = True
        except BaseException as error: self._error(stage, error)
        finally:
            self._children_cleanup()
            if self.registry is not None:
                try:
                    self.registry.close(); count, verified = _sidecar_closure(self.fixture, self.registry)
                    report.update(sidecar_fds_closed=True, sidecar_fd_count=count, sidecar_ebadf_count=verified)
                except BaseException as error: self._error('sidecar_close', error)
            if self.image is not None:
                try:
                    if self.image.close() is not True: fail('sleep_pin')
                    report['sleep_pin_closed'] = True
                except BaseException as error: self._error('sleep_close', error)
            if store is not None:
                try:
                    stage = 'finish'
                    self.verify_extra_closed()
                    current = store.current(locks)
                    journal = store.commit(locks, current.replace(stage='cleanup_intent', ready=False))
                    journal = store.commit(locks, journal.replace(stage='cleanup_verified'))
                    receipt = store.finish(locks, journal, True, self.clock() + 10.0)
                    self.resources['receipt'] = receipt
                    if (type(receipt) is not self.modules['mta_p2p_client_init'].FinishReceipt or receipt.complete is not True or
                            receipt.terminal_durable is not True or receipt.record.stage != 'reconciled' or
                            receipt.marker_state != 'absent_observed' or receipt.clear_durability != 'verified'):
                        fail('terminal_failed')
                    if store.authenticate_finish(locks, journal, receipt, self.clock() + 10.0) is not True: fail('terminal_failed')
                    report.update(terminal_durable=True, marker_clear_durable=True, finish_receipt_authenticated=True)
                    report['marker_absence_readback'] = self.fixture.absent() is True
                    report['terminal_readback'] = self.fixture.terminal(store._terminal_canonical) is True
                    self.private['terminal_journal'] = receipt.record
                except BaseException as error: self._error(stage, error)
                try:
                    store.close()
                    count, verified = self.fixture.component_closure(store)
                    report.update(component_closed=True, device_last_verified=True, component_fd_count=count, component_ebadf_count=verified)
                except BaseException as error: self._error('component_close', error)
            try:
                if self.resources.get('reader') is not None:
                    after = self.resources['reader'].read_self(); self.private['proc_after'] = after
                    if _proc(self.modules, after) != original_actor: fail('actor_changed')
            except BaseException as error: self._error('proc_after', error)
            try: report.update(self.fixture.finish())
            except BaseException as error: self._error('setup_close', error)
            if (report['child_fds_closed'] and report['sidecar_fds_closed'] and report['sleep_pin_closed'] and
                    report['component_closed'] and report['setup_closed'] and report['children_absence_verified']):
                self.resources = None
        required = ('sleep_elf_verified', 'actual_self_proc', 'initial_empty', 'prepared_verified',
            'preexec_durable', 'postexec_durable', 'all_stages_verified', 'children_reaped', 'children_absence_verified',
            'children_exit_zero', 'child_fds_closed', 'sidecar_fds_closed', 'sleep_pin_closed', 'terminal_durable',
            'marker_clear_durable', 'marker_absence_readback', 'finish_receipt_authenticated', 'terminal_readback',
            'component_closed', 'device_last_verified', 'setup_closed')
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
    if isinstance(value, (tuple, list)): return [_private_json(v) for v in value]
    if isinstance(value, dict): return dict((str(k), _private_json(v)) for k, v in value.items())
    if hasattr(value, '__slots__'): return dict((k, _private_json(getattr(value, k))) for k in value.__slots__ if not k.startswith('_'))
    if value is None or type(value) in (str, int, float, bool): return value
    return '<private unprojected object>'


def _outputs(report, private):
    root = BASE / 'results'
    if any(p.is_symlink() for p in (root,) + tuple(root.parents)): fail('result_output')
    root.mkdir(mode=0o700, exist_ok=True)
    output = root / ('client-launch-linux-host-' + datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(8).hex())
    output.mkdir(mode=0o700); hidden = output / 'private-raw'; hidden.mkdir(mode=0o700)
    records = ((output / 'result.json', json.dumps(report, indent=2).encode('utf-8')),
        (output / 'README.txt', b'HOST Linux isolated direct-child launch registration.\nProduction Provider/P011/phone/RF false; stock/network and restore producer synthetic.\nFixed sleep4/2 natural children; fixture/sidecars/journal retained; stock network synthetic.\nOriginal-FD proof covers component/setup open epochs, not all process FDs or result writer.\n'),
        (hidden / 'observations.json', json.dumps(_private_json(private), indent=2).encode('utf-8')))
    for path, data in records:
        with path.open('xb') as handle: handle.write(data)


def execute_reviewed(expected):
    checks, sources = source_check()
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}', expected) is None or expected != checks['checker_sha256']: fail('reviewed_pin')
    if _EXECUTIONS: fail('already_attempted')
    owner = LinuxLaunchCheck(_load(sources)); _EXECUTIONS.append(owner)
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
        report = _failure('entry', error); report.update({'pass': False, 'evidence': 'HOST_LINUX_ISOLATED_DIRECT_CHILD_REGISTRATION',
            'production_provider': False, 'p011_tested': False, 'phone_tested': False})
        print(json.dumps(report, indent=2)); return 1


if __name__ == '__main__': sys.exit(main())
