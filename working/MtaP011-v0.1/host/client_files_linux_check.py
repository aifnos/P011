"""HOST Linux file-only integration entry; never a P011/CLIENT/RF checker.

Default reads reviewed source only. No constructor performs IO. Explicit
execution preserves one synthetic private run; no cleanup/recovery authority.
"""
import argparse
import ast
import builtins
import datetime
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

BASE = Path(__file__).absolute().parents[1]
# Includes ROOT's reviewed final-readback inode/metadata[:7] fix.
PINS = (
    ('mta_ip', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('p011_json', 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    # ROOT-reviewed finish-contract revision. This file check only constructs
    # Identity/Actor/Snapshot/Journal; it never runs lease/finish/Provider.
    ('mta_p2p_client_init', 'ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1'),
    ('mta_client_journal_codec', '17d362826a90da7fe9d77a82495a34bbc56b4c67aaca608aa5565ee1d3369f73'),
    # Reviewed optional own-marker binding remains dormant in this file-only
    # check; the default absent-pending boundary is unchanged.
    ('mta_client_files', 'd95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3'))
MAX_SOURCE = 262144
CODES = frozenset(('source_pin', 'source_shape', 'source_changed', 'reviewed_pin',
    'unsupported_platform', 'unsupported_io', 'invalid_clock', 'deadline',
    'unsafe_directory', 'directory_changed', 'global_pending_blocked',
    'invalid_token', 'invalid_descriptor', 'descriptor_reused', 'open_unknown',
    'close_unknown', 'readback_failed', 'stale_not_rejected', 'status_invalid',
    'result_output', 'io_error', 'interrupted', 'unexpected', 'already_attempted'))
# Exact check instances, registered before any execute callback. One per process;
# never clear unknown ownership or use GC/destructors to invent close evidence.
_EXECUTIONS = []


class CheckError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in CODES else 'unexpected'
        ValueError.__init__(self, self.code)


def fail(code):
    raise CheckError(code)


def _source(path, pin=None):
    if any(p.is_symlink() for p in (path,) + tuple(path.parents)):
        fail('source_shape')
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_SOURCE:
        fail('source_shape')
    with path.open('rb') as handle:
        opened = os.fstat(handle.fileno())
        data = handle.read(MAX_SOURCE + 1)
    after = path.stat()
    for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns'):
        if getattr(before, field) != getattr(opened, field) or getattr(before, field) != getattr(after, field):
            fail('source_changed')
    if len(data) != before.st_size or pin is not None and hashlib.sha256(data).hexdigest() != pin:
        fail('source_pin')
    return data


def source_check():
    sources = tuple((name, _source(BASE / 'runtime' / (name + '.py'), pin)) for name, pin in PINS)
    own = _source(Path(__file__).absolute())
    for data in (own,) + tuple(data for _, data in sources):
        ast.parse(data.decode('utf-8'), feature_version=(3, 5))
    return {'source_check_pass': True, 'checker_sha256': hashlib.sha256(own).hexdigest(),
        'source_sha256': dict(PINS), 'evidence': 'HOST_SOURCE_ONLY', 'p011_tested': False}, sources


def _load(sources):
    """Fixed pinned modules in memory, without sys.path or test fixture imports."""
    loaded, names = {}, set(name for name, _ in PINS)
    original = builtins.__import__
    def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in names:
            if level or name not in loaded: fail('source_shape')
            return loaded[name]
        if name.startswith('mta_') or name.startswith('p011_') or level:
            fail('source_shape')
        return original(name, globals, locals, fromlist, level)
    for name, data in sources:
        namespace = types.ModuleType(name)
        namespace.__file__ = '<pinned-host-client-files>'
        namespace.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
        exec(compile(data, namespace.__file__, 'exec'), namespace.__dict__)
        loaded[name] = namespace
    return loaded


def synthetic(modules):
    """Deterministic logical schema only; none of these fields observes the OS."""
    core, ip = modules['mta_p2p_client_init'], modules['mta_ip']
    identity = core.Identity(hashlib.sha256(b'HOST_CLIENT_FILES_SYNTHETIC_V1').hexdigest())
    actors = tuple(core.Actor(number, 100, path, '1' * 64, ((number, 100, 'S'),))
        for number, path in enumerate(('/usr/bin/Z03', '/usr/bin/control_engine', '/usr/bin/weston'), 101))
    station = core.Origin(0, 1, 1, 'wlan0', 2)
    ipv4 = ip.IpSnapshot((), (), tuple(ip.RuleRecord(priority, table)
        for priority, table in ((0, 255), (32766, 254), (32767, 253))))
    baseline = core.Snapshot('00000000-0000-0000-0000-000000000000', core.STOCK_PINS,
        actors, station, '2' * 64, 2412, (station,), ipv4, (), (), True)
    first = core.Journal(identity, 'new', baseline, 123.0)
    return identity, first, first.replace(stage='prepared')


class HostIo(object):
    """Constructor is pure; Linux/root checks happen only at execute()."""
    def __init__(self, files):
        self.delegate = files._LinuxIo()

    def validate(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            fail('unsupported_platform')
        self.delegate.validate()
        if os.mkdir not in getattr(os, 'supports_dir_fd', ()):
            fail('unsupported_io')

    def token(self): return os.urandom(16).hex()
    def flag(self, name): return self.delegate.flag(name)
    def open_root(self, flags): return self.delegate.open_root(flags)
    def open_at(self, parent, name, flags, mode=0): return self.delegate.open_at(parent, name, flags, mode)
    def stat_at(self, parent, name): return self.delegate.stat_at(parent, name)
    def mkdir_at(self, parent, name): return os.mkdir(name, 0o700, dir_fd=parent)
    def fstat(self, fd): return self.delegate.fstat(fd)
    def read(self, fd, count): return self.delegate.read(fd, count)
    def write(self, fd, data): return self.delegate.write(fd, data)
    def fsync(self, fd): return self.delegate.fsync(fd)
    def rename_at(self, parent, source, target): return self.delegate.rename_at(parent, source, target)
    def close(self, fd): return self.delegate.close(fd)


class AuditIo(object):
    """Independent open-epoch ledger. Unknown close is never retried."""
    def __init__(self, io):
        self.io, self.rows, self.live = io, [], {}

    def _open(self, operation):
        row = {'fd': None, 'unknown': True, 'attempted': False, 'closed': False}
        self.rows.append(row)  # Before any callback can return/interrupt.
        try:
            fd = operation()
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095:
                row['unknown'] = False
            raise
        if type(fd) is not int or not 0 <= fd <= 0x7fffffff:
            fail('invalid_descriptor')
        row['fd'], row['unknown'] = fd, False
        if fd in self.live:
            row['unknown'] = True
            fail('descriptor_reused')
        self.live[fd] = row
        return fd

    def open_root(self, flags): return self._open(lambda: self.io.open_root(flags))
    def open_at(self, parent, name, flags, mode=0): return self._open(lambda: self.io.open_at(parent, name, flags, mode))
    def validate(self): return self.io.validate()
    def flag(self, name): return self.io.flag(name)
    def stat_at(self, parent, name): return self.io.stat_at(parent, name)
    def fstat(self, fd): return self.io.fstat(fd)
    def read(self, fd, count): return self.io.read(fd, count)
    def write(self, fd, data): return self.io.write(fd, data)
    def fsync(self, fd): return self.io.fsync(fd)
    def rename_at(self, parent, source, target): return self.io.rename_at(parent, source, target)

    def close(self, fd):
        row = self.live.get(fd)
        if row is None or row['attempted']:
            fail('close_unknown')
        row['attempted'] = True
        returned = False
        try:
            self.io.close(fd)
            returned = True
        finally:
            try:
                self.io.fstat(fd)
            except OSError as error:
                if returned and type(error.errno) is int and error.errno == errno.EBADF:
                    row['closed'] = True
                    del self.live[fd]
            except BaseException:
                pass
        if not row['closed']: fail('close_unknown')

    def finish(self):
        # Each original epoch independently attempted; no retry of uncertain FD.
        for row in reversed(self.rows):
            if row['fd'] is not None and not row['unknown'] and not row['attempted']:
                try: self.close(row['fd'])
                except BaseException: pass
        verified = True
        for fd in set(row['fd'] for row in self.rows if row['fd'] is not None):
            try:
                self.io.fstat(fd)
                verified = False
            except OSError as error:
                if type(error.errno) is not int or error.errno != errno.EBADF: verified = False
            except BaseException:
                verified = False
        known = tuple(row for row in self.rows if row['fd'] is not None)
        return {'known_fd_count': len(known), 'close_attempt_count': sum(row['attempted'] for row in known),
            'close_verified_count': sum(row['closed'] for row in known),
            'unknown_open_count': sum(row['unknown'] for row in self.rows),
            'all_epoch_closed': bool(known and all(row['closed'] for row in known) and not any(row['unknown'] for row in self.rows)),
            'final_ebadf_verified': verified}


class LinuxFileCheck(object):
    def __init__(self, modules, io=None, clock=None):
        self.modules, self.io, self.clock = modules, io, clock
        self._attempted, self._resources = False, None

    def execute(self):
        if self._attempted: fail('already_attempted')
        self._attempted = True
        files, codec = self.modules['mta_client_files'], self.modules['mta_client_journal_codec']
        raw = self.io if self.io is not None else HostIo(files)
        io, anchors, obj = AuditIo(raw), [], None
        self._resources = {'modules': self.modules, 'raw': raw, 'audit': io, 'anchors': anchors, 'files': None}
        report = {'evidence': 'HOST_LINUX_FILES_ONLY', 'pass': False, 'p011_tested': False,
            'rf_operations': False, 'network_operations': False, 'global_pending_modified': False,
            'flock_tested': False, 'store_tested': False, 'provider_tested': False, 'recovery_authority': False,
            'first_commit_verified': False, 'second_commit_verified': False, 'stale_generation_rejected': False,
            'stale_rejection_current_unchanged': False, 'file_layer_closed': False,
            'base_created': False, 'run_created': False, 'private_run_retained': False}
        clock, stage = self.clock or time.monotonic, 'platform'
        end, last = None, None
        def budget():
            nonlocal end, last
            now = clock()
            if type(now) not in (int, float) or not 0 <= now < 1e12 or not math.isfinite(float(now)) or last is not None and now < last:
                fail('invalid_clock')
            last = now
            if end is None: end = now + 20.0
            if now >= end: fail('deadline')
        def verify():
            budget()
            for fd, parent, name, identity, private, temporary in anchors:
                if files._dir_identity(io.fstat(fd), private, temporary) != identity or parent is not None and files._dir_identity(io.stat_at(parent, name), private, temporary) != identity:
                    fail('directory_changed')
        def pending():
            budget()
            try: io.stat_at(anchors[1][0], files.GLOBAL_PENDING)
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.ENOENT: return
                raise
            fail('global_pending_blocked')
        def open_dir(parent, name, private=False, temporary=False):
            budget()
            flags = io.flag('O_RDONLY') | io.flag('O_DIRECTORY') | io.flag('O_NOFOLLOW') | io.flag('O_CLOEXEC')
            fd = io.open_root(flags) if parent is None else io.open_at(parent, name, flags)
            identity = files._dir_identity(io.fstat(fd), private, temporary)
            if parent is not None and files._dir_identity(io.stat_at(parent, name), private, temporary) != identity:
                fail('directory_changed')
            anchors.append((fd, parent, name, identity, private, temporary))
            return fd
        try:
            budget(); io.validate()
            stage = 'directories'; root = open_dir(None, None); tmp = open_dir(root, 'tmp', temporary=True)
            verify(); pending()
            try: io.stat_at(tmp, files.ROOT_COMPONENT)
            except OSError as error:
                if type(error.errno) is not int or error.errno != errno.ENOENT: raise
                budget(); raw.mkdir_at(tmp, files.ROOT_COMPONENT); report['base_created'] = True
            base = open_dir(tmp, files.ROOT_COMPONENT, private=True)
            token = raw.token()
            if type(token) is not str or re.fullmatch('[0-9a-f]{32}', token) is None: fail('invalid_token')
            verify(); pending(); budget()
            raw.mkdir_at(base, files.RUN_PREFIX + token)  # mkdir is exclusive; never retry an existing run.
            report['run_created'], report['private_run_retained'] = True, True
            open_dir(base, files.RUN_PREFIX + token, private=True); verify(); pending()
            identity, first, second = synthetic(self.modules)
            stage = 'files_open'; obj = files.ClientJournalFiles(token, identity, _io=io, _clock=clock)
            self._resources['files'] = obj  # Strong reference before open/interrupt.
            obj.open()
            if obj.read_current() is not None: fail('readback_failed')
            stage = 'first_commit'; budget(); verify(); receipt = obj.commit(None, first)
            current = obj.read_current()
            if current is None or receipt.data != codec.encode_journal(first) or current.data != receipt.data or current.metadata != receipt.metadata or current.journal.key() != first.key(): fail('readback_failed')
            report['first_commit_verified'] = True
            stage = 'second_commit'; budget(); verify(); second_receipt = obj.commit(current, second)
            current = obj.read_current()
            if current is None or second_receipt.data != codec.encode_journal(second) or current.data != second_receipt.data or current.metadata != second_receipt.metadata or current.journal.key() != second.key(): fail('readback_failed')
            report['second_commit_verified'] = True
            stage = 'stale_generation'; budget()
            try: obj.commit(receipt, first)
            except files.ClientFileError as error:
                if error.code != 'invalid_expected': raise
                report['stale_generation_rejected'] = True
            else: fail('stale_not_rejected')
            fresh = obj.read_current()
            if fresh is None or fresh.data != current.data or fresh.metadata != current.metadata or fresh.journal.key() != second.key(): fail('readback_failed')
            report['stale_rejection_current_unchanged'] = True
            verify(); pending(); budget()
            stage = 'closed'
        except BaseException as error:
            report['failure_stage'] = stage
            report['failure_class'] = 'os_error' if isinstance(error, OSError) else 'value_error' if isinstance(error, ValueError) else 'interrupted' if not isinstance(error, Exception) else 'unexpected'
            report['failure_reason'] = error.code if type(error) is CheckError or type(error) is files.ClientFileError else 'io_error' if isinstance(error, OSError) else 'interrupted' if not isinstance(error, Exception) else 'unexpected'
            number = getattr(error, 'errno', 0)
            report['errno'] = number if type(number) is int and 0 <= number <= 4095 else 0
        finally:
            if obj is not None:
                try:
                    status = obj.close()
                    report['file_layer_closed'] = bool(status['all_owned_fds_closed'] and not status['resource_pending'] and not status['unresolved_open_count'] and not status['write_pending'] and not status['published_unknown'])
                except BaseException:
                    report['file_layer_closed'] = False
            report.update(io.finish())
            if report['all_epoch_closed'] and report['final_ebadf_verified'] and (obj is None or report['file_layer_closed']):
                self._resources = None  # Only the complete independent close proof releases refs.
        report['pass'] = bool(all(report[key] for key in ('first_commit_verified', 'second_commit_verified', 'stale_generation_rejected',
            'stale_rejection_current_unchanged', 'file_layer_closed', 'all_epoch_closed', 'final_ebadf_verified')) and 'failure_stage' not in report)
        return report


def _outputs(report):
    root = BASE / 'results'
    if any(p.is_symlink() for p in (root,) + tuple(root.parents)): fail('result_output')
    root.mkdir(mode=0o700, exist_ok=True)
    output = root / ('client-files-linux-host-' + datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(8).hex())
    output.mkdir(mode=0o700)
    for name, data in (('result.json', json.dumps(report, indent=2).encode('utf-8')),
        ('README.txt', b'HOST Linux synthetic file-only test. Private synthetic run retained; no automatic cleanup.\nNot P011, RF, network, provider, Store, flock, association, TTL or recovery proof.\nFD proof covers this check file-layer and directory-setup open epochs, not all process FDs or artifact writer FDs.\n')):
        with (output / name).open('xb') as handle: handle.write(data)


def execute_reviewed(expected):
    checks, sources = source_check()
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}', expected) is None or expected != checks['checker_sha256']:
        fail('reviewed_pin')
    if _EXECUTIONS: fail('already_attempted')
    check = LinuxFileCheck(_load(sources))
    _EXECUTIONS.append(check)  # Before OS actions; retained even when result writing fails.
    report = check.execute()
    report['checker_sha256'], report['source_sha256'] = checks['checker_sha256'], checks['source_sha256']
    _outputs(report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--source-check-only', action='store_true')
    modes.add_argument('--execute-reviewed', action='store_true')
    parser.add_argument('--expected-checker-sha256')
    args = parser.parse_args(argv)
    if args.execute_reviewed != (args.expected_checker_sha256 is not None):
        parser.error('Explicit execution and exact checker SHA required together')
    try:
        report = execute_reviewed(args.expected_checker_sha256) if args.execute_reviewed else source_check()[0]
        print(json.dumps(report, indent=2))
        return 0 if report.get('source_check_pass') or report['pass'] else 1
    except Exception as error:
        reason = error.code if type(error) is CheckError else 'io_error' if isinstance(error, OSError) else 'unexpected'
        print(json.dumps({'pass': False, 'evidence': 'HOST_LINUX_FILES_ONLY', 'reason': reason, 'p011_tested': False}))
        return 1


if __name__ == '__main__': sys.exit(main())
