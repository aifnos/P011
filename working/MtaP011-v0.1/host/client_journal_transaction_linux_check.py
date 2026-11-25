"""Fixed HOST Linux isolated journal transaction check; NOT a P011 checker.

Default only checks pinned source. Explicit execution preserves its private
fixture/marker. No RF, process launch, sockets, global pending or cleanup.
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
    ('mta_client_coordination', '6d1b3af860c02046dc53156ecb74ff69423708c919a62fe20e30b9adea223079'),
    ('mta_client_files', 'd95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3'),
    ('mta_client_pending', '7197c04cb96e4fce5c252664199668abe013489cbf3b247f521b3293a7d34d2c'),
    ('mta_client_journal_transaction', '2783f66edbb545aff8adfaa2f80a77fd957c8ba5b365c90907474244b603dcaa'))
REFERENCES = (
    ('tests/test_client_journal_transaction.py', '4c78dbb8c46b165f63801ccabebbd9b670c9602ba7c3fea89016cc17bac06d4a'),
    ('docs/CLIENT_JOURNAL_TRANSACTION_REVIEW.md', '72e1cb2da48f3dee034d4effecbe8db4f511ff8dc3eb339de7c6c40d08bc726d'))
MAX_SOURCE = 262144
CODES = frozenset(('source_pin', 'source_shape', 'source_changed', 'reviewed_pin',
    'unsupported_platform', 'unsupported_io', 'already_attempted', 'unsafe_directory',
    'directory_changed', 'invalid_descriptor', 'open_unknown', 'close_unknown',
    'proc_unknown', 'actor_changed', 'readback_failed', 'binding_unverified',
    'stale_not_rejected', 'retained_marker_unknown', 'component_unknown',
    'io_error', 'interrupted', 'unexpected', 'result_output'))
_EXECUTIONS = []  # One real instance, registered before IO; unknown refs never discarded.


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
        opened = os.fstat(handle.fileno())
        data = handle.read(MAX_SOURCE + 1)
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
        'evidence': 'HOST_SOURCE_ONLY', 'p011_tested': False}, sources


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
        module = types.ModuleType(name)
        module.__file__ = '<pinned-host-client-journal-transaction>'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
        exec(compile(data, module.__file__, 'exec'), module.__dict__)
        loaded[name] = module
    return loaded


def _uint(value):
    return type(value) is int and 0 <= value <= 0x7fffffff


def synthetic(modules, boot):
    """Only boot is actual. Stock/WiFi/IP facts here are explicitly synthetic."""
    core, ip = modules['mta_p2p_client_init'], modules['mta_ip']
    identity = core.Identity(hashlib.sha256(b'HOST_CLIENT_JOURNAL_TRANSACTION_SYNTHETIC_V1').hexdigest())
    actors = tuple(core.Actor(n, 100, path, '1' * 64, ((n, 100, 'S'),))
        for n, path in enumerate(('/usr/bin/Z03', '/usr/bin/control_engine', '/usr/bin/weston'), 101))
    station = core.Origin(0, 1, 1, 'wlan0', 2)
    ipv4 = ip.IpSnapshot((), (), tuple(ip.RuleRecord(p, t) for p, t in ((0, 255), (32766, 254), (32767, 253))))
    return identity, core.Snapshot(boot, core.STOCK_PINS, actors, station, '2' * 64, 2412, (station,), ipv4, (), (), True)


def _proc(modules, observed):
    proc, core = modules['mta_client_proc'], modules['mta_p2p_client_init']
    if (type(observed) is not proc.ProcObservation or observed.kind != 'live_actor' or
            type(observed.actor) is not core.Actor or not observed.actor.live() or
            observed.passes != 2 or type(observed.passes) is not int or
            observed.resource_pending is not False or observed.same_boot is not True or
            type(observed.file_count) is not int or observed.file_count <= 0 or
            observed.closed_count != observed.file_count or type(observed.closed_count) is not int or
            observed.task_count != 1 or type(observed.task_count) is not int or len(observed.actor.tasks) != 1):
        fail('proc_unknown')
    return observed.boot, observed.actor.key()


class LinuxFixture(object):
    """Pure constructor. Only three per-instance open_root overrides are used."""
    def __init__(self, modules):
        self.modules, self.rows, self.anchors = modules, [], []
        self.fixture, self.token, self.ios, self.reader = None, None, None, None
        self.tmp_fd, self.run_fd = None, None
        self.attempted, self.unknown = False, False

    def _open(self, call):
        row = {'fd': None, 'unknown': True, 'attempted': False, 'closed': False}
        self.rows.append(row)  # before the callback, including interrupted results
        try: descriptor = call()
        except OSError as error:
            if type(error.errno) is int and 1 <= error.errno <= 4095: row['unknown'] = False; row['closed'] = True
            else: self.unknown = True
            raise
        except BaseException:
            self.unknown = True
            raise
        row['fd'] = descriptor
        if not _uint(descriptor): self.unknown = True; fail('invalid_descriptor')
        if any(item is not row and item['fd'] == descriptor and not item['closed'] for item in self.rows):
            self.unknown = True; fail('open_unknown')
        row['unknown'] = False
        return row

    def _anchor(self, descriptor, path, private=False, temporary=False):
        coord = self.modules['mta_client_coordination']
        identity = coord._directory(os.fstat(descriptor), private, temporary)
        if coord._directory(os.stat(path, follow_symlinks=False), private, temporary) != identity: fail('directory_changed')
        self.anchors.append((descriptor, path, identity, private, temporary))

    def initialize(self):
        if self.attempted: fail('already_attempted')
        self.attempted = True
        if sys.platform != 'linux' or os.geteuid() != 0: fail('unsupported_platform')
        if os.mkdir not in getattr(os, 'supports_dir_fd', ()): fail('unsupported_io')
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root = self._open(lambda: os.open('/', flags))['fd']; self._anchor(root, '/')
        tmp = self._open(lambda: os.open('tmp', flags, dir_fd=root))['fd']; self._anchor(tmp, '/tmp', temporary=True)
        # mkdtemp is exclusive; no existing fixture or global namespace is adopted.
        self.fixture = tempfile.mkdtemp(prefix='p011-mta-client-journal-host-', dir='/tmp')
        isolated = self._open(lambda: os.open(self.fixture, flags))['fd']; self._anchor(isolated, self.fixture, True)
        os.mkdir('tmp', 0o700, dir_fd=isolated)
        self.tmp_fd = self._open(lambda: os.open('tmp', flags, dir_fd=isolated))['fd']
        self._anchor(self.tmp_fd, self.fixture + '/tmp', True)
        os.mkdir('p011-mta-client-rfinit', 0o700, dir_fd=self.tmp_fd)
        base = self._open(lambda: os.open('p011-mta-client-rfinit', flags, dir_fd=self.tmp_fd))['fd']
        self._anchor(base, self.fixture + '/tmp/p011-mta-client-rfinit', True)
        self.token = os.urandom(16).hex()
        if re.fullmatch('[0-9a-f]{32}', self.token) is None: fail('open_unknown')
        name = 'client-' + self.token
        os.mkdir(name, 0o700, dir_fd=base)
        self.run_fd = self._open(lambda: os.open(name, flags, dir_fd=base))['fd']
        self._anchor(self.run_fd, self.fixture + '/tmp/p011-mta-client-rfinit/' + name, True)
        coord, files, pending = (self.modules[name] for name in ('mta_client_coordination', 'mta_client_files', 'mta_client_pending'))
        self.ios = (coord._LinuxIo(), files._LinuxIo(), pending._LinuxIo())
        for io in self.ios:
            io.open_root = lambda value: os.open(self.fixture, value)
            io.validate()
        self.reader = self.modules['mta_client_proc'].ProcReader(timeout=5.0)
        self.verify()
        return self.token, self.ios, self.reader

    def verify(self, locks=False):
        coord = self.modules['mta_client_coordination']
        for descriptor, path, identity, private, temporary in self.anchors:
            if coord._directory(os.fstat(descriptor), private, temporary) != identity or \
                    coord._directory(os.stat(path, follow_symlinks=False), private, temporary) != identity: fail('directory_changed')
        if locks:
            coord._lock_identity(os.stat('p011-mta-p2p-device.lock', dir_fd=self.tmp_fd, follow_symlinks=False))
            coord._lock_identity(os.stat('journal.lock', dir_fd=self.run_fd, follow_symlinks=False))

    def retained(self, marker):
        """Independent exact original marker bytes/inode after component close."""
        files = self.modules['mta_client_files']
        row = self._open(lambda: os.open('p011-mta-p2p-device.pending', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.tmp_fd))
        try:
            before = files._file_metadata(os.fstat(row['fd']))
            data = b''
            while len(data) <= self.modules['mta_client_pending'].MAX_BYTES:
                chunk = os.read(row['fd'], 4096)
                if not chunk: break
                data += chunk
            if before != marker._metadata or data != marker._data or \
                    files._file_metadata(os.fstat(row['fd'])) != before or \
                    files._file_metadata(os.stat('p011-mta-p2p-device.pending', dir_fd=self.tmp_fd, follow_symlinks=False)) != before:
                fail('retained_marker_unknown')
        finally: self._close(row)
        if not row['closed']: fail('close_unknown')
        return True

    def _close(self, row):
        if row['attempted'] or row['closed']: return
        if row['unknown'] or not _uint(row['fd']): self.unknown = True; return
        row['attempted'] = True
        returned = False
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


def _inventory(transaction):
    rows = list(transaction._coordination._inventory) + list(transaction._files._inventory)
    if transaction._marker is not None and transaction._marker._ticket is not None: rows.append(transaction._marker._ticket)
    verified, count = 0, 0
    for row in rows:
        if row.opening_unknown or row.closed is not True: fail('component_unknown')
        if row.fd is None:
            if row.attempted is not False: fail('component_unknown')
            continue
        if not _uint(row.fd) or row.attempted is not True: fail('component_unknown')
        count += 1
        try: row.io.fstat(row.fd)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.EBADF: verified += 1; continue
        except BaseException: pass
        fail('component_unknown')
    if count <= 0: fail('component_unknown')
    return count, verified


class LinuxTransactionCheck(object):
    """Pure constructor, once-only execution; unknown exact resources retained."""
    def __init__(self, modules, _fixture=None, _clock=None):
        self.modules, self.fixture = modules, _fixture if _fixture is not None else LinuxFixture(modules)
        self.clock = _clock if _clock is not None else time.monotonic
        self.attempted, self.resources, self.private = False, None, {}

    def execute(self):
        if self.attempted: fail('already_attempted')
        self.attempted = True
        self.resources = {'fixture': self.fixture, 'modules': self.modules, 'transaction': None}
        report = {'evidence': 'HOST_LINUX_ISOLATED_JOURNAL_TRANSACTION', 'pass': False,
            'p011_tested': False, 'phone_tested': False, 'rf': False, 'full_store_implemented': False,
            'global_device_namespace_touched': False, 'marker_unlinked': False,
            'network_baseline_authenticated': False, 'synthetic_stock_network_baseline': True,
            'actual_self_proc': False, 'current_initially_none': False, 'first_checkpoint_verified': False,
            'marker_binding_verified': False, 'second_checkpoint_verified': False, 'new_inode_verified': False,
            'stale_receipt_rejected': False, 'fresh_current_verified': False, 'marker_retained_verified': False,
            'marker_component_closed': False, 'files_component_closed': False, 'coordination_component_closed': False,
            'component_closed': False, 'component_fd_count': 0, 'component_ebadf_count': 0,
            'setup_closed': False, 'setup_fd_count': 0, 'setup_ebadf_count': 0,
            'fixture_retained': True, 'failure_stage': 'not_recorded', 'failure_class': 'not_recorded',
            'failure_reason': 'not_recorded', 'errno': 0}
        tx, session, stage = None, None, 'fixture'
        try:
            token, ios, reader = self.fixture.initialize()
            self.resources.update({'ios': ios, 'reader': reader})
            self.private['fixture'] = self.fixture.fixture
            stage = 'proc'
            before = reader.read_self(); self.private['proc_before'] = before
            actor = _proc(self.modules, before)
            identity, baseline = synthetic(self.modules, before.boot)
            report['actual_self_proc'] = True
            transaction = self.modules['mta_client_journal_transaction']
            core, codec = self.modules['mta_p2p_client_init'], self.modules['mta_client_journal_codec']
            tx = transaction.ClientJournalTransaction(token, identity, timeout=10.0,
                _coordination_io=ios[0], _files_io=ios[1], _pending_io=ios[2], _proc_reader=reader, _clock=self.clock)
            self.resources['transaction'] = tx  # retain exact owner before any IO
            stage = 'open'; session = tx.open()
            if tx.current(session) is not None: fail('readback_failed')
            report['current_initially_none'] = True
            self.fixture.verify(True)
            stage = 'prepare'; deadline = self.clock() + 18.0
            first = tx.prepare_initial(session, baseline, deadline)
            self.resources['first'] = first
            if first.canonical.data != codec.encode_journal(first.journal) or first.journal.stage != 'prepared' or first.journal.ready is not False: fail('readback_failed')
            report['first_checkpoint_verified'] = True
            binding = tx._binding.verify(tx._files, tx._epoch)
            if binding._issuer is not tx._marker._issuer or binding.owner_observed is not True or binding.durable_created is not True or binding.resource_pending is not False: fail('binding_unverified')
            report['marker_binding_verified'] = True
            self.fixture.verify(True)
            stage = 'commit'
            second_record = core.Journal(identity, 'prepared', baseline, deadline - 1.0)
            second = tx.commit(session, first, second_record); self.resources['second'] = second
            if second.canonical.data != codec.encode_journal(second_record) or not core._same_journal(second.journal, second_record): fail('readback_failed')
            report['second_checkpoint_verified'] = True
            if second.canonical.metadata[:2] == first.canonical.metadata[:2] or second.canonical._generation != first.canonical._generation + 1: fail('readback_failed')
            report['new_inode_verified'] = True
            stage = 'stale'
            try: tx.commit(session, first, second_record)
            except transaction.JournalTransactionError as error:
                if error.code != 'invalid_receipt': raise
            else: fail('stale_not_rejected')
            report['stale_receipt_rejected'] = True
            stage = 'current'; current = tx.current(session); self.resources['current'] = current
            if current.data != second.canonical.data or current.metadata != second.canonical.metadata or not core._same_journal(current.journal, second_record): fail('readback_failed')
            report['fresh_current_verified'] = True
            after = reader.read_self(); self.private['proc_after'] = after
            if _proc(self.modules, after) != actor: fail('actor_changed')
            self.fixture.verify(True)
            stage = 'close'
        except BaseException as error:
            report.update(_failure(stage, error))
            self.private['traceback'] = traceback.format_exc()
        finally:
            if tx is not None:
                try:
                    closed = tx.close(session)
                    self.resources['close_observation'] = closed
                    if type(closed) is not self.modules['mta_client_journal_transaction'].JournalTransactionCloseObservation or closed._issuer is not tx._issuer: fail('component_unknown')
                    report['marker_component_closed'], report['files_component_closed'], report['coordination_component_closed'] = closed.marker_closed is True, closed.files_closed is True, closed.coordination_closed is True
                    if not closed.complete(): fail('component_unknown')
                    count, verified = _inventory(tx)
                    report['component_closed'], report['component_fd_count'], report['component_ebadf_count'] = True, count, verified
                    if tx._marker is not None:
                        self.fixture.verify(True)
                        report['marker_retained_verified'] = self.fixture.retained(tx._marker) is True
                except BaseException as error:
                    if report['failure_stage'] == 'not_recorded': report.update(_failure('close', error))
                    self.private['close_traceback'] = traceback.format_exc()
            try: report.update(self.fixture.finish())
            except BaseException as error:
                if report['failure_stage'] == 'not_recorded': report.update(_failure('setup_close', error))
                self.private['setup_close_traceback'] = traceback.format_exc()
            if report['component_closed'] and report['setup_closed']: self.resources = None
        required = ('actual_self_proc', 'current_initially_none', 'first_checkpoint_verified', 'marker_binding_verified',
            'second_checkpoint_verified', 'new_inode_verified', 'stale_receipt_rejected', 'fresh_current_verified',
            'marker_retained_verified', 'component_closed', 'setup_closed')
        report['pass'] = report['failure_stage'] == 'not_recorded' and all(report[key] is True for key in required)
        return report


def _failure(stage, error):
    number = getattr(error, 'errno', 0)
    return {'failure_stage': stage,
        'failure_class': 'os_error' if isinstance(error, OSError) else 'value_error' if isinstance(error, ValueError) else 'interrupted' if not isinstance(error, Exception) else 'unexpected',
        'failure_reason': error.code if type(error) is CheckError else 'io_error' if isinstance(error, OSError) else 'interrupted' if not isinstance(error, Exception) else 'unexpected',
        'errno': number if type(number) is int and 0 <= number <= 4095 else 0}


def _private_json(value):
    """Private file only; never print this projection."""
    if isinstance(value, bytes): return {'bytes_hex': value.hex()}
    if isinstance(value, tuple): return [_private_json(v) for v in value]
    if isinstance(value, dict): return dict((str(k), _private_json(v)) for k, v in value.items())
    if hasattr(value, '__slots__'): return dict((key, _private_json(getattr(value, key))) for key in value.__slots__ if not key.startswith('_'))
    if value is None or type(value) in (str, int, float, bool): return value
    return '<private unprojected object>'


def _outputs(report, private):
    root = BASE / 'results'
    if any(path.is_symlink() for path in (root,) + tuple(root.parents)): fail('result_output')
    root.mkdir(mode=0o700, exist_ok=True)
    output = root / ('client-journal-transaction-linux-host-' + datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S') + '-' + os.urandom(8).hex())
    output.mkdir(mode=0o700)
    hidden = output / 'private-raw'; hidden.mkdir(mode=0o700)
    records = ((output / 'result.json', json.dumps(report, indent=2).encode('utf-8')),
        (output / 'README.txt', b'HOST Linux isolated retained-marker journal transaction only.\nFixture retained; no unlink/cleanup, RF, processes, sockets, full Store or P011 validation.\nActual self/boot only; stock/network/IP baseline synthetic. Original-FD proof covers registered component/setup open epochs, not every process FD or result writer.\n'),
        (hidden / 'observations.json', json.dumps(_private_json(private), indent=2).encode('utf-8')))
    for path, data in records:
        # Artifact writer FDs are not included in component/setup proof. The
        # exclusive context owns its handle; no raw-FD -> fdopen transfer here.
        with path.open('xb') as handle: handle.write(data)


def execute_reviewed(expected):
    checks, sources = source_check()
    if type(expected) is not str or re.fullmatch('[0-9a-f]{64}', expected) is None or expected != checks['checker_sha256']: fail('reviewed_pin')
    if _EXECUTIONS: fail('already_attempted')
    check = LinuxTransactionCheck(_load(sources)); _EXECUTIONS.append(check)
    report = check.execute()
    report['checker_sha256'], report['source_sha256'], report['reference_sha256'] = checks['checker_sha256'], checks['source_sha256'], checks['reference_sha256']
    _outputs(report, check.private)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--source-check-only', action='store_true')
    modes.add_argument('--execute-reviewed', action='store_true')
    parser.add_argument('--expected-checker-sha256')
    args = parser.parse_args(argv)
    if args.execute_reviewed != (args.expected_checker_sha256 is not None): parser.error('Explicit execution and exact checker SHA required together')
    try:
        report = execute_reviewed(args.expected_checker_sha256) if args.execute_reviewed else source_check()[0]
        print(json.dumps(report, indent=2))
        return 0 if report.get('source_check_pass') or report['pass'] else 1
    except Exception as error:
        report = _failure('entry', error); report.update({'pass': False, 'evidence': 'HOST_LINUX_ISOLATED_JOURNAL_TRANSACTION', 'p011_tested': False})
        print(json.dumps(report, indent=2)); return 1


if __name__ == '__main__': sys.exit(main())
