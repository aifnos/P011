"""HOST FakeIO only; no Linux /tmp write, native libc, locks or device."""
import ast
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

BASE = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(BASE / 'host'))
import client_files_linux_check as h

# Read/hash/AST project sources once before fake-OS guards. No fixture import.
CHECKS, SOURCES = h.source_check()
MODULES = h._load(SOURCES)
FILES = MODULES['mta_client_files']
TOKEN = 'a' * 32
BASE_DIR = '/tmp/' + FILES.ROOT_COMPONENT
RUN_DIR = BASE_DIR + '/client-' + TOKEN
PENDING = '/tmp/' + FILES.GLOBAL_PENDING


class Node(object):
    def __init__(self, path, mode, inode, data=b'', uid=0, nlink=1):
        self.path, self.mode, self.inode, self.data = path, mode, inode, data
        self.uid, self.nlink, self.stamp = uid, nlink, 100

    def metadata(self):
        return types.SimpleNamespace(st_dev=1, st_ino=self.inode, st_mode=self.mode,
            st_uid=self.uid, st_gid=0, st_nlink=self.nlink, st_size=len(self.data),
            st_mtime_ns=self.stamp, st_ctime_ns=self.stamp)


class FakeIo(object):
    FLAGS = {'O_RDONLY': 0, 'O_WRONLY': 1, 'O_CREAT': 64, 'O_EXCL': 128,
        'O_DIRECTORY': 65536, 'O_NOFOLLOW': 131072, 'O_CLOEXEC': 524288, 'O_NONBLOCK': 2048}

    def __init__(self, base=False):
        self.nodes, self.handles, self.events, self.close_calls = {}, {}, [], []
        self.next_fd, self.fault, self.keep_open, self.bad_close, self.invalid_fd = 10, None, set(), set(), False
        self.valid, self.fixed_token, self.replaced_final = True, TOKEN, False
        self.add('/', stat.S_IFDIR | 0o755, nlink=2)
        self.add('/tmp', stat.S_IFDIR | 0o1777, nlink=2)
        if base: self.add(BASE_DIR, stat.S_IFDIR | 0o700, nlink=2)

    def add(self, path, mode=stat.S_IFREG | 0o600, data=b'', uid=0, nlink=1):
        node = Node(path, mode, len(self.nodes) + 100, data, uid, nlink)
        self.nodes[path] = node
        return node

    def event(self, action, name):
        self.events.append((action, name))
        if self.fault: self.fault(self, action, name)

    def validate(self):
        if not self.valid: h.fail('unsupported_platform')

    def token(self): return self.fixed_token
    def flag(self, name): return self.FLAGS[name]
    def path(self, parent, name): return self.handles[parent][0].path.rstrip('/') + '/' + name
    def open_root(self, flags): return self._open('/', flags, 0)
    def open_at(self, parent, name, flags, mode=0): return self._open(self.path(parent, name), flags, mode)

    def _open(self, path, flags, mode):
        self.event('open', path)
        if self.invalid_fd: return True
        if flags & self.FLAGS['O_CREAT']:
            if path in self.nodes and flags & self.FLAGS['O_EXCL']: raise OSError(errno.EEXIST, 'synthetic')
            self.add(path, stat.S_IFREG | mode)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'synthetic')
        self.next_fd += 1
        self.handles[self.next_fd] = [self.nodes[path], 0]
        return self.next_fd

    def mkdir_at(self, parent, name):
        path = self.path(parent, name); self.event('mkdir', path)
        if path in self.nodes: raise OSError(errno.EEXIST, 'synthetic')
        self.add(path, stat.S_IFDIR | 0o700, nlink=2)

    def stat_at(self, parent, name):
        path = self.path(parent, name); self.event('stat', path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'synthetic')
        return self.nodes[path].metadata()

    def fstat(self, fd):
        if fd not in self.handles: raise OSError(errno.EBADF, 'synthetic')
        node = self.handles[fd][0]; self.event('fstat', node.path)
        return node.metadata()

    def read(self, fd, count):
        node, offset = self.handles[fd]; self.event('read', node.path)
        data = node.data[offset:offset + count]; self.handles[fd][1] += len(data)
        return data

    def write(self, fd, data):
        node, offset = self.handles[fd]; self.event('write', node.path)
        size = min(31, len(data))
        node.data = node.data[:offset] + data[:size] + node.data[offset + size:]
        self.handles[fd][1] += size; node.stamp += 1
        return size

    def fsync(self, fd): self.event('fsync', self.handles[fd][0].path)

    def rename_at(self, parent, source, target):
        before, after = self.path(parent, source), self.path(parent, target)
        self.event('rename', before); node = self.nodes.pop(before)
        node.path, node.stamp = after, node.stamp + 1
        self.nodes[after] = node
        if self.replaced_final:
            self.add(after, node.mode, node.data)
            self.nodes[after].inode = node.inode + 1000

    def close(self, fd):
        self.close_calls.append(fd)
        if fd in self.bad_close: raise OSError(errno.EIO, 'synthetic')
        if fd not in self.keep_open: del self.handles[fd]


class LinuxFilesCheckTests(unittest.TestCase):
    def setUp(self):
        for name in ('open', 'read', 'write', 'close', 'fsync', 'stat', 'lstat', 'fstat',
                'mkdir', 'rename', 'replace', 'unlink', 'urandom', 'kill', 'waitpid'):
            blocker = patch.object(os, name, side_effect=AssertionError('actual OS forbidden'))
            blocker.start(); self.addCleanup(blocker.stop)
        for name in ('socket.socket', 'ctypes.CDLL', 'subprocess.run', 'subprocess.Popen'):
            blocker = patch(name, side_effect=AssertionError('actual native/network forbidden'))
            blocker.start(); self.addCleanup(blocker.stop)

    def run_fake(self, raw=None, clock=None):
        raw = raw or FakeIo()
        return h.LinuxFileCheck(MODULES, raw, clock or (lambda: 1.0)).execute(), raw

    def test_constructor_and_default_never_execute(self):
        h.LinuxFileCheck(MODULES); h.HostIo(FILES)
        with patch.object(h, 'source_check', return_value=(CHECKS, SOURCES)), \
                patch.object(h, 'execute_reviewed', side_effect=AssertionError('execute forbidden')), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, h.main([]))

    def test_explicit_cli_requires_exact_pin_no_arbitrary_options(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for args in (['--execute-reviewed'], ['--expected-checker-sha256', 'a' * 64], ['--path', RUN_DIR], ['--ttl', '20']):
                with self.assertRaises(SystemExit): h.main(args)
        with patch.object(h, 'source_check', return_value=(CHECKS, SOURCES)), patch.object(h, '_outputs', side_effect=AssertionError('output forbidden')):
            with self.assertRaises(h.CheckError): h.execute_reviewed('b' * 64)

    def test_actual_source_pins_and_python35_no_scope_expansion(self):
        self.assertEqual('d95afa25d82c02592d3e4d5a904a397d0f3c366124f793433131bd3d62342ed3', dict(h.PINS)['mta_client_files'])
        self.assertEqual('ec2d927c50bf2946614990bdd9fe1d69ce5538047573d9a4d885a3914b0f85f1', dict(h.PINS)['mta_p2p_client_init'])
        for name, data in SOURCES:
            self.assertEqual(dict(h.PINS)[name], hashlib.sha256(data).hexdigest())
            ast.parse(data.decode('utf-8'), feature_version=(3, 5))
        self.assertFalse(any(name.startswith('test_') for name in h._load(SOURCES)))

    def test_two_commits_full_readback_and_stale_generation(self):
        report, raw = self.run_fake()
        self.assertTrue(report['pass']); self.assertTrue(report['base_created']); self.assertTrue(report['run_created'])
        self.assertEqual(report['known_fd_count'], report['close_verified_count'])
        self.assertEqual(report['known_fd_count'], report['close_attempt_count']); self.assertEqual({}, raw.handles)
        self.assertEqual(len(raw.close_calls), len(set(raw.close_calls)))
        self.assertEqual(2, sum(action == 'rename' for action, _ in raw.events))
        self.assertTrue(report['stale_rejection_current_unchanged'])
        encoded = raw.nodes[RUN_DIR + '/journal.json'].data
        self.assertEqual('prepared', MODULES['mta_client_journal_codec'].decode_journal(encoded).stage)
        public = json.dumps(report)
        for secret in (TOKEN, '/tmp', 'wlan0', 'station', 'deadline', 'actor', '123.0'):
            self.assertNotIn(secret, public)
        for field in ('p011_tested', 'rf_operations', 'network_operations', 'flock_tested', 'store_tested', 'provider_tested', 'recovery_authority'):
            self.assertIs(report[field], False)

    def test_existing_base_not_recreated_and_run_exclusive_no_retry(self):
        raw = FakeIo(base=True); report, _ = self.run_fake(raw)
        self.assertTrue(report['pass']); self.assertFalse(report['base_created'])
        raw = FakeIo(base=True); raw.add(RUN_DIR, stat.S_IFDIR | 0o700)
        report, _ = self.run_fake(raw); self.assertFalse(report['pass'])
        self.assertEqual(1, sum(action == 'mkdir' and path == RUN_DIR for action, path in raw.events))
        self.assertFalse(any(action == 'rename' for action, _ in raw.events))

    def test_any_global_pending_entry_blocks_before_create(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o700):
            raw = FakeIo(); raw.add(PENDING, mode, b'SYNTHETIC_OLD_UNKNOWN')
            report, _ = self.run_fake(raw)
            self.assertFalse(report['pass']); self.assertEqual('global_pending_blocked', report['failure_reason'])
            self.assertFalse(any(action in ('mkdir', 'write', 'rename') for action, _ in raw.events))
            self.assertEqual(b'SYNTHETIC_OLD_UNKNOWN', raw.nodes[PENDING].data); self.assertEqual({}, raw.handles)

    def test_unsafe_root_tmp_base_owner_mode_symlink_fail(self):
        for path, mode, uid in (('/', stat.S_IFDIR | 0o777, 0), ('/tmp', stat.S_IFDIR | 0o777, 0),
            (BASE_DIR, stat.S_IFDIR | 0o755, 0), (BASE_DIR, stat.S_IFDIR | 0o700, 1000),
            (BASE_DIR, stat.S_IFLNK | 0o700, 0)):
            raw = FakeIo(base=True); raw.nodes[path].mode = mode; raw.nodes[path].uid = uid
            report, _ = self.run_fake(raw); self.assertFalse(report['pass'])
            self.assertFalse(report['first_commit_verified']); self.assertEqual({}, raw.handles)

    def test_pending_appearing_after_setup_preserves_run_without_write(self):
        raw = FakeIo()
        def fault(fs, action, name):
            if action == 'mkdir' and name == RUN_DIR: fs.add(PENDING)
        raw.fault = fault
        report, _ = self.run_fake(raw); self.assertFalse(report['pass'])
        self.assertTrue(report['private_run_retained']); self.assertIn(RUN_DIR, raw.nodes)
        self.assertFalse(any(action == 'write' for action, _ in raw.events)); self.assertEqual({}, raw.handles)

    def test_final_readback_same_bytes_different_inode_rejected(self):
        raw = FakeIo(); raw.replaced_final = True
        report, _ = self.run_fake(raw); self.assertFalse(report['pass'])
        self.assertEqual('readback_changed', report['failure_reason']); self.assertFalse(report['first_commit_verified'])
        self.assertIn(RUN_DIR + '/journal.json', raw.nodes); self.assertEqual({}, raw.handles)

    def test_file_fsync_fail_retains_temp_and_does_not_retry(self):
        raw = FakeIo()
        def fault(fs, action, name):
            if action == 'fsync' and name.endswith('.tmp'): raise OSError(errno.EIO, 'SYNTHETIC_PRIVATE')
        raw.fault = fault
        report, _ = self.run_fake(raw); self.assertFalse(report['pass']); self.assertTrue(report['private_run_retained'])
        self.assertTrue(any(name.endswith('.tmp') for name in raw.nodes))
        self.assertFalse(any(action == 'rename' for action, _ in raw.events)); self.assertEqual({}, raw.handles)
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(report))

    def test_close_unknown_all_others_independent_and_no_reclose(self):
        raw = FakeIo(); raw.keep_open.add(11)
        report, _ = self.run_fake(raw); self.assertFalse(report['pass']); self.assertFalse(report['all_epoch_closed'])
        self.assertFalse(report['final_ebadf_verified']); self.assertEqual(1, raw.close_calls.count(11))
        self.assertEqual({11}, set(raw.handles))
        self.assertEqual(report['known_fd_count'], report['close_attempt_count'])

    def test_interrupted_open_unknown_and_invalid_fd_keep_failure(self):
        raw = FakeIo()
        def fault(fs, action, name):
            if action == 'open' and name == '/tmp': raise KeyboardInterrupt()
        raw.fault = fault
        report, _ = self.run_fake(raw); self.assertFalse(report['pass']); self.assertEqual(1, report['unknown_open_count'])
        self.assertEqual({}, raw.handles)
        raw = FakeIo(); raw.invalid_fd = True
        report, _ = self.run_fake(raw); self.assertFalse(report['pass']); self.assertEqual(1, report['unknown_open_count'])
        self.assertEqual([], raw.close_calls)

    def test_platform_token_and_budget_fail_without_auto_retry(self):
        raw = FakeIo(); raw.valid = False
        report, _ = self.run_fake(raw); self.assertFalse(report['pass']); self.assertEqual([], raw.events)
        raw = FakeIo(); raw.fixed_token = '../SYNTHETIC'
        report, _ = self.run_fake(raw); self.assertFalse(report['pass']); self.assertFalse(report['run_created'])
        values = iter((1.0, 22.0))
        report, raw = self.run_fake(clock=lambda: next(values)); self.assertFalse(report['pass'])
        self.assertFalse(report['run_created']); self.assertEqual({}, raw.handles)

    def assert_second_rejected_unchanged(self, check, raw):
        resources = check._resources
        events, closes, handles, nodes = list(raw.events), list(raw.close_calls), dict(raw.handles), dict(raw.nodes)
        with self.assertRaises(h.CheckError) as caught: check.execute()
        self.assertEqual('already_attempted', caught.exception.code)
        self.assertIs(resources, check._resources)
        self.assertEqual(events, raw.events); self.assertEqual(closes, raw.close_calls)
        self.assertEqual(handles, raw.handles); self.assertEqual(nodes, raw.nodes)

    def test_unknown_close_instance_retains_exact_refs_and_once_gate(self):
        raw = FakeIo(); raw.keep_open.add(11)
        check = h.LinuxFileCheck(MODULES, raw, lambda: 1.0)
        report = check.execute(); self.assertFalse(report['pass'])
        held = check._resources
        self.assertIs(MODULES, held['modules']); self.assertIs(raw, held['raw']); self.assertIs(raw, held['audit'].io)
        self.assertIsInstance(held['files'], FILES.ClientJournalFiles); self.assertEqual(4, len(held['anchors']))
        self.assertIs(held['audit'], held['files']._io); self.assertIn(11, held['audit'].live)
        self.assert_second_rejected_unchanged(check, raw)

    def test_interrupted_open_retains_audit_modules_before_file_object(self):
        raw = FakeIo()
        def fault(fs, action, name):
            if action == 'open' and name == '/tmp': raise KeyboardInterrupt()
        raw.fault = fault; check = h.LinuxFileCheck(MODULES, raw, lambda: 1.0)
        report = check.execute(); self.assertFalse(report['pass'])
        held = check._resources
        self.assertIs(MODULES, held['modules']); self.assertIs(raw, held['raw']); self.assertIsNone(held['files'])
        self.assertTrue(held['audit'].rows[-1]['unknown']); self.assertEqual(1, len(held['anchors']))
        self.assert_second_rejected_unchanged(check, raw)

    def test_invalid_fd_retains_exact_io_and_never_reopens(self):
        raw = FakeIo(); raw.invalid_fd = True
        check = h.LinuxFileCheck(MODULES, raw, lambda: 1.0)
        report = check.execute(); self.assertFalse(report['pass'])
        self.assertIs(raw, check._resources['raw']); self.assertIs(MODULES, check._resources['modules'])
        self.assertTrue(check._resources['audit'].rows[0]['unknown'])
        self.assert_second_rejected_unchanged(check, raw)

    def test_proven_closed_success_releases_resources_but_never_reexecutes(self):
        raw = FakeIo(); check = h.LinuxFileCheck(MODULES, raw, lambda: 1.0)
        report = check.execute(); self.assertTrue(report['pass']); self.assertIsNone(check._resources)
        self.assert_second_rejected_unchanged(check, raw)

    def test_entry_registry_keeps_exact_instance_if_result_writer_fails(self):
        raw = FakeIo(); raw.keep_open.add(11)
        original, registry = h.LinuxFileCheck, []
        def make(modules): return original(modules, raw, lambda: 1.0)
        with patch.object(h, 'source_check', return_value=(CHECKS, SOURCES)), patch.object(h, '_EXECUTIONS', registry), \
                patch.object(h, 'LinuxFileCheck', side_effect=make) as factory, \
                patch.object(h, '_outputs', side_effect=h.CheckError('result_output')) as output:
            with self.assertRaises(h.CheckError) as caught: h.execute_reviewed(CHECKS['checker_sha256'])
            self.assertEqual('result_output', caught.exception.code); self.assertEqual(1, len(registry))
            held = registry[0]._resources; self.assertIs(raw, held['raw']); self.assertIsNotNone(held['files'])
            self.assert_second_rejected_unchanged(registry[0], raw)
            with self.assertRaises(h.CheckError) as caught: h.execute_reviewed(CHECKS['checker_sha256'])
            self.assertEqual('already_attempted', caught.exception.code)
            self.assertEqual(1, factory.call_count); self.assertEqual(1, output.call_count)
            self.assertIs(registry[0]._resources, held)
            with contextlib.redirect_stdout(io.StringIO()): self.assertEqual(0, h.main([]))


if __name__ == '__main__': unittest.main()
