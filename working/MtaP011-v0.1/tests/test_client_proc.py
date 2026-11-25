"""HOST fake filesystem only: no actual /proc traversal or mutation."""
import ast
import errno
import hashlib
import importlib.util
import os
import stat
import sys
import types
import unittest
from unittest import mock

RUNTIME = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime'))
sys.path.insert(0, RUNTIME)
import mta_client_proc as p
import mta_p2p_client_init as c

BOOT = '12345678-1234-1234-1234-123456789abc'
BOOT_PATH = '/proc/sys/kernel/random/boot_id'


def stat_data(pid=42, start=100, state='S', comm=b'host ) fixture', flags=0,
              threads=1, ticks=7):
    fields = [b'0'] * 50
    fields[0] = state.encode('ascii')
    fields[1] = b'1'
    fields[6] = str(flags).encode('ascii')
    fields[11] = str(ticks).encode('ascii')
    fields[17] = str(threads).encode('ascii')
    fields[19] = str(start).encode('ascii')
    return str(pid).encode('ascii') + b' (' + comm + b') ' + b' '.join(fields) + b'\n'


def meta(mode, inode=1, nlink=1):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode,
                                 st_uid=0, st_gid=0, st_nlink=nlink)


class FakeFs(object):
    O_RDONLY, O_NOFOLLOW, O_CLOEXEC = 0, 131072, 524288

    def __init__(self, tasks=(42,), cmd=b'/private/fixture\0argument\0', state='S', flags=0, threads=None):
        count = len(tasks) if threads is None else threads
        self.files = {BOOT_PATH: BOOT.encode('ascii') + b'\n',
                      '/proc/42/stat': stat_data(42, state=state, flags=flags, threads=count),
                      '/proc/42/cmdline': cmd}
        self.dirs = {'/proc', '/proc/42', '/proc/42/task'}
        self.links = {'/proc/42/exe': '/private/fixture'}
        for tid in tasks:
            self.dirs.add('/proc/42/task/' + str(tid))
            self.dirs.add('/proc/' + str(tid))
            data = stat_data(tid, start=100 if tid == 42 else 101,
                             state=state, flags=flags, threads=count)
            self.files['/proc/42/task/' + str(tid) + '/stat'] = data
            self.files['/proc/' + str(tid) + '/stat'] = data
        self.fd, self.live, self.closed = 10, {}, []
        self.opens, self.operations, self.call_counts = [], [], {}
        self.hook, self.fail = None, {}
        self.metadata = {}
        self.close_error, self.keep_after_close = None, False
        self.read_error, self.read_result = None, None
        self.directory_override = None
        self.chunk_limit = None

    def event(self, operation, path):
        self.operations.append((operation, path))
        key = operation, path
        self.call_counts[key] = self.call_counts.get(key, 0) + 1
        if self.hook:
            self.hook(self, operation, path, self.call_counts[key])
        if key in self.fail:
            raise self.fail[key]

    def inode(self, path):
        return 100 + sum((i + 1) * ord(ch) for i, ch in enumerate(path))

    def lstat(self, path):
        self.event('lstat', path)
        if path in self.metadata:
            return self.metadata[path]
        if path in self.dirs:
            return meta(stat.S_IFDIR | 0o555, self.inode(path), 2)
        if path in self.links:
            return meta(stat.S_IFLNK | 0o777, self.inode(path))
        if path in self.files:
            return meta(stat.S_IFREG | 0o444, self.inode(path))
        raise OSError(errno.ENOENT, 'HOST missing private fixture')

    def open(self, path, flags):
        self.event('open', path)
        if flags != self.O_RDONLY | self.O_NOFOLLOW | self.O_CLOEXEC:
            raise AssertionError('HOST unsafe open flags')
        if path not in self.files:
            raise OSError(errno.ENOENT, 'HOST missing private fixture')
        self.fd += 1
        self.live[self.fd] = [path, self.files[path], 0]
        self.opens.append((path, flags, self.fd))
        return self.fd

    def fstat(self, fd):
        if fd not in self.live:
            raise OSError(errno.EBADF, 'HOST closed private descriptor')
        path = self.live[fd][0]
        self.event('fstat', path)
        return self.metadata.get(path, meta(stat.S_IFREG | 0o444, self.inode(path)))

    def read(self, fd, count):
        path, data, at = self.live[fd]
        self.event('read', path)
        if self.read_error:
            raise self.read_error
        if self.read_result is not None:
            return self.read_result
        count = min(count, self.chunk_limit) if self.chunk_limit else count
        value = data[at:at + count]
        self.live[fd][2] += len(value)
        return value

    def close(self, fd):
        self.closed.append(fd)
        if self.close_error:
            raise self.close_error
        if not self.keep_after_close:
            del self.live[fd]

    def listdir(self, path):
        self.event('listdir', path)
        if self.directory_override is not None:
            return self.directory_override
        prefix = path + '/'
        return sorted(name[len(prefix):] for name in self.dirs
                      if name.startswith(prefix) and '/' not in name[len(prefix):])

    def readlink(self, path):
        self.event('readlink', path)
        if path not in self.links:
            raise OSError(errno.ENOENT, 'HOST missing private executable')
        return self.links[path]

    def getpid(self):
        self.event('getpid', '/proc/self')
        return 42

    def remove_actor(self):
        self.dirs = {'/proc'}
        self.files = {BOOT_PATH: BOOT.encode('ascii') + b'\n'}
        self.links = {}


def expected(tasks=((42, 100, 'S'),), start=100, exe='/private/fixture', cmd=b'/private/fixture\0argument\0'):
    return c.Actor(42, start, exe, hashlib.sha256(cmd).hexdigest(), tasks)


class ProcTests(unittest.TestCase):
    def setUp(self):
        self.patches = []
        for name in ('open', 'read', 'close', 'fstat', 'lstat', 'listdir', 'readlink', 'kill', 'waitpid'):
            patcher = mock.patch.object(os, name, side_effect=AssertionError('actual OS/proc forbidden'))
            patcher.start()
            self.addCleanup(patcher.stop)
        socket_patch = mock.patch('socket.socket', side_effect=AssertionError('actual socket forbidden'))
        socket_patch.start()
        self.addCleanup(socket_patch.stop)

    def reader(self, fs=None, **kwargs):
        fs = FakeFs() if fs is None else fs
        return p.ProcReader(_fs=fs, _clock=lambda: 1.0, **kwargs), fs

    def observe(self, fs=None, reason='live_actor', **kwargs):
        reader, fs = self.reader(fs)
        result = reader.read_actor(42, **kwargs)
        self.assertEqual(reason, result.reason)
        self.assertFalse(result.reap_complete)
        self.assertTrue(result.public_status()['files_closed'])
        self.assertEqual(len(fs.opens), len(fs.closed))
        self.assertEqual(len(fs.closed), len(set(fs.closed)))
        return result, reader, fs

    def test_constructor_import_no_io(self):
        fs = FakeFs()
        reader = p.ProcReader(_fs=fs)
        self.assertEqual([], fs.operations)
        spec = importlib.util.spec_from_file_location('host_proc_pure', os.path.join(RUNTIME, 'mta_client_proc.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.ProcReader(_fs=fs)
        self.assertEqual([], fs.operations)
        self.assertEqual([], reader._fd_refs)

    def test_python35_ast_and_no_mutation_apis(self):
        with open(os.path.join(RUNTIME, 'mta_client_proc.py'), encoding='utf-8') as stream:
            source = stream.read()
        parsed = ast.parse(source, feature_version=(3, 5))
        names = {n.attr for n in ast.walk(parsed) if isinstance(n, ast.Attribute)}
        self.assertFalse({'kill', 'waitpid', 'fork', 'socket', 'mkdir', 'unlink', 'chmod', 'flock'} & names)
        self.assertFalse(hasattr(p.ProcReader(), 'read_path'))

    def test_stat_spaces_parentheses_and_newline_comm(self):
        for comm in (b'one two', b'a ) b ( c)', b'a\nb', b'', b') () '):
            result = p.parse_stat(stat_data(comm=comm), 42)
            self.assertEqual(comm, result.comm)
            self.assertEqual((42, 100, 'S', 0), (result.pid, result.start, result.state, result.flags))

    def test_stat_exact_pid_fields_numeric_bounds(self):
        good = stat_data()
        bad = (good.replace(b'42 (', b'043 ('), good[:-1], good + b'0\n',
               good.replace(b') S ', b') Q '), b'42 (x) S 1\n', b'42 (x)\0 S 1\n',
               stat_data(start=0), stat_data(start=2 ** 64), stat_data(flags=2 ** 32),
               stat_data(threads=129), stat_data(comm=b'x' * 16),
               good.replace(b') S 1 ', b') S 01 '), good.replace(b') S 1 ', b') S +1 '))
        for raw in bad:
            with self.subTest(size=len(raw)):
                with self.assertRaises(p.ProcReadError):
                    p.parse_stat(raw, 42)
        with self.assertRaises(p.ProcReadError):
            p.parse_stat(good, True)

    def test_stat_cpu_ticks_not_identity_but_start_flags_comm_are(self):
        first = p.parse_stat(stat_data(ticks=1), 42)
        later = p.parse_stat(stat_data(ticks=99999), 42)
        self.assertEqual(first.stable_key(), later.stable_key())
        for raw in (stat_data(start=101), stat_data(flags=1), stat_data(comm=b'different')):
            self.assertNotEqual(first.stable_key(), p.parse_stat(raw, 42).stable_key())

    def test_live_actor_two_pass_full_tasks_exact_current_core(self):
        result, _, fs = self.observe(FakeFs(tasks=(42, 43)))
        self.assertEqual(2, result.passes)
        self.assertEqual(BOOT, result.boot)
        self.assertTrue(result.same_boot)
        self.assertTrue(result.actor.live())
        self.assertEqual(((42, 100, 'S'), (43, 101, 'S')), result.actor.tasks)
        self.assertEqual(hashlib.sha256(b'/private/fixture\0argument\0').hexdigest(), result.actor.argv_sha)
        self.assertEqual(4, fs.call_counts[('open', BOOT_PATH)])
        self.assertEqual(4, fs.call_counts[('listdir', '/proc/42/task')])
        self.assertFalse(result.pid_path_absent)

    def test_read_self_uses_actual_provider_getpid_without_executor_proof(self):
        reader, fs = self.reader()
        result = reader.read_self()
        self.assertEqual('live_actor', result.kind)
        self.assertEqual(1, fs.call_counts[('getpid', '/proc/self')])
        self.assertFalse(hasattr(result, 'same_ofd_verified'))
        self.assertNotIsInstance(result, c.ExecutorProof)

    def test_raw_private_and_public_never_leak_identifiers(self):
        result, _, _ = self.observe()
        self.assertTrue(any(row.data == b'/private/fixture\0argument\0' for row in result.raw))
        self.assertNotIn('/private', repr(result))
        self.assertNotIn('/private', repr(result.raw))
        self.assertNotIn(BOOT, repr(result.public_status()))
        self.assertEqual({'kind', 'reason', 'stage', 'actor_available', 'pid_path_absent',
            'same_boot', 'observation_count', 'task_count', 'remaining_task_count',
            'file_count', 'files_closed', 'resource_pending', 'reap_complete'}, set(result.public_status()))
        with self.assertRaises(AttributeError):
            result.reap_complete = True

    def test_expected_actor_and_pid_reuse_distinguished(self):
        self.observe(expected=expected())
        self.observe(reason='pid_reused', expected=expected(start=99, tasks=((42, 99, 'S'),)))
        self.observe(reason='expected_actor_changed', expected=expected(exe='/private/other'))
        self.observe(reason='expected_actor_changed', expected=expected(cmd=b'other\0'))

    def test_pid_reused_within_first_pass(self):
        fs = FakeFs()
        def change(fs, op, path, count):
            if op == 'open' and path == '/proc/42/stat' and count == 2:
                fs.files[path] = stat_data(start=101)
        fs.hook = change
        result, _, _ = self.observe(fs, 'pid_reused')
        self.assertEqual(0, result.passes)
        self.assertIsNone(result.actor)

    def test_pid_reused_between_passes(self):
        fs = FakeFs()
        def change(fs, op, path, count):
            if op == 'open' and path == BOOT_PATH and count == 3:
                fs.files['/proc/42/stat'] = stat_data(start=101)
                fs.files['/proc/42/task/42/stat'] = stat_data(start=101)
        fs.hook = change
        result, _, _ = self.observe(fs, 'pid_reused')
        self.assertEqual(2, result.passes)

    def test_task_reused_between_passes(self):
        fs = FakeFs(tasks=(42, 43))
        def change(fs, op, path, count):
            if op == 'open' and path == BOOT_PATH and count == 3:
                fs.files['/proc/42/task/43/stat'] = stat_data(43, start=102, threads=2)
        fs.hook = change
        self.observe(fs, 'task_reused')

    def test_boot_change_in_pass_and_between_passes(self):
        for when in (2, 3):
            fs = FakeFs()
            def change(fs, op, path, count):
                if op == 'open' and path == BOOT_PATH and count == when:
                    fs.files[path] = b'22345678-1234-1234-1234-123456789abc\n'
            fs.hook = change
            self.observe(fs, 'boot_changed')

    def test_cpu_time_and_live_scheduling_changes_do_not_forge_identity_change(self):
        fs = FakeFs()
        def change(fs, op, path, count):
            if op == 'open' and path.endswith('/stat'):
                fs.files[path] = stat_data(ticks=count * 101, state='R' if count % 2 else 'S')
        fs.hook = change
        result, _, _ = self.observe(fs)
        self.assertTrue(result.actor.live())

    def test_cmdline_and_executable_change_between_passes(self):
        for field in ('cmd', 'exe'):
            fs = FakeFs()
            def change(fs, op, path, count):
                if op == 'open' and path == BOOT_PATH and count == 3:
                    if field == 'cmd':
                        fs.files['/proc/42/cmdline'] = b'/private/other\0'
                    else:
                        fs.links['/proc/42/exe'] = '/private/other'
            fs.hook = change
            self.observe(fs, 'observation_changed')

    def test_empty_user_zombie_not_actor_or_reap_even_zero_threads_stat(self):
        for threads in (1, 0):
            fs = FakeFs(cmd=b'', state='Z', threads=threads)
            del fs.links['/proc/42/exe']
            result, _, _ = self.observe(fs, 'empty_user_zombie')
            self.assertEqual('opaque', result.kind)
            self.assertIsNone(result.actor)
            self.assertFalse(result.pid_path_absent)
            self.assertFalse(result.reap_complete)

    def test_empty_kernel_not_actor_or_reap_including_parked(self):
        for state in ('S', 'P', 'I'):
            fs = FakeFs(cmd=b'', state=state, flags=p.PF_KTHREAD)
            del fs.links['/proc/42/exe']
            result, _, _ = self.observe(fs, 'empty_kernel')
            self.assertIsNone(result.actor)
            self.assertFalse(result.pid_path_absent)

    def test_empty_unknown_and_nonempty_kernel_or_parked_are_opaque(self):
        self.observe(FakeFs(cmd=b''), 'empty_user_unknown')
        self.observe(FakeFs(flags=p.PF_KTHREAD), 'kernel_cmdline_unexpected')
        self.observe(FakeFs(state='P'), 'unsupported_actor_state')

    def test_any_dead_task_blocks_live_actor(self):
        fs = FakeFs(tasks=(42, 43))
        fs.files['/proc/42/task/43/stat'] = stat_data(43, start=101, state='Z', threads=2)
        result, _, _ = self.observe(fs, 'nonlive_task')
        self.assertIsNone(result.actor)

    def test_task_kernel_flag_mismatch_refuses(self):
        fs = FakeFs(tasks=(42, 43))
        fs.files['/proc/42/task/43/stat'] = stat_data(43, start=101, flags=p.PF_KTHREAD, threads=2)
        self.observe(fs, 'task_kernel_mismatch')

    def test_task_names_duplicates_budget_leader_and_count(self):
        cases = ((['42', '42'], 'duplicate_task'), (['042'], 'invalid_directory_entry'),
                 (['../43'], 'invalid_directory_entry'), (['43'], 'task_set_incomplete'),
                 ([], 'task_budget'), (['42'] * 129, 'task_budget'),
                 ([True], 'invalid_directory_entry'), (['2147483648'], 'invalid_directory_entry'))
        for names, reason in cases:
            fs = FakeFs()
            fs.directory_override = names
            self.observe(fs, reason)
        self.observe(FakeFs(threads=2), 'task_set_incomplete')

    def test_task_set_changes_during_listing_or_between_passes(self):
        fs = FakeFs()
        def add(fs, op, path, count):
            if op == 'listdir' and count == 2:
                fs.dirs.add('/proc/42/task/43')
        fs.hook = add
        self.observe(fs, 'task_directory_changed')
        fs = FakeFs()
        def add_pass(fs, op, path, count):
            if op == 'open' and path == BOOT_PATH and count == 3:
                fs.dirs.add('/proc/42/task/43')
                fs.files['/proc/42/stat'] = stat_data(threads=2)
                fs.files['/proc/42/task/42/stat'] = stat_data(threads=2)
                fs.files['/proc/42/task/43/stat'] = stat_data(43, start=101, threads=2)
        fs.hook = add_pass
        self.observe(fs, 'task_set_changed')

    def test_task_disappeared_and_permission_never_mean_absent(self):
        for code, reason in ((errno.ENOENT, 'record_disappeared'),
                             (errno.ESRCH, 'record_disappeared'),
                             (errno.EACCES, 'permission_denied'), (errno.EIO, 'read_errno')):
            fs = FakeFs(tasks=(42, 43))
            fs.fail[('open', '/proc/42/task/43/stat')] = OSError(code, 'private detail')
            result, _, _ = self.observe(fs, reason)
            self.assertFalse(result.pid_path_absent)

    def test_missing_pid_read_actor_not_absence_proof(self):
        fs = FakeFs()
        fs.remove_actor()
        result, _, _ = self.observe(fs, 'pid_missing')
        self.assertFalse(result.pid_path_absent)

    def test_absence_same_boot_pid_task_tree_and_recorded_tid_twice(self):
        fs = FakeFs()
        fs.remove_actor()
        reader, fs = self.reader(fs)
        result = reader.read_absence(expected(), BOOT)
        self.assertEqual('absence', result.kind)
        self.assertEqual('absence_observed', result.reason)
        self.assertTrue(result.pid_path_absent)
        self.assertTrue(result.same_boot)
        self.assertEqual(2, result.passes)
        self.assertEqual((), result.remaining_tasks)
        self.assertFalse(result.reap_complete)
        self.assertNotIsInstance(result, c.ExitProof)
        self.assertEqual(4, fs.call_counts[('lstat', '/proc/42')])

    def test_absence_pid_present_and_pid_reuse_are_not_reap(self):
        reader, _ = self.reader()
        result = reader.read_absence(expected(), BOOT)
        self.assertEqual('pid_present', result.reason)
        self.assertFalse(result.pid_path_absent)
        fs = FakeFs()
        fs.files['/proc/42/stat'] = stat_data(start=101)
        reader, _ = self.reader(fs)
        result = reader.read_absence(expected(), BOOT)
        self.assertEqual('pid_reused', result.reason)
        self.assertEqual('opaque', result.kind)
        self.assertFalse(result.reap_complete)

    def test_absence_recorded_task_exists_even_without_leader(self):
        fs = FakeFs()
        fs.remove_actor()
        fs.dirs.add('/proc/43')
        fs.files['/proc/43/stat'] = stat_data(43, start=101)
        reader, _ = self.reader(fs)
        actor = expected(tasks=((42, 100, 'S'), (43, 101, 'S')))
        result = reader.read_absence(actor, BOOT)
        self.assertEqual('task_present', result.reason)
        self.assertEqual((43,), result.remaining_tasks)
        self.assertEqual('opaque', result.kind)

    def test_absence_unknown_permission_boot_and_tids_not_zero(self):
        for code in (errno.EPERM, errno.EACCES, errno.EIO):
            fs = FakeFs()
            fs.remove_actor()
            fs.fail[('lstat', '/proc/42')] = OSError(code, 'private')
            reader, _ = self.reader(fs)
            result = reader.read_absence(expected(), BOOT)
            self.assertEqual('unknown', result.kind)
            self.assertFalse(result.pid_path_absent)
        fs = FakeFs()
        fs.remove_actor()
        reader, _ = self.reader(fs)
        result = reader.read_absence(expected(), '22345678-1234-1234-1234-123456789abc')
        self.assertEqual('boot_changed', result.reason)

    def test_absence_pid_appears_between_passes(self):
        fs = FakeFs()
        fs.remove_actor()
        def appear(fs, op, path, count):
            if op == 'open' and path == BOOT_PATH and count == 3:
                fs.dirs.add('/proc/42')
                fs.files['/proc/42/stat'] = stat_data()
        fs.hook = appear
        reader, _ = self.reader(fs)
        result = reader.read_absence(expected(), BOOT)
        self.assertEqual('observation_changed', result.reason)
        self.assertFalse(result.pid_path_absent)

    def test_cmdline_nul_length_and_boot_format_strict(self):
        for cmd in (b'no terminator', b'\0', b'x' * (p.MAX_CMDLINE + 1)):
            self.observe(FakeFs(cmd=cmd), 'read_budget' if len(cmd) > p.MAX_CMDLINE else 'invalid_cmdline')
        for boot in (BOOT.encode(), BOOT.upper().encode() + b'\n', b'x\n', b'\xff' * 36 + b'\n'):
            fs = FakeFs()
            fs.files[BOOT_PATH] = boot
            self.observe(fs, 'invalid_boot_id')

    def test_nonutf8_args_and_empty_secondary_arg_hashed_as_exact_bytes(self):
        cmd = b'/private/fixture\0\xff\0\0'
        result, _, _ = self.observe(FakeFs(cmd=cmd))
        self.assertEqual(hashlib.sha256(cmd).hexdigest(), result.actor.argv_sha)

    def test_exe_missing_deleted_noncanonical_and_symlink_changes(self):
        fs = FakeFs()
        fs.links.clear()
        self.observe(fs, 'executable_missing')
        for exe in ('relative', '/private/../bad', '/private//bad', '/private/deleted (deleted)', '/private/\n'):
            fs = FakeFs()
            fs.links['/proc/42/exe'] = exe
            self.observe(fs, 'invalid_executable')
        fs = FakeFs()
        def change(fs, op, path, count):
            if op == 'readlink':
                fs.metadata[path] = meta(stat.S_IFLNK | 0o777, 999)
        fs.hook = change
        self.observe(fs, 'executable_changed')

    def test_proc_root_pid_task_must_real_directories_not_symlinks(self):
        for path in ('/proc', '/proc/42', '/proc/42/task', '/proc/42/task/42'):
            fs = FakeFs()
            fs.metadata[path] = meta(stat.S_IFLNK | 0o777)
            self.observe(fs, 'invalid_directory_type')

    def test_regular_nlink_and_fstat_change_refuse_close_once(self):
        for mode, links in ((stat.S_IFIFO | 0o444, 1), (stat.S_IFLNK | 0o777, 1),
                            (stat.S_IFREG | 0o444, 2)):
            fs = FakeFs()
            fs.metadata[BOOT_PATH] = meta(mode, nlink=links)
            self.observe(fs, 'invalid_regular_file')
        fs = FakeFs()
        def change(fs, op, path, count):
            if op == 'fstat' and path == BOOT_PATH and count == 2:
                fs.metadata[path] = meta(stat.S_IFREG | 0o444, 999)
        fs.hook = change
        self.observe(fs, 'file_changed')

    def test_partial_read_raw_retained_on_errno_or_interrupt(self):
        for error, reason in ((OSError(errno.EIO, 'private'), 'read_errno'),
                              (KeyboardInterrupt(), 'interrupted')):
            fs = FakeFs()
            def stop(fs, op, path, count):
                if op == 'read' and path == BOOT_PATH and count == 2:
                    raise error
            fs.hook = stop
            result, _, _ = self.observe(fs, reason)
            self.assertTrue(any(row.data == BOOT.encode() + b'\n' for row in result.raw))

    def test_close_failure_retains_exact_fd_fs_and_blocks_future_reads(self):
        for signal in (OSError(errno.EIO, 'private'), KeyboardInterrupt()):
            fs = FakeFs()
            fs.close_error = signal
            reader, _ = self.reader(fs)
            result = reader.read_actor(42)
            self.assertEqual('file_close_unverified', result.reason)
            self.assertTrue(result.resource_pending)
            self.assertFalse(result.public_status()['files_closed'])
            self.assertIs(reader._fd_refs[0][0], fs)
            self.assertEqual(1, len(fs.closed))
            with self.assertRaises(p.ProcReadError):
                reader.read_actor(42)

    def test_close_return_without_ebadf_is_pending(self):
        fs = FakeFs()
        fs.keep_after_close = True
        reader, _ = self.reader(fs)
        result = reader.read_actor(42)
        self.assertEqual('file_close_unverified', result.reason)
        self.assertTrue(result.resource_pending)

    def test_raw_record_memoryerror_and_interrupt_still_close_exact_known_fd(self):
        for signal, reason in ((MemoryError(), 'unexpected_read_error'),
                               (KeyboardInterrupt(), 'interrupted')):
            fs = FakeFs(); reader, _ = self.reader(fs)
            original = reader._record
            def fail_record(path, data, metadata=()):
                if path == BOOT_PATH and type(data) is bytes:
                    raise signal
                return original(path, data, metadata)
            reader._record = fail_record
            result = reader.read_actor(42)
            self.assertEqual(reason, result.reason)
            self.assertEqual('unknown', result.kind); self.assertIsNone(result.actor)
            self.assertEqual(1, result.file_count); self.assertEqual(1, result.closed_count)
            self.assertTrue(result.public_status()['files_closed'])
            self.assertFalse(result.resource_pending)
            self.assertEqual([fs.opens[0][2]], fs.closed); self.assertEqual({}, fs.live)
            self.assertIsNone(reader._open_attempt)
            self.assertIs(reader._fd_refs[0][0], fs)

    def test_raw_record_failure_and_close_failure_keep_owner_pending(self):
        fs = FakeFs(); fs.close_error = OSError(errno.EIO, 'HOST private close')
        reader, _ = self.reader(fs); original = reader._record
        def fail_record(path, data, metadata=()):
            if path == BOOT_PATH and type(data) is bytes:
                raise MemoryError()
            return original(path, data, metadata)
        reader._record = fail_record
        result = reader.read_actor(42)
        self.assertEqual('file_close_unverified', result.reason)
        self.assertTrue(result.resource_pending); self.assertEqual(1, len(fs.closed))
        self.assertIs(reader._open_attempt['fs'], fs)
        self.assertEqual(fs.opens[0][2], reader._open_attempt['descriptor'])
        with self.assertRaises(p.ProcReadError):
            reader.read_actor(42)
        self.assertEqual(1, len(fs.opens)); self.assertEqual(1, len(fs.closed))

    def test_unreturned_open_memoryerror_or_interrupt_retains_exact_attempt(self):
        for signal, reason in ((MemoryError(), 'unexpected_read_error'),
                               (KeyboardInterrupt(), 'interrupted')):
            for allocated in (False, True):
                fs = FakeFs(); actual_open = fs.open
                def unreturned(path, flags):
                    if allocated:
                        actual_open(path, flags)
                    raise signal
                fs.open = unreturned
                reader, _ = self.reader(fs)
                result = reader.read_actor(42)
                self.assertEqual(reason, result.reason); self.assertTrue(result.resource_pending)
                self.assertFalse(result.public_status()['files_closed'])
                self.assertEqual(0, result.file_count); self.assertEqual([], fs.closed)
                held = reader._open_attempt
                self.assertIs(held['fs'], fs); self.assertEqual(BOOT_PATH, held['path'])
                self.assertEqual(fs.O_NOFOLLOW | fs.O_CLOEXEC, held['flags'])
                self.assertIsNone(held['descriptor']); self.assertFalse(held['returned'])
                with self.assertRaises(p.ProcReadError):
                    reader.read_actor(42)
                self.assertIs(held, reader._open_attempt)
                self.assertEqual(int(allocated), len(fs.opens)); self.assertEqual([], fs.closed)

    def test_registration_failure_closes_once_but_does_not_erase_unknown(self):
        class FailedRefs(list):
            def __init__(self, appended, signal):
                list.__init__(self); self.appended, self.signal = appended, signal
            def append(self, value):
                if self.appended:
                    list.append(self, value)
                raise self.signal
        class Reader(p.ProcReader):
            def _begin(self):
                p.ProcReader._begin(self)
                self._fd_refs = refs
        for signal in (MemoryError(), KeyboardInterrupt()):
            for appended in (False, True):
                refs = FailedRefs(appended, signal); fs = FakeFs()
                reader = Reader(_fs=fs, _clock=lambda: 1.0)
                result = reader.read_actor(42)
                self.assertEqual('unknown', result.kind); self.assertTrue(result.resource_pending)
                self.assertFalse(result.public_status()['files_closed'])
                self.assertEqual(1, result.file_count); self.assertEqual(1, result.closed_count)
                self.assertEqual([fs.opens[0][2]], fs.closed); self.assertEqual({}, fs.live)
                held = reader._open_attempt
                self.assertIs(held['fs'], fs); self.assertEqual(fs.opens[0][2], held['descriptor'])
                self.assertTrue(held['returned']); self.assertFalse(held['registered'])
                with self.assertRaises(p.ProcReadError):
                    reader.read_actor(42)
                self.assertIs(held, reader._open_attempt); self.assertIs(refs, reader._fd_refs)
                self.assertEqual(1, len(fs.closed)); self.assertEqual(1, len(fs.opens))

    def test_definite_open_oserror_does_not_fake_absence_or_pending_creation(self):
        for code, reason in ((errno.ENOENT, 'record_disappeared'),
                              (errno.EACCES, 'permission_denied'), (errno.EIO, 'read_errno')):
            fs = FakeFs(); fs.fail[('open', BOOT_PATH)] = OSError(code, 'HOST private error')
            result, reader, _ = self.observe(fs, reason)
            self.assertFalse(result.pid_path_absent); self.assertFalse(result.resource_pending)
            self.assertIsNone(reader._open_attempt); self.assertEqual([], fs.opens)

    def test_fd_reused_after_close_is_pending_without_closing_replacement(self):
        fs = FakeFs(); actual_close = fs.close
        def reused(fd):
            actual_close(fd)
            fs.live[fd] = ['/HOST/foreign', b'', 0]
        fs.close = reused
        reader, _ = self.reader(fs)
        result = reader.read_actor(42)
        self.assertEqual('file_close_unverified', result.reason)
        self.assertTrue(result.resource_pending)
        self.assertEqual([fs.opens[0][2]], fs.closed)
        self.assertEqual('/HOST/foreign', fs.live[fs.opens[0][2]][0])
        with self.assertRaises(p.ProcReadError):
            reader.read_actor(42)
        self.assertEqual(1, len(fs.closed))

    def test_close_readback_requires_strict_ebadf_not_float_or_bool_errno(self):
        for value in (float(errno.EBADF), True, errno.EIO):
            fs = FakeFs(); actual_fstat = fs.fstat
            def wrong_errno(fd):
                if fd not in fs.live:
                    error = OSError(errno.EBADF, 'HOST private readback')
                    error.errno = value
                    raise error
                return actual_fstat(fd)
            fs.fstat = wrong_errno
            reader, _ = self.reader(fs)
            result = reader.read_actor(42)
            self.assertEqual('file_close_unverified', result.reason)
            self.assertTrue(result.resource_pending); self.assertEqual(1, len(fs.closed))

    def test_file_total_budget_and_invalid_read_result(self):
        with mock.patch.object(p, 'MAX_TOTAL', 36):
            self.observe(reason='total_budget')
        with mock.patch.object(p, 'MAX_OPEN_FILES', 0):
            self.observe(reason='file_budget')
        for value in ('not bytes', b'x' * 4097):
            fs = FakeFs()
            fs.read_result = value
            self.observe(fs, 'invalid_read_result')

    def test_chunked_reads_exact_raw_and_fd_flags(self):
        fs = FakeFs()
        fs.chunk_limit = 3
        result, _, _ = self.observe(fs)
        self.assertTrue(any(row.data == stat_data() for row in result.raw))
        self.assertTrue(all(flags == fs.O_NOFOLLOW | fs.O_CLOEXEC for _, flags, _ in fs.opens))

    def test_deadline_clock_invalid_regression_and_overflow_safe(self):
        for timeout in (True, 0, 11, float('nan'), 10 ** 1000):
            with self.assertRaises(p.ProcReadError):
                p.ProcReader(timeout=timeout)
        for clock in (lambda: float('nan'), lambda: 10 ** 1000):
            reader = p.ProcReader(_fs=FakeFs(), _clock=clock)
            result = reader.read_actor(42)
            self.assertEqual('invalid_clock', result.reason)
            self.assertFalse(result.resource_pending)
        ticks = iter((1.0, 0.9))
        result = p.ProcReader(_fs=FakeFs(), _clock=lambda: next(ticks)).read_actor(42)
        self.assertEqual('clock_regressed', result.reason)
        ticks = iter((1.0, 20.0))
        result = p.ProcReader(_fs=FakeFs(), _clock=lambda: next(ticks)).read_actor(42)
        self.assertEqual('deadline', result.reason)

    def test_invalid_api_inputs_do_not_touch_fake_filesystem(self):
        reader, fs = self.reader()
        for pid in (True, 0, -1, 2 ** 31, '42'):
            with self.assertRaises(p.ProcReadError):
                reader.read_actor(pid)
        for boot in (False, '', '../bad', BOOT.upper()):
            with self.assertRaises(p.ProcReadError):
                reader.read_absence(expected(), boot)
        with self.assertRaises(p.ProcReadError):
            reader.read_absence(False, BOOT)
        with self.assertRaises(p.ProcReadError):
            reader.read_actor(42, expected=object())
        self.assertEqual([], fs.operations)

    def test_default_nonlinux_does_not_attempt_real_proc(self):
        with mock.patch.object(p.sys, 'platform', 'win32'):
            result = p.ProcReader().read_actor(42)
        self.assertEqual('unsupported_platform', result.reason)
        self.assertFalse(result.pid_path_absent)
        self.assertEqual((), result.raw)

    def test_foreign_private_exception_text_not_public_and_float_errno_not_absence(self):
        fs = FakeFs()
        fs.fail[('open', BOOT_PATH)] = p.ProcReadError('private arbitrary text')
        result, _, _ = self.observe(fs, 'unexpected_read_error')
        self.assertNotIn('private arbitrary', repr(result.public_status()))
        fs = FakeFs()
        fs.remove_actor()
        error = OSError(2, 'private')
        error.errno = 2.0
        fs.fail[('lstat', '/proc/42')] = error
        reader, _ = self.reader(fs)
        result = reader.read_absence(expected(), BOOT)
        self.assertEqual('read_errno', result.reason)
        self.assertFalse(result.pid_path_absent)


if __name__ == '__main__':
    unittest.main()
