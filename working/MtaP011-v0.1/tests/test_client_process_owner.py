"""HOST fake kernel/process inventory only. No actual fork, child or OS FD."""
import ast
import errno
import hashlib
import os
import stat
import sys
import types
import unittest

RUNTIME = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime'))
sys.path.insert(0, RUNTIME)
import mta_client_process_owner as p
from mta_client_proc import ProcObservation
from mta_p2p_client_init import Actor

BOOT = '12345678-1234-1234-1234-123456789abc'
ELF = b'\x7fELF' + b'HOST_FAKE_ONLY' * 3
SHA = hashlib.sha256(ELF).hexdigest()
PARENT_SHA = hashlib.sha256(b'/private/host-fake\0').hexdigest()


def actor(pid=100, start=10, exe='/private/host-fake', argv=PARENT_SHA, tasks=None):
    return Actor(pid, start, exe, argv, ((pid, start, 'S'),) if tasks is None else tasks)


def observation(value=None, kind='live_actor', pending=False, passes=2, absent=False,
                remaining=(), boot=BOOT, same=True):
    return ProcObservation(kind, '', 'HOST_FAKE_ONLY', boot, value, absent, remaining,
                           same, passes, (), 0, 0, pending, len(value.tasks) if value else 0)


def metadata(inode, mode=stat.S_IFREG | 0o600, data=b'', rdev=0):
    return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=0,
        st_gid=0, st_nlink=1, st_rdev=rdev, st_size=len(data), st_mtime_ns=7, st_ctime_ns=8)


class FakeClock(object):
    def __init__(self): self.value = 10.0
    def __call__(self): return self.value


class FakeReader(object):
    def __init__(self):
        self.parent = actor()
        self.child = actor(200, 20)
        self.self_result = None
        self.actor_result = None
        self.absence_result = observation(kind='absence', absent=True)
        self.calls = []
        self.hook = None
    def read_self(self):
        self.calls.append(('self',))
        if self.hook: self.hook('self')
        return self.self_result or observation(self.parent)
    def read_actor(self, pid, expected=None):
        self.calls.append(('actor', pid, expected))
        if self.hook: self.hook('actor')
        return self.actor_result or observation(self.child)
    def read_absence(self, target, boot):
        self.calls.append(('absence', target, boot))
        if self.hook: self.hook('absence')
        return self.absence_result


class FakeKernel(object):
    O_RDONLY, O_RDWR, O_NOFOLLOW, O_CLOEXEC, O_NONBLOCK, WNOHANG = 0, 2, 131072, 524288, 2048, 1
    def __init__(self, clock):
        self.clock, self.nextfd, self.nextino = clock, 10, 20
        self.live = {3: {'meta': metadata(3), 'data': b'', 'pos': 0,
                         'inherit': False, 'block': True, 'ofd': object()}}
        self.calls, self.closed, self.writes, self.execs = [], [], [], []
        self.supports_fd = {self.execve}
        self.hook, self.faults = None, {}
        self.fork_value, self.waits, self.notify = 200, [(200, 0)], b''
        self.binary, self.binary_mode = ELF, stat.S_IFREG | 0o755
    def event(self, name, *args):
        self.calls.append((name,) + args)
        if self.hook: self.hook(name, args)
        if name in self.faults:
            failure = self.faults[name]
            if isinstance(failure, BaseException): raise failure
            return failure
        return None
    def alloc(self, meta, data=b'', ofd=None):
        fd = self.nextfd; self.nextfd += 1
        self.live[fd] = {'meta': meta, 'data': data, 'pos': 0, 'inherit': False,
                         'block': True, 'ofd': object() if ofd is None else ofd}
        return fd
    def open(self, path, flags):
        value = self.event('open', path, flags)
        if value is not None: return value
        self.nextino += 1
        if path == '/dev/null':
            return self.alloc(metadata(self.nextino, stat.S_IFCHR | 0o666, rdev=259))
        return self.alloc(metadata(self.nextino, self.binary_mode, self.binary), self.binary)
    def fstat(self, fd):
        value = self.event('fstat', fd)
        if value is not None: return value
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST fake closed')
        # Actual os.fstat returns a fresh immutable stat_result, not this
        # fake inventory's mutable metadata storage.
        return types.SimpleNamespace(**vars(self.live[fd]['meta']))
    def set_inheritable(self, fd, enabled):
        self.event('set_inheritable', fd, enabled); self.live[fd]['inherit'] = enabled
    def get_inheritable(self, fd):
        self.event('get_inheritable', fd); return self.live[fd]['inherit']
    def dup(self, original):
        value = self.event('dup', original)
        if value is not None: return value
        row = self.live[original]
        return self.alloc(row['meta'], row['data'], row['ofd'])
    def pipe2(self, flags):
        value = self.event('pipe2', flags)
        if value is not None: return value
        self.nextino += 1
        meta = metadata(self.nextino, stat.S_IFIFO | 0o600)
        return (self.alloc(meta), self.alloc(meta))
    def set_blocking(self, fd, enabled):
        self.event('set_blocking', fd, enabled); self.live[fd]['block'] = enabled
    def flags(self, fd):
        value = self.event('flags', fd)
        if value is not None: return value
        return 0 if self.live[fd]['block'] else self.O_NONBLOCK
    def read(self, fd, count):
        value = self.event('read', fd, count)
        if value is not None: return value
        row = self.live[fd]
        if row['meta'].st_mode & stat.S_IFIFO:
            result, self.notify = self.notify[:count], self.notify[count:]
            return result
        data = row['data'][row['pos']:row['pos'] + count]
        row['pos'] += len(data)
        return data
    def write(self, fd, data):
        value = self.event('write', fd, data); self.writes.append((fd, data))
        return len(data) if value is None else value
    def close(self, fd):
        value = self.event('close', fd); self.closed.append(fd)
        if value is not None: return value
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST fake closed')
        del self.live[fd]
    def listdir(self, path):
        value = self.event('listdir', path)
        return value if value is not None else [str(fd) for fd in (0, 1, 2)] + [str(fd) for fd in self.live]
    def fork(self):
        value = self.event('fork')
        return self.fork_value if value is None else value
    def waitpid(self, pid, flags):
        value = self.event('waitpid', pid, flags)
        return value if value is not None else (self.waits.pop(0) if len(self.waits) > 1 else self.waits[0])
    def execve(self, fd, argv, env):
        self.event('execve', fd); self.execs.append((fd, argv, env)); raise RuntimeError('HOST no actual exec')
    def dup2(self, source, target):
        self.event('dup2', source, target)
    def _exit(self, code):
        self.event('_exit', code); raise RuntimeError('HOST fake child exit')
    def sleep(self, seconds): self.clock.value += seconds
    def getpid(self): return 100
    def getuid(self): return 0
    def major(self, value): return value >> 8
    def minor(self, value): return value & 255
    def WIFEXITED(self, status): return status & 127 == 0
    def WEXITSTATUS(self, status): return status >> 8
    def WIFSIGNALED(self, status): return status & 127 not in (0, 127)
    def WTERMSIG(self, status): return status & 127


class ProcessOwnerTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.reader = FakeClock(), FakeReader()
        self.kernel = FakeKernel(self.clock)
        self.threads = 1
        self.owner = p.DirectChildOwner(_os=self.kernel, _reader=self.reader,
            _clock=self.clock, _threads=lambda: self.threads, _flags=self.kernel.flags)
        self.spec = p.LaunchSpec('controller', '/private/controller', ('/private/controller', '--private'),
                                 (('LANG', 'C'),), SHA)
        self.ticket = self.owner.register(self.spec, 3, 30.0)
    def launch(self): return self.owner.launch(self.ticket)
    def release(self): return self.owner.release(self.ticket, lambda t, a: p.PersistReceipt(t, a))
    def fail(self, code, function, *args):
        with self.assertRaisesRegex(p.ProcessOwnerError, '^' + code + '$'): function(*args)
    def count(self, name): return sum(row[0] == name for row in self.kernel.calls)
    def record(self, role): return next(r for r in self.ticket.fds if r.role == role)

    def test_constructor_register_and_status_are_pure(self):
        self.assertEqual([], self.kernel.calls); self.assertEqual([], self.reader.calls)
        self.owner.status(); self.assertEqual([], self.kernel.calls)
        self.assertFalse(self.owner.status()['provider_ready'])
        self.assertNotIn('/private', repr(self.ticket) + repr(self.spec))
        self.assertFalse(self.owner.status()['complete'])

    def test_strict_spec_and_deadline_inputs(self):
        for deadline in (True, float('nan'), float('inf'), 10 ** 1000, -1):
            self.fail('invalid_input', self.owner.register,
                p.LaunchSpec('watchdog', '/private/d', ('/private/d',), (), SHA), 3, deadline)
        for exe in ('relative', '/private/../d', '/private//d', '/private/d\n'):
            self.fail('invalid_input', p.LaunchSpec, 'controller', exe, (exe,), (), SHA)

    def test_exact_registration_and_fork_before_observation(self):
        def hook(name, args):
            if name in ('open', 'pipe2', 'dup'):
                self.assertGreater(len(self.ticket.fds), 0)
                self.assertTrue(any(r.creator == getattr(self.kernel, name) for r in self.ticket.fds))
            if name == 'fork':
                self.assertTrue(self.ticket.fork_requested)
                self.assertIs(self.owner._tickets[0], self.ticket)
        self.kernel.hook = hook
        self.assertIs(self.launch(), self.ticket)
        self.assertEqual('/private/host-fake', self.ticket.preexec.exe)
        self.assertNotEqual(self.spec.exe, self.ticket.preexec.exe)
        self.assertIsNone(self.ticket.postexec)

    def test_default_fd_exec_support_absent_never_uses_path_fallback(self):
        self.kernel.supports_fd = set()
        self.fail('unsupported', self.launch)
        self.assertEqual(0, self.count('open')); self.assertEqual(0, self.count('fork'))
        self.assertTrue(self.owner.close_inventory(self.ticket))

    def test_binary_pin_checked_on_actual_opened_fd(self):
        self.kernel.binary = b'\x7fELFchanged'
        self.fail('binary_invalid', self.launch)
        self.assertEqual(0, self.count('fork'))
        self.assertTrue(self.owner.close_inventory(self.ticket))
        self.assertEqual(self.kernel.O_RDONLY | self.kernel.O_NOFOLLOW | self.kernel.O_CLOEXEC,
                         next(c[2] for c in self.kernel.calls if c[0] == 'open'))

    def test_binary_not_elf_or_writable_is_rejected(self):
        self.kernel.binary_mode |= 0o002
        self.fail('binary_invalid', self.launch)
        self.assertEqual(0, self.count('fork'))
        self.assertTrue(self.owner.close_inventory(self.ticket))

    def test_binary_changes_during_hash_fail_closed(self):
        def hook(name, args):
            if name == 'read': self.kernel.live[args[0]]['meta'].st_ctime_ns += 1
        self.kernel.hook = hook
        self.fail('binary_invalid', self.launch)
        self.assertEqual(0, self.count('fork'))

    def test_actual_dup_inheritance_not_second_open_or_boolean(self):
        original = self.kernel.live[3]['ofd']
        self.launch()
        inherited = self.record('inherited_device')
        self.assertIs(original, self.kernel.live[inherited.fd]['ofd'])
        self.assertEqual(1, self.count('dup'))
        self.assertFalse(any(c[0] == 'open' and c[1] == 'device' for c in self.kernel.calls))
        self.assertTrue(self.owner.close_inventory(self.ticket))
        self.assertIn(3, self.kernel.live); self.assertNotIn(3, self.kernel.closed)

    def test_multithreaded_python_rejected_before_creation(self):
        self.threads = 2
        self.fail('multithreaded', self.launch)
        self.assertEqual(0, self.count('open')); self.assertEqual(0, self.count('fork'))

    def test_multithreaded_actual_task_inventory_rejected(self):
        self.reader.parent = actor(tasks=((100, 10, 'S'), (101, 11, 'S')))
        self.fail('multithreaded', self.launch)
        self.assertEqual(0, self.count('open'))

    def test_second_thread_before_fork_rejected(self):
        def hook(name, args):
            if name == 'listdir': self.threads = 2
        self.kernel.hook = hook
        self.fail('multithreaded', self.launch)
        self.assertEqual(0, self.count('fork'))

    def test_nonblocking_actual_flags_readback_required(self):
        self.kernel.faults['flags'] = 0
        self.fail('fd_unknown', self.launch)
        self.assertEqual(0, self.count('fork'))
        self.assertTrue(self.owner.close_inventory(self.ticket))

    def test_register_other_owner_and_duplicate_role_are_rejected(self):
        other = p.DirectChildOwner(_os=self.kernel, _reader=self.reader, _clock=self.clock,
                                   _threads=lambda: 1, _flags=self.kernel.flags)
        self.fail('wrong_owner', other.launch, self.ticket)
        self.fail('invalid_input', self.owner.register, self.spec, 3, 30)

    def test_negative_open_is_not_unknown_created_fd(self):
        self.kernel.faults['open'] = OSError(errno.ENOENT, 'HOST private path')
        self.fail('creation_unknown', self.launch)
        self.assertFalse(self.ticket.unknown)
        self.assertTrue(self.owner.close_inventory(self.ticket))

    def test_interrupt_open_preserves_unreturned_creation_ticket(self):
        self.kernel.faults['open'] = KeyboardInterrupt()
        self.fail('creation_unknown', self.launch)
        self.assertTrue(self.ticket.fds[0].unknown)
        self.assertFalse(self.owner.close_inventory(self.ticket))
        self.fail('busy_or_pending', self.launch)
        self.assertEqual(1, self.count('open'))

    def test_pipe_both_refs_saved_before_metadata_failure(self):
        def hook(name, args):
            if name == 'fstat' and args[0] == 12: raise KeyboardInterrupt()
        self.kernel.hook = hook
        self.fail('creation_unknown', self.launch)
        self.assertEqual((12, 13), (self.record('gate_read').fd, self.record('gate_write').fd))
        self.assertTrue(self.record('gate_read').returned)
        self.assertTrue(self.record('gate_write').returned)
        self.assertTrue(self.ticket.unknown)
        self.assertFalse(self.owner.close_inventory(self.ticket))

    def test_fork_known_negative_and_unknown_are_distinct(self):
        self.kernel.faults['fork'] = OSError(errno.EAGAIN, 'HOST fake')
        self.fail('creation_unknown', self.launch)
        self.assertTrue(self.ticket.fork_negative)
        self.assertFalse(self.ticket.unknown)
        self.assertTrue(self.owner.close_inventory(self.ticket))
        self.assertFalse(self.owner.wait_reap(self.ticket))

    def test_unknown_fork_keeps_all_refs_and_never_reforks(self):
        self.kernel.faults['fork'] = KeyboardInterrupt()
        self.fail('creation_unknown', self.launch)
        self.assertTrue(self.ticket.unknown); self.assertIsNone(self.ticket.pid)
        self.assertFalse(self.owner.close_inventory(self.ticket))
        self.fail('busy_or_pending', self.launch)
        self.assertEqual(1, self.count('fork'))

    def test_malformed_fork_return_is_retained(self):
        self.kernel.fork_value = True
        self.fail('fork_unknown', self.launch)
        self.assertIs(self.ticket.pid, True); self.assertTrue(self.ticket.unknown)
        self.assertFalse(self.owner.wait_reap(self.ticket))

    def test_failed_pre_exec_identity_still_allows_actual_known_child_reap(self):
        self.reader.actor_result = observation(kind='unknown')
        self.fail('identity_unknown', self.launch)
        self.assertIsNone(self.ticket.preexec)
        self.assertFalse(self.owner.close_inventory(self.ticket))
        self.assertTrue(self.owner.wait_reap(self.ticket))
        self.assertFalse(self.owner.fresh_exit(self.ticket))
        self.assertTrue(self.ticket.unknown)

    def test_persist_pre_exec_exact_receipt_before_gate_release(self):
        self.launch()
        def persist(ticket, value):
            self.assertIs(ticket, self.ticket); self.assertIs(value, self.ticket.preexec)
            self.assertEqual([], self.kernel.writes)
            return p.PersistReceipt(ticket, value)
        self.assertTrue(self.owner.release(self.ticket, persist))
        self.assertEqual(b'1', self.kernel.writes[0][1])
        self.assertTrue(self.ticket.persist_returned); self.assertTrue(self.ticket.released)
        self.assertTrue(self.record('gate_write').closed)

    def test_persist_boolean_or_equal_but_distinct_actor_never_release(self):
        self.launch()
        self.fail('persist_unknown', self.owner.release, self.ticket,
                  lambda t, a: p.PersistReceipt(t, actor(200, 20)))
        self.assertEqual([], self.kernel.writes)
        self.assertTrue(self.ticket.unknown)
        self.fail('busy_or_pending', self.release)

    def test_persist_interrupt_does_not_release_or_retry(self):
        self.launch()
        def persist(*unused): raise KeyboardInterrupt()
        self.fail('persist_unknown', self.owner.release, self.ticket, persist)
        self.assertEqual([], self.kernel.writes); self.assertTrue(self.ticket.persist_requested)
        self.fail('busy_or_pending', self.release)

    def test_deadline_after_persist_never_releases_gate(self):
        self.launch()
        def persist(t, a):
            self.clock.value = 31
            return p.PersistReceipt(t, a)
        self.fail('deadline', self.owner.release, self.ticket, persist)
        self.assertEqual([], self.kernel.writes)
        self.assertTrue(self.ticket.persist_returned)
        self.assertFalse(self.owner.close_inventory(self.ticket))

    def test_gate_write_bool_is_not_exact_one_byte_receipt(self):
        self.launch(); self.kernel.faults['write'] = True
        self.fail('gate_unknown', self.release)
        self.assertTrue(self.ticket.release_requested); self.assertFalse(self.ticket.released)
        self.assertTrue(self.ticket.unknown)

    def test_gate_close_failure_after_write_retains_release_and_unknown(self):
        self.launch()
        fd = self.record('gate_write').fd
        def hook(name, args):
            if name == 'close' and args[0] == fd: raise KeyboardInterrupt()
        self.kernel.hook = hook
        self.fail('gate_unknown', self.release)
        self.assertTrue(self.ticket.released); self.assertTrue(self.ticket.unknown)
        self.owner.close_inventory(self.ticket)
        self.assertEqual(1, sum(c[0] == 'close' and c[1] == fd for c in self.kernel.calls))

    def test_resolve_observes_actual_final_exe_not_pre_exec_relabel(self):
        self.launch(); self.release()
        self.assertIsNone(self.owner.resolve(self.ticket))
        actual = actor(200, 20, self.spec.exe, self.spec.argv_sha)
        self.reader.child = actual
        self.assertIs(actual, self.owner.resolve(self.ticket))
        self.assertEqual('/private/host-fake', self.ticket.preexec.exe)
        self.assertEqual(self.spec.exe, self.ticket.postexec.exe)

    def test_resolve_reused_pid_or_unexpected_exe_does_not_approve(self):
        self.launch(); self.release()
        self.reader.child = actor(200, 21, self.spec.exe, self.spec.argv_sha)
        self.assertIsNone(self.owner.resolve(self.ticket))
        self.assertIsNone(self.ticket.postexec)
        self.reader.child = actor(200, 20, '/private/foreign', self.spec.argv_sha)
        self.assertIsNone(self.owner.resolve(self.ticket)); self.assertTrue(self.ticket.unknown)

    def test_wait_reap_is_actual_direct_wait_before_fresh_absence(self):
        self.launch(); self.release()
        self.assertFalse(self.owner.fresh_exit(self.ticket))
        self.assertEqual(0, sum(c[0] == 'absence' for c in self.reader.calls))
        self.kernel.waits = [(0, 0), (200, 7 << 8)]
        self.assertTrue(self.owner.wait_reap(self.ticket))
        self.assertEqual(7, self.ticket.exit_code)
        self.assertTrue(self.owner.fresh_exit(self.ticket))
        self.assertEqual(2, self.count('waitpid'))
        self.assertFalse(self.ticket.exit_observation.reap_complete)

    def test_expired_launch_deadline_does_not_block_cleanup_wait(self):
        self.launch(); self.release(); self.clock.value = 50
        self.assertTrue(self.owner.wait_reap(self.ticket, .1))
        self.assertTrue(self.owner.fresh_exit(self.ticket))
        self.assertTrue(self.owner.close_inventory(self.ticket))

    def test_wait_timeout_does_not_claim_reaped_or_send_signal(self):
        self.launch(); self.kernel.waits = [(0, 0)]
        self.fail('deadline', self.owner.wait_reap, self.ticket, .025)
        self.assertFalse(self.ticket.waited); self.assertFalse(self.owner.fresh_exit(self.ticket))
        self.assertFalse(any(c[0] in ('kill', 'signal') for c in self.kernel.calls))

    def test_wait_echild_unknown_is_not_reap_proof(self):
        self.launch(); self.kernel.faults['waitpid'] = OSError(errno.ECHILD, 'HOST fake')
        self.assertFalse(self.owner.wait_reap(self.ticket)); self.assertFalse(self.ticket.waited)
        self.assertTrue(self.ticket.unknown)

    def test_wait_wrong_pid_is_not_reap_proof(self):
        self.launch(); self.kernel.waits = [(201, 0)]
        self.assertFalse(self.owner.wait_reap(self.ticket)); self.assertTrue(self.ticket.unknown)

    def test_actual_reaped_fact_not_repeated_wait_but_absence_is_always_fresh(self):
        self.launch(); self.assertTrue(self.owner.wait_reap(self.ticket))
        self.assertTrue(self.owner.wait_reap(self.ticket)); self.assertEqual(1, self.count('waitpid'))
        self.assertTrue(self.owner.fresh_exit(self.ticket))
        self.reader.absence_result = observation(kind='unknown')
        self.assertFalse(self.owner.fresh_exit(self.ticket))
        self.assertEqual(0, self.owner.status()['exit_observed_count'])

    def test_partial_or_pending_absence_does_not_close_child_inventory(self):
        self.launch(); self.owner.wait_reap(self.ticket)
        self.reader.absence_result = observation(kind='absence', absent=True, passes=1)
        self.assertFalse(self.owner.fresh_exit(self.ticket))
        self.reader.absence_result = observation(kind='absence', absent=True, pending=True)
        self.assertFalse(self.owner.fresh_exit(self.ticket))
        self.assertEqual(0, self.owner.status()['exit_observed_count'])

    def test_close_exception_still_attempts_other_exact_resources_once(self):
        self.launch()
        target = self.record('executable').fd
        def hook(name, args):
            if name == 'close' and args[0] == target: raise KeyboardInterrupt()
        self.kernel.hook = hook
        self.assertFalse(self.owner.close_inventory(self.ticket))
        calls = self.count('close')
        self.assertTrue(self.record('inherited_device').closed)
        self.assertTrue(self.record('null').closed)
        self.assertFalse(self.owner.close_inventory(self.ticket))
        self.assertEqual(calls, self.count('close')); self.assertIn(3, self.kernel.live)

    def test_foreign_fd_replacement_is_never_closed(self):
        self.launch(); target = self.record('executable').fd
        self.kernel.live[target]['meta'] = metadata(999)
        self.assertFalse(self.owner.close_inventory(self.ticket))
        self.assertIn(target, self.kernel.live); self.assertNotIn(target, self.kernel.closed)
        self.assertTrue(self.record('null').closed)

    def test_closed_inventory_only_parent_fd_fact_not_child_or_provider(self):
        self.launch(); self.assertTrue(self.owner.close_inventory(self.ticket))
        self.assertFalse(self.ticket.waited); self.assertFalse(self.ticket.exit_verified)
        self.assertFalse(self.owner.status()['complete']); self.assertFalse(self.owner.status()['provider_ready'])
        self.assertIn(3, self.kernel.live)

    def test_foreign_parent_cannot_close_inventory(self):
        self.launch(); self.reader.parent = actor(100, 99)
        before = self.count('close')
        self.assertFalse(self.owner.close_inventory(self.ticket))
        self.assertEqual(before, self.count('close')); self.assertTrue(self.ticket.unknown)

    def test_status_does_not_perform_reader_clock_or_cleanup(self):
        self.launch()
        before = (len(self.kernel.calls), len(self.reader.calls))
        def bad(): raise AssertionError('HOST no passive IO')
        self.owner._clock = bad
        result = self.owner.status()
        self.assertEqual(before, (len(self.kernel.calls), len(self.reader.calls)))
        self.assertTrue(all(type(v) in (str, int, bool) for v in result.values()))
        self.assertNotIn('200', repr(result)); self.assertNotIn('/private', repr(result))

    def test_watchdog_notification_is_bounded_passive_request_only(self):
        spec = p.LaunchSpec('watchdog', '/private/d', ('/private/d',), (), SHA)
        self.ticket = self.owner.register(spec, 3, 30)
        self.launch(); self.release(); self.kernel.notify = b'RR'
        self.assertTrue(self.owner.read_requests(self.ticket))
        self.assertEqual(2, self.ticket.notify_requests)
        self.assertEqual(0, self.count('waitpid'))
        self.kernel.notify = b'R' * 15
        self.fail('fd_unknown', self.owner.read_requests, self.ticket)
        self.assertTrue(self.ticket.unknown)

    def test_watchdog_unknown_message_and_controller_notify_rejected(self):
        self.launch(); self.release()
        self.fail('wrong_owner', self.owner.read_requests, self.ticket)
        self.assertEqual(0, self.ticket.notify_requests)

    def test_active_creation_reentrancy_cannot_close_or_reap(self):
        def hook(name, args):
            if name == 'fork':
                self.assertFalse(self.owner.close_inventory(self.ticket))
                self.fail('busy_or_pending', self.owner.wait_reap, self.ticket)
                self.fail('busy_or_pending', self.owner.resolve, self.ticket)
        self.kernel.hook = hook
        self.launch()

    def test_child_exec_uses_verified_fd_and_inherited_original_dup_only(self):
        self.launch()
        roles = ('executable', 'inherited_device', 'gate_read', 'error_write', 'notify_write', 'null')
        # Separate fake child copy: restore the F-closed pipe ends only in fake inventory.
        for role in roles:
            row = self.record(role)
            if row.fd not in self.kernel.live:
                self.kernel.live[row.fd] = {'meta': metadata(row.metadata[1], row.metadata[2]),
                    'data': b'', 'pos': 0, 'inherit': False, 'block': True, 'ofd': object()}
        self.kernel.notify = b'1'
        inherited = tuple(self.kernel.live) + (0, 1, 2)
        with self.assertRaisesRegex(RuntimeError, 'HOST fake child exit'):
            self.owner._child(self.ticket, *(self.record(role) for role in roles), inherited=inherited)
        fd, argv, env = self.kernel.execs[0]
        self.assertIs(type(fd), int); self.assertEqual(self.record('executable').fd, fd)
        self.assertEqual(self.spec.argv, argv)
        self.assertEqual(str(self.record('inherited_device').fd), env['P011_CLIENT_DEVICE_FD'])
        self.assertNotIn(3, self.kernel.live)
        self.assertEqual(b'E', self.kernel.writes[-1][1])

    def test_python35_ast_and_no_process_network_or_core_proof_fabrication(self):
        path = os.path.join(RUNTIME, 'mta_client_process_owner.py')
        with open(path, encoding='utf-8') as handle: source = handle.read()
        ast.parse(source, feature_version=(3, 5))
        self.assertIn('fs.execve(binary.fd, ticket.spec.argv, env)', source)
        self.assertNotIn('import fcntl', source)
        for token in ('subprocess.', 'preexec_fn=', 'os.kill(', 'socket.', 'Handle(', 'ExecutorProof('):
            self.assertNotIn(token, source)


if __name__ == '__main__':
    unittest.main()
