"""HOST FakeIO only: no subprocess, real proc, socket, RF or target filesystem."""
import ast
import contextlib
import errno
import hashlib
import io
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

RUNTIME = Path(__file__).resolve().parents[1] / 'runtime'
sys.path.insert(0, str(RUNTIME))
import p011_json as json
import mta_client_executor as f
import mta_client_proc as real_proc
import mta_p2p_client_init as core

TOKEN, PIN = 'a' * 32, 'b' * 64
BOOT = '11111111-1111-1111-1111-111111111111'


def metadata(mode, size=0, ino=1, uid=0, links=1):
    return types.SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode, st_uid=uid,
        st_gid=0, st_nlink=links, st_size=size)


class Clock(object):
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class FakePipe(object):
    def __init__(self, os_io, fd): self.io, self.fd, self.closed = os_io, fd, False
    def fileno(self):
        if self.closed: raise ValueError('I/O operation on closed file')
        return self.fd
    def close(self):
        self.io.close(self.fd); self.closed = True


class FakeProcess(object):
    def __init__(self, os_io):
        self.io, self.pid, self.calls = os_io, 177, 0
        for name in ('stdin', 'stdout', 'stderr'):
            fd = os_io.pipe(); setattr(self, name, FakePipe(os_io, fd))
    def wait(self, timeout):
        self.calls += 1
        if self.io.wait_error is not None: raise self.io.wait_error
        if self.io.wait_timeouts:
            self.io.wait_timeouts -= 1
            raise f.subprocess.TimeoutExpired(self.io.argv, timeout)
        if self.io.block_until_drained and any(self.io.buffers.get(getattr(self, n).fd) for n in ('stdout', 'stderr')):
            raise f.subprocess.TimeoutExpired(self.io.argv, timeout)
        self.io.waited = True
        return self.io.exit_code


class FakeIo(object):
    process_type = FakeProcess
    def __init__(self, clock=None):
        self.clock = clock or Clock()
        self.files, self.fds, self.buffers = {}, {}, {}
        self.next_fd, self.next_ino, self.closes, self.writes = 10, 100, [], []
        self.argv, self.created = None, None
        self.spawn_error = self.wait_error = None
        self.exit_code, self.close_unknown, self.bad_wrapper = 0, set(), False
        self.waited, self.no_eof, self.block_until_drained, self.wait_timeouts = False, False, False, 0
        self.fail_read, self.validation, self.created_count = None, 0, 0
        self.add('/usr/bin/python-fixture', b'\x7fELFpython', 0o755)
        self.fds[0] = {'meta': metadata(stat.S_IFIFO | 0o600, ino=90), 'data': b'', 'position': 0}
    def validate(self): self.validation += 1
    def add(self, path, data, mode=0o400):
        self.next_ino += 1
        self.files[path] = (data, metadata(stat.S_IFREG | mode, len(data), self.next_ino))
    def stat(self, path):
        if path in self.files: return self.files[path][1]
        mode = 0o1777 if path == '/tmp' else 0o700 if path.startswith(f.ROOT) else 0o755
        return metadata(stat.S_IFDIR | mode, ino=hash(path) & 0xffff)
    def open(self, path):
        data, info = self.files[path]
        self.next_fd += 1
        self.fds[self.next_fd] = {'meta': info, 'data': data, 'position': 0}
        return self.next_fd
    def pipe(self):
        self.next_fd += 1
        self.fds[self.next_fd] = {'meta': metadata(stat.S_IFIFO | 0o600, ino=self.next_fd),
            'data': b'', 'position': 0}
        return self.next_fd
    def fstat(self, fd):
        if fd not in self.fds: raise OSError(errno.EBADF, 'fixed fixture')
        return self.fds[fd]['meta']
    def close(self, fd):
        self.closes.append(fd)
        if fd not in self.close_unknown: del self.fds[fd]
    def ready(self, fds, seconds):
        self.clock.value += seconds
        return [n for n in fds if n in self.buffers and self.buffers[n] or self.waited and not self.no_eof and
                self.created is not None and n in (self.created.stdout.fd, self.created.stderr.fd)]
    def read(self, fd, count):
        if fd == self.fail_read: raise RuntimeError('private fixture read error')
        if fd in self.buffers:
            if not self.buffers[fd]: return b''
            value = self.buffers[fd].pop(0)
            if len(value) > count:
                self.buffers[fd].insert(0, value[count:]); value = value[:count]
            return value
        row = self.fds[fd]; start = row['position']; row['position'] += count
        return row['data'][start:start + count]
    def write(self, fd, raw): self.writes.append((fd, raw)); return len(raw)
    def popen(self, argv, executable_fd):
        self.created_count += 1; self.argv = argv
        if self.spawn_error is not None: raise self.spawn_error
        self.created = FakeProcess(self)
        if self.bad_wrapper: self.created.stdout = object()
        return self.created


class ClosedProcFs(object):
    def __init__(self): self.live = False
    def fstat(self, fd):
        if self.live: return metadata(stat.S_IFREG | 0o400)
        raise OSError(errno.EBADF, 'closed fake proc')


def observation(actor=None, absent=False, pending=False):
    return real_proc.ProcObservation('absence' if absent else 'live_actor', 'ok', 'complete',
        BOOT, actor, absent, (), True, 2, (), 1, 0 if pending else 1, pending,
        0 if actor is None else len(actor.tasks))


def digest(argv): return hashlib.sha256(b''.join(x.encode('ascii') + b'\0' for x in argv)).hexdigest()


class FakeLoader(object):
    def __init__(self): self.value = None
    def authenticate(self, value):
        if value is not self.value: raise f.ExecutorError('source_invalid')


class Control(object):
    def __init__(self, values=(True,)): self.values, self.reason = list(values), 'cancelled'
    def poll(self): return self.values.pop(0) if self.values else True


def deployment(os_io, mode='--execute-client-init', ttl_text='20.0'):
    """Explicit HOST fixture issuer; not a production source verifier."""
    loader = FakeLoader()
    pm = types.SimpleNamespace(run_token=TOKEN, python_exe='/usr/bin/python-fixture',
        python_sha=hashlib.sha256(os_io.files['/usr/bin/python-fixture'][0]).hexdigest(),
        executor_path=f.ROOT + '/client-' + TOKEN + '/runtime/mta_client_executor.py')
    state = types.SimpleNamespace(readers=[], proc_pending=False, proc_exception=False,
        wrong_actor=False, two_tasks=False, absence_wrong=False, ready=True, restored=True,
        factory_error=None, restore_error=None, ticket_auth=True, bridge_closed=True,
        provider_closed=True, owner_unknown=0, stops=0, polls=0)
    modules = {'p011_json': json, 'mta_p2p_client_init': core}
    value = f.LoadedDeployment(loader, modules, pm, PIN, f.ROOT + '/client-' + TOKEN)
    loader.value = value
    loader.owner = types.SimpleNamespace(rows=[{'path': pm.python_exe, 'raw': os_io.files[pm.python_exe][0],
        'metadata': f._meta(os_io.files[pm.python_exe][1]), 'unknown': False, 'closed': True}])
    os_io.fds[60] = {'meta': os_io.files[pm.python_exe][1], 'data': b'', 'position': 0}
    class Reader(object):
        def __init__(self, timeout):
            self.fs = ClosedProcFs(); self._fd_refs = [(self.fs, 901)]
            self._open_attempt = {'registered': True, 'failed_without_fd': False}
            self._pending, self._active, self._files, self._closed = False, False, 1, 1
            state.readers.append(self)
        def read_self(self):
            if state.proc_exception:
                self._pending, self.fs.live = True, True
                raise RuntimeError('private reader failure')
            self._pending, self._closed = state.proc_pending, 0 if state.proc_pending else 1
            self.fs.live = state.proc_pending
            args = f._argv(value, mode, ttl_text)
            tasks = ((155, 99, 'S'), (156, 100, 'S')) if state.two_tasks else ((155, 99, 'S'),)
            actor = core.Actor(155, 99, pm.python_exe, digest(args), tasks)
            return observation(actor, pending=state.proc_pending)
        def read_actor(self, pid):
            args = os_io.argv
            actor = core.Actor(pid, 125, pm.python_exe,
                'f' * 64 if state.wrong_actor else digest(args), ((pid, 125, 'S'),))
            return observation(actor)
        def read_absence(self, actor, boot):
            return observation(absent=not state.absence_wrong)
    modules['mta_client_proc'] = types.SimpleNamespace(ProcReader=Reader,
        ProcObservation=real_proc.ProcObservation)
    class Store(core.ClientInitStore):
        def authenticate_finish(self, locks, record, receipt, deadline): return state.ticket_auth
    class Owner(object):
        def status(self): return {'unknown_count': state.owner_unknown}
    class Bridge(object):
        def verify_closed(self): return state.bridge_closed
    class Provider(object):
        def request_stop(self): state.stops += 1
        def poll_requests(self): state.polls += 1; return False
        def closed_resources(self, handles, deadline):
            return core.CloseProof(1, (True,), (state.provider_closed,))
    class Lease(object):
        def start(self, ttl, cancelled):
            self.record = types.SimpleNamespace(deadline=os_io.clock() + ttl)
            self.started = True; return {'client_init_ready': state.ready}
        def restore(self, timeout):
            self.restored = True
            if state.restore_error is not None: raise state.restore_error
            self.cleanup_complete, self.pending = state.restored, not state.restored
            identity = core.Identity('c' * 64)
            receipt = core.FinishReceipt(self.store, object(), identity, None, None,
                state.restored, state.restored, 'absent_observed' if state.restored else 'retained_observed',
                'verified' if state.restored else 'not_attempted', state.restored, not state.restored, state.restored)
            self.finish_receipt = self.store._finish_receipt = receipt
            return {'cleanup_complete': state.restored}
    store, owner, bridge, provider, lease = Store(), Owner(), Bridge(), Provider(), Lease()
    bridge.owner, bridge.store = owner, store
    lease.provider, lease.store, lease.bridge, lease.handles = provider, store, bridge, {}
    lease.record, lease.finish_receipt = None, None
    def assemble(pm_arg):
        if state.factory_error is not None: raise state.factory_error
        return provider, store, owner, bridge, lease
    modules.update({'mta_client_store': types.SimpleNamespace(DurableClientInitStore=Store),
        'mta_client_process_owner': types.SimpleNamespace(DirectChildOwner=Owner),
        'mta_client_two_phase_lease': types.SimpleNamespace(DirectChildLaunchBridge=Bridge),
        'mta_client_linux_provider': types.SimpleNamespace(assemble=assemble, LinuxClientInitLease=Lease,
            LinuxDirectChildLaunchBridge=Bridge)})
    return value, state


class ExecutorTests(unittest.TestCase):
    def setUp(self): self.clock, self.io = Clock(), None; self.io = FakeIo(self.clock)
    def _child(self, dep, control=None, emit=None):
        return f.ClientExecutor(dep, self.io, self.clock, control or Control(), emit,
            _environ={'P011_CLIENT_EXECUTABLE_FD': '60'})
    def test_defaults_are_pure_and_unavailable(self):
        child, parent = f.ClientExecutor(_io=self.io), f.ParentExecutor(_io=self.io)
        self.assertEqual(child.run()['reason'], 'unavailable')
        self.assertEqual(parent.start()['reason'], 'unavailable')
        self.assertEqual(self.io.validation, 0); self.assertEqual(self.io.created_count, 0)
    def test_source_only_main_has_no_assembler(self):
        output = io.StringIO()
        with mock.patch.object(f, 'DeploymentLoader', side_effect=AssertionError), contextlib.redirect_stdout(output):
            self.assertEqual(f.main([]), 0)
        self.assertIn('source_only', output.getvalue())
    def test_budgets_reject_bool_huge_nonfinite(self):
        for bad in (True, 1 << 10000, float('inf'), float('nan'), 21, 0):
            with self.assertRaises(f.ExecutorError): f.ClientExecutor().run(bad)
        self.assertEqual(f.main(['--arbitrary']), 2)
    def test_f_real_contract_fixture_restores_same_lease(self):
        dep, state = deployment(self.io)
        frames = []
        child = self._child(dep, emit=frames.append)
        result = child.run()
        self.assertTrue(result['done']); self.assertFalse(result['resource_pending'])
        self.assertTrue(child.init_ready); self.assertEqual(len(frames), 2)
        self.assertIs(child.finish, child.assembly[1]._finish_receipt)
        self.assertEqual(state.stops, 1)
        self.assertFalse(result['send_available']); self.assertFalse(result['association_verified'])
    def test_f_rejects_multiple_actual_tasks_before_assembly(self):
        dep, state = deployment(self.io); state.two_tasks = True
        child = self._child(dep)
        self.assertEqual(child.run()['reason'], 'actor_unknown')
        self.assertIsNone(child.assembly_ticket)
    def test_f_actual_argv_does_not_match_watchdog(self):
        dep, state = deployment(self.io, '--watchdog')
        child = self._child(dep)
        self.assertEqual(child.run()['reason'], 'actor_unknown')
    def test_f_pending_reader_is_retained_before_call(self):
        dep, state = deployment(self.io); state.proc_pending = True
        child = self._child(dep)
        self.assertFalse(child.run()['done'])
        self.assertIs(child.reader_rows[0]['reader'], state.readers[0])
        self.assertTrue(state.readers[0]._pending)
        self.assertTrue(child.status()['resource_pending'])
    def test_f_exception_reader_is_retained_before_call(self):
        dep, state = deployment(self.io); state.proc_exception = True
        child = self._child(dep)
        self.assertFalse(child.run()['done'])
        self.assertFalse(child.reader_rows[0]['returned'])
        self.assertIs(child.reader_rows[0]['reader'], state.readers[0])
        self.assertTrue(child.status()['resource_pending'])
    def test_f_unknown_factory_cannot_claim_zero_network(self):
        dep, state = deployment(self.io); state.factory_error = RuntimeError('private factory error')
        child = self._child(dep)
        result = child.run(); self.assertTrue(result['resource_pending'])
        self.assertTrue(child.assembly_ticket['unknown']); self.assertIsNone(child.assembly)
    def test_f_start_failure_preserves_cleanup_but_no_init_success(self):
        dep, state = deployment(self.io); state.ready = False
        child = self._child(dep)
        self.assertTrue(child.run()['done']); self.assertFalse(child.init_ready)
    def test_f_restore_pending_retains_exact_assembly(self):
        dep, state = deployment(self.io); state.restored = False
        child = self._child(dep)
        result = child.run(); self.assertFalse(result['done']); self.assertTrue(result['resource_pending'])
        self.assertIsNotNone(child.assembly); self.assertIs(child.finish, child.assembly[4].finish_receipt)
    def test_f_restore_exception_remains_pending(self):
        dep, state = deployment(self.io); state.restore_error = RuntimeError('private restore error')
        child = self._child(dep)
        self.assertTrue(child.run()['resource_pending']); self.assertEqual(len(child.failures), 1)
    def test_f_typed_receipt_is_not_enough(self):
        for attr in ('ticket_auth', 'bridge_closed', 'provider_closed'):
            dep, state = deployment(self.io); setattr(state, attr, False)
            child = self._child(dep)
            self.assertFalse(child.run()['done'])
    def test_f_old_bridge_cannot_pass_new_exact_provider_class(self):
        dep, state = deployment(self.io)
        class NewBridge(object): pass
        dep.modules['mta_client_linux_provider'].LinuxDirectChildLaunchBridge = NewBridge
        child = self._child(dep)
        result = child.run()
        self.assertFalse(result['done']); self.assertTrue(result['resource_pending'])
        self.assertTrue(child.assembly_ticket['unknown'])
        self.assertFalse(hasattr(child.assembly[4], 'restored'))
    def test_stdin_bounded_split_cancel_and_eof(self):
        self.io.buffers[0] = [b'CAN', b'CEL\n']
        control = f._StdinControl(self.io)
        self.assertFalse(control.poll()); self.assertTrue(control.poll())
        self.assertEqual(control.reason, 'cancelled'); self.assertNotIn(0, self.io.closes)
        self.io.buffers[0] = [b'']; control = f._StdinControl(self.io)
        self.assertTrue(control.poll()); self.assertEqual(control.reason, 'eof')
    def test_stdin_unknown_command_rejected(self):
        self.io.buffers[0] = [b'RESTORE\n']
        with self.assertRaises(f.ExecutorError): f._StdinControl(self.io).poll()
    def test_watchdog_only_notifies_original_pipe(self):
        dep, state = deployment(self.io, '--watchdog', '20')
        self.io.fds[6] = {'meta': metadata(stat.S_IFREG | 0o600), 'data': b'', 'position': 0}
        self.io.fds[7] = {'meta': metadata(stat.S_IFIFO | 0o600), 'data': b'', 'position': 0}
        env = {'P011_CLIENT_DEVICE_FD': '6', 'P011_CLIENT_NOTIFY_FD': '7'}
        self.assertEqual(f.watchdog(dep, 20, self.io, self.clock, env, '20'), 0)
        self.assertEqual(self.io.writes, [(7, b'R')]); self.assertEqual(self.io.closes, [])
        self.assertEqual(state.stops, 0)
    def test_watchdog_rejects_unknown_or_same_fd(self):
        dep, state = deployment(self.io, '--watchdog')
        for env in ({}, {'P011_CLIENT_DEVICE_FD': '6', 'P011_CLIENT_NOTIFY_FD': '6'}):
            with self.assertRaises(f.ExecutorError): f.watchdog(dep, 20, self.io, self.clock, env)
    def _parent(self):
        dep, state = deployment(self.io)
        parent = f.ParentExecutor(dep, self.io, self.clock); parent.start()
        return parent, state
    def _frames(self, parent, done=True):
        ready = f._public('not_started', True, True, False, True)
        final = f._public('restored' if done else 'restore_pending', True, False, done, not done)
        raw = b''.join(f.PREFIX + json.dumps(v).encode('ascii') + b'\n' for v in (ready, final))
        self.io.buffers[parent.pipes[1]['fd']] = [raw]
    def test_parent_actual_file_fileno_exception_and_ebadf_close(self):
        parent, state = self._parent(); self._frames(parent)
        result = parent.finish()
        self.assertTrue(result['done']); self.assertTrue(result['parent_waited'])
        self.assertTrue(result['parent_absence_verified']); self.assertTrue(result['parent_resources_closed'])
        self.assertEqual(len(parent.reader_rows), 3)
        self.assertEqual(len(set(id(r['reader']) for r in parent.reader_rows)), 3)
        self.assertTrue(all(self.io.closes.count(r['fd']) == 1 for r in parent.pipes))
        self.assertTrue(all(r['pipe'].closed for r in parent.pipes))
    def test_parent_popen_argv_fixed_no_shell(self):
        parent, state = self._parent()
        self.assertEqual(self.io.argv, f._argv(parent.deployment, '--execute-client-init', '20.0'))
        self.assertIs(parent.spawn_ticket['returned'], self.io.created)
        parent.cancel(); parent.cancel()
        self.assertEqual(self.io.writes, [(parent.pipes[0]['fd'], f.CANCEL)])
    def test_parent_unknown_factory_preserves_attempt(self):
        dep, state = deployment(self.io); self.io.spawn_error = RuntimeError('private spawn')
        parent = f.ParentExecutor(dep, self.io, self.clock)
        self.assertTrue(parent.start()['resource_pending']); self.assertTrue(parent.spawn_ticket['unknown'])
        self.assertIsNotNone(parent.file_owner); self.assertFalse(parent.finish()['done'])
        self.assertEqual(self.io.created_count, 1)
    def test_parent_malformed_return_retains_exact_wrapper(self):
        self.io.bad_wrapper = True
        parent, state = self._parent()
        self.assertIs(parent.pipes[1]['pipe'], parent.process.stdout)
        self.assertTrue(parent.spawn_ticket['unknown']); self.assertFalse(parent.finish()['done'])
        self.assertEqual(self.io.closes, [])
    def test_parent_actual_argv_identity_mismatch(self):
        dep, state = deployment(self.io); state.wrong_actor = True
        parent = f.ParentExecutor(dep, self.io, self.clock)
        self.assertTrue(parent.start()['resource_pending']); self.assertIsNone(parent.actor)
        self.assertFalse(parent.finish()['done'])
    def test_parent_done_frame_without_wait_is_not_success(self):
        parent, state = self._parent(); self._frames(parent)
        self.assertFalse(parent.poll()['done']); self.assertFalse(parent.reaped)
    def test_parent_child_pending_never_upgraded_by_reap(self):
        parent, state = self._parent(); self._frames(parent, False)
        result = parent.finish(); self.assertFalse(result['done'])
        self.assertTrue(result['parent_resources_closed']); self.assertTrue(result['resource_pending'])
    def test_parent_exit_failure_keeps_original_verdict(self):
        parent, state = self._parent(); self._frames(parent); self.io.exit_code = 1
        result = parent.finish(); self.assertFalse(result['done']); self.assertEqual(parent.exit_code, 1)
    def test_parent_negative_wait_is_actual_reap_not_restore(self):
        parent, state = self._parent(); self._frames(parent); self.io.exit_code = -15
        result = parent.finish()
        self.assertEqual(parent.exit_code, -15); self.assertTrue(result['parent_waited'])
        self.assertTrue(result['parent_absence_verified']); self.assertTrue(result['parent_resources_closed'])
        self.assertFalse(result['done']); self.assertTrue(result['resource_pending'])
    def test_parent_unknown_wait_keeps_all_producer_refs_no_retry(self):
        parent, state = self._parent(); self.io.wait_error = RuntimeError('private wait')
        self.assertTrue(parent.finish()['resource_pending'])
        self.assertFalse(parent.reaped); self.assertFalse(parent.pipes[1]['attempted'])
        with self.assertRaises(f.ExecutorError): parent.finish()
        self.assertEqual(parent.process.calls, 1)
    def test_parent_absence_wrong_does_not_close_remaining_fds(self):
        parent, state = self._parent(); state.absence_wrong = True
        result = parent.finish(); self.assertFalse(result['parent_absence_verified'])
        self.assertFalse(parent.pipes[1]['attempted']); self.assertTrue(result['resource_pending'])
    def test_parent_unknown_pipe_close_is_sticky_no_retry(self):
        parent, state = self._parent(); self._frames(parent)
        fd = parent.pipes[2]['fd']; self.io.close_unknown.add(fd)
        self.assertTrue(parent.finish()['resource_pending'])
        self.assertFalse(parent.closed); self.assertEqual(self.io.closes.count(fd), 1)
    def test_parent_frames_unknown_fields_and_partial_rejected(self):
        parent, state = self._parent()
        self.io.buffers[parent.pipes[1]['fd']] = [f.PREFIX + b'{"arbitrary":true}\n']
        self.assertTrue(parent.poll()['resource_pending']); self.assertEqual(parent.reason, 'frame_invalid')
        self._frames(parent); self.assertFalse(parent.finish()['done'])
    def test_parent_poll_after_done_is_passive(self):
        parent, state = self._parent(); self._frames(parent)
        self.assertTrue(parent.finish()['done'])
        self.assertTrue(parent.poll()['done']); self.assertTrue(parent.cancel()['done'])
    def test_f_original_inherited_python_fd_closed_once(self):
        dep, state = deployment(self.io)
        child = self._child(dep)
        self.assertTrue(child.run()['done'])
        self.assertTrue(child.inherited_elf['closed']); self.assertEqual(self.io.closes.count(60), 1)
        with self.assertRaises(OSError): self.io.fstat(60)
    def test_f_missing_inherited_fd_is_pending_not_foreign_close(self):
        dep, state = deployment(self.io)
        child = f.ClientExecutor(dep, self.io, self.clock, Control(), _environ={})
        self.assertTrue(child.run()['resource_pending']); self.assertIsNone(child.assembly_ticket)
        self.assertEqual(self.io.closes, [])
    def test_f_inherited_metadata_wrong_keeps_original_reference(self):
        dep, state = deployment(self.io)
        self.io.fds[60]['meta'] = metadata(stat.S_IFREG | 0o755, 10, 999)
        child = self._child(dep)
        self.assertTrue(child.run()['resource_pending']); self.assertFalse(child.inherited_elf['attempted'])
        self.assertEqual(self.io.closes, [])
    def test_f_inherited_close_unknown_not_retried(self):
        dep, state = deployment(self.io); self.io.close_unknown.add(60)
        child = self._child(dep)
        self.assertTrue(child.run()['resource_pending']); self.assertIsNone(child.assembly_ticket)
        self.assertEqual(self.io.closes.count(60), 1)
    def test_parent_wait_drains_large_stderr_before_reap(self):
        parent, state = self._parent(); self._frames(parent)
        raw = b'private-stderr-' * 700
        self.io.buffers[parent.pipes[2]['fd']] = [raw]
        self.io.block_until_drained = True
        result = parent.finish()
        self.assertTrue(result['done']); self.assertGreater(parent.process.calls, 1)
        self.assertEqual(b''.join(data for index, data in parent.raw if index == 2), raw)
        self.assertTrue(result['stdout_eof_observed']); self.assertTrue(result['stderr_eof_observed'])
    def test_parent_reap_without_eof_never_complete(self):
        parent, state = self._parent(); self._frames(parent); self.io.no_eof = True
        result = parent.finish(timeout=.1)
        self.assertTrue(result['parent_waited']); self.assertTrue(result['parent_absence_verified'])
        self.assertFalse(result['done']); self.assertTrue(result['resource_pending'])
    def test_parent_partial_after_reap_rejected_until_true_eof(self):
        parent, state = self._parent(); self._frames(parent)
        self.io.buffers[parent.pipes[1]['fd']].append(b'MTA_CLIENT_F {')
        result = parent.finish(); self.assertFalse(result['done'])
        self.assertTrue(result['stdout_eof_observed']); self.assertTrue(parent.buffers[1])
    def test_parent_max_raw_failure_cannot_become_eof_success(self):
        parent, state = self._parent(); self._frames(parent)
        self.io.buffers[parent.pipes[2]['fd']] = [b'x' * (f.MAX_RAW + 1)]
        self.io.block_until_drained = True
        self.assertTrue(parent.finish()['resource_pending']); self.assertFalse(parent.reaped)
        self.assertTrue(parent.failures)
    def test_parent_popen_primitives_no_termination_fallback(self):
        tree = ast.parse((RUNTIME / 'mta_client_executor.py').read_text(encoding='utf-8'))
        calls = [n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        self.assertFalse(set(calls) & {'fork', 'kill', 'terminate', 'send_signal'})
        popen = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'Popen')
        keys = {k.arg for k in popen.keywords}
        self.assertNotIn('preexec_fn', keys); self.assertIn('pass_fds', keys)
    def test_python35_ast(self):
        ast.parse((RUNTIME / 'mta_client_executor.py').read_text(encoding='utf-8'), feature_version=(3, 5))


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.io = Clock(), None; self.io = FakeIo(self.clock)
        self.run = f.ROOT + '/client-' + TOKEN
        sources = {name: b'value = 1\n' for name in f.MODULES}
        sources['p011_json'] = (RUNTIME / 'p011_json.py').read_bytes()
        sources['mta_client_linux_provider'] = b'''class ProviderManifest(object):
    def __init__(self, value, _manifest_sha256=None):
        for key, item in value.items(): setattr(self, key, item)
        self.manifest_sha256 = _manifest_sha256
'''
        self.tree = {'version': 1, 'provider': {'run_token': TOKEN, 'python_exe': '/usr/bin/python-fixture',
            'python_sha': hashlib.sha256(self.io.files['/usr/bin/python-fixture'][0]).hexdigest(),
            'wpa_exe': self.run + '/native/mta-wpa-supplicant',
            'wpa_sha': hashlib.sha256(b'\x7fELFwpa').hexdigest(),
            'executor_path': self.run + '/runtime/mta_client_executor.py',
            'executor_sha': hashlib.sha256(sources['mta_client_executor']).hexdigest()},
            'sources': [[name, hashlib.sha256(sources[name]).hexdigest()] for name in f.MODULES]}
        for name, raw in sources.items(): self.io.add(self.run + '/runtime/' + name + '.py', raw)
        self.io.add(self.run + '/native/mta-wpa-supplicant', b'\x7fELFwpa', 0o500)
        self._write_manifest()
    def _write_manifest(self):
        raw = json.dumps(self.tree, sort_keys=True).encode('ascii')
        self.pin = hashlib.sha256(raw).hexdigest(); self.io.add(self.run + '/deployment.json', raw)
    def _loader(self): return f.DeploymentLoader(TOKEN, self.pin, self.io, self.clock)
    def test_full_manifest_graph_reads_every_pin_and_closes_once(self):
        loader = self._loader(); value = loader.load()
        self.assertIsNone(loader.authenticate(value)); self.assertEqual(value.manifest.manifest_sha256, self.pin)
        self.assertEqual(len(loader.owner.rows), len(f.MODULES) + 4)
        self.assertTrue(all(r['closed'] for r in loader.owner.rows))
        self.assertEqual(len(self.io.closes), len(loader.owner.rows))
    def test_source_sha_mismatch_rejects_before_provider(self):
        self.io.add(self.run + '/runtime/mta_ip.py', b'changed\n')
        loader = self._loader()
        with self.assertRaises(f.ExecutorError): loader.load()
        self.assertIsNone(loader.value); self.assertIsNotNone(loader.failure)
    def test_manifest_unknown_or_duplicate_source_rejected(self):
        self.tree['sources'][-1][0] = 'mta_ip'; self._write_manifest()
        loader = self._loader()
        with self.assertRaises(f.ExecutorError): loader.load()
    def test_bools_version_and_native_permissions_rejected(self):
        self.tree['version'] = True; self._write_manifest()
        with self.assertRaises(f.ExecutorError): self._loader().load()
        self.tree['version'] = 1; self._write_manifest()
        self.io.add(self.run + '/native/mta-wpa-supplicant', b'\x7fELFwpa', 0o700)
        with self.assertRaises(f.ExecutorError): self._loader().load()
    def test_unknown_close_cannot_issue_loaded_deployment(self):
        self.io.close_unknown.add(11)
        loader = self._loader()
        with self.assertRaises(f.ExecutorError): loader.load()
        self.assertTrue(loader.owner.pending); self.assertEqual(self.io.closes.count(11), 1)
    def test_no_arbitrary_directory_or_load_retry(self):
        for token in ('../bad', 'a' * 31, True):
            with self.assertRaises(f.ExecutorError): f.DeploymentLoader(token, self.pin)
        loader = self._loader(); loader.load()
        with self.assertRaises(f.ExecutorError): loader.load()


if __name__ == '__main__': unittest.main()
