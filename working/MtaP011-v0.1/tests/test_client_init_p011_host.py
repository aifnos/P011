"""New driver-only HOST fixtures. No ADB, process, socket or real staging."""
import ast
import base64
import builtins
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import types
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
spec = importlib.util.spec_from_file_location('new_client_init_host', str(BASE / 'host/client_init_p011.py'))
driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def fixture_source():
    rows = [(name, digest(b'# HOST fixture only\n'), b'# HOST fixture only\n') for name, pin in driver.PINS]
    native = b'HOST_NOT_A_NATIVE_EXECUTABLE'
    pins = tuple((name, pin) for name, pin, raw in rows)
    source, sha = driver.build_source(rows, native, {}, 'a' * 32, 'b' * 64,
        _pins=pins, _native_pin=digest(native))
    values = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign):
            try: values[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError, AttributeError): pass
    values['payloads'] = {name: raw for name, pin, raw in rows}
    return source, sha, values


class Pipe(object):
    def __init__(self, fd): self.fd, self.closed = fd, False
    def fileno(self):
        if self.closed: raise ValueError('I/O operation on closed file')
        return self.fd


class Process(object):
    def __init__(self, error=None, code=0, close=True):
        self.pid = 800; self.stdin, self.stdout, self.stderr = Pipe(10), Pipe(11), Pipe(12)
        self.error, self.returncode, self.close = error, code, close
        self.calls = []; self.forbidden = []
    def communicate(self, data, timeout):
        self.calls.append((data, timeout))
        if self.error is not None: raise self.error
        if self.close:
            for pipe in (self.stdin, self.stdout, self.stderr): pipe.closed = True
        return b'actual fixture raw', b''
    def kill(self): self.forbidden.append('kill'); raise AssertionError('no kill')
    def terminate(self): self.forbidden.append('terminate'); raise AssertionError('no terminate')


class FakeOS(object):
    O_RDWR, O_CREAT, O_EXCL, O_NOFOLLOW, O_CLOEXEC, O_RDONLY, O_DIRECTORY = 2, 64, 128, 32768, 524288, 0, 16384
    def __init__(self, pending=False):
        self.pending = pending; self.rows = {}; self.fds = {}; self.closed = set(); self.next = 10
        self.calls = []; self.python = b'\x7fELF\x01\x01\x01' + b'\0' * 11 + b'\x28\0' + b'\0' * 44
        self.rows['/python'] = [stat.S_IFREG | 0o500, self.python, 1]
    def metadata(self, path):
        mode, raw, ino = self.rows[path]
        return types.SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode,
            st_uid=0, st_gid=0, st_nlink=1, st_size=len(raw))
    def lstat(self, path):
        self.calls.append(('lstat', path))
        if path == '/tmp/p011-mta-p2p-device.pending':
            if self.pending: return types.SimpleNamespace()
            raise OSError(errno.ENOENT, 'fixture absent')
        if path not in self.rows: raise OSError(errno.ENOENT, 'fixture absent')
        return self.metadata(path)
    def mkdir(self, path, mode):
        self.calls.append(('mkdir', path, mode))
        if path in self.rows: raise OSError(errno.EEXIST, 'fixture exists')
        self.rows[path] = [stat.S_IFDIR | mode, b'', len(self.rows) + 1]
    def listdir(self, path):
        return [p[len(path)+1:] for p in self.rows if p.startswith(path + '/') and '/' not in p[len(path)+1:]]
    def open(self, path, flags, mode=0):
        self.calls.append(('open', path, flags))
        if flags & self.O_CREAT:
            if path in self.rows: raise OSError(errno.EEXIST, 'fixture exists')
            self.rows[path] = [stat.S_IFREG | mode, b'', len(self.rows) + 1]
        if path not in self.rows: raise OSError(errno.ENOENT, 'fixture absent')
        fd = self.next; self.next += 1; self.fds[fd] = [path, 0]; return fd
    def fstat(self, fd):
        if fd not in self.fds or fd in self.closed: raise OSError(errno.EBADF, 'fixture closed')
        return self.metadata(self.fds[fd][0])
    def write(self, fd, raw):
        path, position = self.fds[fd]; previous = self.rows[path][1]
        self.rows[path][1] = previous[:position] + raw + previous[position+len(raw):]
        self.fds[fd][1] += len(raw); return len(raw)
    def fsync(self, fd): self.fstat(fd)
    def lseek(self, fd, offset, whence): self.fstat(fd); self.fds[fd][1] = offset; return offset
    def read(self, fd, count):
        path, position = self.fds[fd]; raw = self.rows[path][1][position:position+count]
        self.fds[fd][1] += len(raw); return raw
    def fchmod(self, fd, mode):
        self.fstat(fd); self.rows[self.fds[fd][0]][0] = stat.S_IFREG | mode
    def close(self, fd):
        if fd in self.closed: raise AssertionError('once original close')
        self.fstat(fd); self.closed.add(fd)


class TargetFixture(object):
    def __init__(self, pending=False, done=True, close_complete=True, reader_error=None):
        self.os = FakeOS(pending); self.calls = []; self.clock = 100.0
        self.done, self.close_complete, self.reader_error = done, close_complete, reader_error
        self.actor = types.SimpleNamespace(pid=100, tasks=('live',), exe='/python', key=lambda: ('actor',))
        owner = self
        class ProcReader(object):
            def __init__(self, timeout): self.closed = reader_error is None
            def read_self(self):
                if reader_error: raise reader_error
                return types.SimpleNamespace(actor=owner.actor, boot='same', kind='live_actor')
            def read_actor(self, pid, actor): return self.read_self()
        class Io(object):
            def validate(self): owner.calls.append('validate')
        class ReadOwner(object):
            def __init__(self, io, clock, deadline): self.rows = []; self.pending = False
            def anchors(self, path, private=False): return ()
            def read_file(self, path, limit, *args, **kwargs):
                row = {'unknown': False, 'closed': True}; self.rows.append(row)
                return owner.os.rows[path][1], row
            def close(self): return True
        class CloseProof(object):
            def complete(self): return owner.close_complete
        class Provider(object):
            def executor(self, deadline): owner.calls.append('executor')
            def snapshot(self, deadline):
                owner.calls.append('snapshot')
                return types.SimpleNamespace(key=lambda: ('full baseline',), stock_actors=(owner.actor,))
            def original_actors(self, snap, deadline): return True
            def close_resources(self, handles, deadline): return CloseProof()
            def closed_resources(self, handles, deadline): return CloseProof()
        class Loader(object):
            def __init__(self, token, sha): owner.calls.append(('loader', token, sha))
            def load(self): return object()
            def authenticate(self, value): return None
        class Parent(object):
            def __init__(self, loaded):
                self.actor = object(); self.spawn_ticket = {'unknown': False}
                self.frames = []; self.failures = []; self.raw = []; self.exit_code = 0; self.pipes = []
            def start(self, ttl):
                owner.calls.append(('start', ttl)); self.frames = [{'client_init_ready': True, 'done': done}]
                return {'attempted': True}
            def finish(self, timeout):
                owner.calls.append(('finish', timeout)); return self.status()
            def poll(self): return None
            def status(self): return {'parent_waited': True, 'parent_absence_verified': True,
                'parent_resources_closed': True, 'resource_pending': not done, 'done': done}
        def meta(value): return tuple(getattr(value, name) for name in
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
        self.modules = {'mta_client_executor': types.SimpleNamespace(_LinuxIo=Io, _ReadOwner=ReadOwner,
            _meta=meta, _actor=lambda observation, *args: observation.actor,
            _reader_closed=lambda reader: reader.closed, ROOT='/tmp/p011-mta-client-rfinit',
            DeploymentLoader=Loader, ParentExecutor=Parent),
            'mta_p2p_client_init': types.SimpleNamespace(CloseProof=CloseProof),
            'mta_client_proc': types.SimpleNamespace(ProcReader=ProcReader),
            'mta_client_linux_provider': types.SimpleNamespace(ProviderManifest=lambda *a, **k: object(),
                assemble=lambda value: (Provider(), None, None, None, None)),
            'p011_json': types.SimpleNamespace(dumps=json.dumps, loads=json.loads)}
    def run(self):
        source, sha, values = fixture_source(); values['modules'] = self.modules
        values.update(base64=base64, hashlib=hashlib)
        imports = {'os': self.os, 'sys': types.SimpleNamespace(flags=types.SimpleNamespace(optimize=0), version_info=(3,5,5)),
            'time': types.SimpleNamespace(monotonic=lambda: self.clock)}
        original = builtins.__import__
        def fake_import(name, *args, **kwargs): return imports[name] if name in imports else original(name, *args, **kwargs)
        output = []
        values['__builtins__'] = dict(vars(builtins), __import__=fake_import, print=lambda text: output.append(text))
        exec(driver.TARGET, values)
        self.values = values
        return ast.literal_eval(output[-1][7:])


class ClientInitHostTests(unittest.TestCase):
    def test_python35_ast_and_all_source_lines_bounded(self):
        source, sha, values = fixture_source()
        ast.parse((BASE / 'host/client_init_p011.py').read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(source, feature_version=(3, 5))
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()), 2048)
        self.assertEqual(len(values['PINS']), 19)
        self.assertEqual(digest(base64.b64decode(values['CANDIDATE_ENCODED'])), sha)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(source))))
    def test_literal_preserves_full_pins_without_single_long_line(self):
        values = tuple((str(i), 'a' * 64) for i in range(32))
        self.assertEqual(ast.literal_eval(driver._literal(values)), values)
        self.assertLessEqual(max(map(len, driver._literal(values).splitlines())), 2048)
    def test_unknown_or_changed_source_cannot_build(self):
        with self.assertRaisesRegex(ValueError, 'source_graph'):
            driver.build_source([], b'', {}, 'a' * 32, 'b' * 64)
    def test_boolean_token_rejected(self):
        with self.assertRaisesRegex(ValueError, 'input_shape'):
            driver.build_source([], b'', {}, True, 'b' * 64)
    def test_reviewed_runtime_source_graph_exact_and_legacy_pending_readonly(self):
        self.assertEqual(driver.PROVIDER_SHA, '8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544')
        self.assertEqual(driver.CLI_SHA, 'e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849')
        tree = ast.parse(driver.TARGET)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        names = [node.func.attr for node in calls if isinstance(node.func, ast.Attribute)]
        self.assertFalse(set(names) & {'kill', 'terminate', 'unlink', 'remove', 'recover', 'rmdir'})
    def test_existing_pending_blocks_before_any_staging_or_provider(self):
        fixture = TargetFixture(pending=True); value = fixture.run()
        self.assertFalse(value['public']['pass']); self.assertEqual(value['public']['reason'], 'pending_blocked')
        self.assertFalse(value['public']['staging_attempted']); self.assertFalse(value['public']['rf_requested'])
        self.assertNotIn('executor', fixture.calls)
        self.assertFalse(any(call[0] == 'mkdir' for call in fixture.os.calls))
    def test_proc_read_error_retains_original_and_pending(self):
        fixture = TargetFixture(reader_error=OSError(errno.EIO, 'fixture private failure')); value = fixture.run()
        self.assertTrue(value['public']['resource_pending']); self.assertFalse(value['public']['rf_requested'])
        self.assertIsNotNone(fixture.values['private']['reads'][0]['owner'])
    def test_fixed_target_fixture_init_and_restore_are_distinct(self):
        fixture = TargetFixture(); value = fixture.run(); self.assertTrue(value['public']['pass'])
        self.assertIn(('start', 20), fixture.calls); self.assertIn(('finish', 45), fixture.calls)
        self.assertFalse(value['public']['send_available']); self.assertFalse(value['public']['receive_available'])
        self.assertTrue(value['public']['client_init_observed']); self.assertTrue(value['public']['restoration_verified'])
        self.assertEqual(len(fixture.os.closed), len(fixture.os.fds))
    def test_ready_does_not_mask_restore_pending(self):
        fixture = TargetFixture(done=False); value = fixture.run()
        self.assertTrue(value['public']['client_init_observed']); self.assertFalse(value['public']['pass'])
        self.assertTrue(value['public']['resource_pending']); self.assertFalse(value['public']['restoration_verified'])
    def test_original_close_proof_required_before_stage(self):
        fixture = TargetFixture(close_complete=False); value = fixture.run()
        self.assertEqual(value['public']['reason'], 'baseline_invalid'); self.assertFalse(value['public']['staging_attempted'])
    def transport(self, process):
        creator = mock.Mock(return_value=process)
        call = driver.HostAdbCall(types.SimpleNamespace(ADB='fixed-adb', select_target=lambda: '8'),
            'FAKE_NO_FILESYSTEM', _popen=creator, _process_type=Process,
            _fstat=lambda fd: (_ for _ in ()).throw(OSError(errno.EBADF, 'fixture closed')))
        call.select(); return call, creator
    def test_transport_communicate_reap_and_actual_wrapper_closed_contract(self):
        process = Process(); call, creator = self.transport(process)
        raw, echo = call.run('print(1)')
        self.assertEqual(raw['host_exit'], 0); self.assertTrue(call.ticket['waited']); self.assertTrue(call.ticket['pipes_closed'])
        self.assertEqual(len(process.calls), 1); self.assertEqual(creator.call_args.kwargs['shell'], False)
        self.assertEqual(creator.call_args.args[0][:4], ['fixed-adb', '-t', '8', 'shell'])
        self.assertFalse(process.forbidden)
    def test_timeout_retains_exact_process_partial_raw_and_no_kill_or_retry(self):
        error = subprocess.TimeoutExpired('private argv', 150, output=b'partial raw', stderr=b'partial error')
        process = Process(error); call, creator = self.transport(process)
        with self.assertRaises(subprocess.TimeoutExpired): call.run('print(1)')
        self.assertIs(call.process, process); self.assertIs(call.ticket['returned'], process)
        self.assertEqual(call.raw, {'stdout': b'partial raw', 'stderr': b'partial error', 'host_exit': 'UNKNOWN'})
        with self.assertRaisesRegex(ValueError, 'once_or_target'): call.run('again')
        self.assertEqual(creator.call_count, 1); self.assertFalse(process.forbidden)
    def test_malformed_return_stays_unknown_with_exact_reference(self):
        process = object(); call, creator = self.transport(process)
        with self.assertRaisesRegex(ValueError, 'process_shape'): call.run('print(1)')
        self.assertTrue(call.ticket['unknown']); self.assertIs(call.process, process)
    def test_closed_pipe_without_ebadf_is_pending_and_keeps_first_raw(self):
        process = Process(); call, creator = self.transport(process); call.fstat = lambda fd: object()
        with self.assertRaisesRegex(ValueError, 'pipe_unknown'): call.run('print(1)')
        self.assertFalse(call.ticket['pipes_closed']); self.assertEqual(call.raw['stdout'], b'actual fixture raw')
    def test_open_pipe_is_not_closed_by_wrapper(self):
        process = Process(close=False); call, creator = self.transport(process)
        with self.assertRaisesRegex(ValueError, 'pipe_unknown'): call.run('print(1)')
        self.assertFalse(call.ticket['pipes_closed']); self.assertFalse(process.stdin.closed)
    def test_negative_host_exit_is_recorded_reaped_but_not_remote_success(self):
        process = Process(code=-15); call, creator = self.transport(process); raw, echo = call.run('print(1)')
        self.assertTrue(call.ticket['waited']); self.assertEqual(raw['host_exit'], -15)
        with self.assertRaisesRegex(ValueError, 'transport_result'): driver.parse(raw, echo)
    def test_bad_transport_id_cannot_spawn(self):
        call = driver.HostAdbCall(types.SimpleNamespace(ADB='fixed', select_target=lambda: True), 'FAKE', _popen=mock.Mock())
        with self.assertRaisesRegex(ValueError, 'target_shape'): call.select()
        call.popen.assert_not_called()
    def raw(self, public=None, extras=''):
        public = public or TargetFixture().run()['public']
        text = 'RESULT=' + repr({'public': public, 'private': {'actual raw': b'private'}}) + '\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n' + extras
        return {'stdout': text.encode('utf-8'), 'stderr': b'', 'host_exit': 0}
    def test_remote_complete_strict_three_frames_and_private_removed_scope(self):
        value = driver.parse(self.raw()); self.assertTrue(value['public']['pass'])
        self.assertFalse(set(value['public']) & {'actual raw', 'mac', 'ip', 'pid', 'path'})
    def test_remote_pass_cannot_hide_missing_restore_or_local_closure(self):
        for key in ('restoration_verified', 'parent_resources_closed', 'baseline_before_after_equal'):
            public = TargetFixture().run()['public']; public[key] = False
            with self.assertRaisesRegex(ValueError, 'false_success'): driver.parse(self.raw(public))
    def test_remote_unknown_or_extra_marker_failclosed(self):
        with self.assertRaisesRegex(ValueError, 'remote_frame'): driver.parse(self.raw(extras='MTA_REMOTE_OK\n'))
        raw = self.raw(); raw['stdout'] = raw['stdout'].replace(b'MTA_REMOTE_EXIT=0', b'MTA_REMOTE_EXIT=UNKNOWN')
        with self.assertRaisesRegex(ValueError, 'remote_frame'): driver.parse(raw)
    def test_source_echo_is_not_a_result_frame(self):
        raw = self.raw(); echo = b"print('RESULT=not actual')\n"
        raw['stdout'] = echo + raw['stdout']; self.assertTrue(driver.parse(raw, echo)['public']['pass'])
        with self.assertRaisesRegex(ValueError, 'remote_frame'): driver.parse(raw)
    def test_invalid_public_boolean_enum_and_capability_rejected(self):
        for key, value in (('pass', 1), ('stage', []), ('send_available', True)):
            public = TargetFixture().run()['public']; public[key] = value
            with self.assertRaisesRegex(ValueError, 'public_shape'): driver.parse(self.raw(public))
    def test_truncated_or_host_stderr_cannot_be_success(self):
        raw = self.raw(); raw['stdout'] = raw['stdout'][:-5]
        with self.assertRaises(ValueError): driver.parse(raw)
        raw = self.raw(); raw['stderr'] = b'private error'
        with self.assertRaisesRegex(ValueError, 'transport_result'): driver.parse(raw)
    def test_default_main_source_only_never_calls_execute_or_host_popen(self):
        with mock.patch.object(driver, 'source_check', return_value=({'source_check_pass': True}, None, None, None, None)), \
                mock.patch.object(driver, 'execute', side_effect=AssertionError('no execute')), mock.patch('builtins.print'):
            self.assertEqual(driver.main([]), 0)
    def test_unavailable_source_blocks_before_host_transport_and_output(self):
        with self.assertRaisesRegex(ValueError, 'unavailable_or_reviewed'):
            driver.execute('a' * 64, _check=lambda: ({'source_check_pass': False, 'driver_sha256': 'a' * 64}, None, None, None, None),
                _transport_factory=mock.Mock(side_effect=AssertionError('no transport')))
    def test_source_only_cmd_has_no_execution_flag(self):
        text = (BASE / 'HOST_CLIENT_INIT_SOURCE_CHECK.cmd').read_text(encoding='utf-8')
        self.assertIn('python -B host\\client_init_p011.py', text)
        self.assertNotIn('--execute-reviewed', text)
    def test_actual_pinned_pc_sources_only_build_complete_bounded_target(self):
        # PC source/fixed historical fact reads only; no target or OS calls.
        report, rows, native, manifest, unused = driver.source_check()
        self.assertTrue(report['source_check_pass']); self.assertEqual(report['source_count'], 19)
        source, candidate_sha = driver.build_source(rows, native, manifest, 'c' * 32, report['driver_sha256'])
        ast.parse(source, feature_version=(3, 5))
        self.assertLessEqual(len(source.encode('utf-8')), driver.MAX_SOURCE)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in source.splitlines()), 2048)
        self.assertEqual(len(candidate_sha), 64)
        self.assertFalse(report['send_available']); self.assertFalse(report['receive_available'])
    def test_windows_path_ctime_is_stable_without_equating_fd_creation_time(self):
        raw = b'FIXTURE'
        before = types.SimpleNamespace(st_dev=1, st_ino=2, st_size=len(raw), st_mode=stat.S_IFREG,
            st_mtime_ns=3, st_ctime_ns=4)
        opened = types.SimpleNamespace(**dict(vars(before), st_ctime_ns=5))
        handle = mock.MagicMock(); handle.__enter__.return_value = handle; handle.fileno.return_value = 10; handle.read.return_value = raw
        path = mock.Mock(); path.parents = (); path.is_symlink.return_value = False
        path.stat.return_value = before; path.open.return_value = handle
        with mock.patch.object(driver.os, 'name', 'nt'), mock.patch.object(driver.os, 'fstat', return_value=opened):
            self.assertEqual(driver._read(path, digest(raw)), raw)
            after = types.SimpleNamespace(**dict(vars(before), st_ctime_ns=6)); path.stat.side_effect = [before, after]
            with self.assertRaisesRegex(ValueError, 'source_changed'): driver._read(path, digest(raw))


if __name__ == '__main__': unittest.main()
