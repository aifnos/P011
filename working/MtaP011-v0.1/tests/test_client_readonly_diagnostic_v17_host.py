"""New v17 SOURCE/Fake notes only; never run TARGET or an actual OS query."""
import ast
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
PATH = BASE / 'host/client_readonly_diagnostic_v17_p011.py'
spec = importlib.util.spec_from_file_location('readonly_diagnostic_v17', str(PATH))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class FakeIo(object):
    def __init__(self, data=None, open_error=None, read_error=None, list_error=None):
        self.data = data or {}; self.open_error = open_error; self.read_error = read_error
        self.list_error = list_error; self.rows = {}; self.calls = []; self.next_fd = 10
    def validate(self): self.calls.append(('validate',))
    def listdir(self, path):
        self.calls.append(('listdir', path))
        if self.list_error is not None: raise self.list_error
        return ['41']
    def open(self, path, flags):
        self.calls.append(('open', path, flags))
        if self.open_error is not None: raise self.open_error
        fd = self.next_fd; self.next_fd += 1
        self.rows[fd] = {'path': path, 'at': 0, 'closed': False}
        return fd
    def stat(self, path):
        directory = path in ('/', '/fixed')
        return types.SimpleNamespace(st_dev=1, st_ino=1 if directory else 2,
            st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o444),
            st_uid=0, st_gid=0, st_nlink=2 if directory else 1,
            st_size=0 if directory else len(self.data.get(path, b'')),
            st_mtime_ns=0, st_ctime_ns=0)
    def fstat(self, fd):
        if self.rows[fd]['closed']: raise OSError(9, 'fixture EBADF')
        return self.stat(self.rows[fd]['path'])
    def read(self, fd, count):
        self.calls.append(('read', fd, count))
        if self.read_error is not None: raise self.read_error
        row = self.rows[fd]; raw = self.data.get(row['path'], b'')
        chunk = raw[row['at']:row['at'] + count]; row['at'] += len(chunk)
        return chunk
    def close(self, fd):
        self.calls.append(('close', fd)); self.rows[fd]['closed'] = True


class ReadonlyDiagnosticV17Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch('socket.socket', side_effect=AssertionError('no socket')), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('no child')), \
                mock.patch('os.mkdir', side_effect=AssertionError('no stage')):
            cls.profile = d.configured_profile()
            cls.report, cls.rows, cls.native, cls.manifest, cls.ref = cls.profile.source_check()
            cls.source, cls.candidate_sha, cls.derived_sha = cls.profile.build_source(
                cls.rows, cls.native, cls.manifest, 'a' * 32, cls.report['driver_sha256'])
        cls.prefix = cls.source[:cls.source.index(cls.profile.TARGET)]

    def setUp(self):
        for name in ('os.open', 'os.mkdir', 'os.unlink', 'os.kill', 'socket.socket', 'subprocess.Popen'):
            patcher = mock.patch(name, side_effect=AssertionError('no actual OS/ADB/RF'))
            patcher.start(); self.addCleanup(patcher.stop)
        self.values = {}; exec(self.prefix, self.values)
        exec(d._INJECTION, self.values)
        self.status = self.values['modules']['mta_client_wpa_status']

    def files(self, io):
        return self.status._ReadFiles(io, lambda: 100., 110.,
            {'daemon_exe': '/fixed/image', 'daemon_sha256': 'a' * 64})

    def source_owner(self, io):
        source = object.__new__(self.status.LinuxStatusSource)
        source._io = io; source._clock = lambda: 100.; source._reader = None
        source._consumer = None; source._issued = []; source._files = []; source._raw = []
        source._actor_calls = []; source._pending = False
        source._manifest = {'daemon_exe': '/fixed/image', 'daemon_sha256': 'a' * 64,
            'real_uid': 0, 'real_gid': 0}
        source._actor = lambda *args, **kwargs: types.SimpleNamespace(actor=None, boot='fixture')
        return source

    def test_exact_nineteen_graph_target_reverse_method_ast_and_python35(self):
        self.assertEqual(19, len(self.rows)); self.assertEqual(19, len(self.values['modules']))
        self.assertEqual(d.V6_SHA, hashlib.sha256(d.V6.read_bytes()).hexdigest())
        self.assertEqual(d.NOTES_SHA, hashlib.sha256(d.NOTES.read_bytes()).hexdigest())
        self.assertEqual(hashlib.sha256(PATH.read_bytes()).hexdigest(), self.report['driver_sha256'])
        fixed_text = (BASE / 'host/client_baseline_v3_performance_p011.py').read_text()
        fixed = ast.literal_eval(next(n.value for n in ast.parse(fixed_text).body
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'TARGET' for t in n.targets)))
        reverse = self.profile.TARGET.replace(d._INJECTION, '', 1).replace(d._PROJECTION, '', 1)
        self.assertEqual(fixed, reverse)
        self.assertEqual(dict(self.ref.PINS), dict((n, pin) for n, pin, raw in self.rows))
        self.assertEqual(self.ref.LOADER.count(' payloads[name]=raw\n'), 1)
        self.assertEqual(self.status._v17_read_source, self.status.LinuxStatusSource.read_source)
        method = d._source_method((BASE / 'runtime/mta_client_wpa_status.py').read_bytes())
        note = "        _v17_record(files, caught, 'source_before_finally', None, None)\n"
        self.assertEqual(1, method.count(note))
        self.assertLess(method.index(note), method.index('\n    finally:\n'))
        self.assertEqual(self.derived_sha, '4270852f4a7719fa663067e407acde800ae84da4b3ed7ab7fbeb6e9e0e0c9c20')
        for raw in (PATH.read_bytes(), d.NOTES.read_bytes(), Path(__file__).read_bytes(), self.source.encode()):
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        self.assertLessEqual(max(len(line.encode()) for line in self.source.splitlines()), 2048)
        self.assertLessEqual(len(self.source.encode()), 4 * 1024 * 1024)

    def test_actual_open_oserror_same_object_no_fd_and_anonymous_original_ordinal(self):
        failure = PermissionError(13, 'SECRET MESSAGE', '/proc/987654/comm')
        io = FakeIo(open_error=failure); files = self.files(io)
        with self.assertRaises(PermissionError) as caught: files._read_file('/proc/987654/comm', 128)
        self.assertIs(failure, caught.exception)
        self.assertEqual(1, len(files._tickets)); row = files._tickets[0]
        self.assertIs(row, files._v17_first_row)
        self.assertEqual((None, False, True), (row['fd'], row['unknown'], row['closed']))
        self.assertTrue(files.close()); self.assertFalse(files._pending)
        note = self.values['_v17_project'](files)
        self.assertEqual({'builtin_class': 'PermissionError', 'errno': 13, 'phase': 'file_open',
            'path_family': 'proc_comm', 'ticket_ordinal': 1, 'note_unknown': False}, note)
        self.assertEqual(1, sum(x[0] == 'open' for x in io.calls))
        self.assertEqual(0, sum(x[0] == 'close' for x in io.calls))
        self.assertNotIn('987654', repr(note)); self.assertNotIn('SECRET', repr(note))

    def test_actual_read_error_once_close_and_note_format_failure_never_masks(self):
        failure = InterruptedError(4, 'PRIVATE', '/proc/41/status')
        io = FakeIo({'/proc/41/status': b'x'}, read_error=failure); files = self.files(io)
        with self.assertRaises(InterruptedError) as caught: files._read_file('/proc/41/status', 128)
        self.assertIs(failure, caught.exception); self.assertTrue(files.close())
        self.assertEqual(1, sum(x[0] == 'read' for x in io.calls))
        self.assertEqual(1, sum(x[0] == 'close' for x in io.calls))
        self.assertEqual('file_read', self.values['_v17_project'](files)['phase'])
        self.assertEqual('proc_status', self.values['_v17_project'](files)['path_family'])
        other = self.files(FakeIo(open_error=failure))
        with mock.patch.dict(self.values, {'_v17_family': mock.Mock(side_effect=MemoryError('note only'))}):
            with self.assertRaises(InterruptedError) as caught: other._read_file('/proc/41/status', 128)
        self.assertIs(caught.exception, failure); self.assertIs(other._v17_first_error, failure)
        self.assertTrue(self.values['_v17_project'](other)['note_unknown'])

    def test_actual_source_first_open_error_survives_original_finally_close_override(self):
        failure = FileNotFoundError(2, 'PRIVATE', '/proc/41/comm')
        io = FakeIo(open_error=failure); source = self.source_owner(io)
        with mock.patch.object(self.status._ReadFiles, 'close', return_value=False):
            with self.assertRaises(self.status.WpaStatusError) as caught: source.read_source(object(), 110.)
        self.assertEqual('close_unknown', caught.exception.code); self.assertTrue(source._pending)
        self.assertEqual([], source._issued); self.assertEqual(1, len(source._files))
        files = source._files[0]; self.assertIs(files._v17_first_error, failure)
        note = self.values['_v17_project'](files)
        self.assertEqual(('FileNotFoundError', 2, 'file_open', 'proc_comm', 1),
            tuple(note[k] for k in ('builtin_class', 'errno', 'phase', 'path_family', 'ticket_ordinal')))
        self.assertEqual(1, sum(x[0] == 'listdir' for x in io.calls))
        self.assertEqual(1, sum(x[0] == 'open' for x in io.calls))

    def test_actual_source_body_first_errno_before_cleanup_without_borrowed_ticket(self):
        failure = PermissionError(13, 'PRIVATE', '/proc')
        io = FakeIo(list_error=failure); source = self.source_owner(io)
        with mock.patch.object(self.status._ReadFiles, 'close', return_value=False):
            with self.assertRaises(self.status.WpaStatusError): source.read_source(object(), 110.)
        files = source._files[0]; self.assertIs(files._v17_first_error, failure)
        self.assertEqual({'builtin_class': 'PermissionError', 'errno': 13,
            'phase': 'source_before_finally', 'path_family': 'proc_directory',
            'ticket_ordinal': None, 'note_unknown': False}, self.values['_v17_project'](files))
        self.assertEqual([], files._tickets); self.assertTrue(source._pending)

    def test_actual_source_success_original_return_reference_queries_and_closed_proof(self):
        core = self.values['modules']['mta_p2p_client_init']
        command = b'fixture-wpa\0'; image = b'fixture-image'
        daemon = core.Actor(41, 7, '/fixed/image', hashlib.sha256(command).hexdigest(), ((41, 7, 'S'),))
        executor = core.Actor(42, 8, '/fixed/python', 'b' * 64, ((42, 8, 'R'),))
        data = {'/proc/41/comm': b'wpa_supplicant\n', '/proc/41/cmdline': command,
            '/proc/41/status': b'Uid:\t0 0 0 0\nGid:\t0 0 0 0\n',
            '/fixed/image': image, '/proc/41/exe': image}
        io = FakeIo(data); source = self.source_owner(io)
        source._manifest['daemon_sha256'] = hashlib.sha256(image).hexdigest()
        source._actor = lambda files, pid=None, expected=None: types.SimpleNamespace(
            boot='fixture', actor=executor if pid is None else daemon)
        source._namespaces = lambda *args: ((), {})
        source._endpoint = lambda *args: ((), (), 1, '/fixed/endpoint', ())
        consumer = object()
        with mock.patch.object(self.status, '_source_key', return_value=('FAKE_ONLY',)):
            result = source.read_source(consumer, 110.)
        self.assertIs(result, source._issued[0][1]); self.assertIs(consumer, source._issued[0][0])
        self.assertIs(source._files[0], source._issued[0][3]); self.assertFalse(source._pending)
        self.assertIsNone(self.values['_v17_project'](source._files[0]))
        self.assertEqual(5, sum(x[0] == 'open' for x in io.calls))
        self.assertEqual(5, sum(x[0] == 'close' for x in io.calls))
        self.assertTrue(all(p.complete() for p in result['files_closed']))

    def test_exact_builtin_not_spoofed_and_first_note_never_overwritten(self):
        spoof = type('PermissionError', (OSError,), {'__module__': 'builtins'})
        files = self.files(FakeIo()); original = spoof(13, 'PRIVATE', '/proc/987654/comm')
        self.values['_v17_record'](files, original, 'source_before_finally', None, None)
        note = self.values['_v17_project'](files)
        self.assertEqual('NON_BUILTIN', note['builtin_class']); self.assertIsNone(note['errno'])
        self.assertEqual('not_available', note['path_family'])
        self.values['_v17_record'](files, PermissionError(1, 'other'), 'file_open', '/secret/address', 0)
        self.assertIs(files._v17_first_error, original); self.assertEqual(note, self.values['_v17_project'](files))
        self.assertNotIn('987654', repr(note)); self.assertNotIn('/proc/', repr(note)); self.assertNotIn('PRIVATE', repr(note))

    def test_public_strict_schema_default_source_only_and_note_not_admission(self):
        public = dict((k, False) for k in self.profile.BOOLS); public.update((k, 0) for k in self.profile.COUNTS)
        public.update(source_check_pass=True, resource_pending=True, stage='baseline_before',
            reason='baseline_failed', failure_site='not_recorded')
        private = {'source_first_failures': ({'builtin_class': 'FileNotFoundError', 'errno': 2,
            'phase': 'file_open', 'path_family': 'proc_comm', 'ticket_ordinal': 199, 'note_unknown': False},)}
        raw = {'stdout': ('RESULT=' + repr({'public': public, 'private': private}) +
            '\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode(), 'stderr': b'', 'host_exit': 0}
        result = self.profile.parse(raw); self.assertEqual(public, result['public'])
        self.assertTrue(result['public']['resource_pending']); self.assertFalse(result['public']['diagnostic_complete'])
        self.assertNotIn('builtin_class', result['public']); self.assertNotIn('errno', result['public'])
        bad = dict(public, errno=2)
        raw['stdout'] = ('RESULT=' + repr({'public': bad, 'private': private}) +
            '\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode()
        with self.assertRaises(ValueError): self.profile.parse(raw)
        with mock.patch.object(d, 'configured_profile', return_value=types.SimpleNamespace(
                source_check=lambda: ({'source_check_pass': True},),
                execute=mock.Mock(side_effect=AssertionError('no execution')))), mock.patch('builtins.print'):
            self.assertEqual(0, d.main([]))


if __name__ == '__main__': unittest.main()
