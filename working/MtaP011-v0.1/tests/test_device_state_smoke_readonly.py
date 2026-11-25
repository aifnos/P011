"""HOST synthetic filesystem/proc/dispatch only; no device or real socket."""
import ast
import base64
import builtins
import contextlib
import copy
import errno
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock
import zlib

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'host'))
import device_state_smoke_readonly as checker


A = '/mnt/data/p011-toolbox'
STOCK = tuple(checker.PINS)


def metadata(mode=stat.S_IFREG | 0o600, size=0, uid=0, nlink=1, ino=10):
    return types.SimpleNamespace(st_dev=1, st_ino=ino, st_mode=mode, st_uid=uid,
        st_nlink=nlink, st_size=size, st_mtime=1, st_ctime=1)


def process(name, exe=None, args=None, start=100, parent=1):
    return {'name': name, 'exe': exe or '/usr/bin/' + name,
        'args': args or [('/usr/bin/' + name).encode('ascii')], 'start': start, 'parent': parent}


class Environment:
    """No real FD/proc/net operations: exact fixture identities are private."""
    def __init__(self):
        self.clock = 0; self.current = -1; self.fd = 20
        self.opened = []; self.closed = []; self.read_counts = []; self.listdir_calls = []
        self.fd_metadata = {}; self.calls = {}; self.faults = {}; self.close_error = False
        self.deadline = False; self.proc_names = None; self.journal_names = []
        self.proc_first = {'7': process('Z03'), '8': process('control_engine'), '9': process('weston'),
            '10': process('connmand'), '11': process('wpa_supplicant')}
        self.proc_second = copy.deepcopy(self.proc_first)
        self.ifaces_first = {'lo': 1, 'wlan0': 4}; self.ifaces_second = dict(self.ifaces_first)
        self.data = {path: ('HOST SYNTHETIC STOCK ' + str(index)).encode('ascii') for index, path in enumerate(STOCK)}
        self.pins = {path: hashlib.sha256(value).hexdigest() for path, value in self.data.items()}
        self.data.update({'/proc/sys/kernel/random/boot_id': b'HOST-PRIVATE-BOOT',
            '/proc/net/route': b'HOST PRIVATE ROUTE', '/proc/net/if_inet6': b'HOST PRIVATE IPV6 ADDRESS',
            '/proc/net/ipv6_route': b'HOST PRIVATE IPV6 ROUTE'})
        self.meta = {path: metadata(size=len(value), ino=index + 20) for index, (path, value) in enumerate(self.data.items())}
        for index, path in enumerate((A, A + '/sessions', A + '/sessions/mta-network')):
            self.meta[path] = metadata(mode=stat.S_IFDIR | 0o700, ino=index + 1)
        self.realpaths = {}; self.changed_cmd = {}; self.changed_stat = {}; self.changed_exe = {}
        self.network_changed = False; self.stock_changed = False; self.fstat_changed = False

    def monotonic(self):
        self.clock += 1
        return self.clock * (13 if self.deadline else .001)

    def lstat(self, path):
        if path in self.faults: raise self.faults[path]
        if path not in self.meta: raise OSError(errno.ENOENT, 'HOST_SECRET_ABSENT')
        return self.meta[path]

    def listdir(self, path):
        self.listdir_calls.append(path)
        if path in self.faults: raise self.faults[path]
        if path == A + '/sessions/mta-network': return self.journal_names
        if path == '/proc':
            self.current += 1
            return self.proc_names if self.proc_names is not None else list(self.rows()) + ['self', 'uptime']
        if path == '/sys/class/net': return list(self.ifaces())
        raise AssertionError('HOST arbitrary directory')

    def rows(self): return self.proc_first if self.current < 1 else self.proc_second
    def ifaces(self): return self.ifaces_first if self.current < 1 else self.ifaces_second

    def readlink(self, path):
        if path in self.faults: raise self.faults[path]
        parts = path.split('/')
        if len(parts) != 4 or parts[1] != 'proc' or parts[3] != 'exe': raise AssertionError('HOST arbitrary link')
        key = (self.current, path); self.calls[key] = self.calls.get(key, 0) + 1
        return self.changed_exe.get(parts[2], self.rows()[parts[2]]['exe']) if self.calls[key] > 1 else self.rows()[parts[2]]['exe']

    def value(self, path):
        if path in self.data:
            value = self.data[path]
            if self.current == 1 and (self.stock_changed and path in STOCK or self.network_changed and path == '/proc/net/route'):
                return value + b'HOST SECRET CHANGED'
            return value
        if path.startswith('/sys/class/net/') and path.endswith('/ifindex'):
            name = path.split('/')[4]
            return str(self.ifaces()[name]).encode('ascii') + b'\n'
        parts = path.split('/')
        if len(parts) != 4 or parts[1] != 'proc' or parts[3] not in ('stat', 'cmdline'): raise AssertionError('HOST arbitrary read')
        row = self.rows()[parts[2]]; key = (self.current, path)
        self.calls[key] = self.calls.get(key, 0) + 1
        if parts[3] == 'cmdline':
            args = self.changed_cmd.get(parts[2], row['args']) if self.calls[key] > 1 else row['args']
            return b'\0'.join(args) + b'\0'
        start = self.changed_stat.get(parts[2], row['start']) if self.calls[key] > 1 else row['start']
        fields = [b'S', str(row['parent']).encode('ascii')] + [b'1'] * 17 + [str(start).encode('ascii')]
        return parts[2].encode('ascii') + b' (' + row['name'].encode('ascii') + b') ' + b' '.join(fields)

    def open(self, path, mode):
        if mode != 'rb': raise AssertionError('HOST writing mode')
        if path in self.faults: raise self.faults[path]
        value = self.value(path); self.opened.append(path); self.fd += 1; fd = self.fd
        if path in self.meta: self.fd_metadata[fd] = self.meta[path]
        env = self
        class File:
            position = 0
            def __enter__(self): return self
            def fileno(self): return fd
            def read(self, limit):
                env.read_counts.append(limit); block = value[self.position:self.position + limit]; self.position += len(block); return block
            def __exit__(self, *unused):
                env.closed.append(path)
                if env.close_error: raise OSError('HOST_SECRET_CLOSE')
        return File()

    def fstat(self, fd):
        row = self.fd_metadata[fd]
        if not self.fstat_changed: return row
        value = copy.copy(row); value.st_ino += 1; return value

    def execute(self):
        modules = {'hashlib': hashlib, 'stat': stat,
            'os': types.SimpleNamespace(lstat=self.lstat, fstat=self.fstat, listdir=self.listdir,
                readlink=self.readlink, geteuid=lambda: 0, path=types.SimpleNamespace(realpath=lambda path: self.realpaths.get(path, path))),
            'time': types.SimpleNamespace(monotonic=self.monotonic, sleep=lambda duration: None)}
        def importer(name, *unused, **kwargs):
            if name not in modules: raise AssertionError('HOST forbidden import')
            return modules[name]
        namespace = {'__builtins__': dict(vars(builtins), __import__=importer, open=self.open)}
        stream = io.StringIO()
        # Only the HOST fixture has synthetic stock digests. Production payload uses actual pins.
        with mock.patch.object(checker, 'PINS', self.pins): program = checker.source()
        with contextlib.redirect_stdout(stream): exec(program, namespace)
        lines = stream.getvalue().splitlines()
        if len(lines) != 1 or not lines[0].startswith('RESULT='): raise AssertionError('HOST fixed output')
        value = checker.validate_result(ast.literal_eval(lines[0][7:]))
        return value, stream.getvalue(), namespace


class ProgramTests(unittest.TestCase):
    def test_python35_ast_short_argv_roundtrip_and_no_mutation_socket_state_api(self):
        program = checker.source(); tree = ast.parse(program, feature_version=(3, 5)); command = checker.compressed_command(program)
        self.assertLess(len(command.encode('ascii')), 3500)
        self.assertLessEqual(len(program.encode('utf-8')), checker.MAX_SOURCE_BYTES)
        self.assertLessEqual(max(map(len, program.encode('utf-8').splitlines())), 2048)
        self.assertNotIn('exec(sys.stdin', command)
        payload = command.split("base64.b64decode('", 1)[1].split("')", 1)[0]
        self.assertEqual(zlib.decompress(base64.b64decode(payload)).decode('utf-8'), program)
        self.assertEqual({node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}, {'hashlib'})
        names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertEqual(names, {'hashlib', 'os', 'stat', 'time'})
        forbidden = {'Popen', 'socket', 'Thread', 'State', 'run', 'bind', 'connect', 'listen', 'send', 'sendto',
            'kill', 'terminate', 'system', 'chmod', 'unlink', 'remove', 'mkdir', 'makedirs', 'write', 'restore', 'recover_pending'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ''
                self.assertNotIn(name, forbidden)

    def test_clear_synthetic_observation_is_not_state_or_admission(self):
        env = Environment(); value, text, namespace = env.execute()
        self.assertTrue(value['complete']); self.assertTrue(value['snapshots_consistent']); self.assertTrue(checker.blockers_clear(value))
        self.assertEqual(env.opened, env.closed); self.assertTrue(namespace['first'][1][2])
        for secret in ('HOST PRIVATE', 'HOST-PRIVATE', '/usr/bin', 'pid', 'token'): self.assertNotIn(secret, text)

    def test_pending_ui_native_menu_each_blocks_without_reading_contents(self):
        for path in ('/tmp/p011-mta-p2p-device.pending', A + '/mta-ui.lock', A + '/native.lock', '/mnt/data/p011-menu'):
            with self.subTest(path=path):
                env = Environment(); env.meta[path] = metadata(mode=stat.S_IFLNK | 0o777)
                value, text, unused = env.execute()
                self.assertTrue(value['complete']); self.assertFalse(checker.blockers_clear(value)); self.assertNotIn(path, env.opened)

    def test_sta_journal_entries_block_no_receipt_credentials_user_reads(self):
        env = Environment(); env.journal_names = ['HOST_SECRET_LEASE.ini']
        value, text, unused = env.execute(); self.assertEqual(value['sta_journal_entries'], 1)
        self.assertFalse(checker.blockers_clear(value)); self.assertNotIn('HOST_SECRET', text)
        self.assertFalse(any('HOST_SECRET' in path or '/user/' in path for path in env.opened))

    def test_unsafe_parent_journal_mode_or_owner_never_follow_directory(self):
        for path, field, bad in ((A, 'st_mode', stat.S_IFLNK | 0o777), (A, 'st_uid', 1),
                (A + '/sessions/mta-network', 'st_mode', stat.S_IFDIR | 0o755)):
            env = Environment(); setattr(env.meta[path], field, bad)
            value, unused, namespace = env.execute(); self.assertFalse(value['complete']); self.assertFalse(checker.blockers_clear(value))
            self.assertNotIn(A + '/sessions/mta-network', env.listdir_calls)
        env = Environment(); env.realpaths[A] = '/HOST_SECRET_FOREIGN'
        self.assertFalse(env.execute()[0]['complete'])

    def test_missing_journal_is_only_observed_absence_not_cleanup(self):
        env = Environment(); del env.meta[A + '/sessions/mta-network']
        value, unused, namespace = env.execute(); self.assertTrue(checker.blockers_clear(value))
        self.assertNotIn(A + '/sessions/mta-network', env.listdir_calls)

    def test_known_project_and_all_prior_marker_shapes_block(self):
        rows = {'12': process('HOST_PRIVATE_HELPER', A + '/candidates/mta-01-0000000000000000/native/mta-bluez-helper'),
            '13': process('python3', args=[b'python3', b'-c', (A + '/sessions/HOST_SECRET').encode('ascii')]),
            '14': process('python3', args=[b'python3', b'mta-prior-readonly']),
            '15': process('python3', args=[b'python3', b'-c', b'HOST_SECRET_CODE', b'mta-readonly-probe'])}
        env = Environment(); env.proc_first.update(rows); env.proc_second.update(copy.deepcopy(rows))
        value, text, unused = env.execute(); self.assertEqual(value['known_project_actors_first'], 2)
        self.assertEqual(value['prior_marker_actors_second'], 2); self.assertFalse(checker.blockers_clear(value))
        self.assertNotIn('HOST_SECRET', text)

    def test_project_interface_presence_index_change_and_boot_network_change(self):
        env = Environment(); env.ifaces_first['mta12345678'] = 5; env.ifaces_second['mta12345678'] = 5
        value, unused, namespace = env.execute(); self.assertEqual(value['project_interfaces_first'], 1); self.assertFalse(checker.blockers_clear(value))
        env = Environment(); env.ifaces_second['wlan0'] = 8
        value, unused, namespace = env.execute(); self.assertFalse(value['interface_identities_unchanged']); self.assertFalse(value['snapshots_consistent'])
        env = Environment(); env.network_changed = True
        value, unused, namespace = env.execute(); self.assertFalse(value['basic_network_files_unchanged'])

    def test_process_id_starttime_and_reread_swaps_fail_closed(self):
        for mode in ('across', 'cmdline', 'stat', 'exe'):
            env = Environment()
            if mode == 'across': env.proc_second['7']['start'] = 1000
            elif mode == 'cmdline': env.changed_cmd['7'] = [b'HOST_SECRET_CHANGED']
            elif mode == 'stat': env.changed_stat['7'] = 1000
            else: env.changed_exe['7'] = '/HOST_SECRET_FOREIGN'
            value, text, unused = env.execute(); self.assertFalse(checker.blockers_clear(value)); self.assertFalse(value['snapshots_consistent'])
            if mode != 'across': self.assertFalse(value['complete'])
            self.assertNotIn('HOST_SECRET', text)

    def test_stock_type_owner_link_hash_fd_swap_and_close_error(self):
        for mode in ('type', 'uid', 'nlink', 'hash', 'fstat', 'close'):
            env = Environment()
            if mode == 'type': env.meta[STOCK[0]].st_mode = stat.S_IFLNK | 0o777
            elif mode == 'uid': env.meta[STOCK[0]].st_uid = 1
            elif mode == 'nlink': env.meta[STOCK[0]].st_nlink = 2
            elif mode == 'hash': env.data[STOCK[0]] = b'HOST_SECRET_CHANGED'; env.meta[STOCK[0]].st_size = len(env.data[STOCK[0]])
            elif mode == 'fstat': env.fstat_changed = True
            else: env.close_error = True
            value, text, unused = env.execute(); self.assertFalse(checker.blockers_clear(value))
            self.assertEqual(env.opened, env.closed); self.assertNotIn('HOST_SECRET', text)

    def test_unknown_proc_read_permission_and_bounded_transient_races(self):
        env = Environment(); env.faults['/proc/7/cmdline'] = OSError(errno.EACCES, 'HOST_SECRET_ERROR')
        value, text, unused = env.execute(); self.assertFalse(value['complete']); self.assertNotIn('HOST_SECRET', text)
        for number in (errno.ENOENT, errno.ESRCH):
            env = Environment(); env.faults['/proc/10/cmdline'] = OSError(number, 'HOST_SECRET_TRANSIENT')
            self.assertTrue(env.execute()[0]['complete'])
        env = Environment()
        for index in range(33):
            pid = str(100 + index); env.proc_first[pid] = process('HOST_PRIVATE_UNKNOWN')
            env.faults['/proc/' + pid + '/cmdline'] = OSError(errno.ENOENT, 'HOST_SECRET_RACE')
        self.assertFalse(env.execute()[0]['complete'])

    def test_count_read_and_deadline_bounds_are_incomplete(self):
        cases = []
        env = Environment(); env.proc_names = [str(index) for index in range(513)]; cases.append(env)
        env = Environment(); env.proc_names = ['self'] * 4097; cases.append(env)
        env = Environment(); env.journal_names = ['HOST_SECRET'] * 17; cases.append(env)
        env = Environment(); env.ifaces_first = {str(index): index + 1 for index in range(65)}; cases.append(env)
        env = Environment(); env.data['/proc/net/route'] = b'x' * 1048577; cases.append(env)
        env = Environment(); env.deadline = True; cases.append(env)
        for env in cases:
            value, text, unused = env.execute(); self.assertFalse(value['complete']); self.assertFalse(checker.blockers_clear(value))
            self.assertEqual(env.opened, env.closed); self.assertTrue(all(limit <= 1048577 for limit in env.read_counts))

    def test_p2p_lock_presence_is_not_lock_held_but_unsafe_blocks(self):
        path = '/tmp/p011-mta-p2p-device.lock'
        env = Environment(); env.meta[path] = metadata(); self.assertTrue(checker.blockers_clear(env.execute()[0]))
        env.meta[path].st_mode = stat.S_IFLNK | 0o777
        value, unused, namespace = env.execute(); self.assertFalse(value['p2p_lock_safe']); self.assertFalse(checker.blockers_clear(value))
        self.assertNotIn(path, env.opened)

    def test_schema_rejects_private_truthy_missing_inconsistent_unbounded_fields(self):
        baseline = Environment().execute()[0]
        for key, bad in (('pid', 1), ('complete', 1), ('sta_journal_entries', True), ('sta_journal_entries', 17),
                ('known_project_actors_first', 513), ('project_interfaces_first', 65), ('p2p_pending_present', 'false')):
            value = dict(baseline); value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError): checker.validate_result(value)
        value = dict(baseline); del value['complete']
        with self.assertRaises(ValueError): checker.validate_result(value)
        value = dict(baseline); value['known_project_actors_second'] = 1
        with self.assertRaises(ValueError): checker.validate_result(value)
        value = dict(baseline); value['complete'] = False
        with self.assertRaises(ValueError): checker.validate_result(value)


class DispatchTests(unittest.TestCase):
    def dispatch(self, value, failed=False):
        calls = []
        class FakeAdb:
            def __init__(self, directory): calls.append(('construct', Path(directory).name))
            def python(self, label, program, timeout):
                calls.append((label, program, timeout))
                if failed: raise RuntimeError('HOST_SECRET_PID_PATH')
                return copy.deepcopy(value)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(checker, 'Adb', FakeAdb), mock.patch.object(checker, 'verify_reviewed_sources', return_value=True):
            out = Path(directory) / 'observation'; report, returned = checker.run_check(out)
            self.assertEqual(out, returned); self.assertEqual({path.name for path in out.iterdir()}, {'result.json', 'README.txt'})
            public = (out / 'result.json').read_text(encoding='utf-8'); self.assertNotIn('HOST_SECRET', public)
            self.assertEqual(list(Path(directory).glob('*.zip')), [])
            for key in ('staging_allowed', 'run_allowed', 'radio_operations', 'device_writes', 'cleanup_invoked', 'signals_sent', 'candidate_executed'):
                self.assertIs(report[key], False)
            for key in ('latest_state_run', 'ui_pages', 'saved_worker_closed', 'transport_closed'): self.assertEqual(report[key], 'NOT_IMPLEMENTED')
            self.assertEqual(report['prior_receipts'], 'NOT_ASSESSED'); self.assertEqual(report['all_resources_absent'], 'NOT_PROVEN')
            return report, calls

    def test_single_fixed_readonly_no_run_no_staging_no_zip_even_clear(self):
        report, calls = self.dispatch(Environment().execute()[0])
        self.assertTrue(report['pass']); self.assertTrue(report['observed_blockers_clear']); self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], ('state-smoke-prerequisite-readonly', checker.source(), 25))

    def test_pending_observation_pass_never_allows_smoke(self):
        env = Environment(); env.meta['/tmp/p011-mta-p2p-device.pending'] = metadata()
        report, calls = self.dispatch(env.execute()[0]); self.assertTrue(report['pass']); self.assertFalse(report['observed_blockers_clear'])

    def test_parse_failure_incomplete_and_exception_never_public(self):
        value = Environment().execute()[0]; value['complete'] = False; value['snapshots_consistent'] = False
        report, calls = self.dispatch(value); self.assertFalse(report['pass']); self.assertFalse(report['observed_blockers_clear'])
        report, calls = self.dispatch(value, failed=True); self.assertTrue(report['host_or_parse_error']); self.assertFalse(report['check_complete'])
        value = Environment().execute()[0]; value['private'] = 'HOST_SECRET'
        report, calls = self.dispatch(value); self.assertTrue(report['host_or_parse_error'])

    def test_source_budget_and_source_pin_failure_precede_adb_output(self):
        for budget in (True, False):
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(checker, 'Adb', side_effect=AssertionError('HOST no ADB')):
                out = Path(directory) / 'absent'
                with mock.patch.object(checker, 'BODY', 'x' * 12289 if budget else checker.BODY), mock.patch.object(checker, 'verify_reviewed_sources', side_effect=ValueError('HOST pin')):
                    with self.assertRaises(ValueError): checker.run_check(out)
                self.assertFalse(out.exists())

    def test_exact_eight_named_pins_match_current_and_missing_drift_or_link_rejected(self):
        self.assertEqual(len(checker.REVIEWED_PINS), 8); self.assertTrue(checker.verify_reviewed_sources())
        self.assertNotIn('SOURCE.sha256', checker.REVIEWED_PINS)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError): checker.verify_reviewed_sources(root)
            for name in checker.REVIEWED_PINS:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'HOST SYNTHETIC WRONG PIN')
            with self.assertRaises(ValueError): checker.verify_reviewed_sources(root)
        with mock.patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaises(ValueError): checker.verify_reviewed_sources()

    def test_validate_host_never_constructs_adb_or_outputs_device_pass(self):
        stream = io.StringIO()
        with mock.patch.object(checker, 'Adb', side_effect=AssertionError('HOST no ADB')), contextlib.redirect_stdout(stream):
            self.assertEqual(checker.main(['--validate-host']), 0)
        value = json.loads(stream.getvalue()); self.assertEqual(value['evidence_level'], 'HOST_PAYLOAD_VALIDATION')
        self.assertFalse(value['device_invoked']); self.assertFalse(value['run_allowed']); self.assertNotIn('pass', value)
        with self.assertRaises(SystemExit): checker.main(['--validate-host', '--check-readonly'])


if __name__ == '__main__':
    unittest.main()
