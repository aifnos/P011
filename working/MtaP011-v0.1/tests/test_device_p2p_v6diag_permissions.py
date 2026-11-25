"""HOST-only fixed permission entry, FD fixtures and synthetic trial bytes."""
import ast
import contextlib
import copy
import hashlib
import inspect
import io
import json
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'host'))
import device_p2p_v6diag_permissions as entry
from tests import test_device_p2p_v6diag as trial_fixtures
from tests import test_device_prior_journal_readonly as readonly_fixtures


def good_files():
    return {'complete': True, 'file_count': 16, 'pins_verified': True, 'permissions_verified': True,
            'descriptors_closed': True, 'identity_sha256': '1' * 64, 'gate': 'not_recorded'}


def body_fixture(action='good', run=False):
    known = copy.deepcopy(entry.permission_checker.CANDIDATES)
    memory = {}; files = {}; walks = []; directories = {entry.AREA, entry.AREA + '/candidates', entry.AREA + '/sessions'}
    calls = []; closed = []; opened = []
    positions = {}; paths = {}; lstats = {}; clock_calls = []
    for alias in ('v5', 'v6'):
        spec = known[alias]; base = entry.AREA + '/candidates/mta-01-' + spec['identity']
        directories.update((base, base + '/runtime', base + '/native'))
        walks.extend([(base, ['runtime', 'native'], ['SOURCE.sha256']),
                      (base + '/runtime', [], sorted(name.split('/')[1] for name in spec['pins'] if name.startswith('runtime/'))),
                      (base + '/native', [], sorted(name.split('/')[1] for name in spec['pins'] if name.startswith('native/')))])
        for relative in sorted(spec['pins']):
            raw = ('HOST_PRIVATE_' + alias + relative).encode(); path = base + '/' + relative
            memory[path] = raw; files[path] = len(files) + 1
            spec['sizes'][relative] = len(raw); spec['pins'][relative] = hashlib.sha256(raw).hexdigest()
    first = entry.AREA + '/candidates/mta-01-' + known['v5']['identity'] + '/SOURCE.sha256'
    owned_run = entry.AREA + '/sessions/mta-p2p-v2-20000101-000000-00000000' if run else None
    if run:directories.add(owned_run)
    if action == 'digest':memory[first] = b'X' + memory[first][1:]

    def metadata(path, fd=False, final=False):
        if action == 'missing' and path == first:raise FileNotFoundError('HOST_PRIVATE_MISSING')
        mode = (stat.S_IFDIR | 0o700) if path in directories else (stat.S_IFREG | (0o500 if '/native/' in path else 0o400))
        if action == 'unsafe_directory' and path in directories:mode = stat.S_IFDIR | 0o777
        if path == first:
            if action == 'runtime_mode':mode = stat.S_IFREG | 0o666
            elif action == 'symlink':mode = stat.S_IFLNK | 0o400
            elif action == 'fifo':mode = stat.S_IFIFO | 0o400
        if action == 'native_mode' and '/native/' in path:mode = stat.S_IFREG | 0o700
        inode = files.get(path, 100)
        if path == first and (action == 'descriptor_changed' and fd or action == 'final_changed' and final):inode += 1000
        return types.SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=1 if action == 'owner' else 0,
            st_gid=0, st_nlink=2 if action == 'hardlink' and path == first else 1,
            st_size=len(memory[path]) if path in memory else 0, st_mtime_ns=1, st_ctime_ns=1)

    def lstat(path):
        lstats[path] = lstats.get(path, 0) + 1
        return metadata(path, final=lstats[path] > 1)

    def open_file(path, flags):
        if flags != 0x20800:raise AssertionError('HOST expected readonly/no-follow/nonblocking')
        fd = len(opened) + 10; opened.append(path); paths[fd] = path; positions[fd] = 0; return fd

    def read(fd, size):
        if action == 'read_exception':raise OSError(5, 'HOST_PRIVATE_READ')
        if not 1 <= size <= 65536:raise AssertionError('HOST unbounded read')
        begin = positions[fd]; blob = memory[paths[fd]][begin:begin + size]; positions[fd] += len(blob); return blob

    def close(fd):
        closed.append(fd)
        if action == 'close_exception':raise OSError(5, 'HOST_PRIVATE_CLOSE')

    def walk(base, followlinks=False):
        if followlinks:raise AssertionError('HOST followed links')
        rows = [copy.deepcopy(row) for row in walks if row[0] == base or row[0].startswith(base + '/')]
        if action == 'unlisted':rows[0][2].append('HOST_PRIVATE_EXTRA')
        return rows

    def monotonic():
        clock_calls.append(True)
        return 60 if action == 'deadline' and len(clock_calls) > 1 else 1

    fake_os = types.SimpleNamespace(lstat=lstat, fstat=lambda fd:metadata(paths[fd], fd=True), open=open_file,
        read=read, close=close, set_inheritable=lambda fd, value:None, geteuid=lambda:0, getuid=lambda:0,
        uname=lambda:('Linux', '', '', '', 'armv7l'), O_RDONLY=0, O_NOFOLLOW=0x20000, O_NONBLOCK=0x800,
        walk=walk, listdir=lambda path:['HOST_PRIVATE_EXTRA'] if action == 'run_nonempty' else [], sep='/',
        path=types.SimpleNamespace(realpath=lambda path:path + '-redirected' if action == 'redirected' else path,
                                  islink=lambda path:False, relpath=lambda path, base:path[len(base) + 1:]))
    namespace = {'hashlib': hashlib, 'os': fake_os, 'stat': stat, 'time': types.SimpleNamespace(monotonic=monotonic),
                 'sys': types.SimpleNamespace(version_info=(3, 5, 5)), 'CANDIDATES': known, 'AREA': entry.AREA,
                 'RUN': owned_run, 'owned_directory': lambda path:calls.append(path)}
    # The body imports stdlib names; execute its AST with only the imports removed
    # so all filesystem calls remain the explicit HOST fake and never real paths.
    body = ast.parse(entry.FILE_BODY)
    body.body = [node for node in body.body if not isinstance(node, ast.Import)]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):exec(compile(body, '<HOST_FD_FIXTURE>', 'exec'), namespace)
    value = ast.literal_eval(output.getvalue().split('RESULT=', 1)[1].strip())
    entry.validate_files(value)
    return value, opened, closed


class SourceAndFileTests(unittest.TestCase):
    def test_real_host_pins_frozen_identity_and_capsule_no_adb(self):
        old_globals = dict(entry.reference.__dict__)
        with mock.patch.object(entry, 'Adb', side_effect=AssertionError('HOST no ADB')):
            capsule = entry.build_capsule()
        self.assertEqual(entry.reference.__dict__, old_globals)
        self.assertEqual(entry.CANDIDATE, '916a02d44aeeaf0d')
        self.assertEqual(entry.REFERENCE_PINS, {
            'harness': '97f00ca99947d284921a4f382ee7c47199e40bf8e5c8de5c7cf71a33e373a93c',
            'prior_readonly': '3e8192c9396b50e5432e21bf1754ef7bc6e3104d45af215d6591a0a120c7e617',
            'permissions_readonly': 'ca2ab521dd6acc12a5f9e0ff30914917c36b2992b31393d09178768f60d1c1fa'})
        for source in capsule[1:-1]:
            tree = ast.parse(source, feature_version=(3, 5))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertIn('--ttl 20', capsule.command)
        self.assertIn(entry.TARGET + '/runtime/mta_send_wifi.py', capsule.command)
        self.assertNotIn('--recover', capsule.command)
        self.assertIsInstance(capsule, tuple)
        with self.assertRaises(AttributeError):capsule.run = '/HOST_OTHER'
        self.assertIn('RUN=' + repr(capsule.run), capsule.journal_program)
        self.assertIn('RUN=' + repr(capsule.run), capsule.last_file_program)

    def test_fd_exact_sixteen_new_modes_and_all_descriptors_closed(self):
        value, opened, closed = body_fixture()
        self.assertTrue(value['complete']); self.assertTrue(value['pins_verified']); self.assertTrue(value['permissions_verified'])
        self.assertEqual(value['file_count'], 16); self.assertEqual(len(opened), 16); self.assertEqual(len(closed), 16)
        self.assertNotIn('HOST_PRIVATE', json.dumps(value)); self.assertNotIn('/mnt/', json.dumps(value))

    def test_wrong_mode_owner_link_count_symlink_fifo_or_directory_blocks(self):
        for action in ('runtime_mode', 'native_mode', 'owner', 'hardlink', 'symlink', 'fifo', 'unsafe_directory', 'redirected', 'missing'):
            with self.subTest(action=action):
                value, opened, closed = body_fixture(action)
                self.assertFalse(value['complete']); self.assertFalse(value['permissions_verified'])
                self.assertEqual(len(opened), len(closed))

    def test_changed_fd_final_identity_digest_unlisted_and_read_failure_closed(self):
        for action in ('descriptor_changed', 'final_changed', 'digest', 'unlisted', 'read_exception'):
            with self.subTest(action=action):
                value, opened, closed = body_fixture(action)
                self.assertFalse(value['complete']); self.assertFalse(value['pins_verified'])
                self.assertEqual(len(opened), len(closed))

    def test_close_failure_or_deadline_never_grants_authority(self):
        for action in ('close_exception', 'deadline'):
            value, opened, closed = body_fixture(action)
            self.assertFalse(value['complete']); self.assertFalse(value['permissions_verified'])
            self.assertEqual(len(opened), len(closed))
            self.assertEqual(value['descriptors_closed'], action != 'close_exception')

    def test_last_capsule_run_must_be_exact_owned_empty_directory(self):
        value, opened, closed = body_fixture(run=True)
        self.assertTrue(value['complete'])
        value, opened, closed = body_fixture('run_nonempty', run=True)
        self.assertFalse(value['complete']); self.assertEqual(value['gate'], 'run_directory')
        with self.assertRaises(ValueError):entry.file_source('HOST', '/mnt/data/p011-toolbox/sessions/../other')

    def test_file_summary_strict_schema_and_incomplete_never_promoted(self):
        for field, value in (('complete', 1), ('file_count', True), ('file_count', 15),
                             ('identity_sha256', 'HOST_PRIVATE'), ('gate', 'HOST_PRIVATE'), ('descriptors_closed', False)):
            with self.subTest(field=field):
                variant = dict(good_files(), **{field:value})
                with self.assertRaises(ValueError):entry.validate_files(variant)
        value = dict(good_files(), complete=False)
        with self.assertRaises(ValueError):entry.validate_files(value)
        value = dict(good_files(), extra=True)
        with self.assertRaises(ValueError):entry.validate_files(value)

    def test_new_or_changed_reference_rejected_before_adb_and_output(self):
        for key in entry.REFERENCE_PINS:
            with tempfile.TemporaryDirectory() as directory, self.subTest(key=key):
                output = Path(directory) / 'UNCREATED'
                with mock.patch.object(entry, 'REFERENCE_PINS', dict(entry.REFERENCE_PINS, **{key:'0' * 64})), \
                        mock.patch.object(entry, 'Adb', side_effect=AssertionError('HOST no ADB')), self.assertRaises(ValueError):
                    entry.run_reviewed(output)
                self.assertFalse(output.exists())
        with mock.patch.object(entry, 'MANIFEST_SHA256', '0' * 64), self.assertRaises(ValueError):entry.build_capsule()
        with mock.patch.object(entry, 'RUNTIME_SHA256', '0' * 64), self.assertRaises(ValueError):entry.build_capsule()

    def test_source_never_calls_legacy_runner_stage_push_chmod_or_cleanup(self):
        tree = ast.parse(inspect.getsource(entry))
        attributes = [node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertFalse(set(attributes) & {'chmod', 'chown', 'unlink', 'remove', 'rmdir', 'setattr'})
        body = ast.parse(entry.FILE_BODY, feature_version=(3, 5))
        calls = [node.func.attr for node in ast.walk(body) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertFalse(set(calls) & {'chmod', 'chown', 'unlink', 'remove', 'mkdir', 'recover', 'sendto', 'listen', 'connect'})
        self.assertNotIn('reference.run_reviewed', inspect.getsource(entry.run_reviewed))
        self.assertNotIn('["push"', inspect.getsource(entry))


class FakeAdb:
    def __init__(self, directory, action='good'):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.action = action; self.calls = []; self.index = 0; self.first = trial_fixtures.private_probe()

    def run(self, label, arguments, timeout=30, input_data=None):
        self.index += 1; self.calls.append((label, arguments, input_data, timeout))
        if label == 'finite-owned-p2p-v6diag-trial':
            if self.action == 'trial_timeout':raise TimeoutError('HOST_PRIVATE_TIMEOUT')
            if self.action == 'trial_failure':return trial_fixtures.wire([trial_fixtures.failure()], 1)
            return trial_fixtures.wire()
        ast.parse(input_data.decode('utf-8'), feature_version=(3, 5))
        if label.endswith('fixed16-readonly'):
            value = good_files()
            if self.action == label:
                value.update(complete=False, pins_verified=False, permissions_verified=False, gate='file_metadata')
            if self.action == 'last_metadata' and label == 'last-fixed16-readonly':value['identity_sha256'] = '2' * 64
        elif label.endswith('prior-journals'):
            value = {'clear': True, 'global_pending_clear': True, 'blocked_count': 0, 'unsafe_count': 0, 'inspected_count': 6}
            if self.action == label:value.update(clear=False, unsafe_count=1)
        elif label == 'new-owned-permissions-run-directory':value = self.action != 'make_run'
        elif label == 'owned-journal-permissions-readonly':
            value = trial_fixtures.journal_summary()
            if self.action in ('journal_incomplete', 'trial_failure'):value.update(complete=False, ip_receipt_restored=False, ip_stage='none')
        else:
            value = copy.deepcopy(self.first)
            if self.action == 'first_baseline' and label == 'first-independent-baseline':value['pending']['present'] = True
            if self.action == 'last_baseline' and label == 'last-independent-baseline':value['ipv4']['routes'][0][2] = 200
            if self.action == 'last_extra' and label == 'last-independent-baseline':value['HOST_PRIVATE_EXTRA_FIELD'] = True
            if self.action == 'after_baseline' and label == 'after-independent-permissions':value['ipv4']['rules'][0][1] = 200
        return readonly_fixtures.wire(value)


class HarnessTests(unittest.TestCase):
    def invoke(self, action, directory):
        fakes = []
        def factory(path):
            fake = FakeAdb(path, action); fakes.append(fake); return fake
        with mock.patch.object(entry, 'Adb', side_effect=factory):
            report, out = entry.run_reviewed(Path(directory) / 'HOST_ONLY_RESULT')
        return report, out, fakes[0]

    def test_approved_fixture_single_old_trial_retains_all_original_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            report, out, fake = self.invoke('good', directory)
            self.assertTrue(report['pass']); self.assertTrue(report['rf_trial_invoked'])
            labels = [row[0] for row in fake.calls]
            self.assertEqual(labels, ['initial-fixed16-readonly', 'initial-prior-journals', 'first-independent-baseline',
                'new-owned-permissions-run-directory', 'last-fixed16-readonly', 'last-prior-journals',
                'last-independent-baseline', 'finite-owned-p2p-v6diag-trial', 'after-independent-permissions',
                'owned-journal-permissions-readonly'])
            self.assertTrue(report['pre_rf_full_baseline_equal_first']); self.assertTrue(report['candidate_metadata_unchanged'])
            self.assertTrue(report['journal_ip_receipt_restored']); self.assertTrue(report['full_ipv4_readback_unchanged'])
            self.assertTrue(report['full_ipv6_readback_unchanged']); self.assertTrue(report['ip_creation_gate_no_rejection'])
            for field in ('candidate_staged', 'permissions_modified', 'retry_invoked', 'recovery_invoked',
                          'send_available', 'dhcp_configuration', 'ip_application_sockets'):
                self.assertFalse(report[field])
            self.assertFalse(list(out.glob('*.zip')))
            self.assertNotIn('HOST_PRIVATE', (out / 'result.json').read_text())

    def test_each_first_last_gate_failure_prevents_rf_and_still_runs_final_independent_reads(self):
        for action in ('initial-fixed16-readonly', 'initial-prior-journals', 'first_baseline', 'make_run',
                       'last-fixed16-readonly', 'last_metadata', 'last-prior-journals', 'last_baseline', 'last_extra'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertFalse(report['pass']); self.assertFalse(report['rf_trial_invoked'])
                self.assertFalse(any(row[0] == 'finite-owned-p2p-v6diag-trial' for row in fake.calls))
                self.assertEqual([row[0] for row in fake.calls][-2:], ['after-independent-permissions', 'owned-journal-permissions-readonly'])
                self.assertFalse(report['retry_invoked']); self.assertFalse(report['recovery_invoked'])

    def test_actual_after_change_or_incomplete_journal_prevents_success(self):
        for action in ('after_baseline', 'journal_incomplete'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertFalse(report['pass']); self.assertTrue(report['rf_trial_invoked'])
                self.assertEqual(sum(row[0] == 'finite-owned-p2p-v6diag-trial' for row in fake.calls), 1)

    def test_failure_cleanup_or_timeout_never_retry_or_claim_ip_acceptance(self):
        for action in ('trial_failure', 'trial_timeout'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertFalse(report['pass']); self.assertTrue(report['rf_trial_invoked'])
                self.assertEqual(sum(row[0] == 'finite-owned-p2p-v6diag-trial' for row in fake.calls), 1)
                self.assertFalse(report['retry_invoked']); self.assertFalse(report['recovery_invoked'])
                self.assertEqual([row[0] for row in fake.calls][-2:], ['after-independent-permissions', 'owned-journal-permissions-readonly'])
                if action == 'trial_failure':
                    self.assertTrue(report['failed_trial_cleanup_complete'])
                    self.assertEqual(report['ip_creation_gate']['reason'], 'interface_carrier')
                self.assertNotIn('HOST_PRIVATE', (out / 'result.json').read_text())

    def test_capsule_journal_cleanup_is_precisely_the_one_new_run_no_global_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            report, out, fake = self.invoke('good', directory)
            command = next(row[1][1] for row in fake.calls if row[0] == 'finite-owned-p2p-v6diag-trial')
            argv = shlex.split(command); run = argv[argv.index('--run-dir') + 1]
            self.assertRegex(run, r'^/mnt/data/p011-toolbox/sessions/mta-p2p-v2-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$')
            journal = next(row[2].decode() for row in fake.calls if row[0] == 'owned-journal-permissions-readonly')
            self.assertIn('RUN=' + repr(run), journal)
            self.assertNotIn('killall', command); self.assertNotIn('--recover', command)
            self.assertEqual(argv[argv.index('--ttl') + 1], '20;')
            self.assertEqual(next(row[3] for row in fake.calls if row[0] == 'finite-owned-p2p-v6diag-trial'), 55)

    def test_cli_only_explicit_execute_no_arbitrary_output_frozen_candidate_or_command(self):
        for argv in (['program'], ['program', '--freeze-only'], ['program', '--execute-reviewed', '--output', 'HOST_OTHER'],
                     ['program', '--execute-reviewed', '--frozen', 'HOST_OTHER'],
                     ['program', '--execute-reviewed', '--expected-candidate', 'f' * 16],
                     ['program', '--execute-reviewed', '--command', 'HOST_OTHER']):
            with self.subTest(argv=argv), mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(entry, 'Adb', side_effect=AssertionError('HOST no ADB')), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):entry.main()


if __name__ == '__main__':unittest.main()
