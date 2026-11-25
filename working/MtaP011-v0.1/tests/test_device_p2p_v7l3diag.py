"""HOST-only V7 harness, fake descriptors/ADB and ephemeral manifest fixtures."""
import ast
import contextlib
import copy
import hashlib
import inspect
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'host'))
import device_p2p_v7l3diag as entry
from tests import test_device_p2p_v6diag as fixtures
from tests import test_device_prior_journal_readonly as readonly


def l3(reason='accepted', stage='done', counts=None, flags=None):
    return {'reason': reason, 'stage': stage,
        'counts': {'ipv6_address_rows': 1, 'ipv6_address_rows_examined': 1, 'ipv6_route_rows_examined': 1} if counts is None else counts,
        'observations': {'address_dump_complete': True, 'addresses_accepted': True,
            'routes_accepted': True, 'route_prefix_is_128': False} if flags is None else flags}


def event(row, diagnostic=None):
    row = copy.deepcopy(row); row['ip_creation_l3'] = l3() if diagnostic is None else diagnostic; return row


def failed():
    return event(fixtures.failure(reason='lease_error', failure_errno=0,
        ip_creation_gate=fixtures.creation('interface_l3', 'interface_l3', {key: True for key in entry.old.IP_CREATION_OBSERVATIONS})),
        l3('route_prefix', 'route_prefix', flags={'address_dump_complete': True, 'addresses_accepted': True, 'route_prefix_is_128': True}))


def wire(rows=None, status=0):
    return fixtures.wire([event(fixtures.ready()), event(fixtures.cleanup())] if rows is None else rows, status)


def good_files(normalize=False):
    return {'complete': True, 'file_count': 8, 'prevalidated_count': 8, 'fchmod_attempt_count': 8 if normalize else 0,
            'readback_count': 8, 'descriptors_closed': True, 'identity_sha256': '1' * 64, 'gate': 'not_recorded'}


def old_files():
    return {'complete': True, 'file_count': 16, 'pins_verified': True, 'permissions_verified': True,
            'descriptors_closed': True, 'identity_sha256': '2' * 64, 'gate': 'not_recorded'}


def body_fixture(action='good', normalize=True, run=False):
    target = entry.AREA + '/candidates/mta-01-' + 'f' * 16
    owned_run = entry.AREA + '/sessions/mta-p2p-v2-20000101-000000-00000000' if run else None
    records = {}; data = {}; inode = {}; modes = {}; times = {}; paths = {}; position = {}
    opened = []; closed = []; changes = []; reads = []; directory_paths = {entry.AREA, entry.AREA + '/candidates', entry.AREA + '/sessions', target, target + '/runtime', target + '/native'}
    if run:directory_paths.add(owned_run)
    for relative in sorted(entry.EXPECTED_FILES):
        path = target + '/' + relative; raw = ('HOST_PRIVATE_' + relative).encode('ascii')
        data[path] = raw; inode[path] = len(inode) + 1; times[path] = 1
        modes[path] = (0o700 if relative.startswith('native/') else 0o666) if normalize else (0o500 if relative.startswith('native/') else 0o400)
        records[relative] = (hashlib.sha256(raw).hexdigest(), len(raw))
    first = target + '/SOURCE.sha256'; last = target + '/' + sorted(entry.EXPECTED_FILES)[-1]
    if action == 'last_pin':data[last] = b'X' + data[last][1:]
    if action == 'pin':data[first] = b'X' + data[first][1:]
    clocks = []
    def metadata(path, fd=False):
        is_dir = path in directory_paths
        mode = stat.S_IFDIR | 0o700 if is_dir else stat.S_IFREG | modes[path]
        if action == 'directory_mode' and is_dir:mode = stat.S_IFDIR | 0o777
        if path == first and action == 'symlink':mode = stat.S_IFLNK | 0o666
        if path == first and action == 'fifo':mode = stat.S_IFIFO | 0o666
        if path == first and action == 'special_mode':mode = stat.S_IFREG | 0o4666
        if not normalize and action == 'readonly_mode' and path == first:mode = stat.S_IFREG | 0o666
        number = inode.get(path, 100)
        if fd and path == first and action == 'fd_changed':number += 100
        if action == 'duplicate_inode' and not is_dir:number = 1
        return types.SimpleNamespace(st_dev=1, st_ino=number, st_mode=mode, st_uid=1 if action == 'owner' and path == first else 0,
            st_gid=0, st_nlink=2 if action == 'hardlink' and path == first else 1, st_size=len(data[path]) if not is_dir else 0,
            st_mtime_ns=1, st_ctime_ns=times.get(path, 1))
    def open_fd(path, flags):
        if flags != 0x20800:raise AssertionError('HOST unexpected FD flags')
        if action == 'partial_open' and path == last:raise OSError(5, 'HOST_PRIVATE_OPEN')
        fd = len(opened) + 20; paths[fd] = path; position[fd] = 0; opened.append(path); return fd
    def read(fd, count):
        if action == 'read_error':raise OSError(5, 'HOST_PRIVATE_READ')
        if not 1 <= count <= 65536:raise AssertionError('HOST read not bounded')
        reads.append((paths[fd], count)); begin = position[fd]; raw = data[paths[fd]][begin:begin + count]; position[fd] += len(raw); return raw
    def change(fd, mode):
        if len(opened) != 8:raise AssertionError('HOST chmod before all eight opened')
        if any(position[value] != len(data[paths[value]]) for value in paths):raise AssertionError('HOST chmod before full prevalidation')
        path = paths[fd]; changes.append((path, mode)); modes[path] = mode; times[path] += 1
        if action == 'fchmod_error':raise OSError(5, 'HOST_PRIVATE_FCHMOD')
    def close(fd):
        closed.append(fd)
        if action == 'close_error':raise OSError(5, 'HOST_PRIVATE_CLOSE')
    def walk(base, followlinks=False):
        if followlinks:raise AssertionError('HOST followed directory links')
        dirs = ['runtime', 'native'] + (['extra'] if action == 'extra_dir' else [])
        root_files = ['SOURCE.sha256'] + (['PRIVATE_EXTRA'] if action == 'extra_file' else [])
        return [(target, dirs, root_files), (target + '/runtime', [], sorted(x.split('/')[1] for x in records if x.startswith('runtime/'))),
                (target + '/native', [], sorted(x.split('/')[1] for x in records if x.startswith('native/')))]
    def clock():
        clocks.append(True); return 60 if action == 'deadline' and len(clocks) > 1 else 1
    fake_os = types.SimpleNamespace(lstat=lambda path:metadata(path), fstat=lambda fd:metadata(paths[fd], True), open=open_fd,
        read=read, close=close, fchmod=change, lseek=lambda fd, offset, whence:position.__setitem__(fd, offset), SEEK_SET=0,
        set_inheritable=lambda fd, value:None, getuid=lambda:0, geteuid=lambda:0, uname=lambda:('Linux', '', '', '', 'armv7l'),
        O_RDONLY=0, O_NOFOLLOW=0x20000, O_NONBLOCK=0x800, walk=walk, sep='/', listdir=lambda path:['PRIVATE'] if action == 'run_nonempty' else [],
        path=types.SimpleNamespace(realpath=lambda path:path + '-redirected' if action == 'redirected' else path,
                                  islink=lambda path:False, relpath=lambda path, base:path[len(base) + 1:]))
    namespace = {'os': fake_os, 'hashlib': hashlib, 'stat': stat, 'time': types.SimpleNamespace(monotonic=clock),
        'sys': types.SimpleNamespace(version_info=(3, 5, 5)), 'AREA': entry.AREA, 'TARGET': target, 'RECORDS': records,
        'MODE': normalize, 'RUN': owned_run, 'owned_directory': lambda path:None}
    tree = ast.parse(entry.FILES_BODY); tree.body = [node for node in tree.body if not isinstance(node, ast.Import)]
    output = io.StringIO()
    with contextlib.redirect_stdout(output):exec(compile(tree, '<HOST_NEW_EIGHT>', 'exec'), namespace)
    value = ast.literal_eval(output.getvalue().split('RESULT=', 1)[1].strip()); entry.validate_files(value, normalize)
    return value, opened, closed, changes


class ParserTests(unittest.TestCase):
    def test_real_source_enum_contract_and_accepted_events(self):
        report = entry.parse_trial(wire())
        self.assertTrue(report['go_ip_ready_event']); self.assertTrue(report['cleanup_complete'])
        self.assertEqual(report['ip_creation_l3'], l3())
        source = ast.parse((entry.BASE / entry.RUNTIME_DIRECTORY / 'mta_send_wifi.py').read_text(encoding='utf-8'))
        constants = {}
        for node in source.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'frozenset':
                constants[node.targets[0].id] = frozenset(ast.literal_eval(node.value.args[0]))
        self.assertEqual(entry.L3_REASONS, constants['IP_L3_REASONS'])
        self.assertEqual(entry.L3_STAGES, constants['IP_L3_STAGES'])
        self.assertEqual(entry.L3_COUNTS, constants['IP_L3_COUNTS'])
        self.assertEqual(entry.L3_BOOLS, constants['IP_L3_OBSERVATIONS'])
    def test_same_read_128_failure_preserves_fail_and_cleanup_not_success(self):
        report = entry.parse_trial(wire([failed()], 1))
        self.assertTrue(report['trial_failed_event']); self.assertTrue(report['failed_trial_cleanup_complete'])
        self.assertFalse(report['go_ip_ready_event']); self.assertFalse(report['cleanup_complete'])
        self.assertEqual(report['ip_creation_l3']['reason'], 'route_prefix')
        self.assertTrue(report['ip_creation_l3']['observations']['route_prefix_is_128'])
    def test_missing_extra_unknown_nonbool_count_bound_rejected(self):
        bad = [None, {}, dict(l3(), extra=True), dict(l3(), reason='PRIVATE'), dict(l3(), stage='PRIVATE'),
               dict(l3(), counts={'ipv6_address_rows': True}), dict(l3(), counts={'ipv6_address_rows': 4096}),
               dict(l3(), observations={'address_dump_complete': 1}), dict(l3(), observations={'PRIVATE': True})]
        for value in bad:
            row = event(fixtures.failure()); row['ip_creation_l3'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):entry.parse_trial(wire([row], 1))
        missing = event(fixtures.failure()); missing.pop('ip_creation_l3')
        with self.assertRaises(ValueError):entry.parse_trial(wire([missing], 1))
    def test_unvisited_read_failure_and_constructor_default_are_precise(self):
        default = l3('not_recorded', 'not_recorded', {}, {})
        row = event(fixtures.failure(failure_phase='backend_construct', cleanup={'complete': True, 'no_radio_mutation': True}), default)
        row.pop('ip_control_socket_closed')
        self.assertEqual(entry.parse_trial(wire([row], 1))['ip_creation_l3'], default)
        for stage in ('not_recorded', 'address_dump'):
            value = l3('unexpected_l3_read', stage, {}, {})
            self.assertEqual(entry.l3_diagnostic(value), value)
        with self.assertRaises(ValueError):entry.l3_diagnostic(l3('not_recorded', 'address_dump', {}, {}))
    def test_address_rejection_cannot_claim_route_or_accepted_facts(self):
        good = l3('address_prefix', 'address_fields', {'ipv6_address_rows': 1, 'ipv6_address_rows_examined': 1}, {'address_dump_complete': True})
        self.assertEqual(entry.l3_diagnostic(good), good)
        bad = [dict(good, stage='done'), dict(good, counts=dict(good['counts'], ipv6_route_rows_examined=1)),
               dict(good, observations=dict(good['observations'], addresses_accepted=True)),
               dict(good, counts={'ipv6_address_rows': 0, 'ipv6_address_rows_examined': 1})]
        for value in bad:
            with self.assertRaises(ValueError):entry.l3_diagnostic(value)
    def test_route_hex_shape_prefix_stage_semantics(self):
        base = {'address_dump_complete': True, 'addresses_accepted': True}
        for reason, stage, flags in (('route_shape', 'route_shape', base), ('route_prefix', 'route_prefix', dict(base, route_prefix_is_128=True)),
                ('route_prefix', 'route_prefix', dict(base, route_prefix_is_128=False)),
                ('route_hex_invalid', 'route_destination', base), ('route_hex_invalid', 'route_gateway', dict(base, route_prefix_is_128=False)),
                ('route_source', 'route_source', dict(base, route_prefix_is_128=False))):
            value = l3(reason, stage, flags=flags)
            self.assertEqual(entry.l3_diagnostic(value), value)
        bad = [l3('route_shape', 'route_shape', flags=dict(base, route_prefix_is_128=False)),
               l3('route_prefix', 'route_prefix', flags=base),
               l3('route_prefix', 'route_prefix', flags=dict(base, route_prefix_is_128=1)),
               l3('route_prefix', 'route_gateway', flags=dict(base, route_prefix_is_128=True)),
               l3('route_hex_invalid', 'route_prefix', flags=dict(base, route_prefix_is_128=False)),
               l3('route_gateway', 'route_gateway', flags=dict(base, route_prefix_is_128=True))]
        for value in bad:
            with self.assertRaises(ValueError):entry.l3_diagnostic(value)
        empty = l3(counts={'ipv6_address_rows': 0, 'ipv6_address_rows_examined': 0, 'ipv6_route_rows_examined': 0},
                   flags={'address_dump_complete': True, 'addresses_accepted': True, 'routes_accepted': True})
        self.assertEqual(entry.l3_diagnostic(empty), empty)
        self.assertNotIn('route_prefix_is_128', empty['observations'])
    def test_ready_requires_accepted_and_terminal_observation_must_not_change(self):
        with self.assertRaises(ValueError):entry.parse_trial(wire([event(fixtures.ready(), l3('not_recorded', 'not_recorded', {}, {})), event(fixtures.cleanup())]))
        changed = l3(); changed['counts']['ipv6_route_rows_examined'] = 2
        with self.assertRaises(ValueError):entry.parse_trial(wire([event(fixtures.ready()), event(fixtures.cleanup(), changed)]))
        inconsistent = failed(); inconsistent['ip_creation_gate'] = fixtures.creation('process', 'process')
        with self.assertRaises(ValueError):entry.parse_trial(wire([inconsistent], 1))
    def test_saturated_counts_are_lower_bounds_and_bool_exact(self):
        value = l3(counts={key:4095 for key in entry.L3_COUNTS}); value['observations']['count_saturated'] = True
        self.assertEqual(entry.l3_diagnostic(value), value)
        for value in (l3(flags=dict(l3()['observations'], count_saturated=True)), l3(flags=dict(l3()['observations'], routes_accepted=False))):
            with self.assertRaises(ValueError):entry.l3_diagnostic(value)
    def test_original_bytes_duplicate_keys_raw_text_order_and_old_whitelist_retained(self):
        original = wire(); saved = bytes(original); entry.parse_trial(original); self.assertEqual(original, saved)
        row = event(fixtures.cleanup()); row['PRIVATE'] = 'PRIVATE'
        with self.assertRaises(ValueError):entry.parse_trial(wire([event(fixtures.ready()), row]))
        for raw in (wire() + b'PRIVATE\n', wire() + b'MTA_REMOTE_EXIT=0\n', wire().replace(b'"reason": "accepted"', b'"reason": "accepted", "reason": "accepted"', 1)):
            with self.assertRaises((ValueError, json.JSONDecodeError)):entry.parse_trial(raw)


class FileTests(unittest.TestCase):
    def test_normalize_all_eight_prevalidated_before_first_fchmod_full_readback_closed(self):
        value, opened, closed, changed = body_fixture()
        self.assertTrue(value['complete']); self.assertEqual(value['prevalidated_count'], 8)
        self.assertEqual(len(opened), 8); self.assertEqual(len(closed), 8); self.assertEqual(len(changed), 8)
        self.assertEqual(value['readback_count'], 8); self.assertNotIn('HOST_PRIVATE', json.dumps(value))
    def test_readonly_exact_modes_have_zero_permission_writes(self):
        value, opened, closed, changed = body_fixture(normalize=False, run=True)
        self.assertTrue(value['complete']); self.assertEqual(value['fchmod_attempt_count'], 0); self.assertFalse(changed)
    def test_last_file_bad_or_partial_open_means_no_fchmod_all_owned_fds_closed(self):
        for action in ('last_pin', 'partial_open'):
            value, opened, closed, changed = body_fixture(action)
            self.assertFalse(value['complete']); self.assertFalse(changed)
            self.assertEqual(len(opened), len(closed)); self.assertLess(value['prevalidated_count'], 8)
    def test_owner_type_link_identity_canonical_directory_set_pin_faults_block(self):
        for action in ('owner', 'symlink', 'fifo', 'special_mode', 'hardlink', 'fd_changed', 'duplicate_inode', 'redirected',
                       'directory_mode', 'extra_dir', 'extra_file', 'pin', 'read_error', 'deadline'):
            with self.subTest(action=action):
                value, opened, closed, changed = body_fixture(action)
                self.assertFalse(value['complete']); self.assertFalse(changed); self.assertEqual(len(opened), len(closed))
    def test_fchmod_or_close_failure_not_clean_and_no_extra_retry(self):
        for action in ('fchmod_error', 'close_error'):
            value, opened, closed, changed = body_fixture(action)
            self.assertFalse(value['complete']); self.assertEqual(len(opened), len(closed))
            if action == 'fchmod_error':self.assertEqual(len(changed), 1); self.assertEqual(value['gate'], 'fchmod')
            else:self.assertFalse(value['descriptors_closed']); self.assertEqual(value['gate'], 'descriptor_close')
    def test_readonly_wrong_mode_or_nonempty_run_blocks_without_write(self):
        for action in ('readonly_mode', 'run_nonempty'):
            value, opened, closed, changed = body_fixture(action, False, True)
            self.assertFalse(value['complete']); self.assertFalse(changed)
    def test_file_summary_unknown_nonbool_or_false_complete_rejected(self):
        bad = [dict(good_files(), extra=True), dict(good_files(), complete=1), dict(good_files(), file_count=True),
               dict(good_files(), file_count=7), dict(good_files(), readback_count=7), dict(good_files(), descriptors_closed=False),
               dict(good_files(True), prevalidated_count=7), dict(good_files(), gate='PRIVATE')]
        for value in bad:
            with self.assertRaises(ValueError):entry.validate_files(value, value['fchmod_attempt_count'] != 0)


class FakeAdb:
    def __init__(self, directory, action='good'):
        self.directory = Path(directory); self.directory.mkdir(parents=True, exist_ok=True)
        self.action = action; self.calls = []; self.index = 0; self.first = fixtures.private_probe(); self.raw = []
    def keep_raw(self, value):
        path = self.directory / ('HOST-stdout-%03d.bin' % self.index)
        path.write_bytes(value); self.raw.append((path, value)); return value
    def run(self, label, arguments, timeout=30, input_data=None):
        self.index += 1; self.calls.append((label, arguments, input_data, timeout))
        if label == 'push-new-v7-file':
            if self.action == 'push_failure':raise OSError('PRIVATE_PUSH')
            return self.keep_raw(b'')
        if label == 'finite-owned-p2p-v7-l3diag-trial':
            if self.action == 'trial_timeout':raise TimeoutError('PRIVATE_TIMEOUT')
            return self.keep_raw(wire([failed()], 1) if self.action == 'trial_failure' else wire())
        ast.parse(input_data.decode('utf-8'), feature_version=(3,5))
        if label.endswith('fixed16-readonly'):
            value = old_files()
            if self.action == label:value.update(complete=False, pins_verified=False, permissions_verified=False, gate='file_metadata')
            if self.action == 'old_metadata' and label.startswith('last'):value['identity_sha256'] = '3' * 64
        elif label in ('new-fresh-v7-directory', 'new-owned-v7-run-directory'):value = self.action != label
        elif label in ('new-eight-fd-normalize', 'new-eight-independent-readback', 'last-new-eight-readonly'):
            value = good_files(label == 'new-eight-fd-normalize')
            if self.action == label:value.update(complete=False, gate='file_pin')
            if self.action == 'new_metadata' and label.startswith('last'):value['identity_sha256'] = '3' * 64
        elif label.endswith('prior-journals'):
            value = {'clear': True, 'global_pending_clear': True, 'blocked_count': 0, 'unsafe_count': 0, 'inspected_count': 7}
            if self.action == label:value.update(clear=False, unsafe_count=1)
        elif label == 'owned-v7-journal-readonly':
            value = fixtures.journal_summary()
            if self.action in ('journal_incomplete', 'trial_failure'):value.update(complete=False, ip_receipt_restored=False, ip_stage='none')
            if self.action.startswith('journal_flag:'):value[self.action.split(':', 1)[1]] = False
            if self.action == 'journal_identity':value['identity_mismatch'] = True
        else:
            value = copy.deepcopy(self.first)
            if self.action == 'first_baseline' and label == 'first-independent-baseline':value['pending']['present'] = True
            if self.action == 'last_baseline' and label == 'last-independent-baseline':value['ipv4']['routes'][0][2] = 200
            if self.action == 'last_extra' and label == 'last-independent-baseline':value['PRIVATE'] = True
            if self.action == 'after_baseline' and label.startswith('after'):value['ipv4']['rules'][0][1] = 200
            if label.startswith('after'):
                if self.action == 'after_stock':value['stock_valid'] = False
                if self.action == 'after_wifi':value['wifi']['completed'] = False
                if self.action == 'after_ipv6':value['ipv6_routes_raw'] += b'HOST_CHANGED'
                if self.action == 'after_ipv4':value['ipv4']['addresses'][0][8][2] += 1
                if self.action == 'after_actor':value['no_project_trial_actors'] = False
                if self.action == 'after_process':value['network_processes'][0]['starttime'] += 1
                if self.action == 'after_interface':value['interfaces'][0]['wdev'] += 1
                if self.action == 'after_pending':value['pending']['present'] = True
                if self.action == 'after_boot':value['boot_id'] += '-changed'
        return self.keep_raw(readonly.wire(value))


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.frozen = Path(cls.temporary.name) / 'HOST_ONLY_EPHEMERAL_CANDIDATE'
        # Ephemeral HOST fixture, not a reviewed immutable workspace freeze.
        cls.identity = entry.freeze(cls.frozen)
    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()
    def invoke(self, action, directory):
        fakes = []
        def factory(path):
            fake = FakeAdb(path, action); fakes.append(fake); return fake
        with mock.patch.object(entry, 'Adb', side_effect=factory):
            report, out = entry.run_reviewed(self.frozen, self.identity, Path(directory) / 'HOST_RESULT')
        return report, out, fakes[0]
    def test_reference_pins_registry_and_capsule_leave_old_globals_unchanged(self):
        old_globals = dict(entry.old.__dict__)
        old_mutable = {name:copy.deepcopy(getattr(entry.old, name)) for name in ('SOURCE_PINS', 'NATIVE_PINS', 'PRIOR_CANDIDATES')}
        with mock.patch.object(entry, 'Adb', side_effect=AssertionError('HOST no ADB')):
            capsule = entry.build_capsule(self.frozen, self.identity)
        self.assertEqual(entry.old.__dict__, old_globals)
        self.assertEqual({name:getattr(entry.old, name) for name in old_mutable}, old_mutable)
        manifest = (self.frozen / 'SOURCE.sha256').read_bytes()
        self.assertEqual(len(manifest), 654); self.assertEqual(len(manifest.splitlines()), 7)
        self.assertEqual(set(capsule.records), entry.EXPECTED_FILES)
        fixed = {'runtime/' + name:pin for name, pin in entry.SOURCE_PINS.items()}
        fixed.update({'native/' + name:pin for name, pin in entry.NATIVE_PINS.items()})
        for relative, pin in fixed.items():
            raw = (self.frozen / relative).read_bytes()
            self.assertEqual(capsule.records[relative], (pin, len(raw)))
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)
        self.assertEqual(capsule.records['SOURCE.sha256'], (hashlib.sha256(manifest).hexdigest(), 654))
        self.assertEqual(set(entry.PRIOR_CANDIDATES), {'0f2a45489fd3e03b', '916a02d44aeeaf0d'})
        self.assertEqual(entry.PRIOR_CANDIDATES['916a02d44aeeaf0d']['manifest_sha256'], '916a02d44aeeaf0dcb24a3eaa57b7762fad5f503e3dabac83bed34df10780daf')
        self.assertEqual(len(entry.PRIOR_CANDIDATES['916a02d44aeeaf0d']['pins']), 7)
        for source in (capsule.stage, capsule.normalize, capsule.files, capsule.last_files, capsule.prior, capsule.baseline, capsule.journal, capsule.make_run):
            tree = ast.parse(source, feature_version=(3,5)); self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
        self.assertIn('--ttl 20', capsule.command); self.assertNotIn('--recover', capsule.command)
        self.assertIn('RUN=' + repr(capsule.run), capsule.journal)
        self.assertIn(repr(entry.IDENTITY3), capsule.prior)
        self.assertNotIn('from mta_send_wifi', capsule.normalize)
        self.assertNotIn('from mta_send_wifi', capsule.files)
    def test_good_fixture_single_rf_after_normalize_full_reread_last_baselines(self):
        with tempfile.TemporaryDirectory() as directory:
            report, out, fake = self.invoke('good', directory)
            self.assertTrue(report['pass']); self.assertTrue(report['rf_trial_invoked'])
            labels = [call[0] for call in fake.calls]
            self.assertEqual(labels[:3], ['initial-fixed16-readonly', 'first-independent-baseline', 'new-fresh-v7-directory'])
            self.assertEqual(labels.count('push-new-v7-file'), 8)
            ordered = ['new-eight-fd-normalize', 'new-eight-independent-readback', 'initial-v7-prior-journals',
                'new-owned-v7-run-directory', 'last-new-eight-readonly', 'last-fixed16-readonly', 'last-v7-prior-journals',
                'last-independent-baseline', 'finite-owned-p2p-v7-l3diag-trial', 'after-independent-old-reference', 'owned-v7-journal-readonly']
            self.assertEqual(labels[11:], ordered)
            for flag in ('old_candidate_metadata_unchanged', 'pre_rf_full_baseline_equal_first', 'full_ipv4_readback_unchanged',
                         'full_ipv6_readback_unchanged', 'journal_ip_receipt_restored'):self.assertTrue(report[flag])
            self.assertFalse(report['old_candidates_permissions_modified']); self.assertFalse(report['send_available'])
            self.assertEqual(sum(call[0] == 'finite-owned-p2p-v7-l3diag-trial' for call in fake.calls), 1)
            result = (out / 'result.json').read_text()
            for private in ('HOST_PRIVATE', 'HOST_SECRET', 'PRIVATE_PUSH', 'PRIVATE_TIMEOUT', '"PRIVATE"'):self.assertNotIn(private, result)
            self.assertTrue(fake.raw)
            for path, raw in fake.raw:self.assertEqual(path.read_bytes(), raw)
            self.assertFalse(list(out.glob('*.zip')))
    def test_preflight_staging_or_any_final_gate_failure_prevents_rf_with_independent_final_read(self):
        actions = ('initial-fixed16-readonly', 'first_baseline', 'new-fresh-v7-directory', 'push_failure', 'new-eight-fd-normalize',
            'new-eight-independent-readback', 'initial-v7-prior-journals', 'new-owned-v7-run-directory', 'last-new-eight-readonly',
            'new_metadata', 'last-fixed16-readonly', 'old_metadata', 'last-v7-prior-journals', 'last_baseline', 'last_extra')
        for action in actions:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertFalse(report['pass']); self.assertFalse(report['rf_trial_invoked'])
                self.assertFalse(any(call[0] == 'finite-owned-p2p-v7-l3diag-trial' for call in fake.calls))
                self.assertTrue(any(call[0] == 'after-independent-old-reference' for call in fake.calls))
                if action in ('new-fresh-v7-directory', 'push_failure', 'new-eight-fd-normalize', 'new-eight-independent-readback'):
                    self.assertFalse(any(call[0] == 'owned-v7-journal-readonly' for call in fake.calls))
                self.assertFalse(report['retry_invoked']); self.assertFalse(report['recovery_invoked'])
    def test_trial_failure_or_timeout_no_retry_and_restore_never_ip_acceptance(self):
        for action in ('trial_failure', 'trial_timeout', 'after_baseline', 'journal_incomplete'):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertFalse(report['pass']); self.assertTrue(report['rf_trial_invoked'])
                self.assertEqual(sum(call[0] == 'finite-owned-p2p-v7-l3diag-trial' for call in fake.calls), 1)
                self.assertEqual([call[0] for call in fake.calls][-2:], ['after-independent-old-reference', 'owned-v7-journal-readonly'])
                if action == 'trial_failure':
                    self.assertEqual(report['ip_creation_l3']['reason'], 'route_prefix'); self.assertTrue(report['failed_trial_cleanup_complete'])
                result = (out / 'result.json').read_text()
                for private in ('HOST_PRIVATE', 'HOST_SECRET', 'PRIVATE_PUSH', 'PRIVATE_TIMEOUT', '"PRIVATE"'):self.assertNotIn(private, result)
                for path, raw in fake.raw:self.assertEqual(path.read_bytes(), raw)
    def test_ready_cleanup_phase_never_masks_any_independent_restoration_gate(self):
        actions = ('after_stock', 'after_wifi', 'after_ipv6', 'after_ipv4', 'after_actor', 'after_process',
                   'after_interface', 'after_pending', 'after_boot', 'journal_identity')
        actions += tuple('journal_flag:' + key for key in ('safe', 'ownership_verified', 'version3', 'ipv4_baseline_present',
            'ipv6_baseline_present', 'pending_clear', 'baseline_independent_match', 'owned_process_gone', 'owned_interface_gone', 'ip_receipt_restored'))
        for action in actions:
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                report, out, fake = self.invoke(action, directory)
                self.assertTrue(report['go_ip_ready_event']); self.assertTrue(report['cleanup_complete'])
                self.assertFalse(report['pass']); self.assertTrue(report['rf_trial_invoked'])
                self.assertEqual(sum(call[0] == 'finite-owned-p2p-v7-l3diag-trial' for call in fake.calls), 1)
                self.assertFalse(report['send_available']); self.assertFalse(report['retry_invoked'])
    def test_unknown_registry_or_changed_reference_block_before_adb_and_output(self):
        for key in entry.REFERENCE_PINS:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(entry, 'REFERENCE_PINS', dict(entry.REFERENCE_PINS, **{key:'0' * 64})), \
                    mock.patch.object(entry, 'Adb', side_effect=AssertionError('HOST no ADB')), self.assertRaises(ValueError):
                entry.run_reviewed(self.frozen, self.identity, Path(directory) / 'UNCREATED')
                self.assertFalse((Path(directory) / 'UNCREATED').exists())
        for change in ('future', 'v6_identity', 'v6_manifest', 'v6_pin'):
            registry = copy.deepcopy(entry.PRIOR_CANDIDATES)
            if change == 'future':registry['f' * 16] = registry['916a02d44aeeaf0d']
            elif change == 'v6_identity':registry['916a02d44aeeaf0d']['identity']['version'] = 4
            elif change == 'v6_manifest':registry['916a02d44aeeaf0d']['manifest_sha256'] = '0' * 64
            else:registry['916a02d44aeeaf0d']['pins']['runtime/mta_send_wifi.py'] = '0' * 64
            with mock.patch.object(entry, 'PRIOR_CANDIDATES', registry), self.assertRaises(ValueError):entry.verify_reference()
    def test_frozen_old_candidate_extra_empty_dir_or_wrong_identity_rejected(self):
        with self.assertRaises(ValueError):entry.verify_frozen(entry.permissions.FROZEN, entry.permissions.CANDIDATE)
        with self.assertRaises(ValueError):entry.verify_frozen(self.frozen, '0' * 16)
        with self.assertRaises(FileExistsError):entry.freeze(self.frozen)
        (self.frozen / 'extra').mkdir()
        try:
            with self.assertRaises(ValueError):entry.verify_frozen(self.frozen)
        finally:(self.frozen / 'extra').rmdir()
    def test_no_old_runner_globals_path_chmod_global_cleanup_or_arbitrary_device_cli(self):
        source = inspect.getsource(entry)
        for token in ('old.run_reviewed(', 'permissions.run_reviewed(', 'setattr(', 'os.chmod(', 'os.chown(', 'killall', 'rm -rf'):
            self.assertNotIn(token, source)
        calls = [node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))]
        self.assertFalse(set(calls) & {'reboot', 'chmod', 'chown', 'killall', 'run_reviewed_old'})
        for argv in (['program'], ['program', '--execute-reviewed'], ['program', '--execute-reviewed', '--ttl', '20'],
                     ['program', '--execute-reviewed', '--command', 'PRIVATE'], ['program', '--freeze-only', '--expected-candidate', 'f' * 16]):
            with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):entry.main()


if __name__ == '__main__':unittest.main()
