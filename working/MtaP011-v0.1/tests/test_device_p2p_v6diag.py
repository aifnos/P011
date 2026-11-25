"""HOST-only V6diag event and frozen-identity contracts, not device evidence."""
import copy
import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'host'))
sys.path.insert(0, str(PROJECT / 'runtime'))
import device_p2p_v6diag as v6
import mta_ip as ip


def diagnostics():
    return {'events': [{'stage': stage, 'code': 0} for stage in sorted(v6.INIT_REQUIRED)],
            'diagnostic_invalid': False, 'raw_diagnostics_not_logged': True}


def creation(reason='not_recorded', gate='not_recorded', observations=None):
    return {'reason': reason, 'gate': gate, 'observations': {} if observations is None else observations}


def ready(**changes):
    row = {'event': 'private_go_ip_ready', 'ttl': 20, 'credentials_not_logged': True,
           'ip_ready': True, 'dhcp_ready': False, 'send_available': False, 'ip_creation_gate': creation()}
    row.update(changes)
    return row


def cleanup(**changes):
    row = {'event': 'private_go_ip_cleanup', 'owned_process_removed': True,
           'owned_interface_removed': True, 'stock_baseline_equal': True,
           'complete': True, 'diagnostics': diagnostics(), 'ip_restored': True,
           'ip_stage': 'restored', 'ip_control_socket_closed': True, 'ip_creation_gate': creation()}
    row.update(changes)
    return row


def failure(**changes):
    row = {'event': 'private_go_ip_trial_failed', 'reason': 'os_error',
           'cleanup': {'event': 'private_go_ip_cleanup', 'owned_process_removed': True, 'owned_interface_removed': True,
                       'stock_baseline_equal': True, 'complete': True, 'ip_restored': True, 'ip_stage': 'none',
                       'independent_readback': True},
           'complete': False, 'diagnostics': diagnostics(), 'failure_phase': 'ip_create',
           'failure_errno': 17, 'netlink_command': 'not_recorded', 'ip_creation_gate': creation('interface_carrier', 'interface_carrier',
               {'flags_read_valid': True, 'flags_up': True, 'carrier_read_valid': True, 'carrier_is_up': False})}
    row['ip_control_socket_closed'] = True
    row.update(changes)
    return row


def wire(events=None, status=0):
    events = [ready(), cleanup()] if events is None else events
    return ('\n'.join(json.dumps(row) for row in events) +
            '\nMTA_REMOTE_EXIT=' + str(status) + '\n').encode('utf-8')


class ParserTests(unittest.TestCase):
    def test_creation_diagnostic_required_for_every_event(self):
        for event in (ready(), cleanup(), failure()):
            event.pop('ip_creation_gate')
            events = [ready(), event] if event['event'] == 'private_go_ip_cleanup' else [event]
            with self.assertRaises(ValueError):v6.parse_trial(wire(events, 1))

    def test_creation_exact_fields_enums_and_bool_observations(self):
        invalid = [None, [], {}, creation(reason=[]), creation(gate=[]), creation(reason='HOST_SECRET'),
                   creation(gate='unexpected_gate_read'), creation(observations=[]),
                   creation(observations={'raw': 'HOST_SECRET'}), creation(observations={'flags_up': True}),
                   creation(observations={'flags_read_valid': False, 'flags_up': False}),
                   creation(observations={'carrier_read_valid': False, 'carrier_is_up': False}),
                   dict(creation(), raw='HOST_SECRET')]
        invalid.extend(creation(observations={key: number}) for key in v6.IP_CREATION_OBSERVATIONS for number in (0, 1, 'true', None))
        for diagnostic in invalid:
            with self.subTest(diagnostic=diagnostic), self.assertRaises(ValueError):
                v6.parse_trial(wire([failure(ip_creation_gate=diagnostic)], 1))
        observations = {key: True for key in v6.IP_CREATION_OBSERVATIONS}
        for reason in v6.IP_CREATION_REASONS:
            row = v6.parse_trial(wire([failure(ip_creation_gate=creation(reason, 'interface_carrier', observations))], 1))
            self.assertEqual(row['ip_creation_gate'], creation(reason, 'interface_carrier', observations))
        for gate in v6.IP_CREATION_GATES:
            row = v6.parse_trial(wire([failure(ip_creation_gate=creation('unexpected_gate_read', gate))], 1))
            self.assertEqual(row['ip_creation_gate']['gate'], gate)

    def test_ready_creation_diagnostic_must_be_default_and_nested_stays_old_schema(self):
        for diagnostic in (creation('interface_carrier', 'interface_carrier'), creation(observations={'flags_read_valid': True})):
            with self.assertRaises(ValueError):v6.parse_trial(wire([ready(ip_creation_gate=diagnostic), cleanup()]))
        nested = failure()['cleanup']; nested['ip_creation_gate'] = creation()
        with self.assertRaises(ValueError):v6.parse_trial(wire([failure(cleanup=nested)], 1))

    def test_failed_trial_restoration_reported_separately_not_ip_success(self):
        row = v6.parse_trial(wire([failure()], 1))
        self.assertTrue(row['failed_trial_cleanup_complete'])
        self.assertTrue(row['failed_trial_socket_closed_reported'])
        self.assertTrue(row['failed_trial_ip_restored_reported'])
        self.assertTrue(row['failed_trial_owned_process_removed_reported'])
        self.assertEqual(row['failed_trial_ip_stage'], 'none')
        self.assertFalse(row['go_ip_ready_event'])
        self.assertFalse(row['cleanup_complete'])
        self.assertTrue(row['trial_failed_event'])

    def test_failed_trial_cleanup_unknown_or_nonbool_rejected(self):
        for change in ({'raw': 'HOST_SECRET'}, {'complete': 1}, {'ip_stage': 'HOST_SECRET'}, {'independent_readback': 1}):
            nested = failure()['cleanup']; nested.update(change)
            with self.assertRaises(ValueError):v6.parse_trial(wire([failure(cleanup=nested)], 1))
        for nested in ({'complete': True, 'no_radio_mutation': True}, {'event': 'cleanup_failed', 'complete': False}):
            row = v6.parse_trial(wire([failure(cleanup=nested)], 1))
            self.assertEqual(row['failed_trial_cleanup_complete'], nested['complete'])
            self.assertTrue(row['trial_failed_event'])

    def test_socket_close_exact_required_except_constructor_failure(self):
        terminal = cleanup()
        terminal.pop('ip_control_socket_closed')
        with self.assertRaises(ValueError):
            v6.parse_trial(wire([ready(), terminal]))
        row = failure()
        row.pop('ip_control_socket_closed')
        with self.assertRaises(ValueError):
            v6.parse_trial(wire([row], 1))
        row['failure_phase'] = 'backend_construct'
        self.assertTrue(v6.parse_trial(wire([row], 1))['trial_failed_event'])
        for wrong in (0, 1, 'true'):
            with self.assertRaises(ValueError):
                v6.parse_trial(wire([ready(), cleanup(ip_control_socket_closed=wrong)]))

    def test_fixed_success_and_no_send_or_dhcp_claim(self):
        row = v6.parse_trial(wire())
        self.assertTrue(row['go_ip_ready_event'])
        self.assertTrue(row['cleanup_complete'])
        self.assertTrue(row['ip_restored_reported'])
        self.assertEqual(row['ip_stage_reported'], 'restored')
        self.assertTrue(row['early_init_success_reported'])
        self.assertNotIn('send_available', row)
        self.assertNotIn('pass', row)

    def test_failure_only_keeps_fixed_diagnostics(self):
        row = v6.parse_trial(wire([failure()], 1))
        self.assertTrue(row['trial_failed_event'])
        self.assertFalse(row['remote_exit_zero'])
        self.assertEqual((row['failure_phase'], row['failure_errno'], row['failure_reason']),
                         ('ip_create', 17, 'os_error'))
        self.assertNotIn('HOST_SECRET', json.dumps(row))

    def test_ready_fields_true_false_and_types_are_exact(self):
        for change in ({'ttl': True}, {'ttl': 19}, {'ttl': 20.0}, {'ip_ready': 1},
                       {'dhcp_ready': True}, {'send_available': True}, {'credentials_not_logged': 1},
                       {'peer_ip': 'HOST_SECRET'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                v6.parse_trial(wire([ready(**change), cleanup()]))

    def test_cleanup_whitelist_stage_bool_and_extra_fields(self):
        for change in ({'ip_restored': 1}, {'ip_stage': 'HOST_SECRET'}, {'ip_stage': []},
                       {'complete': 1}, {'source_ip': 'HOST_SECRET'}, {'independent_readback': 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                v6.parse_trial(wire([ready(), cleanup(**change)]))

    def test_failure_diagnostics_whitelist(self):
        for change in ({'failure_phase': 'HOST_SECRET'}, {'failure_phase': []},
                       {'failure_errno': True}, {'failure_errno': -1}, {'failure_errno': 4096},
                       {'netlink_command': 'HOST_SECRET'}, {'netlink_command': []},
                       {'reason': 'HOST_SECRET'}, {'raw': 'HOST_SECRET'}, {'complete': True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                v6.parse_trial(wire([failure(**change)], 1))

    def test_order_duplicate_and_terminal_rules(self):
        for events in ([], [ready()], [cleanup(), ready()], [failure(), failure()],
                       [ready(), cleanup(), failure()], [ready(), ready(), cleanup()]):
            with self.assertRaises(ValueError):
                v6.parse_trial(wire(events))

    def test_old_go_only_events_not_v6(self):
        for event in ('private_go_ready', 'private_go_cleanup', 'private_go_trial_failed'):
            with self.assertRaises(ValueError):
                v6.parse_trial(wire([{'event': event}]))

    def test_diagnostic_rows_bounded_fixed_codes(self):
        for bad in ({'stage': 'HOST_SECRET', 'code': 0}, {'stage': 'init_enter', 'code': True},
                    {'stage': 'init_enter', 'code': 4096}, {'stage': [], 'code': 0},
                    {'stage': 'init_enter', 'code': 0, 'raw': 'HOST_SECRET'}):
            terminal = cleanup()
            terminal['diagnostics']['events'].append(bad)
            with self.assertRaises(ValueError):
                v6.parse_trial(wire([ready(), terminal]))
        terminal = cleanup()
        terminal['diagnostics']['events'] = [{'stage': 'init_enter', 'code': 0}] * 65
        with self.assertRaises(ValueError):
            v6.parse_trial(wire([ready(), terminal]))

    def test_invalid_or_missing_early_diagnostic_not_success(self):
        for kind in ('invalid', 'missing', 'nonzero'):
            terminal = cleanup()
            if kind == 'invalid':
                terminal['diagnostics']['diagnostic_invalid'] = True
            elif kind == 'missing':
                terminal['diagnostics']['events'] = []
            else:
                terminal['diagnostics']['events'].append({'stage': 'early_param', 'code': 5})
            row = v6.parse_trial(wire([ready(), terminal]))
            self.assertFalse(row['diagnostics_valid'] and row['early_init_success_reported'])

    def test_bad_envelope_free_diagnostic_text_and_duplicated_json_key(self):
        terminal = cleanup()
        terminal['diagnostics']['raw'] = 'HOST_SECRET'
        with self.assertRaises(ValueError):
            v6.parse_trial(wire([ready(), terminal]))
        with self.assertRaises(ValueError):
            v6.parse_trial(b'{"event":"private_go_ip_ready","event":"private_go_ip_ready"}\nMTA_REMOTE_EXIT=0\n')

    def test_exit_utf8_length_and_nonjson_stderr_rejected(self):
        for raw in (wire() + b'MTA_REMOTE_EXIT=0\n', b'\xff\nMTA_REMOTE_EXIT=0\n',
                    b' ' * 32769, b'HOST_SECRET_ERROR\nMTA_REMOTE_EXIT=1\n', wire().replace(b'MTA_REMOTE_EXIT=0', b'MTA_REMOTE_EXIT=-1')):
            with self.assertRaises(ValueError):
                v6.parse_trial(raw)

    def test_failure_even_zero_exit_is_not_success(self):
        row = v6.parse_trial(wire([ready(), failure()], 0))
        self.assertTrue(row['remote_exit_zero'])
        self.assertTrue(row['trial_failed_event'])
        self.assertFalse(row['cleanup_complete'])


class FrozenTests(unittest.TestCase):
    def test_real_diagnostic_schema_and_marker_match_pinned_runtime(self):
        tree = ast.parse((PROJECT / v6.RUNTIME_DIRECTORY / 'mta_send_wifi.py').read_text(encoding='utf-8'))
        values = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):continue
            name = node.targets[0].id
            if name == 'DIAGNOSTIC_RUNTIME_MARKER':values[name] = ast.literal_eval(node.value)
            elif name in ('IP_CREATION_REASONS', 'IP_CREATION_GATES', 'IP_CREATION_OBSERVATIONS'):
                self.assertIsInstance(node.value, ast.Call)
                self.assertEqual(node.value.func.id, 'frozenset')
                values[name] = frozenset(ast.literal_eval(node.value.args[0]))
        self.assertEqual(values.pop('DIAGNOSTIC_RUNTIME_MARKER'), v6.RUNTIME_MARKER)
        for name, value in values.items():self.assertEqual(value, getattr(v6, name))
        self.assertEqual(len(values), 3)

    def test_known_v5_registry_matches_actual_immutable_host_manifest(self):
        frozen = v6.ROOT / 'logs/MtaP011-P2pV5Freeze-20261001-044135-4c11e2d6/private-candidate'
        manifest = (frozen / 'SOURCE.sha256').read_bytes()
        candidate, known = next(iter(v6.PRIOR_CANDIDATES.items()))
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), known['manifest_sha256'])
        self.assertEqual(candidate, known['manifest_sha256'][:16])
        seen = set()
        for line in manifest.decode('ascii').splitlines():
            pin, size, relative = line.split(' ')
            raw = (frozen / relative).read_bytes()
            self.assertEqual(len(raw), int(size)); self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)
            self.assertEqual(known['pins'][relative], pin); self.assertNotIn(relative, seen); seen.add(relative)
        self.assertEqual(seen, set(known['pins'])); self.assertEqual(len(seen), 7)

    def test_real_stable_sources_paths_sha_and_35_syntax_without_freeze(self):
        for name, expected in v6.SOURCE_PINS.items():
            folder = PROJECT / (v6.RUNTIME_DIRECTORY if name == 'mta_send_wifi.py' else 'runtime')
            raw = (folder / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
            v6._source_checks(name, raw)
        for name in v6.NATIVE_PINS:
            v6._native_check(name, (PROJECT / v6.NATIVE_DIRECTORY / name).read_bytes())

    def test_exact_seven_payloads_and_source_import_no_adb(self):
        self.assertEqual(len(v6.PAYLOAD_FILES), 7)
        self.assertEqual(set(v6.SOURCE_NAMES), {'mta_send_wifi.py', 'mta_ip.py', 'mta_ip_lease.py', 'mta_safety.py', 'p011_json.py'})
        self.assertEqual(len(v6.NATIVE_PINS), 2)
        self.assertEqual(v6.SOURCE_PINS['mta_ip.py'], '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5')

    def test_unreviewed_source_pins_fail_before_directory_or_adb(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(v6, 'SOURCE_PINS', dict(v6.SOURCE_PINS, **{'mta_send_wifi.py': None})), \
                mock.patch.object(v6, 'Adb', side_effect=AssertionError('No ADB')):
            destination = Path(directory) / 'must-not-be-created'
            with self.assertRaises(ValueError):
                v6.freeze(destination)
            self.assertFalse(destination.exists())

    def test_synthetic_host_only_freeze_integrity_extra_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'HOST_SYNTHETIC_SOURCE'
            sources = {}
            for name in v6.SOURCE_NAMES:
                raw = ('# HOST-only synthetic source ' + name + '\npass\n').encode('ascii')
                sources[name] = hashlib.sha256(raw).hexdigest()
                folder = base / (v6.RUNTIME_DIRECTORY if name == 'mta_send_wifi.py' else 'runtime')
                folder.mkdir(parents=True, exist_ok=True)
                (folder / name).write_bytes(raw)
            native = b'\x7fELF\x01\x01' + b'\0' * 12 + b'\x28\0HOST_SYNTHETIC_NOT_ARM_EXECUTABLE'
            pins = {name: hashlib.sha256(native).hexdigest() for name in v6.NATIVE_PINS}
            folder = base / v6.NATIVE_DIRECTORY
            folder.mkdir(parents=True, exist_ok=True)
            for name in pins:
                (folder / name).write_bytes(native)
            frozen = Path(directory) / 'synthetic-frozen'
            with mock.patch.object(v6, 'BASE', base), mock.patch.object(v6, 'SOURCE_PINS', sources), \
                    mock.patch.object(v6, 'NATIVE_PINS', pins), mock.patch.object(v6, 'Adb', side_effect=AssertionError('No ADB')):
                identity = v6.freeze(frozen)
                self.assertEqual(v6.verify_frozen(frozen, identity), identity)
                self.assertEqual({p.relative_to(frozen).as_posix() for p in frozen.rglob('*') if p.is_file()}, v6.EXPECTED_FILES)
                with self.assertRaises(ValueError):
                    v6.verify_frozen(frozen, 'f' * 16)
                (frozen / 'unlisted.txt').write_text('HOST_SYNTHETIC', encoding='ascii')
                with self.assertRaises(ValueError):
                    v6.verify_frozen(frozen)
                (frozen / 'unlisted.txt').unlink()
                raw = (frozen / 'runtime/mta_ip.py').read_bytes()
                (frozen / 'runtime/mta_ip.py').write_bytes(raw + b'# tamper\n')
                with self.assertRaises(ValueError):
                    v6.verify_frozen(frozen)


def private_ipv4():
    return {'version': 1, 'addresses': [[1, 0x7f000001, 0x7f000001, 8, 128, 254,
             '6c6f00', None, [ip.UINT_MAX, ip.UINT_MAX, 11, 11]]],
            'routes': [[0, 0, 254, 3, 0, 1, 0, 22, 0x0a000001, 600, None, []]],
            'rules': [[0, 255], [32766, 254], [32767, 253]]}


def private_probe():
    value = {'stock': {'HOST_PRIVATE_STOCK': 'HOST_SECRET_NOT_PUBLIC'}, 'stock_valid': True,
             'wifi': {'completed': True, 'fingerprint': 'a' * 64, 'same_channel_2ghz': True},
             'station_state_digest': 'a' * 64, 'frequency': 2412, 'route_digest': 'b' * 64,
             'ipv6_address_digest': 'c' * 64, 'ipv6_route_digest': 'd' * 64,
             'ipv6_addresses_raw': b'HOST_PRIVATE_IPV6', 'ipv6_routes_raw': b'HOST_PRIVATE_ROUTE',
             'network_processes': [{'pid': 101, 'exe': '/HOST_PRIVATE_EXE', 'starttime': 700,
                                    'name': 'wpa_supplicant', 'cmdline_digest': 'e' * 64}],
             'interfaces': [{'name': 'wlan0', 'phy': 0, 'wdev': 1, 'ifindex': 22, 'iftype': 2}],
             'boot_id': 'HOST_PRIVATE_BOOT', 'pending': {'present': False, 'safe': True, 'valid': True, 'lock_safe': True},
             'ipv4': private_ipv4()}
    for name in ('target_ok', 'query_ok', 'ipv4_complete', 'no_private_wpa_processes', 'no_project_trial_actors',
                 'no_p2p_interfaces', 'no_project_mta_interfaces', 'station_identity_ok'):
        value[name] = True
    return value


def journal_summary():
    row = dict.fromkeys(('present', 'safe', 'ownership_verified', 'complete', 'owned_process_gone', 'owned_interface_gone',
                         'version3', 'ipv6_baseline_present', 'ipv4_baseline_present', 'pending_clear',
                         'baseline_independent_match', 'ip_receipt_restored'), True)
    row.update(identity_mismatch=False, recover_review_ready=False, stage='reconciled', ip_stage='restored')
    return row


def helper_namespace():
    fake = types.ModuleType('mta_send_wifi')
    fake.ReadWriteNetlink = lambda: (_ for _ in ()).throw(AssertionError('No real netlink in HOST'))
    fake.TRACKED = frozenset()
    fake._proc_identity = lambda unused: None
    fake.DEVICE_LOCK = '/HOST_ONLY_LOCK'
    fake.DEVICE_PENDING = '/HOST_ONLY_PENDING'
    ns = {'owned_directory': lambda unused: None, 'AREA': '/HOST_ONLY_AREA',
          'BINARY': '/HOST_ONLY_BINARY', 'IP_STAGES': tuple(v6.IP_STAGES), 'MAIN_STAGES': tuple(v6.STAGES),
          'PRIOR_CANDIDATES': copy.deepcopy(v6.PRIOR_CANDIDATES),
          'IDENTITY3': {'version': 3, 'kind': v6.JOURNAL_KIND, 'runtime_marker': v6.RUNTIME_MARKER,
                       'wpa_sha256': v6.NATIVE_PINS['mta-wpa-supplicant'], 'codec_sha256': v6.SOURCE_PINS['mta_ip.py'],
                       'helper_sha256': v6.SOURCE_PINS['mta_ip_lease.py']}}
    with mock.patch.dict(sys.modules, {'mta_send_wifi': fake}):
        exec(v6.READ_HELPERS, ns)
    return ns


def private_journal(ns, stage='restored'):
    owned = {'name': 'mta1234abcd', 'phy': 0, 'wdev': 2, 'ifindex': 23, 'iftype': 8}
    spec = ip.AddressSpec(23, '192.168.49.1', 24)
    resource = {'stage': stage, 'owned': {key: owned[key] for key in ('name', 'ifindex', 'wdev', 'phy')},
                'spec': list(spec), 'request': {'header': ip.encode_new_address(spec, 3, 20)[:16].hex(),
                                              'sequence': 3, 'port_id': 20}}
    if stage != 'create_intent':
        resource.update(address=[23, spec.address, spec.address, 24, 128, 0,
                                 (owned['name'].encode('ascii') + b'\0').hex(), spec.address | 255,
                                 [ip.UINT_MAX, ip.UINT_MAX, 50, 50]], receipt_fsynced=stage != 'receipt_recorded')
    probe = private_probe()
    baseline = {key: probe[key] for key in ('boot_id', 'interfaces', 'frequency', 'route_digest',
                'ipv6_route_digest', 'ipv6_address_digest', 'station_state_digest', 'ipv4')}
    baseline['station'] = probe['interfaces'][0]
    baseline['processes'] = [{key: value for key, value in row.items() if key != 'name'} for row in probe['network_processes']]
    report = {key: value for key, value in cleanup().items() if key not in ('diagnostics', 'ip_control_socket_closed', 'ip_creation_gate')}
    return {'version': 3, 'kind': v6.JOURNAL_KIND, 'identity': copy.deepcopy(ns['IDENTITY3']), 'stage': 'reconciled',
            'name': owned['name'], 'baseline': baseline, 'deadline': 90.0, 'owned': owned,
            'process': {'pid': 999, 'starttime': 100, 'exe': ns['BINARY']}, 'ip': resource, 'cleanup_result': report}


class ReadonlyProgramsTests(unittest.TestCase):
    def test_prior_none_is_clean_admission_not_current_ip_trial_success(self):
        ns = helper_namespace(); row = private_journal(ns)
        row['ip'] = None; row['cleanup_result']['ip_stage'] = 'none'
        self.assertTrue(ns['validate_journal3'](row))
        self.assertTrue(ns['prior_ip_reconciled'](row))
        row['cleanup_result']['ip_stage'] = 'restored'
        self.assertFalse(ns['prior_ip_reconciled'](row))
        row['cleanup_result']['ip_stage'] = 'none'; row['cleanup_result']['ip_restored'] = False
        self.assertFalse(ns['prior_ip_reconciled'](row))
        for stage in v6.IP_STAGES - {'none'}:
            record = private_journal(ns, stage)
            record['cleanup_result']['ip_stage'] = stage
            self.assertEqual(ns['prior_ip_reconciled'](record), stage == 'restored')

    def test_historical_p011_readonly_fixture_normalization_not_device_trial(self):
        fixture = v6.ROOT / 'logs/MtaP011-IpDumpReadOnly-20261001-032317-adba0ac0/private-raw/02-ipv4-dumps-readonly.stdout.raw'
        if not fixture.is_file():
            self.skipTest('Private historical HOST fixture absent')
        result_lines = [line[7:] for line in fixture.read_text(encoding='utf-8').splitlines() if line.startswith('RESULT=')]
        self.assertEqual(len(result_lines), 1)
        data = ast.literal_eval(result_lines[0])
        collectors = []
        for kind, record in zip(('addresses', 'routes', 'rules'), data['raw_dump_records']):
            request = record['request']
            import struct
            unused_len, unused_type, unused_flags, sequence, unused_request_port = struct.unpack('<IHHII', request[:16])
            # Historical collector used request-port zero. Offline derive only
            # its reply-header port; this is NOT future kernel-sender proof.
            unused_len, unused_type, unused_flags, unused_sequence, port = struct.unpack('<IHHII', record['packets'][0][:16])
            collector = ip.DumpCollector(kind, sequence, port)
            for packet in record['packets']:
                collector.feed(packet)
            collectors.append(collector)
        snapshot = ip.snapshot_from_dumps(*collectors)
        ns = helper_namespace(); value = ns['canonical_ipv4'](snapshot)
        self.assertEqual(ns['normalize_ipv4'](value), value)
        self.assertEqual(tuple(len(value[kind]) for kind in ('addresses', 'routes', 'rules')), (2, 9, 3))

    def test_generated_35_programs_no_assert_or_write_calls(self):
        safety = (PROJECT / 'runtime/mta_safety.py').read_text(encoding='utf-8')
        for body in (v6.PROBE, v6.PRIOR_JOURNALS, v6.JOURNAL):
            source = v6.probe_source('/mnt/data/p011-toolbox/candidates/mta-01-' + 'f' * 16, safety, body, "RUN='/HOST_ONLY_RUN'\n")
            ast.parse(source, feature_version=(3, 5))
            tree = ast.parse(body, feature_version=(3, 5))
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
            calls = {node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
                     for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))}
            self.assertFalse(calls & {'create', 'delete', 'unlink', 'chmod', 'acquire', 'LinuxBackend', 'DeviceGuard',
                                     'GoLease', 'JournalLock', 'address_ack', 'encode_del_address'})
            self.assertIn('optimized_readonly_interpreter', source)
            self.assertIn('recvmsg', source)
            self.assertIn('peer!=(0,0)', source)

    def test_ipv4_complete_schema_and_all_tables_no_policy_fallback(self):
        ns = helper_namespace()
        original = private_ipv4()
        self.assertEqual(ns['normalize_ipv4'](original), original)
        mutations = []
        for field in ('addresses', 'routes', 'rules'):
            bad = copy.deepcopy(original); bad[field].append(copy.deepcopy(bad[field][0])); mutations.append(bad)
        bad = copy.deepcopy(original); bad['rules'].append([100, 999]); mutations.append(bad)
        bad = copy.deepcopy(original); bad['addresses'][0][8][0] = 10; mutations.append(bad)
        bad = copy.deepcopy(original); bad['routes'][0][6] = 16 | 0x80; mutations.append(bad)
        bad = copy.deepcopy(original); bad['version'] = True; mutations.append(bad)
        bad = copy.deepcopy(original); bad['extra'] = 'HOST_SECRET'; mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(ValueError):
                ns['normalize_ipv4'](bad)
        non_main = copy.deepcopy(original)
        non_main['routes'][0][2] = 200
        self.assertEqual(ns['normalize_ipv4'](non_main)['routes'][0][2], 200)

    def test_journal3_exact_identity_baseline_and_fixed_schema(self):
        ns = helper_namespace()
        original = private_journal(ns)
        self.assertTrue(ns['validate_journal3'](original))
        mutations = []
        for field, value in (('version', 2), ('kind', 'go_only'), ('stage', 'HOST_SECRET'), ('deadline', True)):
            bad = copy.deepcopy(original); bad[field] = value; mutations.append(bad)
        for field in ('runtime_marker', 'codec_sha256', 'helper_sha256'):
            bad = copy.deepcopy(original); bad['identity'][field] = 'HOST_SECRET'; mutations.append(bad)
        bad = copy.deepcopy(original); bad['extra'] = 'HOST_SECRET'; mutations.append(bad)
        for field in ('station_state_digest', 'ipv4', 'ipv6_route_digest'):
            bad = copy.deepcopy(original); del bad['baseline'][field]; mutations.append(bad)
        bad = copy.deepcopy(original); bad['baseline']['processes'][0]['pid'] = True; mutations.append(bad)
        bad = copy.deepcopy(original); bad['cleanup_result']['extra'] = 'HOST_SECRET'; mutations.append(bad)
        for bad in mutations:
            with self.assertRaises((ValueError, TypeError)):
                ns['validate_journal3'](bad)

    def test_ip_receipt_header_origin_stage_and_fsync_strict(self):
        ns = helper_namespace()
        for stage in v6.IP_STAGES - {'none'}:
            self.assertTrue(ns['validate_journal3'](private_journal(ns, stage)))
        original = private_journal(ns)
        mutations = []
        bad = copy.deepcopy(original); bad['ip']['request']['header'] = '0' * 32; mutations.append(bad)
        bad = copy.deepcopy(original); bad['ip']['request']['sequence'] = True; mutations.append(bad)
        bad = copy.deepcopy(original); bad['ip']['request']['header_hex'] = bad['ip']['request'].pop('header'); mutations.append(bad)
        for field in ('wdev', 'ifindex', 'phy'):
            bad = copy.deepcopy(original); bad['ip']['owned'][field] += 1; mutations.append(bad)
        bad = copy.deepcopy(original); bad['ip']['receipt_fsynced'] = False; mutations.append(bad)
        bad = copy.deepcopy(original); bad['ip']['address'][8][3] = 'HOST_SECRET'; mutations.append(bad)
        bad = copy.deepcopy(original); bad['ip']['address'][0] = True; mutations.append(bad)
        bad = copy.deepcopy(original); bad['ip']['address'][6] = '776c616e3000'; mutations.append(bad)
        for bad in mutations:
            with self.assertRaises((ValueError, TypeError, ip.IpCoreError)):
                ns['validate_journal3'](bad)


class KnownPriorTests(unittest.TestCase):
    def namespace(self):
        ns = helper_namespace(); self.calls = []
        candidate, known = next(iter(v6.PRIOR_CANDIDATES.items()))
        base = ns['AREA'] + '/candidates/mta-01-' + candidate
        self.base = base; self.known = known
        self.digests = {base + '/SOURCE.sha256': known['manifest_sha256']}
        self.digests.update({base + '/' + relative: pin for relative, pin in known['pins'].items()})
        ns['private_folder'] = lambda path: self.calls.append(('private_folder', path))
        ns['verify_candidate'] = lambda path: self.calls.append(('verify_candidate', path))
        ns['digest'] = lambda path: self.digests[path]
        ns['os'] = types.SimpleNamespace(lstat=lambda unused: types.SimpleNamespace(st_mode=0o100600, st_uid=0), getuid=lambda: 0)
        return ns

    def historical_record(self, ns):
        record = private_journal(ns)
        record['identity'] = copy.deepcopy(self.known['identity'])
        record['process']['exe'] = self.base + '/native/mta-wpa-supplicant'
        record['ip'] = None; record['cleanup_result']['ip_stage'] = 'none'
        return record

    def test_exact_known_v5_prior_only_current_identity_remains_strict(self):
        ns = self.namespace(); record = self.historical_record(ns)
        with self.assertRaises(ValueError):ns['validate_journal3'](record)
        identity, binary, historical = ns['prior3_context'](record)
        self.assertTrue(historical)
        self.assertTrue(ns['validate_journal3'](record, identity, binary))
        self.assertTrue(ns['prior_ip_reconciled'](record))
        self.assertEqual(self.calls, [('private_folder', self.base), ('private_folder', self.base + '/runtime'),
                                     ('private_folder', self.base + '/native'), ('verify_candidate', self.base)])
        current = private_journal(ns)
        self.assertEqual(ns['prior3_context'](current), (None, None, False))
        self.assertTrue(ns['validate_journal3'](current))
        current['process']['exe'] = binary
        with self.assertRaises(ValueError):ns['validate_journal3'](current)
        self.assertNotIn('prior3_context(record)', v6.JOURNAL[len(v6.READ_HELPERS):])
        self.assertIn('validate_journal3(record)', v6.JOURNAL[len(v6.READ_HELPERS):])

    def test_unknown_old_identity_path_or_missing_process_blocked(self):
        ns = self.namespace(); original = self.historical_record(ns)
        variants = []
        bad = copy.deepcopy(original); bad['identity']['runtime_marker'] = 'HOST_UNKNOWN_MARKER'; variants.append(bad)
        bad = copy.deepcopy(original); bad['process']['exe'] = self.base.replace('0f2a45489fd3e03b', 'f' * 16) + '/native/mta-wpa-supplicant'; variants.append(bad)
        bad = copy.deepcopy(original); bad['process']['exe'] += ' (deleted)'; variants.append(bad)
        bad = copy.deepcopy(original); bad['process'] = None; variants.append(bad)
        bad = copy.deepcopy(original); bad['identity']['helper_sha256'] = '0' * 64; variants.append(bad)
        for record in variants:
            with self.assertRaises(ValueError):ns['prior3_context'](record)

    def test_corrupt_complete_manifest_payload_link_or_permissions_blocked(self):
        for action in ('manifest', 'runtime', 'native', 'unsafe_folder', 'symlink', 'writable', 'unlisted', 'manifest_fifo', 'manifest_wrong_owner'):
            ns = self.namespace(); record = self.historical_record(ns)
            if action == 'manifest':self.digests[self.base + '/SOURCE.sha256'] = '0' * 64
            elif action == 'runtime':self.digests[self.base + '/runtime/mta_send_wifi.py'] = '0' * 64
            elif action == 'native':self.digests[self.base + '/native/mta-wpa-supplicant'] = '0' * 64
            elif action == 'unsafe_folder':ns['private_folder'] = lambda unused: (_ for _ in ()).throw(ValueError('HOST_UNSAFE_FOLDER'))
            elif action == 'unlisted':ns['verify_candidate'] = lambda unused: (_ for _ in ()).throw(ValueError('HOST_UNLISTED'))
            elif action in ('manifest_fifo', 'manifest_wrong_owner'):
                ns['os'].lstat = lambda path: types.SimpleNamespace(st_mode=0o010600 if path.endswith('/SOURCE.sha256') and action == 'manifest_fifo' else 0o100600,
                    st_uid=1 if path.endswith('/SOURCE.sha256') and action == 'manifest_wrong_owner' else 0)
            else:ns['os'].lstat = lambda unused: types.SimpleNamespace(st_mode=0o120600 if action == 'symlink' else 0o100622, st_uid=0)
            with self.assertRaises(ValueError):ns['prior3_context'](record)

    def baseline_namespace(self):
        ns = self.namespace(); probe = private_probe(); record = self.historical_record(ns)
        files = {'/proc/sys/kernel/random/boot_id': probe['boot_id'].encode('ascii'), '/proc/net/route': b'route',
                 '/proc/net/ipv6_route': b'ipv6route', '/proc/net/if_inet6': b'ipv6addr'}
        hashes = {b'route': probe['route_digest'], b'ipv6route': probe['ipv6_route_digest'], b'ipv6addr': probe['ipv6_address_digest']}
        ns['bounded'] = lambda path, maximum=1048576: files[path]
        ns['hashbytes'] = lambda raw: hashes[raw]
        ns['actors_and_network'] = lambda: (copy.deepcopy(probe['network_processes']), [], [])
        ns['station_readonly'] = lambda: (copy.deepcopy(probe['wifi']), probe['frequency'])
        ns['ipv4_readonly'] = lambda: copy.deepcopy(probe['ipv4'])
        return ns, record, probe

    def test_old_fresh_full_original_baseline_same_boot_required(self):
        ns, record, probe = self.baseline_namespace()
        self.assertTrue(ns['prior_baseline_matches'](record, probe['interfaces']))
        for field in ('boot_id', 'station_state_digest', 'processes', 'interfaces', 'frequency', 'ipv6_route_digest', 'ipv6_address_digest'):
            changed = copy.deepcopy(record); changed['baseline'][field] = None
            self.assertFalse(ns['prior_baseline_matches'](changed, probe['interfaces']))
        for kind in ('addresses', 'routes', 'rules'):
            changed = copy.deepcopy(record); changed['baseline']['ipv4'][kind] = []
            try:matched = ns['prior_baseline_matches'](changed, probe['interfaces'])
            except ValueError:matched = False
            self.assertFalse(matched)

    def test_prior_program_unknown_manifest_or_live_actors_fail_closed_without_writes(self):
        for action in ('good', 'manifest', 'live_process', 'unreadable_live_process', 'proc_permission', 'proc_io_error', 'live_iface', 'pending', 'unknown', 'ip_intent'):
            ns, record, probe = self.baseline_namespace()
            if action == 'manifest':self.digests[self.base + '/SOURCE.sha256'] = '0' * 64
            if action == 'unknown':record['identity']['runtime_marker'] = 'unknown'
            if action == 'ip_intent':
                other = private_journal(ns, 'create_intent'); record['ip'] = other['ip']; record['cleanup_result']['ip_stage'] = 'create_intent'
            rows = copy.deepcopy(probe['interfaces'])
            if action == 'live_iface':rows.append(copy.deepcopy(record['owned']))
            ns['ReadWriteNetlink'] = lambda: types.SimpleNamespace(interfaces=lambda: rows, close=lambda: None)
            ns['_proc_identity'] = lambda unused: record['process'] if action == 'live_process' else None
            ns['pending_readonly'] = lambda: {'present': action == 'pending', 'safe': True, 'lock_safe': True}
            ns['private_record'] = lambda unused: copy.deepcopy(record)
            session = 'mta-p2p-v2-20000101-000000-00000000'
            ns['os'].path = types.SimpleNamespace(isdir=lambda unused: True,
                lexists=lambda path: action in ('live_process', 'unreadable_live_process') if path.startswith('/proc/') else True)
            def lstat(path):
                if not path.startswith('/proc/'):return types.SimpleNamespace(st_mode=0o100600, st_uid=0)
                if action in ('live_process', 'unreadable_live_process'):return types.SimpleNamespace(st_mode=0o040555, st_uid=0)
                raise OSError(13 if action == 'proc_permission' else 5 if action == 'proc_io_error' else 2, 'HOST_ERROR_NOT_PUBLIC')
            ns['os'].lstat = lstat
            ns['os'].listdir = lambda path: [session] if path.endswith('/sessions') else ['p2p-lease.json']
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):exec(v6.PRIOR_JOURNALS[len(v6.READ_HELPERS):], ns)
            result = ast.literal_eval(buffer.getvalue().split('RESULT=', 1)[1])
            self.assertEqual(result['clear'], action == 'good')
            self.assertNotIn('HOST_PRIVATE', repr(result))


class IndependentGatesTests(unittest.TestCase):
    def test_creation_rejection_cannot_become_pass_even_after_full_cleanup(self):
        before = private_probe(); report = self.report()
        report['ip_creation_gate'] = creation('interface_carrier', 'interface_carrier')
        v6.add_independent_gates(report, before, copy.deepcopy(before), journal_summary())
        self.assertFalse(report['pass']); self.assertFalse(report['ip_creation_gate_no_rejection'])

    def report(self):
        row = v6.parse_trial(wire())
        row.update(rf_trial_invoked=True, preflight_passed=True, prior_journals_clear=True)
        return row

    def test_all_gates_can_pass_only_host_fixture(self):
        before = private_probe(); report = self.report()
        v6.add_independent_gates(report, before, copy.deepcopy(before), journal_summary())
        self.assertTrue(report['pass'])
        self.assertTrue(report['full_ipv4_routes_unchanged'])
        self.assertNotIn('HOST_PRIVATE', json.dumps(report))

    def test_full_ipv4_address_nonmain_route_and_rules_changes_reject(self):
        before = private_probe()
        for field, index, value in (('addresses', 0, 2), ('routes', 2, 200), ('rules', 1, 200)):
            after = copy.deepcopy(before); after['ipv4'][field][0][index] = value
            report = self.report(); v6.add_independent_gates(report, before, after, journal_summary())
            self.assertFalse(report['pass'])
            self.assertFalse(report['full_ipv4_' + field + '_unchanged'])
            self.assertTrue(report['route_digest_unchanged'])

    def test_timestamps_full_view_missing_and_digest_only_reject(self):
        before = private_probe()
        for action in ('timestamp', 'missing', 'not_complete', 'digest_only'):
            after = copy.deepcopy(before)
            if action == 'timestamp':after['ipv4']['addresses'][0][8][3] += 1
            elif action == 'missing':after.pop('ipv4')
            elif action == 'not_complete':after['ipv4_complete'] = False
            else:after['ipv4'] = {'digest': 'a' * 64}
            report = self.report(); v6.add_independent_gates(report, before, after, journal_summary())
            self.assertFalse(report['pass'])
            self.assertFalse(report['full_ipv4_readback_unchanged'])

    def test_station_tracked_args_boot_ipv6_and_pending_changes_reject(self):
        before = private_probe()
        for field in ('station_state_digest', 'network_processes', 'boot_id', 'interfaces', 'ipv6_addresses_raw', 'ipv6_routes_raw'):
            after = copy.deepcopy(before); after[field] = None
            report = self.report(); v6.add_independent_gates(report, before, after, journal_summary())
            self.assertFalse(report['pass'])
        after = copy.deepcopy(before); after['pending']['present'] = True
        report = self.report(); v6.add_independent_gates(report, before, after, journal_summary())
        self.assertFalse(report['pass'])

    def test_journal_and_socket_stage_false_cannot_cached_pass(self):
        before = private_probe()
        for field in ('version3', 'ipv4_baseline_present', 'baseline_independent_match', 'ip_receipt_restored', 'pending_clear'):
            journal = journal_summary(); journal[field] = False
            report = self.report(); v6.add_independent_gates(report, before, before, journal)
            self.assertFalse(report['pass'])
        for field in ('ip_control_socket_closed_reported', 'ip_restored_reported'):
            report = self.report(); report[field] = False
            v6.add_independent_gates(report, before, before, journal_summary())
            self.assertFalse(report['pass'])
        for state in ('none', 'create_intent', 'receipt_recorded', 'confirmed', 'delete_intent'):
            journal = journal_summary(); journal['ip_stage'] = state
            report = self.report(); v6.add_independent_gates(report, before, before, journal)
            self.assertFalse(report['pass'])


class FakeAdb:
    def __init__(self, before=None, after=None, prior=None, journal=None, response=None):
        self.before = private_probe() if before is None else before
        self.after = copy.deepcopy(self.before) if after is None else after
        self.prior = {'clear': True, 'global_pending_clear': True} if prior is None else prior
        self.journal = journal_summary() if journal is None else journal
        self.response = wire() if response is None else response
        self.calls = []

    def python(self, label, source):
        self.calls.append((label, source))
        ast.parse(source, feature_version=(3, 5))
        if label == 'candidate-directory':return True
        if label.startswith('prior-journals'):return self.prior
        if label.startswith('before-independent'):return self.before
        if label.startswith('after-independent'):return self.after
        if label.startswith('owned-journal'):return self.journal
        return True

    def run(self, label, argv, timeout=None):
        self.calls.append((label, argv))
        if isinstance(self.response, Exception):raise self.response
        return self.response


class HarnessTests(unittest.TestCase):
    def invoke(self, fake, directory):
        frozen = Path(directory) / 'HOST_FAKE_FROZEN'
        (frozen / 'runtime').mkdir(parents=True)
        (frozen / 'runtime/mta_safety.py').write_bytes((PROJECT / 'runtime/mta_safety.py').read_bytes())
        (frozen / 'SOURCE.sha256').write_bytes(b'HOST_ONLY_MANIFEST_NOT_REAL_FREEZE')
        with mock.patch.object(v6, 'verify_frozen', return_value='e' * 16), mock.patch.object(v6, 'Adb', return_value=fake):
            return v6.run_reviewed(frozen, 'e' * 16, Path(directory) / 'HOST_FAKE_OUTPUT')

    def test_fake_full_success_single_trial_and_sanitized_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = FakeAdb(); report, out, archive = self.invoke(fake, directory)
            self.assertTrue(report['pass'])
            runs = [args for name, args in fake.calls if name == 'finite-owned-p2p-v6diag-trial']
            self.assertEqual(len(runs), 1)
            self.assertIn('--ttl 20', runs[0][1])
            self.assertNotIn('--recover', runs[0][1])
            self.assertFalse(report['send_available'])
            self.assertFalse(report['dhcp_configuration'])
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()), {'result.json', 'README.txt'})
                content = b''.join(bundle.read(name) for name in bundle.namelist())
                self.assertNotIn(b'HOST_PRIVATE', content)
                self.assertNotIn(b'HOST_SECRET', content)
            self.assertNotIn('assert ', '\n'.join(value for _, value in fake.calls if type(value) is str))

    def test_preflight_and_pending_gates_stop_before_owned_trial(self):
        for action in ('pending', 'ipv4_missing', 'prior'):
            with tempfile.TemporaryDirectory() as directory:
                fake = FakeAdb()
                if action == 'pending':fake.before['pending']['present'] = True
                elif action == 'ipv4_missing':fake.before['ipv4_complete'] = False
                else:fake.prior['clear'] = False
                report, out, archive = self.invoke(fake, directory)
                self.assertFalse(report['pass'])
                self.assertFalse(report['rf_trial_invoked'])
                self.assertFalse(any(name == 'new-owned-v6diag-run-directory' for name, _ in fake.calls))
                self.assertTrue(any(name == 'after-independent-v6diag' for name, _ in fake.calls))

    def test_timeout_only_independent_reads_no_recovery_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = FakeAdb(response=TimeoutError('HOST_SECRET_TIMEOUT'))
            report, out, archive = self.invoke(fake, directory)
            self.assertFalse(report['pass'])
            self.assertTrue(report['host_or_parse_error'])
            labels = [name for name, _ in fake.calls]
            self.assertEqual(labels.count('finite-owned-p2p-v6diag-trial'), 1)
            self.assertEqual(labels[-2:], ['after-independent-v6diag', 'owned-journal-v6diag-readonly'])
            self.assertFalse(report['recovery_invoked'])
            self.assertFalse(report['retry_invoked'])
            self.assertNotIn('HOST_SECRET_TIMEOUT', (out / 'result.json').read_text())

    def test_old_event_or_nonmain_route_change_fails_even_cleanup_report_true(self):
        for action in ('old_event', 'alltable'):
            with tempfile.TemporaryDirectory() as directory:
                fake = FakeAdb()
                if action == 'old_event':fake.response = b'{"event":"private_go_ready"}\nMTA_REMOTE_EXIT=0\n'
                else:fake.after['ipv4']['routes'][0][2] = 200
                report, out, archive = self.invoke(fake, directory)
                self.assertFalse(report['pass'])

    def test_failure_cleanup_true_is_reported_but_never_ip_pass_or_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = journal_summary(); journal.update(complete=False, ip_receipt_restored=False, ip_stage='none')
            fake = FakeAdb(response=wire([failure()], 1), journal=journal)
            report, out, archive = self.invoke(fake, directory)
            self.assertFalse(report['pass']); self.assertFalse(report.get('host_or_parse_error', False))
            self.assertTrue(report['failed_trial_cleanup_complete']); self.assertTrue(report['failed_trial_socket_closed_reported'])
            self.assertTrue(report['stock_independent_unchanged']); self.assertTrue(report['full_ipv4_readback_unchanged'])
            self.assertFalse(report['retry_invoked']); self.assertFalse(report['recovery_invoked'])
            self.assertEqual(sum(name == 'finite-owned-p2p-v6diag-trial' for name, _ in fake.calls), 1)
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()), {'result.json', 'README.txt'})
                self.assertNotIn(b'HOST_PRIVATE', b''.join(bundle.read(name) for name in bundle.namelist()))

    def test_cli_requires_mode_and_exact_review_and_freeze_no_adb(self):
        for argv in (['program'], ['program', '--execute-reviewed'], ['program', '--execute-reviewed', '--frozen', 'fixture', '--expected-candidate', 'bad'],
                     ['program', '--freeze-only', '--expected-candidate', 'a' * 16]):
            with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit), \
                    mock.patch.object(v6, 'Adb', side_effect=AssertionError('No ADB')):
                v6.main()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(sys, 'argv', ['program', '--freeze-only', '--output', str(Path(directory) / 'host')]), \
                mock.patch.object(v6, 'SOURCE_PINS', dict(v6.SOURCE_PINS, **{'mta_send_wifi.py': None})), \
                mock.patch.object(v6, 'Adb', side_effect=AssertionError('No ADB')), self.assertRaises(ValueError):
            v6.main()


if __name__ == '__main__':
    unittest.main()
