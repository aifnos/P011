"""HOST-only V8 rejected-route summaries; no kernel/socket/device/RF calls."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'runtime'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_owned_ip_lease import FakeBackend, FakeLock
import mta_ip_lease as ip

V7 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v7l3diag/runtime/mta_send_wifi.py'
V8 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v8routediag/runtime/mta_send_wifi.py'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


v7 = module(V7, 'v7_route_comparison_only')
v8 = module(V8, 'v8_route_host_only')
OWNED = {'name': 'mta1234abcd', 'ifindex': 9, 'wdev': 20, 'phy': 0, 'iftype': 8}
LL = bytes.fromhex('fe800000000000000000000000000001')


def address(**changes):
    row = {'family': 6, 'prefix': 64, 'scope': 253, 'address': LL}; row.update(changes); return row


def route(**changes):
    row = ['fe800000000000000000000000000000', '40', '0' * 32, '00', '0' * 32,
           '00000100', '00000001', '00000000', '00000001', OWNED['name']]
    positions = {'destination': 0, 'prefix': 1, 'source': 2, 'source_prefix': 3, 'gateway': 4, 'flags': 8, 'name': 9}
    for name, value in changes.items():row[positions[name]] = value
    return ' '.join(row) + '\n'


def detail(values=None, observations=None, invalid=None):
    return {'values': {} if values is None else values,
            'observations': {} if observations is None else observations,
            'invalid_fields': [] if invalid is None else invalid}


class RouteTests(unittest.TestCase):
    def checked(self, text):
        report = v8.ip_creation_l3_diagnostic()
        with mock.patch('builtins.open', return_value=io.StringIO(text)) as opened:
            allowed = v8._creation_owned_routes_safe(OWNED['name'], report)
        opened.assert_called_once_with('/proc/net/ipv6_route')
        with mock.patch('builtins.open', return_value=io.StringIO(text)):
            previous = v7._creation_owned_routes_safe(OWNED['name'], v7.ip_creation_l3_diagnostic())
        self.assertEqual(allowed, previous)
        v8._l3_copy(report)
        return allowed, report
    def test_multicast_8_is_observed_but_remains_rejected(self):
        allowed, report = self.checked(route() + route(destination='ff' + '0' * 30, prefix='08'))
        self.assertFalse(allowed); self.assertEqual(report['reason'], 'route_prefix')
        self.assertEqual(report['counts']['ipv6_route_rows_examined'], 2)
        self.assertFalse(report['observations']['route_prefix_is_128'])
        facts = report['route_details']
        self.assertEqual(facts['values'], {'prefix': 8, 'destination_class': 'multicast'})
        self.assertTrue(facts['observations']['source_zero']); self.assertTrue(facts['observations']['source_prefix_zero'])
        self.assertTrue(facts['observations']['gateway_zero']); self.assertTrue(facts['observations']['flags_up'])
        self.assertFalse(facts['observations']['flags_gateway']); self.assertEqual(facts['invalid_fields'], [])
    def test_local_128_remains_rejected_and_classified_linklocal(self):
        allowed, report = self.checked(route(destination=LL.hex(), prefix='80', flags='80200001'))
        self.assertFalse(allowed); self.assertTrue(report['observations']['route_prefix_is_128'])
        self.assertEqual(report['route_details']['values'], {'prefix': 128, 'destination_class': 'linklocal'})
        self.assertTrue(report['route_details']['observations']['flags_nonexthop'])
        self.assertTrue(report['route_details']['observations']['flags_local'])
    def test_default_zero_other_and_noncanonical_destination_classes(self):
        for destination, expected in [('0' * 32, 'zero'), ('fd' + '0' * 30, 'other'), ('febf' + '0' * 28, 'linklocal')]:
            with self.subTest(expected=expected):
                report = self.checked(route(destination=destination, prefix='00'))[1]
                self.assertEqual(report['route_details']['values']['destination_class'], expected)
        report = self.checked(route(destination='1', prefix='00'))[1]
        self.assertNotIn('destination_class', report['route_details']['values'])
        self.assertIn('destination', report['route_details']['invalid_fields'])
    def test_all_prefixes_keep_old_decision_and_out_of_range_is_missing_not_clamped(self):
        for prefix in range(256):
            with self.subTest(prefix=prefix):
                allowed, report = self.checked(route(prefix='%02x' % prefix))
                self.assertEqual(allowed, 10 <= prefix <= 64)
                if not allowed:
                    if prefix <= 128:self.assertEqual(report['route_details']['values']['prefix'], prefix)
                    else:
                        self.assertNotIn('prefix', report['route_details']['values'])
                        self.assertIn('prefix', report['route_details']['invalid_fields'])
        for raw in ('-1', '100', 'INVALID', '0x00'):
            report = self.checked(route(prefix=raw))[1]
            self.assertNotIn('prefix', report['route_details']['values'])
            self.assertIn('prefix', report['route_details']['invalid_fields'])
    def test_post_rejection_malformed_unvisited_fields_do_not_change_rejection(self):
        report = self.checked(route(prefix='08', source='PRIVATE_SOURCE', source_prefix='PRIVATE_PREFIX',
                                    gateway='PRIVATE_GATEWAY', flags='PRIVATE_FLAGS'))[1]
        self.assertEqual(report['reason'], 'route_prefix'); self.assertEqual(report['stage'], 'route_prefix')
        self.assertEqual(report['route_details']['invalid_fields'], ['flags', 'gateway', 'source', 'source_prefix'])
        self.assertEqual(report['route_details']['observations'], {})
        self.assertNotIn('PRIVATE_', json.dumps(report))
    def test_accepted_routes_have_no_rejected_route_facts_even_with_ignored_malformed_flags(self):
        for text in ('', route(), route(flags='PRIVATE_FLAGS'), route(flags='100000000')):
            allowed, report = self.checked(text)
            self.assertTrue(allowed); self.assertEqual(report['route_details'], {})
    def test_wrong_shape_observed_only_as_fixed_shape_invalid(self):
        report = self.checked('1 2 ' + OWNED['name'] + '\n')[1]
        self.assertEqual(report['reason'], 'route_shape')
        self.assertEqual(report['route_details'], detail(invalid=['shape']))
    def test_original_hex_rejection_stage_and_source_gateway_nonzero_preserved(self):
        for field in ('destination', 'prefix', 'source', 'source_prefix', 'gateway'):
            with self.subTest(field=field):
                report = self.checked(route(**{field:'INVALID'}))[1]
                self.assertEqual(report['reason'], 'route_hex_invalid'); self.assertEqual(report['stage'], 'route_' + field)
                self.assertIn(field, report['route_details']['invalid_fields'])
        for field, reason in [('source', 'route_source'), ('source_prefix', 'route_source_prefix'), ('gateway', 'route_gateway')]:
            value = '01' if field == 'source_prefix' else LL.hex()
            report = self.checked(route(**{field:value}))[1]
            self.assertEqual(report['reason'], reason)
            self.assertFalse(report['route_details']['observations'][field + '_zero'])
    def test_first_rejection_stops_before_following_route_and_unowned_rows_not_counted(self):
        report = self.checked(route(name='other', prefix='08') + route(prefix='08') + route(prefix='80'))[1]
        self.assertEqual(report['counts']['ipv6_route_rows_examined'], 1)
        self.assertEqual(report['route_details']['values']['prefix'], 8)
    def test_flags_each_known_bit_and_unknown_bit_are_truthful_not_policy(self):
        for key, bit in v8.IP_ROUTE_FLAG_BITS:
            report = self.checked(route(prefix='08', flags='%08x' % bit))[1]
            facts = report['route_details']['observations']
            self.assertTrue(facts[key]); self.assertFalse(facts['flags_other_bits_set'])
            for other, unused in v8.IP_ROUTE_FLAG_BITS:
                if other != key:self.assertFalse(facts[other])
        facts = self.checked(route(prefix='08', flags='00080000'))[1]['route_details']['observations']
        self.assertTrue(facts['flags_other_bits_set'])
    def test_raw_destination_gateway_interface_and_error_text_never_exported(self):
        text = json.dumps(self.checked(route(destination=LL.hex(), prefix='80', gateway=LL.hex()))[1])
        for secret in (LL.hex(), OWNED['name'], '/proc/net/', 'PRIVATE_'):self.assertNotIn(secret, text)


class SchemaTests(unittest.TestCase):
    def test_unvisited_default_missing_and_copy_independent(self):
        value = v8.ip_creation_l3_diagnostic(); self.assertEqual(value['route_details'], {})
        value['route_details'] = detail({'prefix': 8, 'destination_class': 'multicast'}, {'flags_up': True})
        copied = v8._l3_copy(value); copied['route_details']['values']['prefix'] = 9
        self.assertEqual(value['route_details']['values']['prefix'], 8)
    def test_prefix_rejects_bool_float_string_negative_and_above128(self):
        for number in (True, False, 8.0, '8', -1, 129, 100000000):
            with self.subTest(number=number), self.assertRaises(v8.LeaseError):v8._route_details_copy(detail({'prefix': number}))
        for number in (0, 8, 64, 128):self.assertEqual(v8._route_details_copy(detail({'prefix': number}))['values']['prefix'], number)
    def test_fixed_class_fields_and_exact_booleans_reject_unrecognized_input(self):
        for value in (detail({'destination_class':'PRIVATE'}), detail({'destination_class':True}), detail({'PRIVATE':1}),
                detail(observations={'PRIVATE':True}), detail(observations={'flags_up':1}), detail(observations={'gateway_zero':0}),
                dict(detail(), extra=True), {'values':{}, 'observations':{}}):
            with self.subTest(value=value), self.assertRaises(v8.LeaseError):v8._route_details_copy(value)
    def test_invalid_fields_fixed_unique_sorted_and_no_conflicting_facts(self):
        bad = [detail(invalid=['PRIVATE']), detail(invalid=[True]), detail(invalid=['prefix','prefix']),
               detail(invalid=['source','prefix']), detail({'prefix':8}, invalid=['prefix']),
               detail({'destination_class':'other'}, invalid=['destination']),
               detail(observations={'gateway_zero':False}, invalid=['gateway']),
               detail(observations={'flags_up':False}, invalid=['flags']),
               detail({'prefix':8}, invalid=['shape']), detail(invalid=['prefix','shape'])]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(v8.LeaseError):v8._route_details_copy(value)
        self.assertEqual(v8._route_details_copy(detail(invalid=['flags','prefix'])), detail(invalid=['flags','prefix']))
    def test_legacy_schema_unknown_counts_or_text_not_implicitly_accepted(self):
        old = v7.ip_creation_l3_diagnostic()
        with self.assertRaises(v8.LeaseError):v8._l3_copy(old)
        for kwargs in (dict(reason='PRIVATE'), dict(counts={'ipv6_address_rows':True}),
                dict(observations={'routes_accepted':1}), dict(route_details={'raw':'PRIVATE'})):
            with self.assertRaises(v8.LeaseError):v8.ip_creation_l3_diagnostic(**kwargs)
    def test_detail_integer_parser_fixed_width_and_bounds_without_free_errors(self):
        for value in (True, None, b'08', 'PRIVATE', '0x08', '-1', '008'):
            self.assertIsNone(v8._route_detail_uint(value, 2, 128))
        self.assertEqual(v8._route_detail_uint('08', 2, 128), 8)
        self.assertIsNone(v8._route_detail_uint('81', 2, 128))


class BackendTests(unittest.TestCase):
    def check(self, source, rows, text, creating=True, carrier='1', failure=None):
        backend = object.__new__(source.LinuxBackend); backend.allow_rf = True; backend.guard = mock.Mock(fd=5)
        backend.nl = mock.Mock(); backend.nl.interfaces.return_value = [dict(OWNED, iftype=9)]
        reads = []
        def opened(path, *unused):
            reads.append(('open', path))
            if path == '/proc/net/ipv6_route':
                if failure:raise failure
                return io.StringIO(text)
            return io.StringIO({'flags':'0x1003','carrier':carrier,'ifindex':'9'}[path.rsplit('/', 1)[1]])
        def dump(index):reads.append(('dump', index)); return rows
        with mock.patch('builtins.open', side_effect=opened), mock.patch.object(source, '_digest', side_effect=lambda path:source.STOCK_PINS[path]), \
                mock.patch.object(source, '_address_dump', side_effect=dump):
            allowed = backend.ip_identity_gate(OWNED, creating)
        return allowed, reads, backend
    def test_full_gate_decision_order_and_read_count_equal_frozen_v7(self):
        cases = [([address()], route()), ([address(prefix=128)], route()), ([address()], route(prefix='08')),
                 ([address()], route(prefix='80')), ([address()], route(gateway=LL.hex())), ([], '')]
        for rows, text in cases:
            previous = self.check(v7, rows, text); current = self.check(v8, rows, text)
            self.assertEqual(previous[:2], current[:2]); self.assertEqual(previous[2].nl.interfaces.call_count, current[2].nl.interfaces.call_count)
    def test_address_rejection_shortcircuits_route_and_has_no_details(self):
        allowed, reads, backend = self.check(v8, [address(prefix=128)], route(), failure=AssertionError('unvisited'))
        self.assertFalse(allowed); self.assertNotIn(('open','/proc/net/ipv6_route'), reads)
        self.assertEqual(backend.ip_creation_l3_info['route_details'], {})
    def test_carrier_failure_has_no_dump_route_or_fabricated_details(self):
        allowed, reads, backend = self.check(v8, [address()], route(), carrier='0')
        self.assertFalse(allowed); self.assertFalse(any(kind == 'dump' for kind, unused in reads))
        self.assertEqual(backend.ip_creation_l3_info, v8.ip_creation_l3_diagnostic())
    def test_read_failure_has_fixed_reason_without_error_text(self):
        allowed, reads, backend = self.check(v8, [address()], route(), failure=OSError('PRIVATE_PATH_AND_ADDRESS'))
        self.assertFalse(allowed); self.assertEqual(backend.ip_creation_l3_info['reason'], 'unexpected_l3_read')
        self.assertEqual(backend.ip_creation_l3_info['route_details'], {})
        self.assertNotIn('PRIVATE_', json.dumps(backend.ip_creation_l3_info))
    def test_restore_keeps_frozen_predicate_even_multicast_is_rejected(self):
        for text in (route(), route(prefix='08', destination='ff' + '0' * 30), route(prefix='80')):
            previous = self.check(v7, [address()], text, False); current = self.check(v8, [address()], text, False)
            self.assertEqual(previous[:2], current[:2]); self.assertEqual(getattr(current[2], 'ip_creation_l3_info', None), None)


class MemoryFixture:
    def __init__(self):
        self.backend = FakeBackend(); self.saved = None; self.saves = 0
        self.lease = v8.GoLease(self.backend, os.path.join(str(ROOT), 'HOST_ONLY_NO_SUCH_JOURNAL'), lambda:100.0)
        def save(locked=False):self.saves += 1; self.saved = copy.deepcopy(self.lease.state)
        self.lease._save = save
        self.lock = mock.patch.object(v8, 'JournalLock', FakeLock)
        self.reader = mock.patch.object(v8, '_read_private_json', side_effect=lambda path:copy.deepcopy(self.saved))
    def enter(self):self.lock.start(); self.reader.start(); return self
    def close(self):self.reader.stop(); self.lock.stop()
    def reject(self):
        report = v8.ip_creation_l3_diagnostic()
        with mock.patch('builtins.open', return_value=io.StringIO(route(prefix='08', destination='ff' + '0' * 30))):
            v8._creation_owned_routes_safe(OWNED['name'], report)
        self.backend.ip_creation_gate_info = v8.ip_creation_diagnostic('interface_l3','interface_l3')
        self.backend.ip_creation_l3_info = report; self.backend.ip_identity_gate = mock.Mock(return_value=False)


class LeaseTests(unittest.TestCase):
    def setUp(self):self.f = MemoryFixture().enter()
    def tearDown(self):self.f.close()
    def test_same_rejected_row_reaches_public_failure_before_cleanup_no_address_write(self):
        self.f.reject()
        with self.assertRaises(ip.IpLeaseError):self.f.lease.start(20, lambda path, end:None)
        report = self.f.lease.failure_info['ip_creation_l3']
        self.assertEqual(report['route_details']['values'], {'prefix':8, 'destination_class':'multicast'})
        self.assertIn('stop_process', self.f.backend.calls); self.assertIn('remove', self.f.backend.calls)
        self.assertNotIn('newaddr', self.f.backend.calls); self.assertNotIn('deladdr', self.f.backend.calls)
        self.assertNotIn('route_details', json.dumps(self.f.saved))
    def test_first_route_diagnostic_cannot_be_overwritten_by_cleanup_or_late_success(self):
        self.f.reject()
        with self.assertRaises(ip.IpLeaseError):self.f.lease.start(20, lambda path, end:None)
        first = copy.deepcopy(self.f.lease.ip_creation_l3_info)
        self.f.backend.ip_creation_l3_info = v8.ip_creation_l3_diagnostic('accepted','done')
        self.f.lease._capture_ip_l3(); self.assertEqual(self.f.lease.ip_creation_l3_info, first)
    def test_malformed_detail_cannot_authorize_address_or_skip_owned_cleanup(self):
        self.f.backend.ip_creation_l3_info = dict(v8.ip_creation_l3_diagnostic(), route_details=detail({'prefix':True}))
        self.f.backend.ip_identity_gate = mock.Mock(return_value=True)
        with self.assertRaises(v8.LeaseError):self.f.lease.start(20, lambda path, end:None)
        self.assertNotIn('newaddr', self.f.backend.calls); self.assertIn('stop_process', self.f.backend.calls)
        self.assertEqual(self.f.lease.failure_info['ip_creation_l3']['route_details'], {})
    def test_fake_success_keeps_durable_receipt_and_restore_contract_send_still_false(self):
        self.f.backend.ip_creation_l3_info = v8.ip_creation_l3_diagnostic('accepted','done')
        ready = self.f.lease.start(20, lambda path, end:None)
        self.assertEqual(ready['ip_creation_l3']['route_details'], {})
        self.assertTrue(self.f.lease.state['ip']['receipt_fsynced']); self.assertFalse(ready['send_available'])
        self.assertTrue(self.f.lease.stop()['complete']); self.assertEqual(self.f.backend.calls.count('newaddr'), 1)
        self.assertEqual(self.f.backend.calls.count('deladdr'), 1)


class SourceTests(unittest.TestCase):
    def test_old_source_helper_native_hashes_unchanged_and_new_marker(self):
        self.assertEqual(hashlib.sha256(V7.read_bytes()).hexdigest(), 'fbf39cfed65400f656ede96be6b12925411c19f65ac1443838e781a1baff4e93')
        for name, pin in (('mta_ip.py', v7.IP_CODEC_SHA256), ('mta_ip_lease.py', v7.IP_HELPER_SHA256)):
            self.assertEqual(hashlib.sha256((ROOT / 'runtime' / name).read_bytes()).hexdigest(), pin)
        native = ROOT / 'native/private-p2p-candidate-20261001-v2'
        for name, pin in (('mta-wpa-supplicant', v7.WPA_SHA256),
                ('mta-wifi-caps', '9ea96e39c8a664cb45efb367522e84d2ac5fd820f256165fa4c0f77113aa58c6')):
            self.assertEqual(hashlib.sha256((native / name).read_bytes()).hexdigest(), pin)
        self.assertEqual(v8.DIAGNOSTIC_RUNTIME_MARKER, 'p011-go-ip-only-v8routediag-1')
        self.assertEqual(set(v7.LEASE_IDENTITY), set(v8.LEASE_IDENTITY))
        self.assertEqual(dict(v7.LEASE_IDENTITY, runtime_marker=v8.DIAGNOSTIC_RUNTIME_MARKER), v8.LEASE_IDENTITY)
    def test_frozen_predicates_restore_journal_helpers_and_all_other_functions_byte_identical(self):
        old_text, new_text = V7.read_text(encoding='utf-8'), V8.read_text(encoding='utf-8')
        def functions(text):
            result = {}
            def visit(body, prefix=''):
                for node in body:
                    if isinstance(node, ast.FunctionDef):
                        result[prefix + node.name] = ast.get_source_segment(text, node)
                        visit(node.body, prefix + node.name + '.')
                    elif isinstance(node, ast.ClassDef):visit(node.body, prefix + node.name + '.')
            visit(ast.parse(text).body)
            return result
        previous, current = functions(old_text), functions(new_text)
        changed = {'ip_creation_l3_diagnostic', '_l3_copy', '_creation_owned_routes_safe'}
        for name in sorted(set(previous) - changed):
            with self.subTest(function=name):self.assertEqual(previous[name], current[name])
        self.assertEqual(set(current) - set(previous), {'_route_details_copy','_route_detail_uint','_route_rejected'})
    def test_python35_no_assert_and_no_new_imports_socket_reads_or_actions(self):
        old = ast.parse(V7.read_text(encoding='utf-8'), feature_version=(3,5))
        new = ast.parse(V8.read_text(encoding='utf-8'), feature_version=(3,5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(new)))
        self.assertEqual([ast.dump(node) for node in old.body if isinstance(node, (ast.Import, ast.ImportFrom))],
                         [ast.dump(node) for node in new.body if isinstance(node, (ast.Import, ast.ImportFrom))])
        for function in (v8._route_details_copy, v8._route_detail_uint, v8._route_rejected):
            import inspect
            tree = ast.parse(inspect.getsource(function))
            calls = [node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
            self.assertFalse(set(calls) & {'open','socket','_address_dump','_digest','ReadWriteNetlink'})
    def test_v7_journal_identity_not_migrated_to_v8_recovery(self):
        fixture = MemoryFixture().enter()
        try:
            fixture.backend.ip_creation_l3_info = v8.ip_creation_l3_diagnostic('accepted','done')
            fixture.lease.start(20, lambda path, end:None)
            row = copy.deepcopy(fixture.lease.state); v8._journal_envelope(row)
            row['identity'] = dict(v7.LEASE_IDENTITY)
            with self.assertRaises(v8.LeaseError):v8._journal_envelope(row)
            fixture.lease.stop()
        finally:fixture.close()


if __name__ == '__main__':unittest.main()
