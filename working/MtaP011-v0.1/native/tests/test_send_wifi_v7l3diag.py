"""PC HOST-only same-read L3 diagnostics; fake kernel/journal/sysfs, no device/RF."""
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

V6 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v6diag/runtime/mta_send_wifi.py'
V7 = ROOT / 'native/private-p2p-runtime-candidate-20261001-v7l3diag/runtime/mta_send_wifi.py'


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


v6 = module(V6, 'v6_l3_comparison_only')
v7 = module(V7, 'v7_l3_host_only')
OWNED = {'name': 'mta1234abcd', 'ifindex': 9, 'wdev': 20, 'phy': 0, 'iftype': 8}
LL = bytes.fromhex('fe800000000000000000000000000001')


def address(**changes):
    result = {'family': 6, 'prefix': 64, 'scope': 253, 'address': LL}
    result.update(changes)
    return result


def route(**changes):
    parts = ['fe800000000000000000000000000000', '40', '0' * 32, '00',
             '0' * 32, '00000100', '00000001', '00000000', '00000001', OWNED['name']]
    fields = {'destination': 0, 'prefix': 1, 'source': 2, 'source_prefix': 3,
              'gateway': 4, 'name': 9}
    for key, value in changes.items(): parts[fields[key]] = value
    return ' '.join(parts) + '\n'


class AddressTests(unittest.TestCase):
    def checked(self, rows):
        report = v7.ip_creation_l3_diagnostic()
        result = v7._creation_only_link_local(rows, report)
        self.assertEqual(result, v6._only_link_local(rows))
        return result, report
    def test_empty_still_accepted_without_fabricating_address_presence(self):
        allowed, report = self.checked([])
        self.assertTrue(allowed); self.assertEqual(report['counts']['ipv6_address_rows_examined'], 0)
        self.assertTrue(report['observations']['addresses_accepted'])
    def test_link_local_64_is_unchanged(self):
        allowed, report = self.checked([address()])
        self.assertTrue(allowed); self.assertEqual(report['counts']['ipv6_address_rows_examined'], 1)
    def test_family_rejection(self):
        self.assertEqual(self.checked([address(family=4)])[1]['reason'], 'address_family')
    def test_prefix_rejection(self):
        self.assertEqual(self.checked([address(prefix=128)])[1]['reason'], 'address_prefix')
    def test_scope_rejection(self):
        self.assertEqual(self.checked([address(scope=0)])[1]['reason'], 'address_scope')
    def test_length_rejection(self):
        self.assertEqual(self.checked([address(address=LL[:8])])[1]['reason'], 'address_length')
    def test_first_byte_rejection(self):
        self.assertEqual(self.checked([address(address=b'\xfd' + LL[1:])])[1]['reason'], 'address_not_link_local')
    def test_second_byte_mask_rejection(self):
        self.assertEqual(self.checked([address(address=b'\xfe\xc0' + LL[2:])])[1]['reason'], 'address_not_link_local')
    def test_address_short_circuit_never_accesses_later_row(self):
        rows = [address(prefix=128), {}]
        allowed, report = self.checked(rows)
        self.assertFalse(allowed); self.assertEqual(report['counts']['ipv6_address_rows_examined'], 1)
    def test_count_saturation_preserves_original_acceptance(self):
        allowed, report = self.checked([address()] * 4100)
        self.assertTrue(allowed); self.assertEqual(report['counts']['ipv6_address_rows_examined'], 4095)
        self.assertTrue(report['observations']['count_saturated'])


class RouteTests(unittest.TestCase):
    def checked(self, text):
        report = v7.ip_creation_l3_diagnostic()
        with mock.patch('builtins.open', return_value=io.StringIO(text)) as opened:
            allowed = v7._creation_owned_routes_safe(OWNED['name'], report)
        opened.assert_called_once_with('/proc/net/ipv6_route')
        with mock.patch('builtins.open', return_value=io.StringIO(text)):
            original = v6._owned_routes_safe(OWNED['name'], allow_ipv4=True)
        self.assertEqual(allowed, original)
        return allowed, report
    def test_empty_routes_accepted(self):
        allowed, report = self.checked('')
        self.assertTrue(allowed); self.assertEqual(report['counts']['ipv6_route_rows_examined'], 0)
        self.assertEqual(report['reason'], 'accepted')
    def test_link_local_64_keeps_exact_acceptance(self):
        allowed, report = self.checked(route())
        self.assertTrue(allowed); self.assertFalse(report['observations']['route_prefix_is_128'])
    def test_owned_local_128_is_diagnosed_but_still_rejected(self):
        allowed, report = self.checked(route(destination=LL.hex(), prefix='80'))
        self.assertFalse(allowed); self.assertEqual(report['reason'], 'route_prefix')
        self.assertTrue(report['observations']['route_prefix_is_128'])
        self.assertEqual(report['stage'], 'route_prefix')
    def test_prefix_limits_are_not_relaxed(self):
        for value in ('09', '41', '81'):
            with self.subTest(prefix=value):
                self.assertEqual(self.checked(route(prefix=value))[1]['reason'], 'route_prefix')
    def test_non_link_local_destination_rejected(self):
        self.assertEqual(self.checked(route(destination='fd' + '0' * 30))[1]['reason'], 'route_destination')
    def test_nonzero_source_rejected(self):
        self.assertEqual(self.checked(route(source='1'))[1]['reason'], 'route_source')
    def test_nonzero_source_prefix_rejected(self):
        self.assertEqual(self.checked(route(source_prefix='01'))[1]['reason'], 'route_source_prefix')
    def test_nonzero_gateway_rejected(self):
        self.assertEqual(self.checked(route(gateway=LL.hex()))[1]['reason'], 'route_gateway')
    def test_wrong_field_count_rejected(self):
        report = self.checked('1 2 ' + OWNED['name'] + '\n')[1]
        self.assertEqual(report['reason'], 'route_shape')
        self.assertNotIn('route_prefix_is_128', report['observations'])
    def test_hex_failures_have_exact_already_visited_stage(self):
        for field in ('destination', 'prefix', 'source', 'source_prefix', 'gateway'):
            with self.subTest(field=field):
                report = self.checked(route(**{field: 'INVALID'}))[1]
                self.assertEqual(report['reason'], 'route_hex_invalid')
                self.assertEqual(report['stage'], 'route_' + field)
    def test_prefix_short_circuit_never_parses_later_invalid_fields(self):
        report = self.checked(route(prefix='80', source='INVALID', gateway='INVALID'))[1]
        self.assertEqual(report['reason'], 'route_prefix')
    def test_first_bad_route_stops_before_later_good_route(self):
        report = self.checked(route(prefix='80') + route())[1]
        self.assertEqual(report['counts']['ipv6_route_rows_examined'], 1)
        self.assertTrue(report['observations']['route_prefix_is_128'])
    def test_other_interface_rows_are_not_owned_or_counted(self):
        allowed, report = self.checked(route(name='other', prefix='80') + route())
        self.assertTrue(allowed); self.assertEqual(report['counts']['ipv6_route_rows_examined'], 1)
    def test_current_malformed_row_does_not_inherit_previous_prefix_observation(self):
        report = self.checked(route() + '1 2 ' + OWNED['name'] + '\n')[1]
        self.assertEqual(report['reason'], 'route_shape')
        self.assertNotIn('route_prefix_is_128', report['observations'])
    def test_route_count_saturation_does_not_add_a_network_gate(self):
        allowed, report = self.checked(route() * 4100)
        self.assertTrue(allowed); self.assertEqual(report['counts']['ipv6_route_rows_examined'], 4095)
        self.assertTrue(report['observations']['count_saturated'])


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.backend = object.__new__(v7.LinuxBackend)
        self.backend.allow_rf = True; self.backend.guard = mock.Mock(fd=5)
        self.backend.nl = mock.Mock(); self.backend.nl.interfaces.return_value = [dict(OWNED, iftype=9)]
        self.sysfs = {'flags': '0x1003', 'carrier': '1', 'ifindex': '9'}
    def check(self, rows=None, route_text='', dump_error=None, route_error=None, creating=True):
        reads = []
        def opened(path, *args):
            reads.append(path)
            if path == '/proc/net/ipv6_route':
                if route_error: raise route_error
                return io.StringIO(route_text)
            return io.StringIO(self.sysfs[path.rsplit('/', 1)[1]])
        with mock.patch('builtins.open', side_effect=opened), \
             mock.patch.object(v7, '_digest', side_effect=lambda path: v7.STOCK_PINS[path]), \
             mock.patch.object(v7, '_address_dump', side_effect=dump_error, return_value=rows or []) as dump:
            allowed = self.backend.ip_identity_gate(OWNED, creating)
        return allowed, reads, dump.call_count, getattr(self.backend, 'ip_creation_l3_info', None)
    def test_success_uses_one_dump_one_route_read(self):
        allowed, reads, dumps, report = self.check([address()], route())
        self.assertTrue(allowed); self.assertEqual(dumps, 1)
        self.assertEqual(reads.count('/proc/net/ipv6_route'), 1)
        self.assertEqual(report['reason'], 'accepted')
        self.assertEqual(report['counts'], {'ipv6_address_rows': 1, 'ipv6_address_rows_examined': 1,
                                           'ipv6_route_rows_examined': 1})
    def test_address_rejection_never_opens_route(self):
        allowed, reads, dumps, report = self.check([address(prefix=128)], route(), route_error=AssertionError('unvisited'))
        self.assertFalse(allowed); self.assertEqual(dumps, 1)
        self.assertNotIn('/proc/net/ipv6_route', reads)
        self.assertNotIn('ipv6_route_rows_examined', report['counts'])
        self.assertNotIn('routes_accepted', report['observations'])
    def test_route_rejection_is_from_same_single_read(self):
        allowed, reads, dumps, report = self.check([address()], route(prefix='80'))
        self.assertFalse(allowed); self.assertEqual(dumps, 1)
        self.assertEqual(reads.count('/proc/net/ipv6_route'), 1)
        self.assertEqual(report['reason'], 'route_prefix')
        self.assertEqual(self.backend.ip_creation_gate_info['reason'], 'interface_l3')
    def test_dump_failure_reports_unvisited_counts_missing(self):
        allowed, reads, dumps, report = self.check(dump_error=OSError('PRIVATE_ADDRESS_NEVER_EXPORT'))
        self.assertFalse(allowed); self.assertEqual(dumps, 1)
        self.assertEqual(report, v7.ip_creation_l3_diagnostic('unexpected_l3_read', 'address_dump'))
        self.assertNotIn('/proc/net/ipv6_route', reads)
    def test_route_open_failure_keeps_observed_address_facts_only(self):
        allowed, reads, dumps, report = self.check([address()], route_error=OSError('PRIVATE_NAME'))
        self.assertFalse(allowed); self.assertEqual(report['reason'], 'unexpected_l3_read')
        self.assertEqual(report['stage'], 'ipv6_routes')
        self.assertTrue(report['observations']['addresses_accepted'])
        self.assertNotIn('routes_accepted', report['observations'])
    def test_carrier_failure_does_not_visit_l3_or_fabricate_facts(self):
        self.sysfs['carrier'] = '0'
        allowed, reads, dumps, report = self.check([address()], route())
        self.assertFalse(allowed); self.assertEqual(dumps, 0)
        self.assertEqual(report, v7.ip_creation_l3_diagnostic())
    def test_restore_uses_original_helpers_and_never_updates_l3(self):
        first = v7.ip_creation_l3_diagnostic('route_prefix', 'route_prefix')
        self.backend.ip_creation_l3_info = copy.deepcopy(first)
        with mock.patch.object(v7, '_creation_only_link_local', side_effect=AssertionError('creation only')), \
             mock.patch.object(v7, '_creation_owned_routes_safe', side_effect=AssertionError('creation only')):
            allowed, unused, dumps, report = self.check([address()], route(), creating=False)
        self.assertTrue(allowed); self.assertEqual(dumps, 1); self.assertEqual(report, first)
    def test_unexpected_diagnostic_corruption_remains_fail_closed(self):
        def corrupt(rows, report):
            report['counts']['PRIVATE_IDENTIFIER'] = True
            return True
        with mock.patch.object(v7, '_creation_only_link_local', side_effect=corrupt):
            allowed, unused, unused_dump, report = self.check([address()], route())
        self.assertFalse(allowed)
        self.assertEqual(report, v7.ip_creation_l3_diagnostic('unexpected_l3_read'))
    def test_exception_text_and_address_bytes_never_exported(self):
        report = self.check([address()], route_error=OSError('PRIVATE_ADDRESS_NEVER_EXPORT'))[3]
        text = json.dumps(report)
        self.assertNotIn('PRIVATE_', text); self.assertNotIn(OWNED['name'], text)
        self.assertNotIn(LL.hex(), text)
    def test_full_backend_acceptance_read_count_and_order_equal_v6(self):
        cases = [([address()], route()), ([address(prefix=128)], route()),
                 ([address()], route(prefix='80')), ([], ''), ([address()], route(gateway='1'))]
        for rows, text in cases:
            observed = []
            for source in (v6, v7):
                backend = object.__new__(source.LinuxBackend)
                backend.allow_rf = True; backend.guard = mock.Mock(fd=5)
                backend.nl = mock.Mock(); backend.nl.interfaces.return_value = [dict(OWNED, iftype=9)]
                calls = []
                def opened(path, *args):
                    calls.append(('open', path))
                    return io.StringIO(text if path == '/proc/net/ipv6_route' else self.sysfs[path.rsplit('/', 1)[1]])
                def dump(index):
                    calls.append(('dump', index)); return rows
                with mock.patch('builtins.open', side_effect=opened), \
                     mock.patch.object(source, '_digest', side_effect=lambda path: source.STOCK_PINS[path]), \
                     mock.patch.object(source, '_address_dump', side_effect=dump):
                    allowed = backend.ip_identity_gate(OWNED, True)
                observed.append((allowed, calls, backend.nl.interfaces.call_count))
            self.assertEqual(observed[0], observed[1])


class MemoryFixture(object):
    def __init__(self):
        self.backend = FakeBackend(); self.saved = None; self.saves = 0
        self.lease = v7.GoLease(self.backend, os.path.join(str(ROOT), 'HOST_ONLY_NO_SUCH_JOURNAL'), lambda: 100.0)
        def save(locked=False):
            self.saves += 1; self.saved = copy.deepcopy(self.lease.state)
        self.lease._save = save
        self.patch_lock = mock.patch.object(v7, 'JournalLock', FakeLock)
        self.patch_read = mock.patch.object(v7, '_read_private_json', side_effect=lambda path: copy.deepcopy(self.saved))
    def enter(self):
        self.patch_lock.start(); self.patch_read.start(); return self
    def close(self):
        self.patch_read.stop(); self.patch_lock.stop()
    def prepare(self):
        self.backend.rows = [dict(OWNED, iftype=9)]
        self.backend.ip_transport.name = OWNED['name']
        self.backend.process = {'pid': 200, 'starttime': 800, 'exe': '/private/mock-wpa'}
        self.lease.state = {'version': 3, 'kind': 'go_ip_only', 'identity': dict(v7.LEASE_IDENTITY),
            'stage': 'go_ready', 'name': OWNED['name'], 'baseline': copy.deepcopy(self.backend.baseline),
            'deadline': 120.0, 'owned': dict(OWNED), 'process': copy.deepcopy(self.backend.process), 'ip': None}
        self.saved = copy.deepcopy(self.lease.state)


class LeaseTests(unittest.TestCase):
    def setUp(self): self.f = MemoryFixture().enter()
    def tearDown(self): self.f.close()
    def reject_backend(self):
        self.f.backend.ip_creation_gate_info = v7.ip_creation_diagnostic('interface_l3', 'interface_l3')
        self.f.backend.ip_creation_l3_info = v7.ip_creation_l3_diagnostic('route_prefix', 'route_prefix',
            {'ipv6_route_rows_examined': 1}, {'route_prefix_is_128': True})
        self.f.backend.ip_identity_gate = mock.Mock(return_value=False)
    def test_creation_l3_rejection_is_captured_before_intent_or_address_write(self):
        self.f.prepare(); self.reject_backend()
        with self.assertRaises(ip.IpLeaseError): self.f.lease._ip_sublease().create(120)
        self.assertEqual(self.f.lease.ip_creation_l3_info['reason'], 'route_prefix')
        self.assertEqual(self.f.saves, 0); self.assertIsNone(self.f.lease.state['ip'])
        self.assertNotIn('newaddr', self.f.backend.calls); self.assertNotIn('deladdr', self.f.backend.calls)
    def test_first_l3_rejection_not_overwritten_by_later_read_or_cleanup(self):
        self.f.prepare(); self.reject_backend()
        self.assertFalse(self.f.lease._ip_gate(True))
        first = copy.deepcopy(self.f.lease.ip_creation_l3_info)
        self.f.backend.ip_creation_l3_info = v7.ip_creation_l3_diagnostic('accepted', 'done')
        self.f.lease._capture_ip_l3()
        self.assertEqual(self.f.lease.ip_creation_l3_info, first)
        self.f.lease._ip_gate(False)
        self.assertEqual(self.f.lease.ip_creation_l3_info, first)
    def test_full_start_failure_public_snapshot_before_cleanup_and_no_journal_diag(self):
        self.reject_backend()
        with self.assertRaises(ip.IpLeaseError): self.f.lease.start(20, lambda path, end: None)
        report = self.f.lease.failure_info['ip_creation_l3']
        self.assertEqual(report['reason'], 'route_prefix')
        self.assertEqual(self.f.lease.failure_info['failure_phase'], 'ip_create')
        self.assertIn('stop_process', self.f.backend.calls); self.assertIn('remove', self.f.backend.calls)
        self.assertNotIn('newaddr', self.f.backend.calls)
        self.assertNotIn('ip_creation_l3', json.dumps(self.f.saved))
    def test_invalid_backend_diagnostic_cannot_authorize_address_write_or_break_cleanup(self):
        self.f.backend.ip_creation_l3_info = {'PRIVATE': True}
        self.f.backend.ip_identity_gate = mock.Mock(return_value=True)
        with self.assertRaises(v7.LeaseError): self.f.lease.start(20, lambda path, end: None)
        self.assertEqual(self.f.lease.failure_info['ip_creation_l3'],
                         v7.ip_creation_l3_diagnostic('unexpected_l3_read'))
        self.assertNotIn('newaddr', self.f.backend.calls); self.assertIn('stop_process', self.f.backend.calls)
    def test_success_fake_transaction_keeps_existing_receipts_and_new_public_diagnostic(self):
        self.f.backend.ip_creation_l3_info = v7.ip_creation_l3_diagnostic('accepted', 'done')
        ready = self.f.lease.start(20, lambda path, end: None)
        self.assertEqual(ready['ip_creation_l3']['reason'], 'accepted')
        self.assertTrue(self.f.lease.state['ip']['receipt_fsynced'])
        self.assertFalse(ready['dhcp_ready']); self.assertFalse(ready['send_available'])
        self.assertTrue(self.f.lease.stop()['complete'])
        self.assertEqual(self.f.backend.calls.count('newaddr'), 1)
        self.assertEqual(self.f.backend.calls.count('deladdr'), 1)


class SourceTests(unittest.TestCase):
    def test_strict_schema_rejects_free_text_unknown_keys_bool_counts_and_nonbool_observations(self):
        bad = [dict(reason='PRIVATE'), dict(stage='PRIVATE'), dict(counts={'ipv6_address_rows': True}),
               dict(counts={'ipv6_address_rows': 4096}), dict(counts={'ipv6_address_rows': -1}),
               dict(counts={'PRIVATE': 1}), dict(observations={'routes_accepted': 1}),
               dict(observations={'PRIVATE': True})]
        for kwargs in bad:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(v7.LeaseError): v7.ip_creation_l3_diagnostic(**kwargs)
        with self.assertRaises(v7.LeaseError): v7._l3_copy(dict(v7.ip_creation_l3_diagnostic(), extra=True))
    def test_old_pins_and_new_identity(self):
        self.assertEqual(hashlib.sha256(V6.read_bytes()).hexdigest(),
                         '82bb5ba72c887608543d64018e2979cd27d6ee112036de9a701f0e5709de4faa')
        for name, pin in (('mta_ip.py', v6.IP_CODEC_SHA256), ('mta_ip_lease.py', v6.IP_HELPER_SHA256)):
            self.assertEqual(hashlib.sha256((ROOT / 'runtime' / name).read_bytes()).hexdigest(), pin)
        self.assertEqual(v7.DIAGNOSTIC_RUNTIME_MARKER, 'p011-go-ip-only-v7l3diag-1')
        self.assertNotEqual(v6.LEASE_IDENTITY, v7.LEASE_IDENTITY)
    def test_old_v6_journal_is_not_new_recovery_identity(self):
        f = MemoryFixture().enter()
        try:
            f.prepare(); old = copy.deepcopy(f.lease.state); old['identity'] = dict(v6.LEASE_IDENTITY)
            with self.assertRaises(v7.LeaseError): v7._journal_envelope(old)
        finally: f.close()
    def test_python35_and_no_assert_mutation(self):
        tree = ast.parse(V7.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(tree)))
    def test_all_other_existing_functions_are_ast_identical(self):
        old = ast.parse(V6.read_text(encoding='utf-8')); new = ast.parse(V7.read_text(encoding='utf-8'))
        def functions(tree):
            result = {}
            for node in tree.body:
                if isinstance(node, ast.FunctionDef): result[node.name] = node
                elif isinstance(node, ast.ClassDef):
                    for sub in node.body:
                        if isinstance(sub, ast.FunctionDef): result[node.name + '.' + sub.name] = sub
            return result
        a, b = functions(old), functions(new)
        allowed = {'LinuxBackend.ip_identity_gate', 'GoLease.__init__', 'GoLease.start', 'GoLease._ip_gate', 'main'}
        for name in sorted(set(a) - allowed):
            with self.subTest(function=name): self.assertEqual(ast.dump(a[name]), ast.dump(b[name]))
        self.assertEqual(set(b) - set(a), {'ip_creation_l3_diagnostic', '_l3_copy', '_l3_count', '_l3_rejected',
            '_creation_only_link_local', '_creation_owned_routes_safe', 'GoLease._capture_ip_l3'})


if __name__ == '__main__': unittest.main()
