"""Pure HOST synthetic records only, not a real kernel/recovery experiment."""
import ast
import copy
import hashlib
import itertools
import pathlib
import sys
import unittest
from unittest import mock

PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'runtime'))
import mta_ip as core
import mta_ip_lease as helper
import mta_ip_receipt_recovery as inspect

RULES = (core.RuleRecord(0, 255), core.RuleRecord(32766, 254), core.RuleRecord(32767, 253))
OWNED = {'name': 'mta1234abcd', 'ifindex': 17, 'wdev': 23, 'phy': 0, 'iftype': 8}
SPEC = core.AddressSpec(17, '192.168.74.1', 24)
CACHE = (core.UINT_MAX, core.UINT_MAX, 123, 123)
STA = core.AddressRecord(3, core.ipv4_number('10.0.0.2'), core.ipv4_number('10.0.0.2'),
                         24, core.IFA_F_PERMANENT, 0, b'wlan0\0',
                         core.ipv4_number('10.0.0.255'), CACHE)
DEFAULT = core.RouteRecord(0, 0, 254, 16, 0, 1, 0, 3,
                           core.ipv4_number('10.0.0.1'), 600, STA.local, ())
STA_LOCAL = core.RouteRecord(STA.local, 32, 255, 2, 254, 2, 0, 3, None, None, STA.local, ())
BEFORE = core.IpSnapshot((STA,), (DEFAULT, STA_LOCAL), RULES)
ADDRESS = core.AddressRecord(17, SPEC.address, SPEC.address, 24, core.IFA_F_PERMANENT, 0,
                             OWNED['name'].encode('ascii') + b'\0', SPEC.address | 255, CACHE)
EXPECTED = helper._expected_routes(SPEC)


def receipt(stage='confirmed'):
    return {'stage': stage, 'owned': helper._origin(OWNED), 'spec': list(SPEC),
            'request': {'header': core.encode_new_address(SPEC, 7, 42)[:16].hex(),
                        'sequence': 7, 'port_id': 42},
            'address': helper.snapshot_data(core.IpSnapshot((ADDRESS,), (), RULES))['addresses'][0],
            'receipt_fsynced': True}


def current(routes=EXPECTED, addresses=(ADDRESS,), original=BEFORE):
    return core.IpSnapshot(original.addresses + tuple(addresses),
                           original.routes + tuple(routes), original.rules)


class ReceiptInspectionTests(unittest.TestCase):
    def rejected(self, code, now=None, before=BEFORE, record=None, owned=OWNED):
        with self.assertRaises(inspect.ReceiptInspectionError) as caught:
            inspect.inspect_receipt_delta(current() if now is None else now, before,
                                          receipt() if record is None else record, owned)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.args, (code,))
        self.assertEqual(str(caught.exception), code)

    def test_every_precise_subset_including_empty_and_all_four(self):
        cases = 0
        for count in range(5):
            for subset in itertools.combinations(EXPECTED, count):
                with self.subTest(count=count, ordinal=cases):
                    result = inspect.inspect_receipt_delta(current(subset), BEFORE, receipt(), OWNED)
                    self.assertEqual(result.state, 'exact_receipt_delta')
                    self.assertEqual(result.receipt_address, ADDRESS)
                    self.assertEqual(set(result.remaining_owned_routes), set(subset))
                    self.assertEqual(helper.snapshot_data(result.baseline_view), helper.snapshot_data(BEFORE))
                    self.assertEqual(result.status()['owned_expected_routes_missing'], 4 - count)
                cases += 1
        self.assertEqual(cases, 16)

    def test_delete_intent_durable_receipt_is_inspectable(self):
        result = inspect.inspect_receipt_delta(current(EXPECTED[1:2]), BEFORE,
                                              receipt('delete_intent'), OWNED)
        self.assertEqual(result.receipt_stage, 'delete_intent')
        self.assertFalse(result.status()['write_authorized'])

    def test_already_baseline_is_separate_readonly_fact(self):
        result = inspect.inspect_receipt_delta(BEFORE, BEFORE, receipt(), OWNED)
        self.assertEqual(result.state, 'baseline_already_equal')
        self.assertIsNone(result.receipt_address)
        self.assertEqual(result.remaining_owned_routes, ())
        self.assertFalse(result.status()['recovery_performed'])

    def test_delete_intent_already_baseline_is_not_a_delete(self):
        result = inspect.inspect_receipt_delta(BEFORE, BEFORE, receipt('delete_intent'), OWNED)
        self.assertEqual(result.state, 'baseline_already_equal')
        self.assertFalse(result.status()['write_authorized'])

    def test_missing_address_with_remaining_routes_rejected(self):
        self.rejected('receipt_address_missing', current(EXPECTED[1:2], ()))

    def test_missing_address_with_foreign_delta_rejected(self):
        self.rejected('receipt_address_missing', core.IpSnapshot((STA._replace(scope=253),),
                      BEFORE.routes, RULES))

    def test_extra_owned_address_rejected(self):
        other = ADDRESS._replace(local=SPEC.address + 1, address=SPEC.address + 1)
        self.rejected('owned_address_count', current(addresses=(ADDRESS, other)))

    def test_duplicate_owned_address_rejected_before_subtraction(self):
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS, ADDRESS)))

    def test_duplicate_address_key_with_different_cstamp_rejected(self):
        other = ADDRESS._replace(cacheinfo=(core.UINT_MAX, core.UINT_MAX, 124, 123))
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS, other)))

    def test_receipt_cstamp_must_match_exactly(self):
        self.rejected('receipt_address_changed', current(addresses=(ADDRESS._replace(
            cacheinfo=(core.UINT_MAX, core.UINT_MAX, 124, 123)),)))

    def test_receipt_tstamp_must_match_exactly(self):
        self.rejected('receipt_address_changed', current(addresses=(ADDRESS._replace(
            cacheinfo=(core.UINT_MAX, core.UINT_MAX, 123, 124)),)))

    def test_finite_lifetime_rejected_not_structurally_ignored(self):
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS._replace(
            cacheinfo=(30, core.UINT_MAX, 123, 123)),)))

    def test_address_flags_changed_rejected(self):
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS._replace(flags=0x180),)))

    def test_address_fields_remain_full_identity(self):
        for changes in ({'scope': 253}, {'prefixlen': 23}, {'label': b'mta00000000\0'},
                        {'broadcast': ADDRESS.broadcast - 1}, {'local': SPEC.address + 1}):
            with self.subTest(fields=tuple(changes)):
                self.rejected('receipt_address_changed', current(addresses=(ADDRESS._replace(**changes),)))

    def test_unknown_owned_route_fields_rejected(self):
        for changes in ({'table': 123}, {'protocol': 99}, {'scope': 253}, {'kind': 1},
                        {'gateway': SPEC.address + 2}, {'priority': 1}, {'prefsrc': SPEC.address + 1},
                        {'flags': 16}, {'metrics': ((1, 1500),)}):
            with self.subTest(fields=tuple(changes)):
                self.rejected('unexpected_owned_route', current((EXPECTED[1]._replace(**changes),)))

    def test_default_route_on_owned_interface_rejected(self):
        self.rejected('unexpected_owned_route', current((DEFAULT._replace(oif=17),)))

    def test_duplicate_expected_routes_rejected(self):
        self.rejected('invalid_snapshot', current((EXPECTED[1], EXPECTED[1])))

    def test_extra_owned_route_rejected(self):
        other = EXPECTED[1]._replace(network=SPEC.address + 2, prefsrc=SPEC.address)
        self.rejected('unexpected_owned_route', current(EXPECTED + (other,)))

    def test_foreign_address_delta_rejected(self):
        modified = core.IpSnapshot((STA._replace(local=STA.local + 1),), BEFORE.routes, RULES)
        self.rejected('original_baseline_changed', current(original=modified))

    def test_foreign_address_cacheinfo_delta_rejected(self):
        modified = core.IpSnapshot((STA._replace(cacheinfo=(core.UINT_MAX, core.UINT_MAX, 125, 125)),),
                                  BEFORE.routes, RULES)
        self.rejected('original_baseline_changed', current(original=modified))

    def test_foreign_route_delta_rejected(self):
        modified = core.IpSnapshot(BEFORE.addresses, (DEFAULT._replace(priority=601), STA_LOCAL), RULES)
        self.rejected('original_baseline_changed', current(original=modified))

    def test_foreign_address_missing_rejected(self):
        self.rejected('original_baseline_changed', current(original=core.IpSnapshot((), BEFORE.routes, RULES)))

    def test_nondefault_policy_rule_rejected(self):
        now = current()._replace(rules=RULES + (core.RuleRecord(100, 123),))
        self.rejected('invalid_snapshot', now)

    def test_removed_rule_rejected(self):
        self.rejected('invalid_snapshot', current()._replace(rules=RULES[:2]))

    def test_baseline_cannot_contain_owned_ifindex_address(self):
        self.rejected('baseline_contains_owned_interface', current(), current(routes=()))

    def test_baseline_cannot_contain_owned_ifindex_route(self):
        before = core.IpSnapshot(BEFORE.addresses, BEFORE.routes + (EXPECTED[1],), RULES)
        self.rejected('baseline_contains_owned_interface', current(), before)

    def test_uncommitted_or_restored_stage_rejected(self):
        for stage in ('create_intent', 'receipt_recorded', 'restored', 'unknown'):
            with self.subTest(stage=stage):
                self.rejected('invalid_receipt', record=receipt(stage))

    def test_receipt_stage_requires_exact_string_scalar(self):
        class StringSubclass(str):
            pass
        for value in (True, None, 1, ['confirmed'], StringSubclass('confirmed')):
            with self.subTest(kind=type(value).__name__):
                self.rejected('invalid_receipt', record=receipt(value))

    def test_facts_use_captured_stage_not_late_mutable_input(self):
        original_snapshot = inspect._full_snapshot
        for stage in ('confirmed', 'delete_intent'):
            for later in ('secret_do_not_publish', 'future_unreviewed_stage'):
                for already_equal in (False, True):
                    item = receipt(stage)
                    def fixture_snapshot(value):
                        result = original_snapshot(value)
                        # Only the HOST fixture changes the external dictionary.
                        item['stage'] = later
                        return result
                    with self.subTest(stage=stage, already_equal=already_equal):
                        with mock.patch.object(inspect, '_full_snapshot', side_effect=fixture_snapshot):
                            result = inspect.inspect_receipt_delta(BEFORE if already_equal else current(),
                                                                  BEFORE, item, OWNED)
                        self.assertEqual(item['stage'], later)
                        self.assertEqual(result.receipt_stage, stage)
                        self.assertEqual(result.status()['receipt_stage'], stage)
                        self.assertNotIn(later, repr(result.status()))

    def test_no_durable_receipt_flag_rejected(self):
        item = receipt(); item['receipt_fsynced'] = False
        self.rejected('invalid_receipt', record=item)

    def test_boolean_not_fsynced_true_rejected(self):
        item = receipt(); item['receipt_fsynced'] = 1
        self.rejected('invalid_receipt', record=item)

    def test_receipt_extra_field_rejected(self):
        item = receipt(); item['arbitrary'] = 'do_not_log'
        self.rejected('invalid_receipt', record=item)

    def test_receipt_request_header_mismatch_rejected(self):
        item = receipt(); item['request']['header'] = '00' * 16
        self.rejected('invalid_receipt', record=item)

    def test_receipt_origin_mismatch_rejected(self):
        for key in ('name', 'ifindex', 'wdev', 'phy'):
            item = receipt()
            item['owned'][key] = 'mta00000000' if key == 'name' else item['owned'][key] + 1
            with self.subTest(field=key):
                self.rejected('invalid_receipt', record=item)

    def test_receipt_address_must_match_spec(self):
        item = receipt(); item['address'][1] += 1
        self.rejected('invalid_receipt', record=item)

    def test_receipt_address_flags_boolean_rejected(self):
        item = receipt(); item['address'][4] = True
        self.rejected('invalid_receipt', record=item)

    def test_snapshot_boolean_integer_rejected(self):
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS._replace(scope=False),)))

    def test_mutable_cacheinfo_rejected(self):
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS._replace(cacheinfo=list(CACHE)),)))

    def test_mutable_metrics_rejected(self):
        self.rejected('invalid_snapshot', current((EXPECTED[1]._replace(metrics=[]),)))

    def test_oversized_label_rejected_without_hex_encoding(self):
        self.rejected('invalid_snapshot', current(addresses=(ADDRESS._replace(label=b'x' * 1000),)))

    def test_snapshot_type_and_record_limit_rejected(self):
        self.rejected('invalid_snapshot', {'addresses': []})
        self.rejected('invalid_snapshot', core.IpSnapshot((STA,) * (core.MAX_DUMP_RECORDS + 1), (), RULES))

    def test_snapshot_mutable_or_non_tuple_containers_rejected_first(self):
        for field in ('addresses', 'routes', 'rules'):
            for bad in ([], 1, None, 'private_do_not_format'):
                with self.subTest(field=field, kind=type(bad).__name__):
                    self.rejected('invalid_snapshot', current()._replace(**{field: bad}))

    def test_snapshot_non_record_rows_rejected_first(self):
        for field in ('addresses', 'routes', 'rules'):
            for bad in (1, (), [], None, 'private_do_not_format'):
                with self.subTest(field=field, kind=type(bad).__name__):
                    self.rejected('invalid_snapshot', current()._replace(**{field: (bad,)}))

    def test_metrics_malformed_nested_parts_rejected(self):
        for bad in ((1,), ([1, 1500],), ((1,),), ((True, 1500),), ((1, 'secret'),),
                    ((1, 1500),) * 16):
            with self.subTest(ordinal=len(bad)):
                self.rejected('invalid_snapshot', current((EXPECTED[1]._replace(metrics=bad),)))

    def test_duplicate_route_metrics_rejected(self):
        self.rejected('invalid_snapshot', current((EXPECTED[1]._replace(metrics=((1, 1500), (1, 1500))),)))

    def test_boolean_rule_field_rejected(self):
        self.rejected('invalid_snapshot', current()._replace(rules=(core.RuleRecord(False, 255),) + RULES[1:]))

    def test_foreign_duplicate_route_rejected(self):
        self.rejected('invalid_snapshot', current()._replace(routes=current().routes + (DEFAULT,)))

    def test_snapshot_order_does_not_hide_any_record_fields(self):
        now = current()._replace(addresses=tuple(reversed(current().addresses)),
                                 routes=tuple(reversed(current().routes)), rules=tuple(reversed(RULES)))
        result = inspect.inspect_receipt_delta(now, BEFORE, receipt(), OWNED)
        self.assertEqual(result.state, 'exact_receipt_delta')

    def test_result_and_nested_records_immutable_inputs_untouched(self):
        item = receipt(); saved = copy.deepcopy(item); own = dict(OWNED)
        result = inspect.inspect_receipt_delta(current(), BEFORE, item, own)
        self.assertEqual(item, saved); self.assertEqual(own, OWNED)
        with self.assertRaises(AttributeError):
            result.state = 'changed'
        with self.assertRaises(TypeError):
            result.receipt_address.cacheinfo[2] = 77
        item['address'][8][2] = 77; item['stage'] = 'create_intent'
        self.assertEqual(result.receipt_address.cacheinfo, CACHE)
        self.assertEqual(result.receipt_stage, 'confirmed')
        status = result.status(); status['state'] = 'changed'
        self.assertEqual(result.status()['state'], 'exact_receipt_delta')

    def test_public_summary_and_repr_never_expose_private_records(self):
        result = inspect.inspect_receipt_delta(current(EXPECTED[1:2]), BEFORE, receipt(), OWNED)
        text = repr(result) + str(result) + repr(result.status())
        for token in ('192.168.74.1', 'mta1234abcd', str(SPEC.address)):
            self.assertNotIn(token, text)
        self.assertEqual(set(result.status()), {'evidence', 'state', 'receipt_stage',
            'owned_address_present', 'owned_expected_routes_present', 'owned_expected_routes_missing',
            'full_ipv4_baseline_equal_after_subtraction', 'write_authorized', 'recovery_performed'})
        self.assertFalse(result.status()['write_authorized'])

    def test_malformed_receipt_error_cannot_leak_input_text(self):
        item = receipt(); item['request']['header'] = 'secret_do_not_log'
        self.rejected('invalid_receipt', record=item)
        self.assertEqual(str(inspect.ReceiptInspectionError(['secret'])), 'invalid_snapshot')

    def test_no_socket_or_transport_or_address_operation(self):
        with mock.patch.object(helper, 'RouteTransport', side_effect=AssertionError('transport')), \
                mock.patch.object(helper.socket, 'socket', side_effect=AssertionError('socket')):
            result = inspect.inspect_receipt_delta(current(EXPECTED[1:2]), BEFORE, receipt(), OWNED)
        self.assertEqual(result.state, 'exact_receipt_delta')

    def test_ordinary_fixed_without_owned_still_requires_four_routes(self):
        with self.assertRaises(helper.IpLeaseError) as caught:
            helper.without_owned(current(EXPECTED[1:2]), receipt(), OWNED)
        self.assertEqual(caught.exception.code, 'ip_owned_delta_changed')
        self.assertEqual(inspect.inspect_receipt_delta(current(EXPECTED[1:2]), BEFORE,
                                                      receipt(), OWNED).state, 'exact_receipt_delta')

    def test_source_python35_ast_and_no_io_or_mutation_entrypoints(self):
        source = (PROJECT / 'runtime/mta_ip_receipt_recovery.py').read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name): calls.add(node.func.id)
                elif isinstance(node.func, ast.Attribute): calls.add(node.func.attr)
        self.assertFalse(calls & {'open', 'socket', 'Popen', 'send', 'sendto', 'address_ack',
                                  'prepare_address', 'unlink', 'remove', 'restore', 'create', 'print'})

    def test_fixed_dependency_hashes_not_modified(self):
        pins = {'mta_ip.py': '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5',
                'mta_ip_lease.py': '39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c'}
        for name, pin in pins.items():
            self.assertEqual(hashlib.sha256((PROJECT / 'runtime' / name).read_bytes()).hexdigest(), pin)


if __name__ == '__main__':
    unittest.main()
