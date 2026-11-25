"""Synthetic HOST bytes/schema fixtures only; no kernel, sockets or device."""

import ast
import builtins
import os
import socket
import struct
import subprocess
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'runtime'))
import mta_client_caps as caps
import mta_p2p_client_init as owner
import mta_ip as ip
_MISSING = object()


def attr(kind, payload=b'', flags=0):
    length = len(payload) + 4
    return struct.pack('<HH', length, kind | flags) + payload + b'\0' * ((-length) % 4)


def u32(value):
    return struct.pack('<I', value)


def types(values, flags=0):
    return b''.join(attr(value, flags=flags) for value in values)


def array(rows, flags=0):
    return b''.join(attr(i + 1, row, flags) for i, row in enumerate(rows))


def limit(values=(2, 8), maximum=2, extra=b'', flags=0):
    return attr(1, u32(maximum)) + attr(2, types(values), flags) + extra


def combo(limits=None, maximum=2, channels=1, bi=1, radar=(0, 0), beacon=False,
          extra=b'', flags=0):
    if limits is None:
        limits = (limit(),)
    out = attr(1, array(limits, flags), flags) + attr(2, u32(maximum)) + attr(4, u32(channels))
    if beacon:
        out += attr(3)
    if radar[0] is not None:
        out += attr(5, u32(radar[0]))
    if radar[1] is not None:
        out += attr(6, u32(radar[1]))
    if bi is not None:
        out += attr(7, u32(bi))
    return out + extra


def phy(index=0, iftypes=(2, 8), software=(), combinations=None, commands=(7,),
        flags=0, extra=b''):
    if combinations is None:
        combinations = (combo(flags=flags),)
    out = attr(caps.WIPHY, u32(index))
    if iftypes is not None:
        out += attr(caps.SUPPORTED_IFTYPES, types(iftypes), flags)
    if software is not None:
        out += attr(caps.SOFTWARE_IFTYPES, types(software), flags)
    if combinations is not False:
        out += attr(caps.INTERFACE_COMBINATIONS, array(combinations, flags), flags)
    if commands is not None:
        out += attr(caps.SUPPORTED_COMMANDS, array(tuple(u32(n) for n in commands)), flags)
    return out + extra


class ClientCapsTests(unittest.TestCase):
    def reject(self, code, fragment=None, fragments=_MISSING, project=False):
        if fragments is _MISSING:
            fragments = (fragment,)
        fn = caps.decoded_client_schema if project else caps.decode_wiphy_projection
        with self.assertRaises(caps.CapsDecodeError) as caught:
            fn(fragments)
        self.assertEqual(code, caught.exception.code)
        self.assertEqual(code, str(caught.exception))

    def test_numeric_ids_match_fixed_header_record(self):
        self.assertEqual((1, 32, 50, 120, 121),
            (caps.WIPHY, caps.SUPPORTED_IFTYPES, caps.SUPPORTED_COMMANDS,
             caps.INTERFACE_COMBINATIONS, caps.SOFTWARE_IFTYPES))
        self.assertEqual((1, 2, 3, 4, 5, 6, 7), (caps.COMB_LIMITS, caps.COMB_MAXNUM,
            caps.COMB_BEACON_MATCH, caps.COMB_CHANNELS, caps.COMB_RADAR_WIDTHS,
            caps.COMB_RADAR_REGIONS, caps.COMB_BI_MIN_GCD))

    def test_complete_known_projection_preserves_all_values(self):
        row = caps.decode_wiphy_projection((phy(),)).phys[0]
        self.assertEqual((0, True, (2, 8), True, (), True, True, (7,)),
            (row.index, row.iftypes_present, row.iftypes, row.software_iftypes_present,
             row.software_iftypes, row.combinations_present, row.commands_present, row.commands))
        item = row.combinations[0]
        self.assertEqual((True, 1, 'minimum_gcd', True, 0, True, 0, False, False),
            (item.bi_min_gcd_present, item.bi_min_gcd, item.bi_policy,
             item.radar_widths_present, item.radar_widths, item.radar_regions_present,
             item.radar_regions, item.beacon_match_present, item.beacon_match))
        self.assertEqual((caps.Limit(2, (2, 8)),), item.limits)

    def test_v414_unflagged_and_nested_containers_are_both_valid(self):
        self.assertEqual(caps.decode_wiphy_projection((phy(),)),
                         caps.decode_wiphy_projection((phy(flags=caps.NLA_F_NESTED),)))

    def test_identity_only_fragment_keeps_missing_distinct_from_empty(self):
        row = caps.decode_wiphy_projection((attr(1, u32(0)),)).phys[0]
        self.assertFalse(row.iftypes_present)
        self.assertFalse(row.software_iftypes_present)
        self.assertFalse(row.combinations_present)
        self.assertFalse(row.commands_present)
        self.assertEqual((), row.software_iftypes)

    def test_empty_software_and_combinations_are_recorded_present(self):
        row = caps.decode_wiphy_projection((phy(combinations=()),)).phys[0]
        self.assertTrue(row.software_iftypes_present)
        self.assertTrue(row.combinations_present)
        self.assertEqual((), row.combinations)
        self.reject('incomplete_decoded_schema', phy(combinations=()), project=True)

    def test_multifragment_same_wiphy_is_not_duplicate_identity(self):
        first = attr(1, u32(0)) + attr(32, types((2, 8)))
        second = attr(1, u32(0)) + attr(121) + attr(120, array((combo(),))) + attr(50, array((u32(7),)))
        self.assertEqual(caps.decode_wiphy_projection((phy(),)),
                         caps.decode_wiphy_projection((first, second)))

    def test_same_identity_across_empty_fragments_is_legal(self):
        self.assertEqual(1, len(caps.decode_wiphy_projection((attr(1, u32(0)),) * 64).phys))

    def test_multiple_phys_are_sorted_not_merged(self):
        result = caps.decode_wiphy_projection((phy(3), phy(1)))
        self.assertEqual((1, 3), tuple(row.index for row in result.phys))

    def test_duplicate_wiphy_in_one_fragment_rejects(self):
        self.reject('duplicate_phy_attribute', phy(extra=attr(1, u32(0))))

    def test_duplicate_top_attribute_even_identical_rejects(self):
        self.reject('duplicate_phy_attribute', phy(extra=attr(121)))

    def test_cross_fragment_repeated_constraint_not_silently_deduplicated(self):
        self.reject('duplicate_phy_attribute', fragments=(phy(), attr(1, u32(0)) + attr(121)))
        self.reject('duplicate_phy_attribute', fragments=(phy(), phy()))

    def test_fragment_without_identity_rejects(self):
        self.reject('missing_wiphy', attr(121))

    def test_unknown_top_projected_attribute_rejects(self):
        self.reject('unknown_projected_attribute', phy(extra=attr(122)))

    def test_unknown_limit_constraint_cannot_be_omitted(self):
        self.reject('unknown_limit_constraint', phy(combinations=(combo(limits=(limit(extra=attr(3)),)),)))

    def test_unknown_combination_constraint_cannot_be_omitted(self):
        self.reject('unknown_combination_constraint', phy(combinations=(combo(extra=attr(8)),)))

    def test_duplicate_limit_and_combo_attributes_reject(self):
        self.reject('duplicate_limit_attribute', phy(combinations=(combo(limits=(limit(extra=attr(1, u32(2))),)),)))
        for kind, payload in ((2, u32(2)), (3, b''), (5, u32(0)), (6, u32(0)), (7, u32(1))):
            original = combo(beacon=True)
            self.reject('duplicate_combination_attribute', phy(combinations=(original + attr(kind, payload),)))

    def test_duplicate_iftype_and_command_reject(self):
        self.reject('duplicate_iftype', phy(iftypes=(2, 2, 8)))
        self.reject('duplicate_command', phy(commands=(7, 7)))

    def test_duplicate_combination_semantics_rejects(self):
        self.reject('duplicate_combination', phy(combinations=(combo(), combo())))

    def test_overlapping_limit_coverage_rejects(self):
        self.reject('overlapping_limit_types', phy(combinations=(combo(limits=(limit((2,)), limit((2, 8)))),)))

    def test_unadvertised_limit_or_software_type_rejects(self):
        self.reject('unadvertised_iftype', phy(iftypes=(2,)))
        self.reject('unadvertised_iftype', phy(software=(3,)))

    def test_known_software_types_are_preserved_not_removed_from_counts(self):
        decoded = caps.decode_wiphy_projection((phy(software=(8,)),)).phys[0]
        self.assertEqual((8,), decoded.software_iftypes)
        self.assertEqual((8,), caps.decoded_client_schema((phy(software=(8,)),))['phys'][0]['software_iftypes'])

    def test_unknown_or_unspecified_iftype_rejects(self):
        for number in (0, 13, 0x3fff):
            self.reject('unknown_iftype', phy(iftypes=(2, number)))

    def test_scalar_and_flag_nested_or_net_order_flags_reject(self):
        for flag in (caps.NLA_F_NESTED, caps.NLA_F_NET_BYTEORDER, 0xc000):
            self.reject('invalid_attribute_flags', attr(1, u32(0), flag))
            self.reject('invalid_attribute_flags', phy(iftypes=(2,), combinations=(), extra=attr(50, b'', flag)),
                        fragments=(attr(1, u32(0)) + attr(32, types((2,), flag)),))

    def test_nested_net_order_and_comb_scalar_flags_reject(self):
        self.reject('invalid_attribute_flags', attr(1, u32(0)) + attr(121, b'', caps.NLA_F_NET_BYTEORDER))
        malformed = attr(1, array((limit(),))) + attr(2, u32(2), caps.NLA_F_NESTED) + attr(4, u32(1))
        self.reject('invalid_attribute_flags', phy(combinations=(malformed,)))

    def test_flag_payload_and_bad_u32_reject(self):
        self.reject('invalid_flag_payload', attr(1, u32(0)) + attr(32, attr(2, b'x')))
        self.reject('invalid_u32', attr(1, b'x'))
        self.reject('invalid_u32', attr(1, u32(0) + u32(1)))
        self.reject('invalid_flag_payload', phy(combinations=(combo(extra=attr(3, b'x')),)))

    def test_required_positive_scalars_zero_reject(self):
        for item in (combo(maximum=0), combo(channels=0), combo(bi=0), combo(limits=(limit(maximum=0),))):
            self.reject('invalid_positive_u32', phy(combinations=(item,)))

    def test_required_attributes_and_nonempty_sets_reject(self):
        self.reject('missing_limit_attribute', phy(combinations=(combo(limits=(attr(1, u32(1)),)),)))
        self.reject('missing_combination_attribute', phy(combinations=(attr(2, u32(2)),)))
        self.reject('empty_iftypes', phy(iftypes=()))
        self.reject('empty_iftypes', phy(combinations=(combo(limits=(limit(values=()),)),)))
        self.reject('empty_limits', phy(combinations=(combo(limits=()),)))

    def test_array_duplicate_gap_zero_and_too_large_index_reject(self):
        for payload, code in ((attr(1, combo()) + attr(1, combo()), 'duplicate_array_index'),
                (attr(2, combo()), 'noncanonical_array_index'),
                (attr(0, combo()), 'array_budget_or_index'),
                (attr(17, combo()), 'array_budget_or_index')):
            self.reject(code, attr(1, u32(0)) + attr(120, payload))

    def test_default_bi_semantics_preserved_and_projection_refused(self):
        raw = phy(combinations=(combo(bi=None),))
        row = caps.decode_wiphy_projection((raw,)).phys[0].combinations[0]
        self.assertEqual((False, None, 'all_beacons_identical'),
                         (row.bi_min_gcd_present, row.bi_min_gcd, row.bi_policy))
        self.reject('unrepresented_bi_constraint', raw, project=True)

    def test_nonzero_bi_preserved_but_threshold_not_lost(self):
        for minimum in (2, 100, 0xffffffff):
            raw = phy(combinations=(combo(bi=minimum),))
            row = caps.decode_wiphy_projection((raw,)).phys[0].combinations[0]
            self.assertEqual(minimum, row.bi_min_gcd)
            self.reject('unrepresented_bi_constraint', raw, project=True)

    def test_absent_or_partial_radar_is_not_zero(self):
        for values in ((None, None), (0, None), (None, 0)):
            raw = phy(combinations=(combo(radar=values),))
            row = caps.decode_wiphy_projection((raw,)).phys[0].combinations[0]
            self.assertEqual(values, (row.radar_widths, row.radar_regions))
            self.reject('unrepresented_radar_absence', raw, project=True)

    def test_known_radar_bits_and_beacon_present_are_preserved(self):
        raw = phy(combinations=(combo(radar=(0xff, 0xf), beacon=True),))
        result = caps.decoded_client_schema((raw,))['phys'][0]['combinations'][0]
        self.assertEqual((0xff, 0xf, True), (result['radar_widths'], result['radar_regions'], result['beacon_match']))

    def test_unknown_radar_bits_reject(self):
        self.reject('unknown_radar_width', phy(combinations=(combo(radar=(0x100, 0)),)))
        self.reject('unknown_radar_region', phy(combinations=(combo(radar=(0, 0x10)),)))

    def test_projection_is_exact_current_schema_but_not_complete_proof(self):
        result = caps.decoded_client_schema((phy(),))
        self.assertEqual({'phys'}, set(result))
        self.assertEqual({'index', 'iftypes', 'software_iftypes', 'combinations', 'unknown_constraints'}, set(result['phys'][0]))
        self.assertEqual({'max_interfaces', 'num_channels', 'limits', 'radar_widths', 'radar_regions', 'beacon_match'},
                         set(result['phys'][0]['combinations'][0]))
        station = owner.Origin(0, 1, 22, 'wlan0', 2)
        actors = tuple(owner.Actor(n, 100, exe, 'b' * 64, ((n, 100, 'S'),))
            for n, exe in ((11, '/usr/bin/Z03'), (12, '/usr/bin/control_engine'), (13, '/usr/bin/weston')))
        rules = (ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254), ip.RuleRecord(32767, 253))
        snapshot = owner.Snapshot('12345678-1234-1234-1234-123456789abc', owner.STOCK_PINS,
            actors, station, 'a' * 64, 2412, (station,), ip.IpSnapshot((), (), rules), (), (), True)
        with self.assertRaises(owner.ClientInitError):
            owner.client_combo(result, snapshot)
        # Explicit HOST-only transport fixture, not a production proof provider.
        host_fixture = dict(result, complete=True)
        self.assertTrue(owner.client_combo(host_fixture, snapshot))

    def test_no_complete_or_split_boolean_can_be_supplied(self):
        for function in (caps.decode_wiphy_projection, caps.decoded_client_schema):
            with self.assertRaises(TypeError):
                function((phy(),), complete=True)
            with self.assertRaises(TypeError):
                function((phy(),), split=True)

    def test_projection_missing_known_fields_refuses(self):
        for raw in (phy(software=None), phy(iftypes=None), phy(combinations=False)):
            self.reject('incomplete_decoded_schema', raw, project=True)

    def test_decoded_records_are_immutable_and_projection_returns_fresh_dicts(self):
        row = caps.decode_wiphy_projection((phy(),)).phys[0]
        with self.assertRaises(AttributeError):
            row.index = 99
        first = caps.decoded_client_schema((phy(),))
        first['phys'][0]['combinations'][0]['limits'][0]['max'] = 999
        self.assertEqual(2, caps.decoded_client_schema((phy(),))['phys'][0]['combinations'][0]['limits'][0]['max'])

    def test_invalid_input_types_and_empty_fragments_reject(self):
        for value in (None, [], b'x', (), (b'',), (bytearray(phy()),)):
            code = 'invalid_fragment' if type(value) is tuple and value else 'invalid_fragments'
            self.reject(code, fragments=value)

    def test_missing_alignment_truncated_header_and_tail_reject(self):
        for raw in (b'\x00\x00\x01\x00', b'\x03\x00\x01\x00', b'\x09\x00\x01\x00xxxx',
                    attr(1, u32(0)) + b'x', struct.pack('<HH', 5, 122) + b'x'):
            self.reject('truncated_attribute', raw)

    def test_nested_truncation_and_nonzero_padding_reject(self):
        self.reject('truncated_attribute', attr(1, u32(0)) + attr(121, b'x'))
        self.reject('nonzero_padding', attr(1, u32(0)) + struct.pack('<HH', 5, 122) + b'x\0\0\x01')

    def test_fragment_count_byte_phy_and_command_budgets_reject(self):
        self.reject('invalid_fragments', fragments=(attr(1, u32(0)),) * 65)
        self.reject('invalid_fragment', fragments=(b'x' * (caps.MAX_BYTES + 1),))
        self.reject('byte_budget', fragments=(b'x' * caps.MAX_BYTES, attr(1, u32(0))))
        self.reject('phy_budget', fragments=tuple(attr(1, u32(n)) for n in range(9)))
        self.reject('array_budget_or_index', phy(commands=tuple(range(1, 258))))

    def test_global_attribute_budget_bounds_nested_work(self):
        limits = tuple(limit((n,), maximum=1) for n in range(1, 13))
        combinations = tuple(combo(limits=limits, maximum=n) for n in range(1, 17))
        raw = tuple(phy(n, iftypes=tuple(range(1, 13)), combinations=combinations) for n in range(8))
        self.reject('attribute_budget', fragments=raw)

    def test_python35_ast_and_pure_import_has_no_resource_actions(self):
        filename = os.path.join(ROOT, 'runtime', 'mta_client_caps.py')
        with open(filename, 'r', encoding='utf-8') as stream:
            source = stream.read()
        tree = ast.parse(source, filename=filename, feature_version=(3, 5))
        self.assertEqual({'struct', 'collections'}, {node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
            for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))})
        compiled = compile(tree, filename, 'exec')
        with mock.patch.object(builtins, 'open', side_effect=AssertionError('HOST unexpected I/O')), \
                mock.patch.object(socket, 'socket', side_effect=AssertionError('HOST unexpected socket')), \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('HOST unexpected process')):
            namespace = {'__name__': 'host_pure_caps_fixture'}
            exec(compiled, namespace)
            result = namespace['decode_wiphy_projection']((phy(),))
            self.assertEqual(1, len(result.phys))


if __name__ == '__main__':
    unittest.main(verbosity=2)
