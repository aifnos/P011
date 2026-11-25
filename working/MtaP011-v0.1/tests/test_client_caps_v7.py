"""Versioned CLIENT-init caps SOURCE/Fake tests; no actual OS/RF calls."""
import ast
import copy
import hashlib
import os
import sys
import types
import unittest
from unittest import mock

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, 'runtime'))
import mta_client_caps as decoder
import mta_ip as ip
from test_client_caps import phy, combo, limit

PROVIDER_SOURCE = os.path.join(BASE, 'candidate', 'client-owned-origin-v4', 'runtime', 'mta_client_linux_provider.py')
CORE_SOURCE = os.path.join(BASE, 'candidate', 'client-baseline-v3', 'runtime', 'mta_p2p_client_init.py')
DIRECTORY = os.path.join(BASE, 'candidate', 'client-caps-v7', 'runtime')
PROVIDER_PIN = 'a8ca35f57841bf75b9ea53120404a395e2ad446cb2859a16a6c5c225efbb5491'
CORE_PIN = 'f5ebf037743f9fc910a7107425119576acdea649e16cf9e0660c0e9e257a607e'
COMMANDS = (6, 7, 11, 15, 19, 46, 48, 52, 53, 54, 55, 59, 65, 75, 89, 104, 105)


def read(path):
    with open(path, 'rb') as stream:
        return stream.read()


def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = path
    exec(compile(read(path), path, 'exec'), module.__dict__)
    return module


c = load('v7_private_core', os.path.join(DIRECTORY, 'mta_p2p_client_init.py'))
p = load('v7_private_provider', os.path.join(DIRECTORY, 'mta_client_linux_provider.py'))
p.core = c  # Pure test namespace only; actual deployment uses the pinned graph names.
old = load('v7_reference_core', CORE_SOURCE)


def decoded(bi=None, commands=COMMANDS):
    wire = phy(iftypes=(2, 3, 8, 9, 10), commands=commands, combinations=(combo(
        limits=(limit((2, 3), 1), limit((8, 9), 1), limit((10,), 1)),
        maximum=3, channels=2, bi=bi),))
    return decoder.decode_wiphy_projection((wire,))


def snapshot(module=c, roles=()):
    station = module.Origin(0, 1, 22, 'wlan0', 2)
    interfaces = (station,) + tuple(module.Origin(0, i + 2, i + 23, 'fake' + str(i), role)
                                   for i, role in enumerate(roles))
    actors = tuple(module.Actor(i + 10, 100, '/usr/bin/' + name, 'a' * 64,
                                ((i + 10, 100, 'S'),))
                   for i, name in enumerate(('Z03', 'control_engine', 'weston')))
    ipv4 = ip.IpSnapshot((), (), (ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254), ip.RuleRecord(32767, 253)))
    return module.Snapshot('12345678-1234-1234-1234-123456789abc', module.STOCK_PINS,
        actors, station, 'b' * 64, 2412, interfaces, ipv4, (), (), True)


def fields(value):
    return value['phys'][0]['combinations'][0]


def legacy(value):
    result = copy.deepcopy(value)
    for item in result['phys'][0]['combinations']:
        del item['bi_policy']
        del item['bi_min_gcd']
    return result


class ClientCapsV7Tests(unittest.TestCase):
    def reject_core(self, value, observed=None):
        with self.assertRaises(c.ClientInitError):
            c.client_combo(value, snapshot() if observed is None else observed)

    def replace_combo(self, **changes):
        value = decoded()
        row = value.phys[0]
        item = row.combinations[0]._replace(**changes)
        return value._replace(phys=(row._replace(combinations=(item,)),))

    def test_actual_public_command_profile_absent_del_and_bi(self):
        value = decoded()
        self.assertEqual(COMMANDS, value.phys[0].commands)
        self.assertNotIn(8, value.phys[0].commands)
        result = p._caps_core(value)
        item = fields(result)
        self.assertEqual(('all_beacons_identical', None), (item['bi_policy'], item['bi_min_gcd']))
        self.assertEqual((3, 2), (item['max_interfaces'], item['num_channels']))
        self.assertEqual(({'max': 1, 'types': (2, 3)}, {'max': 1, 'types': (8, 9)},
                          {'max': 1, 'types': (10,)}), item['limits'])
        self.assertTrue(c.client_combo(result, snapshot()))

    def test_provider_requires_new_and_exact_known_bi_presence(self):
        invalid = [decoded(commands=tuple(n for n in COMMANDS if n != 7)), decoded(bi=2),
            self.replace_combo(bi_policy=True), self.replace_combo(bi_min_gcd=1),
            self.replace_combo(bi_policy='minimum_gcd', bi_min_gcd_present=True, bi_min_gcd=True),
            self.replace_combo(bi_min_gcd_present=0), self.replace_combo(radar_widths_present=False),
            self.replace_combo(bi_policy='future')]
        for value in invalid:
            with self.subTest(value_index=invalid.index(value)):
                with self.assertRaises(p.LinuxProviderError) as caught:
                    p._caps_core(value)
                self.assertEqual('interface_unknown', caught.exception.code)

    def test_minimum_one_explicit_value_and_old_schema_behavior(self):
        value = p._caps_core(decoded(bi=1))
        self.assertEqual(('minimum_gcd', 1), (fields(value)['bi_policy'], fields(value)['bi_min_gcd']))
        self.assertTrue(c.client_combo(value, snapshot()))
        original = legacy(value)
        self.assertTrue(c.client_combo(original, snapshot()))
        self.assertTrue(old.client_combo(original, snapshot(old)))
        for changes in ({'max_interfaces': 1}, {'radar_widths': 1}, {'beacon_match': True}, {'num_channels': False}):
            bad = copy.deepcopy(original)
            fields(bad).update(changes)
            for module in (old, c):
                with self.assertRaises(module.ClientInitError):
                    module.client_combo(bad, snapshot(module))

    def test_core_bi_unknown_larger_bool_and_mismatched_values_reject(self):
        for policy, minimum in ((True, None), ('future', None), ('all_beacons_identical', 1),
                ('all_beacons_identical', False), ('minimum_gcd', None), ('minimum_gcd', True),
                ('minimum_gcd', 2), ('minimum_gcd', 1.0)):
            value = p._caps_core(decoded())
            fields(value).update(bi_policy=policy, bi_min_gcd=minimum)
            self.reject_core(value)

    def test_identical_bi_current_only_original_station_no_other_roles(self):
        value = p._caps_core(decoded())
        for role in (1, 2, 3, 7, 8, 9, 10):
            with self.subTest(role=role):
                self.reject_core(value, snapshot(roles=(role,)))

    def test_shared_limit_maximum_coverage_and_channel_types(self):
        value = p._caps_core(decoded())
        cases = ({'max_interfaces': 1}, {'num_channels': 0}, {'num_channels': True},
            {'limits': ({'max': 1, 'types': (2, 8)},)},
            {'limits': ({'max': 1, 'types': (2,)},)},
            {'limits': ({'max': True, 'types': (2,)}, {'max': 1, 'types': (8,)})},
            {'limits': ({'max': 1, 'types': (2, 8)}, {'max': 1, 'types': (8,)})})
        for changes in cases:
            bad = copy.deepcopy(value)
            fields(bad).update(changes)
            self.reject_core(bad)
        # Shared CLIENT/GO bucket is still one combined limit in minimum-GCD mode.
        self.reject_core(p._caps_core(decoded(bi=1)), snapshot(roles=(9,)))

    def test_software_radar_beacon_and_unknown_constraints_retained(self):
        value = p._caps_core(decoded())
        for changes in ({'radar_widths': 1}, {'radar_regions': 1}, {'beacon_match': True}):
            bad = copy.deepcopy(value)
            fields(bad).update(changes)
            self.reject_core(bad)
        for key, changed in (('software_iftypes', (8,)), ('unknown_constraints', ('future',)),
                             ('iftypes', (2, 3, 9, 10))):
            bad = copy.deepcopy(value)
            bad['phys'][0][key] = changed
            self.reject_core(bad)
        bad = copy.deepcopy(value)
        fields(bad)['future'] = 1
        self.reject_core(bad)

    def test_explicit_bi_requires_both_new_fields_and_strict_types(self):
        value = p._caps_core(decoded())
        for missing in ('bi_policy', 'bi_min_gcd'):
            bad = copy.deepcopy(value)
            del fields(bad)[missing]
            self.reject_core(bad)
        for key in ('max_interfaces', 'radar_widths', 'radar_regions'):
            bad = copy.deepcopy(value)
            fields(bad)[key] = True
            self.reject_core(bad)

    def test_only_two_functions_ast_changed_and_v4_origin_preserved(self):
        pairs = ((PROVIDER_SOURCE, p.__file__, '_caps_core', PROVIDER_PIN),
                 (CORE_SOURCE, c.__file__, 'client_combo', CORE_PIN))
        for original, candidate, changed, pin in pairs:
            self.assertEqual(pin, hashlib.sha256(read(original)).hexdigest())
            trees = [ast.parse(read(path).decode('utf-8')) for path in (original, candidate)]
            for tree in trees:
                tree.body = [node for node in tree.body if not isinstance(node, ast.FunctionDef) or node.name != changed]
            self.assertEqual(ast.dump(trees[0]), ast.dump(trees[1]))
        source = read(p.__file__).decode('utf-8')
        self.assertIn('issued.key() != owned.key()', source)
        self.assertIn('self.provider.delete_client(owned, deadline)', source)

    def test_route_multiplicity_and_journal_cas_stay_unchanged(self):
        functions = {}
        for path in (CORE_SOURCE, c.__file__):
            tree = ast.parse(read(path).decode('utf-8'))
            functions[path] = dict((node.name, ast.dump(node)) for node in tree.body
                                  if isinstance(node, (ast.FunctionDef, ast.ClassDef)))
        for name in ('Snapshot', '_same_journal', '_rows'):
            self.assertEqual(functions[CORE_SOURCE][name], functions[c.__file__][name])

    def test_python35_ast_and_pure_default_constructor(self):
        for path in (p.__file__, c.__file__, __file__):
            ast.parse(read(path).decode('utf-8'), feature_version=(3, 5))
        with mock.patch('os.open', side_effect=AssertionError('OS forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('socket forbidden')), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('process forbidden')), \
                mock.patch('ctypes.CDLL', side_effect=AssertionError('libc forbidden')):
            provider = p.LinuxClientInitProvider()
        self.assertEqual([], provider._ledger.rows)
        self.assertIsNone(provider.manifest)
        self.assertIsNone(provider._owned)
        self.assertIsNone(provider._kernel.row)


if __name__ == '__main__':
    unittest.main()
