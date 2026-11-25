"""New HOST-only parser tests; all observations below are explicit fixtures.

No native helper, radio, device, actor, owner admission or restore is executed.
"""
import copy
import importlib.util
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'runtime' / 'mta_receive_radio_baseline.py'
SPEC = importlib.util.spec_from_file_location('new_radio_observation', str(SOURCE))
radio = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(radio)


def fixture():
    return {'event': 'capabilities', 'radio_schema': radio.SCHEMA,
        'mgmt_info': True, 'features': True, 'bluez_advertising_known': True,
        'adapter_properties_known': True, 'connected_devices_known': True,
        'powered': True, 'bredr_enabled': True, 'le_enabled': True,
        'global_advertising': False, 'bluez_advertising_active': False,
        'connectable_advert': True, 'discovering': False, 'discoverable': False,
        'pairable': True, 'current_settings': 1 | (1 << 7) | (1 << 9),
        'bluez_owner': ':1.12', 'max_adv': 31, 'max_scan': 31,
        'max_instances': 5, 'active_instances': 2,
        'active_instance_ids': [1, 3],
        'connected_devices': ['/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01',
                              '/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02']}


class RadioComparisonTests(unittest.TestCase):
    def test_order_independent_private_data(self):
        before, after = fixture(), fixture()
        after['active_instance_ids'].reverse()
        after['connected_devices'].reverse()
        self.assertTrue(radio.matches(before, after))
        normalized = radio.normalize(before)
        before['active_instance_ids'].append(4)
        self.assertEqual(normalized, radio.normalize(after))

    def test_every_required_field_missing_unknown_or_wrong_type_refuses(self):
        original = fixture()
        for name in tuple(original):
            missing = copy.deepcopy(original)
            del missing[name]
            with self.subTest(field=name):
                self.assertFalse(radio.matches(missing, missing))
        for name in radio._KNOWN_FIELDS:
            for value in (False, None, 0, 1, 'true'):
                mutated = fixture()
                mutated[name] = value
                with self.subTest(field=name, value=value):
                    self.assertFalse(radio.matches(mutated, mutated))
        for name in radio._BOOL_FIELDS:
            for value in (None, 0, 1, 'false'):
                mutated = fixture()
                mutated[name] = value
                self.assertFalse(radio.matches(mutated, mutated))

    def test_ownership_and_full_settings_change_refuse(self):
        original = fixture()
        for name, value in (('bluez_owner', ':1.13'), ('discovering', True),
                ('discoverable', True), ('pairable', False),
                ('active_instance_ids', [1, 4]),
                ('connected_devices', ['/org/bluez/hci0/dev_AA_BB_CC_DD_EE_03']),
                ('current_settings', original['current_settings'] | (1 << 15))):
            changed = fixture()
            changed[name] = value
            with self.subTest(field=name):
                self.assertFalse(radio.matches(original, changed))

    def test_invalid_identity_sets_and_counts_refuse(self):
        original = fixture()
        mutations = [('active_instance_ids', [1, 1]), ('active_instance_ids', [True, 3]),
            ('active_instance_ids', [0, 3]), ('active_instance_ids', [1, 256]),
            ('active_instance_ids', [1, 6]), ('max_instances', 255),
            ('active_instance_ids', [1]), ('active_instance_ids', (1, 3)),
            ('active_instances', True), ('max_instances', 1),
            ('connected_devices', [original['connected_devices'][0]] * 2),
            ('connected_devices', ['/org/bluez/hci1/dev_AA_BB_CC_DD_EE_01']),
            ('connected_devices', ['/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01/extra']),
            ('bluez_owner', 'org.bluez'), ('bluez_owner', ':1.2\n'),
            ('current_settings', True), ('current_settings', -1),
            ('current_settings', 2 ** 32), ('powered', False),
            ('bredr_enabled', False), ('global_advertising', True)]
        for name, value in mutations:
            changed = fixture()
            changed[name] = value
            with self.subTest(field=name, value=value):
                self.assertFalse(radio.matches(changed, changed))

    def test_existing_vendor_resources_are_not_required_to_be_empty(self):
        before = fixture()
        self.assertTrue(radio.matches(before, copy.deepcopy(before)))
        empty = fixture()
        empty['active_instance_ids'] = []
        empty['active_instances'] = 0
        empty['connected_devices'] = []
        self.assertTrue(radio.matches(empty, copy.deepcopy(empty)))
        self.assertFalse(radio.matches(before, empty))
        self.assertFalse(radio.matches({}, {}))


if __name__ == '__main__':
    unittest.main()
