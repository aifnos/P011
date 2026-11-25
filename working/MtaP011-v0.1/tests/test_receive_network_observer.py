"""New HOST DATA/provenance models, not ARM, D-Bus or P011 evidence."""
import copy
import importlib.util
from pathlib import Path
import sys
import time
import unittest


BASE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.modules['p011_json'] = load('p011_json', BASE / 'runtime/p011_json.py')
network = load('_new_network_observer_under_test', BASE / 'runtime/mta_receive_network.py')


def wrapped(value=None, present=False):
    return {'present': present, 'value': value}


def fixture():
    # Synthetic identities intentionally do not identify any real device.
    return {'event': 'network_observation', 'network_schema': network.SCHEMA,
        'ok': True, 'identity_known': True, 'technologies_known': True,
        'services_known': True, 'bus_closed': True, 'proc_files_closed': True,
        'profile_bytes_observed': False, 'reason': 'ok',
        'connman_owner': ':1.999', 'connman_pid': 999, 'connman_start': 1000,
        'boot_id': '00000000-0000-0000-0000-000000000001',
        'connman_exe': '/usr/sbin/connmand', 'connman_exe_sha256': 'a'*64,
        'technologies': [{'path': '/net/connman/technology/wifi', 'powered': True}],
        'services': [{'path': '/net/connman/service/wifi_MODEL_managed_psk',
            'state': 'ready', 'auto_connect': wrapped(True, True),
            'favorite': wrapped(True, True), 'immutable': wrapped(False, True),
            'ipv4': wrapped({'Method': 'dhcp', 'Address': '192.0.2.2'}, True),
            'ipv6': wrapped({}, True), 'ipv4_configuration': wrapped({}, True),
            'ipv6_configuration': wrapped(),
            'nameservers': wrapped(['192.0.2.1', '192.0.2.3'], True),
            'nameservers_configuration': wrapped([], True)}]}


class ReceiveNetworkObserverTests(unittest.TestCase):
    def test_data_presence_and_empty_are_not_unknown(self):
        source = fixture()
        self.assertEqual(network.normalize(source), network.normalize(copy.deepcopy(source)))
        changed = copy.deepcopy(source)
        changed['services'][0]['ipv6'] = wrapped()
        self.assertNotEqual(network.normalize(source), network.normalize(changed))
        for field in ('ok', 'identity_known', 'technologies_known', 'services_known',
                      'bus_closed', 'proc_files_closed'):
            with self.subTest(field=field):
                bad = copy.deepcopy(source)
                bad[field] = False
                with self.assertRaises(network.NetworkObservationError):
                    network.normalize(bad)
                del bad[field]
                with self.assertRaises(network.NetworkObservationError):
                    network.normalize(bad)

    def test_same_counts_do_not_hide_changed_owner_service_or_configuration(self):
        source = fixture()
        for field, value in (('connman_owner', ':1.998'), ('connman_pid', 998),
                              ('connman_start', 1001), ('connman_exe_sha256', 'b'*64)):
            changed = copy.deepcopy(source)
            changed[field] = value
            self.assertNotEqual(network.normalize(source), network.normalize(changed))
        for field, value in (('path', '/net/connman/service/wifi_OTHER_managed_psk'),
                              ('state', 'online'), ('auto_connect', wrapped(False, True)),
                              ('ipv4', wrapped({'Method': 'dhcp', 'Address': '192.0.2.4'}, True)),
                              ('nameservers', wrapped(['192.0.2.3', '192.0.2.1'], True))):
            changed = copy.deepcopy(source)
            changed['services'][0][field] = value
            self.assertNotEqual(network.normalize(source), network.normalize(changed))

    def test_strict_shapes_boolean_numeric_unknown_and_duplicates(self):
        source = fixture()
        bad_rows = []
        for field, value in (('connman_pid', True), ('connman_start', 0),
                              ('services', None), ('technologies', None),
                              ('profile_bytes_observed', True)):
            bad = copy.deepcopy(source); bad[field] = value; bad_rows.append(bad)
        for field, value in (('favorite', wrapped(1, True)),
                              ('ipv4', wrapped({'Unexpected': ''}, True)),
                              ('ipv6', wrapped({'PrefixLength': True}, True)),
                              ('immutable', wrapped(False, False)),
                              ('nameservers', wrapped(None, True))):
            bad = copy.deepcopy(source); bad['services'][0][field] = value; bad_rows.append(bad)
        for collection in ('technologies', 'services'):
            bad = copy.deepcopy(source); bad[collection].append(copy.deepcopy(bad[collection][0])); bad_rows.append(bad)
        bad = copy.deepcopy(source); del bad['services'][0]['ipv4_configuration']; bad_rows.append(bad)
        for number, bad in enumerate(bad_rows):
            with self.subTest(number=number):
                with self.assertRaises(network.NetworkObservationError):
                    network.normalize(bad)

    def test_bundled_codec_rejects_duplicate_and_trailing_json(self):
        codec = sys.modules['p011_json']
        for raw in ('{"ok":true,"ok":true}', '{"ok":true} {}', '{"ok":NaN}'):
            with self.assertRaises(ValueError):
                codec.loads(raw)

    def test_original_closed_calls_required_not_dict_or_repeated_call(self):
        owner = network.NetworkObserver('/private/model-observer', 64, 'a'*64, 99999.0)
        a, b = (network.NetworkObservation(owner, float(n)) for n in (1, 2))
        owner._calls.extend((a, b))
        for row in (a, b):
            row._ticket['finished'] = True
            row.valid = True
            row.baseline = network.normalize(fixture())
        self.assertTrue(network.compare_observations(a, b))  # Explicit DATA/receipt model.
        self.assertFalse(network.compare_observations(a, a))
        self.assertFalse(network.compare_observations(fixture(), fixture()))
        b._ticket['spawn_called'] = True
        self.assertFalse(network.compare_observations(a, b))
        b._ticket['spawn_called'] = False
        b._ticket['close_error'] = True
        self.assertFalse(network.compare_observations(a, b))
        b._ticket['close_error'] = False
        owner._active = True
        self.assertFalse(network.compare_observations(a, b))
        owner._active = False
        other = network.NetworkObserver('/private/model-observer', 64, 'a'*64, 99999.0)
        b._owner = other
        self.assertFalse(network.compare_observations(a, b))

    def test_constructor_is_pure_and_partial_early_fail_is_retained(self):
        bare = network.NetworkObserver.__new__(network.NetworkObserver)
        self.assertFalse(bare.resources_closed())
        with self.assertRaises(network.NetworkObservationError):
            bare.__init__('not-an-absolute-path', 64, 'a'*64, 99999.0)
        self.assertTrue(bare.resources_closed())
        self.assertTrue(bare.close())
        self.assertFalse(bare._initialized)

    def test_bad_phase_is_recorded_before_clock_or_target_io(self):
        def forbidden_clock():
            self.fail('No clock or IO permitted for invalid phase')
        owner = network.NetworkObserver('/private/model-observer', 64, 'a'*64, 99999.0,
                                       clock=forbidden_clock)
        for phase in (None, True, float('nan'), 100000.0):
            row = owner.observe(phase)
            self.assertIs(row._owner, owner)
            self.assertIn(row, owner._calls)
            self.assertFalse(row.valid)
            self.assertEqual(row.error, 'observer_deadline')
            self.assertTrue(row.resources_closed())
            self.assertFalse(row._ticket['fd_open_called'])
            self.assertFalse(row._ticket['spawn_called'])
        self.assertTrue(owner.resources_closed())


if __name__ == '__main__':
    unittest.main()
