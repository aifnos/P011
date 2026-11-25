"""New v12 HOST/projection checks only; no device, RF, staging or old suite."""
import ast
from collections import namedtuple
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


driver = load('isolated_client_diagnostic_v12_host', BASE / 'host/client_init_diagnostic_v12_p011.py')
previous = load('isolated_client_diagnostic_v12_previous', BASE / 'host/client_init_tmp_alias_v11_p011.py')
ip = load('isolated_client_diagnostic_v12_ip', BASE / 'runtime/mta_ip.py')
scope = {'modules': {'mta_ip': ip}}
exec(driver._PROJECTION_NEW, scope)
project = scope['projection']


class DiagnosticHostTests(unittest.TestCase):
    def test_frozen_graph_replaces_only_three_existing_sources(self):
        self.assertTrue(driver._FROZEN)
        self.assertEqual(len(driver.PINS), 20)
        self.assertEqual(tuple(name for name, pin in driver.PINS),
                         tuple(name for name, pin in previous.PINS))
        changed = {name for (name, pin), (_, old) in zip(driver.PINS, previous.PINS) if pin != old}
        self.assertEqual(changed, set(driver._DIAGNOSTIC_PINS))
        self.assertEqual(hashlib.sha256(driver._V11_RAW).hexdigest(), driver._V11_SHA)
        self.assertEqual(driver._STAGE_OWNER, previous._STAGE_OWNER)
        self.assertEqual(driver.LOADER, previous.LOADER)

    def test_actual_pc_graph_and_built_source_have_new_identity(self):
        report, rows, native, manifest, legacy = driver.source_check()
        self.assertTrue(report['source_check_pass'])
        self.assertEqual(report['source_count'], 20)
        self.assertEqual(tuple((name, pin) for name, pin, raw in rows), driver.PINS)
        source, candidate_sha = driver.build_source(rows, native, manifest, 'a' * 32, report['driver_sha256'])
        tree = ast.parse(source, feature_version=(3, 5))
        literals = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'CANDIDATE'}
        self.assertEqual(literals['CANDIDATE']['kind'], 'client-init-diagnostic-v12')
        self.assertEqual(len(candidate_sha), 64)
        self.assertIn("pm=modules['mta_client_linux_provider']", source)
        self.assertFalse(report['send_available'])
        self.assertFalse(report['receive_available'])
        self.assertFalse(report['phone_tested'])

    def test_target_except_projection_is_exact_previous(self):
        self.assertEqual(driver.TARGET.count(driver._PROJECTION_NEW), 1)
        self.assertEqual(driver.TARGET.replace(driver._PROJECTION_NEW, driver._PROJECTION_OLD, 1), previous.TARGET)
        self.assertEqual(driver.HostAdbCall.run.__code__.co_consts, previous.HostAdbCall.run.__code__.co_consts)
        self.assertEqual(driver.parse.__code__.co_consts, previous.parse.__code__.co_consts)

    def test_nonempty_ipv4_preserves_every_named_record_field(self):
        address = ip.AddressRecord(7, 1, 2, 24, 128, 0, 'synthetic', 3, (4, 5, 6, 7))
        route = ip.RouteRecord(8, 24, 254, 4, 0, 1, 0, 7, 9, 10, 1, ((2, 3),))
        rule = ip.RuleRecord(32766, 254)
        snapshot = ip.IpSnapshot((address,), (route,), (rule,))
        value = project(snapshot)
        self.assertEqual(set(value), {'addresses', 'routes', 'rules'})
        self.assertEqual(value['addresses'][0], dict(zip(address._fields, address)))
        self.assertEqual(value['routes'][0], dict(zip(route._fields, route)))
        self.assertEqual(value['rules'][0], {'priority': 32766, 'table': 254})
        self.assertEqual(len(json.loads(json.dumps(value))['addresses']), 1)

    def test_empty_ipv4_remains_explicit_three_empty_collections(self):
        self.assertEqual(project(ip.IpSnapshot((), (), ())), {'addresses': (), 'routes': (), 'rules': ()})
        self.assertEqual(json.loads(json.dumps(project(ip.IpSnapshot((), (), ())))),
                         {'addresses': [], 'routes': [], 'rules': []})

    def test_unknown_namedtuple_and_subclass_do_not_gain_schema(self):
        class Deceptive(namedtuple('_Unknown', 'secret')):
            __slots__ = ()
            def _asdict(self): raise AssertionError('never invoke')
        class Derived(ip.RuleRecord):
            __slots__ = ()
            def _asdict(self): raise AssertionError('never invoke')
        self.assertEqual(project(Deceptive('PRIVATE')), {})
        self.assertEqual(project(Derived(1, 2)), {})
        self.assertNotIn('PRIVATE', json.dumps(project(Deceptive('PRIVATE'))))

    def test_existing_private_projection_cases_preserved(self):
        namespace = {}
        exec(driver._PROJECTION_OLD, namespace)
        old = namespace['projection']
        class Holder:
            __slots__ = ('field', '_private')
        holder = Holder(); holder.field = (1, 'fixture'); holder._private = 'PRIVATE'
        for value in (None, 0, True, 1.25, 'fixture', b'fixture', [1, 2], {'a': (1, 2)}, holder, object()):
            self.assertEqual(project(value), old(value))

    def test_unfrozen_source_blocks_execute_before_transport(self):
        calls = []
        with mock.patch.object(driver, '_FROZEN', False):
            report = driver.source_check()[0]
            self.assertFalse(report['source_check_pass'])
            with self.assertRaisesRegex(ValueError, 'unavailable_or_reviewed'):
                driver.execute(report['driver_sha256'], _transport_factory=lambda *a: calls.append(a))
        self.assertEqual(calls, [])
        self.assertEqual(driver._ATTEMPTS, [])


if __name__ == '__main__': unittest.main()
