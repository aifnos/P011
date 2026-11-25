"""Four new v20 HOST methods; actual pinned definitions, no TARGET execution."""
import ast
import base64
from collections import namedtuple
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
PATH = BASE / 'host/client_readonly_ipv4_v20_p011.py'
spec = importlib.util.spec_from_file_location('readonly_ipv4_v20_host', str(PATH))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


def tripwires():
    stack = ExitStack()
    for name in ('os.open', 'os.mkdir', 'os.unlink', 'os.rename', 'os.kill', 'os.system',
            'socket.socket', 'subprocess.Popen', 'subprocess.run', 'subprocess.call',
            'subprocess.check_call', 'subprocess.check_output'):
        stack.enter_context(mock.patch(name, side_effect=AssertionError('no actual OS/ADB/RF')))
    return stack


class ReadonlyIpv4V20Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tripwires():
            cls.profile = d.configured_profile()
            cls.checked = cls.profile.source_check()
            cls.report, cls.rows, cls.native, cls.manifest, cls.ref = cls.checked
            cls.source, cls.candidate_sha, cls.derived_sha = cls.profile.build_source(
                cls.rows, cls.native, cls.manifest, 'a' * 32, cls.report['driver_sha256'])
            cls.prefix = cls.source[:cls.source.index(cls.profile.TARGET)]
            cls.values = {}; exec(cls.prefix, cls.values)
            exec(d._V17._INJECTION, cls.values)
            cls.ip = cls.values['modules']['mta_ip']
            target_tree = ast.parse(cls.profile.TARGET, feature_version=(3, 5))
            node = next(n for n in target_tree.body
                if isinstance(n, ast.FunctionDef) and n.name == 'projection')
            scope = {'modules': cls.values['modules'], 'hashlib': hashlib, 'base64': base64,
                'fail': lambda reason: (_ for _ in ()).throw(ValueError(reason))}
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<v20-projection-only>', 'exec'), scope)
            cls.project = staticmethod(scope['projection'])

    def setUp(self):
        self.enterContext(tripwires())

    def fixture(self):
        address = self.ip.AddressRecord(7, 1, 2, 24, 128, 0, b'fixture\0', 3, (4, 5, 6, 7))
        route = self.ip.RouteRecord(8, 24, 254, 4, 0, 1, 0, 7, 9, 10, 1, ((2, 3),))
        rule = self.ip.RuleRecord(32766, 254)
        return self.ip.IpSnapshot((address,), (route,), (rule,))

    def test_full_target_reverse_ast_frozen_labels_and_python35(self):
        self.assertEqual(d.V17_SHA, hashlib.sha256(d.V17.read_bytes()).hexdigest())
        self.assertEqual(d.PROFILE_SHA, hashlib.sha256(d.PROFILE.read_bytes()).hexdigest())
        original = self.profile.TARGET.replace(d._IPV4_PROJECTION, '', 1)
        self.assertEqual(1, self.profile.TARGET.count(d._IPV4_PROJECTION))
        self.assertEqual(d._derive_target(original), self.profile.TARGET)
        fixed = ast.literal_eval(next(n.value for n in ast.parse(d.PROFILE.read_text()).body
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'TARGET' for t in n.targets)))
        self.assertEqual(fixed, original.replace(d._V17._INJECTION, '', 1).replace(d._V17._PROJECTION, '', 1))
        with self.assertRaisesRegex(ValueError, 'projection_fragment'):
            d._derive_target(original + d._TUPLE_ANCHOR)
        with self.assertRaisesRegex(ValueError, 'projection_fragment'):
            d._derive_target(self.profile.TARGET)
        old_tree = ast.parse(original, feature_version=(3, 5))
        new_tree = ast.parse(self.profile.TARGET, feature_version=(3, 5))
        body = d._projection_node(new_tree).body
        insertion = ast.parse('def projection(value):\n' + d._IPV4_PROJECTION).body[0].body
        at = next(i for i in range(len(body)) if ast.dump(body[i]) == ast.dump(insertion[0]))
        del body[at:at + 2]
        self.assertEqual(ast.dump(old_tree), ast.dump(new_tree))
        raw = d.PROFILE.read_bytes()
        holder = types.ModuleType('labels_only'); holder.__dict__.update(self.profile.__dict__)
        d._label_definition(holder, raw, 'build_source', (
            ('client-v3-baseline-readonly-performance', 'client-readonly-ipv4-v20'),))
        self.assertEqual(holder.build_source.__code__.co_consts, self.profile.build_source.__code__.co_consts)
        self.assertIn('P011_READONLY_IPV4_V20', self.profile.execute.__code__.co_consts)
        self.assertEqual(self.derived_sha, '4270852f4a7719fa663067e407acde800ae84da4b3ed7ab7fbeb6e9e0e0c9c20')
        for raw in (PATH.read_bytes(), Path(__file__).read_bytes(), self.source.encode('utf-8')):
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        self.assertLessEqual(len(self.source.encode('utf-8')), 4 * 1024 * 1024)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in self.source.splitlines()), 2048)

    def test_actual_nineteen_source_graph_loader_identity_and_v17_notes_retained(self):
        modules = self.values['modules']
        self.assertEqual(19, len(self.rows)); self.assertEqual(19, len(modules))
        self.assertEqual(self.ref.PINS, tuple((name, pin) for name, pin, raw in self.rows))
        self.assertEqual(self.ref.PINS, self.values['PINS'])
        self.assertEqual(dict((name, raw) for name, pin, raw in self.rows), self.values['payloads'])
        for name, pin, raw in self.rows:
            self.assertEqual(pin, hashlib.sha256(raw).hexdigest())
        self.assertIs(modules['mta_client_baseline'].ip, self.ip)
        self.assertIs(modules['mta_client_linux_provider'].baseline, modules['mta_client_baseline'])
        self.assertIs(modules['mta_client_linux_provider'].original_status, modules['mta_client_wpa_status'])
        self.assertIs(modules['mta_client_wpa_status'].LinuxStatusSource.read_source,
            modules['mta_client_wpa_status']._v17_read_source)
        self.assertEqual(1, self.profile.TARGET.count(d._V17._PROJECTION))
        self.assertEqual(1, self.profile.TARGET.count(d._V17._INJECTION))
        frozen_loader = ast.literal_eval(next(n.value for n in ast.parse(
            (BASE / 'host/client_init_baseline_v3_p011.py').read_text()).body
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'LOADER' for t in n.targets)))
        self.assertEqual(frozen_loader, self.ref.LOADER)
        self.assertEqual(hashlib.sha256(PATH.read_bytes()).hexdigest(), self.report['driver_sha256'])
        self.assertEqual('source_only', self.report['stage']); self.assertEqual(19, self.report['source_count'])

    def test_nonempty_nested_ipv4_exact_fields_bytes_elf_and_no_generic_asdict(self):
        snapshot = self.fixture(); projected = self.project(snapshot)
        self.assertEqual({'addresses', 'routes', 'rules'}, set(projected))
        self.assertEqual({'ifindex': 7, 'local': 1, 'address': 2, 'prefixlen': 24, 'flags': 128,
            'scope': 0, 'label': {'bytes_b64': base64.b64encode(b'fixture\0').decode('ascii'), 'length': 8},
            'broadcast': 3, 'cacheinfo': (4, 5, 6, 7)}, projected['addresses'][0])
        self.assertEqual(dict(zip(snapshot.routes[0]._fields, snapshot.routes[0])), projected['routes'][0])
        self.assertEqual({'priority': 32766, 'table': 254}, projected['rules'][0])
        nested = self.project({'rounds': ({'ipv4': snapshot}, {'ipv4': snapshot}), 'snapshot': {'ipv4': snapshot}})
        self.assertEqual(projected, nested['rounds'][0]['ipv4'])
        self.assertEqual(projected, nested['rounds'][1]['ipv4'])
        self.assertEqual(projected, nested['snapshot']['ipv4'])
        self.assertEqual({'addresses': (), 'routes': (), 'rules': ()}, self.project(self.ip.IpSnapshot((), (), ())))
        self.assertEqual(7, json.loads(json.dumps(nested))['snapshot']['ipv4']['addresses'][0]['ifindex'])
        class Deceptive(namedtuple('_Unknown', 'secret')):
            __slots__ = ()
            def _asdict(self): raise AssertionError('never invoke generic _asdict')
        class Derived(self.ip.RuleRecord):
            __slots__ = ()
            def _asdict(self): raise AssertionError('never invoke subclass _asdict')
        with mock.patch.object(self.ip.RuleRecord, '_asdict', side_effect=AssertionError('never invoke exact _asdict')):
            self.assertEqual({'priority': 1, 'table': 2}, self.project(self.ip.RuleRecord(1, 2)))
            self.assertEqual({}, self.project(Deceptive('PRIVATE')))
            self.assertEqual({}, self.project(Derived(1, 2)))
        class Holder(object):
            __slots__ = ('field', '_private')
        holder = Holder(); holder.field = (1, 'fixture'); holder._private = 'PRIVATE'
        self.assertEqual({'field': (1, 'fixture')}, self.project(holder))
        self.assertEqual((1, 2), self.project([1, 2]))
        elf = b'\x7fELFfixture'
        self.assertEqual({'binary_digest': hashlib.sha256(elf).hexdigest(), 'length': len(elf)}, self.project(elf))
        with self.assertRaisesRegex(ValueError, 'inventory_unknown'): self.project(object())

    def test_public_schema_capabilities_false_default_and_explicit_guard_no_transport(self):
        public = dict((k, False) for k in self.profile.BOOLS); public.update((k, 0) for k in self.profile.COUNTS)
        public.update(source_check_pass=True, resource_pending=True, stage='baseline_before',
            reason='baseline_failed', failure_site='not_recorded')
        private = {'snapshot': {'ipv4': self.project(self.fixture())}, 'source_first_failures': ({'errno': 2},)}
        def frame(value):
            return {'stdout': ('RESULT=' + repr({'public': value, 'private': private}) +
                '\nMTA_REMOTE_OK\nMTA_REMOTE_EXIT=0\n').encode('utf-8'), 'stderr': b'', 'host_exit': 0}
        result = self.profile.parse(frame(public))
        self.assertEqual(public, result['public']); self.assertEqual(private, result['private'])
        self.assertTrue(result['public']['resource_pending']); self.assertFalse(result['public']['diagnostic_complete'])
        for key in ('staging_attempted', 'rf_requested', 'restoration_verified', 'send_available', 'receive_available', 'phone_tested'):
            with self.subTest(key=key):
                self.assertFalse(result['public'][key])
                with self.assertRaisesRegex(ValueError, 'public_shape'): self.profile.parse(frame(dict(public, **{key: True})))
        with self.assertRaisesRegex(ValueError, 'public_shape'): self.profile.parse(frame(dict(public, ipv4={})))
        transport = mock.Mock(side_effect=AssertionError('no transport'))
        with self.assertRaisesRegex(ValueError, 'reviewed_or_once'):
            self.profile.execute('0' * 64, _check=lambda: self.checked, _transport_factory=transport)
        transport.assert_not_called(); self.assertEqual([], self.profile._ATTEMPTS)
        fake = types.SimpleNamespace(source_check=lambda: ({'source_check_pass': True},), execute=transport)
        with mock.patch.object(d, 'configured_profile', return_value=fake), mock.patch('builtins.print'):
            self.assertEqual(0, d.main([]))
            with mock.patch('sys.stderr'):
                with self.assertRaises(SystemExit) as missing: d.main(['--execute-readonly'])
                self.assertEqual(2, missing.exception.code)
                with self.assertRaises(SystemExit) as extra: d.main(['--expected-driver-sha256', '0' * 64])
                self.assertEqual(2, extra.exception.code)
        transport.assert_not_called()
        execute_text = d._definition(d.PROFILE.read_bytes(), 'execute')
        self.assertIn("for key in ('result.json','README.txt'):bundle.write(output/key,key)", execute_text)


if __name__ == '__main__': unittest.main()
