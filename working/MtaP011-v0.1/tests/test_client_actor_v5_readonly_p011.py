"""Only the new fixed v5 source binding, not old transport tests or P011."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
PATH = BASE / 'host/client_actor_v5_readonly_p011.py'
spec = importlib.util.spec_from_file_location('actor_v5_readonly_driver', str(PATH))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class ActorV5ReadonlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = d.configured_profile()
        cls.report, cls.rows, cls.native, cls.manifest, cls.ref = cls.profile.source_check()
        cls.source, cls.sha, cls.derived_sha = cls.profile.build_source(
            cls.rows, cls.native, cls.manifest, 'a' * 32, cls.report['driver_sha256'])

    def setUp(self):
        for name in ('socket.socket', 'subprocess.Popen', 'os.kill', 'os.mkdir'):
            patcher = mock.patch(name, side_effect=AssertionError('no device or OS mutation'))
            patcher.start(); self.addCleanup(patcher.stop)

    def test_one_exact_source_override_and_other_eighteen_original_pins(self):
        original = self.ref._module(d.REFERENCE, d.REFERENCE_SHA, 'v5_test_original_reference')
        self.assertEqual(19, len(self.rows))
        self.assertEqual(19, len(original.PINS))
        changed = [(name, old_pin, dict(self.ref.PINS)[name]) for name, old_pin in original.PINS
            if dict(self.ref.PINS)[name] != old_pin]
        self.assertEqual([('mta_client_baseline', 'ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a',
            d.BASELINE_SHA)], changed)
        self.assertEqual(d.BASELINE, self.ref.SOURCE_LOCATIONS['mta_client_baseline'])
        self.assertEqual(original.SOURCE_LOCATIONS, dict(self.ref.SOURCE_LOCATIONS,
            mta_client_baseline=original.SOURCE_LOCATIONS['mta_client_baseline']))
        raw = next(raw for name, pin, raw in self.rows if name == 'mta_client_baseline')
        self.assertEqual(d.BASELINE.read_bytes(), raw)
        self.assertEqual(d.BASELINE_SHA, hashlib.sha256(raw).hexdigest())

    def test_six_notes_reverse_to_exact_actor_v5_predicates(self):
        original = d.BASELINE.read_bytes()
        derived, pin = self.profile.derive_baseline(original)
        text = derived.decode('utf-8')
        for before, after in reversed(self.profile.REPLACEMENTS):
            self.assertEqual(1, text.count(after)); text = text.replace(after, before, 1)
        self.assertEqual(original, text.encode('utf-8'))
        self.assertEqual(self.derived_sha, pin)
        self.assertEqual(6, self.report['site_count'])
        self.assertIn('or not fresh.actor.live() or not actor.live()', text)
        self.assertNotIn('fresh.actor.tasks != actor.tasks', text)

    def test_generated_memory_graph_imports_v5_exact_type_and_raw_state(self):
        values = {}; exec(self.source[:self.source.index(self.profile.TARGET)], values)
        modules = values['modules']; baseline = modules['mta_client_baseline']
        self.assertEqual(19, len(modules))
        self.assertIs(baseline.core, modules['mta_p2p_client_init'])
        self.assertIs(baseline.proc, modules['mta_client_proc'])
        self.assertIs(modules['mta_client_linux_provider'].baseline, baseline)
        actor = baseline.core.Actor(1, 10, '/usr/bin/Z03', 'a' * 64, ((1, 10, 'R'),))
        other = baseline.core.Actor(1, 10, '/usr/bin/Z03', 'a' * 64, ((1, 10, 'S'),))
        self.assertEqual(actor.key(), other.key()); self.assertNotEqual(actor.tasks, other.tasks)
        self.assertNotIn('mta_client_connection', modules)
        ast.parse(self.source, feature_version=(3, 5))
        self.assertLessEqual(len(self.source.encode('utf-8')), 4 * 1024 * 1024)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in self.source.splitlines()), 2048)

    def test_wrapper_identity_fixed_profile_and_readonly_target_unchanged(self):
        self.assertEqual(hashlib.sha256(PATH.read_bytes()).hexdigest(), self.report['driver_sha256'])
        self.assertEqual(d.BASELINE_SHA, self.report['baseline_original_sha256'])
        frozen = self.ref._module(d.PROFILE, d.PROFILE_SHA, 'v5_test_original_profile')
        self.assertEqual(frozen.TARGET, self.profile.TARGET)
        self.assertEqual(frozen.BOOLS, self.profile.BOOLS)
        self.assertEqual(frozen.COUNTS, self.profile.COUNTS)
        self.assertIn('pm._AuthenticatedCollector(p,10)', self.profile.TARGET)
        self.assertIn('provider.snapshot(time.monotonic()+10)', self.profile.TARGET)
        ast.parse(PATH.read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertEqual('8996ae6aa82e48170514f61fc301a83532cf28a20f385153ff41c1e68b236544',
            dict(self.ref.PINS)['mta_client_linux_provider'])

    def test_default_never_executes_and_wrong_pin_stops_before_transport(self):
        with mock.patch.object(self.profile, 'execute', side_effect=AssertionError('no execution')), \
                mock.patch('builtins.print'):
            self.assertEqual(0, d.main([]))
        calls = []
        with self.assertRaisesRegex(ValueError, 'reviewed_or_once'):
            self.profile.execute('0' * 64, _transport_factory=lambda *args: calls.append(args))
        self.assertEqual([], calls); self.assertEqual([], self.profile._ATTEMPTS)


if __name__ == '__main__': unittest.main()
