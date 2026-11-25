"""Only the new v6 wrapper binding; no old transport suite or actual P011."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
PATH = BASE / 'host/client_readparts_v6_readonly_p011.py'
spec = importlib.util.spec_from_file_location('readparts_v6_readonly_driver', str(PATH))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class ReadpartsV6ReadonlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch('socket.socket', side_effect=AssertionError('no actual socket')), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('no actual child')), \
                mock.patch('os.mkdir', side_effect=AssertionError('no actual staging')):
            cls.profile = d.configured_profile()
            cls.report, cls.rows, cls.native, cls.manifest, cls.ref = cls.profile.source_check()
            cls.source, cls.sha, cls.derived_sha = cls.profile.build_source(
                cls.rows, cls.native, cls.manifest, 'a' * 32, cls.report['driver_sha256'])

    def test_exact_wrapper_four_replacements_original_802d_and_python35(self):
        original = (BASE / 'host/client_actor_v5_readonly_p011.py').read_bytes()
        revised = PATH.read_bytes()
        changes = (
            (b'Fixed Actor-v5 readonly baseline', b'Fixed readparts-v6 readonly baseline'),
            (b'candidate/client-actor-v5/runtime/mta_client_baseline.py',
             b'candidate/client-readparts-v6/runtime/mta_client_baseline.py'),
            (b'3e1575d94020bf9e1e54a9fca2ca35876efbcb1385a15dd0bc0bfdf8ac8736ea',
             b'1df29147a9cface972c9a2f486fee45c0f33d7979c6ad49dd02cdc330fe9dcc1'),
            (b'MtaP011-ClientActorV5Readonly-', b'MtaP011-ClientReadpartsV6Readonly-'))
        reverse = revised
        for before, after in changes:
            self.assertEqual(1, reverse.count(after)); reverse = reverse.replace(after, before, 1)
        self.assertEqual(original, reverse)
        self.assertEqual('802d3b93846f0e56e8c0c96469d6fa6a27cd833c1b71c64eeb4eeb1c5bceb4f3', hashlib.sha256(original).hexdigest())
        self.assertEqual(hashlib.sha256(revised).hexdigest(), self.report['driver_sha256'])
        for source in (revised, Path(__file__).read_bytes(), self.source.encode('utf-8')):
            ast.parse(source.decode('utf-8'), feature_version=(3, 5))

    def test_fixed_actual_nineteen_graph_only_new_baseline_and_six_notes_reverse(self):
        original = self.ref._module(d.REFERENCE, d.REFERENCE_SHA, 'readparts_v6_reference_check')
        self.assertEqual(19, len(self.rows)); self.assertEqual(19, len(original.PINS))
        changed = [(name, pin, dict(self.ref.PINS)[name]) for name, pin in original.PINS
            if dict(self.ref.PINS)[name] != pin]
        self.assertEqual([('mta_client_baseline', 'ed41639b1f74c096132a04f9a9a137f2ccc48ddc274c4d3786fe43d718d6c51a', d.BASELINE_SHA)], changed)
        self.assertEqual(d.BASELINE, self.ref.SOURCE_LOCATIONS['mta_client_baseline'])
        self.assertEqual(original.SOURCE_LOCATIONS, dict(self.ref.SOURCE_LOCATIONS,
            mta_client_baseline=original.SOURCE_LOCATIONS['mta_client_baseline']))
        baseline = next(raw for name, pin, raw in self.rows if name == 'mta_client_baseline')
        self.assertEqual(d.BASELINE.read_bytes(), baseline)
        derived, pin = self.profile.derive_baseline(baseline)
        text = derived.decode('utf-8')
        for before, after in reversed(self.profile.REPLACEMENTS):
            self.assertEqual(1, text.count(after)); text = text.replace(after, before, 1)
        self.assertEqual(baseline, text.encode('utf-8'))
        self.assertEqual(pin, self.derived_sha); self.assertEqual(6, self.report['site_count'])
        self.assertEqual(d.BASELINE_SHA, self.report['baseline_original_sha256'])

    def test_memory_exact_modules_readparts_and_readonly_profile_target_unchanged(self):
        with mock.patch('socket.socket', side_effect=AssertionError('no actual socket')), \
                mock.patch('subprocess.Popen', side_effect=AssertionError('no actual child')), \
                mock.patch('os.mkdir', side_effect=AssertionError('no actual staging')):
            values = {}; exec(self.source[:self.source.index(self.profile.TARGET)], values)
        modules = values['modules']; baseline = modules['mta_client_baseline']
        self.assertEqual(19, len(modules))
        self.assertIs(baseline.core, modules['mta_p2p_client_init'])
        self.assertIs(baseline.proc, modules['mta_client_proc'])
        self.assertIs(modules['mta_client_linux_provider'].baseline, baseline)
        self.assertNotIn('mta_client_connection', modules)
        self.assertIn(b"data = b''.join(parts)", d.BASELINE.read_bytes())
        fixed = self.ref._module(d.PROFILE, d.PROFILE_SHA, 'readparts_v6_profile_check')
        self.assertEqual(fixed.TARGET, self.profile.TARGET)
        self.assertEqual(fixed.BOOLS, self.profile.BOOLS); self.assertEqual(fixed.COUNTS, self.profile.COUNTS)
        self.assertIn('pm._AuthenticatedCollector(p,10)', self.profile.TARGET)
        self.assertIn('provider.snapshot(time.monotonic()+10)', self.profile.TARGET)
        self.assertLessEqual(len(self.source.encode('utf-8')), 4 * 1024 * 1024)
        self.assertLessEqual(max(len(line.encode('utf-8')) for line in self.source.splitlines()), 2048)


if __name__ == '__main__': unittest.main()
