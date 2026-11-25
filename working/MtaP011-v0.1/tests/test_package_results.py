"""HOST-only synthetic whitelist/ZIP tests; never package workspace logs."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'host'))
import package_results as package


PUBLIC_ADDITIONS = {
    'docs/P2P_TRIAL_V2_PLAN.md': 'documents/P2P_TRIAL_V2_PLAN.md',
    'docs/P2P_TRIAL_V3_PLAN.md': 'documents/P2P_TRIAL_V3_PLAN.md',
    'docs/RECEIVE_P2P_PLAN.md': 'documents/RECEIVE_P2P_PLAN.md',
    'native/OWNED_IP_DHCP_NEXT_STAGE.md': 'documents/OWNED_IP_DHCP_NEXT_STAGE.md',
    'native/P2P_V2_REVIEW_NOTES.md': 'documents/P2P_V2_REVIEW_NOTES.md',
    'native/P2P_V2_TRIAL_FAILURE_REVIEW.md': 'documents/P2P_V2_TRIAL_FAILURE_REVIEW.md',
    'native/P2P_V3_DIAGNOSTIC_REVIEW.md': 'documents/P2P_V3_DIAGNOSTIC_REVIEW.md',
    'native/tests/HOST_P2P_V2_EVIDENCE.md': 'native-host/HOST_P2P_V2_EVIDENCE.md',
    'native/tests/HOST_P2P_V3_EVIDENCE.md': 'native-host/HOST_P2P_V3_EVIDENCE.md',
}


class PackageResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mta-host-package-fixture-')
        self.root = Path(self.temp.name)
        self.base = self.root / 'working/MtaP011-v0.1'
        (self.base / 'results').mkdir(parents=True)
        for name in ('README.md', 'GOAL.md', 'CURRENT_STATUS.md'):
            self.write(self.base / name, 'HOST synthetic document\n')
        self.base_patch = mock.patch.object(package, 'BASE', self.base)
        self.root_patch = mock.patch.object(package, 'ROOT', self.root)
        self.base_patch.start()
        self.root_patch.start()

    def tearDown(self):
        self.root_patch.stop()
        self.base_patch.stop()
        self.temp.cleanup()

    def write(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        return path

    def report(self, directory, value, readme=False):
        folder = self.root / 'logs' / directory
        self.write(folder / 'result.json', json.dumps(value))
        if readme:
            self.write(folder / 'README.txt', 'HOST synthetic evidence, not P011 or PHONE\n')
        return folder

    def members(self):
        return {name: path for path, name in package.collect_members()}

    def test_new_documents_are_exact_optional_whitelist(self):
        for source in PUBLIC_ADDITIONS:
            self.write(self.base / source, 'HOST reviewed public fixture\n')
        self.write(self.base / 'docs/PRIVATE_NOT_ALLOWED.md', 'HOST_PRIVATE_MARKER')
        members = self.members()
        self.assertEqual(set(members), set(PUBLIC_ADDITIONS.values()) | {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})
        for source, name in PUBLIC_ADDITIONS.items():
            self.assertEqual(members[name], self.base / source)

    def test_latest_v2_is_separate_from_v1_fail_and_recovery(self):
        self.report('MtaP011-DeviceP2p-20260929-100000-old', {'pass': True})
        v1 = self.report('MtaP011-DeviceP2p-20260930-100000-fail', {'pass': False, 'version': 1})
        recovery = self.report('MtaP011-OwnedStaRecovery-20260930-100100-restored', {'pass': True, 'restore': True})
        self.report('MtaP011-DeviceP2pV2-20261001-010000-old', {'pass': True}, readme=True)
        v2 = self.report('MtaP011-DeviceP2pV2-20261001-020000-latest', {'pass': False, 'version': 2}, readme=True)
        (self.root / 'logs/MtaP011-DeviceP2pV2-20261001-030000-incomplete').mkdir()
        members = self.members()
        self.assertEqual(members['device-p2p/result.json'], v1 / 'result.json')
        self.assertEqual(members['device-owned-cleanup/result.json'], recovery / 'result.json')
        self.assertEqual(members['device-p2p-v2/result.json'], v2 / 'result.json')
        self.assertEqual(members['device-p2p-v2/README.txt'], v2 / 'README.txt')
        self.assertFalse(json.loads(members['device-p2p/result.json'].read_text())['pass'])
        self.assertFalse(json.loads(members['device-p2p-v2/result.json'].read_text())['pass'])

    def test_latest_v3_retains_v1_v2_fail_and_owned_cleanup_separately(self):
        v1 = self.report('MtaP011-DeviceP2p-20260930-100000-fail', {'pass': False, 'version': 1})
        v2 = self.report('MtaP011-DeviceP2pV2-20261001-020000-fail', {'pass': False, 'version': 2}, readme=True)
        recovery = self.report('MtaP011-OwnedStaRecovery-20260930-100100-restored', {'pass': True, 'restore': True})
        self.report('MtaP011-DeviceP2pV3-20261001-030000-old', {'pass': False, 'version': 3}, readme=True)
        v3 = self.report('MtaP011-DeviceP2pV3-20261001-040000-latest', {'pass': False, 'version': 3}, readme=True)
        (self.root / 'logs/MtaP011-DeviceP2pV3-20261001-050000-incomplete').mkdir()
        members = self.members()
        for label, folder in (('device-p2p', v1), ('device-p2p-v2', v2), ('device-p2p-v3', v3)):
            self.assertEqual(members[label + '/result.json'], folder / 'result.json')
            self.assertFalse(json.loads(members[label + '/result.json'].read_text())['pass'])
        self.assertEqual(members['device-p2p-v3/README.txt'], v3 / 'README.txt')
        self.assertEqual(members['device-owned-cleanup/result.json'], recovery / 'result.json')

    def test_v2_v3_never_walk_private_or_unreviewed_siblings(self):
        for version in (2, 3):
            with self.subTest(version=version):
                folder = self.report('MtaP011-DeviceP2pV%d-20261001-020000-latest' % version,
                                     {'pass': False}, readme=True)
                for relative in ('private-raw/result.json', 'private-raw/README.txt',
                                 'private-candidate/manifest.json', 'journal/owned.json',
                                 'candidate/wpa_supplicant', 'binaries/helper',
                                 'extra.json', 'credentials.txt', 'unreviewed.png'):
                    self.write(folder / relative, 'HOST_PRIVATE_MARKER')
                label = 'device-p2p-v%d' % version
                selected = {name: path for name, path in self.members().items()
                            if name.startswith(label + '/')}
                self.assertEqual(set(selected), {label + '/result.json', label + '/README.txt'})
                self.assertTrue(all(path.parent == folder for path in selected.values()))
                self.assertTrue(all(b'HOST_PRIVATE_MARKER' not in path.read_bytes() for path in selected.values()))

    def test_missing_optional_v2_outputs_do_not_create_members(self):
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_latest_v2_missing_public_readme_fails_closed(self):
        self.report('MtaP011-DeviceP2pV2-20261001-010000-old', {'pass': True}, readme=True)
        self.report('MtaP011-DeviceP2pV2-20261001-020000-latest', {'pass': False})
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_latest_v3_missing_public_readme_fails_closed(self):
        self.report('MtaP011-DeviceP2pV3-20261001-030000-old', {'pass': False}, readme=True)
        self.report('MtaP011-DeviceP2pV3-20261001-040000-latest', {'pass': False})
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_existing_member_byte_limit_still_applies(self):
        path = self.base / 'README.md'
        with path.open('wb') as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, 'Evidence byte limit'):
            package.collect_members()

    def test_synthetic_zip_crc_membership_and_every_sha256(self):
        for source in PUBLIC_ADDITIONS:
            self.write(self.base / source, 'HOST public fixture ' + source)
        self.report('MtaP011-DeviceP2p-20260930-100000-fail', {'pass': False, 'version': 1})
        self.report('MtaP011-OwnedStaRecovery-20260930-100100-restored', {'pass': True})
        folder = self.report('MtaP011-DeviceP2pV2-20261001-020000-latest', {'pass': False, 'version': 2}, readme=True)
        self.write(folder / 'private-raw/secret.txt', 'HOST_PRIVATE_MARKER')
        v3 = self.report('MtaP011-DeviceP2pV3-20261001-040000-latest', {'pass': False, 'version': 3}, readme=True)
        self.write(v3 / 'private-candidate/wpa_supplicant', 'HOST_PRIVATE_MARKER')
        expected = self.members()
        with contextlib.redirect_stdout(io.StringIO()):
            package.main()
        bundles = list((self.base / 'results').glob('*.zip'))
        self.assertEqual(len(bundles), 1)
        bundle_path = bundles[0]
        with zipfile.ZipFile(bundle_path) as bundle:
            self.assertIsNone(bundle.testzip())
            manifest = json.loads(bundle.read('MANIFEST.json'))
            self.assertEqual(set(bundle.namelist()), set(expected) | {'MANIFEST.json'})
            self.assertEqual(len(manifest), len(expected))
            self.assertEqual(len({row['name'] for row in manifest}), len(manifest))
            for row in manifest:
                self.assertEqual(set(row), {'name', 'sha256'})
                self.assertEqual(row['sha256'], hashlib.sha256(bundle.read(row['name'])).hexdigest())
                self.assertEqual(bundle.read(row['name']), expected[row['name']].read_bytes())
                self.assertNotIn(b'HOST_PRIVATE_MARKER', bundle.read(row['name']))
        verification = json.loads(bundle_path.with_suffix('.verification.json').read_text())
        self.assertTrue(verification['pass'])
        self.assertTrue(verification['crc_verified'])
        self.assertTrue(verification['sha256_all_members_verified'])
        self.assertEqual(verification['member_count'], len(expected))
        self.assertEqual(verification['zip_sha256'], hashlib.sha256(bundle_path.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
