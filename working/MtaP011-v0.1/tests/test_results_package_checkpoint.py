"""HOST synthetic whitelist checks, not device or phone acceptance."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'host'))
import package_results as package


class CheckpointPackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mta-host-checkpoint-')
        self.root = Path(self.tmp.name)
        self.base = self.root / 'working/MtaP011-v0.1'
        (self.base / 'results').mkdir(parents=True)
        for name in ('README.md', 'GOAL.md', 'CURRENT_STATUS.md'):
            self.write(self.base / name, 'HOST synthetic document')
        self.patches = [mock.patch.object(package, 'BASE', self.base),
                        mock.patch.object(package, 'ROOT', self.root)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.tmp.cleanup()

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding='utf-8')
        return path

    def members(self):
        return dict((name, path) for path, name in package.collect_members())

    def failed_host(self, companion=True):
        folder = self.base / 'results/host-20261001-063809-641096'
        value = {'evidence_level': 'HOST_ONLY', 'pass': False, 'tests': 729,
                 'failures': 0, 'errors': 4, 'skipped': 33,
                 'device_runtime': 'NOT_EVALUATED', 'phone_interop': 'NOT_TESTED'}
        self.write(folder / 'result.json', json.dumps(value))
        if companion:
            self.write(folder / 'unittest.txt', 'HOST ImportError: No module named tests\n')
        return folder, value

    def test_exact_durable_linux_and_no_target_failure_keep_real_synthetic_scope(self):
        records = (
            (self.base / 'results/client-durable-linux-host-review-20261001',
             'host-client-durable-linux-review',
             {'fake_test_batches': [{'methods': 20, 'passed': 16, 'failures': 4},
                                   {'methods': 4, 'passed': 4}], 'project_full_suite_rerun': False}),
            (self.base / 'results/client-durable-store-linux-host-20261001-093144-3f5db4906e3669e7',
             'host-linux-client-durable-store',
             {'pass': True, 'component_fd_count': 92, 'setup_fd_count': 7,
              'synthetic_stock_network_baseline': True, 'synthetic_restore_producer': True,
              'production_provider': False, 'p011_tested': False, 'phone_tested': False, 'rf': False}),
            (self.root / 'logs/MtaP011-WpaCliFileOnly-20261001-172839-376481',
             'device-file-only-target-selection-failure',
             {'pass': False, 'device_command_sent': False, 'remote_exit': None,
              'wpa_cli_sha256': None, 'raw_enumeration_retained': False, 'reboot': False}))
        for folder, label, value in records:
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / 'README.txt', 'HOST whitelist fixture, scope preserved')
            self.write(folder / 'private-raw/observations.json', 'HOST_PRIVATE')
            future = folder.with_name(folder.name + '-future')
            self.write(future / 'result.json', '{"pass": true}')
            self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        document = self.write(self.base / 'docs/CLIENT_DURABLE_STORE_LINUX_CHECK_REVIEW.md', 'HOST reviewed isolated scope')
        members = self.members()
        self.assertEqual(document, members['documents/CLIENT_DURABLE_STORE_LINUX_CHECK_REVIEW.md'])
        for folder, label, value in records:
            chosen = {name: path for name, path in members.items() if name.startswith(label + '/')}
            self.assertEqual(chosen, {label + '/' + name: folder / name for name in ('result.json', 'README.txt')})
            self.assertEqual(json.loads(chosen[label + '/result.json'].read_text()), value)

    def test_original_import_failure_retained_beside_latest_host_pass(self):
        folder, value = self.failed_host()
        latest = self.base / 'results/host-20261001-063938-580208'
        self.write(latest / 'result.json', json.dumps({'pass': True, 'tests': 777}))
        self.write(latest / 'unittest.txt', 'HOST successful later integration\n')
        members = self.members()
        prefix = 'host-direct-entry-import-failure/'
        self.assertEqual({name: path for name, path in members.items() if name.startswith(prefix)},
                         {prefix + name: folder / name for name in ('result.json', 'unittest.txt')})
        self.assertEqual(json.loads(members[prefix + 'result.json'].read_text()), value)
        self.assertIs(json.loads(members['host/result.json'].read_text())['pass'], True)

    def test_exact_launch_composition_and_adb_reconnect_keep_private_and_scope_separate(self):
        records = (
            (self.base / 'results/client-launch-registration-host-review-20261001',
             'host-client-launch-registration-review',
             {'actual_linux_c': False, 'production_provider': False, 'test_batches': [{'host_exit': 1}, {'host_exit': 0}]}),
            (self.base / 'results/client-launch-linux-host-review-20261001',
             'host-client-launch-linux-review',
             {'distinct_current_named_methods': 25, 'final_source_whole_suite_rerun': False, 'production_provider': False}),
            (self.base / 'results/client-launch-linux-host-20261001-102942-b9fadf630b752bc8',
             'host-linux-client-launch-registration',
             {'pass': True, 'child_fd_count': 18, 'sidecar_fd_count': 12, 'component_fd_count': 89,
              'synthetic_restore_producer': True, 'p011_tested': False, 'phone_tested': False, 'rf': False}),
            (self.base / 'results/host-adb-enumeration-only-20261001-181513',
             'host-adb-enumeration-only',
             {'identified_ready_p011_count': 0, 'remote_command_sent': False, 'exact_p011_identity_established': False}),
            (self.root / 'logs/MtaP011-WpaCliFileOnly-20261001-182506-877184',
             'device-file-only-identified-ready',
             {'pass': True, 'stock_file_hashes_match': True, 'wpa_cli_executed': False,
              'network_operations': False, 'baseline_collector_executed': False}))
        for folder, label, value in records:
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / 'README.txt', 'HOST whitelist fixture; physical levels separate')
            self.write(folder / 'private-raw/observations.json', 'HOST_PRIVATE')
            future = folder.with_name(folder.name + '-future')
            self.write(future / 'result.json', '{"phone_tested": true}')
            self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        documents = ('CLIENT_LAUNCH_REGISTRATION_REVIEW.md',
                     'CLIENT_LAUNCH_REGISTRATION_LINUX_CHECK_REVIEW.md', 'CLIENT_WPA_STATUS_AUTH_NEXT.md')
        for name in documents:
            self.write(self.base / 'docs' / name, 'HOST reviewed source or explicit plan, not RF')
            self.write(self.base / 'docs' / (name + '.future'), 'HOST_UNREVIEWED')
        members = self.members()
        for folder, label, value in records:
            chosen = {name: path for name, path in members.items() if name.startswith(label + '/')}
            self.assertEqual(chosen, {label + '/' + name: folder / name for name in ('result.json', 'README.txt')})
            self.assertEqual(json.loads(chosen[label + '/result.json'].read_text()), value)
            self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                                 for path in chosen.values()))
        for name in documents:
            self.assertEqual(self.base / 'docs' / name, members['documents/' + name])

    def test_host_diagnostic_prefix_cannot_replace_timestamped_integration_report(self):
        integration = self.base / 'results/host-20261001-091512-316513'
        self.write(integration / 'result.json', '{"tests": 1322, "pass": true}')
        self.write(integration / 'unittest.txt', 'HOST integration historical run')
        for name in ('host-pnp-sprd-readonly-20261001', 'host-adb-enumeration-only-20990101',
                     'host-20261001-091512-316513-unreviewed'):
            folder = self.base / 'results' / name
            self.write(folder / 'result.json', '{"pass": true, "scope": "not_integration"}')
        members = self.members()
        self.assertEqual(integration / 'result.json', members['host/result.json'])
        self.assertEqual(integration / 'unittest.txt', members['host/unittest.txt'])

    def test_fixed_failure_excludes_source_raw_and_future_substitution(self):
        folder, _ = self.failed_host()
        for relative in ('private-raw/result.json', 'stdout.raw', 'source/runner.py'):
            self.write(folder / relative, 'HOST_UNREVIEWED')
        self.write(self.base / 'results/host-20261001-063809-641096-future/result.json', '{}')
        self.write(self.base / 'results/host-20261001-063809-641096-future/unittest.txt', 'HOST latest fixture')
        prefix = 'host-direct-entry-import-failure/'
        selected = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(set(selected), {prefix + 'result.json', prefix + 'unittest.txt'})
        self.assertTrue(all(b'HOST_UNREVIEWED' not in path.read_bytes() for path in selected.values()))

    def test_fixed_failure_missing_companion_fails_closed(self):
        folder, _ = self.failed_host(companion=False)
        self.write(folder / 'private-raw/unittest.txt', 'HOST_PRIVATE')
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_reviews_only_exact_optional_documents(self):
        for name in ('P2P_IP_V7_L3_DIAG_REVIEW.md', 'DHCP_CLIENT_CORE_REVIEW.md',
                     'P2P_TRIAL_V7_L3_PLAN.md', 'TRANSFER_SESSION_REVIEW.md',
                     'UDP_LOOPBACK_REVIEW.md', 'P2P_IP_V8_ROUTE_DIAG_REVIEW.md',
                     'P2P_TRIAL_V8_ROUTE_PLAN.md', 'DHCP_CLIENT_SOCKET_REVIEW.md',
                     'P2P_IP_V9_MROUTE_REVIEW.md', 'P2P_CLIENT_NATIVE_NEXT_REVIEW.md',
                     'STATE_SESSION_INTEGRATION_REVIEW.md', 'P2P_TRIAL_V9_MROUTE_PLAN.md',
                     'P2P_V9_PREFLIGHT_TIMEOUT_REVIEW.md', 'P2P_CLIENT_CTRL_REVIEW.md',
                     'TTY_ACTOR_READONLY_REVIEW.md', 'P2P_TRIAL_V9_BOUNDED_PLAN.md',
                     'P2P_CLIENT_INIT_OWNER_PLAN.md', 'STATE_DEVICE_SMOKE_NEXT_REVIEW.md',
                     'IP_RECEIPT_RECOVERY_REVIEW.md', 'P2P_V9_RESTORE_READONLY_REVIEW.md',
                     'P2P_V9_091400_FAILURE_ANALYSIS.md', 'P2P_V9_CURRENT_TRIAGE_REVIEW.md',
                     'STATE_SMOKE_READONLY_ENTRY_REVIEW.md', 'LATEST_CHECKPOINT.md',
                     'CLIENT_CAPS_DECODER_REVIEW.md', 'STATE_SMOKE_OBSERVER_REVIEW.md',
                     'P2P_CLIENT_INIT_IMPLEMENTATION_REVIEW.md', 'CLIENT_CAPS_TRANSPORT_REVIEW.md',
                     'CLIENT_JOURNAL_CODEC_REVIEW.md', 'CLIENT_PROC_READER_REVIEW.md',
                     'DEVICE_CLIENT_CAPS_READONLY_REVIEW.md', 'CLIENT_FILES_REVIEW.md',
                     'CLIENT_FILES_LINUX_HOST_CHECK.md','CLIENT_STORE_IMPLEMENTATION_NEXT.md',
                     'CLIENT_COORDINATION_REVIEW.md'):
            with self.subTest(name=name):
                self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
                self.write(self.base / 'private-raw' / name, 'HOST_UNREVIEWED')
                self.write(self.base / 'docs' / (name + '.future'), 'HOST_UNREVIEWED')
                self.assertNotIn('documents/' + name, self.members())
                path = self.write(self.base / 'docs' / name, 'HOST review, not P011 RF')
                self.assertEqual(self.members()['documents/' + name], path)

    def test_exact_state_observer_component_is_not_latest_full_suite(self):
        folder = self.base / 'results/state-observer-host-20261001-103410-feab09'
        value = {'evidence_level': 'HOST_COMPONENT_ONLY', 'component': 'state_smoke_observer',
                 'tests': 20, 'pass': True, 'device_runtime': 'NOT_EVALUATED',
                 'phone_interop': 'NOT_TESTED', 'radio_operations': False,
                 'project_full_suite_rerun': False, 'record_kind': 'DERIVED_FROM_TOOL_OUTPUT',
                 'stdout_stderr_separately_captured': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST synthetic fixture of the fixed component result')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        self.write(folder / 'source/observer.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/state-observer-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "tests": 9999}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        full = self.base / 'results/host-20261001-091512-316513'
        self.write(full / 'result.json', json.dumps({'evidence_level': 'HOST_ONLY', 'tests': 1322}))
        self.write(full / 'unittest.txt', 'HOST synthetic project integration result')
        members = self.members()
        prefix = 'host-state-observer-component/'
        selected = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(selected, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(selected[prefix + 'result.json'].read_text()), value)
        self.assertEqual(json.loads(members['host/result.json'].read_text())['tests'], 1322)
        self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                             for path in selected.values()))

    def test_exact_incremental_components_do_not_become_full_source_or_device_pass(self):
        folder = self.base / 'results/client-components-host-review-20261001'
        value = {'evidence_level': 'HOST_INCREMENTAL_COMPONENT_BATCHES',
                 'record_kind': 'DERIVED_FROM_AGENT_TOOL_OUTPUT',
                 'final_source_single_full_batch': False, 'project_full_suite_rerun': False,
                 'affected_batches_pass': True, 'device_runtime': 'NOT_EVALUATED',
                 'phone_interop': 'NOT_TESTED', 'radio_operations': False,
                 'components': [{'current_test_method_count': 81,
                                  'final_revision_affected_batch': {'tests_run': 21}}]}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST reviewed incremental component fixture')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        self.write(folder / 'runtime/core.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/client-components-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "tests": 9999}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        full = self.base / 'results/host-20261001-091512-316513'
        self.write(full / 'result.json', json.dumps({'tests': 1322, 'pass': True}))
        self.write(full / 'unittest.txt', 'HOST synthetic earlier full suite')
        members = self.members()
        prefix = 'host-client-incremental-components/'
        chosen = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertFalse(value['final_source_single_full_batch'])
        self.assertEqual(json.loads(members['host/result.json'].read_text())['tests'], 1322)

    def test_latest_tls_keeps_actual_loopback_boundary_and_closure_facts(self):
        folder = self.root / 'logs/MtaP011-DeviceTls-20261001-064951-2a568c8a'
        value = {'pass': True, 'evidence_level': 'P011_TLS_LOOPBACK_SYNTHETIC',
                 'sender_closure_proof_verified': True, 'receiver_closure_proofs_verified': True,
                 'radio_operations': False, 'ui_started': False, 'user_files_accessed': False,
                 'phone_interop': 'NOT_TESTED', 'production_wifi_sender': 'NOT_TESTED'}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        members = self.members()
        self.assertEqual(json.loads(members['device-tls/result.json'].read_text()), value)
        self.assertFalse(any(name.startswith('device-tls/private') for name in members))

    def test_caps_failures_and_linux_host_proc_keep_exact_separate_evidence(self):
        cases = (
            ('device-client-caps-initial-frame-failure',
             self.root / 'logs/MtaP011-ClientCapsReadOnly-20261001-112454-67ff5518',
             {'pass': False, 'caps_read_invoked': 'NOT_RECORDED', 'phone_interop': 'NOT_TESTED'}),
            ('device-client-caps-reviewed-precondition-failure',
             self.root / 'logs/MtaP011-ClientCapsReadOnly-20261001-113255-3acb18fc',
             {'pass': False, 'caps_read_invoked': False, 'p2p_restoration': 'NOT_EVALUATED'}),
            ('device-client-caps-initial-analysis',
             self.base / 'results/client-caps-readonly-analysis-20261001-112454',
             {'original_check_pass': False, 'record_kind': 'DERIVED_FROM_RETAINED_PRIVATE_RAW'}),
            ('host-linux-client-proc',
             self.base / 'results/client-proc-linux-host-20261001-03a573',
             {'pass': True, 'p011_execution': False, 'wait_or_reap_proof': False}))
        for label, folder, value in cases:
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / 'README.txt', 'HOST fixture preserving the distinct evidence layer')
            self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
            self.write(folder / 'source/checker.py', 'HOST_UNREVIEWED')
        future = self.root / 'logs/MtaP011-ClientCapsReadOnly-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        members = self.members()
        for label, folder, value in cases:
            prefix = label + '/'
            selected = {name: path for name, path in members.items() if name.startswith(prefix)}
            self.assertEqual(selected, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
            self.assertEqual(json.loads(selected[prefix + 'result.json'].read_text()), value)
            self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                                 for path in selected.values()))

    def test_exact_linux_files_result_excludes_private_run_and_keeps_host_boundary(self):
        folder = self.base / 'results/client-files-linux-host-20261001-040520-db3f3abc9c37595f'
        value = {'evidence': 'HOST_LINUX_FILES_ONLY', 'pass': True, 'p011_tested': False,
                 'known_fd_count': 17, 'close_verified_count': 17, 'unknown_open_count': 0,
                 'store_tested': False, 'flock_tested': False, 'provider_tested': False,
                 'private_run_retained': True, 'global_pending_modified': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture, not device or recovery proof')
        self.write(folder / 'private-raw/journal.json', 'HOST_PRIVATE')
        self.write(folder / 'source/checker.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/client-files-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "p011_tested": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        members = self.members(); prefix = 'host-linux-client-files/'
        chosen = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                             for path in chosen.values()))

    def test_exact_libc_flock_adapter_result_is_not_full_coordination_or_device(self):
        folder = self.base / 'results/client-coordination-linux-host-20261001-af12be'
        value = {'record_kind': 'DERIVED_FROM_ROOT_TOOL_OUTPUT', 'pass': True,
                 'evidence_level': 'HOST_LINUX_LIBC_FLOCK_ADAPTER_ONLY',
                 'p011_execution': False, 'client_coordination_acquire_tested': False,
                 'cross_process_tested': False, 'same_ofd_inheritance_tested': False,
                 'pending_accessed': False, 'device_gate_accessed': False,
                 'owned_fd_count': 3, 'close_ebadf_verified_count': 3}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture of the independently reviewed adapter probe')
        self.write(folder / 'private-raw/fixture.lock', 'HOST_PRIVATE')
        self.write(folder / 'probe.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/client-coordination-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "p011_execution": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        members = self.members(); prefix = 'host-linux-client-coordination-adapter/'
        chosen = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                             for path in chosen.values()))

    def test_preparation_namespace_pass_keeps_initial_fixture_failure_and_document_scope(self):
        cases = (
            ('host-linux-client-preparation-initial-failure',
             'results/client-preparation-linux-host-20261001-12ae9d-initial-failure',
             {'pass': False, 'store_constructor_executed': False,
              'error_code': 'invalid_snapshot', 'p011_execution': False}),
            ('host-linux-client-preparation',
             'results/client-preparation-linux-host-20261001-c6d315',
             {'pass': True, 'root_path_redirected_to_private_host_fixture': True,
              'default_root_namespace_tested': False, 'p011_execution': False,
              'full_rf_store_or_finish_tested': False, 'close_ebadf_verified_count': 14}))
        for label, relative, value in cases:
            folder = self.base / relative
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / 'README.txt', 'HOST synthetic package fixture')
            self.write(folder / 'private-raw/journal.json', 'HOST_PRIVATE')
            self.write(folder / 'source/loader.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/client-preparation-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "p011_execution": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        name = 'CLIENT_PREPARATION_STORE_REVIEW.md'
        self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
        self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE')
        self.assertNotIn('documents/' + name, self.members())
        reviewed = self.write(self.base / 'docs' / name, 'HOST review, not full RF Store')
        members = self.members()
        self.assertEqual(members['documents/' + name], reviewed)
        for label, relative, value in cases:
            selected = {key: path for key, path in members.items() if key.startswith(label + '/')}
            self.assertEqual(selected, {label + '/' + filename: self.base / relative / filename
                                       for filename in ('result.json', 'README.txt')})
            self.assertEqual(json.loads(selected[label + '/result.json'].read_text()), value)
            self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                                 for path in selected.values()))

    def test_file_selection_linux_pair_and_new_reviews_keep_exact_host_scope(self):
        relative = 'results/file-selection-linux-host-20261001-7b680f'
        folder = self.base / relative
        value = {'pass': True, 'evidence_level': 'HOST_LINUX_FILE_SELECTION_ONLY',
                 'p011_tested': False, 'phone_interop': 'NOT_TESTED',
                 'known_selection_close_attempts': 4, 'known_original_fd_ebadf_observations': 4}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST synthetic package fixture')
        self.write(folder / 'private-raw/user.bin', 'HOST_PRIVATE')
        self.write(folder / 'probe.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/file-selection-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "p011_tested": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        for name in ('FILE_SELECTION_LIFECYCLE_REVIEW.md', 'SEND_WORKER_REVIEW.md',
                     'TRANSFER_SESSION_DIRECTION_REVIEW.md', 'SCAN_HANDOFF_REVIEW.md'):
            self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE')
            self.assertNotIn('documents/' + name, self.members())
            reviewed = self.write(self.base / 'docs' / name, 'HOST review, not phone interop')
            self.assertEqual(self.members()['documents/' + name], reviewed)
        prefix = 'host-linux-file-selection/'
        selected = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(selected, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(selected[prefix + 'result.json'].read_text()), value)
        self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                             for path in selected.values()))

    def test_state_send_and_finish_design_reviews_are_only_exact_public_documents(self):
        for name in ('STATE_SEND_INTEGRATION_REVIEW.md', 'CLIENT_STORE_FINISH_DECISION.md'):
            self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE')
            self.assertNotIn('documents/' + name, self.members())
            reviewed = self.write(self.base / 'docs' / name,
                                  'HOST review or design only; production unavailable, no device grant')
            self.assertEqual(self.members()['documents/' + name], reviewed)
        self.write(self.base / 'runtime' / 'mta_service.py', 'HOST_UNREVIEWED')
        self.write(self.base / 'runtime' / 'mta_client_store.py', 'HOST_UNREVIEWED')
        self.write(self.base / 'docs' / 'CLIENT_STORE_UNREVIEWED_FUTURE.md', 'HOST_UNREVIEWED')
        members = self.members()
        self.assertFalse(any(path.parts[-2] == 'runtime' for path in members.values()))
        self.assertNotIn('documents/CLIENT_STORE_UNREVIEWED_FUTURE.md', members)

    def test_finish_contract_and_pending_exact_reports_do_not_admit_future_store(self):
        for name in ('CLIENT_FINISH_CONTRACT_REVIEW.md', 'CLIENT_PENDING_FILE_REVIEW.md'):
            self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE')
            self.assertNotIn('documents/' + name, self.members())
            reviewed = self.write(self.base / 'docs' / name, 'HOST component only, no RF/Store grant')
            self.assertEqual(self.members()['documents/' + name], reviewed)
        folder = self.base / 'results/client-pending-linux-host-20261001-5b45e5'
        value = {'evidence_level': 'HOST_LINUX_ISOLATED_PENDING_FILE_ONLY',
                 'known_fd_count': 7, 'send_available': False, 'phone_interop': 'NOT_TESTED'}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture, marker retained; no unlink/complete Store')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        self.write(folder / 'probe.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/client-pending-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        for name in ('P2P_ASSOCIATION_UNREVIEWED_FUTURE.md', 'CLIENT_PROCESS_UNREVIEWED_FUTURE.md',
                     'CLIENT_STORE_UNREVIEWED_FUTURE.md'):
            self.write(self.base / 'docs' / name, 'HOST_UNREVIEWED')
            self.assertNotIn('documents/' + name, self.members())
        self.write(self.base / 'runtime/mta_client_store.py', 'HOST_UNREVIEWED')
        prefix = 'host-linux-client-pending/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertFalse(any(path.parts[-2] == 'runtime' for path in self.members().values()))

    def test_owned_marker_transaction_and_current_sysfs_exact_reports_only(self):
        for name in ('CLIENT_OWNED_MARKER_REVIEW.md', 'CLIENT_JOURNAL_TRANSACTION_REVIEW.md'):
            self.write(self.base / 'docs' / (name + '.future'), 'HOST_UNREVIEWED')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE')
            self.assertNotIn('documents/' + name, self.members())
            reviewed = self.write(self.base / 'docs' / name, 'HOST-only composition, not full Store or RF')
            self.assertEqual(reviewed, self.members()['documents/' + name])
        folder = self.root / 'logs/MtaP011-CurrentSysfsReadOnly-20261001-151948-152166'
        value = {'host_exit': 0, 'remote_exit': 0, 'stock_three_file_pins_match': True,
                 'wlan0_present': False, 'phy_count': 0, 'backlight_any_positive': False,
                 'network_mutation': False, 'radio_trial': False,
                 'full_network_restore': 'NOT_EVALUATED', 'radio_fault_cause': 'NOT_ESTABLISHED'}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture of fixed device read-only observations')
        self.write(folder / 'private-raw/stdout.raw', 'HOST_PRIVATE')
        self.write(folder / 'source/probe.py', 'HOST_UNREVIEWED')
        future = self.root / 'logs/MtaP011-CurrentSysfsReadOnly-20990101-unreviewed'
        self.write(future / 'result.json', '{}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-current-sysfs-readonly/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                             for path in chosen.values()))

    def test_journal_transaction_snapshot_is_exact_not_future_or_runtime(self):
        folder = self.base / 'results/client-journal-transaction-host-review-20261001'
        value = {'evidence_level': 'HOST_INCREMENTAL_COMPOSITION_NOT_PROJECT_SUITE',
                 'production_send_available': False, 'rf_operations': False,
                 'isolated_linux_transaction_test': 'NOT_YET_RUN', 'phone_interop': 'NOT_TESTED'}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST aggregate only')
        self.write(folder / 'private-raw/stdout.raw', 'HOST_PRIVATE')
        self.write(folder / 'runtime/transaction.py', 'HOST_UNREVIEWED')
        future = self.base / 'results/client-journal-transaction-host-review-20990101'
        self.write(future / 'result.json', '{}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'host-client-journal-transaction-review/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)

    def test_journal_transaction_linux_exact_pair_and_review_exclude_private_and_future(self):
        folder = self.base / 'results/client-journal-transaction-linux-host-20261001-075743-8344d8420325c16a'
        value = {'evidence': 'HOST_LINUX_ISOLATED_JOURNAL_TRANSACTION', 'pass': True,
                 'component_fd_count': 24, 'component_ebadf_count': 24,
                 'setup_fd_count': 7, 'setup_ebadf_count': 7,
                 'marker_unlinked': False, 'fixture_retained': True,
                 'network_baseline_authenticated': False, 'p011_tested': False,
                 'phone_tested': False, 'rf': False, 'full_store_implemented': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture, not production or phone transfer')
        for relative in ('private-raw/observations.json', 'stdout.raw', 'source/checker.py'):
            self.write(folder / relative, 'HOST_PRIVATE_OR_UNREVIEWED')
        future = self.base / 'results/client-journal-transaction-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true, "p011_tested": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        doc = 'CLIENT_JOURNAL_TRANSACTION_LINUX_CHECK_REVIEW.md'
        self.write(self.base / 'docs' / (doc + '.future'), 'HOST_UNREVIEWED')
        self.write(self.base / 'private-raw' / doc, 'HOST_PRIVATE')
        self.assertNotIn('documents/' + doc, self.members())
        reviewed = self.write(self.base / 'docs' / doc, 'Reviewed HOST-only checker scope')
        members = self.members(); prefix = 'host-linux-client-journal-transaction/'
        chosen = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertEqual(members['documents/' + doc], reviewed)
        self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                             for path in chosen.values()))

    def test_handoff_and_terminal_clear_exact_pairs_keep_split_errors_and_scope(self):
        cases = (
            ('client-journal-handoff-host-review-20261001', 'host-client-journal-handoff-review', 'README.txt'),
            ('client-pending-clear-host-review-20261001', 'host-client-pending-clear-review', 'README.md'))
        for folder_name, label, companion in cases:
            folder = self.base / 'results' / folder_name
            value = {'evidence': 'HOST_FAKE_COMPONENT_REVIEW_ONLY',
                     'test_batches': [{'host_exit': 1, 'errors': 27}, {'host_exit': 0}],
                     'actual_linux_clear': False, 'p011_test': False, 'phone_interoperability': 'NOT_TESTED'}
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / companion, 'HOST component only; split failures retained')
            for relative in ('private-raw/observations.json', 'source/candidate.py', 'stdout.raw'):
                self.write(folder / relative, 'HOST_PRIVATE_OR_UNREVIEWED')
            future = self.base / 'results' / (folder_name + '-future')
            self.write(future / 'result.json', '{"p011_test": true}')
            self.write(future / companion, 'HOST_UNREVIEWED')
            prefix = label + '/'
            chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
            self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', companion)})
            self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
            self.assertFalse(any('HOST_PRIVATE' in path.read_text() or 'HOST_UNREVIEWED' in path.read_text()
                                 for path in chosen.values()))
        for doc in ('CLIENT_JOURNAL_HANDOFF_REVIEW.md', 'CLIENT_PENDING_CLEAR_REVIEW.md'):
            self.write(self.base / 'private-raw' / doc, 'HOST_PRIVATE')
            self.write(self.base / 'docs' / (doc + '.future'), 'HOST_UNREVIEWED')
            self.assertNotIn('documents/' + doc, self.members())
            path = self.write(self.base / 'docs' / doc, 'HOST component review, no production gate')
            self.assertEqual(path, self.members()['documents/' + doc])

    def test_durable_and_baseline_exact_pair_keep_failed_batches_and_no_real_manifest(self):
        for component, doc in (('durable-store', 'DURABLE_CLIENT_STORE_REVIEW.md'),
                               ('baseline', 'CLIENT_BASELINE_REVIEW.md')):
            folder = self.base / ('results/client-' + component + '-host-review-20261001')
            label = 'host-client-' + component + '-review/'
            value = {'evidence': 'HOST_FAKE_COMPONENT_ONLY', 'production_provider': False,
                     'test_batches': [{'host_exit': 1}, {'host_exit': 0}],
                     'real_wpa_cli_sha_established': False, 'p011_tested': False}
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / 'README.txt', 'HOST FakeIO only; no real manifest or network restore')
            self.write(folder / 'private-raw/observations.json', 'HOST_PRIVATE')
            self.write(folder / 'source/runtime.py', 'HOST_UNREVIEWED')
            future = folder.with_name(folder.name + '-future')
            self.write(future / 'result.json', '{"p011_tested": true}')
            self.write(future / 'README.txt', 'HOST_UNREVIEWED')
            self.write(self.base / 'docs' / (doc + '.future'), 'HOST_UNREVIEWED')
            path = self.write(self.base / 'docs' / doc, 'HOST scope retained')
            chosen = {name: source for name, source in self.members().items() if name.startswith(label)}
            self.assertEqual(chosen, {label + name: folder / name for name in ('result.json', 'README.txt')})
            self.assertEqual(json.loads(chosen[label + 'result.json'].read_text()), value)
            self.assertEqual(self.members()['documents/' + doc], path)
            self.assertFalse(any('HOST_PRIVATE' in source.read_text() or 'HOST_UNREVIEWED' in source.read_text()
                                 for source in chosen.values()))

    def test_association_process_exact_reviews_and_linux_owner_result_only(self):
        for name in ('P2P_ASSOCIATION_REVIEW.md', 'CLIENT_PROCESS_OWNER_REVIEW.md'):
            self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE')
            self.assertNotIn('documents/' + name, self.members())
            reviewed = self.write(self.base / 'docs' / name, 'HOST component; production send false')
            self.assertEqual(self.members()['documents/' + name], reviewed)
        folder = self.base / 'results/client-process-owner-linux-host-20261001-69bab0'
        value = {'evidence_level': 'HOST_LINUX_PRIVATE_DIRECT_CHILD_ONLY',
                 'known_parent_original_fd_count': 9, 'p011_tested': False,
                 'phone_interop': 'NOT_TESTED', 'full_store_or_provider': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture; exact direct child, no RF/Store')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.base / 'results/client-process-owner-linux-host-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        self.write(self.base / 'docs/CLIENT_STORE_UNREVIEWED_FUTURE.md', 'HOST_UNREVIEWED')
        prefix = 'host-linux-client-process-owner/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)
        self.assertNotIn('documents/CLIENT_STORE_UNREVIEWED_FUTURE.md', self.members())

    def test_exact_v7_failure_retains_observed_non128_route_rejection_and_restore(self):
        folder = self.root / 'logs/MtaP011-DeviceP2pV7L3Diag-20261001-072210-d0ad939a'
        value = {'pass': False, 'rf_trial_invoked': True,
                 'ip_creation_l3': {'reason': 'route_prefix', 'stage': 'route_prefix',
                     'observations': {'addresses_accepted': True, 'route_prefix_is_128': False}},
                 'failed_trial_cleanup_complete': True,
                 'full_ipv4_readback_unchanged': True, 'full_ipv6_readback_unchanged': True,
                 'phone_interop': 'NOT_TESTED', 'send_available': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture of exact reviewed V7 FAIL boundary')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.root / 'logs/MtaP011-DeviceP2pV7L3Diag-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-v7-l3diag-failure/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)

    def test_exact_initial_udp_failure_does_not_become_kernel_or_restore_acceptance(self):
        folder = self.root / 'logs/MtaP011-UdpLoopback-20261001-072329-0cfa2813'
        value = {'pass': False, 'udp_trial_invoked': False,
                 'host_error_stage': 'before', 'host_error_class': 'value_error',
                 'independent_stock_unchanged': False, 'independent_baseline_unchanged': False,
                 'phone_interop': 'NOT_TESTED', 'ipv4_all_tables_verified': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture; real first trial never invoked UDP')
        self.write(folder / 'private-raw/stdout.raw', 'HOST_PRIVATE')
        prefix = 'device-udp-loopback-initial-failure/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(set(chosen), {prefix + 'result.json', prefix + 'README.txt'})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)

    def test_exact_v8_failure_retains_same_read_multicast8_and_no_ip_receipt(self):
        folder = self.root / 'logs/MtaP011-DeviceP2pV8RouteDiag-20261001-075353-9ad31b4d'
        value = {'pass': False, 'rf_trial_invoked': True,
                 'ip_creation_l3': {'reason': 'route_prefix', 'route_details': {
                     'values': {'prefix': 8, 'destination_class': 'multicast'},
                     'invalid_fields': [], 'observations': {'flags_up': True, 'gateway_zero': True}}},
                 'failed_trial_cleanup_complete': True,
                 'full_ipv4_readback_unchanged': True, 'full_ipv6_readback_unchanged': True,
                 'journal_ip_stage': 'none', 'phone_interop': 'NOT_TESTED', 'send_available': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST package fixture, not IP installation acceptance')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.root / 'logs/MtaP011-DeviceP2pV8RouteDiag-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-v8-route-diagnostic-failure/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)

    def test_reviewed_udp_pass_preserves_only_loopback_and_explicit_not_tested_layers(self):
        folder = self.root / 'logs/MtaP011-UdpLoopback-20261001-073152-11ad27e3'
        value = {'pass': True, 'udp_trial_invoked': True,
                 'independent_stock_unchanged': True, 'independent_baseline_unchanged': True,
                 'radio_operations': False, 'network_configuration': False,
                 'dhcp_exchange': 'NOT_TESTED', 'p2p_interface_binding': 'NOT_TESTED',
                 'phone_interop': 'NOT_TESTED', 'ipv4_all_tables_verified': False,
                 'udp': {'all_sockets_closed': True, 'closed_readbacks': 2, 'close_failures': 0}}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture of exact reviewed UDP loopback result')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        prefix = 'device-udp-loopback-reviewed/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)

    def test_exact_v9_preflight_timeout_retains_no_rf_and_independent_baseline_facts(self):
        folder = self.root / 'logs/MtaP011-DeviceP2pV9MRoute-20261001-082419-8c70df17'
        value = {'pass': False, 'rf_trial_invoked': False,
                 'error_stage': 'initial_prior_journals', 'candidate_staged': True,
                 'new_candidate_permissions_verified': True,
                 'full_ipv4_readback_unchanged': True, 'full_ipv6_readback_unchanged': True,
                 'journal_present': False, 'phone_interop': 'NOT_TESTED', 'send_available': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture; pre-RF timeout is not an IP trial result')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.root / 'logs/MtaP011-DeviceP2pV9MRoute-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-v9-preflight-timeout/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)


    def test_exact_tty_collection_pass_is_not_rf_or_universal_actor_absence(self):
        folder = self.root / 'logs/MtaP011-TtyActorReadOnly-20261001-084503-4abc3a74'
        value = {'pass': True, 'check_complete': True,
                 'observed_prior_marker_actors_zero': True,
                 'radio_operations': False, 'device_writes': False,
                 'cleanup_invoked': False, 'historical_tty_mode': 'NOT_PROVEN',
                 'all_resources_absent': 'NOT_PROVEN'}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture; current observation only, not RF admission')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.root / 'logs/MtaP011-TtyActorReadOnly-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-tty-actor-readonly/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)


    def test_v9_bounded_readonly_does_not_hide_owned_ip_cleanup_failure(self):
        records = (
            ('device-v9-bounded-readonly', '20261001-084730-3b89eb62',
             {'pass': True, 'readonly_preflight_complete': True, 'rf_trial_invoked': False,
              'go_ip_ready_event': False, 'send_available': False}),
            ('device-v9-bounded-functional-failure', '20261001-084811-e064eae6',
             {'pass': False, 'rf_trial_invoked': True, 'go_ip_ready_event': True,
              'cleanup_complete': False, 'journal_ip_stage': 'confirmed',
              'global_pending_clear_independent': False, 'full_ipv4_readback_unchanged': False,
              'stock_independent_unchanged': True, 'wifi_completed_after': True,
              'phone_interop': 'NOT_TESTED', 'send_available': False}))
        for label, stamp, value in records:
            folder = self.root / ('logs/MtaP011-DeviceP2pV9Bounded-' + stamp)
            self.write(folder / 'result.json', json.dumps(value))
            self.write(folder / 'README.txt', 'HOST fixture preserving independent result layers')
            self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
            prefix = label + '/'
            chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
            self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
            self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)


    def test_restore_readonly_failure_stays_observation_not_restoration(self):
        folder = self.root / 'logs/MtaP011-V9RestoreReadOnly-20261001-091400-682a4364'
        value = {'pass': False, 'check_complete': False, 'readonly_only': True,
                 'network_mutations': False, 'recovery_invoked': False,
                 'authorization_or_lock_held': False,
                 'historical_stop_failure_cause': 'NOT_PROVEN',
                 'observation': {'stage': 'actors', 'reason': 'schema_or_read_error',
                                 'netlink_sockets_closed': True, 'observations': []},
                 'full_current_baseline_unchanged': False}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture, current collection failed; no restore authorization')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.root / 'logs/MtaP011-V9RestoreReadOnly-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-v9-restore-readonly-failure/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)


    def test_current_triage_failure_keeps_stable_baseline_distinct_from_wifi_and_absence(self):
        folder = self.root / 'logs/MtaP011-V9CurrentTriage-20261001-094137-72d4e1f2'
        value = {'pass': False, 'check_complete': False, 'readonly_only': True,
                 'current_baseline_equal': True, 'wifi_completed_preconditions': False,
                 'network_mutations': False, 'recovery_invoked': False,
                 'observation': {'netlink_socket_closed': True, 'snapshots_equal': True,
                     'observations': [{'owned': {'complete': True, 'reason': 'absent',
                         'sysfs_recorded': True, 'sysfs_present': False},
                         'actors': {'complete': False, 'clear': False,
                             'reason': 'empty_user_zombie', 'zombie_task_count': 1,
                             'counts': {'numeric_seen': 197, 'examined': 158}},
                         'pending': {'present': True, 'valid': True},
                         'journal': {'stage': 'recovery_required', 'ip_stage': 'confirmed'}}]}}
        self.write(folder / 'result.json', json.dumps(value))
        self.write(folder / 'README.txt', 'HOST fixture, complete current baseline equality not restoration')
        self.write(folder / 'private-raw/result.json', 'HOST_PRIVATE')
        future = self.root / 'logs/MtaP011-V9CurrentTriage-20990101-unreviewed'
        self.write(future / 'result.json', '{"pass": true}')
        self.write(future / 'README.txt', 'HOST_UNREVIEWED')
        prefix = 'device-v9-current-triage-failure/'
        chosen = {name: path for name, path in self.members().items() if name.startswith(prefix)}
        self.assertEqual(chosen, {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(chosen[prefix + 'result.json'].read_text()), value)


class ClientFilesHostEntryTests(unittest.TestCase):
    def test_entry_is_source_only_and_preserves_exit_without_starting_linux(self):
        source = (BASE / 'HOST_CLIENT_FILES_CHECK.cmd').read_text(encoding='utf-8')
        commands = [line.strip() for line in source.splitlines()
                    if line.strip() and not line.lower().startswith('echo ')]
        self.assertEqual(commands, ['@echo off', 'cd /d "%~dp0"',
            'python -B host\\client_files_linux_check.py --source-check-only',
            'set "MTA_CLIENT_FILES_HOST_EXIT=%ERRORLEVEL%"', 'pause',
            'exit /b %MTA_CLIENT_FILES_HOST_EXIT%'])
        self.assertNotIn('--execute-reviewed', source)
        self.assertIn('does not start WSL or Docker', source)
        self.assertIn('or prove phone transfer', source)


class ClientCapsReadOnlyEntryTests(unittest.TestCase):
    def test_entry_is_exact_source_check_then_hash_reviewed_readonly_checker(self):
        source = (BASE / 'DEVICE_CLIENT_CAPS_READONLY_CHECK.cmd').read_text(encoding='utf-8')
        commands = [line.strip() for line in source.splitlines()
                    if line.strip() and not line.lower().startswith('echo ')]
        self.assertEqual(commands, ['@echo off', 'cd /d "%~dp0"',
            'python -B host\\device_client_caps_readonly.py --source-check-only',
            'if errorlevel 1 goto end',
            'python -B host\\device_client_caps_readonly.py --execute-reviewed --expected-checker-sha256 '
            '948a6c8dfdbb134fcd2f060ff30447c96e4111e1af135f89174ec1f3e3c00a21',
            ':end', 'pause'])
        self.assertIn('No RF, network changes, staging, locks or pending cleanup.', source)
        self.assertIn('does not test file transfer', source)


class SyntheticTlsEntryTests(unittest.TestCase):
    def test_entry_is_only_the_reviewed_finite_synthetic_checker(self):
        source = (BASE / 'DEVICE_TLS_SYNTHETIC_CHECK.cmd').read_text(encoding='utf-8')
        commands = [line.strip() for line in source.splitlines()
                    if line.strip() and not line.lower().startswith('echo ')]
        self.assertEqual(commands, ['@echo off', 'cd /d "%~dp0"',
                                    'python -B host\\device_tls.py', 'pause'])
        self.assertIn('No radio, UI or user files.', source)
        self.assertIn('Does not prove Wi-Fi or phone interoperability.', source)


class SyntheticUdpEntryTests(unittest.TestCase):
    def test_entry_is_only_the_reviewed_loopback_checker_with_exact_pin(self):
        source = (BASE / 'DEVICE_UDP_LOOPBACK_CHECK.cmd').read_text(encoding='utf-8')
        commands = [line.strip() for line in source.splitlines()
                    if line.strip() and not line.lower().startswith('echo ')]
        self.assertEqual(commands, ['@echo off', 'cd /d "%~dp0"',
            'python -B host\\device_udp_loopback.py --execute-reviewed --expected-checker-sha256 '
            '3319052523fb791ca1eb4bedd7fe449d4f663ae400f339f33b5d33b203d0fd87', 'pause'])
        self.assertIn('lo only, 2 sockets, 4 datagrams.', source)
        self.assertIn('No RF, network configuration, DHCP ports, UI or user files.', source)
        self.assertIn('Does not prove P2P binding, DHCP or phone interoperability.', source)


if __name__ == '__main__':
    unittest.main()
