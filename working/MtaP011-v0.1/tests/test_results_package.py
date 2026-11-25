"""HOST-only fixed-history evidence admission; all ZIPs are temporary fixtures."""
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


WARM = 'MtaP011-DeviceP2pV3-20261001-022112-fc590b0e'
COLD = 'MtaP011-DeviceP2pV3-20261001-023349-HOST-cold'
REBOOT = 'MtaP011-NormalReboot-20261001-023005-d1bbea10'
BOOT = 'MtaP011-BootReadOnly-20261001-023304-9c8871df'
SPAWN = 'MtaP011-SpawnReadOnly-20261001-024645-8ad3725d'
CONFIG = 'MtaP011-WpaConfigNoRf-20261001-025636-5a66dea7'
VERSION = 'MtaP011-WpaVersionNoRf-20261001-025014-32f57de4'
IPDUMP = 'MtaP011-IpDumpReadOnly-20261001-032317-adba0ac0'
IPCORE_INITIAL = 'MtaP011-IpCoreReadOnly-20261001-034723-58f50b59'
IPCORE_REVIEWED = 'MtaP011-IpCoreReadOnly-20261001-035650-66a4c890'
V5_FAILURE = 'MtaP011-DeviceP2pV5-20261001-044609-c53555d6'
UDP_API = 'MtaP011-UdpApiReadOnly-20261001-043409-b782aaca'
OWNED_IP_HOST = 'owned-ip-host-20261001-043347-0e487f'
V6_DIAG_HOST = 'v6diag-host-20261001-051618-55379f'
V6_ADMISSION_FAILURE = 'MtaP011-DeviceP2pV6Diag-20261001-053019-ffaa543c'
PRIOR_JOURNAL_READONLY = 'MtaP011-PriorJournalReadOnly-20261001-054328-59c5c157'
PERMISSIONS_NORMALIZE = 'MtaP011-CandidatePermissionsNormalize-20261001-060853-204a0e0a'
V6_PERMISSIONS_ENTRY = 'MtaP011-DeviceP2pV6DiagPermissions-20261001-061551-48fbed57'


class FixedHistoryPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mta-host-fixed-package-')
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
            self.write(folder / 'README.txt', 'HOST synthetic report; no actual RF/PHONE evidence\n')
        return folder

    def members(self):
        return {name: path for path, name in package.collect_members()}

    def histories(self):
        warm = self.report(WARM, {'pass': False, 'failure_errno': 5,
                                 'failure_phase': 'interface_create',
                                 'netlink_command': 'new_interface', 'failure_reason': 'os_error'}, readme=True)
        cold = self.report(COLD, {'pass': False, 'failure_errno': 0,
                                 'failure_phase': 'private_spawn',
                                 'netlink_command': 'not_recorded', 'failure_reason': 'lease_error'}, readme=True)
        reboot = self.report(REBOOT, {'pass': False, 'error_class': 'RuntimeError'})
        boot = self.report(BOOT, {'pass': True, 'new_boot_verified': True,
                                  'historical_initial_wait_timeout_preserved': True})
        return warm, cold, reboot, boot

    def no_rf_reports(self):
        spawn = {'journal_stage': 'reconciled', 'ctrl_directory_created': True,
                 'owned_saved': True, 'global_pending_clear': True, 'ctrl_private_directory': True,
                 'no_project_trial_actors': True, 'process_saved': True, 'stock_unchanged': True,
                 'config_private_regular': True, 'child_exit_status_recorded': False,
                 'evidence_level': 'P011_PRIVATE_SPAWN_READONLY', 'config_created': True,
                 'ctrl_socket_exists': False, 'radio_operations': False, 'effective_cap_sys_ptrace': True,
                 'process_gone': True, 'no_private_wpa_processes': True}
        config = {'version_exit': 0, 'version_first_line_matches': True, 'original_config_exit': 255,
                  'radio_operations': False, 'interface_arguments_supplied': False,
                  'user_files_accessed': False, 'network_configuration': False,
                  'opt_in_environment_supplied': False, 'corrected_config_exit': 0,
                  'stock_unchanged': True, 'single_directive_removed': True,
                  'evidence_level': 'P011_WPA_CONFIG_PARSE_ONLY', 'candidate_identity': 'a' * 16,
                  'preflight_passed': True, 'prior_journals_clear': True,
                  'independent_baseline_unchanged': True, 'go_formation': 'NOT_TESTED',
                  'phone_interop': 'NOT_TESTED', 'pass': True}
        version = {'evidence_level': 'P011_WPA_VERSION_ONLY_NO_RF', 'loader_exists': True,
                   'version_matches_2_12': False, 'configuration_arguments_supplied': False,
                   'interface_arguments_supplied': False, 'opt_in_environment_supplied': False,
                   'exit_code': 0, 'stock_unchanged': True, 'radio_operations': False, 'pass': False}
        rows = ((SPAWN, spawn, False), (CONFIG, config, True), (VERSION, version, False))
        for directory, value, readme in rows:
            self.report(directory, value, readme=readme)
        return {directory: value for directory, value, _ in rows}

    def ip_dump_report(self):
        value = {'collections_imported': True, 'summaries': [
            {'dump_kind': kind, 'attribute_type_length_counts': {'1:4': 1},
             'message_type_counts': {message: 1}}
            for kind, message in (('addresses', '20'), ('routes', '24'), ('rules', '32'))],
            'radio_operations': False, 'stock_unchanged': True, 'network_configuration': False,
            'evidence_level': 'P011_IPV4_RTNETLINK_READONLY', 'independent_baseline_unchanged': True,
            'ip_installation': 'NOT_TESTED', 'phone_interop': 'NOT_TESTED', 'pass': True}
        return self.report(IPDUMP, value), value

    def ip_core_reports(self):
        initial = {'evidence_level': 'P011_IPV4_CORE_READONLY', 'pass': True,
                   'candidate_identity': '9' * 16, 'core_sha256': '1' * 64,
                   'radio_operations': False, 'network_configuration': False,
                   'ip_installation': 'NOT_TESTED', 'phone_interop': 'NOT_TESTED',
                   'project_candidate_staged': True, 'kernel_sender_checked': True,
                   'rules_count': 3, 'stable_complete_views': True,
                   'permanent_infinite_addresses': True, 'complete_dump_sets': 2,
                   'default_rules': True, 'unique_monotonic_sequences': True,
                   'socket_port_checked': True, 'addresses_count': 2, 'core_imported': True,
                   'routes_count': 9, 'subnet_candidate_available': True,
                   'netlink_socket_closed': True, 'independent_baseline_unchanged': True}
        reviewed = dict(initial, checker_sha256='8' * 64, project_candidate_staged=False)
        for directory, value in ((IPCORE_INITIAL, initial), (IPCORE_REVIEWED, reviewed)):
            self.report(directory, value, readme=True)
        return {IPCORE_INITIAL: initial, IPCORE_REVIEWED: reviewed}

    def v5_udp_owned_ip_reports(self):
        v5 = {'evidence_level': 'P011_PRIVATE_P2P_V5_GO_IP_ONLY_TRIAL',
              'candidate_identity': '0' * 16, 'journal_version': 3, 'ttl_seconds': 20,
              'phone_interop': 'NOT_TESTED', 'checker_sha256': '1' * 64,
              'next_step': 'READONLY_OWNERSHIP_PENDING_AND_IP_RECEIPT_REVIEW_REQUIRED',
              'ip_stage_reported': 'none', 'failure_phase': 'ip_create', 'failure_errno': 0,
              'netlink_command': 'not_recorded', 'failure_reason': 'lease_error',
              'journal_stage': 'reconciled', 'journal_ip_stage': 'none',
              'diagnostic_events': [{'code': 0, 'stage': stage} for stage in (
                  'init_enter', 'capability', 'early_param', 'initial_type_gate', 'initial_mode',
                  'interface_up', 'driver_finish', 'driver_init_result', 'wps_init', 'eapol_init',
                  'control_init', 'p2p_init', 'go_deinit_preserved', 'driver_deinit')]}
        for name in ('pass', 'global_service_changes', 'recovery_invoked', 'retry_invoked',
                     'dhcp_configuration', 'ip_application_sockets', 'send_available', 'ui_started',
                     'user_files_accessed', 'remote_exit_zero', 'go_ip_ready_event', 'cleanup_event',
                     'cleanup_complete', 'owned_process_removed_reported', 'owned_interface_removed_reported',
                     'stock_baseline_equal_reported', 'ip_restored_reported', 'ip_control_socket_closed_reported',
                     'journal_complete', 'journal_identity_mismatch', 'journal_recover_review_ready',
                     'journal_ip_receipt_restored'):
            v5[name] = False
        for name in ('rf_trial_invoked', 'ip_trial_requested', 'historical_v1_v2_v3_v4_unchanged',
                     'prior_journals_clear', 'preflight_passed', 'trial_failed_event', 'diagnostics_valid',
                     'early_init_success_reported', 'stock_independent_unchanged',
                     'wifi_state_fingerprint_unchanged', 'station_state_digest_unchanged',
                     'frequency_unchanged', 'route_digest_unchanged', 'ipv6_address_digest_unchanged',
                     'ipv6_route_digest_unchanged', 'network_processes_unchanged', 'interface_identities_unchanged',
                     'same_boot', 'full_ipv4_addresses_unchanged', 'full_ipv4_routes_unchanged',
                     'full_ipv4_rules_unchanged', 'full_ipv4_readback_unchanged', 'full_ipv6_readback_unchanged',
                     'wifi_completed_after', 'no_p2p_interfaces_after', 'no_project_mta_interfaces_after',
                     'no_private_wpa_processes_after', 'no_project_trial_actors_after',
                     'global_pending_clear_independent', 'journal_present', 'journal_safe',
                     'journal_ownership_verified', 'journal_owned_process_gone', 'journal_owned_interface_gone',
                     'journal_version3', 'journal_ipv6_baseline_present', 'journal_ipv4_baseline_present',
                     'journal_pending_clear', 'journal_baseline_independent_match'):
            v5[name] = True
        udp = {'evidence_level': 'P011_UDP_PYTHON_API_READONLY', 'pass': True,
               'checker_sha256': 'b' * 64, 'actual_udp_bind': 'NOT_TESTED',
               'dhcp_exchange': 'NOT_TESTED', 'phone_interop': 'NOT_TESTED',
               'ipv4_family_constant': True, 'broadcast_constant': True, 'recvmsg_api': True,
               'bindtodevice_constant': True, 'socket_created': False, 'cmsg_space_api': True,
               'sendmsg_api': True, 'ipv4_pktinfo_constant_exposed': False, 'radio_operations': False,
               'truncation_constants': True, 'network_configuration': False,
               'independent_baseline_unchanged': True}
        unittest_text = '----------------------------------------------------------------------\nRan 48 tests in 0.980s\n\nOK\n'
        host = {'schema_version': 1, 'evidence_level': 'HOST_FAULT_INJECTION', 'pass': True,
                'tests_run': 48, 'tests_passed': 48, 'failures': 0, 'errors': 0, 'skipped': 0,
                'host_exit_code': 0, 'archived_at_utc': '2026-09-30T20:33:47Z',
                'original_execution_timestamp_utc': None,
                'command': 'python3 -m unittest discover -s native/tests -p test_owned_ip_lease.py -q',
                'environment': {'platform': 'Linux', 'runner': 'Existing Docker build environment',
                    'container_started_for_this_run': False, 'container_restarted_for_this_run': False},
                'provenance': {'tool': 'exec_command', 'source_chunk_id': '0e487f',
                    'source_output_complete': True, 'captured_stream_kind': 'combined_exec_output',
                    'original_separate_stdout_file_retained': False, 'original_separate_stderr_file_retained': False,
                    'archived_from_existing_tool_return': True, 'tests_rerun_for_archive': False,
                    'original_summary': 'Ran 48 tests in 0.980s; OK', 'summary_seconds': 0.98,
                    'tool_wall_time_seconds': 1.3865034999999999,
                    'limitation': 'Combined retained tool output, not separate stdout/stderr.'},
                'artifacts': [{'path': 'unittest.txt', 'sha256': hashlib.sha256(unittest_text.encode()).hexdigest(),
                               'bytes': len(unittest_text.encode())}],
                'sources': [{'path': name, 'sha256': '9' * 64} for name in (
                    'native/private-p2p-runtime-candidate-20261001-v5/runtime/mta_send_wifi.py',
                    'runtime/mta_ip_lease.py', 'runtime/mta_ip.py', 'native/tests/test_owned_ip_lease.py')],
                'verified_layers': {'fake_lock': 'FakeLock fixture', 'fake_kernel': 'FakeKernel fixture',
                    'journal_filesystem': 'Real POSIX temporary filesystem, atomic replacement and file/directory fsync',
                    'fault_injection': 'HOST only'},
                'unverified_layers': {name: 'NOT_TESTED' for name in ('real_fork_watchdog',
                    'real_flock_inheritance', 'p011_ip_install_restore', 'phone_interoperability')},
                'scope': {name: False for name in ('adb_actions', 'radio_actions', 'real_ip_network_writes',
                    'af_inet_service', 'dhcp_service', 'production_send_available')},
                'immutability': 'New archive of retained prior result; no historical/source rewrite.'}
        self.report(V5_FAILURE, v5, readme=True)
        self.report(UDP_API, udp, readme=True)
        folder = self.base / 'results' / OWNED_IP_HOST
        retained = self.write(folder / 'unittest.txt', unittest_text).read_bytes()
        host['artifacts'][0].update(sha256=hashlib.sha256(retained).hexdigest(), bytes=len(retained))
        self.write(folder / 'result.json', json.dumps(host))
        return {'device-p2p-v5-initial-failure': v5, 'device-udp-api-readonly': udp, 'owned-ip-host': host}

    def v6_diag_report(self):
        output = '----------------------------------------------------------------------\r\nRan 39 tests in 0.075s\r\n\r\nOK\r\n'
        value = {'schema_version': 1, 'evidence_level': 'PC_HOST_FAULT_INJECTION_V6DIAG',
                 'pass': True, 'tests_run': 39, 'passed': 39, 'failures': 0, 'errors': 0,
                 'skipped': 0, 'command': 'python -m unittest discover -s native/tests -p test_send_wifi_v6diag.py -q',
                 'host_exit_code': 0,
                 'provenance': {'source_chunk_id': '55379f', 'source_capture': 'combined_exec_output',
                     'source_output_complete': True, 'separate_stdout_stderr_retained': False,
                     'original_tool_output': output, 'derived_unittest_normalization': 'CRLF to LF only',
                     'archived_at_utc': '2026-09-30T21:16:18Z', 'execution_timestamp_utc': None,
                     'tests_rerun_for_archive': False},
                 'source': {'v6diag': {'path': 'native/private-p2p-runtime-candidate-20261001-v6diag/runtime/mta_send_wifi.py',
                                      'bytes': 78359, 'sha256': '8' * 64},
                            'v5_unchanged': {'sha256': '9' * 64}, 'helper_unchanged': {'sha256': '3' * 64},
                            'core_unchanged': {'sha256': '1' * 64},
                            'tests': {'path': 'native/tests/test_send_wifi_v6diag.py', 'sha256': 'd' * 64}},
                 'artifacts': {'unittest': {'path': 'unittest.txt',
                               'sha256': hashlib.sha256(output.replace('\r\n', '\n').encode()).hexdigest()}},
                 'checks': {name: 'PASS' for name in ('python35_ast', 'assert_side_effects_absent',
                     'original_restore_cleanup_recover_ast_equal', 'supported_sysfs_acceptance_matches_v5',
                     'failure_causes_distinguished', 'earliest_failure_preserved',
                     'rejected_creation_no_fake_newaddr_deladdr')},
                 'fixtures': ['FakeKernel', 'FakeLock', 'MemoryJournal', 'FakeSysfs'],
                 'unverified': ['P011 V6 execution', 'RF', 'real journal fsync in this suite',
                     'real flock/fork watchdog', 'real IPv4 NEWADDR/DELADDR', 'phone interoperability'],
                 'scope': {'device_actions': False, 'docker_operations': False, 'formal_freeze': False,
                           'send_available': False, 'dhcp_service': False, 'application_sockets': False,
                           'historical_v5_failure_unchanged': True}}
        folder = self.base / 'results' / V6_DIAG_HOST
        self.write(folder / 'result.json', json.dumps(value))
        # Exact derived bytes matter: do not add Windows newline translation.
        (folder / 'unittest.txt').write_bytes(output.replace('\r\n', '\n').encode())
        return folder, value

    def v6_device_admission_reports(self):
        failure = {'evidence_level': 'P011_PRIVATE_P2P_V6_DIAGNOSTIC_GO_IP_ONLY_TRIAL',
                   'pass': False, 'candidate_identity': '9' * 16, 'journal_version': 3,
                   'ttl_seconds': 20, 'rf_trial_invoked': False, 'ip_trial_requested': True,
                   'prior_journals_clear': False, 'error_stage': 'prior_journals',
                   'host_or_parse_error': True, 'send_available': False,
                   'phone_interop': 'NOT_TESTED', 'ip_creation_gate_no_rejection': False}
        readonly = {'evidence_level': 'P011_PRIOR_JOURNAL_READONLY_DIAGNOSTIC',
                    'pass': True, 'check_complete': True, 'candidate_identity': '9' * 16,
                    'radio_operations': False, 'network_configuration': False,
                    'recovery_invoked': False, 'retry_invoked': False, 'candidate_staged': False,
                    'device_writes': False, 'send_available': False, 'ip_installation': 'NOT_TESTED',
                    'phone_interop': 'NOT_TESTED', 'prior_admission_clear': False,
                    'unsafe_exception_observed': True,
                    'diagnostic': {'unsafe_count': 1, 'blocked_count': 0, 'inspected_count': 6,
                        'clear': False, 'diagnostic_complete': True, 'global_pending_clear': True,
                        'netlink_socket_closed': True, 'records': [
                            {'ordinal': 6, 'version': 3, 'classification': 'unsafe',
                             'rejected_stage': 'prior_context', 'reason': 'historical_manifest_permissions',
                             'error_class': 'value_error', 'errno': 0,
                             'historical_v5_baseline_checked': False}]}}
        for name in ('stock_independent_unchanged', 'wifi_state_fingerprint_unchanged',
                     'station_state_digest_unchanged', 'frequency_unchanged', 'route_digest_unchanged',
                     'full_ipv4_addresses_unchanged', 'full_ipv4_routes_unchanged',
                     'full_ipv4_rules_unchanged', 'full_ipv4_readback_unchanged',
                     'full_ipv6_readback_unchanged', 'ipv6_address_digest_unchanged',
                     'ipv6_route_digest_unchanged', 'same_boot', 'network_processes_unchanged',
                     'interface_identities_unchanged'):
            failure[name] = False
            readonly[name] = True
        rows = {}
        for directory, label, value, readme in (
                (V6_ADMISSION_FAILURE, 'device-v6diag-admission-failure', failure,
                 'HOST synthetic admission failure before RF; not GO/IP acceptance.\n'),
                (PRIOR_JOURNAL_READONLY, 'device-prior-journal-readonly', readonly,
                 'HOST synthetic check_complete only; prior admission false, IP/PHONE NOT_TESTED.\n')):
            folder = self.report(directory, value, readme=True)
            self.write(folder / 'README.txt', readme)
            rows[label] = (folder, value)
        return rows

    def test_warm_eio_kept_separately_from_latest_cold_v3(self):
        warm, cold, _, _ = self.histories()
        members = self.members()
        for label, folder in (('device-p2p-v3-warm', warm), ('device-p2p-v3', cold)):
            self.assertEqual(members[label + '/result.json'], folder / 'result.json')
            self.assertEqual(members[label + '/README.txt'], folder / 'README.txt')
            self.assertFalse(json.loads(members[label + '/result.json'].read_text())['pass'])
        self.assertEqual(json.loads(members['device-p2p-v3-warm/result.json'].read_text())['failure_phase'],
                         'interface_create')
        self.assertEqual(json.loads(members['device-p2p-v3/result.json'].read_text())['failure_phase'],
                         'private_spawn')

    def test_initial_reboot_fail_is_not_promoted_by_later_readonly_pass(self):
        _, _, reboot, boot = self.histories()
        self.report('MtaP011-NormalReboot-20261001-050000-unreviewed', {'pass': True})
        self.report('MtaP011-BootReadOnly-20261001-050000-unreviewed', {'pass': False})
        members = self.members()
        self.assertEqual(members['device-normal-reboot-initial/result.json'], reboot / 'result.json')
        self.assertEqual(members['device-boot-readonly/result.json'], boot / 'result.json')
        self.assertFalse(json.loads(members['device-normal-reboot-initial/result.json'].read_text())['pass'])
        self.assertTrue(json.loads(members['device-boot-readonly/result.json'].read_text())['pass'])
        self.assertNotIn('device-normal-reboot-initial/README.txt', members)
        self.assertNotIn('device-boot-readonly/README.txt', members)

    def test_historical_warm_folder_is_exact_not_another_v3(self):
        self.report(WARM + '-unreviewed', {'pass': False}, readme=True)
        members = self.members()
        self.assertIn('device-p2p-v3/result.json', members)
        self.assertNotIn('device-p2p-v3-warm/result.json', members)

    def test_fixed_reports_only_admit_result_and_warm_readme(self):
        folders = self.histories()
        for folder in folders:
            for relative in ('private-raw/result.json', 'private-raw/README.txt',
                             'journal/owned.json', 'private-candidate/wpa_supplicant',
                             'binaries/helper', 'user/music.mp3', 'stdout.raw',
                             'free-device-output.json', 'screens/unreviewed.png'):
                self.write(folder / relative, 'HOST_PRIVATE_MARKER')
        selected = {name: path for name, path in self.members().items()
                    if name.startswith(('device-p2p-v3/', 'device-p2p-v3-warm/',
                                        'device-normal-reboot-initial/', 'device-boot-readonly/'))}
        self.assertEqual(set(selected), {
            'device-p2p-v3/result.json', 'device-p2p-v3/README.txt',
            'device-p2p-v3-warm/result.json', 'device-p2p-v3-warm/README.txt',
            'device-normal-reboot-initial/result.json', 'device-boot-readonly/result.json'})
        self.assertTrue(all(b'HOST_PRIVATE_MARKER' not in path.read_bytes() for path in selected.values()))

    def test_fixed_warm_missing_readme_rejects_even_with_valid_latest_cold(self):
        self.report(WARM, {'pass': False})
        self.report(COLD, {'pass': False}, readme=True)
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_v3_failure_review_is_fixed_optional_document(self):
        path = self.write(self.base / 'native/P2P_V3_TRIAL_FAILURE_REVIEW.md', 'HOST public review\n')
        self.write(self.base / 'native/P2P_V3_UNREVIEWED.md', 'HOST_PRIVATE_MARKER')
        members = self.members()
        self.assertEqual(members['documents/P2P_V3_TRIAL_FAILURE_REVIEW.md'], path)
        self.assertNotIn('documents/P2P_V3_UNREVIEWED.md', members)

    def test_older_v1_v2_and_restore_remain_independent(self):
        self.histories()
        v1 = self.report('MtaP011-DeviceP2p-20260930-100000-fail', {'pass': False})
        v2 = self.report('MtaP011-DeviceP2pV2-20261001-010000-fail', {'pass': False}, readme=True)
        recovery = self.report('MtaP011-OwnedStaRecovery-20260930-100100-restored', {'pass': True})
        members = self.members()
        for label, folder in (('device-p2p', v1), ('device-p2p-v2', v2),
                              ('device-owned-cleanup', recovery)):
            self.assertEqual(members[label + '/result.json'], folder / 'result.json')

    def test_no_rf_fixed_reports_have_distinct_schemas_and_preserved_verdicts(self):
        original = self.no_rf_reports()
        members = self.members()
        for label, directory in (('device-spawn-readonly', SPAWN),
                                 ('device-wpa-config-norf', CONFIG),
                                 ('device-wpa-version-initial', VERSION)):
            path = members[label + '/result.json']
            self.assertEqual(path, self.root / 'logs' / directory / 'result.json')
            self.assertEqual(json.loads(path.read_text()), original[directory])
        spawn = json.loads(members['device-spawn-readonly/result.json'].read_text())
        config = json.loads(members['device-wpa-config-norf/result.json'].read_text())
        version = json.loads(members['device-wpa-version-initial/result.json'].read_text())
        self.assertEqual(len(spawn), 17)
        self.assertNotIn('pass', spawn)
        self.assertFalse(spawn['ctrl_socket_exists'])
        self.assertFalse(spawn['child_exit_status_recorded'])
        self.assertEqual(len(config), 19)
        self.assertEqual(config['original_config_exit'], 255)
        self.assertEqual(config['corrected_config_exit'], 0)
        self.assertEqual(config['version_exit'], 0)
        self.assertEqual(config['go_formation'], 'NOT_TESTED')
        self.assertEqual(config['phone_interop'], 'NOT_TESTED')
        self.assertTrue(config['pass'])
        self.assertEqual(len(version), 10)
        self.assertEqual(version['exit_code'], 0)
        self.assertTrue(version['loader_exists'])
        self.assertFalse(version['version_matches_2_12'])
        self.assertFalse(version['pass'])
        self.assertTrue(all(row['radio_operations'] is False for row in original.values()))
        for name in ('device-spawn-readonly/README.txt', 'device-wpa-version-initial/README.txt'):
            self.assertNotIn(name, members)
        self.assertIn('device-wpa-config-norf/README.txt', members)

    def test_no_rf_exact_pinned_paths_not_future_unreviewed_reports(self):
        self.no_rf_reports()
        for prefix in ('MtaP011-SpawnReadOnly', 'MtaP011-WpaConfigNoRf', 'MtaP011-WpaVersionNoRf'):
            self.report(prefix + '-20261001-060000-unreviewed', {'pass': True}, readme=True)
        members = self.members()
        for label, directory in (('device-spawn-readonly', SPAWN),
                                 ('device-wpa-config-norf', CONFIG),
                                 ('device-wpa-version-initial', VERSION)):
            self.assertEqual(members[label + '/result.json'].parent.name, directory)

    def test_no_rf_reports_never_admit_private_raw_or_free_device_output(self):
        self.no_rf_reports()
        for directory in (SPAWN, CONFIG, VERSION):
            folder = self.root / 'logs' / directory
            for name in ('stdout.raw', 'stderr.raw', 'private-raw/result.json',
                         'private-candidate/private.conf', 'journal/owner.json',
                         'binaries/wpa_supplicant', 'user/filename.txt', 'free-output.json'):
                self.write(folder / name, 'HOST_PRIVATE_MARKER')
        selected = {name: path for name, path in self.members().items()
                    if name.startswith(('device-spawn-readonly/', 'device-wpa-config-norf/',
                                        'device-wpa-version-initial/'))}
        self.assertEqual(set(selected), {'device-spawn-readonly/result.json',
            'device-wpa-config-norf/result.json', 'device-wpa-config-norf/README.txt',
            'device-wpa-version-initial/result.json'})
        self.assertTrue(all(b'HOST_PRIVATE_MARKER' not in path.read_bytes() for path in selected.values()))

    def test_config_parse_report_missing_readme_fails_closed(self):
        self.report(CONFIG, {'pass': True, 'go_formation': 'NOT_TESTED'})
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_v4_is_independent_latest_report_and_only_fixed_optional_docs(self):
        self.histories()
        self.report('MtaP011-DeviceP2pV4-20261001-060000-old', {'pass': False}, readme=True)
        v4 = self.report('MtaP011-DeviceP2pV4-20261001-070000-HOST-latest',
                         {'pass': False, 'phone_interop': 'NOT_TESTED'}, readme=True)
        (self.root / 'logs/MtaP011-DeviceP2pV4-20261001-080000-incomplete').mkdir()
        plan = self.write(self.base / 'docs/P2P_TRIAL_V4_PLAN.md', 'HOST public V4 plan\n')
        evidence = self.write(self.base / 'native/tests/HOST_P2P_V4_EVIDENCE.md', 'HOST V4 evidence\n')
        self.write(self.base / 'native/tests/HOST_P2P_V4_RAW.md', 'HOST_PRIVATE_MARKER')
        self.write(v4 / 'private-candidate/wpa_supplicant', 'HOST_PRIVATE_MARKER')
        members = self.members()
        self.assertEqual(members['device-p2p-v4/result.json'], v4 / 'result.json')
        self.assertEqual(members['device-p2p-v4/README.txt'], v4 / 'README.txt')
        self.assertEqual(members['documents/P2P_TRIAL_V4_PLAN.md'], plan)
        self.assertEqual(members['native-host/HOST_P2P_V4_EVIDENCE.md'], evidence)
        self.assertIn('device-p2p-v3/result.json', members)
        self.assertIn('device-p2p-v3-warm/result.json', members)
        self.assertNotIn('native-host/HOST_P2P_V4_RAW.md', members)
        self.assertEqual({name for name in members if name.startswith('device-p2p-v4/')},
                         {'device-p2p-v4/result.json', 'device-p2p-v4/README.txt'})

    def test_latest_v4_missing_readme_rejects_without_promoting_older_report(self):
        self.report('MtaP011-DeviceP2pV4-20261001-060000-old', {'pass': False}, readme=True)
        self.report('MtaP011-DeviceP2pV4-20261001-070000-HOST-latest', {'pass': False})
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_ip_dump_only_fixed_public_result_statistics_are_selected(self):
        folder, value = self.ip_dump_report()
        self.report('MtaP011-IpDumpReadOnly-20261001-090000-unreviewed', {'pass': True})
        members = self.members()
        selected = {name: path for name, path in members.items()
                    if name.startswith('device-ip-dump-readonly/')}
        self.assertEqual(selected, {'device-ip-dump-readonly/result.json': folder / 'result.json'})
        parsed = json.loads(selected['device-ip-dump-readonly/result.json'].read_text())
        self.assertEqual(parsed, value)
        self.assertEqual(parsed['evidence_level'], 'P011_IPV4_RTNETLINK_READONLY')
        self.assertFalse(parsed['radio_operations'])
        self.assertFalse(parsed['network_configuration'])
        self.assertEqual(parsed['ip_installation'], 'NOT_TESTED')
        self.assertEqual(parsed['phone_interop'], 'NOT_TESTED')
        self.assertEqual([row['dump_kind'] for row in parsed['summaries']], ['addresses', 'routes', 'rules'])
        for row in parsed['summaries']:
            self.assertEqual(set(row), {'dump_kind', 'attribute_type_length_counts', 'message_type_counts'})

    def test_ip_dump_private_raw_records_and_parent_extras_never_admitted(self):
        folder, _ = self.ip_dump_report()
        for relative in ('private-raw/raw_dump_records.json', 'private-raw/result.json',
                         'raw_dump_records.json', 'stdout.raw', 'address-details.json',
                         'candidate/helper', 'journal/state.json', 'user/filename.txt', 'README.txt'):
            self.write(folder / relative, 'HOST_PRIVATE_IP_DUMP_MARKER')
        selected = {name: path for name, path in self.members().items()
                    if name.startswith('device-ip-dump-readonly/')}
        self.assertEqual(set(selected), {'device-ip-dump-readonly/result.json'})
        self.assertTrue(all(b'HOST_PRIVATE_IP_DUMP_MARKER' not in path.read_bytes()
                            for path in selected.values()))
        self.assertFalse(any('raw_dump_records' in name for name in self.members()))

    def test_owned_ip_documents_only_use_exact_public_docs_paths(self):
        for name in ('OWNED_IP_CORE.md', 'OWNED_IP_LEASE_REVIEW.md'):
            path = self.write(self.base / 'docs' / name, 'HOST public owned IP document\n')
            self.write(self.base / 'native' / name, 'HOST_PRIVATE_MARKER')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE_MARKER')
            self.assertEqual(self.members()['documents/' + name], path)
        members = self.members()
        self.assertEqual(set(members), {'documents/README.md', 'documents/GOAL.md',
            'documents/CURRENT_STATUS.md', 'documents/OWNED_IP_CORE.md', 'documents/OWNED_IP_LEASE_REVIEW.md'})

    def test_missing_ip_dump_and_optional_documents_create_no_fake_members(self):
        (self.root / 'logs' / IPDUMP).mkdir(parents=True)
        self.report('MtaP011-IpDumpReadOnly-20261001-090000-unreviewed', {'pass': True})
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_ip_core_reports_are_independent_exact_history_with_preserved_pass(self):
        original = self.ip_core_reports()
        self.report('MtaP011-IpCoreReadOnly-20261001-090000-unreviewed', {'pass': False}, readme=True)
        members = self.members()
        for label, directory in (('device-ip-core-readonly-initial', IPCORE_INITIAL),
                                 ('device-ip-core-readonly-reviewed', IPCORE_REVIEWED)):
            folder = self.root / 'logs' / directory
            self.assertEqual(members[label + '/result.json'], folder / 'result.json')
            self.assertEqual(members[label + '/README.txt'], folder / 'README.txt')
            parsed = json.loads(members[label + '/result.json'].read_text())
            self.assertEqual(parsed, original[directory])
            self.assertIs(parsed['pass'], True)
        self.assertIs(original[IPCORE_INITIAL]['project_candidate_staged'], True)
        self.assertNotIn('checker_sha256', original[IPCORE_INITIAL])
        self.assertIs(original[IPCORE_REVIEWED]['project_candidate_staged'], False)
        self.assertIn('checker_sha256', original[IPCORE_REVIEWED])

    def test_ip_core_schemas_only_contain_fixed_counts_booleans_hashes_and_enums(self):
        original = self.ip_core_reports()
        initial_keys = {'evidence_level', 'pass', 'candidate_identity', 'core_sha256',
                        'radio_operations', 'network_configuration', 'ip_installation',
                        'phone_interop', 'project_candidate_staged', 'kernel_sender_checked',
                        'rules_count', 'stable_complete_views', 'permanent_infinite_addresses',
                        'complete_dump_sets', 'default_rules', 'unique_monotonic_sequences',
                        'socket_port_checked', 'addresses_count', 'core_imported', 'routes_count',
                        'subnet_candidate_available', 'netlink_socket_closed',
                        'independent_baseline_unchanged'}
        counts = {'rules_count': 3, 'complete_dump_sets': 2, 'addresses_count': 2, 'routes_count': 9}
        strings = {'evidence_level', 'candidate_identity', 'core_sha256',
                   'ip_installation', 'phone_interop', 'checker_sha256'}
        for directory, value in original.items():
            expected = initial_keys | ({'checker_sha256'} if directory == IPCORE_REVIEWED else set())
            self.assertEqual(set(value), expected)
            self.assertEqual(value['evidence_level'], 'P011_IPV4_CORE_READONLY')
            self.assertEqual(value['ip_installation'], 'NOT_TESTED')
            self.assertEqual(value['phone_interop'], 'NOT_TESTED')
            self.assertRegex(value['candidate_identity'], r'^[0-9a-f]{16}$')
            for key in ('core_sha256', 'checker_sha256'):
                if key in value:
                    self.assertRegex(value[key], r'^[0-9a-f]{64}$')
            for key, count in counts.items():
                self.assertIs(type(value[key]), int)
                self.assertEqual(value[key], count)
            for key in expected - strings - set(counts):
                self.assertIs(type(value[key]), bool)
            self.assertIs(value['radio_operations'], False)
            self.assertIs(value['network_configuration'], False)

    def test_ip_core_private_records_and_unreviewed_files_are_excluded(self):
        self.ip_core_reports()
        for directory in (IPCORE_INITIAL, IPCORE_REVIEWED):
            folder = self.root / 'logs' / directory
            for relative in ('private-raw/raw_dump_records.json', 'private-raw/result.json',
                             'raw_dump_records.json', 'addresses.json', 'stdout.raw',
                             'journal/owner.json', 'candidate/checker.py', 'binaries/helper',
                             'user/file.txt', 'free-device-output.json'):
                self.write(folder / relative, 'HOST_PRIVATE_IP_CORE_MARKER')
        selected = {name: path for name, path in self.members().items()
                    if name.startswith(('device-ip-core-readonly-initial/',
                                        'device-ip-core-readonly-reviewed/'))}
        self.assertEqual(set(selected), {
            label + '/' + name
            for label in ('device-ip-core-readonly-initial', 'device-ip-core-readonly-reviewed')
            for name in ('result.json', 'README.txt')})
        self.assertTrue(all(b'HOST_PRIVATE_IP_CORE_MARKER' not in path.read_bytes()
                            for path in selected.values()))
        self.assertFalse(any('raw_dump_records' in name for name in self.members()))

    def test_each_ip_core_report_requires_its_own_readme(self):
        for missing_directory in (IPCORE_INITIAL, IPCORE_REVIEWED):
            with self.subTest(directory=missing_directory):
                self.ip_core_reports()
                (self.root / 'logs' / missing_directory / 'README.txt').unlink()
                with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
                    package.collect_members()

    def test_missing_ip_core_reports_not_substituted_or_fabricated(self):
        for directory in (IPCORE_INITIAL, IPCORE_REVIEWED):
            self.write(self.root / 'logs' / directory / 'README.txt', 'HOST incomplete reviewed folder\n')
        self.report(IPCORE_INITIAL + '-unreviewed', {'pass': True}, readme=True)
        self.report('MtaP011-IpCoreReadOnly-20261001-090000-unreviewed', {'pass': True}, readme=True)
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_worker_and_v5_plan_documents_are_exact_optional_checkpoint_paths(self):
        for name in ('WORKER_IMPLEMENTATION_NEXT.md', 'P2P_TRIAL_V5_PLAN.md'):
            path = self.write(self.base / 'docs' / name, 'HOST checkpoint plan; not actual PHONE evidence\n')
            self.write(self.base / 'native' / name, 'HOST_PRIVATE_MARKER')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE_MARKER')
            self.assertEqual(self.members()['documents/' + name], path)
        self.report('MtaP011-DeviceP2pV5-20261001-090000-unreviewed', {'pass': True}, readme=True)
        self.assertEqual(set(self.members()), {'documents/README.md', 'documents/GOAL.md',
            'documents/CURRENT_STATUS.md', 'documents/WORKER_IMPLEMENTATION_NEXT.md',
            'documents/P2P_TRIAL_V5_PLAN.md'})

    def test_missing_worker_and_v5_plan_documents_do_not_create_members(self):
        for name in ('WORKER_IMPLEMENTATION_NEXT.md', 'P2P_TRIAL_V5_PLAN.md'):
            self.write(self.base / 'native' / name, 'HOST wrong non-whitelisted location\n')
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_v5_failure_udp_api_and_owned_ip_host_keep_distinct_fixed_schemas(self):
        original = self.v5_udp_owned_ip_reports()
        members = self.members()
        for label, value in original.items():
            self.assertEqual(json.loads(members[label + '/result.json'].read_text()), value)
        v5, udp, host = (original[name] for name in
                         ('device-p2p-v5-initial-failure', 'device-udp-api-readonly', 'owned-ip-host'))
        self.assertEqual(len(v5), 76)
        self.assertEqual(v5['evidence_level'], 'P011_PRIVATE_P2P_V5_GO_IP_ONLY_TRIAL')
        self.assertIs(v5['pass'], False)
        self.assertEqual(v5['failure_phase'], 'ip_create')
        self.assertIs(v5['cleanup_complete'], False)
        self.assertIs(v5['journal_complete'], False)
        self.assertIs(v5['ip_restored_reported'], False)
        self.assertIs(v5['stock_independent_unchanged'], True)
        self.assertIs(v5['full_ipv4_readback_unchanged'], True)
        self.assertIs(v5['full_ipv6_readback_unchanged'], True)
        self.assertEqual(v5['phone_interop'], 'NOT_TESTED')
        self.assertEqual(v5['ttl_seconds'], 20)
        self.assertEqual(v5['journal_version'], 3)
        self.assertEqual(len(v5['diagnostic_events']), 14)
        self.assertTrue(all(set(event) == {'code', 'stage'} and event['code'] == 0
                            for event in v5['diagnostic_events']))
        self.assertEqual(len(udp), 18)
        self.assertEqual(udp['evidence_level'], 'P011_UDP_PYTHON_API_READONLY')
        self.assertIs(udp['pass'], True)
        self.assertIs(udp['socket_created'], False)
        self.assertIs(udp['ipv4_pktinfo_constant_exposed'], False)
        for key in ('actual_udp_bind', 'dhcp_exchange', 'phone_interop'):
            self.assertEqual(udp[key], 'NOT_TESTED')
        self.assertEqual(len(host), 20)
        self.assertEqual(host['evidence_level'], 'HOST_FAULT_INJECTION')
        self.assertEqual(host['tests_run'], 48)
        self.assertEqual(host['tests_passed'], 48)
        self.assertEqual(host['host_exit_code'], 0)
        self.assertIs(host['original_execution_timestamp_utc'], None)
        self.assertIs(host['provenance']['tests_rerun_for_archive'], False)
        self.assertIs(host['provenance']['original_separate_stdout_file_retained'], False)
        self.assertIs(host['provenance']['original_separate_stderr_file_retained'], False)
        self.assertTrue(all(value is False for value in host['scope'].values()))
        self.assertTrue(all(value == 'NOT_TESTED' for value in host['unverified_layers'].values()))
        content = members['owned-ip-host/unittest.txt'].read_bytes()
        self.assertEqual(host['artifacts'][0]['sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(host['artifacts'][0]['bytes'], len(content))

    def test_new_fixed_events_not_replaced_by_future_unreviewed_candidates(self):
        self.v5_udp_owned_ip_reports()
        self.report('MtaP011-DeviceP2pV5-20261001-090000-unreviewed', {'pass': True}, readme=True)
        self.report('MtaP011-UdpApiReadOnly-20261001-090000-unreviewed', {'pass': True}, readme=True)
        self.write(self.base / 'results/owned-ip-host-20261001-090000-unreviewed/result.json', '{"pass": true}')
        self.write(self.base / 'results/owned-ip-host-20261001-090000-unreviewed/unittest.txt', 'HOST unreviewed\n')
        members = self.members()
        for label, directory in (('device-p2p-v5-initial-failure', V5_FAILURE),
                                 ('device-udp-api-readonly', UDP_API), ('owned-ip-host', OWNED_IP_HOST)):
            self.assertEqual(members[label + '/result.json'].parent.name, directory)
        self.assertIs(json.loads(members['device-p2p-v5-initial-failure/result.json'].read_text())['pass'], False)

    def test_new_fixed_reports_exclude_raw_private_candidates_and_unlisted_outputs(self):
        self.v5_udp_owned_ip_reports()
        folders = (self.root / 'logs' / V5_FAILURE, self.root / 'logs' / UDP_API,
                   self.base / 'results' / OWNED_IP_HOST)
        for folder in folders:
            for relative in ('private-raw/result.json', 'private-raw/raw_dump_records.json',
                             'private-candidate/wpa_supplicant', 'private-candidate/source.py',
                             'raw_dump_records.json', 'stdout.raw', 'stderr.raw',
                             'journal/owner.json', 'binaries/helper', 'user/file.txt', 'free-output.json'):
                self.write(folder / relative, 'HOST_PRIVATE_V5_IP_MARKER')
        self.write(self.base / 'native/private-p2p-runtime-candidate-20261001-v5/runtime/mta_send_wifi.py',
                   'HOST_PRIVATE_V5_IP_MARKER')
        selected = {name: path for name, path in self.members().items()
                    if name.startswith(('device-p2p-v5-initial-failure/', 'device-udp-api-readonly/', 'owned-ip-host/'))}
        self.assertEqual(set(selected), {'device-p2p-v5-initial-failure/result.json',
            'device-p2p-v5-initial-failure/README.txt', 'device-udp-api-readonly/result.json',
            'device-udp-api-readonly/README.txt', 'owned-ip-host/result.json', 'owned-ip-host/unittest.txt'})
        self.assertTrue(all(b'HOST_PRIVATE_V5_IP_MARKER' not in path.read_bytes()
                            for path in selected.values()))
        self.assertFalse(any('private' in name or 'raw_dump_records' in name for name in self.members()))

    def test_new_fixed_reports_require_their_own_companion_file(self):
        for label, directory, filename in (('device-p2p-v5-initial-failure', V5_FAILURE, 'README.txt'),
                                           ('device-udp-api-readonly', UDP_API, 'README.txt'),
                                           ('owned-ip-host', OWNED_IP_HOST, 'unittest.txt')):
            with self.subTest(label=label):
                self.v5_udp_owned_ip_reports()
                folder = self.base / 'results' / directory if label == 'owned-ip-host' else self.root / 'logs' / directory
                (folder / filename).unlink()
                self.write(folder / 'private-raw' / filename, 'HOST wrong private companion\n')
                with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
                    package.collect_members()

    def test_missing_new_fixed_reports_never_create_or_guess_members(self):
        self.report(V5_FAILURE + '-unreviewed', {'pass': True}, readme=True)
        self.report(UDP_API + '-unreviewed', {'pass': True}, readme=True)
        self.write(self.base / 'results' / (OWNED_IP_HOST + '-unreviewed') / 'result.json', '{"pass": true}')
        self.write(self.root / 'logs' / V5_FAILURE / 'README.txt', 'HOST incomplete\n')
        self.write(self.root / 'logs' / UDP_API / 'README.txt', 'HOST incomplete\n')
        self.write(self.base / 'results' / OWNED_IP_HOST / 'unittest.txt', 'HOST incomplete\n')
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_dhcp_socket_review_is_exact_optional_public_document(self):
        self.assertNotIn('documents/DHCP_SOCKET_REVIEW.md', self.members())
        path = self.write(self.base / 'docs/DHCP_SOCKET_REVIEW.md', 'HOST public socket boundary review\n')
        self.write(self.base / 'native/DHCP_SOCKET_REVIEW.md', 'HOST_PRIVATE_MARKER')
        self.write(self.base / 'private-raw/DHCP_SOCKET_REVIEW.md', 'HOST_PRIVATE_MARKER')
        self.assertEqual(self.members()['documents/DHCP_SOCKET_REVIEW.md'], path)
        self.assertEqual(set(self.members()), {'documents/README.md', 'documents/GOAL.md',
            'documents/CURRENT_STATUS.md', 'documents/DHCP_SOCKET_REVIEW.md'})

    def test_v6_diag_host_preserves_pc_memoryjournal_not_actual_device_evidence(self):
        folder, original = self.v6_diag_report()
        members = self.members()
        self.assertEqual(members['v6-gate-diag-host/result.json'], folder / 'result.json')
        self.assertEqual(members['v6-gate-diag-host/unittest.txt'], folder / 'unittest.txt')
        value = json.loads(members['v6-gate-diag-host/result.json'].read_text())
        self.assertEqual(value, original)
        self.assertEqual(len(value), 17)
        self.assertEqual(value['evidence_level'], 'PC_HOST_FAULT_INJECTION_V6DIAG')
        self.assertIs(value['pass'], True)
        self.assertEqual(value['tests_run'], 39)
        self.assertEqual(value['passed'], 39)
        self.assertEqual(value['fixtures'], ['FakeKernel', 'FakeLock', 'MemoryJournal', 'FakeSysfs'])
        self.assertIn('P011 V6 execution', value['unverified'])
        self.assertIn('real journal fsync in this suite', value['unverified'])
        self.assertIn('real IPv4 NEWADDR/DELADDR', value['unverified'])
        self.assertIs(value['scope']['device_actions'], False)
        self.assertIs(value['scope']['formal_freeze'], False)
        self.assertIs(value['scope']['send_available'], False)
        self.assertIs(value['scope']['historical_v5_failure_unchanged'], True)
        provenance = value['provenance']
        self.assertIs(provenance['execution_timestamp_utc'], None)
        self.assertIs(provenance['tests_rerun_for_archive'], False)
        self.assertIs(provenance['separate_stdout_stderr_retained'], False)
        output = members['v6-gate-diag-host/unittest.txt'].read_bytes()
        self.assertEqual(output, provenance['original_tool_output'].replace('\r\n', '\n').encode())
        self.assertEqual(hashlib.sha256(output).hexdigest(), value['artifacts']['unittest']['sha256'])

    def test_v6_diag_host_fixed_path_excludes_future_actual_raw_diff_and_source(self):
        folder, _ = self.v6_diag_report()
        self.write(self.base / 'results/v6diag-host-20261001-090000-unreviewed/result.json', '{"pass": true}')
        self.write(self.base / 'results/v6diag-host-20261001-090000-unreviewed/unittest.txt', 'HOST future\n')
        self.report('MtaP011-DeviceP2pV6diag-20261001-090000-unreviewed', {'pass': True}, readme=True)
        for relative in ('private-raw/result.json', 'private-raw/raw_dump_records.json',
                         'private-candidate/mta_send_wifi.py', 'source/mta_send_wifi.py',
                         'diff.patch', 'stdout.raw', 'stderr.raw', 'journal/owner.json',
                         'binaries/helper', 'free-output.json'):
            self.write(folder / relative, 'HOST_PRIVATE_V6_MARKER')
        self.write(self.base / 'native/private-p2p-runtime-candidate-20261001-v6diag/runtime/mta_send_wifi.py',
                   'HOST_PRIVATE_V6_MARKER')
        members = self.members()
        selected = {name: path for name, path in members.items() if name.startswith('v6-gate-diag-host/')}
        self.assertEqual(selected, {'v6-gate-diag-host/result.json': folder / 'result.json',
                                   'v6-gate-diag-host/unittest.txt': folder / 'unittest.txt'})
        self.assertTrue(all(b'HOST_PRIVATE_V6_MARKER' not in path.read_bytes() for path in selected.values()))
        self.assertFalse(any(name.startswith('device-p2p-v6') for name in members))

    def test_v6_diag_missing_unittest_fails_closed_without_future_or_private_substitute(self):
        folder, _ = self.v6_diag_report()
        (folder / 'unittest.txt').unlink()
        self.write(folder / 'private-raw/unittest.txt', 'HOST wrong private companion\n')
        self.write(self.base / 'results/v6diag-host-20261001-090000-unreviewed/result.json', '{"pass": true}')
        self.write(self.base / 'results/v6diag-host-20261001-090000-unreviewed/unittest.txt', 'HOST wrong future\n')
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_v6_diag_missing_reviewed_result_does_not_fabricate_or_select_future(self):
        self.write(self.base / 'results' / V6_DIAG_HOST / 'unittest.txt', 'HOST incomplete\n')
        self.write(self.base / 'results/v6diag-host-20261001-090000-unreviewed/result.json', '{"pass": true}')
        self.write(self.base / 'results/v6diag-host-20261001-090000-unreviewed/unittest.txt', 'HOST future\n')
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_v6_diag_documents_are_optional_exact_public_paths(self):
        names = ('P2P_IP_V6_DIAG_REVIEW.md', 'P2P_TRIAL_V6DIAG_PLAN.md')
        self.assertTrue(all('documents/' + name not in self.members() for name in names))
        for name in names:
            path = self.write(self.base / 'docs' / name, 'HOST V6 diagnostic checkpoint, not device execution\n')
            self.write(self.base / 'native' / name, 'HOST_PRIVATE_MARKER')
            self.write(self.base / 'private-raw' / name, 'HOST_PRIVATE_MARKER')
            self.assertEqual(self.members()['documents/' + name], path)
        self.assertEqual(set(self.members()), {'documents/README.md', 'documents/GOAL.md',
            'documents/CURRENT_STATUS.md'} | {'documents/' + name for name in names})

    def test_v6_device_fixed_pairs_preserve_before_rf_failure_and_readonly_only_pass(self):
        rows = self.v6_device_admission_reports()
        members = self.members()
        for label, (folder, expected) in rows.items():
            self.assertEqual(members[label + '/result.json'], folder / 'result.json')
            self.assertEqual(members[label + '/README.txt'], folder / 'README.txt')
            self.assertEqual(json.loads(members[label + '/result.json'].read_text()), expected)
        failed = rows['device-v6diag-admission-failure'][1]
        checked = rows['device-prior-journal-readonly'][1]
        self.assertIs(failed['pass'], False)
        self.assertIs(failed['rf_trial_invoked'], False)
        self.assertEqual(failed['error_stage'], 'prior_journals')
        self.assertIs(checked['pass'], True)
        self.assertIs(checked['check_complete'], True)
        self.assertIs(checked['prior_admission_clear'], False)
        self.assertIs(checked['unsafe_exception_observed'], True)
        self.assertEqual(checked['diagnostic']['unsafe_count'], 1)
        self.assertEqual(checked['diagnostic']['records'][0]['reason'], 'historical_manifest_permissions')
        self.assertTrue(all(value is True for name, value in checked.items()
                            if name.endswith('_unchanged')))
        for value in (failed, checked):
            self.assertIs(value['send_available'], False)
            self.assertEqual(value['phone_interop'], 'NOT_TESTED')
        self.assertEqual(checked['ip_installation'], 'NOT_TESTED')

    def test_v6_device_fixed_pairs_exclude_future_private_source_and_permissions_probe(self):
        rows = self.v6_device_admission_reports()
        for directory in ('MtaP011-DeviceP2pV6Diag-20990101-unreviewed',
                          'MtaP011-PriorJournalReadOnly-20990101-unreviewed',
                          'MtaP011-PriorPermissionsReadOnly-20990101-unreviewed'):
            self.report(directory, {'pass': True, 'marker': 'HOST_UNREVIEWED'}, readme=True)
        for folder, _ in rows.values():
            for relative in ('private-raw/result.json', 'private-raw/README.txt',
                             'private-candidate/mta_send_wifi.py', 'source/checker.py',
                             'journal/owner.json', 'stdout.raw', 'free-output.json'):
                self.write(folder / relative, 'HOST_UNREVIEWED')
        selected = {name: path for name, path in self.members().items()
                    if name.startswith(('device-v6diag-', 'device-prior-'))}
        self.assertEqual(selected, {
            label + '/' + filename: folder / filename
            for label, (folder, _) in rows.items() for filename in ('result.json', 'README.txt')})
        self.assertTrue(all(b'HOST_UNREVIEWED' not in path.read_bytes() for path in selected.values()))

    def test_v6_device_each_missing_companion_fails_without_private_or_future_substitution(self):
        rows = self.v6_device_admission_reports()
        for label, (folder, _) in rows.items():
            with self.subTest(label=label):
                (folder / 'README.txt').unlink()
                self.write(folder / 'private-raw/README.txt', 'HOST private companion\n')
                self.report(folder.name + '-future-unreviewed', {'pass': True}, readme=True)
                with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
                    package.collect_members()
                self.write(folder / 'README.txt', 'HOST reviewed synthetic companion\n')

    def test_v6_device_missing_fixed_results_create_no_guessed_or_future_members(self):
        for directory in (V6_ADMISSION_FAILURE, PRIOR_JOURNAL_READONLY):
            self.write(self.root / 'logs' / directory / 'README.txt', 'HOST incomplete pair\n')
            self.report(directory + '-future-unreviewed', {'pass': True}, readme=True)
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_scoped_socket_review_only_uses_exact_optional_public_path(self):
        name = 'SCOPED_SOCKET_REVIEW.md'
        self.assertNotIn('documents/' + name, self.members())
        self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
        self.write(self.base / 'private-raw' / name, 'HOST_UNREVIEWED')
        path = self.write(self.base / 'docs' / name, 'HOST synthetic public API review, not device evidence\n')
        self.assertEqual(self.members()['documents/' + name], path)
        self.assertEqual(set(self.members()), {'documents/README.md', 'documents/GOAL.md',
                                             'documents/CURRENT_STATUS.md', 'documents/' + name})

    def test_permission_facts_exact_pair_not_repair_or_rf_and_no_future(self):
        value = {'evidence_level': 'P011_FIXED_CANDIDATE_PERMISSIONS_READONLY',
                 'pass': True, 'check_complete': True, 'permissions_modified': False,
                 'device_writes': False, 'radio_operations': False,
                 'ip_installation': 'NOT_TESTED', 'phone_interop': 'NOT_TESTED',
                 'diagnostic': {'diagnostic_complete': True, 'pins_verified': True,
                     'permissions_gate_satisfied': False, 'file_count': 16,
                     'files': [{'candidate': alias, 'relative': relative,
                         'mode': 448 if relative.startswith('native/') else 438,
                         'owner_matches_euid': True, 'full_sha_match': True,
                         'size_match': True, 'file_regular': True, 'no_symlink': True,
                         'not_other_writable': relative.startswith('native/')}
                         for alias in ('v5', 'v6') for relative in (
                             'SOURCE.sha256', 'native/mta-wifi-caps', 'native/mta-wpa-supplicant',
                             'runtime/mta_ip.py', 'runtime/mta_ip_lease.py',
                             'runtime/mta_safety.py', 'runtime/mta_send_wifi.py', 'runtime/p011_json.py')]}}
        directory = 'MtaP011-CandidatePermissionsReadOnly-20261001-055734-dd922b01'
        folder = self.report(directory, value, readme=True)
        self.report('MtaP011-CandidatePermissionsReadOnly-20990101-unreviewed',
                    {'pass': True, 'marker': 'HOST_UNREVIEWED'}, readme=True)
        self.write(folder / 'private-raw/permission-files.txt', 'HOST_PRIVATE')
        self.write(folder / 'private-candidate/SOURCE.sha256', 'HOST_PRIVATE')
        members = self.members()
        prefix = 'device-candidate-permissions-readonly/'
        selected = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(selected, {prefix + name: folder / name
                                  for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(selected[prefix + 'result.json'].read_text()), value)
        self.assertFalse(value['diagnostic']['permissions_gate_satisfied'])
        self.assertFalse(value['permissions_modified'])

    def test_permission_pair_missing_companion_does_not_use_raw_or_future(self):
        directory = 'MtaP011-CandidatePermissionsReadOnly-20261001-055734-dd922b01'
        folder = self.report(directory, {'pass': True})
        self.write(folder / 'private-raw/README.txt', 'HOST_PRIVATE')
        self.report(directory + '-future', {'pass': True}, readme=True)
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def permission_normalize_report(self):
        value = {'evidence_level': 'P011_FIXED_CANDIDATE_PERMISSION_NORMALIZATION',
                 'pass': True, 'normalization_complete': True,
                 'permission_write_requested': True, 'permission_program_invoked': True,
                 'radio_operations': False, 'network_configuration': False,
                 'candidate_staged': False, 'chown_requested': False,
                 'rollback_invoked': False, 'recovery_invoked': False, 'retry_invoked': False,
                 'send_available': False, 'ip_installation': 'NOT_TESTED',
                 'phone_interop': 'NOT_TESTED', 'stock_independent_unchanged': True,
                 'full_ipv4_readback_unchanged': True, 'full_ipv6_readback_unchanged': True,
                 'normalization': {'complete': True, 'all_prevalidated_before_writes': True,
                     'change_count_complete': True, 'descriptors_all_closed': True,
                     'file_count': 16, 'prevalidated_count': 16, 'fchmod_attempt_count': 16,
                     'partial_change_count': 16, 'readback_count': 16, 'fd_open_count': 16,
                     'fd_close_attempt_count': 16, 'fd_closed_count': 16, 'fd_close_failed_count': 0,
                     'files': [{'candidate': alias, 'relative': relative,
                         'old_mode': 448 if relative.startswith('native/') else 438,
                         'new_mode': 320 if relative.startswith('native/') else 256,
                         'target_mode': 320 if relative.startswith('native/') else 256,
                         'prevalidated': True, 'fchmod_attempted': True, 'changed': True,
                         'mode_observed': True, 'readback_confirmed': True,
                         'identity_unchanged': True, 'hash_unchanged': True}
                         for alias in ('v5', 'v6') for relative in (
                             'SOURCE.sha256', 'native/mta-wifi-caps', 'native/mta-wpa-supplicant',
                             'runtime/mta_ip.py', 'runtime/mta_ip_lease.py',
                             'runtime/mta_safety.py', 'runtime/mta_send_wifi.py', 'runtime/p011_json.py')]}}
        return self.report(PERMISSIONS_NORMALIZE, value, readme=True), value

    def test_normalization_exact_pair_keeps_permission_write_and_old_failure_no_future(self):
        folder, value = self.permission_normalize_report()
        old = self.v6_device_admission_reports()
        self.report('MtaP011-CandidatePermissionsNormalize-20990101-unreviewed',
                    {'pass': True, 'marker': 'HOST_UNREVIEWED'}, readme=True)
        for relative in ('private-raw/result.json', 'private-raw/README.txt',
                         'private-candidate/SOURCE.sha256', 'source/normalizer.py',
                         'journal/owner.json', 'stdout.raw', 'free-output.json'):
            self.write(folder / relative, 'HOST_UNREVIEWED')
        members = self.members()
        prefix = 'device-candidate-permissions-normalize/'
        selected = {name: path for name, path in members.items() if name.startswith(prefix)}
        self.assertEqual(selected, {prefix + name: folder / name
                                  for name in ('result.json', 'README.txt')})
        self.assertEqual(json.loads(selected[prefix + 'result.json'].read_text()), value)
        self.assertTrue(value['permission_write_requested'])
        self.assertTrue(value['permission_program_invoked'])
        self.assertFalse(value['radio_operations'])
        self.assertFalse(value['network_configuration'])
        self.assertFalse(value['send_available'])
        self.assertEqual(value['ip_installation'], 'NOT_TESTED')
        self.assertEqual(value['phone_interop'], 'NOT_TESTED')
        failure = json.loads(members['device-v6diag-admission-failure/result.json'].read_text())
        self.assertEqual(failure, old['device-v6diag-admission-failure'][1])
        self.assertFalse(failure['pass'])
        self.assertFalse(failure['rf_trial_invoked'])
        self.assertTrue(all(b'HOST_UNREVIEWED' not in path.read_bytes() for path in members.values()))

    def test_normalization_missing_companion_rejects_raw_or_future_substitution(self):
        folder = self.report(PERMISSIONS_NORMALIZE, {'pass': True, 'permission_write_requested': True})
        self.write(folder / 'private-raw/README.txt', 'HOST_PRIVATE')
        self.report(PERMISSIONS_NORMALIZE + '-future', {'pass': True}, readme=True)
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()

    def test_normalization_missing_fixed_result_creates_no_future_or_guessed_member(self):
        self.write(self.root / 'logs' / PERMISSIONS_NORMALIZE / 'README.txt', 'HOST incomplete pair\n')
        self.report(PERMISSIONS_NORMALIZE + '-future', {'pass': True}, readme=True)
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_permission_and_lifecycle_docs_use_only_three_exact_optional_public_paths(self):
        names = ('CANDIDATE_PERMISSIONS_REVIEW.md', 'P2P_V6DIAG_PERMISSIONS_ENTRY.md',
                 'TRANSPORT_LIFECYCLE_REVIEW.md')
        for name in names:
            self.write(self.base / 'native' / name, 'HOST_UNREVIEWED')
            self.write(self.base / 'private-raw' / name, 'HOST_UNREVIEWED')
            self.write(self.base / 'docs' / (name + '.future'), 'HOST_UNREVIEWED')
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})
        expected = {}
        for name in names:
            expected['documents/' + name] = self.write(
                self.base / 'docs' / name, 'HOST synthetic public review; not device acceptance\n')
        members = self.members()
        self.assertEqual({name: path for name, path in members.items() if name in expected}, expected)
        self.assertEqual(set(members), set(expected) | {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def v6_permissions_entry_report(self):
        value = {'evidence_level': 'P011_PRIVATE_V6DIAG_PERMISSION_NORMALIZED_ENTRY',
                 'pass': False, 'ttl_seconds': 20, 'journal_version': 3,
                 'rf_trial_invoked': True, 'ip_trial_requested': True,
                 'permissions_modified': False, 'candidate_staged': False,
                 'recovery_invoked': False, 'retry_invoked': False,
                 'early_init_success_reported': True, 'diagnostics_valid': True,
                 'diagnostic_events': [{'stage': stage, 'code': 0} for stage in (
                     'init_enter', 'capability', 'early_param', 'initial_type_gate',
                     'initial_mode', 'interface_up', 'driver_finish', 'driver_init_result',
                     'wps_init', 'eapol_init', 'control_init', 'p2p_init',
                     'go_deinit_preserved', 'driver_deinit')],
                 'failure_phase': 'ip_create', 'failure_errno': 0,
                 'failure_reason': 'lease_error', 'netlink_command': 'not_recorded',
                 'ip_creation_gate': {'reason': 'interface_l3', 'gate': 'interface_l3',
                     'observations': {name: True for name in (
                         'flags_read_valid', 'flags_up', 'carrier_read_valid',
                         'carrier_is_up', 'sysfs_identity_match', 'go_identity_match')}},
                 'go_ip_ready_event': False, 'cleanup_event': False, 'cleanup_complete': False,
                 'failed_trial_cleanup_complete': True, 'failed_trial_socket_closed_reported': True,
                 'failed_trial_no_radio_mutation_reported': False,
                 'stock_independent_unchanged': True, 'full_ipv4_readback_unchanged': True,
                 'full_ipv6_readback_unchanged': True, 'global_pending_clear_independent': True,
                 'journal_stage': 'reconciled', 'journal_ip_stage': 'none',
                 'journal_ip_receipt_restored': False, 'journal_complete': False,
                 'dhcp_configuration': False, 'ip_application_sockets': False,
                 'ui_started': False, 'send_available': False, 'phone_interop': 'NOT_TESTED'}
        return self.report(V6_PERMISSIONS_ENTRY, value, readme=True), value

    def test_v6_permissions_entry_exact_pair_preserves_l3_rejection_not_carrier_or_ip_pass(self):
        folder, value = self.v6_permissions_entry_report()
        old_reports = self.v6_device_admission_reports()
        _, normalized = self.permission_normalize_report()
        members = self.members()
        prefix = 'device-v6diag-permissions-entry/'
        self.assertEqual({name: path for name, path in members.items() if name.startswith(prefix)},
                         {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        selected = json.loads(members[prefix + 'result.json'].read_text())
        self.assertEqual(selected, value)
        self.assertFalse(selected['pass'])
        self.assertTrue(selected['rf_trial_invoked'])
        self.assertTrue(selected['ip_trial_requested'])
        self.assertEqual(selected['ip_creation_gate']['reason'], 'interface_l3')
        self.assertTrue(all(selected['ip_creation_gate']['observations'].values()))
        self.assertEqual(len(selected['diagnostic_events']), 14)
        self.assertTrue(all(row['code'] == 0 for row in selected['diagnostic_events']))
        self.assertFalse(selected['go_ip_ready_event'])
        self.assertFalse(selected['cleanup_complete'])
        self.assertTrue(selected['failed_trial_cleanup_complete'])
        self.assertEqual(selected['journal_stage'], 'reconciled')
        self.assertEqual(selected['journal_ip_stage'], 'none')
        self.assertFalse(selected['dhcp_configuration'])
        self.assertFalse(selected['ip_application_sockets'])
        self.assertFalse(selected['ui_started'])
        self.assertFalse(selected['send_available'])
        self.assertEqual(selected['phone_interop'], 'NOT_TESTED')
        old = json.loads(members['device-v6diag-admission-failure/result.json'].read_text())
        self.assertEqual(old, old_reports['device-v6diag-admission-failure'][1])
        self.assertFalse(old['rf_trial_invoked'])
        repaired = json.loads(members['device-candidate-permissions-normalize/result.json'].read_text())
        self.assertEqual(repaired, normalized)
        self.assertTrue(repaired['permission_write_requested'])
        self.assertFalse(selected['permissions_modified'])

    def test_v6_permissions_entry_excludes_future_raw_source_journal_and_extra_files(self):
        folder, _ = self.v6_permissions_entry_report()
        for directory in (V6_PERMISSIONS_ENTRY + '-future',
                          'MtaP011-DeviceP2pV6DiagPermissions-20990101-unreviewed'):
            self.report(directory, {'pass': True, 'marker': 'HOST_UNREVIEWED'}, readme=True)
        for relative in ('private-raw/result.json', 'private-raw/README.txt',
                         'private-candidate/SOURCE.sha256', 'source/entry.py',
                         'journal/owner.json', 'stdout.raw', 'free-output.json'):
            self.write(folder / relative, 'HOST_UNREVIEWED')
        prefix = 'device-v6diag-permissions-entry/'
        members = self.members()
        self.assertEqual({name: path for name, path in members.items() if name.startswith(prefix)},
                         {prefix + name: folder / name for name in ('result.json', 'README.txt')})
        self.assertTrue(all(b'HOST_UNREVIEWED' not in path.read_bytes() for path in members.values()))

    def test_v6_permissions_entry_missing_pair_no_private_future_or_fabricated_member(self):
        folder = self.report(V6_PERMISSIONS_ENTRY, {'pass': False, 'rf_trial_invoked': True})
        self.write(folder / 'private-raw/README.txt', 'HOST_PRIVATE')
        self.report(V6_PERMISSIONS_ENTRY + '-future', {'pass': True}, readme=True)
        with self.assertRaisesRegex(ValueError, 'Missing or linked public evidence'):
            package.collect_members()
        (folder / 'result.json').unlink()
        self.write(folder / 'README.txt', 'HOST incomplete public pair\n')
        self.assertEqual(set(self.members()), {
            'documents/README.md', 'documents/GOAL.md', 'documents/CURRENT_STATUS.md'})

    def test_synthetic_manifest_preserves_all_events_bytes_crc_and_sha(self):
        self.histories()
        self.no_rf_reports()
        self.ip_dump_report()
        self.ip_core_reports()
        self.v5_udp_owned_ip_reports()
        self.v6_diag_report()
        v6_device_reports = self.v6_device_admission_reports()
        _, normalized = self.permission_normalize_report()
        _, permissions_entry = self.v6_permissions_entry_report()
        for name in ('OWNED_IP_CORE.md', 'OWNED_IP_LEASE_REVIEW.md',
                     'WORKER_IMPLEMENTATION_NEXT.md', 'P2P_TRIAL_V5_PLAN.md', 'DHCP_SOCKET_REVIEW.md',
                     'P2P_IP_V6_DIAG_REVIEW.md', 'P2P_TRIAL_V6DIAG_PLAN.md',
                     'CANDIDATE_PERMISSIONS_REVIEW.md', 'P2P_V6DIAG_PERMISSIONS_ENTRY.md',
                     'TRANSPORT_LIFECYCLE_REVIEW.md'):
            self.write(self.base / 'docs' / name, 'HOST public owned IP document\n')
        self.write(self.base / 'native/P2P_V3_TRIAL_FAILURE_REVIEW.md', 'HOST public review\n')
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
                content = bundle.read(row['name'])
                self.assertEqual(content, expected[row['name']].read_bytes())
                self.assertEqual(row['sha256'], hashlib.sha256(content).hexdigest())
            self.assertFalse(json.loads(bundle.read('device-normal-reboot-initial/result.json'))['pass'])
            self.assertTrue(json.loads(bundle.read('device-boot-readonly/result.json'))['pass'])
            self.assertFalse(json.loads(bundle.read('device-wpa-version-initial/result.json'))['pass'])
            config = json.loads(bundle.read('device-wpa-config-norf/result.json'))
            self.assertTrue(config['pass'])
            self.assertEqual(config['go_formation'], 'NOT_TESTED')
            dump = json.loads(bundle.read('device-ip-dump-readonly/result.json'))
            self.assertEqual(dump['ip_installation'], 'NOT_TESTED')
            self.assertEqual(dump['phone_interop'], 'NOT_TESTED')
            initial = json.loads(bundle.read('device-ip-core-readonly-initial/result.json'))
            reviewed = json.loads(bundle.read('device-ip-core-readonly-reviewed/result.json'))
            self.assertIs(initial['pass'], True)
            self.assertIs(reviewed['pass'], True)
            self.assertIs(initial['project_candidate_staged'], True)
            self.assertIs(reviewed['project_candidate_staged'], False)
            self.assertNotIn('checker_sha256', initial)
            self.assertIn('checker_sha256', reviewed)
            for value in (initial, reviewed):
                self.assertEqual(value['ip_installation'], 'NOT_TESTED')
                self.assertEqual(value['phone_interop'], 'NOT_TESTED')
            self.assertFalse(any(name.startswith('device-p2p-v5/') for name in bundle.namelist()))
            v5 = json.loads(bundle.read('device-p2p-v5-initial-failure/result.json'))
            self.assertIs(v5['pass'], False)
            self.assertIs(v5['cleanup_complete'], False)
            self.assertIs(v5['journal_complete'], False)
            self.assertIs(v5['stock_independent_unchanged'], True)
            udp = json.loads(bundle.read('device-udp-api-readonly/result.json'))
            self.assertEqual(udp['actual_udp_bind'], 'NOT_TESTED')
            self.assertIs(udp['socket_created'], False)
            host = json.loads(bundle.read('owned-ip-host/result.json'))
            self.assertEqual(host['evidence_level'], 'HOST_FAULT_INJECTION')
            self.assertEqual(host['tests_run'], 48)
            self.assertEqual(host['unverified_layers']['p011_ip_install_restore'], 'NOT_TESTED')
            v6 = json.loads(bundle.read('v6-gate-diag-host/result.json'))
            self.assertEqual(v6['evidence_level'], 'PC_HOST_FAULT_INJECTION_V6DIAG')
            self.assertEqual(v6['tests_run'], 39)
            self.assertIn('MemoryJournal', v6['fixtures'])
            self.assertIn('real journal fsync in this suite', v6['unverified'])
            self.assertIs(v6['scope']['device_actions'], False)
            self.assertEqual(bundle.read('v6-gate-diag-host/unittest.txt'),
                             v6['provenance']['original_tool_output'].replace('\r\n', '\n').encode())
            self.assertFalse(any(name.startswith('device-p2p-v6') for name in bundle.namelist()))
            for label, (_, expected_value) in v6_device_reports.items():
                self.assertEqual(json.loads(bundle.read(label + '/result.json')), expected_value)
            failure = json.loads(bundle.read('device-v6diag-admission-failure/result.json'))
            self.assertIs(failure['pass'], False)
            self.assertIs(failure['rf_trial_invoked'], False)
            readonly = json.loads(bundle.read('device-prior-journal-readonly/result.json'))
            self.assertIs(readonly['pass'], True)
            self.assertIs(readonly['check_complete'], True)
            self.assertIs(readonly['prior_admission_clear'], False)
            self.assertEqual(readonly['diagnostic']['records'][0]['reason'], 'historical_manifest_permissions')
            self.assertEqual(readonly['ip_installation'], 'NOT_TESTED')
            self.assertIs(readonly['full_ipv4_readback_unchanged'], True)
            self.assertIs(readonly['full_ipv6_readback_unchanged'], True)
            normalized_zip = json.loads(bundle.read('device-candidate-permissions-normalize/result.json'))
            self.assertEqual(normalized_zip, normalized)
            self.assertIs(normalized_zip['permission_write_requested'], True)
            self.assertIs(normalized_zip['permission_program_invoked'], True)
            self.assertIs(normalized_zip['radio_operations'], False)
            self.assertIs(normalized_zip['network_configuration'], False)
            self.assertEqual(normalized_zip['normalization']['fd_closed_count'], 16)
            self.assertEqual(normalized_zip['normalization']['fd_close_failed_count'], 0)
            for row in normalized_zip['normalization']['files']:
                expected_mode = 0o500 if row['relative'].startswith('native/') else 0o400
                self.assertEqual(row['new_mode'], expected_mode)
                self.assertEqual(row['target_mode'], expected_mode)
                self.assertIs(row['hash_unchanged'], True)
            self.assertEqual(normalized_zip['ip_installation'], 'NOT_TESTED')
            self.assertEqual(normalized_zip['phone_interop'], 'NOT_TESTED')
            entry_zip = json.loads(bundle.read('device-v6diag-permissions-entry/result.json'))
            self.assertEqual(entry_zip, permissions_entry)
            self.assertIs(entry_zip['pass'], False)
            self.assertIs(entry_zip['rf_trial_invoked'], True)
            self.assertEqual(entry_zip['ip_creation_gate']['reason'], 'interface_l3')
            self.assertIs(entry_zip['ip_creation_gate']['observations']['carrier_is_up'], True)
            self.assertIs(entry_zip['failed_trial_cleanup_complete'], True)
            self.assertIs(entry_zip['go_ip_ready_event'], False)
            self.assertFalse(any('raw_dump_records' in name for name in bundle.namelist()))
        verification = json.loads(bundle_path.with_suffix('.verification.json').read_text())
        self.assertTrue(verification['pass'])
        self.assertTrue(verification['crc_verified'])
        self.assertTrue(verification['sha256_all_members_verified'])
        self.assertEqual(verification['member_count'], len(expected))
        self.assertEqual(verification['zip_sha256'], hashlib.sha256(bundle_path.read_bytes()).hexdigest())

    def test_existing_manifest_guard_rejects_member_sha_mismatch(self):
        original_read = Path.read_bytes
        target = self.base / 'README.md'
        def altered_read(path):
            return b'HOST different manifest content' if path == target else original_read(path)
        with mock.patch.object(Path, 'read_bytes', altered_read), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'independent SHA-256 failed'):
                package.main()
        self.assertFalse(list((self.base / 'results').glob('*.verification.json')))


if __name__ == '__main__':
    unittest.main()
