"""Fixed receive-filecenter-v1 envelopes using the unchanged formal-v3 graph.

Default HOST SOURCE only. --check-device uses the fresh original P011 Owner,
with the trusted one-shot policy requested, but issues no discover/RF action.
Service PASS requires actual pending_exists refusal, zero claim/Session, original
revocation/closure and unchanged stock/old-record baseline. It is not a receive
or phone PASS. No pending content handling, cleanup, repair or bypass exists.
Optional --ui selects one original 600-second constructor profile, including
startup time. It never renews READY, Owner, Gate, Session or cleanup periods.
There is no automatic receive action. The focused service mode remains the
60-second refusal diagnostic; runtime75 roots/manifests are reused unchanged.
Nine original v3 role sources plus the new runner/worker and short-line envelopes
are syntax/literal crosschecked. Unchanged private/parser sources are byte checked,
not re-executed or retested. Raw streams and source snapshots stay private.
The public ZIP contains scalar result fields and fixed explanatory text only.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_filecenter_v1_check.py'
CHECKER = ('host/device_receive_startup_readonly_v4_check.py', 27003,
           '4ed9c5eb9403f81d967cce91bf21d71e2230d82e49e7d8dfb1d178a353311cbf')
MANIFEST = ('host/formal_receive_v3_definition_manifest.json', 7795,
    'd1dabbdbc070cf81f5809093cc2adbdac939bbe48547e31c8674b9eaa2458c96')
PRIVATE_MANIFEST = ('host/formal_receive_v3_private_source_manifest.json', 8133,
    '1da411676f7e368cd188bb8789564aeed8dbaa780f71e7ec859e6f30f0dcc483')
PREVIOUS_PRIVATE_SHA = '47dfc262bc1c3fdddf74bb34c52a387f15a00d6f9f2ba28de7397494bbef538c'
RUNNER = ('candidate/receive-interactive-v1/runtime/mta_formal_receive_session.py', 79209,
    'ad254568bded664a61b197eff0e1155b19bcf9c8ba4b6bb684ba4e981564a7ad')
WORKER = ('candidate/receive-filecenter-v1/runtime/ui_session.py', 89778,
    '89c2af00763f86393aa39b528ec01615adfd04b69a4866b747fd41bbfdd74147')
VALIDATOR = ('candidate/receive-filecenter-v1/runtime/ui_assets.py', 12509,
             '63080e070df39cd10a94e6a8d1f3e2bb3d2e8a6fd877f78c334fc8adb87360a5')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
CMDS = (
    ('HOST_MTA_RECEIVE_FILECENTER_V1_CHECK.cmd', 255,
     '1b4885eb9e153fc0a0ada68e5e2f05883187ab89920083c12ca045415a02d917'),
    ('TEST_MTA_RECEIVE_FILECENTER_V1.cmd', 258,
     '4f8120395fc96e1c1a684539f8fc896a35ed22da694f11cc7eeb0fd30ff410c0'),
)
FILECENTER_SOURCES = (
    ('mta_toolbox_json', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('mta_toolbox_minhttp', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py', 9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
    ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('mta_toolbox_metrics', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py', 4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('mta_toolbox_audio', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('mta_toolbox_server', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py', 19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('mta_filecenter_audio', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_audio.py', 8773, 'dd559da62af71042b11ada6ba26ee574548daace3650b9a9e99f8dbfe737d154'),
    ('mta_filecenter_storage', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py', 4581, '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
    ('mta_filecenter_companion', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_companion.py', 23598, '06508a083f2865b143c2ada6f52b86f87f9514c57b878bb1ece59c24f73c8813'),
)
FILECENTER_SOURCE_BYTES = 91295
FILECENTER_SOURCE_CAP = 131072
BUNDLE_SESSION = 'b6a84fe755092535bb996f40'
BUNDLE = 'out/mta-ui-' + BUNDLE_SESSION
BUNDLE_PAYLOAD_PINS = (
    ('Bridge.qml', 1007, '73454ae237dcfc75cac8f82045bde9fbf24339797ece9def1dc7b972cc0c96ae'),
    ('FormalEntry.qml', 4079, '2310e99d70e53903e390598a82f9d2c46ae03c1621bc0fa4505c39349830cb3d'),
    ('ReceiveComposition.qml', 401, '6f1701b31faa62822dcf3e51afd74e001c000d588c6df1cba8b6700e8320ac39'),
    ('Z03.mta-ui-candidate', 4103844, '6e8d5aab7a9c0af6e83ba2d4eb09c37054f175de294169c099357f300aef985c'),
    ('mta/MtaButton.qml', 757, '5abb4dabbd735ef4a071e8e10a65cf5c946e505cceb2373a12fa5f54827d1339'),
    ('mta/MtaHost.qml', 6341, 'e610b343fe4058bb89d45ee65cb14bdd4471363b56a737d85ab5c51297e42f11'),
    ('mta/MtaKeyboard.qml', 5344, '3241344572163deff5bc195cfb06dc5647f76861c03736f99a331d5bb53ef661'),
    ('mta/MtaLabel.qml', 351, 'e6298ebb141e4eba23b7acd1dee6900c141d1065ed194be953d1b3daff77eaa3'),
    ('mta/MtaPage.qml', 26088, '2e63016d806f890703c5d361b35cc80d2e092e55a2714088f27dcb948ef5c44e'),
    ('mta/MtaTheme.js', 261, 'b795cd24c1bae4c9423c6c9c3e45303b0494c267a897715c4f8eab14f8f12f2c'),
    ('toolbox/Button.qml', 665, 'ef4f1f83c198ae40e56982eec7d1ee87d36185fae9bbf1b15ea8853b64dcb015'),
    ('toolbox/ExtensionPage.qml', 10109, 'e2ea4ac96acda29509df272001599be9410d5989a2400bfaef73901378062093'),
    ('toolbox/FilesPage.qml', 11639, '5f1b4255211f4369f64dfc24eddcc565d6e6a64f708e181e15b68828376bd1e1'),
    ('toolbox/Label.qml', 269, '4f109dd7591c7363dc95883ca2c13cf43c3b9c9f461d72238d1567a52bd949fc'),
    ('toolbox/MtaEmbedded.qml', 6543, 'cf5e0c34eae957e8f6ebd5c0641ff7d6d177cb8407db3957049255e6e94e095b'),
    ('toolbox/NativeIcon.qml', 1999, '08baa5b5b7176fc5abaa59c5ef261f0474c05565838a68fa6c110aed80867f4d'),
    ('toolbox/Theme.js', 244, '308cc441d29a5d39e61e0418ad0b4dfbb3efa2be6ce0bf6e80577c73479d2edb'),
    ('toolbox/VideoPane.qml', 705, 'e09873e298aa6b762051ab866ca82ea5b44f0d2988ab97e6ad6719c947934651'),
)
BUNDLE_MANIFEST_PIN = ('SOURCE.sha256', 1603, 'b334d5ebc0598ca0583406efed9c063894e30c97186e12b28846545a8600ad24')
BUNDLE_PINS = BUNDLE_PAYLOAD_PINS + (BUNDLE_MANIFEST_PIN,)
ROOT_NAMES = ('Bridge.qml', 'FormalEntry.qml', 'ReceiveComposition.qml', 'SOURCE.sha256',
              'Z03.mta-ui-candidate', 'mta', 'toolbox')
MTA_NAMES = ('MtaButton.qml', 'MtaHost.qml', 'MtaKeyboard.qml', 'MtaLabel.qml', 'MtaPage.qml', 'MtaTheme.js')
TOOLBOX_NAMES = ('Button.qml', 'ExtensionPage.qml', 'FilesPage.qml', 'Label.qml',
                 'MtaEmbedded.qml', 'NativeIcon.qml', 'Theme.js', 'VideoPane.qml')
HELPERS = (
    ('mta-bluez-helper',
     'results/receive-radio-baseline-build-20261004-112415-de67547c/mta-bluez-radio-baseline',
     74920, 'c06398ddae281cf4a6f8a41953baf84795992f8f3e3769baebaf11f6d9964181'),
    ('mta-network-helper', 'out/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
    ('mta-connman-observer',
     'results/receive-network-observer-build-20261004-120127-0ce26786/mta-connman-observer',
     46008, '5f2612224a3db35d8f0850adf10d1fece7094bff6387521c185570c4be8068e2'),
)
WPA = ('mta-wpa-supplicant', 'native/private-p2p-candidate-20261001-v2/mta-wpa-supplicant',
       1351192, 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301')
MONITOR = ('receive_monitor', 'candidate/formal-ui-receive-monitor-v1/runtime/receive_monitor.py',
           13963, 'fe2a8bab0db21c45c6fe3d0a4733029492c8617d57ddbc9f296888c8c6837e36')
MODULE_NAMES = (
    'mta_client_executor', 'p011_json', 'mta_protocol', 'mta_storage', 'mta_files',
    'mta_crypto', 'mta_transfer_session', 'mta_dhcp', 'mta_dhcp_server', 'mta_scoped_sockets',
    'mta_transport', 'mta_sender', 'mta_send_worker', 'mta_scan_handoff', 'mta_wifi', 'minhttp',
    'mta_client_control_frame', 'mta_client_connect_handoff', 'mta_client_tmp_alias',
    'mta_client_startup_readonly', 'mta_client_receive_factory', 'mta_client_state_bridge',
    'mta_go_deployment', 'mta_send_preparation', 'mta_go_readonly_parent',
    'mta_go_send_publication', 'mta_go_send_bridge', 'mta_go_readonly_terminal_parent',
    'mta_receive_radio_baseline', 'mta_receive_network', 'mta_receive_barrier',
    'mta_receive_trial', 'mta_service',
    'mta_client_receive_boot', 'mta_client_service_owner',
)
PRIVATE_MODULE_NAMES = (
    'p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc', 'mta_client_caps',
    'mta_client_caps_transport', 'mta_client_baseline', 'mta_client_journal_codec',
    'mta_client_coordination', 'mta_client_files', 'mta_client_pending', 'mta_client_store',
    'mta_client_process_owner', 'mta_client_launch_registration', 'mta_client_two_phase_lease',
    'mta_p2p_client_ctrl', 'mta_client_wpa_status', 'mta_protocol', 'mta_client_control_frame',
    'mta_client_kernel_proof', 'mta_client_connection', 'mta_client_linux_provider',
    'mta_client_executor', 'mta_dhcp', 'mta_dhcp_client_core', 'mta_dhcp_client',
    'mta_client_dora', 'mta_client_dynamic_ip', 'mta_client_peer', 'mta_scoped_sockets',
    'mta_storage', 'mta_transport', 'mta_client_transfer',
)
CHANGED_ROLES = ('mta_client_executor', 'mta_client_receive_factory',
                 'mta_client_state_bridge', 'mta_service', 'mta_client_receive_boot',
                 'mta_client_service_owner', 'mta_receive_barrier', 'mta_receive_trial',
                 'mta_client_connect_handoff')
STATE_ALIAS = '/tmp/p011-mta-formal-receive-v3'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-v3'
STARTUP_BOOL_FIELDS = ('startup_readonly_called', 'startup_readonly_verified',
                       'startup_baseline_collected', 'startup_status_verified',
                       'startup_resources_closed')
TRIAL_BOOL_FIELDS = ('requested', 'available', 'claimed', 'session_attached', 'revoked',
                    'expired', 'startup_verified', 'probe_verified', 'radio_known',
                    'barrier_clear', 'network_spec_verified', 'restoration_verified', 'phone_verified')
TRIAL_FIELDS = frozenset(TRIAL_BOOL_FIELDS + ('claim_count', 'reason'))
TRIAL_REASONS = ('not_requested', 'ready', 'claimed', 'revoked', 'expired',
    'owner_context', 'source_changed', 'startup_unknown', 'probe_unknown',
    'radio_unknown', 'radio_unavailable', 'radio_busy', 'network_spec_unknown',
    'barrier_unknown', 'state_not_idle', 'claim_changed', 'already_claimed',
    'session_unknown', 'owner_stopped', 'owner_closed', 'cancelled',
    'state_closing', 'operation_failed', 'session_failed',
    'not_started', 'clear', 'wrong_worker', 'deadline', 'unsupported_platform',
    'unsafe_anchor', 'anchor_changed', 'alias_changed', 'pending_exists',
    'pending_symlink', 'client_root_missing', 'client_history',
    'inventory_unknown', 'descriptor_unknown', 'io_error', 'close_unknown', 'already_attempted')
UI_COUNT_FIELDS = ('startup_status_count', 'startup_proc_reader_count', 'receive_trial_claim_count')
UI_TRIAL_BOOL_FIELDS = ('receive_trial_policy_requested', 'auto_receive_action_issued',
                       'receive_trial_initial_observed', 'receive_trial_initial_available',
                       'receive_trial_claimed', 'receive_trial_session_attached',
                       'receive_trial_terminal_observed', 'receive_trial_terminal_revoked')
UI_INTERACTIVE_BOOL_FIELDS = ('interactive_window_requested', 'interactive_window_expired',
                              'interactive_window_bound')
UI_FILECENTER_BOOL_FIELDS = ('filecenter_constructed', 'filecenter_credentials_issued',
                            'filecenter_close_called', 'filecenter_closed', 'filecenter_http_observed')
UI_REASON_FIELDS = ('reason', 'receive_trial_initial_reason', 'receive_trial_terminal_reason')
UI_BOOL_FIELDS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
                  'credentials_removed', 'candidate_exited', 'stock_restored',
                  'guardian_exited', 'worker_fds_closed', 'radio_admission',
                  'original_ui_exited', 'physical_ui_verified', 'resource_pending') + STARTUP_BOOL_FIELDS + UI_TRIAL_BOOL_FIELDS + UI_INTERACTIVE_BOOL_FIELDS + UI_FILECENTER_BOOL_FIELDS
UI_FIELDS = frozenset(UI_BOOL_FIELDS + UI_COUNT_FIELDS + UI_REASON_FIELDS)
UI_REASONS = (
    'not_started', 'ui_finished', 'session_failed', 'read_budget', 'boot',
    'pid', 'process_stat', 'pid_changed', 'process_unknown', 'process_exec_changed',
    'boot_changed', 'self_signal', 'candidate_identity', 'process_did_not_exit',
    'process_budget', 'foreign_candidate', 'process_race_budget', 'stock_file_identity',
    'hash_budget', 'hash_changed', 'pipe_frame', 'pipe_write', 'pipe_budget',
    'private_core_limit', 'inherited_fd_changed', 'inherited_fd_close',
    'guardian_fd_offset', 'guardian_inherited_fd', 'guardian_stdio',
    'inherited_fd_unknown', 'inherited_fd_duplicate', 'duplicate_close_frame',
    'restore_without_close_report', 'duplicate_candidate_frame', 'candidate_frame',
    'guardian_frame', 'worker_not_stopped', 'candidate_inventory', 'candidate_remains',
    'launcher_missing', 'stock_pins_changed', 'control_changed', 'guardian_after_write',
    'fresh_worker', 'worker_threads', 'source_pin', 'artifacts', 'assets_identity',
    'stop_requested', 'raw_file', 'raw_write', 'raw_close', 'pipe_fd',
    'asset_directory_changed', 'credentials_changed', 'credentials_remove',
    'stock_pins', 'private_assets_required', 'asset_binding', 'other_ui_trial',
    'stock_identity', 'stock_topology', 'stock_ui', 'stock_launcher', 'wayland',
    'fork_boundary', 'guardian_parent_fd_close', 'guardian_not_armed',
    'guardian_armed_frame', 'rf_gate_open', 'credential_pair', 'credential_file',
    'credential_write', 'credential_identity', 'credential_close', 'guardian_missing',
    'launcher_not_stopped', 'candidate_start', 'ui_log_identity', 'ui_writer_close',
    'closed_service_changed', 'ui_log_budget', 'qml_failed', 'qml_ready_timeout',
    'guardian_eof_close', 'guardian_result_frame', 'startup_observation', 'receive_trial_observation',
    'receive_ui_inventory', 'interactive_window_expired', 'interactive_window_changed',
    'interactive_clock_unknown', 'filecenter_source', 'filecenter_owner',
    'filecenter_namespace', 'filecenter_original',
    'audio_guardian_ack', 'audio_guardian_ack_timeout', 'audio_guardian_actor',
    'audio_guardian_cancel', 'audio_guardian_clock', 'audio_guardian_command',
    'audio_guardian_deadline', 'audio_guardian_eof', 'audio_guardian_exec_changed',
    'audio_guardian_frame', 'audio_guardian_missing', 'audio_guardian_parent',
    'audio_guardian_pid_changed', 'audio_guardian_pipe', 'audio_guardian_program',
    'audio_guardian_registration_pending', 'audio_guardian_source',
    'audio_guardian_stop_pending', 'audio_guardian_ticket', 'audio_wrapper_exited',
    'audio_wrapper_not_stopped',
)
UI_SUCCESS = ('complete', 'ui_ready', 'ui_http_observed', 'owner_close_verified',
              'credentials_removed', 'candidate_exited', 'stock_restored',
              'guardian_exited', 'worker_fds_closed', 'original_ui_exited',
              'receive_trial_policy_requested', 'receive_trial_initial_observed',
              'receive_trial_terminal_observed', 'receive_trial_terminal_revoked',
              'interactive_window_requested', 'interactive_window_bound') + STARTUP_BOOL_FIELDS + UI_FILECENTER_BOOL_FIELDS
HOST_ERROR_CODES = (
    'checker_ancestor', 'checker_link', 'checker_file', 'checker_identity',
    'checker_changed', 'checker_pin', 'checker_base', 'fixed_path', 'fixed_ancestor',
    'fixed_link', 'fixed_file', 'fixed_identity', 'fixed_changed', 'fixed_pin',
    'pins_not_frozen', 'input_shared_changed', 'manifest_schema', 'manifest_row',
    'payload_budget', 'source_assignment', 'source_literal', 'source_graph',
    'target_source_budget', 'transport_identity', 'remote_result_unknown',
    'result_fields', 'zip_readback', 'bundle_pin', 'bundle_manifest', 'filecenter_source',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _meta(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_bundle_fixed(name, pin):
    # The one fixed ELF is larger than the old generic 2 MiB helper ceiling.
    # No supplied path or file can exceed its actual pinned 4,103,844 bytes.
    if (type(name) is not str or not name or '\\' in name or PurePosixPath(name).is_absolute() or
            re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))): raise ValueError('fixed_path')
    expected = {BUNDLE + '/' + path: (size, sha) for path, size, sha in BUNDLE_PINS}
    if name not in expected or pin != expected[name]:
        raise ValueError('bundle_pin')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode): raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 4103844: raise ValueError('fixed_file')
    before = _meta(value)
    with path.open('rb') as handle:
        opened = _meta(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = handle.read(4103844 + 1)
        if _meta(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if _meta(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin: raise ValueError('fixed_pin')
    return raw



def load_checker():
    # Only this literal bootstrap file is executed, never its __main__.
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('checker_ancestor')
    path = BASE
    for part in CHECKER[0].split('/'):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('checker_link')
        if path != BASE / CHECKER[0] and not stat.S_ISDIR(value.st_mode):
            raise ValueError('checker_ancestor')
    before = _meta(value)
    if not stat.S_ISREG(value.st_mode) or value.st_size != CHECKER[1]:
        raise ValueError('checker_file')
    with path.open('rb') as handle:
        opened = _meta(os.fstat(handle.fileno()))
        same = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not same:
            raise ValueError('checker_identity')
        raw = handle.read(CHECKER[1] + 1)
        if _meta(os.fstat(handle.fileno())) != opened:
            raise ValueError('checker_changed')
    if _meta(path.lstat()) != before:
        raise ValueError('checker_changed')
    if (len(raw), digest(raw)) != CHECKER[1:]:
        raise ValueError('checker_pin')
    value = types.ModuleType('fixed_formal_receive_host_helpers')
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    if value.BASE != BASE:
        raise ValueError('checker_base')
    # Keep the bootstrap file/pin unchanged. Only this new private helper realm
    # has the exact new runner result schema; no old checker main is executed.
    value.BOOL_FIELDS = value.BOOL_FIELDS + ('interactive_window_requested',)
    value.FIELDS = frozenset(value.BOOL_FIELDS + value.COUNT_FIELDS + ('reason',))
    return value, raw


def manifest_rows(raw, private=False):
    names = PRIVATE_MODULE_NAMES if private else MODULE_NAMES
    schema = 'client-receive-directory-v1-private-source' if private else 'client-receive-directory-v1-definitions'
    value = json.loads(raw.decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != schema or
            private and value['previous_manifest_sha256'] != PREVIOUS_PRIVATE_SHA or
            type(value['sources']) is not list or len(value['sources']) != len(names)):
        raise ValueError('manifest_schema')
    rows, paths = [], set()
    for row, name in zip(value['sources'], names):
        if (type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or
                row['module'] != name or type(row['path']) is not str or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 2 * 1024 * 1024 or
                type(row['sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is None or
                not row['path'].endswith('/' + name + '.py') or row['path'] in paths or
                PurePosixPath(row['path']).is_absolute() or '\\' in row['path'] or
                re.fullmatch(r'[A-Za-z0-9_./-]+', row['path']) is None or
                any(part in ('', '.', '..') for part in row['path'].split('/'))):
            raise ValueError('manifest_row')
        expected_changed_path = 'candidate/formal-receive-v3/runtime/' + name + '.py'
        if not private and name in CHANGED_ROLES and row['path'] != expected_changed_path:
            raise ValueError('manifest_row')
        paths.add(row['path'])
        rows.append(('runtime35/' + name if private else name,
                     row['path'], row['bytes'], row['sha256']))
    return tuple(rows)


def _assignment(tree, name, bindings=None):
    rows = []
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else [])
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            rows.append(node.value)
    if len(rows) != 1:
        raise ValueError('source_assignment')
    bindings = {} if bindings is None else bindings
    def literal(node):
        if isinstance(node, ast.Constant) and type(node.value) in (str, int, float, bool, type(None)):
            return node.value
        if isinstance(node, ast.Tuple):
            return tuple(literal(value) for value in node.elts)
        if isinstance(node, ast.List):
            return [literal(value) for value in node.elts]
        if isinstance(node, ast.Name) and node.id in bindings:
            return bindings[node.id]
        raise ValueError('source_literal')
    return literal(rows[0])



def _ui_policy_literals(tree):
    """Fixed SOURCE policy only; no UI fact is an authority or RF result."""
    creators, initializers = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'runner' and node.func.attr == 'FixedSession':
            creators.append(node)
        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'facts' and node.func.attr == 'update':
            values = {keyword.arg: keyword.value for keyword in node.keywords}
            if 'receive_trial_policy_requested' in values or 'auto_receive_action_issued' in values:
                initializers.append(values)
    if len(creators) != 1 or len(initializers) != 1:
        return False
    creator = creators[0]
    policy = initializers[0]
    values = {keyword.arg: keyword.value for keyword in creator.keywords}
    return (len(creator.args) == 2 and len(creator.keywords) == 2 and
            isinstance(creator.args[0], ast.Name) and creator.args[0].id == 'artifacts' and
            isinstance(creator.args[1], ast.Constant) and creator.args[1].value is False and
            set(values) == {'receive_trial_requested', 'profile'} and
            isinstance(values['receive_trial_requested'], ast.Constant) and
            values['receive_trial_requested'].value is True and
            isinstance(values['profile'], ast.Name) and values['profile'].id == 'INTERACTIVE_PROFILE' and
            isinstance(policy.get('interactive_window_requested'), ast.Constant) and
            policy['interactive_window_requested'].value is True and
            isinstance(policy.get('interactive_window_expired'), ast.Constant) and
            policy['interactive_window_expired'].value is False and
            isinstance(policy.get('interactive_window_bound'), ast.Constant) and
            policy['interactive_window_bound'].value is False and
            isinstance(policy.get('receive_trial_policy_requested'), ast.Constant) and
            policy['receive_trial_policy_requested'].value is True and
            isinstance(policy.get('auto_receive_action_issued'), ast.Constant) and
            policy['auto_receive_action_issued'].value is False)


INTERACTIVE_AST = (
    ('runner.__init__', '8e7789392f7e541f3940a9e68a547fa316835bcbd77e1e11d486bcfb05517a8e'),
    ('runner.window_current', '17d8bbecc17a4d452e7ff3b3599fc6713ad97e527b9c2e2c239dfe2a6ba12523'),
    ('runner.check', 'f818d0e10944da482dbc01c48eb04fb262feef0ac2971b99cbbc65340c46ac3c'),
    ('ui._receive_interactive_window', 'd7ceb1390be498b156734ea3a53db65564d412eb60d0629aefccdfb4a54bda3e'),
    ('ui._receive_interactive_originals', 'e9d0acdb8f91b724a10941a1991630bfcdc70756856c0e8acca572617cda8304'),
    ('ui._receive_interactive_expired', 'ea2d8bb3cc478a275930af04fd9dd988acbeb7876857d05b0692bcaa8687497a'),
)


def _interactive_profile_literals(runner, worker):
    """SOURCE-only fixed profile and already-tested AST continuity, never exec."""
    if (_assignment(worker, 'INTERACTIVE_PROFILE') != 'receive-interactive-v1' or
            _assignment(worker, 'INTERACTIVE_SECONDS') != 600.0 or
            _assignment(worker, 'EXIT_MARGIN_SECONDS') != 1.0):
        return False
    cls = next((node for node in runner.body if isinstance(node, ast.ClassDef) and node.name == 'FixedSession'), None)
    if cls is None:
        return False
    found = {}
    for role, tree in (('runner', cls), ('ui', worker)):
        for node in tree.body:
            name = role + '.' + getattr(node, 'name', '')
            if isinstance(node, ast.FunctionDef) and any(key == name for key, sha in INTERACTIVE_AST):
                if name in found:
                    return False
                found[name] = digest(ast.dump(node, include_attributes=False).encode('utf-8'))
    if found != dict(INTERACTIVE_AST):
        return False
    ctor = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == '__init__')
    names = tuple(arg.arg for arg in ctor.args.args)
    if names != ('self', 'artifacts', 'preflight_only', 'receive_trial_requested', 'profile'):
        return False
    return (len(ctor.args.defaults) == 2 and
            isinstance(ctor.args.defaults[0], ast.Constant) and ctor.args.defaults[0].value is False and
            isinstance(ctor.args.defaults[1], ast.Constant) and ctor.args.defaults[1].value == 'diagnostic')


def _filecenter_literals(worker, validator):
    definitions = [node for node in worker.body if isinstance(node, ast.FunctionDef) and node.name == 'run_fixed']
    if len(definitions) != 1:
        return False
    arguments = definitions[0].args
    return (tuple(arg.arg for arg in arguments.args) ==
            ('runner_raw', 'artifacts', 'validator_raw', 'filecenter_sources') and
            not arguments.defaults and arguments.vararg is None and arguments.kwarg is None and
            not arguments.kwonlyargs and
            _assignment(worker, 'FILECENTER_PINS') == tuple((name, size, sha) for name, path, size, sha in FILECENTER_SOURCES) and
            _assignment(worker, 'VALIDATOR_PIN') == VALIDATOR[1:] and
            _assignment(worker, 'SESSION') == BUNDLE_SESSION and
            _assignment(validator, 'SESSION') == BUNDLE_SESSION and
            _assignment(validator, 'PINS') == BUNDLE_PAYLOAD_PINS and
            _assignment(validator, 'MANIFEST_PIN') == BUNDLE_MANIFEST_PIN[1:] and
            _assignment(validator, 'ROOT_NAMES') == ROOT_NAMES and
            _assignment(validator, 'MTA_NAMES') == MTA_NAMES and
            _assignment(validator, 'TOOLBOX_NAMES') == TOOLBOX_NAMES)


def check_source_graph(checker, inputs, rows, private_rows, payload):
    # Reuse v3's nine role literal crosschecks; only two lifecycle sources changed.
    # Literal resolution accepts only these named fixed SHA bindings, never eval.
    ordinary = {name: (path, size, sha) for name, path, size, sha in rows}
    trees = {name: ast.parse(inputs[ordinary[name][0]].decode('utf-8'), feature_version=(3, 5))
             for name in CHANGED_ROLES}
    runner = ast.parse(inputs[RUNNER[0]].decode('utf-8'), feature_version=(3, 5))
    worker = ast.parse(inputs[WORKER[0]].decode('utf-8'), feature_version=(3, 5))
    validator = ast.parse(inputs[VALIDATOR[0]].decode('utf-8'), feature_version=(3, 5))
    factory = trees['mta_client_receive_factory']
    boot = trees['mta_client_receive_boot']
    owner = trees['mta_client_service_owner']
    executor = trees['mta_client_executor']
    role_pins = tuple((name, size, sha) for name, path, size, sha in rows)
    private_pins = tuple((name.split('/', 1)[1], size, sha) for name, path, size, sha in private_rows)
    source_pins = role_pins[:-2]
    f_sha = ordinary['mta_client_executor'][2]
    actual_checks = (
        _assignment(runner, 'ROLE_PINS') == role_pins,
        _assignment(runner, 'PRIVATE_PINS') == private_pins,
        _assignment(runner, 'HELPER_PINS') == tuple((name, size, sha) for name, path, size, sha in HELPERS),
        _assignment(runner, 'WPA_PIN') == (WPA[0], WPA[2], WPA[3]),
        _assignment(runner, 'MONITOR_PIN') == (MONITOR[0], MONITOR[2], MONITOR[3]),
        _assignment(worker, 'MONITOR_PIN') == (MONITOR[0], MONITOR[2], MONITOR[3]),
        _assignment(worker, 'RUNNER_PIN') == RUNNER[1:],
        _assignment(worker, 'TRIAL_BOOL_FIELDS') == TRIAL_BOOL_FIELDS,
        _ui_policy_literals(worker) is True,
        _interactive_profile_literals(runner, worker) is True,
        _filecenter_literals(worker, validator) is True,
        _assignment(boot, 'SOURCE_PINS', {'F37_SHA': f_sha}) == source_pins,
        _assignment(factory, 'SOURCE_PINS', {'F_SHA': f_sha}) == private_pins,
        _assignment(boot, 'F37_SHA') == f_sha,
        _assignment(factory, 'F_SHA') == f_sha,
        _assignment(boot, 'CLIENT_MANIFEST_SHA') == PRIVATE_MANIFEST[2],
        _assignment(factory, 'SOURCE_MANIFEST_SHA') == PRIVATE_MANIFEST[2],
        _assignment(owner, 'BOOT_PIN') == ordinary['mta_client_receive_boot'][1:],
        _assignment(owner, 'BOOT_MODULES') == tuple(row[0] for row in source_pins),
        _assignment(owner, 'HELPER_PINS') == tuple((row[2], row[3]) for row in HELPERS[:2]),
        _assignment(owner, 'CONNMAN_PIN') == HELPERS[2][2:],
        _assignment(owner, 'BOOT_SCHEMA') == 'sender-state-boot-v98-source',
        _assignment(boot, 'SOURCE_SCHEMA') == 'sender-state-boot-v98-source',
        _assignment(owner, 'STARTUP_READONLY_SCHEMA') == 'receive-startup-readonly-v1',
        _assignment(factory, 'STARTUP_READONLY_SCHEMA') == 'receive-startup-readonly-v1',
        _assignment(executor, 'ROOT') == '/tmp/p011-mta-client-rfinit',
        _assignment(executor, 'PHYSICAL_ROOT') == '/var/volatile/tmp/p011-mta-client-rfinit',
        tuple(_assignment(runner, 'BOOL_FIELDS')) == tuple(checker.BOOL_FIELDS),
        tuple(_assignment(runner, 'COUNT_FIELDS')) == tuple(checker.COUNT_FIELDS),
        tuple(_assignment(runner, 'REASONS')) == tuple(checker.REASONS),
    )
    if not all(actual_checks):
        raise ValueError('source_graph')
    for tree, logical, physical in (
            (runner, 'STATE_ALIAS', 'STATE_ROOT'), (worker, 'STATE_ALIAS', 'STATE_ROOT'),
            (factory, 'ASSET_ROOT', 'ASSET_PHYSICAL_ROOT'), (boot, 'ROOT', 'PHYSICAL_ROOT')):
        if _assignment(tree, logical) != STATE_ALIAS or _assignment(tree, physical) != STATE_ROOT:
            raise ValueError('source_graph')
    if _assignment(owner, 'ROOT') != STATE_ALIAS:
        raise ValueError('source_graph')
    if tuple(row[0] for row in payload) != (
            tuple(row[0] for row in role_pins) +
            tuple(row[0] for row in HELPERS) +
            tuple('runtime35/' + row[0] for row in private_pins) + (WPA[0], MONITOR[0])):
        raise ValueError('source_graph')
    # No unchanged parser/private graph AST, import or historical test execution.
    return len(trees) + 3


TARGET_COMMON = r'''
import base64,hashlib,re,types,zlib
def fixed_decode(encoded,size,sha):
 if type(size) is not int or not 0<size<=2097152:raise ValueError('payload_budget')
 compressed=base64.b64decode(encoded)
 decoder=zlib.decompressobj();raw=decoder.decompress(compressed,size+1)
 if (len(raw)!=size or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof or
     hashlib.sha256(raw).hexdigest()!=sha):raise ValueError('payload_pin')
 return raw
def fixed_error_details(errors):
 rows=[];seen=set()
 for error in errors:
  if len(rows)>=16:break
  if not isinstance(error,BaseException) or id(error) in seen:continue
  seen.add(id(error));kind='Exception'
  if isinstance(error,OSError):kind='OSError'
  else:
   for cls,name in ((ValueError,'ValueError'),(RuntimeError,'RuntimeError'),
                    (TypeError,'TypeError'),(AttributeError,'AttributeError'),
                    (KeyError,'KeyError'),(IndexError,'IndexError'),
                    (AssertionError,'AssertionError'),(ImportError,'ImportError'),
                    (SyntaxError,'SyntaxError')):
    if isinstance(error,cls):kind=name;break
   if USE_UI and type(error) is session.UiSessionError:kind='UiSessionError'
  code=getattr(error,'code',None)
  code=code if type(code) is str and code in RESULT_REASONS else 'unclassified'
  number=error.errno if isinstance(error,OSError) else None
  number=number if type(number) is int and 1<=number<=4095 else None
  frames=[];tb=error.__traceback__;count=0
  while tb is not None and count<32:
   frame=tb.tb_frame;module=frame.f_globals.get('__name__');name=frame.f_code.co_name;line=tb.tb_lineno
   if (type(module) is str and module in ERROR_MODULES and type(name) is str and
       re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,95}',name) is not None and
       type(line) is int and 1<=line<=1000000):frames.append((module,name,line))
   tb=tb.tb_next;count+=1
  rows.append(dict(kind=kind,code=code,errno=number,trace=tuple(frames)))
 return tuple(rows)
runner_raw=fixed_decode(RUNNER_ENCODED,RUNNER_PIN[0],RUNNER_PIN[1])
artifacts=tuple((name,size,sha,fixed_decode(encoded,size,sha)) for name,size,sha,encoded in ARTIFACT_ROWS)
'''

TARGET_SERVICE = r'''
session=types.ModuleType('fixed_startup_readonly_diagnostic')
session.__file__='<fixed-formal-receive-service-stdin>'
exec(runner_raw,session.__dict__)
try:
 component=session.run_fixed(artifacts,False,receive_trial_requested=True)
except BaseException as error:
 detail=fixed_error_details((error,))
 if detail:print('ERROR_DETAIL='+repr(detail))
 print('SESSION_ERROR_CODE=service_exception')
 raise SystemExit(2)
retained=session._RETAINED
if retained is not None:
 print('TRIAL_START='+repr(retained.trial_start_facts))
 print('TRIAL_END='+repr(retained.trial_end_facts))
if component['complete'] is not True and retained is not None:
 errors=[getattr(retained,'first_error',None)]
 scope=getattr(retained,'startup_scope',None)
 errors.append(getattr(scope,'failure',None))
 collection=getattr(retained,'startup_collection',None)
 errors.append(getattr(collection,'failure',None))
 owner=getattr(retained,'owner',None)
 errors.append(getattr(owner,'receive_trial_failure',None))
 trial=getattr(owner,'receive_trial',None)
 errors.append(getattr(trial,'failure',None))
 values=getattr(collection,'close_failures',None)
 if type(values) is list:errors.extend(values[:16])
 detail=fixed_error_details(errors)
 if detail:print('ERROR_DETAIL='+repr(detail))
 startup=retained.private_startup_error_details()
 if startup:print('STARTUP_ERROR_DETAILS='+repr(startup))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''

TARGET_UI = r'''
def fixed_filecenter_sources(rows):
 if type(rows) is not tuple or len(rows)!=9 or len(FILECENTER_PINS)!=9:raise ValueError('filecenter_source')
 result=[];total=0
 for row,pin in zip(rows,FILECENTER_PINS):
  if type(row) is not tuple or len(row)!=4 or row[:3]!=pin:raise ValueError('filecenter_source')
  name,size,sha,encoded=row
  if (type(name) is not str or type(size) is not int or not 0<size<=131072 or
      type(sha) is not str or re.fullmatch(r'[0-9a-f]{64}',sha) is None or
      type(encoded) is not str or not 0<len(encoded)<=262144):raise ValueError('filecenter_source')
  compressed=base64.b64decode(encoded,validate=True)
  if not 0<len(compressed)<=131072:raise ValueError('filecenter_source')
  decoder=zlib.decompressobj();raw=decoder.decompress(compressed,size+1)
  if (len(raw)!=size or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof or
      hashlib.sha256(raw).hexdigest()!=sha):raise ValueError('filecenter_source')
  total+=len(raw)
  if total>131072:raise ValueError('filecenter_source')
  result.append((name,raw))
 if total!=91295:raise ValueError('filecenter_source')
 return tuple(result)
filecenter_sources=fixed_filecenter_sources(FILECENTER_ROWS)
worker_raw=fixed_decode(WORKER_ENCODED,WORKER_PIN[0],WORKER_PIN[1])
validator_raw=fixed_decode(VALIDATOR_ENCODED,VALIDATOR_PIN[0],VALIDATOR_PIN[1])
session=types.ModuleType('fixed_formal_ui_session')
session.__file__='<fixed-formal-receive-ui-stdin>'
exec(worker_raw,session.__dict__)
try:
 component=session.run_fixed(runner_raw,artifacts,validator_raw,filecenter_sources)
except BaseException as error:
 detail=fixed_error_details((error,))
 if detail:print('ERROR_DETAIL='+repr(detail))
 code=(error.code if type(error) is session.UiSessionError and error.code in RESULT_REASONS else 'ui_exception')
 print('UI_ERROR_CODE='+code)
 raise SystemExit(2)
if component['complete'] is not True:
 retained=session._RETAINED;errors=[]
 if type(retained) is dict:
  values=retained.get('failures')
  if type(values) is list:errors.extend(values[:16])
  ticket=retained.get('filecenter')
  if type(ticket) is dict:
   errors.append(ticket.get('failure'))
   companion=ticket.get('companion')
   errors.append(getattr(companion,'failure',None))
   values=getattr(companion,'cleanup_failures',None)
   if type(values) is list:errors.extend(values[:16])
  original=retained.get('component')
  values=getattr(original,'failures',None)
  if type(values) is list:errors.extend(values[:16])
  owner=getattr(original,'owner',None)
  errors.append(getattr(owner,'startup_failure',None))
  scope=getattr(original,'startup_scope',None)
  errors.append(getattr(scope,'failure',None))
  collection=getattr(original,'startup_collection',None)
  errors.append(getattr(collection,'failure',None))
  values=getattr(collection,'close_failures',None)
  if type(values) is list:errors.extend(values[:16])
  values=getattr(collection,'status_rows',None)
  if type(values) is list:
   for row in values[:2]:
    if type(row) is dict:errors.append(row.get('failure'))
 detail=fixed_error_details(errors)
 if detail:print('ERROR_DETAIL='+repr(detail))
print('RESULT='+repr(component))
print('MTA_REMOTE_OK')
raise SystemExit(0 if component['complete'] else 1)
'''


def _short_chunks(checker, raw):
    # Reuse the pinned helper's exact encoder, but not its 1024-character lines.
    # The device transport may traverse a canonical TTY with a 512-byte line cap.
    # Generated ASCII base64 repr is always this one quote shape, not arbitrary
    # input code. Fragment width96 keeps each physical encoded line below128.
    parts = []
    for line in checker.chunks(raw).splitlines():
        if (not line.startswith("    '") or not line.endswith("'") or
                re.fullmatch(r'[A-Za-z0-9+/=]{1,1024}', line[5:-1]) is None):
            raise ValueError('target_source_budget')
        parts.append(line[5:-1])
    encoded = ''.join(parts)
    if not encoded:
        raise ValueError('target_source_budget')
    return '\n'.join('    ' + repr(encoded[index:index + 96])
                     for index in range(0, len(encoded), 96))


def parse_trial_facts(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    output = {}
    for tag in ('START', 'END'):
        rows = re.findall(r'^TRIAL_' + tag + r'=(.*)$', derived, re.M)
        if len(rows) != 1:
            raise ValueError('remote_result_unknown')
        value = ast.literal_eval(rows[0])
        if (type(value) is not dict or set(value) != TRIAL_FIELDS or
                any(type(value[name]) is not bool for name in TRIAL_BOOL_FIELDS) or
                type(value['claim_count']) is not int or value['claim_count'] not in (0, 1) or
                type(value['reason']) is not str or value['reason'] not in TRIAL_REASONS):
            raise ValueError('result_fields')
        output[tag.lower()] = value
    return output


def make_source(checker, inputs, payload, use_ui):
    modules = tuple(sorted(set(MODULE_NAMES + PRIVATE_MODULE_NAMES + (
        'fixed_formal_ui_session', 'fixed_formal_ui_runner', 'fixed_formal_ui_assets',
        'fixed_formal_receive_monitor', 'fixed_startup_readonly_diagnostic',
        'startup_readonly_private_owner', 'threading', 'socket', 'subprocess', 'types'))))
    if use_ui:
        modules = tuple(sorted(set(modules + tuple(row[0] for row in FILECENTER_SOURCES))))
    lines = ['USE_UI=' + repr(use_ui), 'ERROR_MODULES=(']
    lines.extend('    ' + repr(name) + ',' for name in modules)
    lines.extend((')', 'RESULT_REASONS=('))
    lines.extend('    ' + repr(name) + ',' for name in (UI_REASONS if use_ui else
                  tuple(dict.fromkeys(tuple(checker.REASONS) + TRIAL_REASONS))))
    lines.append(')')
    pins = (RUNNER, WORKER, VALIDATOR) if use_ui else (RUNNER,)
    for tag, pin in zip(('RUNNER', 'WORKER', 'VALIDATOR'), pins):
        lines.append(tag + '_PIN=' + repr(pin[1:]))
        lines.extend((tag + '_ENCODED=(', _short_chunks(checker, inputs[pin[0]]), ')'))
    lines.append('ARTIFACT_ROWS=(')
    for name, path, size, sha in payload:
        lines.append('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(')
        lines.extend((_short_chunks(checker, inputs[path]), '    )),'))
    lines.append(')')
    if use_ui:
        lines.append('FILECENTER_PINS=(')
        for name, path, size, sha in FILECENTER_SOURCES:
            lines.append('    ' + repr((name, size, sha)) + ',')
        lines.extend((')', 'FILECENTER_ROWS=('))
        for name, path, size, sha in FILECENTER_SOURCES:
            lines.append('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(')
            lines.extend((_short_chunks(checker, inputs[path]), '    )),'))
        lines.append(')')
    raw = ('\n'.join(lines) + '\n' + TARGET_COMMON +
           (TARGET_UI if use_ui else TARGET_SERVICE)).encode('ascii')
    if len(raw) > 2 * 1024 * 1024 or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return raw


def _filecenter_envelope_literals(ui, service):
    """SOURCE-only dispatch cardinality, not a runtime or phone receipt."""
    pins = tuple((name, size, sha) for name, path, size, sha in FILECENTER_SOURCES)
    if _assignment(ui, 'FILECENTER_PINS') != pins:
        return False
    rows = _assignment(ui, 'FILECENTER_ROWS')
    if (type(rows) is not tuple or len(rows) != 9 or
            any(type(row) is not tuple or len(row) != 4 or row[:3] != pin or
                type(row[3]) is not str or not 0 < len(row[3]) <= 262144
                for row, pin in zip(rows, pins))):
        return False
    injections, decoders = [], []
    for node in ast.walk(ui):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == 'fixed_filecenter_sources':
            decoders.append(node)
        if (isinstance(node.func, ast.Attribute) and node.func.attr == 'run_fixed' and
                isinstance(node.func.value, ast.Name) and node.func.value.id == 'session'):
            injections.append(node)
    if len(injections) != 1 or len(decoders) != 1:
        return False
    call, decode = injections[0], decoders[0]
    if (call.keywords or tuple(arg.id if isinstance(arg, ast.Name) else None for arg in call.args) !=
            ('runner_raw', 'artifacts', 'validator_raw', 'filecenter_sources') or
            decode.keywords or len(decode.args) != 1 or not isinstance(decode.args[0], ast.Name) or
            decode.args[0].id != 'FILECENTER_ROWS'):
        return False
    for node in ast.walk(service):
        if isinstance(node, ast.Name) and node.id in ('FILECENTER_ROWS', 'FILECENTER_PINS', 'filecenter_sources'):
            return False
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                node.func.id == 'fixed_filecenter_sources'):
            return False
    return True


def parse_ui_result(raw):
    derived = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = derived.splitlines()
    remote = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    rows = [line[7:] for line in lines if line.startswith('RESULT=')]
    if len(remote) != 1 or lines.count('MTA_REMOTE_OK') != 1 or len(rows) != 1:
        raise ValueError('remote_result_unknown')
    value = ast.literal_eval(rows[0])
    if (type(value) is not dict or set(value) != UI_FIELDS or
            any(type(value[key]) is not bool for key in UI_BOOL_FIELDS) or
            any(type(value[key]) is not int or not 0 <= value[key] <= 512 for key in UI_COUNT_FIELDS) or
            type(value['reason']) is not str or value['reason'] not in UI_REASONS or
            any(type(value[key]) is not str or value[key] not in TRIAL_REASONS
                for key in UI_REASON_FIELDS[1:]) or
            value['receive_trial_claim_count'] not in (0, 1) or
            value['receive_trial_claimed'] is not (value['receive_trial_claim_count'] == 1) or
            value['receive_trial_session_attached'] and not value['receive_trial_claimed'] or
            value['receive_trial_policy_requested'] is not True or
            value['auto_receive_action_issued'] is not False or
            value['interactive_window_requested'] is not True or
            value['reason'] == 'interactive_window_expired' and value['interactive_window_expired'] is not True or
            value['reason'] == 'ui_finished' and value['interactive_window_expired'] is not False):
        raise ValueError('result_fields')
    ready = lines.count('MTA_FORMAL_UI_READY')
    if (ready not in (0, 1) or ready == 1 and not (value['ui_ready'] and value['credentials_removed']) or
            value['complete'] and ready != 1):
        raise ValueError('result_fields')
    return int(remote[0]), value


def host_error_code(error):
    if (type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in HOST_ERROR_CODES):
        return error.args[0]
    for cls, name in ((OSError, 'host_OSError'), (SyntaxError, 'host_SyntaxError'),
                      (TypeError, 'host_TypeError'), (KeyError, 'host_KeyError'),
                      (ValueError, 'host_ValueError'), (RuntimeError, 'host_RuntimeError')):
        if isinstance(error, cls):
            return name
    return 'host_Exception'


def _pin_valid(pin):
    return (type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
            type(pin[1]) is int and 0 < pin[1] <= 2 * 1024 * 1024 and
            type(pin[2]) is str and re.fullmatch(r'[0-9a-f]{64}', pin[2]) is not None)


def _write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    parser.add_argument('--ui', action='store_true')
    args = parser.parse_args()
    if args.ui and not args.check_device:
        parser.error('--ui requires --check-device')
    mode = 'ui' if args.ui else 'service' if args.check_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    out = BASE / 'results' / ('receive-filecenter-v1-' + mode + '-' + stamp + '-' + secrets.token_hex(4))
    private = out / 'private-raw'
    private.mkdir(parents=True, exist_ok=False)
    inputs, programs, checker, component, trial_facts = {}, {}, None, None, None
    expected_paths = None
    label = 'receive-filecenter-v1-' + mode
    report = dict(
        schema='p011-receive-filecenter-v1', mode=mode, passed=False,
        source_check_complete=False, source_graph_crosschecked=False,
        source_preserved=False, source_count=0, payload_role_count=0,
        changed_role_ast_count=0, reused_v3_role_ast_count=0, lifecycle_ast_count=0, envelope_ast_count=0,
        source_runtime_graph_executed=False, old_test_methods=0, old_http_smoke_replayed=False,
        host_error_code=None, device_invoked=False, ui_requested=args.ui,
        host_exit=None, remote_exit=None, remote_status_known=False,
        stdout_bytes=None, stdout_sha256=None, stderr_bytes=None, stderr_sha256=None,
        result_received=False, startup_observation_only=not args.ui,
        interactive_window_entry_selected=args.ui, interactive_profile_source_crosschecked=False,
        interactive_business_ast_count=0, interactive_constructor_seconds=600,
        interactive_exit_margin_seconds=1, ui_remote_alarm_seconds=800, ui_host_timeout_seconds=810,
        service_remote_alarm_seconds=240, service_host_timeout_seconds=250,
        mta_scan_requested=False, mta_receive_requested=False, mta_send_requested=False,
        receive_admission_requested=False, pending_removed=False, phone_tested=False,
        receive_trial_policy_requested=args.check_device, auto_receive_action_issued=False,
        receive_trial_facts_received=False, receive_trial_refusal_verified=False,
        physical_ui_verified=False, full_network_restore_verified=False,
        whole_system_zero_rf_claimed=False, vendor_binary_replaced=False,
        startup_changed=False, wake_or_timeout_changed=False,
        ui_bundle_staging_requested=False, private_raw_public=False,
        runner_bytes=RUNNER[1], runner_sha256=RUNNER[2],
        worker_bytes=WORKER[1], worker_sha256=WORKER[2],
        validator_bytes=VALIDATOR[1], validator_sha256=VALIDATOR[2],
        filecenter_source_count=9, filecenter_source_bytes=FILECENTER_SOURCE_BYTES,
        filecenter_source_byte_limit=FILECENTER_SOURCE_CAP, filecenter_source_envelope_single_copy=False,
        filecenter_service_payload_count=0, bundle_source_crosschecked=False,
        bundle_asset_count=19, bundle_directory_count=3, bundle_payload_bytes=4182249,
        bundle_staged=False, qt_visuals_verified=False)
    try:
        checker, checker_raw = load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw:
                    raise ValueError('input_shared_changed')
                return
            inputs[path] = raw
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_new(target, raw)
        retain(CHECKER[0], checker_raw)
        fixed = ((MANIFEST, PRIVATE_MANIFEST, RUNNER, WORKER, VALIDATOR, TRANSPORT) + CMDS +
                 tuple((path, size, sha) for name, path, size, sha in FILECENTER_SOURCES))
        if not all(_pin_valid(pin) for pin in fixed):
            raise ValueError('pins_not_frozen')
        for path, size, sha in fixed:
            retain(path, checker.read_fixed(path, (size, sha)))
        if (len(FILECENTER_SOURCES) != 9 or len({row[0] for row in FILECENTER_SOURCES}) != 9 or
                sum(row[2] for row in FILECENTER_SOURCES) != FILECENTER_SOURCE_BYTES or
                FILECENTER_SOURCE_BYTES > FILECENTER_SOURCE_CAP):
            raise ValueError('filecenter_source')
        if (len(BUNDLE_PINS) != 19 or sum(row[1] for row in BUNDLE_PINS) != 4182249 or
                sum(row[1] for row in BUNDLE_PINS) >= 4 * 1024 * 1024):
            raise ValueError('bundle_pin')
        for name, size, sha in BUNDLE_PINS:
            path = BUNDLE + '/' + name
            retain(path, read_bundle_fixed(path, (size, sha)))
        manifest_expected = ''.join(sha + ' ' + str(size) + ' ' + name + '\n'
                                    for name, size, sha in BUNDLE_PAYLOAD_PINS).encode('ascii')
        if inputs[BUNDLE + '/SOURCE.sha256'] != manifest_expected:
            raise ValueError('bundle_manifest')
        report['bundle_source_crosschecked'] = True
        rows = manifest_rows(inputs[MANIFEST[0]])
        private_rows = manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)
        payload = rows + HELPERS + private_rows + (WPA, MONITOR)
        if (len(payload) != 75 or len({row[0] for row in payload}) != len(payload) or
                sum(row[2] for row in payload) > 4 * 1024 * 1024):
            raise ValueError('payload_budget')
        for name, path, size, sha in payload:
            retain(path, checker.read_fixed(path, (size, sha)))
        retain(SELF, checker.read_fixed(SELF))
        expected_paths = (set(pin[0] for pin in fixed) | {CHECKER[0], SELF} | {row[1] for row in payload} |
                          {BUNDLE + '/' + row[0] for row in BUNDLE_PINS})
        if set(inputs) != expected_paths:
            raise ValueError('source_graph')
        inventory = {path: dict(bytes=len(raw), sha256=digest(raw)) for path, raw in inputs.items()}
        _write_new(out / 'private-inputs.json',
                   (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        ast_count = check_source_graph(checker, inputs, rows, private_rows, payload)
        report['interactive_profile_source_crosschecked'] = True
        report['interactive_business_ast_count'] = len(INTERACTIVE_AST)
        envelope_trees = {}
        for use_ui, tag in ((False, 'service'), (True, 'ui')):
            raw = make_source(checker, inputs, payload, use_ui)
            envelope_trees[tag] = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
            programs[tag] = raw
            _write_new(out / ('private-target-' + tag + '.py'), raw)
            report[tag + '_source_bytes'] = len(raw)
            report[tag + '_source_sha256'] = digest(raw)
        if not _filecenter_envelope_literals(envelope_trees['ui'], envelope_trees['service']):
            raise ValueError('source_graph')
        report['filecenter_source_envelope_single_copy'] = True
        report.update(source_check_complete=True, source_graph_crosschecked=True,
                      source_count=len(inputs), payload_role_count=len(payload),
                      changed_role_ast_count=0, reused_v3_role_ast_count=len(CHANGED_ROLES),
                      lifecycle_ast_count=ast_count - len(CHANGED_ROLES), envelope_ast_count=len(programs))
        if args.check_device:
            # Import only the fixed transport helper; no old checker main/START.
            transport = checker.load_transport(inputs[TRANSPORT[0]])
            adb = transport.Adb(private)
            data = programs['ui' if args.ui else 'service']
            alarm, host_timeout = (800, 810) if args.ui else (240, 250)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(' + str(alarm) + ');'
                       'exec(sys.stdin.buffer.read(' + str(len(data)) + '))" p011-receive-filecenter-v1; '
                       'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            raw = adb.run(label, ['shell', command], timeout=host_timeout, input_data=data)
            remote, component = parse_ui_result(raw) if args.ui else checker.parse_result(raw)
            report.update(remote_status_known=True, remote_exit=remote, result_received=True)
            for key, value in component.items():
                report['component_' + key] = value
            if not args.ui:
                trial_facts = parse_trial_facts(raw)
                report['receive_trial_facts_received'] = True
                for tag, values in trial_facts.items():
                    for key, value in values.items():
                        report['trial_' + tag + '_' + key] = value
    except Exception as error:
        report['host_error_code'] = host_error_code(error)
    finally:
        report['source_count'] = len(inputs)
        prefix = private / ('01-' + label)
        host_path = Path(str(prefix) + '.host-exit')
        if host_path.exists():
            raw = host_path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(raw) if re.fullmatch(r'-?\d+', raw) else 'TIMEOUT'
        stdout_path = Path(str(prefix) + '.stdout.raw')
        stderr_path = Path(str(prefix) + '.stderr.raw')
        for stream, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.exists():
                original = path.read_bytes()
                report[stream + '_bytes'] = len(original)
                report[stream + '_sha256'] = digest(original)
        marker = 'NOT_INVOKED' if not report['device_invoked'] else 'UNKNOWN'
        if stdout_path.exists():
            derived = stdout_path.read_bytes().decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
            found = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
            if len(found) == 1:
                report['remote_exit'] = int(found[0])
                report['remote_status_known'] = True
                marker = found[0]
        _write_new(Path(str(prefix) + '.remote-exit'), (marker + '\n').encode('ascii'))
        try:
            report['source_preserved'] = (
                checker is not None and expected_paths is not None and set(inputs) == expected_paths and
                all((read_bundle_fixed(path, dict((BUNDLE + '/' + name, (size, sha))
                       for name, size, sha in BUNDLE_PINS)[path]) if path.startswith(BUNDLE + '/')
                     else checker.read_fixed(path)) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in inputs.items()) and
                all((out / ('private-target-' + tag + '.py')).read_bytes() == raw
                    for tag, raw in programs.items()) and len(programs) == 2)
        except (OSError, ValueError):
            report['source_preserved'] = False
    source_ok = (report['host_error_code'] is None and report['source_check_complete'] and
                 report['source_graph_crosschecked'] and report['source_preserved'] and
                 report['bundle_source_crosschecked'] and report['filecenter_source_envelope_single_copy'])
    if not args.check_device:
        report['passed'] = source_ok and not report['device_invoked']
    elif (source_ok and report['host_exit'] == 0 and report['stderr_bytes'] == 0 and
          report['remote_status_known'] and report['remote_exit'] == 0 and type(component) is dict):
        if args.ui:
            report['passed'] = (
                all(component[key] is True for key in UI_SUCCESS) and
                component['resource_pending'] is False and component['auto_receive_action_issued'] is False and
                component['physical_ui_verified'] is False and
                (component['reason'] == 'ui_finished' and component['interactive_window_expired'] is False or
                 component['reason'] == 'interactive_window_expired' and component['interactive_window_expired'] is True))
        else:
            service = tuple(key for key in checker.SERVICE if key != 'http_verified')
            start = {} if trial_facts is None else trial_facts['start']
            end = {} if trial_facts is None else trial_facts['end']
            report['receive_trial_refusal_verified'] = (
                trial_facts is not None and start['requested'] is True and start['available'] is False and
                start['reason'] == 'pending_exists' and start['barrier_clear'] is False and
                all(start[key] is True for key in ('startup_verified', 'probe_verified', 'radio_known',
                                                 'network_spec_verified')) and
                start['claimed'] is False and start['claim_count'] == 0 and start['session_attached'] is False and
                end['requested'] is True and end['available'] is False and end['revoked'] is True and
                end['reason'] == 'owner_closed' and end['claimed'] is False and end['claim_count'] == 0 and
                end['session_attached'] is False and start['restoration_verified'] is False and
                end['restoration_verified'] is False and start['phone_verified'] is False and end['phone_verified'] is False)
            report['passed'] = (
                report['receive_trial_refusal_verified'] and
                all(component[key] is True for key in checker.COMMON + service + ('complete',)) and
                component['resource_pending'] is False and component['staging_pending'] is False and
                component['http_verified'] is False and component['http_request_count'] == 0 and
                component['client_socket_count'] == 0 and component['reason'] == 'complete' and
                component['interactive_window_requested'] is False)
    # Never publish raw traces, inventories, tokens, paths from exceptions or user data.
    if any(type(value) not in (type(None), bool, int, str) for value in report.values()):
        raise ValueError('result_fields')
    public = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii')
    readme = (
        b'Fixed receive-filecenter-v1 envelopes with unchanged formal-v3 runtime75 graph. '
        b'Nine exact FileCenter sources are compressed once into the UI envelope only, '
        b'bounded to 131072 raw bytes with exact original lengths and SHA pins. Each is '
        b'decoded once and handed to the four-argument UI injection entry; no extra '
        b'FileCenter source is dispatched by the service branch. The UI stdin envelope '
        b'keeps its original 2 MiB total and 256-byte physical line limits. SOURCE '
        b'also authenticates and privately snapshots the fixed built b6a84fe755092535bb996f40 '
        b'19-asset/3-directory bundle (4182249 raw bytes), but never stages or dispatches '
        b'those assets in this UI envelope. PC build diagnostics are not staged assets. '

        b'Default HOST SOURCE checks 35 ordinary roles, '
        b'35 private roles, three helpers, WPA and one monitor (75 payload rows); only nine '
        b'unchanged v3 role sources, new runner/worker and two short-line envelopes get AST '
        b'checks. No old tests or HTTP smoke are replayed. Explicit --check-device stages '
        b'only the fixed independent volatile graph, starts its original Owner, seals the '
        b'actual startup resources and runs the actual read-only publication barrier. The '
        b'trusted one-shot receive policy is requested but no discover, scan, broadcast, '
        b'connect, Wi-Fi mutation or file transfer is started. Service PASS specifically '
        b'requires pending_exists refusal, zero Operation/Session claim, original revoke '
        b'and closure receipts and unchanged limited stock/old-record baseline. It does not '
        b'prove receive admission, RF restoration, phone compatibility or physical UI. '
        b'The barrier stats old pending metadata only; the original baseline fingerprints '
        b'its fixed file bytes without parsing. It is not backed up, cleared or bypassed. --ui '
        b'selects the fixed receive-interactive-v1 profile in the pre-staged FileCenter copied UI. '
        b'Its original 600-second constructor cap includes startup; READY does not renew it. '
        b'UI exits one second before that original cap. Session task300, Factory prepare120, '
        b'Owner cleanup60 and guardian+68/+135 keep their original bounds. No automatic '
        b'receive action is issued; manual UI actions may start the original receive operation. '
        b'UI PASS is display/original-close evidence, not received-file or phone acceptance. '
        b'Its radio_admission field records observed qualification, not '
        b'physical RF or transfer success. It neither installs '
        b'assets nor changes vendor Z03/startup/wake/auto-sleep. Original stdout/stderr, '
        b'host and remote exit, input snapshots, generated programs and private errors '
        b'remain local. Service host250/remote240; UI host810/remote800, covering one '
        b'600-second constructor cap, original guardian135 and bounded envelope/startup '
        b'margin only. Missing results cannot sign '
        b'cleanup and never authorize killing unknown workers or clearing records. '
        b'A PASS describes only the selected layer and mode.\n')
    _write_new(out / 'result.json', public)
    _write_new(out / 'README.txt', readme)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public)
        bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(archive) as bundle:
        if (bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or
                bundle.read('result.json') != public or bundle.read('README.txt') != readme):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
                         result_zip=str(archive), zip_sha256=digest(archive.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
