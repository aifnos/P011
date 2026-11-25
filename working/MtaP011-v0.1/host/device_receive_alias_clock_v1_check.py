"""Single-variable fixed metadata alias clock; frozen progress-v2 observer.

Default SOURCE only. Device is explicit; original600+60/120+15 and all closure
predicates remain unchanged. New graph changes Factory alias clock only; all
private IO/startup checks, Handoff/Trial/trace and observer bytes are retained.
"""
import argparse
import ast
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import secrets
import subprocess
import threading
import traceback
import types
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_alias_clock_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_ALIAS_CLOCK_V1_CHECK.cmd', 'TEST_MTA_RECEIVE_ALIAS_CLOCK_V1.cmd',
        'HOST_MTA_RECEIVE_ALIAS_CLOCK_V1_CONTRACT.cmd')
DIAGNOSTIC = ('host/device_receive_advertise_smoke_v2_diagnostic.py', 19645,
              'c33a0e73569ddac453230e0ba509955a4b08a84742633b021c433b8dc77d6201')
RUNTIME_V2 = ('candidate/receive-handoff-progress-120s-v2/runtime/phone_discovery_session.py', 26305,
              '15540ef933e3c18853f8ab650e8ddc4aa902c2499eec3a7538f6f178e295ddf4')
PREVIOUS_PROGRESS_RUNTIME = ('candidate/receive-handoff-progress-120s-v1/runtime/phone_discovery_session.py', 21406,
    '43b38516f40f49398a824311f721d5fb04b8f34234c15ca194ed6b274265764a')
PREVIOUS_PROGRESS_HOST = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
    '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
DURATION_RUNTIME = ('candidate/receive-phone-discovery-120s-v1/runtime/phone_discovery_session.py', 16334,
                    '532e5f9d78b80825ff82e589c5fc17445f50d884e4fa227a55df60c3211696f2')
OLD_RUNTIME = ('candidate/receive-phone-discovery-v1/runtime/phone_discovery_session.py', 16332,
               '66554a39a63f95bad6b683f2121dd3a58417ab2b63168dd2a1db4a72eda0b34e')
BASE_HOST = ('host/device_receive_phone_discovery_120s_v1_check.py', 32996,
             'bff7904cb4b4a2cbf1743235c96f6de7af6e487baa322f4ef4d73306135ee31f')
BASE_COMPAT_HOST = ('host/device_receive_handoff_compat_v2_check.py', 19697,
                    'bd67fe3fda00ff19388fe0646ef9dc3e20b56219be60c78516c633d4eaa246bb')

PHONE_HOST = ('host/device_receive_phone_discovery_v1_check.py', 20192,
              '09fb7cd14876d04916db1aca0eaf40c437dadcf79b7bee1354f3cb1cb605bcbc')
TRACE = ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
         '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657')
TEST_SOURCE = 'tests/test_receive_alias_clock_v1.py'
COMPAT = ('host/formal_receive_alias_clock_v1_definitions.py', 19468,
          '7bd0155ae2ddcb0892bf53e0429bd323b02046b8c5a365531fb929bce7e9e6e1')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw):
    with path.open('xb') as handle:
        if handle.write(raw) != len(raw):
            raise OSError('short_write')


def load_base_host():
    raw = (BASE / BASE_HOST[0]).read_bytes()
    if len(raw) != BASE_HOST[1] or digest(raw) != BASE_HOST[2]:
        raise ValueError('base_host_pin')
    module = types.ModuleType('fixed_phone_120s_base_definitions')
    module.__file__ = str(BASE / BASE_HOST[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module, raw


def make_source(original, v1, diagnostic, helpers, inputs, payload):
    base, unused = load_base_host()
    old = base.make_source(original, v1, diagnostic, helpers, inputs, payload)
    previous = ('SMOKE_PIN=' + repr(DURATION_RUNTIME[1:]) + '\nSMOKE_ENCODED=(\n' +
                original._short_chunks(helpers, inputs[DURATION_RUNTIME[0]]) + '\n)\n').encode('ascii')
    selected = ('SMOKE_PIN=' + repr(RUNTIME_V2[1:]) + '\nSMOKE_ENCODED=(\n' +
                original._short_chunks(helpers, inputs[RUNTIME_V2[0]]) + '\n)\n').encode('ascii')
    if old.count(previous) != 1:
        raise ValueError('frozen_runtime_encoding_changed')
    program = old.replace(previous, selected)
    marker = b"print('PHONE_WINDOW_RESULT='+repr(smoke._PHONE_WINDOW))\n"
    if program.count(marker) != 1:
        raise ValueError('frozen_phone_result_marker_changed')
    added = b"print('HANDSHAKE_PROGRESS_RESULT='+repr(smoke._HANDSHAKE_WINDOW))\n"
    program = program.replace(marker, marker + added)
    if len(program) > 2097152 or any(len(line) > 256 for line in program.splitlines()):
        raise ValueError('target_source_budget')
    return program


def parse_trace(diagnostic, raw):
    value = diagnostic.one_literal(raw, 'HANDOFF_TRACE_RESULT')
    keys = {'schema', 'thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown',
            'overflow_unknown', 'failure_codes', 'events', 'terminal'}
    if type(value) is not dict or set(value) != keys or value['schema'] != 'receive-handoff-trace-v1':
        raise ValueError('trace_fields')
    for name in ('thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown', 'overflow_unknown'):
        if type(value[name]) is not bool:
            raise ValueError('trace_bool')
    failures = {'existing_trace', 'install_failed', 'hook_changed', 'current_hook_changed',
                'projection_failed', 'source_changed', 'event_overflow', 'event_contended', 'terminal_unknown'}
    if (type(value['failure_codes']) is not tuple or len(value['failure_codes']) > len(failures) or
            any(type(item) is not str or item not in failures for item in value['failure_codes'])):
        raise ValueError('trace_failure')
    allowed_keys = {'kind', 'code', 'module', 'function', 'line', 'handoff_flags', 'actor_unknown',
        'cancel_requested', 'input_ready', 'radio_restore_pending', 'wifi_restore_pending',
        'receive_extra_verified', 'radio_probes', 'failed', 'cancelled', 'received',
        'decrypt_attempted', 'claimed', 'source', 'actors_closed', 'failure', 'call_returned',
        'error_present', 'before_actor', 'current_actor', 'before_normalized', 'current_normalized',
        'normalization_errors', 'field_equal', 'counts', 'comparison_matches', 'bluez_owner',
        'current_settings', 'powered', 'bredr_enabled', 'le_enabled', 'global_advertising',
        'bluez_advertising_active', 'connectable_advert', 'discovering', 'discoverable', 'pairable',
        'max_adv', 'max_scan', 'max_instances', 'active_instances', 'active_instance_ids',
        'connected_devices', 'connected_before', 'connected_after', 'adv_before', 'adv_after'}
    allowed_strings = {'HandoffError', 'ProtocolError', 'RadioObservationError', 'ValueError',
        'TypeError', 'UnicodeError', 'UnicodeDecodeError', 'UnicodeEncodeError', 'RuntimeError',
        'OverflowError', 'OtherError', 'present', 'mta_client_connect_handoff', 'mta_protocol',
        '_check', 'capture', 'decode_json', '_base64', '_integer', 'validate_task_id',
        'P2pInfo.__init__', 'P2pInfo.from_dict', 'invalid_owner', 'invalid_budget', 'wrong_thread',
        'cancelled', 'expired', 'invalid_event', 'already_received', 'not_received',
        'decrypt_failed', 'already_claimed', 'invalid_binding', 'frame_failed', 'radio_schema',
        'radio_unknown', 'radio_fields', 'radio_inconsistent', 'radio_instances', 'radio_peers'}
    def finite(item, depth=0):
        if depth > 6:
            return False
        if item is None or type(item) is bool:
            return True
        if type(item) is int:
            return 0 <= item <= 10000
        if type(item) is str:
            return item in allowed_strings
        if type(item) is tuple:
            return len(item) <= 24 and all(finite(row, depth + 1) for row in item)
        if type(item) is dict:
            return len(item) <= 32 and set(item) <= allowed_keys and all(
                finite(row, depth + 1) for row in item.values())
        return False
    if type(value['events']) is not tuple or len(value['events']) > 24 or not finite(value['events']):
        raise ValueError('trace_events')
    for event in value['events']:
        if (type(event) is not dict or set(event) != {'kind', 'code', 'module', 'function', 'line'} or
                type(event['line']) is not int or not 1 <= event['line'] <= 10000):
            raise ValueError('trace_event_fields')
    if value['terminal'] is not None and (type(value['terminal']) is not dict or not finite(value['terminal'])):
        raise ValueError('trace_terminal')
    if value['overflow_unknown'] and not value['trace_unknown']:
        raise ValueError('trace_overflow_unknown')
    return value



FLAGS = ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
         'peer_activity_seen', 'stop_called', 'stop_returned', 'native_failure_seen',
         'late_peer_activity_seen', 'closure_verified', 'baseline_verified', 'resource_pending')
PROGRESS_BOOL = ('decrypt_attempted', 'frame_claimed', 'handoff_failed', 'bridge_running',
                 'parent_present', 'deployment_present', 'progress_unknown')
STAGE_OPTIONAL_BOOL = ('executor_exact', 'factory_started', 'factory_returned',
    'factory_authenticated', 'plain_present', 'factory_active_present', 'factory_ended', 'factory_success')
STAGE_FIELDS = STAGE_OPTIONAL_BOOL + ('factory_phase', 'stage_unknown')
FACTORY_PHASES = ('new', 'write', 'loader', 'ended')
OBS_BOOL = ('discoverable', 'advertising', 'handoff_received', 'bridge_started', 'request_present',
            'peer_activity', 'native_failure', 'worker_alive', 'helper_retained')
TERMINAL_BOOL = ('operation_retained', 'session_retained', 'worker_alive', 'helper_retained',
    'helper_reader_alive', 'helper_reaped', 'helper_closed', 'key_retained', 'key_closed',
    'bridge_retained', 'bridge_started', 'handoff_received', 'parent_retained', 'deployment_retained',
    'network_before_present', 'network_after_present', 'network_zero_known', 'network_verified',
    'receive_extra_verified', 'radio_restore_pending', 'wifi_restore_pending')
REASONS = ('not_started', 'receive_refused', 'advert_not_observed', 'peer_activity_cancelled',
           'native_operation_failed', 'advertising_observed', 'operation_unknown')

def parse_smoke(raw, component, remote, trials):
    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    rows = re.findall(r'^SMOKE_RESULT=(.*)$', text, re.M)
    if len(rows) != 1:
        raise ValueError('smoke_result_unknown')
    value = ast.literal_eval(rows[0])
    if (type(value) is not dict or set(value) != {'scope', 'complete', 'reason', 'flags',
            'observations', 'terminal', 'trials', 'component'} or
            value['scope'] != 'receive-advertise-cancel-only-v1' or type(value['complete']) is not bool or
            value['reason'] not in REASONS or value['component'] != component or
            type(value['flags']) is not dict or set(value['flags']) != set(FLAGS) or
            any(type(item) is not bool for item in value['flags'].values()) or
            type(value['observations']) is not tuple or len(value['observations']) > 320 or
            value['trials'] != trials or
            value['terminal'] is not None and type(value['terminal']) is not dict or
            remote != (0 if value['complete'] else 1)):
        raise ValueError('smoke_result_fields')
    def counts_valid(row):
        return (type(row) is tuple and len(row) == 6 and
                all(type(item) is int and 0 <= item <= 1000000 for item in row))
    for row in value['observations']:
        if (type(row) is not dict or set(row) != set(OBS_BOOL + PROGRESS_BOOL + STAGE_FIELDS + ('stage', 'state', 'event_counts', 'elapsed_seconds', 'f_process_retained')) or
                any(type(row[key]) is not bool for key in OBS_BOOL + PROGRESS_BOOL) or
                (row['f_process_retained'] is not None if row['progress_unknown'] else
                 type(row['f_process_retained']) is not bool) or
                any(type(row[key]) is not str or re.fullmatch(r'[a-z_]{1,40}', row[key]) is None for key in ('stage', 'state')) or
                not counts_valid(row['event_counts']) or type(row['elapsed_seconds']) is not float or
                not math.isfinite(row['elapsed_seconds']) or not 0 <= row['elapsed_seconds'] <= 135):
            raise ValueError('smoke_observation_fields')
        if type(row['stage_unknown']) is not bool:
            raise ValueError('stage_unknown_type')
        if row['stage_unknown']:
            if any(row[name] is not None for name in STAGE_OPTIONAL_BOOL) or row['factory_phase'] is not None:
                raise ValueError('stage_unknown_not_retained')
        else:
            if (any(type(row[name]) is not bool for name in STAGE_OPTIONAL_BOOL) or
                    row['factory_returned'] and not row['factory_started'] or
                    row['factory_authenticated'] and not (row['factory_started'] and row['factory_returned']) or
                    row['factory_active_present'] and (
                        type(row['factory_phase']) is not str or row['factory_phase'] not in FACTORY_PHASES) or
                    not row['factory_active_present'] and (
                        row['factory_phase'] is not None or row['factory_ended'] or row['factory_success'])):
                raise ValueError('stage_fields')
    ended = value['terminal']
    if ended is not None and (set(ended) != set(TERMINAL_BOOL + ('event_counts',)) or
            any(type(ended[key]) is not bool for key in TERMINAL_BOOL) or not counts_valid(ended['event_counts'])):
        raise ValueError('smoke_terminal_fields')
    if value['complete'] and (not all(value['flags'][name] for name in
            ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
             'stop_called', 'stop_returned', 'closure_verified', 'baseline_verified')) or
            any(value['flags'][name] for name in ('peer_activity_seen', 'late_peer_activity_seen', 'native_failure_seen', 'resource_pending')) or
            value['reason'] != 'advertising_observed' or not value['observations'] or
            value['terminal'] is None or not value['terminal'].get('helper_closed') or
            not value['terminal'].get('network_zero_known') or value['terminal'].get('bridge_started') is not False):
        raise ValueError('smoke_complete_fields')
    return value

def parse_observation(original, v1, diagnostic, helpers, raw):
    remote, component = helpers.parse_result(raw)
    trials, missing = diagnostic.parse_trials(original, raw, component)
    smoke = parse_smoke(raw, component, remote, trials)
    if missing and (remote != 1 or smoke['complete'] is not False or smoke['reason'] != 'operation_unknown' or
            smoke['observations'] != () or smoke['terminal'] is not None or
            any(smoke['flags'][name] is not False for name in
                ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
                 'peer_activity_seen', 'late_peer_activity_seen', 'stop_called', 'stop_returned'))):
        raise ValueError('absent_trial_not_pre_receive')
    projection = diagnostic.parse_inner(original, raw)
    busy = diagnostic.one_literal(raw, 'OBSERVATION_LOCK_BUSY_COUNT')
    if type(busy) is not int or not 0 <= busy <= 2000:
        raise ValueError('observation_busy_count_unknown')
    window = diagnostic.one_literal(raw, 'PHONE_WINDOW_RESULT')
    ready_rows = re.findall(r'^PHONE_DISCOVERY_READY=(.*)$',
        raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n'), re.M)
    if window is None:
        if smoke['observations'] or smoke['complete'] or ready_rows:
            raise ValueError('phone_window_absent_after_observation')
    else:
        if (type(window) is not dict or set(window) !=
                {'ready', 'completed', 'ready_elapsed', 'opportunity_seconds', 'elapsed'} or
                type(window['ready']) is not bool or type(window['completed']) is not bool or
                type(window['opportunity_seconds']) is not float or window['opportunity_seconds'] != 120.0):
            raise ValueError('phone_window_fields')
        if window['ready']:
            if (type(window['ready_elapsed']) is not float or not 0 <= window['ready_elapsed'] <= 15 or
                    type(window['elapsed']) is not float or not 0 <= window['elapsed'] <= 135 or
                    len(ready_rows) != 1 or parse_ready(ready_rows[0].encode('ascii')) != READY_VALUE or
                    not any(row['advertising'] for row in smoke['observations'])):
                raise ValueError('phone_window_ready_unknown')
        elif window['completed'] or window['ready_elapsed'] is not None or window['elapsed'] is not None or ready_rows:
            raise ValueError('phone_window_unready_unknown')
        if window['completed'] and (not window['ready'] or window['elapsed'] < 120.0):
            raise ValueError('phone_window_early_completion')
    if smoke['complete'] and (window is None or window['completed'] is not True):
        raise ValueError('phone_window_not_completed')
    return remote, component, smoke, projection, missing, busy, window


READY_VALUE = dict(ready=True, opportunity_seconds=120.0, accept_allowed=False, send_allowed=False)

def parse_ready(raw):
    value = ast.literal_eval(raw.decode('ascii'))
    if (type(value) is not dict or set(value) != set(READY_VALUE) or
            any(type(value[key]) is not bool or value[key] is not READY_VALUE[key]
                for key in ('ready', 'accept_allowed', 'send_allowed')) or
            type(value['opportunity_seconds']) is not float or value['opportunity_seconds'] != 120.0):
        raise ValueError('live_ready_fields')
    return value

def collect_ready_pipe(pipe, path, inspect_ready, ready, errors, process):
    pending = b''
    dropping = False
    count = 0
    try:
        with path.open('xb') as handle:
            while True:
                block = pipe.read1(4096)
                if not block:
                    break
                handle.write(block)
                handle.flush()
                count += len(block)
                if count > 16777216:
                    raise ValueError('live_raw_budget')
                if not inspect_ready:
                    continue
                for part in block.splitlines(True):
                    pending += part
                    if pending.endswith(b'\n'):
                        line = pending.rstrip(b'\r\n')
                        if not dropping and line.startswith(b'PHONE_DISCOVERY_READY='):
                            value = parse_ready(line[len(b'PHONE_DISCOVERY_READY='):])
                            if ready:
                                raise ValueError('duplicate_live_ready')
                            ready.append(value)
                            print('PHONE_DISCOVERY_READY=' + repr(value), flush=True)
                        pending, dropping = b'', False
                    elif len(pending) > 4096:
                        pending, dropping = b'', True
            if pending and not dropping and pending.startswith(b'PHONE_DISCOVERY_READY='):
                raise ValueError('unterminated_live_ready')
    except BaseException as error:
        errors.append(error)
        try:
            process.kill()
        except OSError:
            pass
    finally:
        pipe.close()

def dispatch_live(transport, adb, private, program, command, timeout):
    """Retain exact pipes; forward only the anchored typed native READY line."""
    prefix = private / '01-phone-discovery'
    errors, ready = [], []
    process = subprocess.Popen([str(transport.ADB), '-t', adb.transport, 'shell', command],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = threading.Event()
    done = threading.Event()
    def watchdog():
        if not done.wait(timeout):
            timed_out.set()
            try:
                process.kill()
            except OSError:
                pass
    workers = [threading.Thread(target=collect_ready_pipe, args=(process.stdout, Path(str(prefix) + '.stdout.raw'), True, ready, errors, process)),
               threading.Thread(target=collect_ready_pipe, args=(process.stderr, Path(str(prefix) + '.stderr.raw'), False, ready, errors, process))]
    for worker in workers:
        worker.start()
    guard = threading.Thread(target=watchdog)
    guard.start()
    try:
        process.stdin.write(program)
        process.stdin.close()
        code = process.wait(timeout=timeout + 1)
    finally:
        done.set()
        guard.join(1)
        for worker in workers:
            worker.join(2)
        write_new(Path(str(prefix) + '.host-exit'),
            (('TIMEOUT' if timed_out.is_set() else str(process.poll())) + '\n').encode('ascii'))
    if any(worker.is_alive() for worker in workers):
        raise ValueError('live_pipe_reader_pending')
    if timed_out.is_set():
        raise RuntimeError('live_host_timeout')
    if errors:
        raise errors[0]
    if code != 0:
        raise RuntimeError('live_adb_host_exit')
    return Path(str(prefix) + '.stdout.raw').read_bytes(), ready

def source_fragment(raw, name):
    text = raw.decode('ascii')
    start = text.index('def ' + name + '(')
    end = text.find('\ndef ', start + 1)
    if end < 0:
        end = text.find('\nif __name__', start)
        if end < 0:
            end = len(text)
    return text[start:end].rstrip() + '\n'


def verify_alias_inputs(inputs, original):
    # Only the actual six-source root/pin closure plus one Factory clock delta.
    derived = original.verify_inputs(inputs)
    previous, current = inputs[PREVIOUS_PROGRESS_HOST[0]], inputs[SELF]
    for name in ('make_source', 'parse_trace', 'parse_smoke', 'parse_observation',
                 'parse_ready', 'collect_ready_pipe', 'dispatch_live', 'parse_progress'):
        if source_fragment(previous, name) != source_fragment(current, name):
            raise ValueError('alias_unrelated_observer_changed')
    if derived != 6:
        raise ValueError('alias_derivation_count')
    return derived

def parse_progress(diagnostic, raw, smoke):
    value = diagnostic.one_literal(raw, 'HANDSHAKE_PROGRESS_RESULT')
    if value is None:
        if smoke['observations'] or smoke['complete']:
            raise ValueError('progress_absent_after_observation')
        return value
    keys = {'peer_seen', 'phase_seconds', 'started_elapsed', 'elapsed', 'outcome'}
    outcomes = {'not_seen', 'waiting', 'native_failure', 'handoff_failed', 'worker_ended',
                'request_seen', 'claimed_with_f', 'phase_deadline'}
    if (type(value) is not dict or set(value) != keys or type(value['peer_seen']) is not bool or
            type(value['phase_seconds']) is not float or value['phase_seconds'] != 15.0 or
            type(value['outcome']) is not str or value['outcome'] not in outcomes):
        raise ValueError('progress_fields')
    if value['peer_seen']:
        if (smoke['flags']['peer_activity_seen'] is not True or
                not any(row['peer_activity'] for row in smoke['observations']) or
                type(value['started_elapsed']) is not float or
                not math.isfinite(value['started_elapsed']) or not 0 <= value['started_elapsed'] <= 135):
            raise ValueError('progress_peer_unknown')
        if value['elapsed'] is None:
            if smoke['reason'] != 'operation_unknown' or value['outcome'] != 'waiting':
                raise ValueError('progress_incomplete_unknown')
        elif (type(value['elapsed']) is not float or not math.isfinite(value['elapsed']) or
                not 0 <= value['elapsed'] <= 20):
            raise ValueError('progress_elapsed_unknown')
        if value['outcome'] == 'not_seen':
            raise ValueError('progress_peer_not_seen')
        if value['outcome'] == 'claimed_with_f' and not any(
                row['frame_claimed'] and row['f_process_retained'] is True and
                row['progress_unknown'] is False for row in smoke['observations']):
            raise ValueError('progress_claimed_without_f')
    elif (value['started_elapsed'] is not None or value['elapsed'] is not None or value['outcome'] != 'not_seen'):
        raise ValueError('progress_unseen_fields')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-alias-clock-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, helpers, program = {}, None, None
    report = dict(schema='p011-receive-alias-clock-v1', mode=mode, passed=False,
        source_checked=False, source_preserved=False, diagnostic_complete=False, device_invoked=False,
        host_exit='NOT_RUN', remote_exit='NOT_RUN', host_error=None, device_outcome='NOT_RUN',
        old_v1_runtime_modified=False, old_runtime_graph_modified=False, old_tests_replayed=0,
        runtime_v2_selected=True, runtime_v2_bytes=RUNTIME_V2[1], runtime_v2_sha256=RUNTIME_V2[2],
        old_graph_ast_replayed=False, source_runtime_graph_executed=False,
        trace_source_bytes=TRACE[1], trace_source_sha256=TRACE[2], trace_result=None,
        compatibility_test_executed=False, old_phone_runtime_modified=False,
        graph_derived=True, frozen_compat_v2_graph_reused=False,
        changed_business_role_count=1, changed_payload_role_count=5,
        frozen_handoff_reused=True, duration_boundary_changed=False, handshake_observer_changed=False,
        handshake_phase_max_seconds=15, handshake_progress=None, handshake_stage_observations=None,
        stage_fields_are_not_authentication=True, stage_inventory_changed=False, alias_metadata_clock_changed=True,
        startup_clock_changed=False, private_io_full_check_preserved=True,
        parent_start_is_not_wifi_proof=True, wifi_initialization_possible=True,
        wifi_connection_verified=False, automatic_file_consent=False,
        ordinary_private_executor_shared=True, private_changed_role_count=1,
        derived_source_count=0, exact_derivation_verified=False,
        automatic_receive_action_requested=args.check_device, http_action_requested=False,
        ui_requested=False, stock_ui_taken_over=False, guardian_requested=False,
        consent_accept_requested=False, scan_requested=False, send_requested=False,
        phone_tested=False, file_transfer_verified=False, full_network_restore_verified=False,
        original_activity_seconds=600, original_cleanup_seconds=60, preparation_max_seconds=15,
        phone_opportunity_seconds=120, observation_max_seconds=135,
        observation_row_max=320, observation_busy_max=2000,
        live_ready_forwarded=False, phone_discovery_user_confirmed=False,
        remote_alarm_seconds=780, host_timeout_seconds=790)
    try:
        raw = (BASE / DIAGNOSTIC[0]).read_bytes()
        if len(raw) != DIAGNOSTIC[1] or digest(raw) != DIAGNOSTIC[2]:
            raise ValueError('diagnostic_pin')
        diagnostic = types.ModuleType('fixed_startup_diagnostic_v2_definitions')
        diagnostic.__file__ = str(BASE / DIAGNOSTIC[0])
        exec(compile(raw, diagnostic.__file__, 'exec'), diagnostic.__dict__)
        original, original_raw = diagnostic.load_definition(COMPAT, 'fixed_receive_compat_definitions')
        v1, v1_raw = diagnostic.load_definition(diagnostic.V1_HOST, 'fixed_advertise_v1_definitions')
        helpers, bootstrap_raw = original.load_checker()
        def retain(path, raw):
            if path in inputs:
                if inputs[path] != raw:
                    raise ValueError('shared_input_changed')
                return
            inputs[path] = raw
            saved = out / 'private-inputs' / path
            saved.parent.mkdir(parents=True, exist_ok=True)
            write_new(saved, raw)
        retain(DIAGNOSTIC[0], raw); retain(COMPAT[0], original_raw)
        base_host, base_raw = load_base_host()
        retain(BASE_HOST[0], base_raw)
        retain(original.ORIGINAL[0], original.ORIGINAL_RAW)
        retain(original.BASE_ORIGINAL[0], original.BASE_ORIGINAL_RAW)
        retain(diagnostic.V1_HOST[0], v1_raw); retain(original.CHECKER[0], bootstrap_raw)
        for pin in (original.MANIFEST, original.PRIVATE_MANIFEST, original.RUNNER, original.TRANSPORT,
                    v1.SMOKE, diagnostic.INNER, RUNTIME_V2, PREVIOUS_PROGRESS_RUNTIME, PREVIOUS_PROGRESS_HOST,
                    DURATION_RUNTIME, OLD_RUNTIME, TRACE, PHONE_HOST,
                    BASE_COMPAT_HOST,
                    original.ORIGINAL_MANIFEST, original.OLD_PRIVATE_MANIFEST):
            retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
        payload = (original.manifest_rows(inputs[original.MANIFEST[0]]) + original.HELPERS +
                   original.manifest_rows(inputs[original.PRIVATE_MANIFEST[0]], private=True) +
                   (original.WPA, original.MONITOR))
        if len(payload) != 75 or len({row[0] for row in payload}) != 75 or sum(row[2] for row in payload) > 4194304:
            raise ValueError('payload_budget')
        for pin in original.ORIGIN_SOURCE_PINS:
            retain(pin[0], helpers.read_fixed(pin[0], pin[1:]))
        for name, path, size, sha in payload:
            retain(path, helpers.read_fixed(path, (size, sha)))
        for path in (SELF,) + CMDS + (TEST_SOURCE,):
            retain(path, helpers.read_fixed(path))
        # Parse only this NEW host and the NEW composition, not old graph/tests.
        ast.parse(inputs[SELF].decode('ascii'))
        ast.parse(inputs[TEST_SOURCE].decode('ascii'))
        derived = verify_alias_inputs(inputs, original)
        report.update(derived_source_count=derived, exact_derivation_verified=True)
        program = make_source(original, v1, diagnostic, helpers, inputs, payload)
        ast.parse(program.decode('ascii'), feature_version=(3, 5))
        write_new(out / 'private-advertise-target.py', program)
        write_new(out / 'private-inputs.json', (json.dumps({path: dict(bytes=len(raw), sha256=digest(raw))
            for path, raw in inputs.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report.update(source_checked=True, source_count=len(inputs), payload_role_count=75,
            target_bytes=len(program), target_sha256=digest(program),
            target_max_line_bytes=max(map(len, program.splitlines())))
        if args.check_device:
            transport = helpers.load_transport(inputs[original.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(780);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-receive-handoff-progress-120s-v2; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report['device_invoked'] = True
            print('PHONE_DISCOVERY_LOG_DIR=' + str(out), flush=True)
            raw, live_ready = dispatch_live(transport, adb, private, program, command, 790)
            report['live_ready_forwarded'] = len(live_ready) == 1
            report['remote_exit'] = v1.exit_marker(raw)
            report['trace_result'] = parse_trace(diagnostic, raw)
            remote, component, smoke, projection, missing, busy, window = parse_observation(
                original, v1, diagnostic, helpers, raw)
            progress = parse_progress(diagnostic, raw, smoke)
            report['handshake_progress'] = progress
            report['handshake_stage_observations'] = [dict((name, row[name]) for name in
                ('elapsed_seconds',) + STAGE_FIELDS) for row in smoke['observations']]
            report['f_process_retained_observed'] = (True if any(row['f_process_retained'] is True
                for row in smoke['observations']) else None if any(row['progress_unknown']
                for row in smoke['observations']) else False)
            report['decryption_attempt_observed'] = any(row['decrypt_attempted'] for row in smoke['observations'])
            report['frame_claim_observed'] = any(row['frame_claimed'] for row in smoke['observations'])
            report.update(diagnostic_complete=True, smoke_complete=smoke['complete'], reason=smoke['reason'],
                trial_absent_startup_branch=missing, original_component_complete=component['complete'],
                inner_error_projection=projection, original_inner_error_available=projection['reason'] == 'observed',
                observation_lock_busy_count=busy, phone_window=window,
                device_outcome='FAIL_STARTUP_BEFORE_RECEIVE' if missing else
                    'PHONE_DISCOVERY_OPPORTUNITY_PASS' if smoke['complete'] else 'PHONE_DISCOVERY_OPPORTUNITY_FAIL')
            for key, value in smoke['flags'].items():
                report[key] = value
            if smoke['terminal'] is not None:
                for key, value in smoke['terminal'].items():
                    report['terminal_' + key] = value
            if report.get('terminal_handoff_received') is True:
                # Classification only: the frozen window deliberately cancels.
                # Original passed/closed/pending predicates below are unchanged.
                report['device_outcome'] = 'HANDOFF_CAPTURED_CANCELLED'
            for key, value in component.items():
                report['component_' + key] = value
            write_new(out / 'private-observation.json', (json.dumps(dict(smoke=smoke, inner=projection),
                sort_keys=True, indent=2) + '\n').encode('ascii'))
    except Exception as error:
        report['host_error'] = type(error).__name__
        write_new(private / 'host-error.txt', traceback.format_exc().encode('utf-8'))
    finally:
        prefix = private / '01-phone-discovery'
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix) + '.' + tag + '.raw')
            if path.exists():
                raw = path.read_bytes(); report[tag + '_bytes'] = len(raw); report[tag + '_sha256'] = digest(raw)
                if tag == 'stdout':
                    value = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
                    rows = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', value, re.M)
                    report['remote_exit'] = int(rows[0]) if len(rows) == 1 else 'UNKNOWN'
        path = Path(str(prefix) + '.host-exit')
        if path.exists():
            value = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT'
        write_new(private / 'remote-exit', (str(report['remote_exit']) + '\n').encode('ascii'))
        try:
            report['source_preserved'] = bool(inputs) and helpers is not None and all(
                helpers.read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                for path, raw in inputs.items()) and program is not None and (
                    out / 'private-advertise-target.py').read_bytes() == program
        except Exception:
            report['source_preserved'] = False
    report['passed'] = (report['source_checked'] and report['source_preserved'] and report['host_error'] is None and
        (not args.check_device or report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and
         report['remote_exit'] == 0 and report.get('smoke_complete') is True and
         report['trace_result'] is not None and report['trace_result']['thread_trace_installed'] is True and
         report['trace_result']['thread_trace_hook_restored'] is True and report['trace_result']['trace_unknown'] is False))
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'One Factory alias metadata/readlink callback clock changed. Original full now remains '
        b'at alias entry/after alias ancestors and all private open/read/raw SHA/anchors/ledger/close. '
        b'StartupReadScope clock remains original; no cache/profile/Trial/JSON/trace/duration changes. '
        b'New guard is fixed method/code/source-bound, actor/cancel/revoke/stop-close/cap/monotonic only; '
        b'it grants no qualification or RF/private IO. Trial last is NOT written. '
        b'Frozen progress-v2 stage observer and original Handoff/Trial/trace retained exactly. '
        b'Production graph ordinary35/private35+helpers/WPA/monitor75 with six necessary root/pin closure. '
        b'Original Owner600+cleanup60, actual-ready120s/peer15s, alarm780/host790/stock/terminal/passed retained. '
        b'Parent started is NOT Wi-Fi connection or file/restore proof. No accept/send/file/UI/Disconnect/'
        b'record cleanup. Default SOURCE checks only six-source exact narrow derivation/new host/test/target '
        b'syntax and budgets, not old graph execution/suite. New HOST component contract not run by entry.\n')
    write_new(out / 'result.json', public); write_new(out / 'README.txt', readme)
    bundle_path = out / 'public-result.zip'
    with zipfile.ZipFile(bundle_path, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', public); bundle.writestr('README.txt', readme)
    with zipfile.ZipFile(bundle_path) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.read('result.json') != public or bundle.read('README.txt') != readme:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, device_outcome=report['device_outcome'],
        result_dir=str(out), public_result_zip=str(bundle_path), zip_sha256=digest(bundle_path.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
