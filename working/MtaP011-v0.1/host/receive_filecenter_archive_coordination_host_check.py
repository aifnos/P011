"""One new fixed HOST coordination method; no target or old-test replay."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_filecenter_archive_coordination.py'
INPUTS = (TEST, 'host/receive_filecenter_archive_coordination_host_check.py',
    'HOST_MTA_RECEIVE_FILECENTER_ARCHIVE_COORDINATION_CHECK.cmd',
    'candidate/receive-filecenter-archive-v1/runtime/ui_session.py')
PINS = {
    TEST: (26164, '1a13cb0a876992ccb35dcd2a3ee13ae9ec5557bb36b3fa2b8c02a2c4da0c0489'),
    INPUTS[3]: (104680, '04d3bbbbda2bccf67b29154a5b481d70cecb17647dc8cec51eb045c679d24a7c'),
}
EXPECTED_CASES = (
    'static_actual_recipe_and_finally_order', 'window_600_and_original_caps',
    'window_original_archive_policy_required', 'window_cap_substitution_refused',
    'window_expiry_uses_original_cutoff', 'closed_original_allows_finish',
    'no_filecenter_constructor_allows_finish', 'unknown_close_cancels_without_finish',
    'cached_true_actual_closed_false_cancels', 'cached_true_guardian_unsettled_cancels',
    'changed_companion_creator_not_invoked', 'passive_error_retained_before_cancel',
    'abort_remaining_wait_clipped', 'abort_expiry_zero_wait_no_renewal',
    'abort_once_keeps_original_inventory', 'revoke_error_still_stops_and_closes_state',
    'stop_error_still_closes_state', 'state_close_unknown_never_closes_owner',
    'changed_owner_refuses_all_actor_calls', 'changed_original_state_cap_refuses_calls',
    'invalid_clock_retains_refusal_without_state_wait', 'noop_projection_strict_scalar_scope',
    'archived_projection_never_calls_getter', 'extra_projection_field_refused_raw_retained',
    'unknown_projection_reason_refused', 'missing_original_projection_refused',
    'native_grant_true_refused', 'receive_grant_true_refused',
    'boolean_history_count_refused', 'owner_not_closed_projection_refused',
    'changed_projection_namespace_refused', 'contradictory_rename_projection_refused',
)
ACTUAL_SCOPE_FIELDS = (
    'actual_selected_ui_error_and_need', 'actual_selected_filecenter_current',
    'actual_selected_original_window_helpers', 'actual_selected_archive_projection_retainer',
    'actual_selected_archive_refusal_identity_guard', 'actual_selected_archive_refusal_coordinator',
    'actual_selected_finish_after_filecenter_coordinator', 'actual_selected_finite_archive_projection',
    'actual_run_fixed_static_recipe_and_order', 'actual_host_current_thread',
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush()
        os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('snapshot_readback')


def main():
    if sys.argv[1:]: raise ValueError('fixed_HOST_only')
    out = BASE / 'results' / ('receive-filecenter-archive-coordination-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources, stdout, stderr = {}, b'', b''
    report = dict(schema='p011-receive-filecenter-archive-coordination-host-v1', passed=False,
        host_exit=None, child_exit=None, remote_exit=None, checker_exit=None,
        new_methods=1, executed_methods=0, old_methods=0,
        actual_selected_ui_error_and_need=False, actual_selected_filecenter_current=False,
        actual_selected_original_window_helpers=False,
        actual_selected_archive_projection_retainer=False,
        actual_selected_archive_refusal_identity_guard=False,
        actual_selected_archive_refusal_coordinator=False,
        actual_selected_finish_after_filecenter_coordinator=False,
        actual_selected_finite_archive_projection=False,
        actual_run_fixed_static_recipe_and_order=False, actual_host_current_thread=False,
        clock_model=True, owner_model=True, state_model=True, gate_model=True,
        companion_model=True, guardian_inventory_model=True, module_inventory_model=True,
        original_definition_identity_inventory_model=True, descriptor_inventory_model=True,
        finish_owner_callback_model=True, owner_cleanup_callback_model=True,
        state_cleanup_callback_model=True, original_archive_data_model=True,
        whole_ui_worker=False, actual_ui_run_fixed=False, actual_fixed_session_constructor=False,
        actual_owner_constructor=False, actual_owner_startup=False, actual_owner_close=False,
        actual_owner_finish_consumer=False, actual_state_constructor=False, actual_state_close=False,
        actual_session_constructor=False, actual_session_worker=False, actual_session_finalizer=False,
        actual_companion_constructor=False, actual_companion_close=False,
        actual_audio_guardian=False, actual_completed_archive_consumer=False,
        actual_boot_load=False, actual_thread_start=False, actual_popen=False,
        actual_os_descriptor=False, actual_network=False, actual_parent=False,
        native=False, rf=False, ui=False, device=False, phone=False,
        receive_verified=False, archive_verified=False, restoration_verified=False,
        production_admitted=False, source_count=0, source_preserved=False,
        contracts=0, case_count=0, exact_case_sequence=False, error=None)
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            sources[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json',
             (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        for name, pin in PINS.items():
            if (len(sources[name]), digest(sources[name])) != pin:
                raise ValueError('fixed_archive_coordination_source_changed')
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(out / 'private-inputs' / TEST)],
                cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
            stdout, stderr = child.stdout, child.stderr
            report['host_exit'] = report['child_exit'] = child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'timeout'
        marks = re.findall(rb'^RECEIVE_ARCHIVE_COORD_CONTRACTS=([0-9]+)\r?$', stdout, re.M)
        cases = re.findall(rb'^HOST_RECEIVE_ARCHIVE_COORD_CASE=([a-z0-9_]+)\r?$', stdout, re.M)
        report['contracts'] = int(marks[0]) if len(marks) == 1 else 0
        report['case_count'] = len(cases)
        report['exact_case_sequence'] = tuple(row.decode('ascii') for row in cases) == EXPECTED_CASES
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    # Complete raw child channels are retained even on pre-child refusal.
    # Fixed inputs, raw errors and channel contents stay out of the public ZIP.
    for name, raw in (('stdout', stdout), ('stderr', stderr)):
        save(out / (name + '.raw'), raw)
        report[name + '_bytes'], report[name + '_sha256'] = len(raw), digest(raw)
    save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
    save(out / 'child-exit.raw', (str(report['child_exit']) + '\n').encode('ascii'))
    save(out / 'remote-exit.raw', b'NOT_RUN_HOST_ONLY\n')
    report['source_count'] = len(sources)
    try:
        report['source_preserved'] = (len(sources) == len(INPUTS) and all(
            (BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items()))
    except Exception as error:
        if report['error'] is None: report['error'] = type(error).__name__
        save(out / 'private-preservation-error.txt', str(error).encode('utf-8'))
    report['passed'] = (report['host_exit'] == 0 and report['child_exit'] == 0 and
        report['error'] is None and report['source_preserved'] and
        report['contracts'] == 32 and report['case_count'] == 32 and report['exact_case_sequence'] and
        len(re.findall(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M)) == 1 and
        len(re.findall(rb'^OK\r?$', stderr, re.M)) == 1)
    if report['passed']:
        report['executed_methods'] = 1
        for name in ACTUAL_SCOPE_FIELDS:
            report[name] = True
    report['checker_exit'] = 0 if report['passed'] else 1
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST method / 32 cases executes only selected actual frozen UI '
        b'coordination, original-window, passive FileCenter identity and finite '
        b'archive-projection helpers, plus the selected actual UiSessionError/need. '
        b'Actual run_fixed is parsed solely for its fixed constructor recipe and '
        b'finally call order; its body is never executed. Python current-thread '
        b'is a real HOST primitive. Clock, Owner, State, Gate, Companion, audio '
        b'guardian, original definitions/modules/descriptors, finish/cleanup '
        b'callbacks and original archive DATA are explicit HOST models. The '
        b'archived DATA case proves only projection validation, not an archive. '
        b'Actual-execution flags remain false until the complete fixed new method '
        b'passes; static model labels are scope declarations. No whole UI worker, '
        b'FixedSession/Owner/State/Session/Companion constructor, actual startup, '
        b'Owner finish/close, State/Companion close, archive consumer, Boot load, '
        b'thread start, Popen, real descriptors/network/Parent, Native, RF, GUI, '
        b'P011, phone, receive, archive or restoration runs. No old audio13, '
        b'send26, Gate18, State16 or other method is replayed. Complete raw '
        b'stdout/stderr, child/host/checker exits, remote NOT_RUN, private errors '
        b'and all four fixed source snapshots remain PRIVATE. This ZIP contains '
        b'only this non-identifying result and README.\n')
    save(out / 'result.json', result)
    save(out / 'README.txt', note)
    save(out / 'checker-exit.raw', (str(report['checker_exit']) + '\n').encode('ascii'))
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return report['checker_exit']


if __name__ == '__main__':
    raise SystemExit(main())
