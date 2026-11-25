"""One fixed new HOST cleanup-budget method; never target/RF/old-test replay."""
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
TEST = 'tests/test_formal_send_cleanup_budget.py'
INPUTS = (TEST, 'host/formal_send_cleanup_budget_host_check.py',
    'HOST_MTA_FORMAL_SEND_CLEANUP_BUDGET_CHECK.cmd',
    'candidate/formal-send-v1/runtime/mta_service.py',
    'candidate/formal-send-v1/runtime/mta_client_service_owner.py',
    'candidate/formal-send-v1/runtime/formal_send_session.py')
PINS = {
    TEST: (28972, '0b5aac9a54639fa8db1af76a76f1d135cae8d35108358c03158de078d69c7612'),
    INPUTS[3]: (145518, '4c580381a6ed2988ea6fa8f968e8145d3ac21748b49e7e5e9eff7809c55b8c43'),
    INPUTS[4]: (46866, '60a5010c02d9e545b437877a939f73eb93fb1262dfeec37e3bf8d714ecf553bc'),
    INPUTS[5]: (21984, '290aa340a0aa646563625a2c64297886f11393f6f1e9986920fa9daee63aca19'),
}
EXPECTED_CASES = (
    'state_join_clipped_to_original_remaining', 'state_join_clipped_to_caller_remaining',
    'state_expiry_zero_wait_still_revokes_and_closes', 'state_partial_session_not_closed',
    'state_changed_original_cap_never_waits', 'state_invalid_budget_starts_nothing',
    'probe_shared_deadline_and_per_actor_remaining', 'probe_expiry_zero_wait_known_actor',
    'probe_unknown_spawn_has_no_actor_operations', 'probe_cached_closed_missing_process_refused',
    'probe_known_unspawned_inventory_not_misclassified', 'probe_foreign_process_never_touched',
    'probe_foreign_pipe_never_touched', 'probe_communicate_failure_keeps_original_error_and_raw',
    'probe_invalid_budget_starts_nothing', 'owner_remaining_clip_and_original_cap_retained',
    'owner_expiry_zero_wait_still_closes_known_socket', 'owner_known_failure_not_erased',
    'owner_idempotent_close_never_renews', 'outer_expiry_still_owner_loader_and_fd_close',
    'outer_owner_failure_still_closes_known_fd', 'outer_fd_failure_retained_other_fd_closed',
    'outer_unknown_fd_not_touched', 'outer_partial_owner_not_invoked_known_fd_closed',
    'outer_idempotent_failure_keeps_originals', 'outer_changed_window_refused_before_foreign_io',
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
    out = BASE / 'results' / ('formal-send-cleanup-budget-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources, stdout, stderr = {}, b'', b''
    report = dict(schema='p011-formal-send-cleanup-budget-host-v1', passed=False,
        host_exit=None, remote_exit=None, checker_exit=None, new_methods=1, old_methods=0,
        actual_selected_state_cleanup_methods=False, actual_probe_closed_helper=False,
        actual_selected_owner_cleanup_methods=False, actual_selected_outer_cleanup_methods=False,
        actual_outer_constructor=False, actual_host_mutex_events=False,
        clock_model=True, process_model=True, pipe_model=True, os_descriptor_model=True,
        session_model=True, trial_model=True, thread_join_model=True,
        owner_startup_model=True, owner_io_model=True, http_model=True,
        outer_owner_model=True, outer_loader_model=True, pid_module_inventory_model=True,
        whole_state_constructor=False, actual_owner_startup=False, actual_boot_load=False,
        actual_session78_constructor=False, actual_session_worker=False,
        actual_session_finalizer=False, actual_popen=False, actual_os_descriptor=False,
        actual_network=False, actual_parent=False, native=False, rf=False,
        ui=False, device=False, phone=False, send_verified=False,
        restoration_verified=False, production_admitted=False,
        source_count=0, source_preserved=False, contracts=0, case_count=0,
        exact_case_sequence=False, error=None)
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
                raise ValueError('fixed_cleanup_source_changed')
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(out / 'private-inputs' / TEST)],
                cwd=str(out / 'private-inputs'), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False)
            stdout, stderr = child.stdout, child.stderr
            report['host_exit'] = child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            report['error'] = 'timeout'
        marks = re.findall(rb'^FORMAL_SEND_CLEANUP_BUDGET_CONTRACTS=([0-9]+)\r?$', stdout, re.M)
        cases = re.findall(rb'^HOST_SEND_CLEANUP_BUDGET_CASE=([a-z0-9_]+)\r?$', stdout, re.M)
        report['contracts'] = int(marks[0]) if len(marks) == 1 else 0
        report['case_count'] = len(cases)
        report['exact_case_sequence'] = tuple(row.decode('ascii') for row in cases) == EXPECTED_CASES
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    # Save complete child channels even for a pre-child refusal or timeout.
    # Private snapshots/logs are never copied into the shareable ZIP.
    for name, raw in (('stdout', stdout), ('stderr', stderr)):
        save(out / (name + '.raw'), raw)
        report[name + '_bytes'], report[name + '_sha256'] = len(raw), digest(raw)
    save(out / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
    save(out / 'remote-exit.raw', b'NOT_RUN_HOST_ONLY\n')
    report['source_count'] = len(sources)
    try:
        report['source_preserved'] = (len(sources) == len(INPUTS) and all(
            (BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items()))
    except Exception as error:
        if report['error'] is None: report['error'] = type(error).__name__
        save(out / 'private-preservation-error.txt', str(error).encode('utf-8'))
    report['passed'] = (report['host_exit'] == 0 and report['error'] is None and
        report['source_preserved'] and report['contracts'] == 26 and report['case_count'] == 26 and
        report['exact_case_sequence'] and
        re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
        re.search(rb'^OK\r?$', stderr, re.M) is not None)
    if report['passed']:
        for name in ('actual_selected_state_cleanup_methods', 'actual_probe_closed_helper',
                     'actual_selected_owner_cleanup_methods', 'actual_selected_outer_cleanup_methods',
                     'actual_outer_constructor', 'actual_host_mutex_events'):
            report[name] = True
    report['checker_exit'] = 0 if report['passed'] else 1
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST method / 26 cases executes selected actual frozen State, '
        b'Owner and outer cleanup control flow, the actual probe-closed helper and '
        b'the selected actual outer constructor. Python RLock/Event/current-thread '
        b'objects are real HOST primitives. Clock, process, pipe, OS descriptor, '
        b'Session, Trial, thread-join, HTTP, Owner-startup/IO, outer-Owner/Loader and '
        b'PID/module inventories are explicit models, not admission receipts. '
        b'No whole State constructor, Owner startup, Boot load, Session78 constructor, '
        b'Session worker/finalizer, real Popen/descriptors/network, original Parent, '
        b'Native, RF, UI, P011, phone, send or restoration runs. No older State16 '
        b'or Gate18 method is replayed. Complete raw stdout/stderr, child exit, '
        b'private errors and all six fixed source snapshots remain PRIVATE. '
        b'This ZIP contains only this non-identifying report and README.\n')
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
