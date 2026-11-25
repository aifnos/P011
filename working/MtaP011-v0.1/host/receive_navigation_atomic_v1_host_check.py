"""Explicit PC-only one-method atomic navigation contract; never a device run."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_navigation_atomic_v1_host_check.py'
TEST = 'tests/test_receive_navigation_atomic_v1.py'
SELECTOR = 'NavigationAtomicV1Contract.test_actual_empty_pair_cancel_transition_and_retained_guards'
SEAL = ('host/host_artifact_seal_v1.py', 6784,
        '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
PINS = (
    (TEST, 20046, '016823530ad18c00330105c150a99190e766aff407dfd4e7204e1d02522821b7'),
    ('tests/test_receive_navigation_refusal_projection_v1.py', 23140,
     '99bcdb66b0b6d0875ddd57114ac7c8273d8cfe5b47a7fab81bb88b8661e7d3be'),
    ('candidate/receive-window-clock-v1/runtime/mta_formal_receive_navigation_session.py', 88850,
     '2aa5c840d9df5293fe10d385060821269d5170da4261b751c49af091ccf31f48'),
    ('candidate/formal-receive-v3/runtime/mta_service.py', 155732,
     '76f48871bb4c2a3b72bb308e9bef56b3d509f01ef45c7ac2808d210acedd6960'),
    ('candidate/formal-receive-v3/runtime/mta_receive_trial.py', 64493,
     'b3ffef7c593d254c375f8f4f0f97aa97cb7027db03e88861db639294dd1de13a'),
    ('candidate/receive-navigation-frame-v2/runtime/ui_session.py', 95351,
     '0c53b23051e5d79cdc392b2f89d3d21de2425028ff4f76292284a72f631cb4fe'),
    ('candidate/receive-navigation-atomic-v1/generate.py', 11019,
     '7a2cbc24c19c850c17244162ca033bf83e8b39246e901becc418fbe265e1f12d'),
    ('candidate/receive-navigation-atomic-v1/runtime/ui_session.py', 100162,
     'cde8ae626632e5d86acb2cc741b7d22eb18582b58ed6d6fd48160c008b62225e'),
    ('candidate/receive-navigation-atomic-v1/exactsource-delta.json', 7470,
     '9af5097dda522efa3bd9b5f406308f3c43123e7159a1ef78251d835b8dd35613'),
    ('candidate/receive-navigation-atomic-v1/generation.json', 1472,
     'bea9c4b9f0bca12c1dbbb6d570a925cdc2a4daf144c3f81c30eb123987f3de49'),
)
MARKER = b'RECEIVE_NAVIGATION_ATOMIC_V1_HOST_PASS methods=1 old_methods=0 real_rlocks=true actual_cancel=true'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-host', action='store_true')
    args = parser.parse_args()
    if not args.run_host:
        print('SOURCE_ONLY; affected_atomic_HOST_method_not_run; no_device')
        return 0
    seal_raw = (BASE / SEAL[0]).read_bytes()
    if (len(seal_raw), sha(seal_raw)) != SEAL[1:]:
        raise ValueError('original_sealer_pin')
    seal = types.ModuleType('atomic_original_artifact_sealer')
    exec(compile(seal_raw, str(BASE / SEAL[0]), 'exec'), seal.__dict__)
    out = BASE / 'results' / ('receive-navigation-atomic-v1-host-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    inputs = {}
    evidence = seal.InputEvidence(inputs)
    code, timed_out, invoked, unchanged = None, False, False, False
    stdout, stderr, failure, detail = b'', b'', None, b''
    started = time.monotonic()
    try:
        evidence.read(BASE / SELF, key=SELF)
        evidence.read(BASE / SEAL[0], key=SEAL[0], pin=SEAL[1:])
        for relative, size, pin in PINS:
            evidence.read(BASE / relative, key=relative, pin=(size, pin))
        evidence.snapshot(out, lambda key: key)
        snapshot = out / 'private-inputs'
        invoked = True
        try:
            process = subprocess.run([sys.executable, '-I', '-B', str(snapshot / TEST), SELECTOR],
                cwd=str(snapshot), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            code, stdout, stderr = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout, stderr = error.stdout or b'', error.stderr or b''
        unchanged = all((BASE / relative).read_bytes() == raw and
                        (snapshot / relative).read_bytes() == raw for relative, raw in inputs.items())
    except BaseException as error:
        failure = type(error).__name__ + ':' + str(error)
        detail = traceback.format_exc().encode('utf-8')
    finally:
        evidence.snapshot(out, lambda key: key)
        seal.fresh(out / 'private-raw/stdout.raw', stdout)
        seal.fresh(out / 'private-raw/stderr.raw', stderr)
        if detail:
            seal.fresh(out / 'private-raw/host-exception.txt', detail)
    passed = failure is None and code == 0 and not timed_out and unchanged and stdout.count(MARKER) == 1
    report = dict(schema='p011-receive-navigation-atomic-v1-affected-host',
        passed=passed, host_exit=0 if passed else 1, child_exit=code, error=failure,
        child_invoked=invoked, timed_out=timed_out, host_elapsed_seconds=time.monotonic() - started,
        source_unchanged=unchanged, methods_requested=1, old_methods_run=0, selector=SELECTOR,
        child_reads_private_snapshot=True, child_python_isolated=True,
        actual_predicates_and_worker_guard_selected_ast=True, actual_state_action_trial_revoke_selected_ast=True,
        canonical_binding_and_http_peripheral_fixtures=True, real_host_rlocks_events_threads=True,
        full_owner_graph_executed=False, device_tested=False, rf_tested=False, phone_tested=False,
        gui_tested=False, restoration_verified=False, performance_measured=False,
        runtime75_modified=False, runner_modified=False, cached_four_guards_unchanged=True,
        run_fixed_line=1246, navigation_failure_line=1560, runner_observer_line=817,
        sources=[dict(path=relative, bytes=len(raw), sha256=sha(raw)) for relative, raw in inputs.items()],
        streams=[dict(name=name, bytes=len(raw), sha256=sha(raw)) for name, raw in
                 (('stdout.raw', stdout), ('stderr.raw', stderr))])
    sealed = seal.seal_result(out, report,
        b'One affected HOST method only, using selected actual predicate/helper/guard/cancel AST.\n'
        b'Real HOST RLocks, Events and threads reproduce the old split-observation refusal and '
        b'verify the atomic observation; Owner/State/Trial canonical binding, HTTP and peripherals '
        b'remain explicit models. No complete Worker/Owner graph, device, RF, GUI, phone, '
        b'performance or restoration acceptance.\n'
        b'No previous suite is rerun. Sources and separate raw streams remain private. '
        b'Public ZIP contains scalar result and this boundary only.\n')
    print(json.dumps(dict(passed=sealed['report']['passed'], child_exit=code,
        host_exit=sealed['host_exit'], result=str(out / 'result.json'),
        zip=None if sealed['archive'] is None else str(sealed['archive']),
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
