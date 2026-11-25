"""Default SOURCE; explicit --check-host exercises only the new terminal envelope.

Ordinary namespace/type/lock/event fixtures are not real P011 lifecycles.
No old main/test, device, RF, graph, phone entry or business deadline change.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_handoff_terminal_v1_check.py'
CMD = 'HOST_MTA_RECEIVE_HANDOFF_TERMINAL_V1_CHECK.cmd'
PINS = (
    ('host/host_artifact_seal_v1.py', 6784,
     '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7'),
    ('host/receive_handoff_terminal_v1_generate.py', 5914,
     '28da59a285d8ab3d2849dcdd359387fab47b66f9616b0a42bad2c8227c6b2b9f'),
    ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
     '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657'),
    ('candidate/receive-handoff-terminal-v1/runtime/handoff_terminal.py', 15049,
     'c77db43cb42d60f624b96bacb92e5a8c03b943faf82921059ab4d04b15085c97'))
SCHEMA = 'p011-receive-handoff-terminal-v1-host-contract'
CASES = ('normal', 'phone-raises', 'terminal-bad-state', 'terminal-locked', 'changed-modules',
         'existing-main-hook', 'existing-default-hook', 'radio-normalize-error', 'missing-component')
HOST_TIMEOUT = 10
OUTPUT_LIMIT = 65536
PUBLIC_FIELDS = {'schema', 'exception_events_observed', 'thread_trace_installed',
    'thread_trace_hook_restored', 'trace_unknown', 'overflow_unknown', 'failure_codes', 'events', 'terminal'}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(index):
    key, size, pin = PINS[index]
    raw = (BASE / key).read_bytes()
    need((len(raw), digest(raw)) == (size, pin), 'input_pin')
    return raw


def definitions(key, raw):
    module = types.ModuleType('_terminal_contract_' + Path(key).stem)
    module.__file__ = str(BASE / key)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def foreign_hook(frame, event, argument):
    # Explicit HOST-only foreign precondition fixture; no local tracing.
    return None


def fixture(terminal, case):
    modules = {role: types.ModuleType(role) for role in terminal.ROLE_NAMES}
    service, radio = modules['mta_service'], modules['mta_receive_radio_baseline']
    handoff = modules['mta_client_connect_handoff']
    service.State = type('FixtureState', (), {})
    service.Operation = type('FixtureOperation', (), {})
    service._CAPABILITY_CREATOR = object()
    handoff.ReceiveConnectHandoff = type('FixtureHandoff', (), {})
    radio.RadioObservationError = type('FixtureRadioObservationError', (Exception,), {})
    radio._BOOL_FIELDS = ('powered',)
    radio._BYTE_FIELDS = ('adapter_flags',)
    radio_error = radio.RadioObservationError()
    radio_error.code = 'radio_schema'

    def normalize(observed):
        if observed.get('fixture_invalid') is True:
            raise radio_error
        return (True, False, True, False, True, (), ())

    radio.normalize = normalize
    state, operation = service.State(), service.Operation()
    state.lock = threading.Lock()
    state.operation = operation
    state.radio_restore_pending = state.wifi_restore_pending = False
    state.probe_actors = []
    operation.kind = 'receive'
    operation.actor_unknown = False
    operation.receive_extra_verified = True
    operation.cancelled, operation.input_ready = threading.Event(), threading.Event()
    operation.input_ready.set()
    retained_handoff = handoff.ReceiveConnectHandoff()
    for key, value in (('_failed', False), ('_cancelled', False), ('_received', False),
                       ('_decrypt_attempted', True), ('_claimed', False)):
        setattr(retained_handoff, key, value)
    operation.client_handoff = retained_handoff
    before = dict(bluez_owner=True, current_settings=1, powered=True, adapter_flags=0)
    after = dict(before)
    if case == 'radio-normalize-error': before['fixture_invalid'] = True

    def actor(parsed):
        stdout, stderr = types.SimpleNamespace(closed=True), types.SimpleNamespace(closed=True)
        process = types.SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
        value = dict(creator=service._CAPABILITY_CREATOR, _creator_original=service._CAPABILITY_CREATOR,
            actors=state.probe_actors, process=process, _process_original=process, parsed=parsed,
            _parsed_original=parsed, returned=parsed, _returned_original=parsed, closed=True,
            spawn_pending=False, spawn_unknown=False, returncode=0, stdout=stdout, stderr=stderr, failure=None)
        state.probe_actors.append(value)
        return value

    before_actor, after_actor = actor(before), actor(after)
    state._bluetooth_probe_actor_original = before_actor
    state._bluetooth_caps_original = before
    state.radio_restore_probes = [dict(creator=service._CAPABILITY_CREATOR, actors=state.probe_actors,
        before_actor=before_actor, before=before, current_actor=after_actor, current=after,
        call_returned=True, error=None)]
    loader = types.SimpleNamespace(modules=modules)
    owner = types.SimpleNamespace(loader=loader, service=service, state=state, _state_original=state)
    phone = types.ModuleType('host_terminal_only_phone_fixture')
    phone._RETAINED = types.SimpleNamespace(owner=owner, loader=loader)
    runner, artifacts, returned = object(), object(), object()
    raised = RuntimeError('private-host-fixture-exception')
    replacement = types.ModuleType('host_terminal_changed_module_fixture')

    def phone_run(actual_runner, actual_artifacts):
        need(actual_runner is runner and actual_artifacts is artifacts, 'phone_arguments')
        if case in ('existing-main-hook', 'existing-default-hook'):
            raise AssertionError('phone_must_not_run')
        if case == 'phone-raises': raise raised
        if case == 'changed-modules': sys.modules['mta_protocol'] = replacement
        return returned

    phone.run_fixed = phone_run
    if case == 'terminal-bad-state': owner._state_original = object()
    if case == 'terminal-locked': need(state.lock.acquire(False), 'fixture_lock')
    if case == 'missing-component': phone._RETAINED = None
    return dict(modules=modules, phone=phone, state=state, runner=runner, artifacts=artifacts,
                returned=returned, raised=raised, replacement=replacement)


def check_public(value, case):
    need(type(value) is dict and set(value) == PUBLIC_FIELDS and
         value['schema'] == 'receive-handoff-terminal-v1' and
         value['exception_events_observed'] is False and value['thread_trace_installed'] is False and
         value['thread_trace_hook_restored'] is False and value['overflow_unknown'] is False and
         value['events'] == (), 'terminal_public')
    unknown = case in ('terminal-bad-state', 'terminal-locked', 'changed-modules',
                       'existing-main-hook', 'existing-default-hook')
    failures = {'terminal-bad-state': ('terminal_unknown',), 'terminal-locked': ('terminal_unknown',),
        'changed-modules': ('source_changed',), 'existing-main-hook': ('current_hook_changed', 'existing_trace'),
        'existing-default-hook': ('existing_trace',)}.get(case, ())
    need(value['trace_unknown'] is unknown and value['failure_codes'] == failures, 'terminal_unknown')
    projected = value['terminal']
    if case in ('terminal-bad-state', 'terminal-locked', 'changed-modules', 'missing-component'):
        need(projected is None, 'terminal_none')
        return
    expected = dict(handoff_flags=dict(failed=False, cancelled=False, received=False,
        decrypt_attempted=True, claimed=False), actor_unknown=False, cancel_requested=False,
        input_ready=True, radio_restore_pending=False, wifi_restore_pending=False,
        receive_extra_verified=True)
    need(type(projected) is dict and set(projected) == set(expected) | {'radio_probes'} and
         all(projected[key] == expected[key] for key in expected), 'terminal_projection')
    probes = projected['radio_probes']
    need(type(probes) is tuple and len(probes) == 1, 'terminal_radio_count')
    probe = probes[0]
    actor = dict(source=True, actors_closed=True, failure=None)
    normal = dict(source=True, call_returned=True, error_present=False, before_actor=actor,
        current_actor=actor, before_normalized=True, current_normalized=True,
        normalization_errors=(None, None), field_equal=dict(bluez_owner=True, current_settings=True,
            powered=True, adapter_flags=True, active_instance_ids=True, connected_devices=True),
        counts=dict(connected_before=0, connected_after=0, adv_before=0, adv_after=0), comparison_matches=True)
    if case == 'radio-normalize-error':
        normal.update(before_normalized=False,
            normalization_errors=(dict(kind='RadioObservationError', code='radio_schema'), None),
            field_equal=None, counts=None, comparison_matches=None)
    need(probe == normal, 'terminal_radio_projection')


def case_run(terminal, case):
    need(sys.gettrace() is None and getattr(threading, '_trace_hook', object()) is None, 'existing_host_hook')
    baseline_threads = tuple(threading.enumerate())
    values = fixture(terminal, case)
    modules = values['modules']
    missing, previous = object(), {}
    hooks_ok = threads_ok = modules_ok = lock_ok = False
    public = None
    try:
        for role, module in modules.items():
            previous[role] = sys.modules.get(role, missing)
            sys.modules[role] = module
        if case == 'existing-main-hook': sys.settrace(foreign_hook)
        if case == 'existing-default-hook': threading.settrace(foreign_hook)
        caught = None
        result = None
        try:
            result = terminal.run_fixed(values['runner'], values['artifacts'], values['phone'])
        except BaseException as error:
            caught = error
        if case == 'phone-raises':
            need(caught is values['raised'] and result is None, 'original_exception_identity')
        elif case in ('existing-main-hook', 'existing-default-hook'):
            need(type(caught) is ValueError and caught.args == ('existing_trace',) and result is None,
                 'original_hook_precondition')
        else:
            need(caught is None and result is values['returned'], 'original_return_identity')
        need(type(terminal._RETAINED) is terminal.TraceOwner and
             terminal._RETAINED.phone is values['phone'], 'retained_identity')
        public = terminal.public_result()
        check_public(public, case)
        hooks_ok = (sys.gettrace() is (foreign_hook if case == 'existing-main-hook' else None) and
            getattr(threading, '_trace_hook', object()) is
            (foreign_hook if case == 'existing-default-hook' else None))
        need(hooks_ok, 'foreign_hook_preserved')
        need(tuple(threading.enumerate()) == baseline_threads, 'no_new_threads')
        threads_ok = True
        if case == 'terminal-locked':
            need(values['state'].lock.locked(), 'foreign_lock_preserved')
            values['state'].lock.release()
        lock_ok = values['state'].lock.acquire(False)
        need(lock_ok, 'terminal_lock_released')
        values['state'].lock.release()
    finally:
        # Restore only explicit fixture hook/aliases, never foreign production state.
        if case == 'existing-main-hook' and sys.gettrace() is foreign_hook: sys.settrace(None)
        if case == 'existing-default-hook' and getattr(threading, '_trace_hook', None) is foreign_hook:
            threading.settrace(None)
        if case == 'terminal-locked' and values['state'].lock.locked(): values['state'].lock.release()
        allowed = list(modules.values()) + [values['replacement']]
        for role, module in modules.items():
            current = sys.modules.get(role, missing)
            if any(current is item for item in allowed):
                if previous[role] is missing: del sys.modules[role]
                else: sys.modules[role] = previous[role]
        modules_ok = all(sys.modules.get(role, missing) is previous[role] for role in modules)
        terminal._RETAINED = None
    need(modules_ok and sys.gettrace() is None and
         getattr(threading, '_trace_hook', object()) is None, 'fixture_restoration')
    return dict(case=case, passed=True, original_return_or_exception_preserved=True,
        hooks_preserved_during_call=hooks_ok, fixture_hooks_restored=True, no_new_threads=threads_ok,
        modules_restored=modules_ok, lock_released=lock_ok, public=public,
        phone_precondition_rejected=case in ('existing-main-hook', 'existing-default-hook'),
        terminal_none_not_safety_receipt=case == 'missing-component')


def worker():
    rows = []
    report = dict(schema=SCHEMA + '-worker', passed=False, cases=rows, error=None)
    try:
        generator = definitions(PINS[1][0], fixed(1))
        expected = generator.make_source(fixed(2))
        candidate = fixed(3)
        need(candidate == expected, 'candidate_readback')
        terminal = definitions(PINS[3][0], candidate)
        need(terminal.public_result() is None, 'initial_public_none')
        for case in CASES:
            rows.append(case_run(terminal, case))
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__
        if type(error) is ValueError and len(error.args) == 1:
            value = error.args[0]
            if type(value) is str and value.isascii() and value.isidentifier(): report['error'] += ':' + value
        traceback.print_exc(file=sys.stderr)
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False), flush=True)
    return 0 if report['passed'] else 1


def parse_worker(raw):
    need(len(raw) <= OUTPUT_LIMIT, 'output_limit')
    lines = raw.decode('ascii').splitlines()
    need(len(lines) == 1, 'worker_envelope')
    value = json.loads(lines[0])
    need(type(value) is dict and set(value) == {'schema', 'passed', 'cases', 'error'} and
         value['schema'] == SCHEMA + '-worker' and value['passed'] is True and value['error'] is None and
         type(value['cases']) is list and tuple(row['case'] for row in value['cases']) == CASES,
         'worker_schema')
    for row in value['cases']:
        fields = {'case', 'passed', 'original_return_or_exception_preserved', 'hooks_preserved_during_call',
            'fixture_hooks_restored', 'no_new_threads', 'modules_restored', 'lock_released', 'public',
            'phone_precondition_rejected', 'terminal_none_not_safety_receipt'}
        need(type(row) is dict and set(row) == fields and row['passed'] is True and
             row['phone_precondition_rejected'] is (row['case'] in ('existing-main-hook', 'existing-default-hook')) and
             row['terminal_none_not_safety_receipt'] is (row['case'] == 'missing-component') and
             all(row[key] is True for key in (
            'original_return_or_exception_preserved', 'hooks_preserved_during_call',
            'fixture_hooks_restored', 'no_new_threads', 'modules_restored', 'lock_released')), 'worker_receipts')
        public = row['public']
        # JSON turns tuple DATA into lists; restore only these fixed fields to
        # validate the exact finite public shape again in the independent parent.
        need(type(public) is dict and set(public) == PUBLIC_FIELDS and
             type(public['events']) is list and type(public['failure_codes']) is list, 'worker_public_fields')
        public['events'] = tuple(public['events'])
        public['failure_codes'] = tuple(public['failure_codes'])
        if public['terminal'] is not None:
            need(type(public['terminal']) is dict and
                 type(public['terminal']['radio_probes']) is list, 'worker_terminal_fields')
            public['terminal']['radio_probes'] = tuple(public['terminal']['radio_probes'])
            for probe in public['terminal']['radio_probes']:
                need(type(probe) is dict and type(probe['normalization_errors']) is list,
                     'worker_radio_fields')
                probe['normalization_errors'] = tuple(probe['normalization_errors'])
        check_public(public, row['case'])
    return value


def run(host):
    seal = definitions(PINS[0][0], fixed(0))
    mode = 'host' if host else 'source'
    out = BASE / 'results' / ('receive-handoff-terminal-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {PINS[0][0]: fixed(0)}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema=SCHEMA, mode=mode, passed=False, error=None, source_preserved=False,
        input_pins=[], input_count=0, host_child_exit='NOT_RUN', host_child_attempted=False,
        worker=None, full_byte_inverse=False, full_ast_inverse=False,
        exception_events_observed=False, empty_events_mean_no_exception=False,
        diagnostic_terminal_none_means_safe=False, business_component_trial_guards_changed=False,
        original_existing_hook_precondition_preserved=True, production_settrace_called=False,
        production_methods_replaced=False, peer_window_seconds_unchanged=15,
        business_deadlines_changed=False, device_invoked=False, rf=False, ui=False,
        real_trial_owner_executed=False, old_main_called=False, old_tests_replayed=0,
        graph_loaded=False, phone_entry_loaded=False, phone_admission_verified=False)
    stdout, stderr = b'', b''
    failure = None
    try:
        for key, size, pin in PINS[1:]: evidence.read(BASE / key, key=key, pin=(size, pin))
        for key in (SELF, CMD): evidence.read(BASE / key, key=key)
        evidence.snapshot(out, lambda key: key)
        generator = definitions(PINS[1][0], inputs[PINS[1][0]])
        expected = generator.make_source(inputs[PINS[2][0]])
        need(expected == inputs[PINS[3][0]], 'candidate_readback')
        report.update(full_byte_inverse=True, full_ast_inverse=True,
            candidate_bytes=len(expected), candidate_sha256=digest(expected))
        if host:
            report['host_child_attempted'] = True
            try:
                child = subprocess.run([sys.executable, '-I', '-B', str(BASE / SELF), '--worker'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=HOST_TIMEOUT, check=False)
                stdout, stderr = child.stdout, child.stderr
                report['host_child_exit'] = child.returncode
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                report['host_child_exit'] = 'TIMEOUT'
                raise ValueError('worker_timeout') from None
            need(len(stdout) <= OUTPUT_LIMIT and len(stderr) <= OUTPUT_LIMIT, 'output_limit')
            need(report['host_child_exit'] == 0 and stderr == b'', 'worker_exit')
            report['worker'] = parse_worker(stdout)
    except BaseException as error:
        failure = error
        seal.fresh(out / 'private-raw/host-exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        seal.fresh(out / 'private-raw/host-worker.stdout.raw', stdout)
        seal.fresh(out / 'private-raw/host-worker.stderr.raw', stderr)
        seal.fresh(out / 'private-raw/host-worker.host-exit', (str(report['host_child_exit']) + '\n').encode('ascii'))
        report.update(stdout_bytes=len(stdout), stdout_sha256=digest(stdout),
            stderr_bytes=len(stderr), stderr_sha256=digest(stderr))
        try:
            if not (out / 'private-raw/input-read-status.json').exists():
                evidence.snapshot(out, lambda key: key)
            for key, expected in tuple(inputs.items()):
                need(evidence.read(BASE / key, key=key) == expected and
                     (out / 'private-inputs' / key).read_bytes() == expected, 'source_or_snapshot_changed')
            need(len(inputs) == len(PINS) + 2 and not evidence.partial, 'input_set_incomplete')
            report['source_preserved'] = True
        except BaseException as error:
            seal.fresh(out / 'private-raw/source-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        try:
            seal.fresh(out / 'private-raw/input-read-status-final.json',
                (json.dumps(dict(partial=sorted(evidence.partial), changed_attempts=[
                    dict(path=key, bytes=len(value), sha256=digest(value))
                    for key, value in evidence.changed_attempts]), sort_keys=True) + '\n').encode('ascii'))
            for index, (key, value) in enumerate(evidence.changed_attempts):
                seal.fresh(out / 'private-input-attempts' / ('final-%04d.raw' % index), value)
        except BaseException as error:
            seal.fresh(out / 'private-raw/evidence-exception.txt', traceback.format_exc().encode('utf-8'))
            if failure is None: failure = error
        report['input_count'] = len(inputs)
        report['input_pins'] = [dict(path=key, bytes=len(value), sha256=digest(value),
            complete=key not in evidence.partial) for key, value in inputs.items()]
        report['passed'] = failure is None
        if failure is not None:
            report['error'] = type(failure).__name__
            if type(failure) is ValueError and len(failure.args) == 1:
                value = failure.args[0]
                if type(value) is str and value.isascii() and value.isidentifier(): report['error'] += ':' + value
    readme = (b'Finite terminal-only receive diagnostic; SOURCE static, explicit --check-host focused HOST fixtures.\n'
        b'Actual frozen trace mother: full byte/AST inverse, install replaced by original existing-hook rejection only.\n'
        b'No production hook installed or withdrawn; actual installed/restored False, exception_events_observed False.\n'
        b'Empty exception events mean NOT OBSERVED, not no exception; terminal None is not a safe/closed receipt.\n'
        b'Original run_fixed return/exception and finally close_trace/project_terminal, identity/lock/actor/radio methods preserved.\n'
        b'Ordinary HOST namespace/type/lock/event fixtures only; not real Handoff/Trial/Owner or native radio observations.\n'
        b'Nine focused cases include original foreign main/default hook rejection and hook preservation.\n'
        b'Missing component keeps original None/no-unknown behavior; unchanged COMPONENT/TRIAL/remote/closed gates remain required.\n'
        b'No old main/tests/graph/phone entry/device/RF/UI or peer15/business deadline change.\n'
        b'Public ZIP: result.json and README.txt; source/pins/snapshots/exact raw streams and HOST child exit stay private.\n')
    sealed = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode, error=sealed['report']['error'],
        result_dir=str(out), result_zip=str(sealed['archive']), zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--check-host', action='store_true')
    group.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    raise SystemExit(worker() if args.worker else run(args.check_host))
