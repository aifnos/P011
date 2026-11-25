"""PC-only tests of the actual two publication diagnostic methods.

Default is source validation; --check-host executes only extracted methods with
explicit fake IO/canonical owners. No target import, ADB, phone or RF operation.
"""
import ast
import datetime
import hashlib
import json
import math
from pathlib import Path
import sys
import types
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PREFIX = 'candidate/receive-publication-progress-v1/'
OLD_FACTORY = 'candidate/receive-proc-freezer-v1/runtime/mta_client_receive_factory.py'
OLD_PHONE = 'candidate/receive-handoff-progress-120s-v2/runtime/phone_discovery_session.py'
NEW_FACTORY = PREFIX + 'runtime/mta_client_receive_factory.py'
NEW_PHONE = PREFIX + 'runtime/phone_discovery_session.py'
DELTA = PREFIX + 'publication-exactsource-delta.json'
GENERATION = PREFIX + 'publication-generation.json'
STEPS = ('start', 'io', 'sources', 'wpa', 'json_pin', 'profile', 'received',
         'identity', 'manifest', 'write', 'loader')
FIELDS = ('publication_step', 'publication_sources_done', 'publication_sample_elapsed',
          'publication_step_elapsed', 'publication_progress_unknown')
ORIGINAL_PINS = {
    OLD_FACTORY: (97757, '051b1f6d1e1823be652f59695628d41f9d11c3d1da1896149dc4cfe3c7b207cb'),
    OLD_PHONE: (26305, '15540ef933e3c18853f8ab650e8ddc4aa902c2499eec3a7538f6f178e295ddf4'),
}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def method(raw, cls, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    scope = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls) if cls else tree
    matches = [n for n in scope.body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(matches) == 1, 'method_inventory')
    return matches[0]


def function(node, namespace):
    selected = ast.Module(body=[node], type_ignores=[])
    ast.fix_missing_locations(selected)
    exec(compile(selected, '<actual-method-host-fixture>', 'exec'), namespace)
    return namespace[node.name]


class StripDiagnostic(ast.NodeTransformer):
    count = 0
    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Attribute) and (
                isinstance(node.targets[0].value, ast.Name) and
                node.targets[0].value.id == 'attempt' and node.targets[0].attr == '_prepdiag'):
            need(isinstance(node.value, ast.Tuple) and len(node.value.elts) == 4 and
                 not any(isinstance(child, (ast.Call, ast.Yield, ast.Await, ast.ListComp, ast.GeneratorExp))
                         for child in ast.walk(node.value)), 'diagnostic_assignment_must_be_pure')
            self.count += 1
            return None
        return self.generic_visit(node)


def source_proof(inputs):
    for name, expected in ORIGINAL_PINS.items():
        need((len(inputs[name]), hashlib.sha256(inputs[name]).hexdigest()) == expected, 'frozen_original_pin')
    old = ast.parse(inputs[OLD_FACTORY].decode('utf-8'), feature_version=(3, 5))
    new = ast.parse(inputs[NEW_FACTORY].decode('utf-8'), feature_version=(3, 5))
    strip = StripDiagnostic()
    new = strip.visit(new)
    need(strip.count == 12, 'exact_twelve_markers')
    need(ast.dump(old, include_attributes=False) == ast.dump(new, include_attributes=False),
         'whole_factory_original_ast')
    need(len(inputs[NEW_FACTORY]) - len(inputs[OLD_FACTORY]) <= 2538, '75_payload_growth_budget')
    old_phone = ast.parse(inputs[OLD_PHONE].decode('utf-8'), feature_version=(3, 5))
    new_phone = ast.parse(inputs[NEW_PHONE].decode('utf-8'), feature_version=(3, 5))
    old_others = [node for node in old_phone.body if not (isinstance(node, ast.FunctionDef) and node.name == 'stage_progress')]
    new_others = [node for node in new_phone.body if not (isinstance(node, ast.FunctionDef) and node.name == 'stage_progress')]
    need(ast.dump(ast.Module(body=old_others, type_ignores=[]), include_attributes=False) ==
         ast.dump(ast.Module(body=new_others, type_ignores=[]), include_attributes=False), 'phone_other_ast_unchanged')


class FixtureFailure(Exception):
    pass


def publication_case(node, fault):
    """Actual __call__; all external owners and IO below are explicit fakes."""
    calls, samples = [], []
    failure = FixtureFailure('injected')
    holder = {}

    def hit(label):
        calls.append(label)
        active = holder.get('factory')
        active = active._active if active else None
        if active is not None:
            samples.append((label, getattr(active, '_prepdiag', None), active.last))
            if type(active.last) is float:
                active.last += .125
        if label == fault:
            raise failure

    class Lock:
        def __enter__(self):
            hit('lock_enter')
        def __exit__(self, *unused):
            hit('lock_exit')

    class Handoff:
        pass

    class Attempt:
        def __init__(self, factory, handoff):
            self.factory, self.handoff = factory, handoff
            self.state = types.SimpleNamespace(lock=Lock())
            self.last = None
            self.files = self.writer = self.loader = self.value = None
            self.closed_facts = self.failure = None
            self.phase, self.ended, self.success = 'new', False, False
            self.token = self.operation_id = '0' * 32
            self.epoch, self.session_id, self.nonce = 1, 'fixture', 'fixture'
            self.prepare_until = self.original_until = 130.0
            self.received_directory = directory
        def start(self):
            hit('start')
            self.last = 10.0
        def now(self):
            hit('now')
            return self.last

    class Files:
        def __init__(self, attempt):
            self.attempt = attempt
            self.io = types.SimpleNamespace(validate=lambda: hit('io'))
        def read(self, path, size, sha=None, **unused):
            if path.endswith('mta-wpa-supplicant'):
                hit('wpa')
            else:
                name = path.rsplit('/', 1)[1][:-3]
                hit('source:' + str(names.index(name)))
            return b'x' * size, None
        def close(self):
            hit('files_close')

    class Writer:
        def __init__(self, attempt):
            self.attempt = attempt
        def stage(self, *unused):
            hit('write')
        def verify(self):
            hit('verify')
        def close(self):
            hit('writer_close')

    class Loaded:
        pass

    class Loader:
        def __init__(self, *unused, **unused_kw):
            hit('loader_create')
        def load(self):
            hit('load')
            value = Loaded()
            value.modules = {'mta_client_executor': executor}
            value.manifest = types.SimpleNamespace(executor_sha='fixture-f')
            value.connect_binding = types.SimpleNamespace(private_metadata=lambda: holder['tree']['connect_binding'])
            value.receive_directory_binding = directory
            value.receive_metadata = ('fixture',)
            return value
        def authenticate(self, value):
            hit('authenticate')

    class Directory:
        def identity_rows(self):
            hit('identity')
            return (('fixture', 1),)

    directory = Directory()
    executor = types.SimpleNamespace(
        ROOT='/fixture', PHYSICAL_ROOT='/fixture', RECEIVE_ROOT='/fixture/received',
        JSON_SHA=hashlib.sha256(b'x').hexdigest(), LoadedDeployment=Loaded, DeploymentLoader=Loader)

    def received(*unused):
        hit('received')
        return ('fixture',)

    def dumps(value, **options):
        hit('manifest')
        holder['tree'] = value
        return json.dumps(value, **options)

    executor._receive_directory = received
    names = tuple('p011_json' if i == 0 else 'fixture' + str(i) for i in range(35))
    namespace = dict(_HANDOFF_TYPE=Handoff, _PublicationAttempt=Attempt, _Files=Files, _Writer=Writer,
        SOURCE_PINS=tuple((n, 1, 'fixture-pin') for n in names), ASSET_PHYSICAL_ROOT='/fixture',
        WPA_BYTES=2, WPA_SHA='fixture-wpa', F_SHA='fixture-f', SOURCE_MANIFEST_SHA='fixture-manifest',
        BASELINE_MANIFEST=(('fixture', 1),), PYTHON='/fixture/python', _DIRECTORY_TYPE=Directory,
        executor=executor, hashlib=hashlib, json_codec=types.SimpleNamespace(dumps=dumps, loads=json.loads),
        _live_profile=lambda unused: (hit('profile') or {'status_manifest': {}, 'python_sha': 'fixture-python'}),
        _same_tree=lambda left, right: left == right, ReceivePublicationError=FixtureFailure)

    def fail(code):
        raise FixtureFailure(code)

    namespace['_fail'] = fail
    actual = function(node, namespace)

    class Factory:
        def __init__(self):
            self._attempts, self._active = [], None
        def closed_publication_facts(self, *unused):
            return True
        def _freeze_closed(self, attempt):
            hit('freeze_closed')
            attempt.closed_facts = {'fixture': True}

    factory = Factory()
    holder['factory'] = factory
    error = None
    try:
        actual(factory, Handoff())
    except BaseException as caught:
        error = caught
    need(error is None if fault is None else error is failure, 'original_exception_identity')
    active = factory._active
    return dict(calls=calls, samples=samples, error=type(error).__name__ if error else None,
                ended=active.ended, success=active.success,
                retained_diagnostic=getattr(active, '_prepdiag', None),
                original_failure=active.failure is failure if error else active.failure is None)


def projection_fixture(node):
    executor = types.ModuleType('fixture_executor')
    protocol = types.ModuleType('fixture_protocol')
    module = types.ModuleType('fixture_factory')
    class Handoff: pass
    class Bridge: pass
    class Factory: pass
    class Attempt: pass
    class Loaded: pass
    class Loader: pass
    class P2p: pass
    executor.LoadedDeployment, executor.DeploymentLoader = Loaded, Loader
    protocol.P2pInfo = P2p
    module.FixedReceiveDeploymentFactory, module._PublicationAttempt = Factory, Attempt
    decrypt_ns = {'protocol': protocol}
    exec('def decrypt(self): return None', decrypt_ns)
    Handoff.decrypt = decrypt_ns['decrypt']
    state, op = types.SimpleNamespace(), types.SimpleNamespace()
    state.worker = object()
    op.session = object()
    handoff, bridge, factory, active = Handoff(), Bridge(), Factory(), Attempt()
    handoff.state, handoff.operation, handoff.session = state, op, op.session
    handoff.worker, handoff._plain = state.worker, P2p()
    bridge.state, bridge.operation, bridge.session = state, op, op.session
    bridge.worker, bridge.handoff, bridge._factory = state.worker, handoff, factory
    bridge._executor = executor
    bridge.factory_ticket = {'started': True, 'returned': None, 'authenticated': False}
    state._trusted_receive_deployment_factory = factory
    active.factory, active.handoff, active.state = factory, handoff, state
    active.operation, active.session, active.bridge, active.worker = op, op.session, bridge, state.worker
    active.phase, active.ended, active.success = 'new', False, False
    active.last = 13.0
    factory._active, factory._attempts = active, [active]
    owner = types.SimpleNamespace(factory=factory,
        service=types.SimpleNamespace(ReceiveConnectHandoff=Handoff, StateClientBridge=Bridge),
        loader=types.SimpleNamespace(modules={'mta_client_executor': executor,
            'mta_protocol': protocol, 'mta_client_receive_factory': module}))
    actual = function(node, {'types': types, 'math': math})
    return actual, (owner, state, op, handoff, bridge), active


def check_host(inputs):
    old_call = method(inputs[OLD_FACTORY], 'FixedReceiveDeploymentFactory', '__call__')
    new_call = method(inputs[NEW_FACTORY], 'FixedReceiveDeploymentFactory', '__call__')
    faults = [None, 'start', 'io'] + ['source:' + str(i) for i in range(35)] + [
        'wpa', 'profile', 'received', 'identity', 'lock_enter', 'lock_exit', 'manifest',
        'write', 'loader_create', 'load', 'authenticate', 'verify', 'files_close', 'writer_close', 'freeze_closed']
    for fault in faults:
        before, after = publication_case(old_call, fault), publication_case(new_call, fault)
        need(all(before[k] == after[k] for k in ('calls', 'error', 'ended', 'success', 'original_failure')),
             'business_or_finalizer_changed')
        if fault is not None:
            failure_record = next(row for row in after['samples'] if row[0] == fault)
            need(after['retained_diagnostic'] is failure_record[1], 'failed_step_not_retained_through_finally')
        for label, diag, sample in after['samples']:
            need(type(diag) is tuple and len(diag) == 4 and diag[0] in STEPS and
                 type(diag[1]) is int and 0 <= diag[1] <= 35, 'finite_marker')
            if label.startswith('source:'):
                need(diag[0] == 'sources' and diag[1] == int(label.split(':')[1]), 'completed_count_semantics')
    old_node, new_node = method(inputs[OLD_PHONE], None, 'stage_progress'), method(inputs[NEW_PHONE], None, 'stage_progress')
    old_fn, old_args, unused = projection_fixture(old_node)
    new_fn, new_args, active = projection_fixture(new_node)
    baseline = old_fn(*old_args)
    cases = 0
    for step in STEPS[1:]:
        for count in ((0,) if step == 'io' else (0, 35) if step == 'sources' else (35,)):
            active._prepdiag = (step, count, 10.0, 12.0)
            result = new_fn(*new_args)
            need({k: result[k] for k in baseline} == baseline, 'old_stage_preserved')
            need(result['publication_progress_unknown'] is False and result['publication_step'] == step and
                 result['publication_sources_done'] == count and result['publication_sample_elapsed'] == 3.0 and
                 result['publication_step_elapsed'] == 1.0, 'cached_time_projection')
            cases += 1
    for last in (None, 13.0):
        active._prepdiag = ('start', 0, None, None)
        active.last = last
        result = new_fn(*new_args)
        need({k: result[k] for k in baseline} == baseline, 'initial_sample_changed_business')
        need(result['publication_progress_unknown'] is False and result['publication_step'] == 'start' and
             result['publication_sources_done'] == 0 and result['publication_sample_elapsed'] is None and
             result['publication_step_elapsed'] is None, 'initial_sample_not_unknown_time')
        cases += 1
    active.last = 13.0
    for diag in (None, [], ('profile', True, 10., 12.), ('unknown', 0, 10., 12.),
                 ('profile', 36, 10., 12.), ('profile', 35, float('nan'), 12.),
                 ('profile', 35, 14., 12.), ('profile', 35, 10., 14.),
                 ('io', 35, 10., 12.), ('profile', 0, 10., 12.),
                 ('profile', 35, True, 12.), ('profile', 35, 10., float('inf'))):
        active._prepdiag = diag
        result = new_fn(*new_args)
        need({k: result[k] for k in baseline} == baseline, 'malformed_diagnostic_changed_business')
        need(result['publication_progress_unknown'] is True and all(result[k] is None for k in FIELDS[:-1]),
             'diagnostic_unknown_not_preserved')
        cases += 1
    # Exercise both identity readbacks with deterministic getter races; these
    # are PC fixtures, not an actual phone/thread scheduling acceptance.
    original_type = type(active)
    factory_module = new_args[0].loader.modules['mta_client_receive_factory']
    for racing_name in ('_prepdiag', 'last'):
        reads = [0]
        class RacyAttempt(original_type):
            def __getattribute__(self, name):
                value = object.__getattribute__(self, name)
                if name == racing_name:
                    reads[0] += 1
                    if reads[0] > 1:
                        return tuple(list(value)) if name == '_prepdiag' else float(str(value))
                return value
        active.__class__ = RacyAttempt
        factory_module._PublicationAttempt = RacyAttempt
        active._prepdiag = ('profile', 35, 10., 12.)
        result = new_fn(*new_args)
        need({k: result[k] for k in baseline} == baseline and
             result['publication_progress_unknown'] is True and all(result[k] is None for k in FIELDS[:-1]),
             'identity_readback_race_not_unknown')
        active.__class__ = original_type
        factory_module._PublicationAttempt = original_type
        cases += 1
    return dict(actual_methods=2, publication_fault_cases=len(faults), projection_cases=cases,
                business_call_order_preserved=True, original_exception_identity_preserved=True,
                closed_facts_are_fixtures_not_device_evidence=True,
                exact_step_timing=False, existing_clock_samples_only=True)


def main():
    need(sys.argv[1:] in ([], ['--check-host']), 'explicit_host_mode')
    names = (OLD_FACTORY, OLD_PHONE, NEW_FACTORY, NEW_PHONE, PREFIX + 'generate.py',
             GENERATION, DELTA,
             'host/receive_publication_progress_v1_check.py', 'HOST_MTA_PUBLICATION_PROGRESS_V1_CHECK.cmd')
    inputs = {}
    for name in names:
        path = BASE / name
        need(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(BASE.resolve()), 'input_scope')
        inputs[name] = path.read_bytes()
    generation = json.loads(inputs[GENERATION])
    # The generated manifest is evidence only after checking its actual output bytes.
    need(generation['schema'] == 'p011-receive-publication-progress-v1-generation' and
         generation['source_count'] == 3 and generation['source_pins'] == [
             [name, size, sha] for name, (size, sha) in ORIGINAL_PINS.items()] and
         {row[0] for row in generation['output_pins']} == {NEW_FACTORY, NEW_PHONE, DELTA} and
         len(generation['output_pins']) == 3, 'exact_generated_inventory')
    for name, size, sha in generation['output_pins']:
        need(name in inputs and (len(inputs[name]), hashlib.sha256(inputs[name]).hexdigest()) == (size, sha),
             'candidate_output_pin')
    source_proof(inputs)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('publication-progress-v1-' + ('host-' if sys.argv[1:] else 'source-') + stamp)
    out.mkdir()
    report = dict(schema='publication-progress-v1-host', passed=False, source_checked=True,
                  device_tested=False, phone_tested=False, rf_requested=False,
                  graph_packaged=False, deployed=False, methods_executed=0)
    try:
        for name, raw in inputs.items():
            target = out / 'private-inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        if sys.argv[1:]:
            report.update(check_host(inputs))
            report['methods_executed'] = 2
        need(all((BASE / name).read_bytes() == raw for name, raw in inputs.items()), 'source_changed')
        report['source_preserved'] = True
        report['source_count'] = len(inputs)
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__
        (out / 'error-private.txt').write_text(str(error), encoding='utf-8')
    (out / 'result.json').write_text(json.dumps(report, sort_keys=True, indent=2), encoding='utf-8')
    (out / 'README.txt').write_text('PC-only actual __call__ and stage_progress with explicit fake IO.\n'
        'No target import, phone, ADB, RF, file receive or actual resource/restoration acceptance.\n'
        'Finite cached sample progress, not exact live timing or successful authentication.\n'
        'Two-source candidate only; full graph/new strict phone parser and device delivery remain pending.\n', encoding='utf-8')
    with zipfile.ZipFile(out / 'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in ('result.json', 'README.txt'):
            archive.write(out / name, name)
    print(json.dumps(report, sort_keys=True))
    print('RESULT_DIR=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
