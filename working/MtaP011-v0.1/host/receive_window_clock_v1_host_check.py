"""One PC-only method: exact delta and isolated actual window predicates.

This checker never constructs a complete FixedSession, imports its module,
runs a historical suite, touches ADB or opens any radio/network. Controlled
HOST floats are not the retained values of the failing P011 session.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import traceback
from types import SimpleNamespace
import uuid
from datetime import datetime


BASE = Path(__file__).resolve().parents[1]
PREFIX = 'candidate/receive-window-clock-v1/'
GENERATOR = (PREFIX + 'generate.py', 8591,
             'aacf1c4127d029f72480e05ade9214cbf3598166d34871b7b5e1ff27dca0dfc6')
SEAL = ('host/host_artifact_seal_v1.py', 6784,
        '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
INPUTS = {}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def module(raw, relative, name):
    namespace = dict(__name__=name, __file__=str(BASE / relative))
    exec(compile(raw, str(BASE / relative), 'exec'), namespace)
    return SimpleNamespace(**namespace)


def function(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and
               node.name == 'FixedSession']
    need(len(classes) == 1, 'single_actual_class')
    nodes = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and
             node.name == name]
    need(len(nodes) == 1, 'single_actual_function:' + name)
    return nodes[0]


def pure_window(raw):
    """Compile only the real window predicate and five real retain assignments."""
    predicate = copy.deepcopy(function(raw, 'window_current'))
    constructor = function(raw, '__init__')
    targets = ('profile', 'window_started_at', 'until', 'cleanup_until',
               '_window_original', '_window_retained')
    selected = []
    target_names = []
    for node in constructor.body:
        if not isinstance(node, ast.Assign):
            continue
        names = tuple(target.attr for target in node.targets if
                      isinstance(target, ast.Attribute) and
                      isinstance(target.value, ast.Name) and target.value.id == 'self')
        if any(name in targets for name in names):
            need(names and all(name in targets for name in names), 'retain_assignment_scope')
            selected.append(copy.deepcopy(node))
            target_names.append(names)
    need(target_names == [('profile',), ('window_started_at',), ('until',),
                          ('cleanup_until',), ('_window_original', '_window_retained')],
         'actual_retain_assignments')
    scaffold = ast.parse('class WindowOnly:\n    pass\n\ndef retain_window(self, profile):\n    pass\n')
    scaffold.body[0].body = [predicate]
    scaffold.body[1].body = selected
    ast.fix_missing_locations(scaffold)
    # No original imports, FixedSession.__init__, process APIs or role graph.
    namespace = {'time': SimpleNamespace(monotonic=lambda: 0.0)}
    exec(compile(scaffold, '<actual-window-only>', 'exec'), namespace)

    def create(start, profile):
        namespace['time'] = SimpleNamespace(monotonic=lambda: start)
        value = namespace['WindowOnly']()
        namespace['retain_window'](value, profile)
        return value

    return create


def mutate(value, name):
    if name == 'retained_list':
        value._window_retained = list(value._window_retained)
    elif name == 'retained_length':
        value._window_retained = value._window_retained[:3]
    elif name == 'retained_equal_new_tuple':
        value._window_retained = tuple(list(value._window_retained))
        need(value._window_original == value._window_retained and
             value._window_original is not value._window_retained, 'equal_tuple_distinct')
    elif name == 'original_equal_new_tuple':
        value._window_original = tuple(list(value._window_original))
        need(value._window_original == value._window_retained and
             value._window_original is not value._window_retained, 'equal_original_distinct')
    elif name == 'profile_equal_new_identity':
        value.profile = value.profile.encode('ascii').decode('ascii')
        need(value.profile == value._window_retained[0] and
             value.profile is not value._window_retained[0], 'equal_profile_distinct')
    elif name.endswith('_equal_new_identity'):
        attribute = name[:-len('_equal_new_identity')]
        old = getattr(value, attribute)
        setattr(value, attribute, float.fromhex(old.hex()))
        need(getattr(value, attribute) == old and getattr(value, attribute) is not old,
             'equal_float_distinct:' + attribute)
    elif name == 'profile_value':
        value.profile = ('receive-interactive-v1' if value.profile == 'diagnostic'
                         else 'diagnostic')
    elif name in ('window_started_at_value', 'until_value', 'cleanup_until_value'):
        attribute = name[:-len('_value')]
        setattr(value, attribute, getattr(value, attribute) + 1.0)
    elif name == 'window_started_at_int':
        value.window_started_at = 0
    elif name.endswith('_coherent_value'):
        attribute = name[:-len('_coherent_value')]
        setattr(value, attribute, getattr(value, attribute) + 1.0)
        value._window_original = value._window_retained = (
            value.profile, value.window_started_at, value.until, value.cleanup_until)
    elif name == 'extended_until_cleanup_record':
        value.until += 60.0
        value.cleanup_until += 60.0
        value._window_original = value._window_retained = (
            value.profile, value.window_started_at, value.until, value.cleanup_until)
    else:
        raise ValueError('unknown_mutation')


def check_predicates(old, candidate, role):
    original_create, candidate_create = pure_window(old), pure_window(candidate)
    cases = []

    def case(name, profile, start, expected_old, expected_candidate, mutation=None):
        source, changed = original_create(start, profile), candidate_create(start, profile)
        if mutation is not None:
            mutate(source, mutation)
            mutate(changed, mutation)
        old_answer, new_answer = source.window_current(), changed.window_current()
        need(old_answer is expected_old and new_answer is expected_candidate,
             role + ':' + profile + ':' + name)
        cases.append(dict(name=name, profile=profile, controlled_start_hex=start.hex(),
                          original=old_answer, candidate=new_answer,
                          actual_device_value=False))

    mutations = ('retained_list', 'retained_length', 'retained_equal_new_tuple',
                 'original_equal_new_tuple', 'profile_equal_new_identity',
                 'window_started_at_equal_new_identity', 'until_equal_new_identity',
                 'cleanup_until_equal_new_identity', 'profile_value',
                 'window_started_at_value', 'until_value', 'cleanup_until_value',
                 'window_started_at_int', 'window_started_at_coherent_value',
                 'until_coherent_value', 'cleanup_until_coherent_value',
                 'extended_until_cleanup_record')
    for profile, counterexample in (
            ('diagnostic', float.fromhex('0x1.1000000000001p+6')),
            ('receive-interactive-v1', float.fromhex('0x1.fffffffffffffp+9'))):
        case('original_constructed_integral', profile, 0.0, True, True)
        case('controlled_float_subtraction_counterexample', profile,
             counterexample, False, True)
        for name, start in (('nan', float('nan')), ('positive_infinity', float('inf')),
                            ('negative_infinity', -float('inf')),
                            ('positive_span_unrepresentable', float.fromhex('0x1p+1000')),
                            ('negative_span_unrepresentable', -float.fromhex('0x1p+1000'))):
            case(name, profile, start, False, False)
        for mutation in mutations:
            case(mutation, profile, 0.0, False, False, mutation)
    return cases


def main():
    need(sys.argv[1:] == [], 'host_only_no_arguments')
    out = BASE / 'results' / ('receive-window-clock-v1-host-' +
                             datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    seal_raw = (BASE / SEAL[0]).read_bytes()
    INPUTS[SEAL[0]] = seal_raw
    need((len(seal_raw), digest(seal_raw)) == SEAL[1:], 'seal_helper_identity')
    seal = module(seal_raw, SEAL[0], '_window_clock_artifact_seal')
    evidence = seal.InputEvidence(INPUTS)
    error, facts, rows = None, {}, []
    try:
        self_relative = 'host/receive_window_clock_v1_host_check.py'
        evidence.read(BASE / self_relative, self_relative)
        gen_raw = evidence.read(BASE / GENERATOR[0], GENERATOR[0], GENERATOR[1:])
        generator = module(gen_raw, GENERATOR[0], '_window_clock_mechanical_spec')
        for role, relative, size, sha, _ in generator.SOURCES:
            evidence.read(BASE / relative, relative, (size, sha))
        expected_outputs, generation = generator.build()
        for relative, expected in expected_outputs.items():
            actual = evidence.read(BASE / relative, relative)
            need(actual == expected, 'exact_generated_artifact:' + relative)
        for role, source_path, _, _, candidate_path in generator.SOURCES:
            rows.extend([dict(role=role, **row) for row in
                         check_predicates(INPUTS[source_path], INPUTS[candidate_path], role)])
        # Re-read exact source/generator pins after pure execution, without writer.
        evidence.read(BASE / GENERATOR[0], GENERATOR[0], GENERATOR[1:])
        for _, relative, size, sha, _ in generator.SOURCES:
            evidence.read(BASE / relative, relative, (size, sha))
        facts = dict(runner_count=2, isolated_actual_predicate_case_count=len(rows),
                     exact_generated_artifacts=True, full_forward_inverse=True,
                     outside_window_function_byte_identical=True,
                     other_ast_identical=True, constructor_deadline_byte_identical=True,
                     finite_positive_span_guard=True, clock_reads_added=0,
                     epsilon_added=False, deadline_renewal_added=False,
                     complete_fixed_session_constructed=False,
                     original_runner_modules_imported=False,
                     old_suites_run=0, historical_graphs_invoked=0,
                     actual_device_failure_reproduced=False,
                     actual_device_window_values_collected=False)
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        seal.fresh(out / 'private-raw/exception.txt', traceback.format_exc().encode('utf-8'))
    evidence.snapshot(out, lambda key: str(key))
    report = dict(schema='p011-receive-window-clock-v1-host-check', passed=error is None,
                  error=error, host_exit=0 if error is None else 1,
                  remote_exit='NOT_RUN', device_executed=False, phone_tested=False,
                  radio_executed=False, file_transfer_tested=False,
                  restoration_verified=False, facts=facts, cases=rows,
                  inputs=[dict(path=str(key), bytes=len(raw), sha256=digest(raw))
                          for key, raw in sorted(INPUTS.items())])
    sealed = seal.seal_result(out, report,
        b'PC-only actual window predicate check. No ADB/RF/session execution.\n'
        b'Controlled HOST float counterexamples are not P011 retained values.\n'
        b'Finite original 60/600 + 60 deadlines, identity guards and check stay unchanged.\n')
    print(json.dumps(dict(passed=sealed['report'].get('passed'),
                          error=sealed['report'].get('error'), output=str(out),
                          archive=str(sealed['archive']) if sealed['archive'] else None,
                          archive_sha256=sealed['archive_sha256'], facts=facts), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
