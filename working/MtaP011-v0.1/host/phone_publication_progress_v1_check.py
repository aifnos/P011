"""Fixed PC SOURCE/affected-parser contract; never imports target business.

--check-host runs only the new five-field wrapper and the frozen full original
parse_smoke, with literal PC fixtures. This is not phone/READY/device evidence.
"""
import ast
import copy
import datetime
import hashlib
import json
from pathlib import Path
import sys
import types
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/phone_publication_progress_v1_check.py'
CMDS = ('HOST_MTA_PHONE_PUBLICATION_PROGRESS_V1_SOURCE_CHECK.cmd',
        'HOST_MTA_PHONE_PUBLICATION_PROGRESS_V1_CHECK.cmd')
SCHEMA = ('host/phone_publication_progress_v1_schema.py', 5907,
          '60e97088233ea1fd26abce7e54070c1f4c3166c5721e9f5c9478045d25eca9ee')
ORIGINAL = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
            '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
PHONE = ('candidate/receive-publication-progress-v1/runtime/phone_discovery_session.py', 28352,
         'cdfcec298c2da5b2ec2eff931b06da4381c56ddcba39a163cb8b58dad4108d12')
GENERATION = ('candidate/receive-publication-progress-v1/publication-generation.json', 2611,
              '46da96f9b5d14a13abfbc598a80c15ea97319ec72fdc86261590d0efb51f9619')
PINS = (SCHEMA, ORIGINAL, PHONE, GENERATION)


def need(value, code):
    if value is not True:
        raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'private_snapshot_short_write')


def snapshot(name, out):
    path = BASE / name
    need(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(BASE.resolve()),
         'fixed_source_scope')
    raw = path.read_bytes()
    write_new(out / 'private-inputs' / name, raw)
    need(len(raw) <= 262144, 'fixed_pc_source_budget')
    return raw


def source_contract(inputs):
    for name, size, sha in PINS:
        need((len(inputs[name]), hashlib.sha256(inputs[name]).hexdigest()) == (size, sha),
             'actual_fixed_source_pin')
    source = ast.parse(inputs[SCHEMA[0]].decode('utf-8'))
    need(all(isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef)) or
             isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and
             type(node.value.value) is str for node in source.body), 'schema_definitions_only')
    need({node.name for node in source.body if isinstance(node, ast.FunctionDef)} ==
         {'need', 'original_parser', 'validate_publication', 'parse_smoke'}, 'schema_exact_definitions')
    schema = types.ModuleType('fixed_publication_five_field_schema')
    schema.__file__ = str(BASE / SCHEMA[0])
    exec(compile(source, '<fixed-publication-schema>', 'exec'), schema.__dict__)
    need('main' not in schema.__dict__ and schema.ORIGINAL == ORIGINAL, 'no_old_main_or_parser_swap')
    original = schema.original_parser(inputs[ORIGINAL[0]])
    generation = json.loads(inputs[GENERATION[0]])
    need(generation['schema'] == 'p011-receive-publication-progress-v1-generation' and
         generation['phone_fields'] == list(schema.FIELDS) and generation['step_names'] == list(schema.STEPS) and
         generation['source_completion_cap'] == 35 and list(PHONE) in generation['output_pins'],
         'actual_phone_projection_contract')
    phone = ast.parse(inputs[PHONE[0]].decode('utf-8'), feature_version=(3, 5))
    selected = [node for node in phone.body if isinstance(node, ast.FunctionDef) and node.name == 'stage_progress']
    need(len(selected) == 1 and all(name in ({node.value for node in ast.walk(selected[0])
         if isinstance(node, ast.Constant) and type(node.value) is str} |
         {node.arg for node in ast.walk(selected[0]) if isinstance(node, ast.keyword) and
          type(node.arg) is str}) for name in schema.FIELDS),
         'actual_phone_five_fields_present')
    need(schema.FIELDS == ('publication_step', 'publication_sources_done', 'publication_sample_elapsed',
         'publication_step_elapsed', 'publication_progress_unknown') and len(schema.FIELDS) == 5 and
         schema.STEPS == ('start', 'io', 'sources', 'wpa', 'json_pin', 'profile', 'received',
                         'identity', 'manifest', 'write', 'loader'), 'fixed_five_fields_and_eleven_steps')
    return schema, original


def fixture(original, schema, complete=False):
    row = dict((name, False) for name in original.OBS_BOOL + original.PROGRESS_BOOL + original.STAGE_OPTIONAL_BOOL)
    row.update(factory_phase=None, stage_unknown=False, stage='observing', state='searching',
               event_counts=(0,) * 6, elapsed_seconds=0.0, f_process_retained=False)
    row.update(schema.UNKNOWN)
    value = dict(scope='receive-advertise-cancel-only-v1', complete=complete, reason='receive_refused',
                 flags=dict((name, False) for name in original.FLAGS), observations=(row,), terminal=None,
                 trials={'fixture': True}, component={'fixture': True})
    if complete:
        for name in ('start_called', 'start_returned', 'receive_ready', 'advertising_seen', 'listen_seen',
                     'stop_called', 'stop_returned', 'closure_verified', 'baseline_verified'):
            value['flags'][name] = True
        value['reason'] = 'advertising_observed'
        value['terminal'] = dict((name, False) for name in original.TERMINAL_BOOL)
        value['terminal'].update(helper_closed=True, network_zero_known=True, event_counts=(0,) * 6)
    return value


def check_host(schema, original, source):
    accepted, rejected, predicates = [], [], []

    def raw(value):
        return ('HOST_FIXTURE_ONLY\r\r\nSMOKE_RESULT=' + repr(value) + '\r\r\n').encode('utf-8')

    def accept(label, value, remote=None):
        observed = schema.parse_smoke(raw(value), value['component'],
            (0 if value['complete'] else 1) if remote is None else remote, value['trials'], source)
        stripped = copy.deepcopy(value)
        for row in stripped['observations']:
            for name in schema.FIELDS:
                del row[name]
        original_result = original.parse_smoke(raw(stripped), value['component'],
            0 if value['complete'] else 1, value['trials'])
        need(observed == value and original_result == stripped, 'full_original_parser_preserved')
        accepted.append(label)

    def reject(label, value, remote=None, component=None, trials=None):
        caught = False
        try:
            schema.parse_smoke(raw(value), value['component'] if component is None else component,
                (0 if value['complete'] else 1) if remote is None else remote,
                value['trials'] if trials is None else trials, source)
        except (ValueError, TypeError, SyntaxError):
            caught = True
        need(caught, 'invalid_literal_was_accepted')
        rejected.append(label)

    base = fixture(original, schema)
    accept('known_old_stage_missing_active_diagnostic_unknown', base)
    value = copy.deepcopy(base)
    value['observations'][0].update(dict((name, None) for name in original.STAGE_OPTIONAL_BOOL))
    value['observations'][0]['stage_unknown'] = True
    accept('original_unknown_diagnostic_unknown', value)
    known = copy.deepcopy(base)
    known['observations'][0].update(factory_started=True, factory_active_present=True, factory_phase='new',
        publication_step='start', publication_sources_done=0, publication_sample_elapsed=None,
        publication_step_elapsed=None, publication_progress_unknown=False)
    accept('known_start_elapsed_none', known)
    for step in schema.STEPS[1:]:
        for count in ((0,) if step == 'io' else (0, 35) if step == 'sources' else (35,)):
            value = copy.deepcopy(known)
            value['observations'][0].update(publication_step=step, publication_sources_done=count,
                publication_sample_elapsed=300.0, publication_step_elapsed=300.0)
            accept('known_' + step + '_' + str(count), value)
    value = copy.deepcopy(known)
    value['observations'][0].update(factory_phase='ended', factory_ended=True, publication_step='sources',
        publication_sources_done=3, publication_sample_elapsed=2.0, publication_step_elapsed=1.0)
    accept('ended_retains_last_step_no_phase_mapping', value)
    accept('original_complete_unknown_data_not_admission', fixture(original, schema, True))
    for name in schema.FIELDS:
        value = copy.deepcopy(base)
        del value['observations'][0][name]
        reject('missing_' + name, value)
    value = copy.deepcopy(base)
    value['observations'][0]['extra_diagnostic_field'] = None
    reject('extra_row_field', value)
    for name in schema.FIELDS[:-1]:
        value = copy.deepcopy(base)
        value['observations'][0][name] = 0
        reject('unknown_value_leak_' + name, value)
    for bad in (None, 0, 1):
        value = copy.deepcopy(base)
        value['observations'][0]['publication_progress_unknown'] = bad
        reject('unknown_bool_' + repr(bad), value)
    mutations = (
        ('active_missing', {'factory_active_present': False, 'factory_phase': None}),
        ('old_stage_unknown', dict(dict((name, None) for name in original.STAGE_OPTIONAL_BOOL),
                                   factory_phase=None, stage_unknown=True)),
        ('step_invalid', {'publication_step': 'not_a_step'}),
        ('count_bool', {'publication_sources_done': True}),
        ('count_negative', {'publication_sources_done': -1}),
        ('count_over', {'publication_sources_done': 36}),
        ('start_count', {'publication_sources_done': 1}),
        ('start_elapsed', {'publication_sample_elapsed': 0.0, 'publication_step_elapsed': 0.0}),
        ('io_count', {'publication_step': 'io', 'publication_sources_done': 1,
                      'publication_sample_elapsed': 0.0, 'publication_step_elapsed': 0.0}),
        ('later_count', {'publication_step': 'write', 'publication_sources_done': 0,
                         'publication_sample_elapsed': 0.0, 'publication_step_elapsed': 0.0}),
    )
    for label, delta in mutations:
        value = copy.deepcopy(known)
        value['observations'][0].update(delta)
        reject(label, value)
    for label, total, elapsed in (('none', None, None), ('integer', 1, 0.0), ('bool', True, 0.0),
                                  ('negative', 1.0, -1.0), ('reversed', 1.0, 2.0), ('over', 301.0, 1.0)):
        value = copy.deepcopy(known)
        value['observations'][0].update(publication_step='sources', publication_sources_done=1,
            publication_sample_elapsed=total, publication_step_elapsed=elapsed)
        reject('elapsed_' + label, value)
    for label, total, elapsed in (('nan_total', float('nan'), 0.0), ('inf_total', float('inf'), 0.0),
                                  ('nan_step', 1.0, float('nan')), ('inf_step', 1.0, float('inf'))):
        row = copy.deepcopy(known['observations'][0])
        row.update(publication_step='sources', publication_sources_done=1,
                   publication_sample_elapsed=total, publication_step_elapsed=elapsed)
        caught = False
        try:
            schema.validate_publication(row)
        except ValueError:
            caught = True
        need(caught, 'non_finite_predicate_accepted')
        predicates.append(label)
    passed = fixture(original, schema, True)
    value = copy.deepcopy(passed)
    value['flags']['closure_verified'] = False
    reject('diagnostic_does_not_upgrade_old_closure', value)
    value = copy.deepcopy(passed)
    value['terminal']['network_zero_known'] = False
    reject('original_terminal_guard', value)
    reject('original_remote_guard', passed, remote=1)
    reject('original_component_guard', base, component={'wrong': True})
    reject('original_trials_guard', base, trials={'wrong': True})
    value = copy.deepcopy(base)
    value['observations'][0]['elapsed_seconds'] = 136.0
    reject('original_observation_elapsed_guard', value)
    return dict(accepted_cases=len(accepted), rejected_literal_cases=len(rejected),
                rejected_nonfinite_predicates=len(predicates), parser_fixture_cases=len(accepted) + len(rejected),
                exact_five_field_schema=True, original_full_parser_preserved=True,
                original_known_not_promoted=True, fixture_complete_is_not_device_success=True)


def main():
    need(sys.argv[1:] in ([], ['--check-host']), 'fixed_pc_mode_only')
    mode = 'host' if sys.argv[1:] else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('phone-publication-progress-v1-' + mode + '-' + stamp)
    out.mkdir()
    inputs = {}
    report = dict(schema='p011-phone-publication-progress-v1-host', mode=mode, passed=False,
        source_preserved=False, device_tested=False, phone_tested=False, rf_requested=False,
        graph_packaged=False, admission_verified=False, restoration_verified=False, parser_fixture_cases=0)
    try:
        for name in (SELF,) + CMDS + tuple(row[0] for row in PINS):
            inputs[name] = snapshot(name, out)
        schema, original = source_contract(inputs)
        report.update(source_checked=True, source_count=len(inputs), original_pure_helper_count=1)
        if sys.argv[1:]:
            report.update(check_host(schema, original, inputs[ORIGINAL[0]]))
        need(all((BASE / name).read_bytes() == raw for name, raw in inputs.items()), 'source_changed')
        report['source_preserved'] = True
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__
        write_new(out / 'error-private.txt', (type(error).__name__ + ':' + str(error)).encode('utf-8'))
    write_new(out / 'result.json', json.dumps(report, sort_keys=True, indent=2).encode('utf-8'))
    write_new(out / 'README.txt', b'PC-only fixed SOURCE or affected five-field parser fixtures.\n'
        b'The complete original parse_smoke remains the authority for all original fields.\n'
        b'Unknown publication data does not promote old stage knowledge or admit receive.\n'
        b'Cached sample deltas are not live time or exact publication call durations.\n'
        b'No target business import, ADB, phone, RF, stage, build or restoration acceptance.\n')
    with zipfile.ZipFile(out / 'public-result.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in ('result.json', 'README.txt'):
            archive.write(out / name, name)
    print(json.dumps(report, sort_keys=True))
    print('RESULT_DIR=' + str(out))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
