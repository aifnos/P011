"""PC-only closure and explicit assembly of the two frozen media-mutex packages.

Default SOURCE writes only fresh evidence, not package artifacts. --assemble
prepares both packages before calling each fixed new PC writer once. A failed
receive writer may be continued with --assemble-receive, which only reads send.
No runtime role, historical main/test, device Stage, ADB, radio or phone is run.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import traceback
import types
import uuid

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/filecenter_mutex_package_v1_check.py'
CMD = 'HOST_MTA_FILECENTER_MUTEX_PACKAGE_V1_CHECK.cmd'
DONOR = ('host/filecenter_http_cap_package_v1_check.py', 18182,
         '0d0b7382b930d02de4845679b9aabde571c9ea3593175d8e9af07f48299dda7d')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
GENERATORS = (
    ('send', 'candidate/formal-send-fc-mutex-v1/generate_package.py', 38185,
     '69ce44c85b11c89e491c8877b839a0eed9322c22ff51f8c6a819589a4d50742a'),
    ('receive', 'candidate/receive-fc-mutex-graph-v1/generate_graph.py', 43011,
     '98ad07f8dabe99fdfdca601da63138dc6bbd62fcf7dcbc277c65a648162534c8'),
)
PURE = {
    'send': ('need', 'digest', 'pin', 'encode', 'metadata', 'relative', 'directories',
        'read', 'take', 'preserve', 'parse', 'literal', 'expression', 'functions',
        'record', 'fc_pins', 'replace_fc', 'ordinary_rows', 'json_change',
        'json_record_text', 'prove_companion', 'prepare'),
    'receive': ('need', 'digest', 'pin', 'jraw', 'scoped', 'read_pin', 'take', 'parse',
        'assignment_node', 'literal_assignment', 'span', 'source_function',
        'pure_current', 'mutex_method_bytes', 'validate_mutex', 'validate_current',
        'verify_inputs', 'assignment', 'source_tuple', 'derive_definitions', 'prepare'),
}
DEFINITION_FUNCTIONS = (
    'need', 'digest', 'jraw', 'literal_assignment', 'replay', 'definition_rows',
    'validate_delta', 'validate_runner', 'owner_context', 'scope_originals',
    'validate_owner_business', 'validate_scope_business', 'validate_fc_http_delta',
    'cache_target', 'remove_cache_assignments', 'profile_method',
    'validate_profile_business', 'validate_prepare20_business', 'validate_manifest_inverse',
    'manifest_rows', 'mutex_method_bytes', 'validate_mutex', 'validate_current', 'verify_inputs',
)
REUSED_LARGE_GUI = (
    'out/mta-ui-send-status-v1-6d4fb1fd4af949cbb3515870/Z03.mta-ui-candidate',
    4103844, '9caf72924d110186a9e4f89e872bb1ca9debb096f9ece6c34263c00aba95d7cf')
COMPANIONS = {
    'send': ('candidate/filecenter-media-lock-deadline-v1/send/mta_filecenter_companion.py',
             27656, '57531992acaf8b3519e090f8e1cf61a2ac97dc18e14bee15662573dbb9ca5bfd'),
    'receive': ('candidate/filecenter-media-lock-deadline-v1/receive/mta_filecenter_companion.py',
                35198, '44c14589ef7b6a0af98c6a3446b3bd7539640f5b7fccc23c5c9677c705ae02ca'),
}
SEND_RUNTIME = ('mta_send_trial', 'mta_send_terminal_consumer', 'mta_service',
    'mta_client_receive_boot', 'mta_client_service_owner', 'formal_send_session',
    'formal_send_stage', 'ui_guardian', 'ui_session', 'ui_assets')
RECEIVE_RUNTIME = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory',
    'mta_client_receive_boot', 'mta_client_service_owner', 'mta_formal_receive_session')
RECEIVE_DEFINITIONS = 'host/formal_receive_fc_mutex_v1_definitions.py'
SEND_ROOT = 'candidate/formal-send-fc-mutex-v1/'
RECEIVE_ROOT = 'candidate/receive-fc-mutex-graph-v1/'
OUTPUT_NAMES = {
    'send': tuple(SEND_ROOT + 'runtime/' + name + '.py' for name in SEND_RUNTIME) +
        tuple(SEND_ROOT + name for name in ('assets/filecenter-source-manifest.json',
            'assets/ordinary-source-manifest.json', 'exactsource-delta.json', 'generation.json')),
    'receive': tuple(RECEIVE_ROOT + 'runtime/' + name + '.py' for name in RECEIVE_RUNTIME) +
        (RECEIVE_ROOT + 'graph-exactsource-delta.json', RECEIVE_ROOT + 'graph-generation.json',
         RECEIVE_DEFINITIONS, 'host/formal_receive_fc_mutex_v1_definition_manifest.json',
         'host/formal_receive_fc_mutex_v1_private_source_manifest.json'),
}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bootstrap(row):
    # Only two reviewed small helpers are read before the retained fixed reader.
    path, size, sha = row
    target = BASE / path
    for node in reversed((target,) + tuple(target.parents)):
        value = node.lstat()
        need(not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'bootstrap_link')
        need(stat.S_ISREG(value.st_mode) if node == target else stat.S_ISDIR(value.st_mode),
             'bootstrap_kind')
    before = target.stat()
    need(before.st_nlink == 1 and before.st_size == size <= 65536, 'bootstrap_file')
    with target.open('rb') as stream:
        held = os.fstat(stream.fileno())
        key = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns)
        need(key(held) == key(before), 'bootstrap_identity')
        raw = stream.read(size + 1)
        need(key(os.fstat(stream.fileno())) == key(held), 'bootstrap_held_changed')
    need(key(target.stat()) == key(before) and (len(raw), digest(raw)) == (size, sha), 'bootstrap_pin')
    return raw


def select_module(raw, path, names, classes=(), assignments=True):
    """Compile only reviewed pure definitions; no writer, main or runtime load."""
    tree = ast.parse(raw.decode('utf-8'))
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) and assignments:
            selected.append(node)
        elif isinstance(node, ast.Assign) and assignments:
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in names:
            need(not node.decorator_list, 'pure_function_decorator')
            selected.append(node)
        elif isinstance(node, ast.ClassDef) and node.name in classes:
            need(not node.decorator_list and len(node.bases) == 1 and
                 isinstance(node.bases[0], ast.Name) and node.bases[0].id == 'object' and not node.keywords,
                 'pure_class_shape')
            selected.append(node)
    need([node.name for node in selected if isinstance(node, ast.FunctionDef)] and
         len([node for node in selected if isinstance(node, ast.FunctionDef)]) == len(names) and
         {node.name for node in selected if isinstance(node, ast.FunctionDef)} == set(names) and
         {node.name for node in selected if isinstance(node, ast.ClassDef)} == set(classes),
         'complete_pure_inventory')
    module = types.ModuleType('_filecenter_mutex_package_pure')
    module.__file__ = str(BASE / path)
    if not assignments:
        module.__dict__.update(ast=ast, hashlib=hashlib, os=os, Path=Path,
            PurePosixPath=PurePosixPath, re=re, stat=stat, BASE=BASE,
            REUSED_LARGE_GUI=REUSED_LARGE_GUI)
    exec(compile(ast.Module(body=selected, type_ignores=[]), module.__file__, 'exec'), module.__dict__)
    need(all(name not in module.__dict__ for name in ('main', 'publish', 'write_outputs',
         'load_checker', 'make_source')), 'excluded_entrypoints')
    return module


def literal(raw, name):
    rows = [node for node in ast.parse(raw.decode('utf-8')).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'literal_assignment:' + name)
    return ast.literal_eval(rows[0].value)


def actual_pin(path, raw):
    return path, len(raw), digest(raw)


def check_fc(label, rows, combined, owner, worker=None):
    need(type(rows) is tuple and len(rows) == 9 and len({row[0] for row in rows}) == 9,
         'fc9_unique_roles')
    expected = 101682 if label == 'send' else 115400
    need(sum(row[2] for row in rows) == expected <= 131072, 'fc9_independent_budget')
    for name, path, size, sha in rows:
        need(path in combined and (len(combined[path]), digest(combined[path])) == (size, sha), 'fc9_source_pin')
        ast.parse(combined[path].decode('utf-8'), feature_version=(3, 5))
    need(next(row[1:] for row in rows if row[0] == 'mta_filecenter_companion') == COMPANIONS[label],
         'fc9_mutex_companion_pin')
    need(next(row[1:] for row in rows if row[0] == 'mta_toolbox_minhttp') ==
         ('candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py', 9323,
          '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55'), 'fc9_retained_http_cap')
    pins = tuple((name, size, sha) for name, path, size, sha in rows)
    need(literal(owner, 'FILECENTER_PINS') == pins and
         (worker is None or literal(worker, 'FILECENTER_PINS') == pins), 'actual_fc9_owner_worker_binding')
    return expected


def check_send(outputs, facts, inputs, recipe):
    combined = dict(inputs, **outputs)
    runtime = {name: outputs[SEND_ROOT + 'runtime/' + name + '.py'] for name in SEND_RUNTIME}
    fc = json.loads(outputs[SEND_ROOT + 'assets/filecenter-source-manifest.json'].decode('ascii'))
    catalog_raw = outputs[SEND_ROOT + 'assets/ordinary-source-manifest.json']
    catalog = json.loads(catalog_raw.decode('ascii'))
    rows = tuple((row['module'], row['source'], row['bytes'], row['sha256']) for row in fc['sources'])
    fc_bytes = check_fc('send', rows, combined, runtime['mta_client_service_owner'], runtime['ui_session'])
    need(fc['schema'] == 'p011-formal-send-fc-mutex-v1-filecenter-source' and
         fc['source_count'] == 9 and fc['source_bytes'] == fc_bytes and fc['source_cap'] == 131072 and
         fc['in_protocol_stage_payload'] is False, 'send_separate_fc_manifest')
    need(catalog['schema'] == 'p011-formal-send-fc-mutex-v1-ordinary-source-catalog' and
         len(catalog['sources']) == catalog['source_count'] == 32 and
         sum(row['bytes'] for row in catalog['sources']) == catalog['ordinary_source_bytes'] == 1078691 and
         catalog['ordinary_batch_files'] == 37 and catalog['ordinary_batch_bytes'] == 1368142,
         'send_ordinary_actual_budget')
    for row in catalog['sources'] + catalog['startup_sources'] + catalog['helper_sources']:
        need(actual_pin(row['source'], combined[row['source']]) ==
             (row['source'], row['bytes'], row['sha256']), 'send_catalog_actual_pin')
    boot_pin = (len(runtime['mta_client_receive_boot']), digest(runtime['mta_client_receive_boot']))
    owner_pin = (len(runtime['mta_client_service_owner']), digest(runtime['mta_client_service_owner']))
    outer_pin = (len(runtime['formal_send_session']), digest(runtime['formal_send_session']))
    need(literal(runtime['mta_client_service_owner'], 'BOOT_PIN') == boot_pin and
         literal(runtime['formal_send_session'], 'BOOT_PIN') == boot_pin and
         literal(runtime['formal_send_session'], 'OWNER_PIN') == owner_pin and
         literal(runtime['ui_session'], 'SENDER_PIN') == outer_pin and
         literal(runtime['ui_session'], 'GUARDIAN_PIN') ==
             (len(runtime['ui_guardian']), digest(runtime['ui_guardian'])) and
         literal(runtime['ui_session'], 'ASSETS_PIN') ==
             (len(runtime['ui_assets']), digest(runtime['ui_assets'])), 'send_actual_startup_worker_chain')
    need(literal(runtime['mta_client_receive_boot'], 'SOURCE_PINS') ==
         tuple((row['module'], row['bytes'], row['sha256']) for row in catalog['sources']), 'send_boot_ordinary32')
    ordinary = recipe.ordinary_rows(catalog)
    need(len(ordinary) == 37 and sum(row[1] for row in ordinary) == 1368142 and
         literal(runtime['formal_send_stage'], 'PROFILE_FILES')[2] ==
             ('ordinary', recipe.NEW_PHYSICAL, ordinary) and
         literal(runtime['formal_send_stage'], 'PROFILE_TOTALS') ==
             (('sender', 27, 2402458), ('observer', 41, 1548495), ('ordinary', 37, 1368142)),
         'send_stage_inventory_binding')
    need(literal(runtime['mta_client_receive_boot'], 'LOAD_SECONDS') == 10.0 and
         literal(runtime['mta_client_service_owner'], 'CLEANUP_SECONDS') == 60.0 and
         literal(runtime['mta_client_service_owner'], 'FILECENTER_MAX_SOURCE') == 131072 and
         literal(runtime['formal_send_session'], 'PROFILES') ==
             (('diagnostic', 60.0, False), ('send-interactive-v1', 600.0, True)) and
         literal(runtime['formal_send_stage'], 'MAX_SECONDS') == 120.0, 'send_original_protection_caps')
    need(facts['reused_gui_files'] == 19 and facts['reused_gui_bytes'] == 4185296 and
         facts['filecenter_companion_only_changed'] is True and facts['filecenter_other_eight_exact'] is True and
         facts['filecenter_parent_deadline_verified'] is False and
         facts['filecenter_media_mutex_device_verified'] is False, 'send_source_not_runtime_evidence')
    return dict(fc9_sources=9, fc9_bytes=fc_bytes, fc9_cap=131072,
        ordinary_sources=32, ordinary_bytes=1078691, ordinary_batch_files=37, ordinary_batch_bytes=1368142,
        gui_unchanged_files=19, gui_unchanged_bytes=4185296, startup_worker_chain=True,
        stage_inventory_source_only=True, original_deadline_constants=True)


def check_receive(outputs, facts, inputs, recipe):
    combined = dict(inputs, **outputs)
    definitions = select_module(outputs[RECEIVE_DEFINITIONS], RECEIVE_DEFINITIONS, DEFINITION_FUNCTIONS)
    need(definitions.verify_inputs(combined) == 6, 'receive_pure_full_closure_return6')
    owner = outputs[RECEIVE_ROOT + 'runtime/mta_client_service_owner.py']
    factory = outputs[RECEIVE_ROOT + 'runtime/mta_client_receive_factory.py']
    rows = definitions.FILECENTER_SOURCES
    fc_bytes = check_fc('receive', rows, combined, owner)
    payload = definitions.ORDINARY_ROWS + definitions.HELPERS + definitions.PRIVATE_ROWS + \
        (definitions.WPA, definitions.MONITOR)
    need(len(payload) == len({row[0] for row in payload}) == 75 and
         sum(row[2] for row in payload) == definitions.PAYLOAD_BYTES == 4193768 <=
         definitions.PAYLOAD_CAP == 4194304, 'receive75_actual_budget')
    for name, path, size, sha in payload:
        need(actual_pin(path, combined[path]) == (path, size, sha), 'receive75_actual_source_pin')
    need(definitions.MECHANICAL_CLOSURE_COUNT == 6 and definitions.BUSINESS_CLOSURE_COUNT == 1 and
         definitions.MUTEX_BUSINESS_CLOSURE_COUNT == 1 and
         definitions.BUSINESS_EXPECTED == definitions.CURRENT_EXPECTED['BUSINESS_EXPECTED'] and
         definitions.ROOT_AFTER == 'p011-mta-rx-mlock1-v001' and
         literal(factory, 'STARTUP_READ_SECONDS') == 20.0 and
         facts['startup_collector_seconds'] == 10.0 and facts['payload_remaining'] == 536 and
         facts['device_tested'] is False and facts['stage_tested'] is False and
         facts['phone_tested'] is False and facts['rf_requested'] is False and
         facts['whole_close_verified'] is False, 'receive_distinct_prepare20_mutex_source_scope')
    return dict(fc9_sources=9, fc9_bytes=fc_bytes, fc9_cap=131072,
        payload_roles=75, payload_bytes=4193768, payload_cap=4194304, payload_remaining=536,
        mechanical_closure_count=6, retained_prepare20_business_count=1, new_mutex_business_count=1,
        prepare_seconds=20.0, collector_seconds=10.0, inverse_and_current_source_closure=True)


def main():
    args = sys.argv[1:]
    need(args in ([], ['--assemble'], ['--assemble-receive']), 'fixed_mode_only')
    need(os.name == 'nt' and sys.version_info[:2] == (3, 12) and
         Path(__file__).resolve() == (BASE / SELF).resolve(), 'fixed_pc_runtime')
    mode = 'source' if not args else args[0][2:]
    donor_raw, seal_raw = bootstrap(DONOR), bootstrap(SEALER)
    reader = select_module(donor_raw, DONOR[0],
        ('need', 'sha', 'metadata', 'read_fixed', 'literal', 'pins_tuple'), assignments=False)
    read_fixed = reader.read_fixed
    seal = types.ModuleType('_filecenter_mutex_package_seal')
    seal.__file__ = str(BASE / SEALER[0])
    exec(compile(seal_raw, seal.__file__, 'exec'), seal.__dict__)
    out = BASE / 'results' / ('filecenter-mutex-package-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {DONOR[0]: donor_raw, SEALER[0]: seal_raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema='filecenter-mutex-package-v1-source', passed=False, error=None,
        mode=mode.upper(), input_count=2, inputs_preserved=False, snapshots_preserved=False,
        packages=[], children=[], prepared_both=False, published_both_actual=False,
        generator_main_called=False, package_write_called=False, old_main_called=False, old_tests_run=0,
        actual_p011=False, staging=False, rf=False, phone=False, ui=False, native_owner=False,
        device_root_existence_verified=False, full_filecenter_deadline_verified=False,
        blocking_file_io_preemption_verified=False, full_restore_verified=False)
    prepared = {}

    def retain(path, raw, pin=None):
        current = read_fixed(path, pin)
        evidence._retain(path, current)
        need(current == raw, 'prepared_source_changed:' + path)
        return current

    def published(label):
        outputs = prepared[label]['outputs']
        entry = prepared[label]['entry']
        for path, raw in outputs.items():
            retain(path, raw, (len(raw), digest(raw)))
            entry['actual_outputs_verified'] += 1
        entry['published_actual'] = True

    try:
        for path in (SELF, CMD):
            evidence._retain(path, read_fixed(path))
        all_outputs = set()
        # Both complete derivations and their inverse/bindings finish before any writer.
        for label, path, size, sha in GENERATORS:
            raw = read_fixed(path, (size, sha))
            evidence._retain(path, raw)
            recipe = select_module(raw, path, PURE[label], ('Edit',) if label == 'send' else ())
            outputs, facts, source_inputs = recipe.prepare()
            need(type(outputs) is dict and type(facts) is dict and type(source_inputs) is dict and
                 bool(source_inputs) and set(outputs) == set(OUTPUT_NAMES[label]), 'fixed_prepare_contract')
            for key, value in source_inputs.items():
                need(type(key) is str and type(value) is bytes, 'source_input_contract')
                retain(key, value)
            for key, value in outputs.items():
                need(type(value) is bytes and 0 < len(value) <= 2097152 and key not in source_inputs and
                     key not in all_outputs, 'immutable_output_partition')
                all_outputs.add(key)
                if key.endswith('.py') and '/runtime/' in key:
                    ast.parse(value.decode('utf-8'), feature_version=(3, 5))
                if (BASE / key).exists():
                    retain(key, value, (len(value), digest(value)))
            observation = check_send(outputs, facts, source_inputs, recipe) if label == 'send' else \
                check_receive(outputs, facts, source_inputs, recipe)
            observation.update(label=label, prepared=True, published_actual=False, actual_outputs_verified=0,
                outputs=len(outputs), generator_sources=len(source_inputs),
                output_pins=[dict(path=key, bytes=len(value), sha256=digest(value))
                             for key, value in sorted(outputs.items())])
            report['packages'].append(observation)
            prepared[label] = dict(outputs=outputs, facts=facts, entry=observation)
            seal.fresh(out / ('private-raw/' + label + '-package-facts.json'),
                       (json.dumps(facts, sort_keys=True, indent=2) + '\n').encode('ascii'))
        need(set(prepared) == {'send', 'receive'}, 'two_prepared_packages')
        report['prepared_both'] = True
        evidence.snapshot(out, lambda key: key)
        need(all(read_fixed(key) == value for key, value in inputs.items()), 'prewriter_inputs_preserved')
        if mode == 'assemble-receive':
            published('send')
        writing = ('send', 'receive') if mode == 'assemble' else ('receive',) if mode == 'assemble-receive' else ()
        for label in writing:
            row = next(row for row in GENERATORS if row[0] == label)
            need(read_fixed(row[1], row[2:]) == inputs[row[1]], 'writer_fixed_pin_again')
            argv = [str(Path(sys.executable)), '-I', '-B', str(BASE / row[1]), '--write']
            seal.fresh(out / ('private-raw/' + label + '-argv.json'),
                       (json.dumps(argv) + '\n').encode('ascii'))
            report.update(generator_main_called=True, package_write_called=True)
            timed_out = False
            try:
                child = subprocess.run(argv, cwd=str(BASE), capture_output=True, timeout=60)
                code, stdout, stderr = child.returncode, child.stdout, child.stderr
            except subprocess.TimeoutExpired as error:
                timed_out = True
                code, stdout, stderr = None, error.stdout or b'', error.stderr or b''
            for tag, value in (('stdout', stdout), ('stderr', stderr)):
                seal.fresh(out / ('private-raw/' + label + '-' + tag + '.raw'), value)
            seal.fresh(out / ('private-raw/' + label + '-host-exit'), (str(code) + '\n').encode('ascii'))
            seal.fresh(out / ('private-raw/' + label + '-timeout'), (str(timed_out) + '\n').encode('ascii'))
            report['children'].append(dict(label=label, exit=code, timed_out=timed_out,
                stdout_bytes=len(stdout), stdout_sha256=digest(stdout),
                stderr_bytes=len(stderr), stderr_sha256=digest(stderr), host_timeout_seconds=60))
            need(timed_out is False and type(code) is int and code == 0 and not stderr,
                 'fixed_package_writer_failed:' + label)
            published(label)
        if mode == 'source':
            published('send')
            published('receive')
        need(all(entry['published_actual'] is True for entry in report['packages']), 'two_actual_packages')
        report.update(published_both_actual=True, passed=True)
    except BaseException as error:
        report['error'] = type(error).__name__ + ':' + str(error)[:180]
        seal.fresh(out / 'private-raw/exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            evidence.snapshot(out, lambda key: key)
            report['input_count'] = len(inputs)
            report['inputs_preserved'] = not evidence.partial and not evidence.changed_attempts and all(
                read_fixed(key) == value for key, value in inputs.items())
            report['snapshots_preserved'] = all(
                (out / 'private-inputs' / key).read_bytes() == value for key, value in inputs.items())
            need(report['inputs_preserved'] and report['snapshots_preserved'], 'source_preservation')
        except BaseException as error:
            report['passed'] = False
            report['error'] = report['error'] or type(error).__name__ + ':' + str(error)[:180]
            seal.fresh(out / 'private-raw/preservation-exception.txt', traceback.format_exc().encode('utf-8'))
    readme = (b'PC-only SOURCE closure of two independently versioned media-mutex packages.\n'
        b'Both frozen pure recipes derive exact bytes and inverse proofs before any writer.\n'
        b'Default SOURCE never writes packages and requires actual published bytes.\n'
        b'Explicit --assemble calls each fixed new PC writer once with a 60-second cap.\n'
        b'--assemble-receive reads complete send artifacts and calls only the receive writer.\n'
        b'Writer stdout, stderr, exit, timeout, facts and all input snapshots are private.\n'
        b'Partial outputs and failed results remain; no automatic retry or deletion.\n'
        b'FC9 independent cap 131072; send 101682, receive 115400 bytes.\n'
        b'Send ordinary 37 files 1368142 bytes; receive 75 roles 4193768, spare 536.\n'
        b'Receive prepare20 and collector10 are distinct unchanged facts.\n'
        b'No old main/tests, runtime, Stage, ADB, RF, phone or device acceptance.\n'
        b'No full deadline, blocking-file-IO preemption or whole restoration claim.\n')
    result = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=result['report']['passed'], output=str(out),
        archive=str(result['archive']) if result['archive'] else None,
        archive_sha256=result['archive_sha256'], error=result['report']['error']), ensure_ascii=True))
    return result['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
