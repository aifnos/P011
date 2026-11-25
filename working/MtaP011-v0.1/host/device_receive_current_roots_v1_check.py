"""Current receiver directories/file metadata; default PC SOURCE only.

Explicit --check-device takes fourteen lstat samples and stock before/after.
The frozen mother's BODY and nine pure helpers are reused, not its main,
Stage contract or three-row classifier. No sampled file content, inventory,
actor, pending, receive admission or RF assertion is made.
"""
import ast, base64, datetime, hashlib, json, re, secrets, stat, subprocess, sys, types, zipfile, zlib
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_current_roots_v1_check.py'
CMD = 'HOST_MTA_RECEIVE_CURRENT_ROOTS_V1.cmd'
MOTHER = ('host/device_formal_send_repair_prerequisite_roots_v1_check.py', 16667,
          '94325f0c0f666c88e198dec11a18efce39daf3d1463c925c9ee51bbe649450fd')
RUNNER = ('candidate/receive-proc-freezer-v1/runtime/mta_formal_receive_session.py', 79279,
          '68573f0c9053db3df42f71647d9765a6af9bda56f4913daeef52b79e907f1894')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
HELPERS = ('sha', 'need', 'write_new', 'literal', 'probe_definitions',
           'compressed_budget', 'receipt', 'run_readonly', 'stock_identity')


def need(value, code):
    if value is not True: raise ValueError(code)


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_changed')
    need(path.read_bytes() == raw, 'source_changed')


def prepare(inputs):
    for row in (MOTHER, RUNNER, TRANSPORT):
        need((len(inputs[row[0]]), hashlib.sha256(inputs[row[0]]).hexdigest()) == row[1:], 'input_pin')
    mother = inputs[MOTHER[0]]
    tree = ast.parse(mother.decode('utf-8'))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in HELPERS]
    need(len(nodes) == 9 and {node.name for node in nodes} == set(HELPERS), 'source_contract')
    helper = types.ModuleType('current_receiver_metadata_pure_helpers')
    helper.__dict__.update(Path=Path, subprocess=subprocess, re=re, base64=base64,
                          zlib=zlib, ast=ast, types=types, hashlib=hashlib, BASE=BASE)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<fixed-current-metadata-helpers>', 'exec'), helper.__dict__)
    need(helper.literal(mother, 'TRANSPORT') == TRANSPORT, 'source_contract')
    source = inputs[RUNNER[0]]
    state, go = helper.literal(source, 'STATE_ROOT'), helper.literal(source, 'GO_ROOT')
    roles = helper.literal(source, 'ROLE_PINS')
    deployment = [row for row in roles if type(row) is tuple and row[0] == 'mta_go_deployment']
    need(type(state) is str and type(go) is str and len(deployment) == 1 and
         deployment[0][1:] == (26543, 'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe'), 'source_contract')
    roots = (('rx', state), ('rx-runtime', state + '/runtime'), ('rx-native', state + '/native'),
             ('rx-runtime35', state + '/runtime35'), ('go', go), ('go-runtime', go + '/runtime'),
             ('go-deployment', go + '/runtime/' + deployment[0][0] + '.py'))
    need(len({path for role, path in roots}) == 7, 'source_contract')
    body = helper.literal(mother, 'BODY')
    program = 'ROOTS=' + repr(roots) + '\n' + body
    helper.compressed_budget(program)
    baseline = 'PINS=' + repr(helper.literal(inputs[TRANSPORT[0]], 'PINS')) + '\n' + helper.literal(inputs[TRANSPORT[0]], 'PROBE')
    helper.compressed_budget(baseline)
    return helper, roots, program, tuple(helper.literal(mother, 'FALSE_FIELDS')), deployment[0], body


def classify(value, roots, false_fields, file_size):
    need(type(value) is dict and set(value) == {'samples', 'lstat_calls'} | set(false_fields) and
         type(value['lstat_calls']) is int and value['lstat_calls'] == 14 and
         all(value[field] is False for field in false_fields) and
         type(value['samples']) is tuple and len(value['samples']) == 7, 'remote_result')
    rows = []
    for index, (actual, expected) in enumerate(zip(value['samples'], roots)):
        need(type(actual) is tuple and len(actual) == 3 and actual[0] == expected[0], 'remote_result')
        for sample in actual[1:]:
            need(type(sample) is tuple and len(sample) == 2 and sample[0] in ('missing', 'error', 'metadata'), 'remote_result')
            if sample[0] == 'metadata':
                need(type(sample[1]) is tuple and len(sample[1]) == 9 and
                     all(type(item) is int and -(1 << 63) <= item < (1 << 64) for item in sample[1]), 'remote_result')
            elif sample[0] == 'missing': need(sample[1] is None, 'remote_result')
            else: need(sample[1] is None or type(sample[1]) is int and 1 <= sample[1] <= 4095, 'remote_result')
        first, second = actual[1:]
        stable = first == second
        meta = first[1] if stable and first[0] == 'metadata' else None
        suitable = meta is not None and meta[3:5] == (0, 0) and (
            meta[2] == stat.S_IFDIR | 0o700 and meta[5] >= 1 if index < 6 else
            meta[2] == stat.S_IFREG | 0o400 and meta[5] == 1 and meta[6] == file_size)
        missing = stable and first[0] == 'missing'
        rows.append(dict(role=expected[0], samples_stable=stable, typed_enoent_both=missing,
                         status='missing' if missing else 'suitable' if suitable else 'unsuitable',
                         metadata_suitable=suitable, independent_leaf_absence_certified=False))
    return rows


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'fixed_argv')
    mode = 'device-readonly' if sys.argv[1:] else 'source'
    out = BASE / 'results' / ('receive-current-roots-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs, inventory = {}, {}
    helper = adb = probe = before = after = None
    report = dict(kind='receive-current-roots-v1', mode=mode, passed=False, source_complete=False,
        source_preserved=False, input_count=0, device_invoked=False, metadata_observed=False,
        observation_complete=False, prerequisites_metadata_suitable=False, lstat_calls=0, path_statuses=None,
        stock_identity_ok=None, stock_unchanged=None, wifi_connected_before=None, wifi_connected_after=None,
        baseline_before_receipt=None, baseline_after_receipt=None, metadata_receipt=None, error_code=None,
        device_writes=False, directory_opened=False, metadata_inventory_read=False, prerequisite_file_contents_read=False,
        sampler_scope='SEVEN_PROJECT_PATHS_ONLY', stock_read_scope='ORIGINAL_PROBE_FILE_HASHES_AND_PROCESSES',
        stage_invoked=False, owner_started=False, ui_started=False, radio_operations=False,
        pending_checked=False, actors_checked=False, inventory_verified=False, file_sha256_verified=False,
        safety_admitted=False, receive_admitted=False, restoration_verified=False,
        evidence='PC_SOURCE_ONLY' if mode == 'source' else 'FIXED_PATH_METADATA_ONLY')
    try:
        # Every source is privately retained immediately, before its pin/AST contract.
        for relative in (SELF, CMD, MOTHER[0], RUNNER[0], TRANSPORT[0]):
            raw = (BASE / relative).read_bytes()
            inputs[relative] = raw
            save(out / 'private-inputs' / relative, raw)
        helper, roots, program, false_fields, deployment, body = prepare(inputs)
        helper.write_new(private / 'metadata.source.private.py', program.encode('ascii'))
        report.update(source_complete=True, source_path_count=len(roots), source_lstat_count=14,
                      helper_definition_count=9, unchanged_body_sha256=helper.sha(body.encode('ascii')))
        if mode == 'device-readonly':
            probe = helper.probe_definitions(inputs[TRANSPORT[0]])
            report['device_invoked'] = True
            adb = probe.Adb(private)
            before = helper.run_readonly(adb, probe, private, 'stock-before', probe.source(), report, 'baseline_before_receipt')
            helper.write_new(private / 'stock-before.private.json', (json.dumps(before, sort_keys=True) + '\n').encode('ascii'))
            need(helper.stock_identity(before, probe.PINS), 'stock_baseline')
            report['wifi_connected_before'] = before['capabilities']['wifi_connected']
            value = helper.run_readonly(adb, probe, private, 'current-metadata', program, report, 'metadata_receipt')
            helper.write_new(private / 'metadata.samples.private.json', (json.dumps(value, sort_keys=True) + '\n').encode('ascii'))
            report['path_statuses'] = classify(value, roots, false_fields, deployment[1])
            report.update(metadata_observed=True, lstat_calls=value['lstat_calls'])
            report['prerequisites_metadata_suitable'] = all(row['metadata_suitable'] for row in report['path_statuses'])
    except BaseException as error:
        code = error.args[0] if type(error) is ValueError and len(error.args) == 1 else None
        report['error_code'] = code if code in ('input_pin', 'source_contract', 'source_budget',
            'remote_result', 'stock_baseline', 'stock_changed', 'source_changed') else 'host_transport' if type(error) is RuntimeError else 'unexpected'
    finally:
        if adb is not None:
            try:
                after = helper.run_readonly(adb, probe, private, 'stock-after', probe.source(), report, 'baseline_after_receipt')
                helper.write_new(private / 'stock-after.private.json', (json.dumps(after, sort_keys=True) + '\n').encode('ascii'))
                report['stock_identity_ok'] = before is not None and helper.stock_identity(before, probe.PINS) and helper.stock_identity(after, probe.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                report['wifi_connected_after'] = after['capabilities']['wifi_connected']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None: report['error_code'] = 'stock_changed'
        preserved = len(inputs) == 5
        for relative, raw in inputs.items():
            inventory[relative] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            try:
                preserved = preserved and (out / 'private-inputs' / relative).read_bytes() == raw and (BASE / relative).read_bytes() == raw
            except BaseException: preserved = False
        report.update(source_preserved=preserved, input_count=len(inputs))
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['observation_complete'] = bool(report['metadata_observed'] and report['stock_identity_ok'] is True and
        report['stock_unchanged'] is True and report['source_preserved'] and report['error_code'] is None)
    report['passed'] = bool(report['source_complete'] and report['source_preserved'] and report['error_code'] is None and
        (mode == 'source' or report['observation_complete']))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE; explicit --check-device fixed metadata and stock before/after only.\n'
        b'Unchanged mother BODY, two lstat samples each of six real directories and one file.\n'
        b'PASS/observation_complete does not mean prerequisites_metadata_suitable.\n'
        b'Suitable metadata does not authenticate file bytes/hash, actors, pending, receive or RF admission.\n'
        b'ENOENT endpoints sharing a missing parent do not certify independent missing leaves.\n'
        b'No prerequisite-path directory open/list or auxiliary-package file content read/write.\n'
        b'Original stock baseline file hashes and process observations do read original bytes.\n'
        b'No Stage/Owner/UI/helper/RF or record handling.\n'
        b'Raw source/stdout/stderr/host and remote exits stay private. ZIP exactly result+README.\n')
    save(out / 'result.json', result)
    save(out / 'README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == result and archive.read('README.txt') == readme, 'source_changed')
    code = 0 if report['passed'] else 1
    save(out / 'checker-exit.txt', (str(code) + '\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out)), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
