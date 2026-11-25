"""PC-only SOURCE audit of two immutable, mechanically integrated packages.

Default does not invoke any generator main/write or subprocess. --assemble
alone executes the two fixed new PC writers and retains their raw streams.
Recompute pure packages, compare actual artifacts and retain all inputs.
This is source closure evidence, not Stage, runtime or phone acceptance.
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
SELF = 'host/filecenter_http_cap_package_v1_check.py'
CMDS = ('HOST_MTA_FILECENTER_HTTP_CAP_PACKAGE_V1_CHECK.cmd',
        'BUILD_MTA_FILECENTER_HTTP_CAP_PACKAGE_V1.cmd')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
# Complete reviewed source pins; never resolve a new writer from CLI input.
GENERATORS = (
    ('send', 'candidate/formal-send-fc-http-cap-v1/generate_package.py', 33030,
     'd949a5d68efd0d4d29a47412feb99a61bed1c9e058716e02522678d7aad7b91d'),
    ('receive', 'candidate/receive-fc-http-cap-graph-v1/generate_graph.py', 31875,
     '15f7f9569f0513c6c7cc15158fe3e24b84875b9ab7d7fb9f5ef48c6d1c3bd0bd'),
)
OUTPUT_SCOPES = {
    'send': ('candidate/formal-send-fc-http-cap-v1/',),
    'receive': ('candidate/receive-fc-http-cap-graph-v1/', 'host/formal_receive_fc_http_cap_v1_'),
}
# Only this unchanged pinned GUI executable exceeds the ordinary 2 MiB input
# cap. It is read-only source provenance, never a deployed original program.
REUSED_LARGE_GUI = (
    'out/mta-ui-send-status-v1-6d4fb1fd4af949cbb3515870/Z03.mta-ui-candidate',
    4103844, '9caf72924d110186a9e4f89e872bb1ca9debb096f9ece6c34263c00aba95d7cf')
HTTP_PIN = (9323, '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55')
COMPANION_PINS = {
    'send': (26088, '5daa53f647db195f02a5588f0fb45d009b490eaa51d0af98de76205b00fdee0f'),
    'receive': (33630, '8b3ab84e17de135622b3a58e29138ca556376172e6c523eb9ab22ef44f4880ba'),
}
FILECENTER_COMMON = (
    ('mta_toolbox_json', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069,
     'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('mta_toolbox_minhttp', 'candidate/filecenter-http-parent-cap-v1/shared/mta_toolbox_minhttp.py', 9323,
     '8ea06020e4b133665ab881e5901af9094ebc2c9d5add9d4eb37ca5b2e55a8c55'),
    ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114,
     'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('mta_toolbox_metrics', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py', 4080,
     'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('mta_toolbox_audio', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045,
     'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('mta_toolbox_server', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py', 19732,
     'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('mta_filecenter_audio', 'candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082,
     '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'),
)
FILECENTER_ROWS = {
    'send': FILECENTER_COMMON + (
        ('mta_filecenter_storage', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py', 4581,
         '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
        ('mta_filecenter_companion', 'candidate/filecenter-http-parent-cap-v1/send/mta_filecenter_companion.py',
         26088, '5daa53f647db195f02a5588f0fb45d009b490eaa51d0af98de76205b00fdee0f')),
    'receive': FILECENTER_COMMON + (
        ('mta_filecenter_storage', 'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757,
         'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4'),
        ('mta_filecenter_companion', 'candidate/filecenter-http-parent-cap-v1/receive/mta_filecenter_companion.py',
         33630, '8b3ab84e17de135622b3a58e29138ca556376172e6c523eb9ab22ef44f4880ba')),
}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_fixed(name, pin=None):
    need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None and
         not PurePosixPath(name).is_absolute() and
         all(part not in ('', '.', '..') for part in name.split('/')), 'fixed_path')
    target = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        target = target / part
        value = target.lstat()
        need(not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'fixed_link')
        if index < len(name.split('/')) - 1:
            need(stat.S_ISDIR(value.st_mode), 'fixed_ancestor')
    cap = REUSED_LARGE_GUI[1] if name == REUSED_LARGE_GUI[0] else 2097152
    need(stat.S_ISREG(value.st_mode) and 0 < value.st_size <= cap, 'fixed_file')
    before = metadata(value)
    with target.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        same = opened == before if os.name != 'nt' else (
            opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
            opened[3:6] == before[3:6])
        need(same, 'fixed_open_identity')
        raw = handle.read(cap + 1)
        need(metadata(os.fstat(handle.fileno())) == opened, 'fixed_held_stability')
    need(metadata(target.lstat()) == before and len(raw) == before[4], 'fixed_path_stability')
    if pin is not None:
        need((len(raw), sha(raw)) == tuple(pin), 'fixed_pin:' + name)
    if name == REUSED_LARGE_GUI[0]:
        need((len(raw), sha(raw)) == REUSED_LARGE_GUI[1:], 'one_reused_large_gui_pin')
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'))
    nodes = [node for node in tree.body if isinstance(node, ast.Assign) and
             len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
             node.targets[0].id == name]
    need(len(nodes) == 1, 'single_literal:' + name)
    return ast.literal_eval(nodes[0].value)


def pins_tuple(rows):
    need(type(rows) is tuple and len(rows) == 9, 'filecenter_tuple')
    need(all(type(row) is tuple and len(row) == 3 and type(row[0]) is str and
             type(row[1]) is int and type(row[2]) is str for row in rows), 'filecenter_pin_fields')
    need(len({row[0] for row in rows}) == 9, 'filecenter_unique')
    return {name: (size, digest) for name, size, digest in rows}


def independent_bindings(label, outputs, source_inputs):
    owners = [(path, raw) for path, raw in outputs.items()
              if path.endswith('/runtime/mta_client_service_owner.py')]
    need(len(owners) == 1, 'one_actual_owner')
    expected = COMPANION_PINS[label]
    exact_rows = tuple((name, size, digest) for name, path, size, digest in FILECENTER_ROWS[label])
    actual_rows = literal(owners[0][1], 'FILECENTER_PINS')
    need(actual_rows == exact_rows, 'complete_actual_owner_fc9')
    bound = pins_tuple(actual_rows)
    need(bound['mta_toolbox_minhttp'] == HTTP_PIN and
         bound['mta_filecenter_companion'] == expected, 'actual_owner_fc_binding')
    limit = 100114 if label == 'send' else 113832
    need(sum(size for size, digest in bound.values()) == limit <= 131072, 'actual_fc9_budget')
    if label == 'send':
        workers = [(path, raw) for path, raw in outputs.items() if path.endswith('/runtime/ui_session.py')]
        need(len(workers) == 1 and literal(workers[0][1], 'FILECENTER_PINS') == exact_rows,
             'actual_worker_fc_binding')
        manifests = [(path, raw) for path, raw in outputs.items()
                     if path.endswith('/filecenter-source-manifest.json')]
        need(len(manifests) == 1, 'one_actual_send_fc_manifest')
        value = json.loads(manifests[0][1].decode('ascii'))
        expected_sources = [dict(module=name, source=path, bytes=size, sha256=digest)
                            for name, path, size, digest in FILECENTER_ROWS[label]]
        need(value['sources'] == expected_sources and value['source_count'] == 9 and
             value['source_bytes'] == limit and value['source_cap'] == 131072, 'send_fc9_source_paths')
    else:
        defs = [(path, raw) for path, raw in outputs.items()
                if path.startswith('host/') and path.endswith('_definitions.py')]
        need(len(defs) == 1, 'one_actual_receive_definition')
        rows = literal(defs[0][1], 'FILECENTER_SOURCES')
        need(rows == FILECENTER_ROWS[label], 'actual_receive_fc_source_paths')
        need(literal(defs[0][1], 'PAYLOAD_BYTES') == 4193464, 'actual_receive_payload_budget')
        module = types.ModuleType('_actual_fc_http_cap_receive_source_validation')
        module.__file__ = str(BASE / defs[0][0])
        exec(compile(defs[0][1], module.__file__, 'exec'), module.__dict__)
        combined = dict(source_inputs)
        for path, raw in outputs.items():
            need(path not in combined or combined[path] == raw, 'new_definition_input_collision')
            combined[path] = raw
        count = module.verify_inputs(combined)
        need(type(count) is int and count == 6, 'new_receive_source_validator')
    observation = dict(owner=owners[0][0], filecenter_sources=9, filecenter_bytes=limit,
                       filecenter_cap=131072, source_bindings_verified=True)
    if label == 'receive':
        observation.update(new_source_validator_called=True, mechanical_closures=6,
                           origin_sources=len(module.ORIGIN_SOURCE_PINS), payload_roles=75,
                           payload_bytes=4193464, payload_spare=840)
    return observation


def main():
    need(sys.argv[1:] in ([], ['--assemble'], ['--assemble-receive']) and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and
         Path(sys.executable) == Path(r'C:\Users\P011_USER\AppData\Local\Programs\Python\Python312\python.exe'),
         'fixed_pc_entry')
    writing_labels = (frozenset(('send', 'receive')) if sys.argv[1:] == ['--assemble'] else
                      frozenset(('receive',)) if sys.argv[1:] == ['--assemble-receive'] else frozenset())
    mode = ('assembly' if sys.argv[1:] == ['--assemble'] else
            'assembly-receive' if writing_labels else 'source')
    seal_raw = read_fixed(SEALER[0], SEALER[1:])
    seal = types.ModuleType('_fc_http_cap_package_v1_sealer')
    exec(compile(seal_raw, str(BASE / SEALER[0]), 'exec'), seal.__dict__)
    out = BASE / 'results' / ('filecenter-http-cap-package-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs = {SEALER[0]: seal_raw}
    evidence = seal.InputEvidence(inputs)
    report = dict(schema='filecenter-http-cap-package-v1-source', passed=False, error=None,
        mode=mode.upper(), inputs_preserved=False, snapshots_preserved=False,
        input_count=1, packages=[], children=[], actual_p011=False, staging=False, rf=False, phone=False,
        ui=False, native_owner=False, generator_main_called=False, package_write_called=False,
        old_tests_run=0, full_filecenter_deadline_verified=False, full_restore_verified=False)
    all_outputs = {}

    def retain(path, raw, pin=None):
        current = read_fixed(path, pin)
        need(current == raw, 'prepared_source_changed:' + path)
        evidence._retain(path, raw)
        return raw

    try:
        for path in (SELF,) + CMDS:
            evidence._retain(path, read_fixed(path))
        need(type(GENERATORS) is tuple and len(GENERATORS) == 2 and type(OUTPUT_SCOPES) is dict,
             'package_pins_not_frozen')
        for label, path, size, digest in GENERATORS:
            for name, source_path, source_size, source_sha in FILECENTER_ROWS[label]:
                evidence._retain(source_path, read_fixed(source_path, (source_size, source_sha)))
            raw = read_fixed(path, (size, digest))
            evidence._retain(path, raw)
            module = types.ModuleType('_fc_http_cap_package_v1_' + label)
            module.__file__ = str(BASE / path)
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
            outputs, facts, source_inputs = module.prepare()
            need(type(outputs) is dict and 1 <= len(outputs) <= 64 and
                 type(facts) is dict and type(source_inputs) is dict and bool(source_inputs),
                 'pure_package_contract')
            for key, value in source_inputs.items():
                need(type(key) is str and type(value) is bytes, 'input_contract')
                retain(key, value)
            if label in writing_labels:
                argv = [str(Path(sys.executable)), '-I', '-B', str(BASE / path), '--write']
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
                report['children'].append(dict(label=label, exit=code, timed_out=timed_out,
                    stdout_bytes=len(stdout), stdout_sha256=sha(stdout),
                    stderr_bytes=len(stderr), stderr_sha256=sha(stderr), host_timeout_seconds=60))
                need(timed_out is False and type(code) is int and code == 0 and not stderr,
                     'fixed_package_writer_failed:' + label)
            for key, value in outputs.items():
                need(type(key) is str and type(value) is bytes and value and
                     any(key.startswith(prefix) for prefix in OUTPUT_SCOPES[label]), 'output_scope')
                need(key not in all_outputs, 'output_collision')
                retain(key, value)
                all_outputs[key] = value
                if key.endswith('.py') and '/runtime/' in key:
                    ast.parse(value.decode('utf-8'), feature_version=(3, 5))
            observation = independent_bindings(label, outputs, source_inputs)
            observation.update(label=label, outputs=len(outputs), generator_sources=len(source_inputs),
                output_pins=[dict(path=key, bytes=len(value), sha256=sha(value))
                             for key, value in sorted(outputs.items())])
            report['packages'].append(observation)
            seal.fresh(out / ('private-raw/' + label + '-package-facts.json'),
                       (json.dumps(facts, sort_keys=True, indent=2) + '\n').encode('ascii'))
        need({row['label'] for row in report['packages']} == {'send', 'receive'}, 'two_actual_packages')
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ':' + str(error)[:180]
        seal.fresh(out / 'private-raw/exception.txt', traceback.format_exc().encode('utf-8'))
    finally:
        try:
            evidence.snapshot(out, lambda key: key)
            report['input_count'] = len(inputs)
            report['inputs_preserved'] = not evidence.partial and all(
                read_fixed(key) == value for key, value in inputs.items())
            report['snapshots_preserved'] = all(
                (out / 'private-inputs' / key).read_bytes() == value for key, value in inputs.items())
            need(report['inputs_preserved'] and report['snapshots_preserved'], 'source_preservation')
        except BaseException as error:
            report['passed'] = False
            report['error'] = report['error'] or type(error).__name__ + ':' + str(error)[:180]
            seal.fresh(out / 'private-raw/preservation-exception.txt', traceback.format_exc().encode('utf-8'))
    readme = (b'PC-only closure for independently versioned send/receive FileCenter HTTP cap packages.\n'
              b'Fixed pure generators recompute artifacts; actual files and every input are reread.\n'
              b'Default SOURCE does not write packages or start a child; explicit --assemble alone\n'
              b'executes two frozen new PC writers, preserving stdout/stderr/exit without runtime tests.\n'
              b'No old main/tests, ADB, device Stage, RF, UI or phone action in either mode.\n'
              b'Owner/Worker/receive definitions bind the real respective FC9 sources and budgets.\n'
              b'Original deadline contrast is reused; this is not device, full Owner or phone acceptance.\n'
              b'Raw facts and source snapshots stay private; public ZIP contains only result/README.\n')
    result = seal.seal_result(out, report, readme)
    print(json.dumps(dict(passed=result['report']['passed'], output=str(out),
        archive=str(result['archive']) if result['archive'] else None,
        archive_sha256=result['archive_sha256'], error=result['report']['error']), ensure_ascii=True))
    return result['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
