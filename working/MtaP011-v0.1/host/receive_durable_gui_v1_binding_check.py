"""Read back the one actual PC bundle and its fixed validator binding; no IO on P011."""
import ast
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import traceback
import uuid

BASE = Path(__file__).resolve().parents[1]
DELTA = ('candidate/formal-receive-durable-state-gui-v1/actual-binding-delta.json',
    3759, '1e709ed194e8b4e24e098bd204961532cb8cf9e7a4dd355f82a6eb923edf6bc9')
CHECKER = ('host/receive_durable_gui_v1_pc_check.py',
    11583, '6e77ef506e409ffc057e53dc6bbe8c242e24180a934755cbaf73855f4da9ae4b')
BUNDLE = 'out/mta-ui-receive-durable-state-gui-v1-559c72ccf8f8ff1b7fc83fb6'
BUILD = (BUNDLE + '/build-result.json', 8700,
    '588f0d0b8acaeebe93d2884b20c051b35e56539cb76b90ae1d92e4542d020c18')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fresh(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short_write')
    need(path.read_bytes() == raw, 'artifact_readback')


def artifacts():
    path = BASE / 'host/host_artifact_seal_v1.py'
    spec = importlib.util.spec_from_file_location('fixed_host_artifact_seal_v1', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    need(sys.argv[1:] == [] and sys.platform == 'win32' and
         BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'), 'fixed_pc_only')
    out = BASE / 'results' / ('receive-durable-gui-v1-binding-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    originals, facts, error = {}, {}, None
    helper = artifacts()
    evidence = helper.InputEvidence(originals)

    def read(pin):
        path, size, sha = pin
        return evidence.read(BASE / path, key=path, pin=(size, sha))

    try:
        evidence.read(Path(__file__), key='host/receive_durable_gui_v1_binding_check.py')
        evidence.read(BASE / 'host/host_artifact_seal_v1.py', key='host/host_artifact_seal_v1.py')
        spec = json.loads(read(DELTA))
        need(spec['schema'] == 'p011-receive-durable-gui-v1-actual-binding' and
             spec['bundle'] == BUNDLE and len(spec['replacements']) == 4 and
             spec['device_executed'] is False and spec['worker_connected'] is False, 'binding_shape')
        before, after = read(spec['source']), read(spec['candidate'])
        forward = before
        for row in spec['replacements']:
            left, right = row['before'].encode('utf-8'), row['after'].encode('utf-8')
            need(row['count'] == 1 and forward.count(left) == 1, 'forward_count')
            forward = forward.replace(left, right)
        need(forward == after, 'forward_bytes')
        reverse = after
        for row in reversed(spec['replacements']):
            left, right = row['before'].encode('utf-8'), row['after'].encode('utf-8')
            need(reverse.count(right) == 1, 'inverse_count')
            reverse = reverse.replace(right, left)
        need(reverse == before, 'inverse_bytes')
        def definitions(raw):
            return [ast.dump(node, include_attributes=False) for node in
                    ast.parse(raw.decode('utf-8'), feature_version=(3, 5)).body
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
        need(definitions(before) == definitions(after), 'validator_logic_changed')
        table = {node.targets[0].id: ast.literal_eval(node.value) for node in
                 ast.parse(after.decode('utf-8'), feature_version=(3, 5)).body
                 if isinstance(node, ast.Assign) and len(node.targets) == 1 and
                 isinstance(node.targets[0], ast.Name) and
                 node.targets[0].id in ('SESSION', 'MANIFEST_PIN', 'PINS')}
        need(table['SESSION'] == '559c72ccf8f8ff1b7fc83fb6', 'bound_session')
        checker = read(CHECKER)
        scope = dict(__name__='fixed_pc_bundle_readback', __file__=str(BASE / CHECKER[0]))
        exec(compile(checker, str(BASE / CHECKER[0]), 'exec'), scope)
        build = json.loads(read(BUILD))
        files, path = scope['bundle_readback'](build, evidence, lambda node: node.relative_to(BASE).as_posix())
        actual_pins = tuple((name, len(raw), digest(raw)) for name, raw in sorted(files.items())
                            if name != 'SOURCE.sha256')
        need(table['PINS'] == actual_pins and table['MANIFEST_PIN'] ==
             (len(files['SOURCE.sha256']), digest(files['SOURCE.sha256'])), 'actual_bound_pins')
        evidence.snapshot(out, lambda name: name)
        need(all((BASE / name).read_bytes() == raw for name, raw in originals.items()), 'input_changed')
        facts.update(forward_inverse_verified=True, validator_logic_unchanged=True,
            actual_20_files_verified=True, actual_manifest_bound=True, source_preserved=True,
            stage_bytes=sum(len(raw) for raw in files.values()))
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        exception = traceback.format_exc().encode('utf-8')
    try:
        evidence.snapshot(out, lambda name: name)
        if 'exception' in locals():
            fresh(out / 'private-raw/checker-exception.txt', exception)
    except BaseException as failure:
        error = (error + ';' if error else '') + 'evidence_failed:' + type(failure).__name__ + ':' + str(failure)
    passed = error is None
    report = dict(schema='p011-receive-durable-gui-v1-binding-check', passed=passed,
        host_exit=0 if passed else 1, remote_exit='NOT_RUN_PC_ONLY', error=error,
        evidence_level='PC_SOURCE_AND_BUNDLE_READBACK_ONLY', facts=facts,
        validator_bound=passed, validator_device_executed=False, worker_connected=False,
        device=False, rf=False, phone=False, deployed=False, restoration_verified=False,
        business_tests_replayed=0,
        inputs=[dict(path=name, bytes=len(raw), sha256=digest(raw), complete=name not in evidence.partial)
            for name, raw in originals.items()])
    readme = (b'Actual PC-built GUI20 and validator binding readback only.\n'
                      b'No validator execution, P011/device/RF/phone/worker/deployment/restoration acceptance.\n'
                      b'Private source snapshots are excluded. Unchanged business tests were not replayed.\n')
    sealed = helper.seal_result(out, report, readme)
    report = sealed['report']
    print(json.dumps(dict(passed=report['passed'], error=report['error'], result=str(out / 'result.json'),
        zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
