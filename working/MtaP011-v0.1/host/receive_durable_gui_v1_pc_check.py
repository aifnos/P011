"""Fixed PC SOURCE or explicit fresh GUI build; save private streams/public ZIP.

No device, Qt process, RF, credentials or worker is started. Historical builders
are used as pinned pure definitions only; unchanged runtime tests are not replayed.
"""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import traceback
import uuid

BASE = Path(__file__).resolve().parents[1]
BUILDER = 'host/build_formal_receive_durable_state_gui_v1.py'
BUILDER_PIN = (28199, 'd4664732e7255b071e211eb4d3536846be66df510038fb1e2b87732cc15d37cc')
DELTA = 'candidate/formal-receive-durable-state-gui-v1/exactsource-delta.json'
DELTA_PIN = (19009, '139a52695d8935308331ca6df62246f10ff6bbfb104f8e6a0cabb473384951bf')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


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


def input_label(path):
    return (path.relative_to(BASE) if path.is_relative_to(BASE) else
            Path('project') / path.relative_to(BASE.parents[1])).as_posix()


def inputs(originals, evidence):

    def add(path, pin=None):
        path = Path(path)
        return evidence.read(path, pin=pin)

    raw = add(BASE / BUILDER, BUILDER_PIN)
    scope = dict(__name__='fixed_durable_gui_definitions', __file__=str(BASE / BUILDER))
    exec(compile(raw, str(BASE / BUILDER), 'exec'), scope)
    add(scope['DONOR'], scope['DONOR_PIN'])
    donor_raw = scope['bootstrap_source']()
    donor = scope['donor_definitions'](donor_raw)
    spec = json.loads(add(BASE / DELTA, DELTA_PIN))
    need(spec['schema'] == 'p011-formal-receive-durable-state-gui-source-delta-v1' and
         len(spec['groups']) == 3, 'delta_shape')
    for key in ('sources', 'candidates', 'bindings'):
        for path, size, sha in spec[key]:
            add(BASE / path, (size, sha))
    for group in spec['groups']:
        source = originals[BASE / spec['sources'][group['source']][0]]
        candidate = originals[BASE / spec['candidates'][group['candidate']][0]]
        forward = source
        for row in group['replacements']:
            before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
            need(type(row['count']) is int and row['count'] > 0 and
                 forward.count(before) == row['count'], 'forward_count')
            forward = forward.replace(before, after)
        need(forward == candidate, 'forward_bytes')
        inverse = candidate
        for row in reversed(group['replacements']):
            before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
            need(inverse.count(after) == row['count'], 'inverse_count')
            inverse = inverse.replace(after, before)
        need(inverse == source, 'inverse_bytes')
    add(donor['ALGORITHMS'], donor['ALGORITHMS_PIN'])
    add(donor['ORIGINAL'], donor['ORIGINAL_PIN'])
    add(donor['HELPER'], donor['HELPER_PIN'])
    add(donor['BRIDGE'], donor['BRIDGE_PIN'])
    for row in donor['SOURCE_PINS'] + scope['NAVIGATION_PINS'] + (scope['DURABLE_PIN'],):
        add(BASE / row[1], row[2:])
    stage = json.loads(originals[scope['OLD_BUNDLE'] / 'stage-manifest.json'])
    for row in stage['files']:
        add(scope['OLD_BUNDLE'] / row['path'], (row['bytes'], row['sha256']))
    return originals


def bundle_readback(report, evidence=None, label=None):
    def read(path):
        return (path.read_bytes() if evidence is None else
                evidence.read(path, key=label(path) if label is not None else path))

    session = report['session']
    need(re.fullmatch(r'[0-9a-f]{24}', session) is not None, 'session')
    path = BASE / 'out' / ('mta-ui-receive-durable-state-gui-v1-' + session)
    need(Path(report['bundle']) == path and path.resolve() == path, 'bundle_path')
    stage = json.loads(read(path / 'stage-manifest.json'))
    need(stage['schema'] == 'p011-formal-receive-durable-state-gui-v1-stage' and
         stage['session'] == session and len(stage['files']) == 20 and
         stage['payload_file_count'] == 19 and stage['staged_file_count'] == 20 and
         stage['directories'] == [dict(path=name, mode='0700') for name in ('', 'mta', 'toolbox')],
         'bundle_shape')
    files = {}
    for row in stage['files']:
        name = row['path']
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]{1,128}', name) is not None and
             not Path(name).is_absolute() and '..' not in Path(name).parts and name not in files,
             'bundle_filename')
        raw = read(path / name)
        need((len(raw), digest(raw)) == (row['bytes'], row['sha256']) and
             row['mode'] == ('0500' if name == 'Z03.mta-ui-candidate' else '0400'), 'bundle_pin')
        files[name] = raw
    expected = ''.join(digest(raw) + ' ' + str(len(raw)) + ' ' + name + '\n'
                       for name, raw in sorted(files.items()) if name != 'SOURCE.sha256').encode('ascii')
    need(files['SOURCE.sha256'] == expected and len(expected) == 1691 and
         sum(len(raw) for raw in files.values()) == 4192479 and
         report['candidate_sha256'] == digest(files['Z03.mta-ui-candidate']) and
         report['source_manifest_sha256'] == digest(expected), 'bundle_manifest')
    for relative in ('', 'mta', 'toolbox'):
        root = path if not relative else path / relative
        wanted = {Path(name).name for name in files if
                  ('' if str(Path(name).parent) == '.' else Path(name).parent.as_posix()) == relative}
        if not relative:
            wanted.update(('mta', 'toolbox', 'NaviPanel.embedded.qml', 'stage-manifest.json', 'build-result.json'))
        need({node.name for node in root.iterdir()} == wanted, 'bundle_inventory')
        need(all(not node.is_symlink() for node in root.iterdir()), 'bundle_link')
    built = json.loads(read(path / 'build-result.json'))
    need(built == report, 'bundle_report_readback')
    return files, path


def main():
    need(sys.argv[1:] in ([], ['--build']), 'fixed_source_or_build')
    need(BASE == Path(r'D:\project\P011\working\MtaP011-v0.1') and sys.platform == 'win32',
         'development_pc_only')
    build = sys.argv[1:] == ['--build']
    out = BASE / 'results' / ('receive-durable-gui-v1-' + ('build-' if build else 'source-') +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    originals, checked, bundle, files = {}, None, None, {}
    helper = artifacts()
    evidence = helper.InputEvidence(originals)
    stdout, stderr, error = b'', b'', None
    child_exit, timeout, unchanged, inputs_verified = None, False, False, False
    try:
        evidence.read(Path(__file__))
        evidence.read(BASE / 'host/host_artifact_seal_v1.py')
        inputs(originals, evidence)
        inputs_verified = True
        evidence.snapshot(out, input_label)
        child = subprocess.run([sys.executable, '-I', '-B', str(BASE / BUILDER)] + sys.argv[1:],
            cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        child_exit, stdout, stderr = child.returncode, child.stdout, child.stderr
        need(child_exit == 0 and stderr == b'', 'builder_failed')
        body = stdout.decode('ascii')
        if build:
            body, tail = body.rsplit('BUNDLE=', 1)
        checked = json.loads(body)
        need(checked['builder_sha256'] == BUILDER_PIN[1] and checked['planned_stage_bytes'] == 4192479 and
             checked['source_text_bytes'] == 86837 and checked['staged_file_count'] == 20 and
             checked['device_executed'] is False and checked['radio_executed'] is False and
             checked['old_suite_executed'] is False and checked['validator_connected'] is False,
             'builder_report')
        if build:
            files, bundle = bundle_readback(checked, evidence)
            need(tail.strip() == str(bundle), 'bundle_output')
        else:
            need(checked['session_created'] is False and checked['bundle_created'] is False and
                 checked['future_session'] is None, 'source_only')
        unchanged = all(path.read_bytes() == raw for path, raw in originals.items())
        need(unchanged, 'input_changed')
    except subprocess.TimeoutExpired as failure:
        timeout, stdout, stderr = True, failure.stdout or b'', failure.stderr or b''
        error = 'builder_timeout'
    except BaseException as failure:
        error = type(failure).__name__ + ':' + str(failure)
        exception = traceback.format_exc().encode('utf-8')
    try:
        evidence.snapshot(out, input_label)
        if 'exception' in locals():
            fresh(out / 'private-raw/checker-exception.txt', exception)
        fresh(out / 'private-raw/stdout.raw', stdout)
        fresh(out / 'private-raw/stderr.raw', stderr)
    except BaseException as failure:
        error = (error + ';' if error else '') + 'evidence_failed:' + type(failure).__name__ + ':' + str(failure)
    passed = error is None and unchanged and child_exit == 0 and not timeout
    report = dict(schema='p011-receive-durable-gui-v1-pc-check', passed=passed,
        mode='PC_BUILD' if build else 'SOURCE', error=error, child_exit=child_exit,
        host_exit=0 if passed else 1, remote_exit='NOT_RUN_PC_ONLY', timeout=timeout,
        child_invocations=1 if child_exit is not None or timeout else 0,
        business_tests_replayed=0, source_preserved=unchanged,
        forward_inverse_groups_verified=3 if inputs_verified else 0,
        actual_bundle_readback=bool(passed and build), validator_bound=False,
        bundle_session=checked.get('session') if checked else None,
        stage_bytes=4192479 if passed else None, stage_remaining_bytes=1825 if passed else None,
        stage_files=20 if passed else None, stage_directories=3 if passed else None,
        device=False, rf=False, phone=False, deployed=False, full_graph=False, restoration_verified=False,
        inputs=[dict(path=input_label(path), bytes=len(raw), sha256=digest(raw), complete=path not in evidence.partial)
            for path, raw in originals.items()],
        bundle_files=[dict(path=name, bytes=len(raw), sha256=digest(raw)) for name, raw in sorted(files.items())])
    readme = (b'PC SOURCE or explicit fresh GUI build only. No device/RF/phone/worker/credentials.\n'
                      b'Unchanged business tests were not replayed. Raw streams and source inputs are private.\n'
                      b'The runtime validator remains unbound; build is not deployment or mobile acceptance.\n')
    sealed = helper.seal_result(out, report, readme)
    report = sealed['report']
    print(json.dumps(dict(passed=report['passed'], mode=report['mode'], child_exit=child_exit,
        error=report['error'], result=str(out / 'result.json'),
        zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256'], bundle=str(bundle) if bundle else None), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
