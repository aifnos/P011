"""One affected FileCenter close contract; default SOURCE, no ADB or radio.

The source patch is not a packaged Owner deployment. Explicit --run-linux
runs one fixed method in existing kali-linux WSL, never an old suite.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/filecenter_close_seal_v1_check.py'
CMD = 'TEST_MTA_FILECENTER_CLOSE_SEAL_V1.cmd'
TEST = 'tests/test_filecenter_close_seal_v1.py'
METHOD = 'FileCenterCloseSealV1Contract.test_actual_filecenter_original_close_seals_and_numeric_reuse'
INPUTS = (
    (TEST, 22244, '404d258705cf20f192d98016127290d9fba574cf453982776a3868144d9875b8'),
    ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_client_service_owner.py', 89599,
     'a9a5aa60d4cf5c26df46d6de88a9c79fb1df76eb88ff869f186fcf277ea7af11'),
    ('candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py', 4581,
     '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_companion.py', 25966,
     '51f212ef07e0e323cc3803cfd2583ec29867ce0bbf7daff9129ad51d4f6eeeb3'),
    ('candidate/filecenter-close-seal-v1/runtime/mta_client_service_owner.py', 90745,
     '9341ffdf01bd9927384ad78a9c824b3f7c42a29ffdbe19858b9bbba14c1826f8'),
    ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757,
     'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4'),
    ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py', 33508,
     'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069,
     'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py', 9303,
     '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114,
     'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py', 4080,
     'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045,
     'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py', 19732,
     'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082,
     '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'))
FILECENTER_INPUTS = tuple('integration/ToolboxMta-v0.1/runtime/' + name + '.py'
    for name in ('mta_toolbox_json', 'mta_toolbox_minhttp', 'mta_toolbox_storage',
                 'mta_toolbox_metrics', 'mta_toolbox_audio', 'mta_toolbox_server')) + (
    'candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py',
    'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py',
    'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py')
LINUX_COMMAND = ('wsl.exe', '-d', 'kali-linux', '--', 'python3', '-I', '-B',
    '/mnt/d/project/P011/working/MtaP011-v0.1/' + TEST, METHOD, '-v')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True: raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'record_write')
    need(path.read_bytes() == raw, 'record_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-linux', action='store_true',
        help='Run one fixed affected Linux primitive method; maximum 50 seconds.')
    args = parser.parse_args()
    mode = 'linux-contract' if args.run_linux else 'source'
    out = BASE / 'results' / ('filecenter-close-seal-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    originals = {}
    stdout = stderr = b''
    report = dict(kind='actual_filecenter_original_close_contract', mode=mode,
        passed=False, source_checked=False, source_unchanged=False,
        source_preserved=False, host_invoked=False, host_exit='NOT_RUN',
        exactly_one_method=False, timed_out=False, execution_unknown=False,
        timeout_seconds=50, skipped_not_accepted=True, old_tests_run=0,
        old_graph_run=False, adb=False, device=False, rf=False, phone=False,
        http_request=False, audio=False, full_owner_pass=False,
        runnable_deployment=False, filecenter_source_budget=131072,
        filecenter_source_bytes=None, error_code=None)
    try:
        need(type(INPUTS) is tuple and len(INPUTS) >= 7, 'inputs_not_frozen')
        for path, size, digest in INPUTS:
            raw = (BASE / path).read_bytes()
            need((len(raw), sha(raw)) == (size, digest), 'input_pin')
            originals[path] = raw
        for path in (SELF, CMD): originals[path] = (BASE / path).read_bytes()
        need(all(path in originals for path in FILECENTER_INPUTS), 'filecenter_input_closure')
        report['filecenter_source_bytes'] = sum(len(originals[path]) for path in FILECENTER_INPUTS)
        need(report['filecenter_source_bytes'] <= report['filecenter_source_budget'], 'filecenter_source_budget')
        for path, raw in originals.items():
            if path.endswith('.py'):
                ast.parse(raw, filename=path, feature_version=(3, 5))
        tree = ast.parse(originals[TEST], filename=TEST)
        methods = [(row.name, item.name) for row in tree.body if isinstance(row, ast.ClassDef)
            for item in row.body if isinstance(item, ast.FunctionDef) and item.name.startswith('test_')]
        need(methods == [('FileCenterCloseSealV1Contract', METHOD.split('.')[1])], 'one_method')
        report['source_checked'] = True
        if args.run_linux:
            report['host_invoked'] = True
            try:
                result = subprocess.run(LINUX_COMMAND, cwd=str(BASE),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=50)
                stdout, stderr = result.stdout, result.stderr
                report['host_exit'] = result.returncode
                report['exactly_one_method'] = (b'Ran 1 test in ' in stderr and
                    stderr.rstrip().endswith(b'OK') and b'skipped' not in stderr.lower())
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout if type(error.stdout) is bytes else b''
                stderr = error.stderr if type(error.stderr) is bytes else b''
                report.update(host_exit='UNKNOWN_TIMEOUT', timed_out=True,
                    execution_unknown=True, error_code='linux_timeout')
    except BaseException as error:
        allowed = ('inputs_not_frozen', 'input_pin', 'one_method', 'filecenter_input_closure',
            'filecenter_source_budget', 'record_write', 'record_readback')
        report['error_code'] = str(error) if type(error) is ValueError and str(error) in allowed else type(error).__name__
    finally:
        report['source_unchanged'] = bool(originals) and all(
            (BASE / path).read_bytes() == raw for path, raw in originals.items())
        for path, raw in originals.items(): write_new(out / 'private-inputs' / path, raw)
        report['source_preserved'] = bool(originals) and all(
            (out / 'private-inputs' / path).read_bytes() == raw for path, raw in originals.items())
        write_new(out / 'private-raw' / 'stdout.raw', stdout)
        write_new(out / 'private-raw' / 'stderr.raw', stderr)
        write_new(out / 'private-raw' / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
    report['passed'] = (report['source_checked'] is True and report['source_unchanged'] is True and
        report['source_preserved'] is True and report['error_code'] is None and
        (not args.run_linux or (type(report['host_exit']) is int and report['host_exit'] == 0 and
                               report['exactly_one_method'] is True)))
    outputs = {
        'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'source-sha256.json': (json.dumps({path: dict(bytes=len(raw), sha256=sha(raw))
            for path, raw in originals.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'Default SOURCE checks exact pinned inputs and Python 3.5 syntax, without imports or tests.\n'
            b'Explicit --run-linux runs one affected method in existing kali-linux WSL.\n'
            b'Uses actual confined Store, loopback listener and threads; no HTTP requests, audio or RF.\n'
            b'Only affected original Owner methods are extracted; unrelated Owner admission is a labelled fixture.\n'
            b'Raw streams, host exit and source copies are private and excluded from this ZIP.\n'
            b'Not a packaged deployment, complete Owner, P011, UI, restoration or phone-transfer PASS.\n')}
    for name, raw in outputs.items(): write_new(out / name, raw)
    archive = out / 'PC_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        need(bundle.testzip() is None and set(bundle.namelist()) == set(outputs) and
            all(bundle.read(name) == raw for name, raw in outputs.items()), 'zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
        zip_sha256=sha(archive.read_bytes()), host_exit=report['host_exit']), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
