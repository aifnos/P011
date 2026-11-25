"""Thin affected Receive contract recorder, default SOURCE, no ADB/old graph.

Only --run-linux runs one fixed method through the existing kali-linux WSL.
Raw streams and exact source copies stay private; public ZIP excludes them.
The earlier Owner AST/diff result is pinned, not replayed here.
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
SELF = 'host/receive_socket_close_v1_contract_check.py'
CMD = 'TEST_MTA_RECEIVE_SOCKET_CLOSE_V1.cmd'
TEST = 'tests/test_formal_receive_socket_close_v1_linux.py'
METHOD = 'ReceiveSocketCloseV1Contract.test_actual_receive_original_socket_receipt_and_http_borrowers'
INPUTS = (
    (TEST, 11888, 'b1b2c6c53e3e64960ad1da552c7779f8b123caed94b0df931eda33646fb20064'),
    ('candidate/formal-receive-socket-close-v1/runtime/mta_client_service_owner.py', 78755,
     '7073b4140c62314416237428c1fdffb124407a9dab0043b9dd2f83e48e55992f'),
    ('candidate/formal-receive-socket-close-v1/runtime/minhttp.py', 9690,
     'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235'),
    ('candidate/formal-receive-alias-clock-v1/runtime/mta_client_service_owner.py', 72108,
     '6ac819c9af70fd38a69f0271e1ea11d983db261fc54f400a4d08e151cc619e6a'),
    ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_client_service_owner.py', 89599,
     'a9a5aa60d4cf5c26df46d6de88a9c79fb1df76eb88ff869f186fcf277ea7af11'),
    ('candidate/formal-send-filecenter-deploy-v5/runtime/minhttp.py', 9690,
     'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235'),
    ('tests/test_formal_socket_close_v5_linux.py', 23512,
     '550f071e8c74a77fc37ce069345856ed8a0843f80feacfd769850cef95b27bf0'),
    ('candidate/formal-receive-socket-close-v1/source-changes.diff', 11222,
     '9f4c6cf05129b20c7a20c0626f45c338292742d90d023667c457962b2287a321'),
    ('candidate/formal-receive-socket-close-v1/SOURCE-report.json', 568,
     'eaf36cc9acd95fde900adf1f9efd3512b983c5c07e599022ba65b0c6a99d9d5d'),
    ('candidate/formal-receive-socket-close-v1/SOURCE-PINS.json', 2955,
     '0364180b284de43c3bdb0a4bf3ac2e580602b79674546d61bb05b524218bd8eb'))
LINUX_COMMAND = ('wsl.exe', '-d', 'kali-linux', '--', 'python3', '-I', '-B',
    '/mnt/d/project/P011/working/MtaP011-v0.1/' + TEST, METHOD, '-v')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True: raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'record_write')
    need(path.read_bytes() == raw, 'record_readback')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-linux', action='store_true', help='One fixed affected method, kali-linux WSL only; timeout 60s.')
    args = parser.parse_args()
    mode = 'linux-contract' if args.run_linux else 'source'
    out = BASE / 'results' / ('receive-socket-close-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    originals = {}
    stdout = stderr = b''
    report = dict(kind='one_affected_actual_receive_socket_contract', mode=mode, passed=False,
        source_checked=False, source_unchanged=False, source_preserved=False,
        owner_source_graph_replayed=False, owner_ast_diff_replayed=False,
        host_invoked=False, host_exit='NOT_RUN', timed_out=False, execution_unknown=False,
        exactly_one_method=False, skipped_not_accepted=True, timeout_seconds=60,
        old_tests_run=0, original_minhttp_retested=False, adb=False, device=False,
        rf=False, phone=False, runnable_graph=False, full_owner_pass=False,
        ui_pass=False, error_code=None)
    try:
        for path, size, digest in INPUTS:
            raw = (BASE / path).read_bytes()
            need((len(raw), sha(raw)) == (size, digest), 'input_pin')
            originals[path] = raw
        for path in (SELF, CMD):
            originals[path] = (BASE / path).read_bytes()
        # Syntax only, no imports of test/Owner/old graph or old test execution.
        ast.parse(originals[SELF], filename=SELF, feature_version=(3, 5))
        test_tree = ast.parse(originals[TEST], filename=TEST, feature_version=(3, 5))
        tests = [(value.name, row.name) for value in test_tree.body if isinstance(value, ast.ClassDef)
                 for row in value.body if isinstance(row, ast.FunctionDef) and row.name.startswith('test_')]
        need(tests == [('ReceiveSocketCloseV1Contract', METHOD.split('.')[1])], 'one_method')
        source_report = json.loads(originals['candidate/formal-receive-socket-close-v1/SOURCE-report.json'])
        need(source_report.get('source_only') is True and source_report.get('passed') is True and
             source_report.get('runnable_graph') is False, 'source_receipt')
        report['source_checked'] = True
        if args.run_linux:
            report['host_invoked'] = True
            try:
                value = subprocess.run(LINUX_COMMAND, cwd=str(BASE),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                stdout, stderr = value.stdout, value.stderr
                report['host_exit'] = value.returncode
                report['exactly_one_method'] = (b'Ran 1 test in ' in stderr and
                    stderr.rstrip().endswith(b'OK') and b'skipped' not in stderr.lower())
            except subprocess.TimeoutExpired as error:
                stdout = error.stdout if type(error.stdout) is bytes else b''
                stderr = error.stderr if type(error.stderr) is bytes else b''
                report.update(host_exit='UNKNOWN_TIMEOUT', timed_out=True, execution_unknown=True,
                              error_code='linux_timeout')
    except BaseException as error:
        report['error_code'] = str(error) if type(error) is ValueError and str(error) in (
            'input_pin', 'one_method', 'source_receipt', 'record_write', 'record_readback') else type(error).__name__
    finally:
        report['source_unchanged'] = bool(originals) and all((BASE / path).read_bytes() == raw for path, raw in originals.items())
        for path, raw in originals.items():
            write_new(out / 'private-inputs' / path, raw)
        report['source_preserved'] = all((out / 'private-inputs' / path).read_bytes() == raw for path, raw in originals.items())
        write_new(out / 'private-raw' / 'stdout.raw', stdout)
        write_new(out / 'private-raw' / 'stderr.raw', stderr)
        write_new(out / 'private-raw' / 'host-exit.raw', (str(report['host_exit']) + '\n').encode('ascii'))
    report['passed'] = (report['source_checked'] is True and report['source_unchanged'] is True and
        report['source_preserved'] is True and report['error_code'] is None and
        (not args.run_linux or (type(report['host_exit']) is int and report['host_exit'] == 0 and
                               report['exactly_one_method'] is True)))
    outputs = {'result.json': (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'source-sha256.json': (json.dumps({path: dict(bytes=len(raw), sha256=sha(raw))
            for path, raw in originals.items()}, sort_keys=True, indent=2) + '\n').encode('ascii'),
        'README.txt': (b'Default SOURCE checks new driver/test syntax and exact source pins only.\n'
            b'Explicit --run-linux runs one fixed actual Receive contract in existing kali-linux WSL, maximum 60s.\n'
            b'Original stdout/stderr, host exit and source bytes remain in private-raw/private-inputs; excluded from this ZIP.\n'
            b'No old graph or tests replay, minhttp retest, ADB, device, RF, UI or phone operation.\n'
            b'Linux contract is not complete Owner/Trial/Session/UI/P011 acceptance; source patch is not runnable deployment.\n')}
    for name, raw in outputs.items():
        write_new(out / name, raw)
    archive = out / 'PC_RESULTS.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in outputs.items(): bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        need(bundle.testzip() is None and all(bundle.read(name) == raw for name, raw in outputs.items()), 'zip_readback')
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out),
        zip_sha256=sha(archive.read_bytes()), host_exit=report['host_exit']), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
