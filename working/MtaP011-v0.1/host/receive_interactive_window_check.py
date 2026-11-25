"""Fixed new HOST receive-window method; private raw and complete child exit."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
TEST = 'tests/test_receive_interactive_window.py'
RUNNER = 'candidate/receive-interactive-v1/runtime/mta_formal_receive_session.py'
UI = 'candidate/receive-interactive-v1/runtime/ui_session.py'
INPUTS = (TEST, RUNNER, UI,
    'candidate/formal-receive-v3/runtime/ui_session.py',
    'candidate/formal-receive-v3/runtime/mta_client_service_owner.py',
    'candidate/formal-receive-v3/runtime/mta_service.py',
    'candidate/formal-receive-v3/runtime/mta_client_receive_factory.py',
    'candidate/go-send-state-v78/runtime/mta_transfer_session.py',
    'host/receive_interactive_window_check.py', 'HOST_MTA_RECEIVE_INTERACTIVE_WINDOW_CHECK.cmd')
AST_METHODS = {'runner': ('__init__', 'window_current', 'check'),
               'ui': ('_receive_interactive_window', '_receive_interactive_originals', '_receive_interactive_expired')}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short_write')


def source_ast_hashes(raw_runner, raw_ui):
    result = {}
    for role, raw in (('runner', raw_runner), ('ui', raw_ui)):
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        if role == 'runner':
            tree = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'FixedSession')
        for name in AST_METHODS[role]:
            node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
            result[role + '.' + name] = digest(ast.dump(node, include_attributes=False).encode('utf-8'))
    return result


def main():
    if sys.argv[1:]:
        raise ValueError('fixed HOST method only; no device mode')
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8]
    out = BASE / 'results' / ('receive-interactive-window-host-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    report = dict(schema='p011-receive-interactive-window-host-v1', passed=False,
        child_exit=None, child_exit_retained=False, child_timeout=False,
        checker_exit_retained=False, error=None, new_methods_invoked=1, old_methods_invoked=0,
        device_tested=False, qt_tested=False, rf_tested=False, phone_tested=False,
        network_restoration_verified=False, original_resource_closure_verified=False,
        pending_handled=False, source_preserved=False,
        evidence_level='HOST_EXTRACTED_NEW_METHODS_AND_EXPLICIT_CLOCK_OWNER_MODELS')
    originals = {}
    stdout = stderr = b''
    invoked = False
    try:
        inventory = {}
        for name in INPUTS:
            raw = (BASE / name).read_bytes()
            originals[name] = raw
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json', (json.dumps(inventory, indent=2, sort_keys=True) + '\n').encode('ascii'))
        expected_ast = source_ast_hashes(originals[RUNNER], originals[UI])
        try:
            invoked = True
            process = subprocess.Popen([sys.executable, '-I', '-B', str(BASE / TEST)],
                cwd=str(BASE), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=35)
            except subprocess.TimeoutExpired:
                report['child_timeout'] = True
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
            report['child_exit'] = process.returncode
            report['child_exit_retained'] = type(process.returncode) is int
        except Exception as error:
            report['error'] = 'new_child_' + type(error).__name__
        for name, raw in (('stdout', stdout), ('stderr', stderr)):
            save(out / (name + '.raw'), raw)
            report[name + '_bytes'] = len(raw)
            report[name + '_sha256'] = digest(raw)
        save(out / 'child-exit.raw', (str(report['child_exit']) + '\n').encode('ascii'))
        report['source_count'] = len(originals)
        report['source_preserved'] = all((BASE / name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in originals.items())
        domain_markers = re.findall(rb'^RECEIVE_INTERACTIVE_WINDOW_DOMAINS=([0-9]+)\r?$', stdout, re.M)
        method_markers = re.findall(rb'^NEW_METHODS_EXECUTED=([0-9]+)\r?$', stdout, re.M)
        report['contract_domains'] = int(domain_markers[0]) if len(domain_markers) == 1 else 0
        report['new_methods_completed'] = int(method_markers[0]) if len(method_markers) == 1 else 0
        observed_ast = re.findall(rb'^TESTED_AST ([a-z._]+)=([0-9a-f]{64})\r?$', stdout, re.M)
        actual_ast = {name.decode('ascii'): value.decode('ascii') for name, value in observed_ast}
        report['tested_ast_hashes'] = actual_ast
        report['tested_ast_matches_snapshots'] = (len(observed_ast) == len(expected_ast) and actual_ast == expected_ast)
        report['passed'] = (report['child_exit'] == 0 and report['child_exit_retained'] and
            not report['child_timeout'] and report['error'] is None and report['source_preserved'] and
            report['contract_domains'] == 16 and report['new_methods_completed'] == 1 and
            report['tested_ast_matches_snapshots'] and
            re.search(rb'^Ran 1 test in [0-9.]+s\r?$', stderr, re.M) is not None and
            re.search(rb'^OK\r?$', stderr, re.M) is not None)
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    report['new_methods_invoked'] = 1 if invoked else 0
    public = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'One new HOST method for the fixed original receive window. '
        b'Actual new runner constructor/window/check and UI pure guards are extracted. '
        b'Clock, Owner, Loader, Gate, State and Directory are explicit HOST models. '
        b'The 600-second service cap is issued once before startup; READY does not renew it. '
        b'Original Session 300s, Factory 120s, Owner cleanup 60s and guardian budgets are not raised. '
        b'No full platform graph, Qt, ADB, RF, phone, pending handling or original resource closure/restore proof. '
        b'Raw stdout/stderr, child exit and source snapshots stay private. '
        b'Checker outer exit is observed separately by the invoking terminal; it is not backfilled here.\n')
    save(out / 'result.json', public)
    save(out / 'README.txt', note)
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', public)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or \
                archive.read('result.json') != public or archive.read('README.txt') != note:
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], child_exit=report['child_exit'],
        result_dir=str(out), result_zip=str(bundle), zip_bytes=bundle.stat().st_size,
        zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
