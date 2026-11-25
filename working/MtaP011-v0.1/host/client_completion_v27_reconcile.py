"""Reconcile one pinned HOST receipt; never rerun the passed test."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = 'results/client-completion-v27-host-boundary-20261002-053803-bd561f81'
RESULT_SHA = 'b622edcb4a6d26ba2512b5792d6167137b59c404a5d60faca417da57b9c73f5e'
STDOUT_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
STDERR_SHA = 'a20dddd05972dfb97ed5fa146de893f66955648969e0ba6996d420558162ae9c'
CHECKER = 'host/client_completion_v27_check.py'
CHECKER_SHA = '21b1253cfb5d96155da8c7e0e6792e24f43d109520f5465f9a896ba82a7838f5'


def fixed(relative, pin):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin: raise ValueError('fixed_receipt_changed')
    return raw


def main():
    if len(sys.argv) != 1: return 2
    original = json.loads(fixed(ORIGINAL + '/result.json', RESULT_SHA))
    stdout = fixed(ORIGINAL + '/stdout.raw', STDOUT_SHA)
    stderr = fixed(ORIGINAL + '/stderr.raw', STDERR_SHA)
    fixed(CHECKER, CHECKER_SHA)
    spec = importlib.util.spec_from_file_location('PC_completion_check', str(BASE / CHECKER))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)  # PC definitions only; checker.main is not called.
    rows, method = checker.verify()  # Static source pins/AST only; no subprocess/test.
    if original['schema'] != checker.KIND or original['sources'] != rows or \
            original['selected_method'] != method or original['test_sha256'] != checker.TEST_SHA or \
            original['host_exit'] != 0 or original['timeout'] is not False or \
            original['tests_run'] != 1 or original['public_raw_included'] is not False or \
            original['host_boundary_method_passed'] is not False or \
            original['stdout_sha256'] != STDOUT_SHA or original['stderr_sha256'] != STDERR_SHA or \
            not checker.standard_output(stdout, stderr):
        raise ValueError('original_receipt_not_reconcilable')
    result = dict(original)
    result.update(schema='client-completion-v27-host-reconciled',
        host_boundary_method_passed=True, public_raw_included=True,
        reconciliation_only=True, tests_run=0, new_test_invocations=0,
        host_target_definitions_executed=False, original_tests_run=1,
        original_host_target_definitions_executed=True, original_result=ORIGINAL + '/result.json',
        original_result_sha256=RESULT_SHA, checker_sha256=CHECKER_SHA,
        correction='unittest separator line omitted by original packaging parser; child exit 0 and raw OK retained')
    output = BASE / 'results' / ('client-completion-v27-reconciled-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
    note = b'PC unit boundary receipt reconciliation only. No new test, target, device or RF execution. Original child passed; packaging regex correction only. Not full lifecycle or transfer acceptance.\n'
    entries = [('result.json', encoded), ('README.txt', note), ('stdout.raw', stdout), ('stderr.raw', stderr)]
    for name, raw in entries: (output / name).write_bytes(raw)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in entries: bundle.writestr(name, raw)
    with zipfile.ZipFile(str(archive)) as bundle:
        if bundle.namelist() != [name for name, raw in entries] or bundle.testzip() is not None or \
                any(bundle.read(name) != raw for name, raw in entries):
            raise ValueError('archive_invalid')
    print(json.dumps(dict(reconciled_pass=True, new_test_invocations=0, result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())
