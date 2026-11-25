"""Pure correction of one pinned successful schema receipt; no target/test run."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = BASE / 'results/client-session-v28-schema-20261002-062224-629c2b44'
PINS = {'result.json': '5698f4d3019b14040ee16569736790d5c367a1a98f580c9ef9c208fcd37f4ef6',
    'stdout.raw': '3b8dfe54340dfadd3ebca4bb69af5480eded8855ba7f75c8c31b72d33fe9cf7d',
    'stderr.raw': '2e6dba9605abb64ca664970b72965f985cb4c7d7b75010edfcb0994fe9157f08'}


def main():
    if len(sys.argv) != 1: return 2
    raw = {name: (ORIGINAL / name).read_bytes() for name in PINS}
    if any(hashlib.sha256(raw[name]).hexdigest() != pin for name, pin in PINS.items()):
        raise ValueError('original_changed')
    spec = importlib.util.spec_from_file_location('PC_v28_checker', str(BASE / 'host/client_session_v28_check.py'))
    checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
    rows, inputs, unused = checker.verify('schema')  # Only pinned reads and AST, never target imports.
    original = json.loads(raw['result.json'])
    if original['host_exit'] != 0 or original['timeout'] is not False or \
            original['test_sha256'] != checker.TESTS['schema'][1] or \
            original['source_manifest_sha256'] != checker.PLAN_SHA or \
            not checker.standard_output(raw['stdout.raw'], raw['stderr.raw'], 'schema', rows):
        raise ValueError('original_not_fixed_success')
    for path, value in inputs.items():
        if (ORIGINAL / 'private-inputs' / path).read_bytes() != value:
            raise ValueError('original_input_changed')
    value = dict(original)
    value.update(schema='client-session-v28-schema-reconciled', host_method_passed=True,
        host_target_method_completed=True, public_raw_included=True, original_judgment_preserved=True,
        original_host_checker_exit=1, new_test_invocations=0, current_target_definitions_executed=False,
        original_receipt_sha256=PINS['result.json'],
        current_checker_sha256=hashlib.sha256(Path(checker.__file__).read_bytes()).hexdigest())
    output = BASE / 'results' / ('client-session-v28-schema-reconciled-'
        + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode('utf-8')
    note = b'Pure original receipt correction only: fixed success marker recognized, no new test invocation or target execution. Not IP, P011, endpoint, transfer or phone acceptance. Original failed packaging judgment preserved.\n'
    (output / 'result.json').write_bytes(encoded); (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, content in [('result.json', encoded), ('README.txt', note),
                ('stdout.raw', raw['stdout.raw']), ('stderr.raw', raw['stderr.raw'])]:
            bundle.writestr(name, content)
    with zipfile.ZipFile(str(archive)) as bundle:
        if bundle.testzip() is not None or bundle.namelist() != ['result.json', 'README.txt', 'stdout.raw', 'stderr.raw']:
            raise ValueError('archive_invalid')
    print(json.dumps(dict(reconciled=True, new_test_invocations=0, result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())
