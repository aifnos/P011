"""PC-only fixed v19 graph; no target execution, tests, ADB or RF.

Reuse the exact reviewed v15 verifier in a private helper namespace. Only its
fixed graph paths and plan/kind are changed; target modules are parsed, not
imported. This is not a deployment or network restoration approval.
"""
import datetime
import hashlib
import json
from pathlib import Path
import sys
import types
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = BASE / 'host/client_durable_connect_v19_source_manifest.json'
KIND = 'client-durable-connect-v19-source-only'
SHARED_SHA = 'd0f9bbcfa29b6fad218a75dec393777e9ca966267899f582bdac9632f45bfadf'
REPLACEMENTS = {
    'mta_p2p_client_init': 'candidate/client-durable-association-v18/runtime/mta_p2p_client_init.py',
    'mta_client_journal_codec': 'candidate/client-durable-association-v18/runtime/mta_client_journal_codec.py',
    'mta_client_store': 'candidate/client-durable-association-v18/runtime/mta_client_store.py',
    'mta_client_kernel_proof': 'candidate/client-association-v16/runtime/mta_client_kernel_proof.py',
    'mta_client_connection': 'candidate/client-durable-connect-v19/runtime/mta_client_connection.py',
    'mta_client_linux_provider': 'candidate/client-durable-connect-v19/runtime/mta_client_linux_provider.py',
    'mta_client_executor': 'candidate/client-durable-connect-v19/runtime/mta_client_executor.py'}


def private_checker():
    path = BASE / 'host/client_kernel_connect_v15_source_check.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHARED_SHA:
        raise ValueError('shared_checker_changed')
    module = types.ModuleType('private_v19_static_verifier')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    original_expected = module.expected
    def fixed_expected(scope):
        old = original_expected(scope)
        if len(old) != 24 or set(REPLACEMENTS) - {name for name, unused in old}:
            raise ValueError('graph_invalid')
        return tuple((name, REPLACEMENTS.get(name, relative)) for name, relative in old)
    module.PLAN, module.KIND, module.expected = PLAN, KIND, fixed_expected
    return module


def verify():
    # The shared verify reads the complete plan and exactly those pinned bytes.
    return private_checker().verify()


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments or device mode accepted')
        return 2
    try:
        rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError):
        print('SOURCE_ONLY_FAIL: fixed source, syntax or static graph mismatch; no device action')
        return 1
    public = {'schema': KIND, 'source_integrity_verified': True,
        'python35_syntax_verified': True, 'static_dependency_order_verified': True,
        'executor_modules_match': True, 'source_count': len(rows), 'sources': rows,
        'shared_v15_checker_sha256': SHARED_SHA,
        'target_code_executed': False, 'tests_run': False, 'device_accessed': False,
        'rf_requested': False, 'restoration_verified': False,
        'durable_association_verified_on_device': False,
        'deferred_import_call_timing_verified': False,
        'send_available': False, 'receive_available': False, 'phone_tested': False}
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / (KIND + '-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static graph only. No target imports/tests, ADB, RF or phone acceptance.\n'
    (output / 'result.json').write_bytes(encoded)
    (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded)
        bundle.writestr('README.txt', note)
    with zipfile.ZipFile(str(archive), 'r') as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None:
            raise ValueError('archive_invalid')
        if bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps({'source_only_pass': True, 'source_count': len(rows),
        'result_zip': str(archive), 'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()},
        ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
