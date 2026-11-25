"""PC-only v13 source freeze verifier and sanitized result ZIP writer.

No ADB, subprocess, radio, test execution, target code import or cleanup. A
hash/AST match is source integrity, not an independent review or hardware pass.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
PLAN = BASE / 'host/platform_v13_source_manifest.json'
EXPECTED = (
    ('candidate/client-connect-v13/runtime/mta_client_control_frame.py', 'target'),
    ('candidate/client-connect-v13/runtime/mta_client_connect_handoff.py', 'target'),
    ('candidate/client-kernel-proof-v13/runtime/mta_client_kernel_proof.py', 'target'),
    ('candidate/state-platform-budget-v13/mta_service.py', 'target'),
    ('tests/test_client_control_frame_v13.py', 'test'),
    ('tests/test_client_connect_handoff_v13.py', 'test'),
    ('tests/test_client_kernel_proof_v13.py', 'test'),
    ('tests/test_state_platform_budget_v13.py', 'test'),
    ('docs/CLIENT_CONTROL_FRAME_V13_REVIEW.md', 'doc'),
    ('docs/CLIENT_CONNECT_HANDOFF_V13_REVIEW.md', 'doc'),
    ('docs/CLIENT_KERNEL_PROOF_V13_REVIEW.md', 'doc'),
    ('docs/STATE_PLATFORM_BUDGET_V13_REVIEW.md', 'doc'),
)


def verify():
    plan = json.loads(PLAN.read_text(encoding='utf-8'))
    if (type(plan) is not dict or set(plan) != {'version', 'kind', 'files'} or
            type(plan['version']) is not int or plan['version'] != 1 or
            plan['kind'] != 'platform-v13-source-only' or type(plan['files']) is not list or
            len(plan['files']) != len(EXPECTED)):
        raise ValueError('manifest_invalid')
    result = []
    for row, (relative, role) in zip(plan['files'], EXPECTED):
        if (type(row) is not dict or set(row) != {'path', 'role', 'sha256', 'bytes'} or
                row['path'] != relative or row['role'] != role or
                type(row['sha256']) is not str or len(row['sha256']) != 64 or
                any(c not in '0123456789abcdef' for c in row['sha256']) or
                type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152):
            raise ValueError('manifest_invalid')
        path = BASE / relative
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if len(raw) != row['bytes'] or digest != row['sha256']:
            raise ValueError('source_mismatch')
        if role == 'target':
            ast.parse(raw.decode('utf-8'), filename=relative, feature_version=(3, 5))
        elif role == 'test':
            ast.parse(raw.decode('utf-8'), filename=relative)
        else:
            raw.decode('utf-8')
        result.append({'path': relative, 'role': role, 'sha256': digest, 'bytes': len(raw)})
    return result


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no arguments or device mode accepted')
        return 2
    try:
        rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError):
        print('SOURCE_ONLY_FAIL: missing, changed or invalid frozen source; no device action')
        return 1
    public = {'schema': 'platform-v13-source-only', 'source_integrity_verified': True,
        'file_count': len(rows), 'files': rows,
        'tests_run': False, 'device_accessed': False, 'rf_requested': False,
        'restoration_verified': False, 'send_available': False,
        'receive_available': False, 'phone_tested': False}
    # Generated evidence files only; no source rewrite or deletion.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    output = BASE / 'results' / ('platform-v13-source-only-' + stamp + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC source integrity only. No tests, ADB, radio, cleanup, restoration or phone acceptance.\n'
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
    print(json.dumps({'source_only_pass': True, 'file_count': len(rows),
        'result_zip': str(archive), 'zip_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()},
        ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
