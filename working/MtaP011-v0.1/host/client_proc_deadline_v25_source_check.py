"""PC static-only v25 four-source increment. No target imports or test calls."""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import sys
import types
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
OLD_PLAN = 'host/client_proc_history_v24_source_manifest.json'
OLD_PLAN_SHA = 'dcfab972fed81b1a63bafe1a8cae6a2681d2c83d3e666bf10a827c2c7b36f70e'
OLD_HELPER = 'host/client_proc_history_v24_source_check.py'
OLD_HELPER_SHA = '1f913dc2a40bcef07ae2b4d12bdfbaf40dbb03fded7916b41b5c2e413dd794f8'
NEW_ROOT = 'candidate/client-proc-deadline-v25/runtime/'
KIND = 'client-proc-deadline-v25-source-only'
REPLACEMENTS = {
    'mta_client_proc': ('ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6', 39384),
    'mta_client_baseline': ('b74696eb4fa0586b254633f667eb588634700234cc30d8b49d5453e4592782bf', 29510),
    'mta_client_wpa_status': ('47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269', 39133),
    'mta_client_linux_provider': ('ca8b7055aaa8eb4d54496286c6394bc58cf195569f9acc81fe4d4c7b6a139e5e', 131611),
}


def fixed(relative, digest, size=None):
    raw = (BASE / relative).read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest or size is not None and len(raw) != size:
        raise ValueError('fixed_source_drift')
    return raw


def verify():
    old = json.loads(fixed(OLD_PLAN, OLD_PLAN_SHA).decode('utf-8'))['sources']
    if len(old) != 29 or len({row['module'] for row in old}) != 29:
        raise ValueError('fixed_graph_shape')
    # Reuse only the frozen PC AST dependency helper, not its verify/main or
    # any target definitions. It has no import-time device/OS actions.
    helper = types.ModuleType('private_v25_pc_ast_helper')
    helper.__file__ = str(BASE / OLD_HELPER)
    exec(compile(fixed(OLD_HELPER, OLD_HELPER_SHA), helper.__file__, 'exec'), helper.__dict__)
    rows, available = [], set()
    for original in old:
        raw = fixed(original['path'], original['sha256'], original['bytes'])
        name, row = original['module'], dict(original)
        if name in REPLACEMENTS:
            digest, size = REPLACEMENTS[name]
            row.update(path=NEW_ROOT + name + '.py', sha256=digest, bytes=size)
            raw = fixed(row['path'], digest, size)
        tree = ast.parse(raw.decode('utf-8'), filename=row['path'], feature_version=(3, 5))
        if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
            raise ValueError('target_assert_forbidden')
        # The frozen helper's approved lazy-import scopes cover the changed
        # sources plus budget/files only. Do not reinterpret unchanged modules'
        # other archived lazy imports as new dependency failures.
        if name in REPLACEMENTS or name in ('mta_client_resource_budget', 'mta_client_files'):
            helper._dependencies(tree, name, available)
        available.add(name); rows.append(row)
    return rows


def main():
    if len(sys.argv) != 1:
        print('SOURCE_ONLY: no device/test/deployment mode or arguments accepted')
        return 2
    try: rows = verify()
    except (OSError, ValueError, SyntaxError, UnicodeError, TypeError, KeyError):
        print('SOURCE_ONLY_FAIL: source/syntax/dependency mismatch; no device action')
        return 1
    public = dict(schema=KIND, sources=rows, source_count=len(rows),
        source_integrity_verified=True, python35_syntax_verified=True,
        static_dependency_order_verified=False, changed_source_dependency_order_verified=True,
        previous_sources_preserved=True,
        target_code_executed=False, tests_run=False, device_accessed=False,
        rf_requested=False, formal_executor_rewired=False, restoration_verified=False,
        absolute_deadline_behavior_tested=False, all_syscall_wall_bound_verified=False,
        full_lifecycle_actual_collector_tested=False, global_proc_history_complete=False,
        payload_projection_complete=False, heap_bound_verified=False, cleanup_proved=False,
        dhcp_verified_on_device=False, ip_installed=False, endpoint_verified=False,
        send_available=False, receive_available=False, phone_tested=False)
    output = BASE / 'results' / (KIND + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        + '-' + uuid.uuid4().hex[:8])
    output.mkdir()
    encoded = (json.dumps(public, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')
    note = b'PC static source check only. No target code or test methods run. No device, RF, wall deadline, full lifecycle, heap, restoration, IP install, endpoint, send/receive or phone acceptance. HOST receipts are separate.\n'
    (output / 'result.json').write_bytes(encoded); (output / 'README.txt').write_bytes(note)
    archive = output / 'public-result.zip'
    with zipfile.ZipFile(str(archive), 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('result.json', encoded); bundle.writestr('README.txt', note)
    with zipfile.ZipFile(str(archive)) as bundle:
        if bundle.namelist() != ['result.json', 'README.txt'] or bundle.testzip() is not None or \
                bundle.read('result.json') != encoded or bundle.read('README.txt') != note:
            raise ValueError('archive_invalid')
    print(json.dumps(dict(source_only_pass=True, source_count=len(rows), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()), ensure_ascii=False))
    return 0


if __name__ == '__main__': sys.exit(main())
