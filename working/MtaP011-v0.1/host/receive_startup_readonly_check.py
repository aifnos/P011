"""New startup-only SOURCE graph and two narrow HOST methods; no device IO."""
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
CANDIDATE = 'candidate/receive-startup-readonly-v1/runtime/'
OLD_PRIVATE = 'host/client_receive_directory_auth_clock_v2_private_source_manifest.json'
PRIVATE = 'host/client_receive_startup_readonly_v1_private_source_manifest.json'
DEFINITIONS = 'host/client_receive_startup_readonly_v1_definition_manifest.json'
TABLE_PINS = {
    OLD_PRIVATE: (8144, 'bbd5362d9d8ca5598b504a6ba3cbd4cf56f92af2f714d34b806c4e660f342941'),
    PRIVATE: (8140, 'cbd574b76f9027d4c616dd5e514c8bad2d5d88201a561429f227c2773564066f'),
    DEFINITIONS: (6972, '7e1f69048ed9645f9bf02cfe001f2642155ce64b04ca976d11d85786bb65a06a'),
}
TESTS = (
    ('tests/test_receive_startup_importer.py', 19271,
     'dd7eba5713d839359b5bbd3b165ebbbcbf8323e9ccbcfe9a657f43c442b6dfae',
     b'HOST_RECEIVE_STARTUP_IMPORTER new_methods=1 cases=6 private_modules=35 '
     b'old_methods=0 live_io_calls=0 host=true device=false phone=false rf=false\n'),
    ('tests/test_receive_startup_collector.py', 15732, '51ca05caa9132626803a6b7f60fd42feb42e0c365ac5194135d3909d36f7d615',
     b'HOST_RECEIVE_STARTUP_COLLECTOR new_methods=1 cases=3 actual_pure_constructors=true '
     b'close_control_model=true old_methods=0 device=false phone=false rf=false\n'),
)
NEW_ROLES = ('mta_client_executor', 'mta_client_startup_readonly',
             'mta_client_receive_factory', 'mta_client_state_bridge',
             'mta_client_receive_boot', 'mta_client_service_owner')


def _path(value):
    return type(value) is str and not value.startswith('/') and ':' not in value and '\\' not in value and \
        all(p not in ('', '.', '..') for p in value.split('/'))


def _read(path, size, sha):
    if not _path(path) or type(size) is not int or size < 1 or \
            type(sha) is not str or re.fullmatch('[0-9a-f]{64}', sha) is None:
        raise ValueError('fixed_input_shape')
    raw = (BASE / path).read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('fixed_input_changed:' + path)
    return raw


def _table(raw, count):
    value = json.loads(raw.decode('utf-8'))
    rows = value['sources']
    if type(rows) is not list or len(rows) != count or len({r['module'] for r in rows}) != count or \
            any(type(r) is not dict or set(r) != {'module', 'path', 'bytes', 'sha256'} for r in rows):
        raise ValueError('fixed_table_shape')
    return value


def _literal(node, context):
    # Only inert assignment literals/names/+; never execute deployment code.
    if isinstance(node, ast.Constant): return node.value
    if isinstance(node, ast.Name): return context[node.id]
    if isinstance(node, ast.Tuple): return tuple(_literal(v, context) for v in node.elts)
    if isinstance(node, ast.List): return [_literal(v, context) for v in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _literal(node.left, context) + _literal(node.right, context)
    raise ValueError('nonliteral_source_constant')


def _constants(tree):
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try: result[node.targets[0].id] = _literal(node.value, result)
            except (KeyError, ValueError): pass
    return result


def main():
    if len(sys.argv) != 1 or sys.version_info[:2] != (3, 12):
        raise ValueError('fixed_HOST_python312_no_arguments_required')
    originals = {path: _read(path, *pin) for path, pin in TABLE_PINS.items()}
    old = _table(originals[OLD_PRIVATE], 35)
    private = _table(originals[PRIVATE], 35)
    definitions = _table(originals[DEFINITIONS], 31)
    if private['previous_manifest_sha256'] != TABLE_PINS[OLD_PRIVATE][1] or \
            private['schema'] != old['schema'] or definitions['schema'] != 'client-receive-directory-v1-definitions':
        raise ValueError('source_lineage')
    for before, after in zip(old['sources'], private['sources']):
        if before['module'] != after['module'] or before['module'] != 'mta_client_executor' and before != after:
            raise ValueError('unrelated_private_role_changed')
    for row in private['sources'] + definitions['sources']:
        raw = _read(row['path'], row['bytes'], row['sha256'])
        if row['path'] in originals and originals[row['path']] != raw:
            raise ValueError('source_path_alias')
        originals[row['path']] = raw
    for path, size, pin, unused in TESTS:
        originals[path] = _read(path, size, pin)
    for path in ('host/receive_startup_readonly_check.py', 'HOST_MTA_RECEIVE_STARTUP_READONLY_CHECK.cmd'):
        originals[path] = (BASE / path).read_bytes()
    # Only these six independent new runtime sources receive the Python 3.5
    # parse check. Passed historical definitions/tests are not replayed.
    trees = {name: ast.parse(originals[CANDIDATE + name + '.py'].decode('utf-8'),
                            filename=CANDIDATE + name + '.py', feature_version=(3, 5))
             for name in NEW_ROLES}
    boot, factory, owner, bridge = (_constants(trees[n]) for n in
        ('mta_client_receive_boot', 'mta_client_receive_factory', 'mta_client_service_owner', 'mta_client_state_bridge'))
    ordinary = tuple((r['module'], r['bytes'], r['sha256']) for r in definitions['sources'][:-2])
    private_pins = tuple((r['module'], r['bytes'], r['sha256']) for r in private['sources'])
    f_sha = private['sources'][24]['sha256']
    boot_raw = originals[CANDIDATE + 'mta_client_receive_boot.py']
    root, physical = '/tmp/p011-mta-state-startup-v1', '/var/volatile/tmp/p011-mta-state-startup-v1'
    if (len(ordinary) != 29 or boot['SOURCE_PINS'] != ordinary or factory['SOURCE_PINS'] != private_pins or
            owner['BOOT_MODULES'] != tuple(r[0] for r in ordinary) or
            factory['SOURCE_MANIFEST_SHA'] != TABLE_PINS[PRIVATE][1] or
            boot['CLIENT_MANIFEST_SHA'] != TABLE_PINS[PRIVATE][1] or
            boot['F37_SHA'] != f_sha or factory['F_SHA'] != f_sha or bridge['PARENT_SOURCE_SHA'] != f_sha or
            owner['BOOT_PIN'] != (len(boot_raw), hashlib.sha256(boot_raw).hexdigest()) or
            (boot['ROOT'], boot['PHYSICAL_ROOT'], factory['ASSET_ROOT'], factory['ASSET_PHYSICAL_ROOT'], owner['ROOT']) !=
            (root, physical, root, physical, root)):
        raise ValueError('new_fixed_graph_pins')
    out = BASE / 'results' / ('receive-startup-readonly-host-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    snapshot = out / 'private-inputs'
    for path, raw in originals.items():
        target = snapshot / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        if target.read_bytes() != raw: raise ValueError('snapshot_readback')
    outcomes = []
    for ordinal, (path, unused_size, unused_pin, marker) in enumerate(TESTS):
        timed_out = False
        try:
            child = subprocess.run([sys.executable, '-I', '-B', str(snapshot / path)],
                                   cwd=snapshot, capture_output=True, timeout=45)
            stdout, stderr, code = child.stdout, child.stderr, child.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code, timed_out = error.stdout or b'', error.stderr or b'', None, True
        (out / ('test%d-stdout.raw' % ordinal)).write_bytes(stdout)
        (out / ('test%d-stderr.raw' % ordinal)).write_bytes(stderr)
        derived_out = stdout.replace(b'\r\n', b'\n')
        derived_err = stderr.replace(b'\r\n', b'\n')
        summary_ok = re.fullmatch(br'-+\nRan 1 test in [0-9]+\.[0-9]+s\n\nOK\n', derived_err) is not None
        outcomes.append(dict(path=path, passed=code == 0 and not timed_out and derived_out == marker and summary_ok,
            child_exit=code, timeout=timed_out, stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest()))
    unchanged = all((BASE / path).read_bytes() == raw and (snapshot / path).read_bytes() == raw
                    for path, raw in originals.items())
    passed = unchanged and all(r['passed'] for r in outcomes)
    report = dict(schema='receive-startup-readonly-host-v1', passed=passed, tests=outcomes,
        new_methods=2, old_methods=0, domains_completed=9 if passed else None,
        source_snapshots_equal=unchanged, snapshot_count=len(originals), target_python35_ast_sources=6,
        fixed_private_roles=35, fixed_ordinary_roles=29, definition_rows=31, graph_pins_consistent=True,
        actual_private_importer_tested=outcomes[0]['passed'],
        actual_pure_constructor_error_paths_tested=outcomes[1]['passed'], close_control_model=True,
        factory_started=False, owner_started=False, actual_baseline_collected=False, actual_wpa_status_collected=False,
        hardware_FD_close_tested=False, RF_requested=False, device_accessed=False, phone_tested=False,
        old_pending_modified=False, receive_admission=False, restoration_verified=False,
        inputs=[dict(path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                for path, raw in originals.items()], private_raw_included=False)
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'New SOURCE graph: 35 private roles, 29 ordinary roles plus Boot/Owner, six Python 3.5 AST sources. '
        b'Two new HOST methods only. Actual importing and pure constructor failure handling; scope and close '
        b'control are explicit HOST models. No Factory/Owner start, actual ARM baseline or WPA STATUS, '
        b'hardware FD closure, device, RF, phone, pending cleanup, receive admission or restoration proof. '
        b'Raw child output and frozen inputs are private, not included.\n')
    members = {'result.json': result, 'README.txt': note}
    for path, raw in members.items(): (out / path).write_bytes(raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, raw in members.items(): bundle.writestr(path, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(path) != raw for path, raw in members.items()):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, result_dir=str(out), result_zip=str(archive),
        zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest())))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
