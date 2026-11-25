"""SOURCE-only fixed ordinary32/Boot/Owner/outer audit. No target execution."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import struct
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
CATALOG = 'candidate/formal-send-v1/assets/ordinary-source-manifest.json'
CATALOG_PIN = (18219, '0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1')
SELF = 'host/formal_send_graph_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_GRAPH_SOURCE_CHECK.cmd'
BOOT = 'candidate/formal-send-v1/runtime/mta_client_receive_boot.py'
OWNER = 'candidate/formal-send-v1/runtime/mta_client_service_owner.py'
OUTER = 'candidate/formal-send-v1/runtime/formal_send_session.py'
PRIOR_STATE = ('results/formal-send-state-constructor-host-20261004-172535-d5209d55/'
               'private-inputs/candidate/formal-send-v1/runtime/mta_service.py')
PRIOR_STATE_PIN = (139711, 'a227e7ad56cf9d9e04eedc986064b2b764144eeaabf466cfaca9299980d72dec')
VIRTUAL = '/tmp/p011-mta-formal-send-v1'
PHYSICAL = '/var/volatile/tmp/p011-mta-formal-send-v1'
DEPLOYMENT = '/var/volatile/tmp/p011-mta-go-send-v76-assets/runtime/mta_go_deployment.py'


def digest(raw): return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw): raise OSError('short_write')
        stream.flush(); os.fsync(stream.fileno())
    if path.read_bytes() != raw: raise ValueError('snapshot_readback')


def safe_source(name):
    path = PurePosixPath(name)
    if (type(name) is not str or str(path) != name or path.is_absolute() or
            not path.parts or '..' in path.parts or '\\' in name or ':' in name):
        raise ValueError('fixed_source_path')
    return BASE.joinpath(*path.parts)


def expression(node, values):
    if isinstance(node, ast.Name): return values[node.id]
    if isinstance(node, ast.BinOp):
        left, right = expression(node.left, values), expression(node.right, values)
        if isinstance(node.op, ast.Mult): return left * right
        if isinstance(node.op, ast.Add): return left + right
        raise ValueError('constant_operator')
    if isinstance(node, ast.Tuple): return tuple(expression(value, values) for value in node.elts)
    if isinstance(node, ast.List): return [expression(value, values) for value in node.elts]
    return ast.literal_eval(node)


def constants(raw):
    tree = ast.parse(raw, feature_version=(3, 5)); values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name): continue
        try: values[node.targets[0].id] = expression(node.value, values)
        except (ValueError, KeyError, TypeError): pass
    return tree, values


def main():
    if sys.argv[1:]: raise ValueError('fixed_SOURCE_only')
    out = BASE / 'results' / ('formal-send-graph-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    sources = {}
    report = dict(schema='p011-formal-send-graph-source-v1', passed=False,
        host_exit=None, remote_exit=None, new_methods=0, old_methods=0,
        ordinary_roles=0, startup_roles=0, helper_roles=0, python35_ast=0,
        boot_shape_count_matches=False, boot_owner_outer_pins_match=False,
        roles_and_paths_match=False, helper_arm32_shapes=False,
        prior_five_state_method_asts_unchanged=False, prior_operation_ast_unchanged=False,
        source_pins_do_not_admit_rf=True, asset_payload_inline=False,
        separate_private_assets_reverified=False, program_built=False, stager_verified=False,
        actual_boot_load=False, actual_owner=False, actual_outer=False, whole_graph_host_tested=False,
        device=False, phone=False, rf=False, send_verified=False,
        restoration_verified=False, production_admitted=False, error=None)

    def take(name, pin=None):
        if name not in sources:
            raw = safe_source(name).read_bytes(); sources[name] = raw
            save(out / 'private-inputs' / name, raw)
        raw = sources[name]
        if pin is not None and (len(raw), digest(raw)) != tuple(pin): raise ValueError('fixed_source_pin')
        return raw

    try:
        take(SELF); take(CMD)
        catalog = json.loads(take(CATALOG, CATALOG_PIN))
        if (catalog['schema'] != 'p011-formal-send-v1-ordinary-source-catalog' or
                catalog['source_count'] != 32 or catalog['ordinary_root'] != VIRTUAL + '/runtime' or
                catalog['physical_ordinary_root'] != PHYSICAL + '/runtime' or
                catalog['asset_payload_inline'] is not False or
                catalog['source_pins_do_not_admit_rf'] is not True or
                (catalog['program_cap_bytes'], catalog['wire_cap_bytes'],
                 catalog['original_per_source_cap_bytes'], catalog['original_boot_load_seconds']) !=
                    (2097152, 4194304, 2097152, 10)):
            raise ValueError('catalog_contract')
        rows, startup, helpers = catalog['sources'], catalog['startup_sources'], catalog['helper_sources']
        if len(rows) != 32 or len(startup) != 3 or len(helpers) != 3: raise ValueError('role_count')
        roles, pins, ordinary_bytes = [], [], 0
        for row in rows:
            module = row['module']; roles.append(module)
            pins.append((module, row['bytes'], row['sha256']))
            raw = take(row['source'], (row['bytes'], row['sha256']))
            ast.parse(raw, feature_version=(3, 5)); report['python35_ast'] += 1
            ordinary_bytes += len(raw)
            expected = DEPLOYMENT if module == 'mta_go_deployment' else VIRTUAL + '/runtime/' + module + '.py'
            physical = DEPLOYMENT if module == 'mta_go_deployment' else PHYSICAL + '/runtime/' + module + '.py'
            if (row['target'] != expected or row['physical_target'] != physical or row['mode'] != 0o400 or
                    row['reused_sender_asset'] is not (module == 'mta_go_deployment')):
                raise ValueError('source_target_identity')
        if len(set(roles)) != 32 or ordinary_bytes != catalog['ordinary_source_bytes'] or ordinary_bytes != 1036797:
            raise ValueError('ordinary_inventory')
        for row in startup:
            raw = take(row['source'], (row['bytes'], row['sha256']))
            ast.parse(raw, feature_version=(3, 5)); report['python35_ast'] += 1
            if (row['target'] != VIRTUAL + '/runtime/' + row['module'] + '.py' or
                    row['physical_target'] != PHYSICAL + '/runtime/' + row['module'] + '.py' or
                    row['mode'] != 0o400): raise ValueError('startup_target')
        if tuple(row['source'] for row in startup) != (BOOT, OWNER, OUTER): raise ValueError('startup_roles')
        for row in helpers:
            raw = take(row['source'], (row['bytes'], row['sha256']))
            if (len(raw) < 52 or raw[:7] != b'\x7fELF\x01\x01\x01' or
                    struct.unpack_from('<H', raw, 18)[0] != 40): raise ValueError('helper_arm_shape')
            if (not row['target'].startswith(VIRTUAL + '/') or
                    row['physical_target'] != PHYSICAL + row['target'][len(VIRTUAL):] or
                    row['mode'] not in (0o500, 0o700)): raise ValueError('helper_target')
        for key in ('separate_asset_catalog', 'separate_sender_manifest'):
            row = catalog[key]; take(row['source'], (row['bytes'], row['sha256']))
        bt, boot = constants(sources[BOOT]); unused, owner = constants(sources[OWNER]); unused, outer = constants(sources[OUTER])
        if (boot['SOURCE_PINS'] != tuple(pins) or owner['BOOT_MODULES'] != tuple(roles) or
                boot['SOURCE_SCHEMA'] != owner['BOOT_SCHEMA'] or boot['SOURCE_SCHEMA'] != outer['SOURCE_SCHEMA'] or
                boot['LOAD_SECONDS'] != 10.0 or boot['MAX_SOURCE'] != 2097152 or
                outer['PROFILES'] != (('diagnostic', 60.0, False), ('send-interactive-v1', 600.0, True))):
            raise ValueError('cross_role_contract')
        shape = next(node for node in ast.walk(bt) if isinstance(node, ast.FunctionDef) and node.name == '_source_shape')
        counts = [expression(node.comparators[0], {}) for node in ast.walk(shape) if isinstance(node, ast.Compare) and
            isinstance(node.left, ast.Call) and isinstance(node.left.func, ast.Name) and node.left.func.id == 'len' and
            len(node.left.args) == 1 and isinstance(node.left.args[0], ast.Name) and node.left.args[0].id == 'SOURCE_PINS' and
            len(node.comparators) == 1]
        if counts != [32]: raise ValueError('boot_shape_count')
        bp, op = (len(sources[BOOT]), digest(sources[BOOT])), (len(sources[OWNER]), digest(sources[OWNER]))
        if owner['BOOT_PIN'] != bp or outer['BOOT_PIN'] != bp or outer['OWNER_PIN'] != op:
            raise ValueError('cross_source_pin')
        # Reuse the preserved 16-case HOST scope, never rerun its test method.
        previous = ast.parse(take(PRIOR_STATE, PRIOR_STATE_PIN), feature_version=(3, 5))
        current = ast.parse(sources[next(row['source'] for row in rows if row['module'] == 'mta_service')],
                            feature_version=(3, 5))
        selected = ('_new_operation_locked', '_verify_go_terminal_restoration',
                    '_go_freeze', '_go_restoration_current', '_go_zero_closed')
        def selected_state_keys(tree):
            state = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'State')
            return {node.name: ast.dump(node, include_attributes=False) for node in state.body
                    if isinstance(node, ast.FunctionDef) and node.name in selected}
        if selected_state_keys(previous) != selected_state_keys(current) or len(selected_state_keys(current)) != 5:
            raise ValueError('previous_HOST_method_scope_changed')
        def operation_key(tree):
            return ast.dump(next(node for node in tree.body if isinstance(node, ast.ClassDef) and
                                 node.name == 'Operation'), include_attributes=False)
        if operation_key(previous) != operation_key(current): raise ValueError('previous_HOST_operation_changed')
        report['prior_five_state_method_asts_unchanged'] = report['prior_operation_ast_unchanged'] = True
        report.update(ordinary_roles=32, startup_roles=3, helper_roles=3, ordinary_source_bytes=ordinary_bytes,
            boot_shape_count_matches=True, boot_owner_outer_pins_match=True, roles_and_paths_match=True,
            helper_arm32_shapes=True)
        inventory = {name: dict(bytes=len(raw), sha256=digest(raw)) for name, raw in sources.items()}
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report['source_count'] = len(sources)
        report['source_preserved'] = all(safe_source(name).read_bytes() == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in sources.items())
        if not report['source_preserved']: raise ValueError('source_changed_during_check')
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__
        save(out / 'private-error.txt', str(error).encode('utf-8'))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'SOURCE ONLY: 32 ordinary roles / 3 startup sources / 3 helper bytes and ARM32 '
        b'ELF shapes; Python3.5 AST, exact fixed paths, Boot32 shape, cross Owner/outer pins '
        b'and 60/600/10s static budgets. The five previously tested State method ASTs and '
        b'Operation AST are compared with preserved HOST inputs, without replaying those '
        b'16 cases. New close/probe budgets remain SOURCE-only. No target module import '
        b'or graph execution. Separate '
        b'sender25/Observer41/WPA assets are referenced by immutable catalogs, not reverified '
        b'or inlined here. This does not build a program/stager, execute Boot/Owner/outer, '
        b'Native/RF, P011, phone, transfer or restoration. Zero new/old HOST tests. '
        b'Private source snapshots stay local; this ZIP contains only scalar result/README.\n')
    save(out / 'result.json', result); save(out / 'README.txt', note)
    for name in ('stdout.raw', 'stderr.raw', 'host-exit.raw', 'remote-exit.raw'):
        save(out / name, b'NOT_INVOKED_SOURCE_ONLY\n')
    bundle = out / 'public-result.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result); archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        if (archive.namelist() != ['result.json', 'README.txt'] or archive.testzip() is not None or
                archive.read('result.json') != result or archive.read('README.txt') != note):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
