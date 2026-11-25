"""Fixed receive-adapter SOURCE check only: no target imports or child/test.

Only the six new adapter files are parsed once for Python 3.5 syntax. Their
same ASTs supply fixed literal metadata; both graphs' other sources are bytes
only. Matching pins/roles is not a loaded graph, publication seal, admission,
directory initialization, native closure or device/phone acceptance.
"""
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import traceback
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/receive_directory_adapters_source_check.py'
CMD = 'HOST_MTA_RECEIVE_DIRECTORY_ADAPTERS_SOURCE_CHECK.cmd'
NEW_ROOT = 'candidate/receive-directory-adapters-v1/runtime/'
NEW_MODULES = ('mta_client_executor', 'mta_client_receive_factory',
    'mta_client_state_bridge', 'mta_service', 'mta_client_receive_boot',
    'mta_client_service_owner')
PRIVATE = 'host/client_receive_directory_v1_private_source_manifest.json'
DEFINITIONS = 'host/client_receive_directory_v1_definition_manifest.json'
# Final SOURCE pins only; these are not a target publication/admission seal.
MANIFEST_PINS = {
    PRIVATE: (8142, 'ca12a3a653ac9ada3f7910fb4223b9aa271968808a2596ad33cd3c817f4450ad'),
    DEFINITIONS: (6744, '6e563e23c924a46d271cb17090ee64fd683d307efe1aeb586dc55939fcc9caa6'),
}
ADAPTER_PINS = {
    'mta_client_executor': (113901, 'ddac5d4eb684f248d78471ba20388ed52e2a738c873ab4ba977b4ff2a14b7099'),
    'mta_client_receive_factory': (56177, '40979ef6949f5afae6e31277c6377587a2e5bd34013d87e82fe142fde2e4ea34'),
    'mta_client_state_bridge': (21284, '3515451464d3e3563309dfd7112cdb25e3980cf628e755f658f84c01c1f75208'),
    'mta_service': (102579, 'e53321ff0d2271d67ae498d4d393e2a621a28da3b74a3d35c43e1de9ff2e42f6'),
    'mta_client_receive_boot': (19144, '277ab8b8d648eb427442e157050e750392bc12a745e2545d103b38101857475f'),
    'mta_client_service_owner': (34681, 'fd63d2224e32db77edb691a412c283753b2b7ecf955c0b4591ab44c59d603fc4'),
}
PREVIOUS_PRIVATE = '0ea4db9b3ac41d1036d5796602db48b7740f6c51f1f0281604d6d8ebeb19319c'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def _path(relative):
    if (type(relative) is not str or not relative or '\\' in relative or ':' in relative or
            any(part in ('', '.', '..') for part in relative.split('/'))):
        raise ValueError('source_relative_path')
    target = BASE / relative
    if not target.resolve().is_relative_to(BASE):
        raise ValueError('source_outside_workspace')
    return target


def _capture(relative, originals, private, pin=None):
    raw = _path(relative).read_bytes()
    if relative in originals and raw != originals[relative]:
        raise ValueError('input_changed_during_check')
    if relative not in originals:
        originals[relative] = raw
        saved = private / relative
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(raw)
        if saved.read_bytes() != raw:
            raise ValueError('snapshot_readback')
    if pin is not None and (type(pin) is not tuple or len(pin) != 2 or
            len(raw) != pin[0] or _sha(raw) != pin[1]):
        raise ValueError('fixed_input_pin')
    return raw


def _manifest(raw, schema, count, previous=False):
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if previous else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != schema or
            type(value['sources']) is not list or len(value['sources']) != count or
            previous and value['previous_manifest_sha256'] != PREVIOUS_PRIVATE):
        raise ValueError('manifest_shape')
    names = set()
    for row in value['sources']:
        if (type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'} or
                type(row['module']) is not str or re.fullmatch(r'[a-z][a-z0-9_]*', row['module']) is None or
                row['module'] in names or type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152 or
                type(row['sha256']) is not str or re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is None):
            raise ValueError('manifest_row')
        _path(row['path'])
        names.add(row['module'])
    return value['sources']


def _assignment(tree, name):
    nodes = [item.value for item in tree.body if isinstance(item, ast.Assign) and
        len(item.targets) == 1 and isinstance(item.targets[0], ast.Name) and item.targets[0].id == name]
    if len(nodes) != 1:
        raise ValueError('fixed_literal_assignment')
    return nodes[0]


def _literal(tree, name):
    # Only primitive literals/tuples and explicit top-level literal aliases.
    # This never evaluates target expressions, imports or function calls.
    def data(node, seen):
        if isinstance(node, ast.Name):
            if node.id in seen:
                raise ValueError('literal_cycle')
            return data(_assignment(tree, node.id), seen | {node.id})
        if isinstance(node, ast.Tuple):
            return tuple(data(part, seen) for part in node.elts)
        return ast.literal_eval(node)
    return data(_assignment(tree, name), {name})


def _boot_modules_shape(tree):
    node = _assignment(tree, 'MODULES')
    if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != 'tuple' or
            len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.GeneratorExp)):
        raise ValueError('boot_modules_derivation')
    gen = node.args[0]
    if len(gen.generators) != 1:
        raise ValueError('boot_modules_derivation')
    row = gen.generators[0]
    item = gen.elt
    if (not isinstance(row.target, ast.Name) or row.target.id != 'row' or
            not isinstance(row.iter, ast.Name) or row.iter.id != 'SOURCE_PINS' or row.ifs or row.is_async or
            not isinstance(item, ast.Subscript) or not isinstance(item.value, ast.Name) or item.value.id != 'row' or
            ast.literal_eval(item.slice) != 0):
        raise ValueError('boot_modules_derivation')


def _method(tree, class_name, method_name):
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
    if len(classes) != 1:
        raise ValueError('fixed_class_shape')
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name == method_name]
    if len(methods) != 1:
        raise ValueError('fixed_method_shape')
    return methods[0]


def _false_assignment(method, owner, field):
    nodes = [node for node in ast.walk(method) if isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Attribute) and target.attr == field and
        ((owner == 'self' and isinstance(target.value, ast.Name) and target.value.id == 'self') or
         (owner == 'self.state' and isinstance(target.value, ast.Attribute) and target.value.attr == 'state' and
          isinstance(target.value.value, ast.Name) and target.value.value.id == 'self')) for target in node.targets)]
    if not nodes or any(ast.literal_eval(node.value) is not False for node in nodes):
        raise ValueError('source_admission_flag_changed')


def _metadata(trees, private_rows, definition_rows, private_sha):
    rows = lambda values: tuple((row['module'], row['bytes'], row['sha256']) for row in values)
    names = lambda values: tuple(row['module'] for row in values)
    f, factory, bridge, state, boot, owner = (trees[name] for name in NEW_MODULES)
    if (_literal(f, 'MODULES') != names(private_rows) or _literal(factory, 'SOURCE_PINS') != rows(private_rows) or
            _literal(factory, 'SOURCE_MANIFEST_SHA') != private_sha or
            _literal(boot, 'CLIENT_MANIFEST_SHA') != private_sha or
            _literal(boot, 'SOURCE_PINS') != rows(definition_rows[:28]) or
            names(definition_rows[28:]) != ('mta_client_receive_boot', 'mta_client_service_owner') or
            _literal(owner, 'BOOT_MODULES') != names(definition_rows[:28]) or
            _literal(owner, 'BOOT_SCHEMA') != _literal(boot, 'SOURCE_SCHEMA') or
            _literal(owner, 'BOOT_PIN') != (definition_rows[28]['bytes'], definition_rows[28]['sha256'])):
        raise ValueError('literal_graph_contract')
    _boot_modules_shape(boot)
    f_row = next(row for row in private_rows if row['module'] == 'mta_client_executor')
    codec = next(row for row in private_rows if row['module'] == 'mta_client_control_frame')
    if (_literal(factory, 'F_SHA') != f_row['sha256'] or _literal(boot, 'F37_SHA') != f_row['sha256'] or
            _literal(bridge, 'PARENT_SOURCE_SHA') != f_row['sha256'] or
            _literal(factory, 'CODEC_SHA') != codec['sha256'] or
            _literal(f, 'CONNECT_CODEC_SHA') != codec['sha256'] or
            _literal(bridge, 'CODEC_SOURCE_SHA') != codec['sha256']):
        raise ValueError('literal_parent_codec_pin')
    constructor = _method(state, 'State', '__init__')
    _false_assignment(constructor, 'self', 'receive_available')
    _false_assignment(constructor, 'self', 'send_available')
    _false_assignment(_method(owner, 'FixedStateServiceOwner', 'start'), 'self.state', 'scan_available')
    admitted = _method(state, 'State', '_go_send_admitted')
    if len(admitted.body) != 1 or not isinstance(admitted.body[0], ast.Return) or \
            ast.literal_eval(admitted.body[0].value) is not False:
        raise ValueError('source_sender_admission_changed')


def main():
    if len(sys.argv) != 1:
        return 2
    out = BASE / 'results' / ('receive-directory-adapters-source-' +
        datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    private = out / 'private-inputs'
    private.mkdir(parents=True)
    originals, parsed, private_rows, definition_rows = {}, [], [], []
    failure = None
    try:
        for relative in (SELF, CMD):
            _capture(relative, originals, private)
        if (type(MANIFEST_PINS) is not dict or set(MANIFEST_PINS) != {PRIVATE, DEFINITIONS} or
                type(ADAPTER_PINS) is not dict or set(ADAPTER_PINS) != set(NEW_MODULES)):
            raise ValueError('source_inputs_not_frozen')
        first = _capture(PRIVATE, originals, private, MANIFEST_PINS[PRIVATE])
        second = _capture(DEFINITIONS, originals, private, MANIFEST_PINS[DEFINITIONS])
        private_rows = _manifest(first, 'client-receive-directory-v1-private-source', 35, True)
        definition_rows = _manifest(second, 'client-receive-directory-v1-definitions', 30)
        for row in private_rows + definition_rows:
            _capture(row['path'], originals, private, (row['bytes'], row['sha256']))
        # Separate private 35 from ordinary 28+Boot+Owner; shared roles must
        # retain the same complete row, not merely a same-named module.
        old = {row['module']: row for row in private_rows}
        if any(row != old[row['module']] for row in definition_rows if row['module'] in old):
            raise ValueError('shared_source_row_changed')
        trees = {}
        for name in NEW_MODULES:
            relative = NEW_ROOT + name + '.py'
            raw = _capture(relative, originals, private, ADAPTER_PINS[name])
            trees[name] = ast.parse(raw.decode('utf-8'), filename=relative, feature_version=(3, 5))
            parsed.append(relative)
        _metadata(trees, private_rows, definition_rows, _sha(first))
    except Exception as error:
        failure = type(error).__name__
        (out / 'failure.private.txt').write_text(traceback.format_exc(), encoding='utf-8')
    try:
        unchanged = all(_path(name).read_bytes() == raw and (private / name).read_bytes() == raw
            for name, raw in originals.items())
    except Exception as error:
        unchanged = False
        if failure is None:
            failure = type(error).__name__
            (out / 'failure.private.txt').write_text(traceback.format_exc(), encoding='utf-8')
    if not unchanged and failure is None:
        failure = 'InputChanged'
    passed = failure is None and unchanged and len(parsed) == 6
    report = dict(schema='receive-directory-adapters-source-check-v1', passed=passed,
        failure_type=failure, source_snapshots_equal=unchanged,
        private_manifest_count=len(private_rows), definition_manifest_count=len(definition_rows),
        ordinary_role_count=28, target_python35_ast_sources=len(parsed), ast_sources=parsed,
        source_literals_match=passed, source_admission_false_assignments_verified=passed,
        referenced_unique_source_count=len(set(row['path'] for row in private_rows + definition_rows)),
        snapshot_count=len(originals), source_graph_loaded=False, full_graph_sealed=False,
        target_definitions_executed=False, child_invocations=0, tests_run=False, old_methods=0,
        directory_initialized=False, native_closure_verified=False, restoration_verified=False,
        send_available=False, receive_available=False, production_admission=False,
        device_accessed=False, rf_requested=False, phone_tested=False, private_inputs_included=False,
        inputs=[dict(path=name, bytes=len(raw), sha256=_sha(raw)) for name, raw in originals.items()])
    result = (json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'PC SOURCE only: two fixed manifests and each row verified against saved/current bytes. '
        b'Only six new receive adapters are parsed once for Python 3.5; those same ASTs supply literal pins/roles. '
        b'No old Storage/Transport AST, target import, dynamic load, test method, child, WSL, ADB, RF or phone. '
        b'Matching source is not a full graph seal/load, production admission or restoration. '
        b'Original snapshots and failure details remain private.\n')
    members = {'result.json': result, 'README.txt': note}
    for name, raw in members.items():
        (out / name).write_bytes(raw)
    archive = out / 'public-result.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, raw in members.items():
            bundle.writestr(name, raw)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.namelist() != list(members) or bundle.testzip() is not None or \
                any(bundle.read(name) != raw for name, raw in members.items()):
            raise ValueError('zip_readback')
    print(json.dumps(dict(passed=passed, source_only=True, target_python35_ast_sources=len(parsed),
        snapshot_count=len(originals), result_dir=str(out), result_zip=str(archive), zip_sha256=_sha(archive.read_bytes()))))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
