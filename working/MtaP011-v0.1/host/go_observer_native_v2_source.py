"""PC-only fixed observer/native-path source derivation; import is inert.

Default SOURCE returns eight new files in memory and never writes or executes
target definitions. Explicit --write exclusively creates the one fresh prefix.
The actual diagnostic-v1 graph is frozen: four asset roles change only fixed
roots and dependent source pins, 37 are byte-identical, and Parent is inline.
Private failure DATA, readonly manifest/38 loads, Proc, caps and methods stay.
No native staging, Parent collection, Owner, UI, RF or test runs here.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/go_observer_native_v2_source.py'
PREFIX = 'candidate/go-observer-native-v2'
OLD_ROOT = '/var/volatile/tmp/p011-mta-go-observer-diag-v1'
ROOT = '/var/volatile/tmp/p011-mta-go-observer-native-v2'
OLD_ALIAS = '/tmp/p011-mta-go-observer-diag-v1'
ALIAS = '/tmp/p011-mta-go-observer-native-v2'
OLD_NATIVE = '/var/volatile/tmp/p011-mta-state-v69'
NATIVE_ROOT = '/var/volatile/tmp/p011-mta-go-readonly-native-v1'
CATALOG = 'candidate/go-observer-diag-v1/assets/observer-source-catalog.json'
CATALOG_PIN = (15862, 'aeb4cc01d992f9a39ec1fb57ecaea57b4a8e3aef4ac5b5bf2a995fa2836eedea')
PARENT = 'candidate/go-observer-diag-v1/runtime/mta_go_readonly_parent.py'
PARENT_PIN = (52882, '9ef36a53b80427af03e1bcc51b198e08917eebe22ce1545b53fa88f8bac58b06')
ROLES = ('mta_go_readonly_preflight', 'mta_go_readonly_loader',
         'mta_observer_packet', 'mta_go_readonly_entry', 'mta_go_readonly_parent')
ASSET_ROLES = ROLES[:4]
PINS = (
    (64948, 'a10d6c9ff9ec4bf4b2d542120b19af3e36a111caf1153eaa8bc7d842aaa245eb'),
    (36543, '18de54e9dd3db344aaff522a873bc1094798eda6766b1a80259a71999dff919d'),
    (48253, '004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f'),
    (151251, '930775277dc3b6872ee8b34d7ae0ffc9aeac2dc098b3597a474c3dbecc98c53b'),
    PARENT_PIN)
NATIVE_PINS = (
    ('mta-bluez-helper', 65832, '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('mta-network-helper', 47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'))
READONLY_MANIFEST = (8096, '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def pin(raw):
    need(type(raw) is bytes, 'source_type')
    return len(raw), hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('ascii')


def local(path):
    need(type(path) is str and path and '\\' not in path and
         not Path(path).is_absolute() and '..' not in Path(path).parts, 'fixed_path')
    result = (BASE / path).resolve()
    need(result.is_relative_to(BASE) and result != BASE, 'fixed_path_escape')
    return result


def tree(raw):
    return ast.parse(raw.decode('ascii'), feature_version=(3, 5))


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    return tuple((type(node).__name__, node.name, node.lineno, node.end_lineno,
                  b''.join(lines[node.lineno - 1:node.end_lineno]))
                 for node in ast.walk(tree(raw))
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def literal(raw, name):
    values = [node.value for node in tree(raw).body if isinstance(node, ast.Assign) and
              any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(values) == 1, 'literal_once')
    return ast.literal_eval(values[0])


def catalog(raw):
    need(pin(raw) == CATALOG_PIN, 'mother_catalog_pin')
    result = json.loads(raw.decode('ascii'))
    need(result['schema'] == 'p011-go-observer-diag-v1-fixed-asset-catalog' and
         result['root'] == OLD_ROOT and result['alias'] == OLD_ALIAS and
         result['source_count'] == len(result['files']) == 41 and
         result['source_bytes'] == sum(row['bytes'] for row in result['files']) == 1548449 and
         result['load_count'] == 38 and result['unchanged_asset_count'] == 38 and
         tuple(result['changed_asset_modules']) == (ROLES[0], ROLES[1], ROLES[3]) and
         (result['original_readonly_manifest_bytes'], result['original_readonly_manifest_sha256']) == READONLY_MANIFEST and
         result['program_cap_bytes'] == 2097152 and result['wire_cap_bytes'] == 4194304 and
         result['active_seconds'] == 30 and result['cleanup_seconds'] == 5 and
         result['parent_inline_only']['source'] == PARENT and
         (result['parent_inline_only']['bytes'], result['parent_inline_only']['sha256']) == PARENT_PIN and
         result['parent_inline_only']['not_in_asset_files'] is True and
         len({row['module'] for row in result['files']}) == 41 and
         len({row['source'] for row in result['files']}) == 41, 'mother_catalog_shape')
    for row in result['files']:
        need(set(row) == {'module', 'source', 'target', 'bytes', 'sha256', 'mode'} and
             row['mode'] == '0400' and row['target'] == OLD_ROOT + '/runtime/' + row['module'] + '.py' and
             type(row['bytes']) is int and 0 < row['bytes'] <= 2097152 and
             re.fullmatch('[0-9a-f]{64}', row['sha256']) is not None, 'mother_role_shape')
    for role, expected in zip(ASSET_ROLES, PINS[:4]):
        row = next(item for item in result['files'] if item['module'] == role)
        need((row['bytes'], row['sha256']) == expected, 'mother_role_pin')
    return result


def contracts(value):
    result = ((CATALOG,) + CATALOG_PIN,) + tuple((row['source'], row['bytes'], row['sha256'])
        for row in value['files']) + ((PARENT,) + PARENT_PIN,)
    need(len(result) == len({row[0] for row in result}) == 43, '43_source_contracts')
    return result


def source_inputs():
    return contracts(catalog(local(CATALOG).read_bytes()))


def load_inputs():
    result = {}
    for path, size, sha in source_inputs():
        raw = local(path).read_bytes()
        need(pin(raw) == (size, sha), 'fixed_source_pin')
        result[path] = raw
    return result


def edit(raw, changes, label, before, after, count=1):
    need(type(before) is bytes and type(after) is bytes and before != after and
         type(count) is int and count > 0 and raw.count(before) == count, 'exact_forward_edit')
    result = raw.replace(before, after)
    need(result.count(after) == count and result.replace(after, before) == raw, 'exact_reverse_edit')
    changes.append(dict(label=label, before=before.decode('ascii'), after=after.decode('ascii'), count=count))
    return result


def reversed_bytes(raw, changes):
    for row in reversed(changes):
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(raw.count(after) == row['count'], 'full_inverse_anchor')
        raw = raw.replace(after, before)
    return raw


def root(raw, changes, alias=None):
    raw = edit(raw, changes, 'observer_root',
        ("ROOT = '" + OLD_ROOT + "'\n").encode('ascii'), ("ROOT = '" + ROOT + "'\n").encode('ascii'))
    if alias:
        raw = edit(raw, changes, 'observer_alias',
            (alias + " = '" + OLD_ALIAS + "'\n").encode('ascii'),
            (alias + " = '" + ALIAS + "'\n").encode('ascii'))
    return raw


def derive_sources(value, inputs):
    mothers = {row['module']: inputs[row['source']] for row in value['files'] if row['module'] in ASSET_ROLES}
    mothers[ROLES[4]] = inputs[PARENT]
    changed, proofs = {}, []
    # Packet and Body precede their dependent Loader/Entry/Parent pins.
    order = (ROLES[0], ROLES[2], ROLES[1], ROLES[3], ROLES[4])
    for role in order:
        index = ROLES.index(role)
        mother, changes = mothers[role], []
        need(pin(mother) == PINS[index] and b'\r' not in mother, 'actual_LF_mother_pin')
        if role == ROLES[2]:
            raw = mother
            for name, size, sha in NATIVE_PINS:
                before = ("    ('" + OLD_NATIVE + '/native/' + name + "',\n").encode('ascii')
                after = ("    ('" + NATIVE_ROOT + '/native/' + name + "',\n").encode('ascii')
                raw = edit(raw, changes, 'packet_helper_path_' + name, before, after)
        else:
            raw = root(mother, changes, None if role == ROLES[0] else 'ALIAS_ROOT' if role == ROLES[1] else 'ALIAS')
        if role == ROLES[0]:
            raw = edit(raw, changes, 'independent_native_root',
                ("STATE_ROOT = '" + OLD_NATIVE + "'\n").encode('ascii'),
                ("STATE_ROOT = '" + NATIVE_ROOT + "'\n").encode('ascii'))
        elif role == ROLES[1]:
            size, sha = pin(changed[ROLES[0]])
            before = ("    ('mta_go_readonly_preflight', 64948, '" + PINS[0][1] + "'),\n").encode('ascii')
            after = ("    ('mta_go_readonly_preflight', " + str(size) + ", '" + sha + "'),\n").encode('ascii')
            raw = edit(raw, changes, 'actual_body_pin', before, after)
        elif role == ROLES[3]:
            for dependency, old_pin in ((ROLES[1], PINS[1]), (ROLES[2], PINS[2])):
                size, sha = pin(changed[dependency])
                before = ("    ('" + dependency + "', " + str(old_pin[0]) + ",\n     '" + old_pin[1] + "'),\n").encode('ascii')
                after = ("    ('" + dependency + "', " + str(size) + ",\n     '" + sha + "'),\n").encode('ascii')
                raw = edit(raw, changes, 'actual_pin_' + dependency, before, after)
        elif role == ROLES[4]:
            packet_size, packet_sha = pin(changed[ROLES[2]])
            before = ("    ('mta_observer_packet', 48253, '" + PINS[2][1] + "'),\n").encode('ascii')
            after = ("    ('mta_observer_packet', " + str(packet_size) + ", '" + packet_sha + "'),\n").encode('ascii')
            raw = edit(raw, changes, 'actual_parent_packet_pin', before, after)
            size, sha = pin(changed[ROLES[3]])
            before = ("ENTRY_PIN = ('mta_go_readonly_entry', 151251,\n             '" + PINS[3][1] + "')\n").encode('ascii')
            after = ("ENTRY_PIN = ('mta_go_readonly_entry', " + str(size) + ",\n             '" + sha + "')\n").encode('ascii')
            raw = edit(raw, changes, 'actual_entry_pin', before, after)
        original_tree, new_tree = tree(mother), tree(raw)
        inverse = reversed_bytes(raw, changes)
        need(inverse == mother and
             ast.dump(tree(inverse), include_attributes=True) == ast.dump(original_tree, include_attributes=True) and
             definitions(raw) == definitions(mother), 'complete_source_inverse_and_definitions')
        # No other AST nodes may change: only the named top-level constants.
        allowed = ({'HELPERS'} if role == ROLES[2] else
                   {'ROOT', 'STATE_ROOT'} if role == ROLES[0] else
                   {'ROOT', 'ALIAS_ROOT', 'SOURCE_PINS'} if role == ROLES[1] else
                   {'ROOT', 'ALIAS', 'SOURCE_PINS'} if role == ROLES[3] else {'ROOT', 'ALIAS', 'SOURCE_PINS', 'ENTRY_PIN'})
        def remaining(parsed):
            return tuple(ast.dump(node, include_attributes=True) for node in parsed.body
                if not (isinstance(node, ast.Assign) and len(node.targets) == 1 and
                        isinstance(node.targets[0], ast.Name) and node.targets[0].id in allowed))
        need(remaining(original_tree) == remaining(new_tree), 'only_fixed_top_level_constants')
        changed[role] = raw
        proofs.append(dict(module=role, old=dict(zip(('bytes', 'sha256'), pin(mother))),
            new=dict(zip(('bytes', 'sha256'), pin(raw))), edits=changes,
            complete_byte_ast_inverse=True, definitions_bytes_and_lines_unchanged=True,
            original_definition_count=len(definitions(mother))))
    need(tuple(literal(changed[ROLES[2]], 'HELPERS')) == tuple(
        (NATIVE_ROOT + '/native/' + name, sha) for name, size, sha in NATIVE_PINS), 'actual_packet_helpers')
    need(literal(changed[ROLES[0]], 'STATE_ROOT') == NATIVE_ROOT and
         literal(changed[ROLES[1]], 'LOAD_COUNT') == 38 and
         literal(changed[ROLES[1]], 'READONLY_MANIFEST_SHA') == READONLY_MANIFEST[1] and
         literal(changed[ROLES[2]], 'SOURCE_COUNT') == 38 and
         literal(changed[ROLES[2]], 'SOURCE_MANIFEST_SHA') == READONLY_MANIFEST[1], 'readonly_manifest_and_native_paths')
    return changed, proofs


def derive_catalog(mother_raw, value, changed):
    result = json.loads(mother_raw.decode('ascii'))
    result['schema'] = 'p011-go-observer-native-v2-fixed-asset-catalog'
    result['root'], result['alias'] = ROOT, ALIAS
    result['unchanged_asset_count'] = 37
    result['changed_asset_modules'] = list(ASSET_ROLES)
    for row in result['directories']:
        row['path'] = row['path'].replace(OLD_ROOT, ROOT)
    for row in result['files']:
        row['target'] = ROOT + '/runtime/' + row['module'] + '.py'
        if row['module'] in ASSET_ROLES:
            row['source'] = PREFIX + '/runtime/' + row['module'] + '.py'
            row['bytes'], row['sha256'] = pin(changed[row['module']])
    result['source_bytes'] = sum(row['bytes'] for row in result['files'])
    result['parent_inline_only'].update(source=PREFIX + '/runtime/' + ROLES[4] + '.py',
        bytes=pin(changed[ROLES[4]])[0], sha256=pin(changed[ROLES[4]])[1])
    edits = []
    raw = edit(mother_raw, edits, 'catalog_schema',
        b'p011-go-observer-diag-v1-fixed-asset-catalog', b'p011-go-observer-native-v2-fixed-asset-catalog')
    raw = edit(raw, edits, 'catalog_observer_roots', OLD_ROOT.encode('ascii'), ROOT.encode('ascii'),
        1 + len(value['directories']) + len(value['files']))
    # Exact quoted alias avoids counting the alias substring within physical roots.
    raw = edit(raw, edits, 'catalog_quoted_alias', ('"' + OLD_ALIAS + '"').encode('ascii'),
        ('"' + ALIAS + '"').encode('ascii'))
    raw = edit(raw, edits, 'four_existing_candidate_sources',
        b'candidate/go-observer-diag-v1/runtime/', (PREFIX + '/runtime/').encode('ascii'), 4)
    raw = edit(raw, edits, 'packet_candidate_source',
        b'"candidate/go-send-terminal-channel-v94/runtime/mta_observer_packet.py"',
        ('"' + PREFIX + '/runtime/mta_observer_packet.py"').encode('ascii'))
    for index, role in enumerate(ROLES):
        indent = '    ' if role == ROLES[4] else '      '
        old_size, old_sha = PINS[index]
        new_size, new_sha = pin(changed[role])
        before = ('"bytes": ' + str(old_size) + ',\n' + indent + '"sha256": "' + old_sha + '"').encode('ascii')
        after = ('"bytes": ' + str(new_size) + ',\n' + indent + '"sha256": "' + new_sha + '"').encode('ascii')
        raw = edit(raw, edits, 'actual_catalog_pin_' + role, before, after)
    raw = edit(raw, edits, 'four_changed_modules',
        b'"changed_asset_modules": [\n    "mta_go_readonly_preflight",\n    "mta_go_readonly_loader",\n    "mta_go_readonly_entry"\n  ]',
        b'"changed_asset_modules": [\n    "mta_go_readonly_preflight",\n    "mta_go_readonly_loader",\n    "mta_observer_packet",\n    "mta_go_readonly_entry"\n  ]')
    raw = edit(raw, edits, '37_unchanged_assets', b'"unchanged_asset_count": 38,', b'"unchanged_asset_count": 37,')
    raw = edit(raw, edits, 'actual_source_bytes', b'"source_bytes": 1548449,',
        ('"source_bytes": ' + str(result['source_bytes']) + ',').encode('ascii'))
    need(json.loads(raw.decode('ascii')) == result and reversed_bytes(raw, edits) == mother_raw,
         'catalog_complete_byte_and_object_inverse')
    return raw, result, edits


def assemble(inputs=None):
    """Return exact eight path/raw outputs and actual facts; never execute/write."""
    inputs = load_inputs() if inputs is None else inputs
    need(type(inputs) is dict and CATALOG in inputs, 'input_mapping')
    value = catalog(inputs[CATALOG])
    fixed = contracts(value)
    need(set(inputs) == {row[0] for row in fixed}, 'exact_input_keys')
    for path, size, sha in fixed:
        need(pin(inputs[path]) == (size, sha), 'fixed_source_pin')
    changed, source_proofs = derive_sources(value, inputs)
    catalog_raw, current, catalog_edits = derive_catalog(inputs[CATALOG], value, changed)
    unchanged = [row for row in value['files'] if row['module'] not in ASSET_ROLES]
    need(len(unchanged) == 37 and all(pin(inputs[row['source']]) == (row['bytes'], row['sha256'])
         for row in unchanged) and current['source_bytes'] <= current['program_cap_bytes'], '37_actual_unchanged_assets')
    facts = dict(schema='p011-go-observer-native-v2-source-facts', scope='SOURCE_ONLY_NOT_STAGED_NOT_RUN',
        root=ROOT, alias=ALIAS, native_root=NATIVE_ROOT, native_pins=[list(row) for row in NATIVE_PINS],
        source_count=41, source_bytes=current['source_bytes'], changed_asset_count=4, unchanged_asset_count=37,
        load_count=38, parent_inline_only=current['parent_inline_only'], source_inputs=[list(row) for row in fixed],
        runtime_pins={role: dict(zip(('bytes', 'sha256'), pin(changed[role]))) for role in ROLES},
        readonly_manifest=list(READONLY_MANIFEST), diagnostic_max_bytes=512, exception_layers=4,
        tb_frames_per_layer=8, tb_frames_total=32, diagnostic_single_fixed_fd2_attempt=True,
        frame_projection='namespace_bound_name_and_original_lineno',
        exact_original_function_or_code_identity_certified=False, stderr_identity_nonblocking_closure_certified=False,
        successful_packet_unchanged=False, packet_business_definitions_unchanged=True, packet_helper_paths_rebound=True,
        terminal_definitions_unchanged=True, original_proc_unchanged=True, all_business_methods_unchanged=True,
        device_accessed=False, target_definitions_executed=0, tests_invoked=0, rf_requested=False, stager_included=False)
    outputs = [dict(path=PREFIX + '/runtime/' + role + '.py', raw=changed[role]) for role in ROLES]
    outputs.append(dict(path=PREFIX + '/assets/observer-source-catalog.json', raw=catalog_raw))
    outputs.append(dict(path=PREFIX + '/assets/delta.json', raw=encoded(dict(
        schema='p011-go-observer-native-v2-exact-delta', roles=source_proofs, catalog_edits=catalog_edits,
        catalog_complete_byte_inverse=True, changed_assets=4, unchanged_assets=37, parent_outside_assets=True))))
    outputs.append(dict(path=PREFIX + '/assets/generation.json', raw=encoded(dict(
        schema='p011-go-observer-native-v2-generation', generated_by=SELF, facts=facts,
        outputs=[dict(path=item['path'], bytes=pin(item['raw'])[0], sha256=pin(item['raw'])[1]) for item in outputs]))))
    need(len(outputs) == len({item['path'] for item in outputs}) == 8, 'eight_exclusive_outputs')
    return dict(files=tuple(outputs), facts=facts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Exclusively create the one fresh source prefix; never execute target code.')
    args = parser.parse_args(argv)
    inputs = load_inputs()
    result = assemble(inputs)
    if args.write:
        destination = local(PREFIX)
        need(not destination.exists(), 'new_prefix_exists')
        destination.mkdir()
        (destination / 'runtime').mkdir()
        (destination / 'assets').mkdir()
        for item in result['files']:
            with local(item['path']).open('xb') as handle:
                need(handle.write(item['raw']) == len(item['raw']), 'short_pc_write')
        for item in result['files']:
            need(local(item['path']).read_bytes() == item['raw'], 'pc_readback')
    # Every original source must still match the exact captured bytes.
    for path, raw in inputs.items():
        need(local(path).read_bytes() == raw, 'source_changed')
    print(json.dumps(dict(mode='WRITE_SOURCE_ONLY' if args.write else 'SOURCE_ONLY_NO_WRITE',
        files=[dict(path=item['path'], bytes=pin(item['raw'])[0], sha256=pin(item['raw'])[1])
               for item in result['files']], facts=result['facts']), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
