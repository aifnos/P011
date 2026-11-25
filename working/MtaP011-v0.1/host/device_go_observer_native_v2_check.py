"""Independent observer/native-path SOURCE, files-only stage and one Parent.

Default and --source-only are PC-only. The fixed TEST stages the fresh observer
41-file root before one original Parent call; native staging is a separate
explicit phase and is not performed here. Four source assets change fixed
paths/pins, 37 stay exact and inline Parent is outside the 41. Original Proc,
private failure DATA, packet methods, periods, close/finally and FAIL remain.
Only this new report receives actual observer bytes after payload preparation.
Old sources/reports/ZIPs are retained. No old main, suite, Owner, UI or RF runs.
"""
import ast
import hashlib
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_observer_native_v2_check.py'
SOURCE_CMD = 'HOST_MTA_GO_OBSERVER_NATIVE_V2_SOURCE_CHECK.cmd'
TEST_CMD = 'TEST_MTA_GO_OBSERVER_NATIVE_V2.cmd'
HOST_ORIGIN = ('host/device_go_observer_diag_v1_check.py', 17848,
               '803b1644e1c867e04bbc40701a1dd008b079fcc41f76ea719e2590d912f7691a')
DERIVER = ('host/go_observer_native_v2_source.py', 19941,
           'f8e04fc2fcffcea4d5bf6616be323c774f803850ff5a861567b4a5d21913de5e')
ROOT = '/var/volatile/tmp/p011-mta-go-observer-native-v2'
NATIVE_ROOT = '/var/volatile/tmp/p011-mta-go-readonly-native-v1'
PREFIX = 'candidate/go-observer-native-v2'
ACTUAL_BYTES = 1548495
ROLES = ('mta_go_readonly_preflight', 'mta_go_readonly_loader',
         'mta_observer_packet', 'mta_go_readonly_entry', 'mta_go_readonly_parent')
ACTUAL_OUTPUTS = (
    (PREFIX + '/runtime/mta_go_readonly_preflight.py', 64962,
     'ad190dff407fcacd06353713c318aa05489f3d2ec2dad6d0f05546a1ef5c5e75'),
    (PREFIX + '/runtime/mta_go_readonly_loader.py', 36547,
     '67fe8e424f5e6caf0ed308970bcfd4225170df2f9b3e2e1d7019e3eefe2ab304'),
    (PREFIX + '/runtime/mta_observer_packet.py', 48277,
     '41fa92e056c0ca6ab4d89b3b0ca6c580f03e29221c271bc4ac1a80150a381853'),
    (PREFIX + '/runtime/mta_go_readonly_entry.py', 151255,
     'd28f4dce77b64cd8d9017d614d1567aeced15aa6f5b50b286cb4cfe4e7905b34'),
    (PREFIX + '/runtime/mta_go_readonly_parent.py', 52886,
     '1e7279cbfb60db5a7bf5058f33e366df00d85162c61159e0884790ae9f8d0b1f'),
    (PREFIX + '/assets/observer-source-catalog.json', 15982,
     '72b817785e3986f29792d5ef5a0f0557ef5324e877b1a0668def79c3a7013560'),
    (PREFIX + '/assets/delta.json', 10366,
     '07c1a310b527d2a87940b782c8d6a9d8db8e891f65ed11797e54f2f40403bbcb'),
    (PREFIX + '/assets/generation.json', 11691,
     '42ff5072c5e472d6027dc5d60988c57f174cc49706d77ee9e41a32162c54c22b'))
HOST_HELPERS = frozenset(('need', 'sha', 'pinned', 'literal', 'definitions',
    'replacement', 'reverse', 'stage_raw', 'selected_mother', 'derive_main', 'payloads'))


def need(value, code='native_host_overlay'):
    if value is not True:
        raise ValueError(code)


def fixed(row):
    raw = (BASE / row[0]).read_bytes()
    need((len(raw), hashlib.sha256(raw).hexdigest()) == row[1:], 'input_pin')
    return raw


def function_raw(raw, tree, name):
    rows = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(rows) == 1)
    node = rows[0]
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def change(raw, rows, label, before, after, count=1):
    need(type(before) is bytes and type(after) is bytes and before != after and
         raw.count(before) == count)
    changed = raw.replace(before, after)
    need(changed.count(after) == count)
    rows.append(dict(label=label, before=before.decode('ascii'), after=after.decode('ascii'), count=count))
    return changed


def proof(changed, changes, original, name):
    inverse = changed
    for row in reversed(changes):
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(inverse.count(after) == row['count'])
        inverse = inverse.replace(after, before)
    need(inverse == original and
         ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(original.decode('ascii')), include_attributes=True))
    return dict(function=name, replacements=changes, complete_byte_ast_inverse=True)


def derive_stage(raw, tree):
    original = function_raw(raw, tree, 'stage_raw')
    rows = []
    changed = change(original, rows, 'four_fixed_asset_pins', b'ROLES[:3]', b'ROLES[:4]', 2)
    changed = change(changed, rows, 'four_changed_assets', b'changed_assets=3', b'changed_assets=4')
    changed = change(changed, rows, '37_unchanged_assets', b'unchanged_assets=38', b'unchanged_assets=37')
    return changed, proof(changed, rows, original, 'stage_raw')


def derive_payloads(raw, tree):
    original = function_raw(raw, tree, 'payloads')
    rows = []
    changed = change(original, rows, 'preserve_fixed_host_and_actual_outputs',
        b'    need(pinned(inputs, MOTHER) == mother_raw)\n',
        b'    need(pinned(inputs, MOTHER) == mother_raw)\n'
        b'    pinned(inputs, HOST_ORIGIN)\n'
        b'    for actual in ACTUAL_OUTPUTS:\n'
        b'        pinned(inputs, actual)\n')
    changed = change(changed, rows, 'native_deriver_without_bridge',
        b'    need(source.bridge_source_inputs() == BRIDGES)\n', b'    need(BRIDGES == ())\n')
    changed = change(changed, rows, 'exact_native_assembler_arguments',
        b'    assembled = source.assemble(frozen, bridge_inputs=bridge_inputs)\n',
        b'    assembled = source.assemble(frozen)\n')
    changed = change(changed, rows, 'eight_actual_outputs', b"len(assembled['files']) == 7", b"len(assembled['files']) == 8")
    changed = change(changed, rows, 'four_37_source_facts',
        b"facts['changed_asset_count'] == 3 and facts['unchanged_asset_count'] == 38",
        b"facts['changed_asset_count'] == 4 and facts['unchanged_asset_count'] == 37")
    changed = change(changed, rows, 'fixed_native_and_actual_total_facts',
        b"need(facts['root'] == ROOT and facts['source_count'] == 41 and\n",
        b"need(facts['root'] == ROOT and facts['source_count'] == 41 and\n"
        b"         facts['native_root'] == NATIVE_ROOT and facts['source_bytes'] == ACTUAL_BYTES and\n")
    changed = change(changed, rows, 'accurate_packet_constant_delta',
        b"facts['original_proc_unchanged'] is True and facts['successful_packet_unchanged'] is True and\n",
        b"facts['original_proc_unchanged'] is True and facts['successful_packet_unchanged'] is False and\n"
        b"         facts['packet_business_definitions_unchanged'] is True and facts['packet_helper_paths_rebound'] is True and\n"
        b"         facts['all_business_methods_unchanged'] is True and\n")
    changed = change(changed, rows, '37_unchanged_catalog_assets',
        b"catalog['unchanged_asset_count'] == 38", b"catalog['unchanged_asset_count'] == 37")
    changed = change(changed, rows, 'four_catalog_asset_roles', b'ROLES[:3]', b'ROLES[:4]', 3)
    changed = change(changed, rows, 'independent_private_contract_namespace',
        b'observer-diag-v1-mechanical-source-contract', b'observer-native-v2-mechanical-source-contract')
    changed = change(changed, rows, 'private_host_overlay_provenance',
        b"        assembler_facts=assembled['facts'],\n",
        b"        assembler_facts=assembled['facts'],\n"
        b"        host_origin=list(HOST_ORIGIN), host_function_overlays=HOST_OVERLAY_PROOFS,\n")
    return changed, proof(changed, rows, original, 'payloads')


def derive_main_factory(raw, tree):
    original = function_raw(raw, tree, 'derive_main')
    rows = []
    changed = change(original, rows, 'new_result_namespace',
        b"b'go-observer-diag-v1-'", b"b'go-observer-native-v2-'")
    changed = change(changed, rows, 'new_report_actual_bytes_after_payloads',
        b'''        b"        write_new(private / 'observer-stage.derived.py', DERIVED_STAGE_RAW)\\n"\n''',
        b'''        b"        report['observer_bytes'] = OBSERVER_BYTES\\n"\n'''
        b'''        b"        write_new(private / 'observer-stage.derived.py', DERIVED_STAGE_RAW)\\n"\n''')
    return changed, proof(changed, rows, original, 'derive_main')


def prepare():
    origin = fixed(HOST_ORIGIN)
    tree = ast.parse(origin.decode('ascii'))
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in HOST_HELPERS]
    need(len(helpers) == len(HOST_HELPERS) and {node.name for node in helpers} == HOST_HELPERS)
    selected = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or node in helpers]
    # Frozen definitions only: the origin's main and __main__ guard are excluded.
    namespace = dict(__file__=str(BASE / HOST_ORIGIN[0]), __name__='observer_native_PC_definitions', __doc__=__doc__)
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<frozen-observer-diag-PC-definitions>', 'exec'), namespace)
    namespace.update(SELF=SELF, SOURCE_CMD=SOURCE_CMD, TEST_CMD=TEST_CMD,
        DERIVER=DERIVER, BRIDGES=(), ROOT=ROOT, PREFIX=PREFIX, ROLES=ROLES,
        HOST_ORIGIN=HOST_ORIGIN, ACTUAL_OUTPUTS=ACTUAL_OUTPUTS, ACTUAL_BYTES=ACTUAL_BYTES,
        NATIVE_ROOT=NATIVE_ROOT)
    overlays = []
    for assembler in (derive_stage, derive_payloads, derive_main_factory):
        source, current = assembler(origin, tree)
        ast.parse(source.decode('ascii'))
        exec(compile(source, '<observer-native-narrow-PC-overlay>', 'exec'), namespace)
        overlays.append(current)
    namespace['HOST_OVERLAY_PROOFS'] = overlays
    mother_raw = namespace['pinned']({}, namespace['MOTHER'])
    driver, mother_tree = namespace['selected_mother'](mother_raw)
    main_raw, main_proof = namespace['derive_main'](mother_raw, mother_tree)
    driver['payloads'] = lambda inputs: namespace['payloads'](inputs, driver, mother_raw, main_proof)
    exec(compile(main_raw, '<independent-observer-native-PC-driver>', 'exec'), driver)
    return driver


def main():
    return prepare()['main']()


if __name__ == '__main__':
    raise SystemExit(main())
