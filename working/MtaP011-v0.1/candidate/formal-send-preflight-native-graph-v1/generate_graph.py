"""Fixed PC source composition; default dry, explicit --write is EXCL only.

The fresh readonly Parent and cleanup-only Owner are already separate sources.
This graph only propagates their actual pins and independent ordinary/observer
paths. Sender27, FileCenter9, private Proc, helpers, GUI and binaries stay exact.
No source main, verifier, suite, build, subprocess, transport, device or RF runs.
"""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/formal-send-preflight-native-graph-v1/generate_graph.py'
OLD = 'candidate/formal-send-filecenter-deploy-v6'
NEW = 'candidate/formal-send-filecenter-deploy-v7'
OLD_NAME = 'p011-mta-formal-send-filecenter-deploy-v6'
NEW_NAME = 'p011-mta-formal-send-filecenter-deploy-v7'
OLD_ROOT, NEW_ROOT = '/tmp/' + OLD_NAME, '/tmp/' + NEW_NAME
OLD_PHYSICAL, NEW_PHYSICAL = '/var/volatile/tmp/' + OLD_NAME, '/var/volatile/tmp/' + NEW_NAME
OLD_OBSERVER_ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
OBSERVER_ROOT = '/var/volatile/tmp/p011-mta-go-observer-native-v2'
NATIVE_ROOT = '/var/volatile/tmp/p011-mta-go-readonly-native-v1'
CATALOG = (OLD + '/assets/ordinary-source-manifest.json', 20796,
           'd2300225159796bee6f6d2664ba86cdd1d13f8033899596effeb0431c7633052')
STAGE = (OLD + '/runtime/formal_send_stage.py', 37417,
         '49e9f972d093d7f7749f5dd4a38558a73cc0e36ea894e558455238aeb8f840da')
ASSETS = ('candidate/formal-send-filecenter-deploy-v4/assets/asset-sources.json', 24267,
          'be76740f8d7283e2db5806790c87997dee24a0911beb1306d7c9833086745ec0')
OLD_OBSERVER = ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json', 15861,
                '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')
OBSERVER = ('candidate/go-observer-native-v2/assets/observer-source-catalog.json', 15982,
            '72b817785e3986f29792d5ef5a0f0557ef5324e877b1a0668def79c3a7013560')
PARENT = ('candidate/go-observer-native-v2/runtime/mta_go_readonly_parent.py', 52886,
          '1e7279cbfb60db5a7bf5058f33e366df00d85162c61159e0884790ae9f8d0b1f')
OBSERVER_GENERATION = ('candidate/go-observer-native-v2/assets/generation.json', 11691,
                       '42ff5072c5e472d6027dc5d60988c57f174cc49706d77ee9e41a32162c54c22b')
OBSERVER_DELTA = ('candidate/go-observer-native-v2/assets/delta.json', 10366,
                  '07c1a310b527d2a87940b782c8d6a9d8db8e891f65ed11797e54f2f40403bbcb')
FILECENTER = ('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json', 2466,
              '14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')
MOTHER = ('candidate/formal-send-cancel-graph-v1/generate_graph.py', 26849,
          'b6f4d51c451461cc9627e432699ccf5afe51496d24d7dd2f1da783520ba58d5a')
OWNER_SOURCE = ('candidate/formal-send-failed-preflight-close-v1/runtime/mta_client_service_owner.py', 103872,
                '97155c28caab79f579f4549439dabfe959dc9093a159238deee5f0157a62176e')
OWNER_DELTA = ('candidate/formal-send-failed-preflight-close-v1/exactsource-delta.json', 33671,
               '3643fc150d922268ce27a0d22c1b7392857572961b77a8eec74fc4360cb206f6')
BOOT, OWNER, OUTER, PARENT_ROLE = ('mta_client_receive_boot', 'mta_client_service_owner',
                                  'formal_send_session', 'mta_go_readonly_parent')
ROOT_ROLES = ('mta_send_trial', 'mta_send_terminal_consumer', 'mta_service')
GENERATED_ROLES = (PARENT_ROLE,) + ROOT_ROLES + (BOOT, OWNER, OUTER)
OBSERVER_CHANGED = ('mta_go_readonly_preflight', 'mta_go_readonly_loader',
                    'mta_observer_packet', 'mta_go_readonly_entry')
HELPERS = frozenset(('need', 'digest', 'pin', 'literal', 'ast_shape', 'definitions',
                     'replace', 'replay', 'tuple_pin_line', 'rows_from_catalog'))


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return len(raw), digest(raw)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def read_fixed(inputs, row):
    relative, size, checksum = row
    parts = PurePosixPath(relative)
    need(not parts.is_absolute() and '..' not in parts.parts and str(parts) == relative, 'input_path')
    path = BASE / relative
    need(path.resolve() == path and stat.S_ISREG(path.lstat().st_mode) and
         not path.is_symlink(), 'input_identity')
    raw = path.read_bytes()
    need(pin(raw) == (size, checksum), 'input_pin:' + relative)
    need(relative not in inputs or inputs[relative] == raw, 'duplicate_input_changed')
    inputs[relative] = raw
    return raw


def mechanical_helpers(inputs):
    raw = read_fixed(inputs, MOTHER)
    tree = ast.parse(raw.decode('utf-8'))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in HELPERS]
    need(len(selected) == len(HELPERS) and {node.name for node in selected} == HELPERS, 'helper_roster')
    namespace = dict(ast=ast, hashlib=hashlib)
    # Only finite byte/AST arithmetic definitions; no old module, compose/main,
    # verifier or business definition executes or enters a canonical namespace.
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<fixed-mechanical-graph-helpers>', 'exec'), namespace)
    return namespace


def definition_locations(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    rows = []
    def visit(body, prefix):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                name = prefix + node.name
                rows.append((name, type(node).__name__, node.lineno, node.end_lineno))
                visit(node.body, name + '.')
    visit(tree.body, '')
    return tuple(rows)


def source_record(helper, source, destination, before, after, changes):
    need(helper['replay'](before, changes) == after and
         helper['replay'](after, changes, True) == before, 'source_byte_inverse')
    restored = helper['replay'](after, changes, True)
    need(helper['ast_shape'](restored) == helper['ast_shape'](before) and
         definition_locations(before) == definition_locations(after), 'source_definition_inverse')
    return dict(source=[source, len(before), digest(before)],
        candidate=[destination, len(after), digest(after)], replacements=changes,
        exact_bytes_forward=True, exact_bytes_reverse=True,
        complete_ast_inverse=True, definition_names_and_lines_unchanged=True)


def json_record(helper, source, destination, before, after, changes, expected):
    need(helper['replay'](before, changes) == after and
         helper['replay'](after, changes, True) == before and
         json.loads(after) == expected, 'catalog_exact_inverse')
    return dict(source=[source, len(before), digest(before)],
        candidate=[destination, len(after), digest(after)], replacements=changes,
        exact_bytes_forward=True, exact_bytes_reverse=True, exact_selected_json_changes=True)


def json_pin(helper, raw, changes, name, before, after, indent=6):
    prefix = ' ' * indent
    pattern = ('"source": "%s",\n%s"bytes": %d,\n%s"sha256": "%s"')
    left = pattern % (before[0], prefix, before[1], prefix, before[2])
    right = pattern % (after[0], prefix, after[1], prefix, after[2])
    return helper['replace'](raw, changes, name, left, right)


def preserved(inputs):
    need(all((BASE / path).read_bytes() == raw for path, raw in inputs.items()), 'input_changed')


def verified_owner(inputs, original):
    current = read_fixed(inputs, OWNER_SOURCE)
    delta = json.loads(read_fixed(inputs, OWNER_DELTA))
    origin = [OLD + '/runtime/mta_client_service_owner.py', len(original), digest(original)]
    need(delta['schema'] == 'p011-formal-send-failed-preflight-close-v1-exact-source-delta' and
         delta['origin'] == origin and delta['candidate'] == list(OWNER_SOURCE) and
         delta['replacement_count'] == len(delta['replacements']) == 4 and
         delta['changed_original_methods'] == ['__init__', '_prepare_send_trial', '_close_directories'] and
         delta['new_private_methods'] == ['_failed_preflight_closed_receipt',
                                           '_failed_preflight_directory_release_closed'] and
         delta['original_root_boot_and_asset_pins_unchanged'] is True and
         delta['closed_receipt_is_cleanup_only'] is True and
         delta['business_unknown_failure_and_report_retained'] is True and
         delta['new_parent_method_clock_syscall_status_invocations'] == 0, 'owner_business_contract')
    changes = delta['replacements']
    need([row['name'] for row in changes] == ['__init__', '_prepare_send_trial', '_close_directories',
                                             'two_private_helpers'], 'owner_delta_names')
    forward, reverse = original, current
    for row in changes:
        before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(row['count'] == 1 and forward.count(before) == 1, 'owner_forward_count')
        forward = forward.replace(before, after, 1)
    for row in reversed(changes):
        before, after = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        need(reverse.count(after) == 1, 'owner_reverse_count')
        reverse = reverse.replace(after, before, 1)
    need(forward == current and reverse == original, 'owner_full_byte_inverse')
    removed = {'__init__', '_prepare_send_trial', '_close_directories',
               '_failed_preflight_closed_receipt', '_failed_preflight_directory_release_closed'}
    def shape(raw):
        tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        classes = [row for row in tree.body if isinstance(row, ast.ClassDef) and
                   row.name == 'FixedStateServiceOwner']
        need(len(classes) == 1, 'owner_class')
        classes[0].body = [row for row in classes[0].body if
            not (isinstance(row, ast.FunctionDef) and row.name in removed)]
        return ast.dump(tree, include_attributes=False)
    need(shape(current) == shape(original), 'owner_other_ast_unchanged')
    return current, dict(source=list(OWNER_SOURCE), delta=list(OWNER_DELTA),
        origin=origin, exact_bytes_forward=True, exact_bytes_reverse=True,
        other_ast_unchanged=True, cleanup_only_not_admission=True)


def compose():
    inputs, outputs, records = {}, {}, []
    self_raw = (BASE / SELF).read_bytes()
    read_fixed(inputs, (SELF, len(self_raw), digest(self_raw)))
    helper = mechanical_helpers(inputs)
    literal, replace = helper['literal'], helper['replace']
    raw_catalog, raw_stage, raw_assets, raw_old_observer, raw_observer, raw_parent, raw_fc = (
        read_fixed(inputs, row) for row in (CATALOG, STAGE, ASSETS, OLD_OBSERVER, OBSERVER, PARENT, FILECENTER))
    generation = json.loads(read_fixed(inputs, OBSERVER_GENERATION))
    read_fixed(inputs, OBSERVER_DELTA)
    catalog, assets, old_observer, observer, fc = map(json.loads,
        (raw_catalog, raw_assets, raw_old_observer, raw_observer, raw_fc))
    need(catalog['schema'] == 'p011-formal-send-filecenter-deploy-v6-ordinary-source-catalog' and
         catalog['source_count'] == len(catalog['sources']) == 32 and
         catalog['ordinary_source_bytes'] == 1078686 and
         catalog['ordinary_root'] == OLD_ROOT + '/runtime' and
         catalog['physical_ordinary_root'] == OLD_PHYSICAL + '/runtime' and
         (catalog['ordinary_batch_files'], catalog['ordinary_batch_bytes']) == (37, 1353776) and
         len(catalog['startup_sources']) == len(catalog['helper_sources']) == 3 and
         catalog['original_boot_load_seconds'] == 10 and
         catalog['original_per_source_cap_bytes'] == catalog['program_cap_bytes'] == 2097152 and
         catalog['wire_cap_bytes'] == 4194304 and catalog['source_pins_do_not_admit_rf'] is True and
         catalog['asset_payload_inline'] is False, 'ordinary_catalog')
    need((catalog['separate_asset_catalog']['source'], catalog['separate_asset_catalog']['bytes'],
          catalog['separate_asset_catalog']['sha256']) == ASSETS and
         (catalog['filecenter_source_manifest']['source'], catalog['filecenter_source_manifest']['bytes'],
          catalog['filecenter_source_manifest']['sha256']) == FILECENTER, 'catalog_input_pins')
    need(observer['root'] == OBSERVER_ROOT and observer['source_count'] == len(observer['files']) == 41 and
         observer['source_bytes'] == sum(row['bytes'] for row in observer['files']) == 1548495 and
         observer['load_count'] == 38 and observer['unchanged_asset_count'] == 37 and
         tuple(observer['changed_asset_modules']) == OBSERVER_CHANGED and
         (observer['parent_inline_only']['source'], observer['parent_inline_only']['bytes'],
          observer['parent_inline_only']['sha256']) == PARENT and
         observer['parent_inline_only']['not_in_asset_files'] is True and
         observer['original_readonly_manifest_bytes'] == 8096 and
         observer['original_readonly_manifest_sha256'] ==
         '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60', 'fresh_observer')
    facts = generation['facts']
    need(facts['root'] == OBSERVER_ROOT and facts['native_root'] == NATIVE_ROOT and
         facts['source_count'] == 41 and facts['source_bytes'] == 1548495 and
         facts['original_proc_unchanged'] is True and facts['all_business_methods_unchanged'] is True,
         'observer_generation')
    need(old_observer['root'] == assets['observer_root'] == OLD_OBSERVER_ROOT and
         old_observer['source_count'] == len(old_observer['files']) == 41 and
         old_observer['source_bytes'] == assets['observer_source_bytes'] == 1442508 and
         assets['sender_root'] == '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets' and
         assets['observer_source_table'] == list(OLD_OBSERVER), 'original_private_mapping')
    old_files = {row['module']: row for row in old_observer['files']}
    new_files = {row['module']: row for row in observer['files']}
    need(len(old_files) == len(new_files) == 41 and set(old_files) == set(new_files), 'observer_roles')
    changed_observer = []
    for role, row in new_files.items():
        raw = read_fixed(inputs, (row['source'], row['bytes'], row['sha256']))
        old = old_files[role]
        original = read_fixed(inputs, (old['source'], old['bytes'], old['sha256']))
        if raw != original:
            changed_observer.append(role)
        else:
            need((row['source'], row['bytes'], row['sha256']) ==
                 (old['source'], old['bytes'], old['sha256']), 'unchanged_observer_source')
        need(row['target'] == OBSERVER_ROOT + '/runtime/' + role + '.py', 'observer_target')
    need(tuple(changed_observer) == OBSERVER_CHANGED, 'observer_exact_four')
    body = inputs[new_files['mta_go_readonly_preflight']['source']]
    packet = inputs[new_files['mta_observer_packet']['source']]
    need(literal(body, 'ROOT') == OBSERVER_ROOT and literal(body, 'STATE_ROOT') == NATIVE_ROOT and
         literal(body, 'DEVICE_LOCK') == '/var/volatile/tmp/p011-mta-p2p-device.lock' and
         literal(packet, 'HELPERS') == (
             (NATIVE_ROOT + '/native/mta-bluez-helper',
              '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
             (NATIVE_ROOT + '/native/mta-network-helper',
              'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6')),
         'native_source_paths')
    ordinary = {}
    for item in catalog['sources'] + catalog['startup_sources'] + catalog['helper_sources']:
        raw = read_fixed(inputs, (item['source'], item['bytes'], item['sha256']))
        if 'module' in item:
            need(item['module'] not in ordinary, 'ordinary_duplicate')
            ordinary[item['module']] = (item, raw)
    need(len(ordinary) == 35, 'ordinary_roles')
    root_counts = dict((role, 1) for role in ROOT_ROLES)
    root_counts.update({BOOT: 2, OWNER: 2, OUTER: 2})
    need(all(raw.count(OLD_NAME.encode('ascii')) == root_counts.get(role, 0)
             for role, (item, raw) in ordinary.items()) and
         raw_stage.count(OLD_NAME.encode('ascii')) == 1, 'exact_root_scope')
    old_rows = helper['rows_from_catalog'](catalog, OLD_PHYSICAL)
    sender_rows = []
    for item in assets['sender_sources'] + [assets['sender_manifest'], assets['wpa']]:
        raw = read_fixed(inputs, (item['source'], item['bytes'], item['sha256']))
        need(item['target'].startswith(assets['sender_root'] + '/'), 'sender_target')
        sender_rows.append((item['target'][len(assets['sender_root']) + 1:], len(raw), digest(raw),
                            int(item.get('mode', '0400'), 8)))
    old_observer_rows = tuple(('runtime/' + row['module'] + '.py', row['bytes'], row['sha256'], 256)
                              for row in old_observer['files'])
    observer_rows = tuple(('runtime/' + row['module'] + '.py', row['bytes'], row['sha256'], 256)
                          for row in observer['files'])
    table = literal(raw_stage, 'PROFILE_FILES')
    need(len(sender_rows) == 27 and sum(row[1] for row in sender_rows) == 2402458 and
         table == (('sender', assets['sender_root'], tuple(sender_rows)),
                   ('observer', OLD_OBSERVER_ROOT, old_observer_rows),
                   ('ordinary', OLD_PHYSICAL, old_rows)) and
         literal(raw_stage, 'PROFILE_TOTALS') == (
             ('sender', 27, 2402458), ('observer', 41, 1442508), ('ordinary', 37, 1353776)) and
         literal(raw_stage, 'MAX_SECONDS') == 120.0, 'original_stage_profiles')
    fc_rows = tuple((row['module'], row['bytes'], row['sha256']) for row in fc['sources'])
    need(fc['source_count'] == len(fc_rows) == 9 and fc['source_bytes'] ==
         sum(row[1] for row in fc_rows) == 99972 and fc['source_cap'] == 131072 and
         literal(ordinary[OWNER][1], 'FILECENTER_PINS') == fc_rows, 'filecenter9')
    for row in fc['sources']:
        read_fixed(inputs, (row['source'], row['bytes'], row['sha256']))
    owner_raw, owner_contract = verified_owner(inputs, ordinary[OWNER][1])
    changed = {}
    def retain(role, origin_path, before, after, changes):
        destination = NEW + '/runtime/' + role + '.py'
        records.append(source_record(helper, origin_path, destination, before, after, changes))
        outputs[destination] = changed[role] = after
    # Copy the actual fresh Parent after proving its narrow old-source inverse.
    old_parent = ordinary[PARENT_ROLE][1]
    parent_changes = []
    rebuilt_parent = replace(old_parent, parent_changes, 'fresh_parent_root',
        'p011-mta-go-observer-libc-v1', 'p011-mta-go-observer-native-v2', 2)
    old, new = old_files['mta_observer_packet'], new_files['mta_observer_packet']
    rebuilt_parent = helper['tuple_pin_line'](rebuilt_parent, parent_changes, 'parent_packet',
        (old['bytes'], old['sha256']), (new['bytes'], new['sha256']), 'mta_observer_packet')
    old, new = old_files['mta_go_readonly_entry'], new_files['mta_go_readonly_entry']
    rebuilt_parent = replace(rebuilt_parent, parent_changes, 'parent_entry',
        "ENTRY_PIN = ('mta_go_readonly_entry', %d,\n             '%s')" % (old['bytes'], old['sha256']),
        "ENTRY_PIN = ('mta_go_readonly_entry', %d,\n             '%s')" % (new['bytes'], new['sha256']))
    need(rebuilt_parent == raw_parent, 'actual_parent_copy')
    retain(PARENT_ROLE, ordinary[PARENT_ROLE][0]['source'], old_parent, raw_parent, parent_changes)
    for role in ROOT_ROLES:
        changes = []
        raw = replace(ordinary[role][1], changes, 'independent_ordinary_root', OLD_NAME, NEW_NAME)
        retain(role, ordinary[role][0]['source'], ordinary[role][1], raw, changes)
    changes = []
    raw = replace(ordinary[BOOT][1], changes, 'independent_boot_root', OLD_NAME, NEW_NAME, 2)
    for role in (PARENT_ROLE,) + ROOT_ROLES:
        raw = helper['tuple_pin_line'](raw, changes, role, pin(ordinary[role][1]), pin(changed[role]), role)
    retain(BOOT, ordinary[BOOT][0]['source'], ordinary[BOOT][1], raw, changes)
    expected_boot = tuple((row['module'],) + (pin(changed[row['module']]) if row['module'] in changed else
                          (row['bytes'], row['sha256'])) for row in catalog['sources'])
    need(literal(raw, 'SOURCE_PINS') == expected_boot and len(expected_boot) == 32 and
         literal(raw, 'LOAD_SECONDS') == 10.0, 'boot_actual_closure')
    changes = []
    raw = replace(owner_raw, changes, 'independent_owner_root', OLD_NAME, NEW_NAME, 2)
    raw = helper['tuple_pin_line'](raw, changes, 'BOOT_PIN', pin(ordinary[BOOT][1]), pin(changed[BOOT]))
    raw = replace(raw, changes, 'fresh_owner_observer_paths', OLD_OBSERVER_ROOT, OBSERVER_ROOT, 43)
    for role in OBSERVER_CHANGED:
        old, new = old_files[role], new_files[role]
        path = OBSERVER_ROOT + '/runtime/' + role + '.py'
        raw = replace(raw, changes, 'owner_observer_pin_' + role,
            '("%s", %d, \'%s\', 0o400)' % (path, old['bytes'], old['sha256']),
            '("%s", %d, \'%s\', 0o400)' % (path, new['bytes'], new['sha256']))
    retain(OWNER, OWNER_SOURCE[0], owner_raw, raw, changes)
    original_fixed = literal(owner_raw, 'FIXED_ASSET_PINS')
    expected_fixed = []
    for path, size, checksum, mode in original_fixed:
        if path.startswith(OLD_OBSERVER_ROOT + '/'):
            role = path.rsplit('/', 1)[1][:-3]
            row = new_files[role]
            path, size, checksum = row['target'], row['bytes'], row['sha256']
        expected_fixed.append((path, size, checksum, mode))
    need(literal(raw, 'FIXED_ASSET_PINS') == tuple(expected_fixed) and
         literal(raw, 'FILECENTER_PINS') == fc_rows and literal(raw, 'CLEANUP_SECONDS') == 60.0 and
         all(literal(raw, name) == literal(owner_raw, name) for name in ('HELPER_PINS', 'CONNMAN_PIN')),
         'owner_actual_private_closure')
    changes = []
    raw = replace(ordinary[OUTER][1], changes, 'independent_outer_root', OLD_NAME, NEW_NAME, 2)
    for name, role in (('BOOT_PIN', BOOT), ('OWNER_PIN', OWNER)):
        raw = helper['tuple_pin_line'](raw, changes, name, pin(ordinary[role][1]), pin(changed[role]))
    retain(OUTER, ordinary[OUTER][0]['source'], ordinary[OUTER][1], raw, changes)
    need(literal(raw, 'PROFILES') == (('diagnostic', 60.0, False), ('send-interactive-v1', 600.0, True)),
         'outer_original_profiles')
    return finish_graph(inputs, outputs, records, changed, helper, catalog, raw_catalog,
        assets, raw_assets, observer, table, raw_stage, ordinary, sender_rows, observer_rows, owner_contract)


def write_exclusive(inputs, outputs):
    target = BASE / NEW
    need(target.parent.resolve() == BASE / 'candidate' and
         not target.exists() and not target.is_symlink(), 'output_root_identity')
    preserved(inputs)
    target.mkdir(mode=0o700, exist_ok=False)
    for child in ('runtime', 'assets'):
        (target / child).mkdir(mode=0o700, exist_ok=False)
    # A partial failure remains intact; no deletion, repair, overwrite or retry.
    for relative, raw in sorted(outputs.items()):
        path = BASE / relative
        need(path.parent.resolve() in (target, target / 'runtime', target / 'assets') and
             not path.exists() and not path.is_symlink(), 'output_path_identity')
        with path.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'output_write')
        need(path.read_bytes() == raw, 'output_readback')
    preserved(inputs)
    need({str(path.relative_to(BASE)).replace('\\', '/') for path in target.rglob('*')
          if path.is_file()} == set(outputs), 'output_inventory')


def finish_graph(inputs, outputs, records, changed, helper, catalog, raw_catalog,
                 assets, raw_assets, observer, table, raw_stage, ordinary,
                 sender_rows, observer_rows, owner_contract):
    replace, literal = helper['replace'], helper['literal']
    changes = []
    new_assets = replace(raw_assets, changes, 'asset_catalog_schema',
        'p011-formal-send-filecenter-deploy-v4-fixed-asset-sources',
        'p011-formal-send-filecenter-deploy-v7-fixed-asset-sources')
    old_table = ('"observer_source_table": [\n    "%s",\n    %d,\n    "%s"\n  ]') % OLD_OBSERVER
    new_table = ('"observer_source_table": [\n    "%s",\n    %d,\n    "%s"\n  ]') % OBSERVER
    new_assets = replace(new_assets, changes, 'fresh_asset_source_table', old_table, new_table)
    new_assets = replace(new_assets, changes, 'fresh_asset_observer_paths',
                         OLD_OBSERVER_ROOT, OBSERVER_ROOT, 42)
    expected_assets = copy.deepcopy(assets)
    expected_assets['schema'] = 'p011-formal-send-filecenter-deploy-v7-fixed-asset-sources'
    expected_assets['observer_source_table'] = list(OBSERVER)
    expected_assets['observer_root'] = OBSERVER_ROOT
    expected_assets['observer_source_bytes'] = 1548495
    files = {row['module']: row for row in observer['files']}
    for index, original in enumerate(assets['observer_sources']):
        updated = files[original['module']]
        if original['module'] in OBSERVER_CHANGED:
            pattern = ('"source": "%s",\n      "target": "%s",\n'
                       '      "bytes": %d,\n      "sha256": "%s"')
            before = pattern % (original['source'], updated['target'], original['bytes'], original['sha256'])
            after = pattern % (updated['source'], updated['target'], updated['bytes'], updated['sha256'])
            new_assets = replace(new_assets, changes, 'asset_source_' + original['module'], before, after)
        expected_assets['observer_sources'][index] = {key: updated[key] for key in original}
    new_assets = replace(new_assets, changes, 'asset_observer_bytes',
                         '"observer_source_bytes": 1442508', '"observer_source_bytes": 1548495')
    note_changes = (
        (2, 'Observer41 uses the isolated libc-v1 root: only Body/Loader/Entry differ, the other 38 assets retain original bytes.',
         'Observer41 uses the isolated native-v2 root: four actual source pins differ, the other 37 assets retain original bytes.'),
        (4, 'Ordinary Parent reuses the actually passed readonly child candidate; that is not whole v4 Owner/UI evidence.',
         'Ordinary Parent is the fixed fresh native-v2 readonly child candidate; source linkage is not whole Owner/UI evidence.'))
    for index, before, after in note_changes:
        need(assets['notes'][index] == before, 'original_asset_note')
        new_assets = replace(new_assets, changes, 'asset_note_' + str(index), before, after)
        expected_assets['notes'][index] = after
    asset_destination = NEW + '/assets/asset-sources.json'
    records.append(json_record(helper, ASSETS[0], asset_destination,
                               raw_assets, new_assets, changes, expected_assets))
    outputs[asset_destination] = new_assets
    need(expected_assets['sender_sources'] == assets['sender_sources'] and
         expected_assets['sender_manifest'] == assets['sender_manifest'] and
         expected_assets['wpa'] == assets['wpa'], 'sender_catalog_exact')
    ordinary_bytes = 1078686 + sum(len(changed[role]) - len(ordinary[role][1])
                                  for role in (PARENT_ROLE,) + ROOT_ROLES)
    staged_bytes = 1353776 + sum(len(raw) - len(ordinary[role][1]) for role, raw in changed.items())
    changes = []
    new_catalog = replace(raw_catalog, changes, 'ordinary_catalog_schema',
        'p011-formal-send-filecenter-deploy-v6-ordinary-source-catalog',
        'p011-formal-send-filecenter-deploy-v7-ordinary-source-catalog')
    new_catalog = replace(new_catalog, changes, 'ordinary_catalog_roots',
                          OLD_NAME, NEW_NAME, raw_catalog.count(OLD_NAME.encode('ascii')))
    for role in GENERATED_ROLES:
        row = ordinary[role][0]
        new_catalog = json_pin(helper, new_catalog, changes, 'ordinary_source_' + role,
            (row['source'], row['bytes'], row['sha256']),
            (NEW + '/runtime/' + role + '.py', len(changed[role]), digest(changed[role])))
    new_catalog = json_pin(helper, new_catalog, changes, 'new_asset_catalog_pin',
                           ASSETS, (asset_destination, len(new_assets), digest(new_assets)), indent=4)
    for name, before, after in (('ordinary_source_bytes', 1078686, ordinary_bytes),
                                ('ordinary_batch_bytes', 1353776, staged_bytes)):
        new_catalog = replace(new_catalog, changes, name,
                              '"%s": %d' % (name, before), '"%s": %d' % (name, after))
    expected_catalog = copy.deepcopy(catalog)
    expected_catalog.update(schema='p011-formal-send-filecenter-deploy-v7-ordinary-source-catalog',
        ordinary_root=NEW_ROOT + '/runtime', physical_ordinary_root=NEW_PHYSICAL + '/runtime',
        ordinary_source_bytes=ordinary_bytes, ordinary_batch_bytes=staged_bytes)
    for group in ('sources', 'startup_sources', 'helper_sources'):
        for row in expected_catalog[group]:
            for name in ('target', 'physical_target'):
                row[name] = row[name].replace(OLD_NAME, NEW_NAME)
            role = row.get('module')
            if role in changed:
                row['source'] = NEW + '/runtime/' + role + '.py'
                row['bytes'], row['sha256'] = pin(changed[role])
    expected_catalog['separate_asset_catalog'].update(
        source=asset_destination, bytes=len(new_assets), sha256=digest(new_assets))
    catalog_destination = NEW + '/assets/ordinary-source-manifest.json'
    records.append(json_record(helper, CATALOG[0], catalog_destination,
                               raw_catalog, new_catalog, changes, expected_catalog))
    outputs[catalog_destination] = new_catalog
    new_rows = helper['rows_from_catalog'](expected_catalog, NEW_PHYSICAL)
    need(len(new_rows) == 37 and sum(row[1] for row in new_rows) == staged_bytes and
         sum(row['bytes'] for row in expected_catalog['sources']) == ordinary_bytes and
         [row for row in expected_catalog['sources'] if row['reused_sender_asset']] ==
         [row for row in catalog['sources'] if row['reused_sender_asset']], 'actual_ordinary_totals')
    changes = []
    stage = replace(raw_stage, changes, 'independent_stage_root', OLD_NAME, NEW_NAME)
    stage = replace(stage, changes, 'fresh_stage_observer_root', OLD_OBSERVER_ROOT, OBSERVER_ROOT)
    old_observer = {row['module']: row for row in assets['observer_sources']}
    for role in OBSERVER_CHANGED:
        old, new = old_observer[role], files[role]
        stage = helper['tuple_pin_line'](stage, changes, 'observer_' + role,
            (old['bytes'], old['sha256']), (new['bytes'], new['sha256']),
            'runtime/' + role + '.py', double_quotes=True, tail=', 256')
    for role in GENERATED_ROLES:
        stage = helper['tuple_pin_line'](stage, changes, 'ordinary_' + role,
            pin(ordinary[role][1]), pin(changed[role]), 'runtime/' + role + '.py',
            double_quotes=True, tail=', 256')
    for name, before, after in (('observer', 1442508, 1548495), ('ordinary', 1353776, staged_bytes)):
        stage = replace(stage, changes, 'stage_total_' + name,
            "('%s', %d, %d)" % (name, 41 if name == 'observer' else 37, before),
            "('%s', %d, %d)" % (name, 41 if name == 'observer' else 37, after))
    stage_destination = NEW + '/runtime/formal_send_stage.py'
    records.append(source_record(helper, STAGE[0], stage_destination, raw_stage, stage, changes))
    outputs[stage_destination] = stage
    need(literal(stage, 'PROFILE_FILES') == (table[0], ('observer', OBSERVER_ROOT, observer_rows),
         ('ordinary', NEW_PHYSICAL, new_rows)) and literal(stage, 'PROFILE_TOTALS') == (
             ('sender', 27, 2402458), ('observer', 41, 1548495), ('ordinary', 37, staged_bytes)) and
         literal(stage, 'MAX_SECONDS') == 120.0, 'stage_actual_closure')
    need(len(outputs) == 10 and len(changed) == 7 and
         len(records) == 10 and all(path.startswith(NEW + '/') and len(raw) <= 2097152
         for path, raw in outputs.items()), 'generated_scope')
    for path, raw in outputs.items():
        if path.endswith('.py'):
            ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    preserved(inputs)
    input_rows = [[path, len(raw), digest(raw)] for path, raw in sorted(inputs.items())]
    delta = dict(schema='p011-formal-send-preflight-native-graph-v1-exactsource',
        generator=[SELF, len(inputs[SELF]), digest(inputs[SELF])], inputs=input_rows,
        files=records, owner_business_contract=owner_contract, graph_business_edits=0,
        ordinary_roles_changed=list((PARENT_ROLE,) + ROOT_ROLES), ordinary_roles_reused=28,
        startup_roles_changed=[BOOT, OWNER, OUTER], observer_asset_changes=4, observer_assets_reused=37,
        sender27_exact=True, filecenter9_exact=True, private_proc_unchanged=True,
        source_byte_and_ast_inverse=True, target_code_not_executed=True)
    report = dict(schema='p011-formal-send-preflight-native-graph-v1-generation',
        scope='SOURCE_ONLY_NOT_STAGED_NOT_RUN', original_root=OLD_ROOT, root=NEW_ROOT,
        physical_root=NEW_PHYSICAL, observer_root=OBSERVER_ROOT, native_root=NATIVE_ROOT,
        generator=[SELF, len(inputs[SELF]), digest(inputs[SELF])],
        ordinary_roles=32, ordinary_source_bytes=ordinary_bytes, staged_files=37, staged_bytes=staged_bytes,
        sender_files=27, sender_bytes=2402458, observer_files=41, observer_bytes=1548495,
        observer_changes=4, observer_reused=37, helpers=3, filecenter_files=9, filecenter_bytes=99972,
        owner_business_source=list(OWNER_SOURCE), owner_business_delta=list(OWNER_DELTA),
        fixed_parent_source=list(PARENT), original_loader_seconds=10, stage_seconds=120,
        original_service_profiles=[['diagnostic', 60.0, False], ['send-interactive-v1', 600.0, True]],
        program_cap_bytes=2097152, wire_cap_bytes=4194304, graph_business_edits=0,
        source_byte_and_ast_inverse=True, business_definitions_executed=False,
        runtime=False, build=False, ui=False, device=False, rf=False, tests_replayed=False,
        input_count=len(input_rows), inputs=input_rows,
        outputs=[[path, len(raw), digest(raw)] for path, raw in sorted(outputs.items())])
    outputs[NEW + '/exactsource-delta.json'] = encoded(delta)
    outputs[NEW + '/generation.json'] = encoded(report)
    need(len(outputs) == 12, 'complete_output_count')
    return inputs, outputs, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='EXCL create only the absent fixed deploy-v7 PC tree')
    args = parser.parse_args()
    inputs, outputs, report = compose()
    if args.write:
        write_exclusive(inputs, outputs)
    result = dict(report, mode='WRITE_SOURCE_ONLY' if args.write else 'SOURCE_PLAN_NO_WRITE',
                  written=bool(args.write), planned_output_count=len(outputs),
                  all_output_readbacks_verified=bool(args.write))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
