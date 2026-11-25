"""Independent observer diagnostic SOURCE / files-only stage / one Parent.

Default and --source-only are PC-only. The fixed TEST CMD stages the independent
41-file root, and only a zero stage exit permits one --check-device Parent call.
The original Parent failure, packet, period, close/finally and stock gates remain.
Child diagnostic DATA and all source snapshots stay outside the public ZIP.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import types
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_observer_diag_v1_check.py'
SOURCE_CMD = 'HOST_MTA_GO_OBSERVER_DIAG_V1_SOURCE_CHECK.cmd'
TEST_CMD = 'TEST_MTA_GO_OBSERVER_DIAG_V1.cmd'
MOTHER = ('host/device_go_observer_libc_v1_check.py', 30217,
          '078ea42b28465eb58a02cb64589fd2fdba30ed3f46b0fd29f7d4bc6e6c15a1ea')
DERIVER = ('host/go_observer_diag_v3_source.py', 3743,
           '80d9a9ffb23cff4db81342ea77e8f27dbbcd415a9ec6cc836f39958e7ad5b458')
BRIDGES = (('host/go_observer_diag_v1_source.py', 24747,
            'b589880919577a37b7992e56f935a2f8af9967c57eb275a715704e786ce08496'),
           ('host/go_observer_diag_v2_source.py', 5348,
            '1ab4929bc725549edfb87d334150e74145110917051324cb72086052ef6f5ee5'))
OLD_ROOT = '/var/volatile/tmp/p011-mta-go-observer-libc-v1'
ROOT = '/var/volatile/tmp/p011-mta-go-observer-diag-v1'
PREFIX = 'candidate/go-observer-diag-v1'
ROLES = ('mta_go_readonly_preflight', 'mta_go_readonly_loader',
         'mta_go_readonly_entry', 'mta_go_readonly_parent')
OLD_STAGE = ('candidate/go-observer-libc-v1/runtime/formal_observer_stage.py',
             29349, 'c2799754f4d4638a79ec74e5f029550540b3597f1dbab1ddfc4fd077928b206f')
HELPERS = frozenset(('sha', 'need', 'write_new', 'fixed', 'literal', 'module',
                    'selected_generator', 'parent_payload', 'parse_parent',
                    'parent_completed'))


def need(value, code='stage_contract'):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(inputs, row):
    need(type(row) is tuple and len(row) == 3 and type(row[0]) is str and
         type(row[1]) is int and row[1] > 0 and type(row[2]) is str and
         re.fullmatch('[0-9a-f]{64}', row[2]), 'input_pin')
    path, size, digest = row
    raw = (BASE / path).read_bytes()
    need((len(raw), sha(raw)) == (size, digest), 'input_pin')
    if path in inputs:
        need(inputs[path] == raw, 'source_changed')
    inputs[path] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name
                for target in node.targets)]
    need(len(rows) == 1)
    return ast.literal_eval(rows[0])


def definitions(raw):
    lines = raw.splitlines(keepends=True)
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    return tuple((node.name, node.lineno, node.end_lineno,
                  b''.join(lines[node.lineno - 1:node.end_lineno]))
                 for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def replacement(raw, changes, label, before, after, count=1):
    need(type(before) is bytes and type(after) is bytes and before != after and
         raw.count(before) == count)
    result = raw.replace(before, after)
    need(result.count(after) == count)
    changes.append(dict(label=label, before=before.decode('ascii'),
                        after=after.decode('ascii'), count=count))
    return result


def reverse(raw, changes):
    for row in reversed(changes):
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        need(raw.count(after) == row['count'])
        raw = raw.replace(after, before)
    return raw


def stage_raw(old, rows, old_rows):
    """One profile only; exact root/three actual pins/total, no target execution."""
    need((len(old), sha(old)) == OLD_STAGE[1:])
    old_table = literal(old, 'PROFILE_FILES')
    need(old_table == (('observer', OLD_ROOT, tuple(old_rows)),) and
         literal(old, 'PROFILE_TOTALS') == (('observer', 41, 1442508),) and
         literal(old, 'SERVICE_PARENTS') == () and
         literal(old, 'MAX_SECONDS') == 120.0 and
         old.count(b'RAW_LIMIT = 4 * 1024 * 1024\n') == 1)
    need(len(rows) == len(old_rows) == 41)
    total = sum(row[1] for row in rows)
    changes = []
    raw = replacement(old, changes, 'independent_observer_root',
                      OLD_ROOT.encode('ascii'), ROOT.encode('ascii'))
    changed = []
    for before, after in zip(old_rows, rows):
        need(before[0] == after[0] and before[3] == after[3] == 256)
        role = before[0][8:-3]
        if role in ROLES[:3]:
            need(before != after)
            old_line = ('        %r,\n' % (before,)).encode('ascii')
            new_line = ('        %r,\n' % (after,)).encode('ascii')
            raw = replacement(raw, changes, 'actual_pin_' + role, old_line, new_line)
            changed.append(role)
        else:
            need(before == after)
    need(tuple(changed) == ROLES[:3])
    raw = replacement(raw, changes, 'actual_profile_bytes',
        b"PROFILE_TOTALS = (('observer', 41, 1442508),)\n",
        ("PROFILE_TOTALS = (('observer', 41, %d),)\n" % total).encode('ascii'))
    need(reverse(raw, changes) == old and definitions(raw) == definitions(old))
    before_tree = ast.parse(old.decode('ascii'), feature_version=(3, 5))
    after_tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    before_nodes = []; after_nodes = []
    for tree, roster in ((before_tree, before_nodes), (after_tree, after_nodes)):
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                    target.id in ('PROFILE_FILES', 'PROFILE_TOTALS') for target in node.targets):
                continue
            roster.append(ast.dump(node, include_attributes=True))
    need(before_nodes == after_nodes and
         literal(raw, 'PROFILE_FILES') == (('observer', ROOT, tuple(rows)),) and
         literal(raw, 'PROFILE_TOTALS') == (('observer', 41, total),) and
         literal(raw, 'SERVICE_PARENTS') == () and
         literal(raw, 'MAX_SECONDS') == 120.0 and
         raw.count(b'RAW_LIMIT = 4 * 1024 * 1024\n') == 1)
    return raw, dict(original=list(OLD_STAGE), bytes=len(raw), sha256=sha(raw),
        replacements=changes, complete_byte_inverse=True, complete_ast_inverse=True,
        definitions_bytes_and_lines_unchanged=True, changed_assets=3,
        unchanged_assets=38, files=41, source_bytes=total, target_executed=False)


def selected_mother(raw):
    """Frozen PC helpers/constants only; no old payloads/main/SOURCE entry."""
    tree = ast.parse(raw.decode('ascii'))
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name in HELPERS]
    need(len(helpers) == len(HELPERS) and {node.name for node in helpers} == HELPERS)
    selected = [node for node in tree.body
                if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
                isinstance(node, ast.FunctionDef) and node.name in HELPERS]
    namespace = {'__file__': str(BASE / MOTHER[0]),
                 '__name__': 'observer_diag_derived_driver_private', '__doc__': __doc__}
    exec(compile(ast.Module(body=selected, type_ignores=[]),
                 '<frozen-observer-PC-helpers>', 'exec'), namespace)
    need(namespace['PARENT_BODY'] == literal(raw, 'PARENT_BODY'))
    namespace.update(SELF=SELF, CMD=SOURCE_CMD, ROOT=ROOT, OBSERVER_BYTES=1442508)
    return namespace, tree


def derive_main(raw, tree):
    """Exact PC namespace/argv/report delta; every original business gate retained."""
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name == 'main']
    need(len(matches) == 1)
    node = matches[0]
    before = b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    changes = []
    after = replacement(before, changes, 'source_only_argument',
        b"    group = parser.add_mutually_exclusive_group()\n",
        b"    group = parser.add_mutually_exclusive_group()\n"
        b"    group.add_argument('--source-only', action='store_true', help='PC SOURCE only; no target.')\n")
    after = replacement(after, changes, 'independent_result_namespace',
                        b'go-observer-libc-v1-', b'go-observer-diag-v1-', 2)
    after = replacement(after, changes, 'actual_observer_bytes',
                        b'1442508', b'OBSERVER_BYTES', 3)
    after = replacement(after, changes, 'private_derived_source_evidence',
        b'        stage_payload, check_payload, reasons = payloads(inputs)\n',
        b'        stage_payload, check_payload, reasons = payloads(inputs)\n'
        b"        write_new(private / 'observer-stage.derived.py', DERIVED_STAGE_RAW)\n"
        b"        write_new(private / 'observer-source-contract.private.json',\n"
        b"            (json.dumps(DERIVED_CONTRACT, sort_keys=True, indent=2) + '\\n').encode('ascii'))\n")
    need(reverse(after, changes) == before and
         ast.dump(ast.parse(reverse(after, changes).decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(before.decode('ascii')), include_attributes=True))
    # The only target calls and gates are the frozen mother's unchanged text.
    for token in (b"210 if mode == 'stage' else 75", b'parent_completed(report[',
                  b'carrier.baseline(helper, adb, transport, private,',
                  b"need(receipt['remote_exit'] == 0", b'    finally:\n'):
        need(after.count(token) == before.count(token))
    return after, dict(replacements=changes, complete_byte_inverse=True,
                       complete_ast_inverse=True, parent_body_unchanged=True,
                       success_and_failure_gates_unchanged=True)


def payloads(inputs, driver, mother_raw, main_proof):
    need(pinned(inputs, MOTHER) == mother_raw)
    for path in (SELF, SOURCE_CMD, TEST_CMD):
        raw = (BASE / path).read_bytes()
        if path in inputs:
            need(inputs[path] == raw, 'source_changed')
        inputs[path] = raw
    bridge_inputs = {row[0]: pinned(inputs, row) for row in BRIDGES}
    deriver_raw = pinned(inputs, DERIVER)
    source = types.ModuleType('fixed_observer_diag_source_private')
    source.__file__ = str(BASE / DERIVER[0])
    exec(compile(deriver_raw, source.__file__, 'exec'), source.__dict__)
    need(source.bridge_source_inputs() == BRIDGES)
    source_rows = source.source_inputs()
    need(type(source_rows) is tuple and len(source_rows) == 43 and
         len({row[0] for row in source_rows}) == len(source_rows))
    frozen = {row[0]: pinned(inputs, row) for row in source_rows}
    assembled = source.assemble(frozen, bridge_inputs=bridge_inputs)
    need(type(assembled) is dict and set(assembled) == {'files', 'facts'} and
         type(assembled['files']) is tuple and len(assembled['files']) == 7 and
         type(assembled['facts']) is dict)
    facts = assembled['facts']
    need(facts['root'] == ROOT and facts['source_count'] == 41 and
         facts['changed_asset_count'] == 3 and facts['unchanged_asset_count'] == 38 and
         facts['load_count'] == 38 and facts['diagnostic_max_bytes'] == 512 and
         facts['original_proc_unchanged'] is True and facts['successful_packet_unchanged'] is True and
         facts['terminal_definitions_unchanged'] is True and facts['device_accessed'] is False and
         facts['target_definitions_executed'] == facts['tests_invoked'] == 0 and
         facts['rf_requested'] is False and facts['stager_included'] is False and
         facts['frame_projection'] == 'namespace_bound_name_and_original_lineno' and
         facts['exact_original_function_or_code_identity_certified'] is False and
         facts['stderr_identity_nonblocking_closure_certified'] is False and
         facts['source_inputs'] == [list(row) for row in source_rows])
    outputs = {}
    for item in assembled['files']:
        need(type(item) is dict and set(item) == {'path', 'raw'} and
             type(item['path']) is str and type(item['raw']) is bytes and
             item['path'].startswith(PREFIX + '/') and
             '..' not in Path(item['path']).parts and item['path'] not in outputs)
        outputs[item['path']] = item['raw']
        need(pinned(inputs, (item['path'], len(item['raw']), sha(item['raw']))) == item['raw'])
    catalog_path = PREFIX + '/assets/observer-source-catalog.json'
    parent_path = PREFIX + '/runtime/mta_go_readonly_parent.py'
    need(set(outputs) == {PREFIX + '/runtime/' + role + '.py' for role in ROLES} |
         {catalog_path, PREFIX + '/assets/delta.json', PREFIX + '/assets/generation.json'})
    catalog = json.loads(outputs[catalog_path])
    old_catalog_raw = pinned(inputs, driver['CATALOG'])
    old_catalog = json.loads(old_catalog_raw)
    need(catalog['root'] == ROOT and catalog['alias'] == '/tmp/' + ROOT.rsplit('/', 1)[1] and
         catalog['source_count'] == 41 and catalog['load_count'] == 38 and
         catalog['unchanged_asset_count'] == 38 and
         tuple(catalog['changed_asset_modules']) == ROLES[:3] and
         len(catalog['files']) == len(old_catalog['files']) == 41 and
         catalog['parent_inline_only']['not_in_asset_files'] is True and
         catalog['parent_inline_only']['source'] == parent_path, 'catalog_shape')
    rows = []; old_rows = []; changed = []
    for item, old in zip(catalog['files'], old_catalog['files']):
        need(item['module'] == old['module'] and item['mode'] == old['mode'] == '0400' and
             item['target'] == ROOT + '/runtime/' + item['module'] + '.py', 'catalog_shape')
        raw = pinned(inputs, (item['source'], item['bytes'], item['sha256']))
        old_raw = pinned(inputs, (old['source'], old['bytes'], old['sha256']))
        if item['module'] in ROLES[:3]:
            need(item['source'] == PREFIX + '/runtime/' + item['module'] + '.py' and
                 raw == outputs[item['source']] and raw != old_raw, 'catalog_shape')
            changed.append(item['module'])
        else:
            need(item['source'] == old['source'] and raw == old_raw, 'catalog_shape')
        rows.append((('runtime/' + item['module'] + '.py', len(raw), sha(raw), 256), raw))
        old_rows.append(('runtime/' + old['module'] + '.py', len(old_raw), sha(old_raw), 256))
    total = sum(len(raw) for row, raw in rows)
    need(tuple(changed) == ROLES[:3] and catalog['source_bytes'] == facts['source_bytes'] == total and
         len({row[0] for row, raw in rows}) == 41, 'catalog_shape')
    parent = outputs[parent_path]
    need((catalog['parent_inline_only']['bytes'], catalog['parent_inline_only']['sha256']) ==
         (len(parent), sha(parent)), 'catalog_shape')
    stage, stage_proof = stage_raw(pinned(inputs, OLD_STAGE),
                                 tuple(row for row, raw in rows), tuple(old_rows))
    for key in ('GENERATOR', 'ENVELOPE', 'WRAPPER', 'CARRIER', 'HELPER', 'TRANSPORT'):
        pinned(inputs, driver[key])
    driver.update(PARENT=(parent_path, len(parent), sha(parent)),
                  STAGE=('<memory-derived-observer-diag-stage>', len(stage), sha(stage)),
                  OBSERVER_BYTES=total)
    generator = driver['selected_generator'](inputs[driver['GENERATOR'][0]])
    inner, wire = generator['make_program']('observer', tuple(rows), stage)
    wrapper = inputs[driver['WRAPPER'][0]]
    before = b'len(_DATA_TABLE_ORIGINAL) == 3 and'
    after = b'len(_DATA_TABLE_ORIGINAL) == 1 and'
    need(wrapper.count(before) == 1 and wrapper.count(after) == 0)
    changed_wrapper = wrapper.replace(before, after)
    need(changed_wrapper.replace(after, before) == wrapper)
    data, changed_wrapper = generator['bootstrap_parts'](
        [('observer', inner)], [('observer', wire)], changed_wrapper)
    program = generator['bootstrap_program']('observer', data, changed_wrapper,
                    literal(inputs[driver['ENVELOPE'][0]], 'ENVELOPE'))
    check_program, check_wire, reasons = driver['parent_payload'](parent)
    for value in (program, check_program):
        need(len(value) <= 2097152 and max(map(len, value.splitlines())) <= 256, 'source_budget')
        ast.parse(value.decode('ascii'), feature_version=(3, 5))
    need(len(wire) <= 4194304 and max(map(len, wire.splitlines())) <= 256, 'source_budget')
    driver['DERIVED_STAGE_RAW'] = stage
    driver['DERIVED_CONTRACT'] = dict(kind='observer-diag-v1-mechanical-source-contract',
        mother=list(MOTHER), deriver=list(DERIVER), bridges=[list(row) for row in BRIDGES],
        assembler_facts=assembled['facts'],
        actual_outputs=[dict(path=path, bytes=len(raw), sha256=sha(raw))
                        for path, raw in sorted(outputs.items())],
        stage=stage_proof, main=main_proof, parent_body_pin=[
            len(driver['PARENT_BODY'].encode('ascii')), sha(driver['PARENT_BODY'].encode('ascii'))],
        original_parent_caps=[30, 5, 40, 50, 9, 4096, 262144, 16384],
        child_data_is_private=True, original_nonzero_failure_preserved=True,
        owner_started=False, ui_started=False, rf_requested=False, old_tests_run=0)
    return (program, wire), (check_program, check_wire), reasons


def main():
    mother_raw = pinned({}, MOTHER)
    driver, tree = selected_mother(mother_raw)
    main_raw, main_proof = derive_main(mother_raw, tree)
    driver['payloads'] = lambda inputs: payloads(inputs, driver, mother_raw, main_proof)
    exec(compile(main_raw, '<independent-observer-diag-PC-driver>', 'exec'), driver)
    return driver['main']()


if __name__ == '__main__':
    raise SystemExit(main())
