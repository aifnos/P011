"""Independent media-mutex ordinary files-only carrier; default SOURCE.

Only new ordinary37/root is published by explicit --stage-device. The actually
measured ordinary-v7 carrier keeps its FD/stock/finally/PASS and 120/180/200/
HOST210 limits. Sender27/observer41 remain readonly prerequisites. The fixed
ASSETS v7 table is NOT provenance for the new ordinary business graph. Its
actual 14 published outputs are compared with the pinned new pure recipe and
check_send boundary before the inherited payload path. No older prepare/main,
writer, suite, Parent/Owner/UI/RF, GUI19/FC9 stage, retry or phone action.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_fc_mutex_stage_v1_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_FC_MUTEX_STAGE_V1_CHECK.cmd'
TEST_CMD = 'TEST_MTA_FORMAL_SEND_FC_MUTEX_STAGE_V1.cmd'
ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-mutex1-v1'
MOTHER = ('host/device_formal_send_coldstart_ordinary_v1_check.py', 9186,
          'c70f50cbaa0c196eafaf0fb0ad10070b757bf4b8fa3ab323cec087651d472294')
PRIOR_ENTRY = ('host/device_formal_send_fc_http_cap_stage_v1_check.py', 12389,
               '85e9880cba4b31142c7922a33bb18baf4845bae02d0a26f3fd35be69b97f2b92')
PACKAGE_PARENT = ('host/filecenter_mutex_package_v1_check.py', 24842,
                  '4cd5961ecf3459d5793e7e3781d8f665f6eb957265364dcc633789d06b58d966')
GENERATOR = ('candidate/formal-send-fc-mutex-v1/generate_package.py', 38185,
             '69ce44c85b11c89e491c8877b839a0eed9322c22ff51f8c6a819589a4d50742a')
GENERATION = ('candidate/formal-send-fc-mutex-v1/generation.json', 31186,
              '5b53a2c7481595ba9815cc05b4c5267afcce9aaab4deb2059fc79792ae96477e')
CATALOG = ('candidate/formal-send-fc-mutex-v1/assets/ordinary-source-manifest.json', 20738,
           '61e2344234bb63677f61cb52317f84367b9250f69ef3832ff1288f17e74a2423')
FC_MANIFEST = ('candidate/formal-send-fc-mutex-v1/assets/filecenter-source-manifest.json', 2477,
               '611ca4aa72fb01e7f4393a0e789344ee0590846c5dc955380aba141d689c59e3')
STAGE = ('candidate/formal-send-fc-mutex-v1/runtime/formal_send_stage.py', 37421,
         '6155769f9fe67e50cbcc9a34f2a17a7c51d0a695cec0454d0c7bed1b92c417cd')
MEASURED_NAMES = frozenset(('need', 'fixed', 'derive', 'target_methods'))
PACKAGE_NAMES = frozenset(('need', 'digest', 'select_module', 'literal', 'actual_pin',
                           'check_fc', 'check_send'))


def need(value):
    if value is not True:
        raise ValueError('stage_contract')


def fixed(inputs, row):
    key, size, pin = row
    raw = inputs[key] if key in inputs else (BASE / key).read_bytes()
    inputs[key] = raw
    need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) == (size, pin))
    return raw


def pure(row, inputs, names, label):
    raw = fixed(inputs, row)
    parsed = ast.parse(raw.decode('ascii'))
    selected = [node for node in parsed.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign)) or
                isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in selected if isinstance(node, ast.FunctionDef)} == names and 'main' not in names)
    value = types.ModuleType(label)
    value.__file__ = str(BASE / row[0])
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<' + label + '>', 'exec'), value.__dict__)
    need('main' not in value.__dict__ and 'prepare' not in value.__dict__)
    return value


def derive(raw):
    """Finite identity/data derivation of measured v7; no runtime gate changes."""
    changes = (
        ("SELF = 'host/device_formal_send_coldstart_ordinary_v1_check.py'", 'SELF = ' + repr(SELF), 1),
        ("CMD = 'HOST_MTA_FORMAL_SEND_COLDSTART_ORDINARY_V1_SOURCE_CHECK.cmd'", 'CMD = ' + repr(CMD), 1),
        ("TEST_CMD = 'TEST_MTA_FORMAL_SEND_COLDSTART_ORDINARY_V1.cmd'", 'TEST_CMD = ' + repr(TEST_CMD), 1),
        ("CATALOG = ('candidate/formal-send-filecenter-deploy-v7/assets/ordinary-source-manifest.json',\n"
         "    20810, '9be61347f4a44d031cf7c07095692b4cd0de21f79410a9f45c5ad6b2073f9d52')",
         "CATALOG = ('candidate/formal-send-fc-mutex-v1/assets/ordinary-source-manifest.json',\n"
         "    20738, '61e2344234bb63677f61cb52317f84367b9250f69ef3832ff1288f17e74a2423')", 1),
        ("STAGE = ('candidate/formal-send-filecenter-deploy-v7/runtime/formal_send_stage.py',\n"
         "    37421, 'eafc45ced6c0b4b0598b9bfb6fc86adefed68a5b94137303ca91d2256e7adc14')",
         "STAGE = ('candidate/formal-send-fc-mutex-v1/runtime/formal_send_stage.py',\n"
         "    37421, '6155769f9fe67e50cbcc9a34f2a17a7c51d0a695cec0454d0c7bed1b92c417cd')", 1),
        ("'/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v7'", repr(ROOT), 1),
        ('coldstart-ordinary-v1', 'fc-mutex-stage-v1', 3),
        ('ordinary v7', 'media-mutex ordinary', 2),
        ('production_admitted=False, pending_handled=False, old_tests_run=0, error_code=None)',
         'production_admitted=False, pending_handled=False, old_tests_run=0, error_code=None, '
         'package_provenance=_MUTEX_STAGE_SOURCE_FACTS)', 1),
    )
    original, ledger = raw, []
    for before, after, count in changes:
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == count and before.count(b'\n') == after.count(b'\n'))
        positions = [index for index in range(len(raw)) if raw.startswith(before, index)]
        for offset in reversed(positions):
            need(raw[offset:offset + len(before)] == before)
            raw = raw[:offset] + after + raw[offset + len(before):]
            ledger.append((offset, before, after))
    inverse = raw
    for offset, before, after in reversed(ledger):
        need(inverse[offset:offset + len(after)] == after)
        inverse = inverse[:offset] + before + inverse[offset + len(after):]
    need(inverse == original and ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(original.decode('ascii')), include_attributes=True))

    def positioned(value, remove_data):
        tree = ast.parse(value.decode('ascii'))
        if remove_data:
            matches = [node for node in ast.walk(tree) if isinstance(node, ast.keyword) and
                       node.arg == 'package_provenance']
            need(len(matches) == 1 and isinstance(matches[0].value, ast.Name) and
                 matches[0].value.id == '_MUTEX_STAGE_SOURCE_FACTS')
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                     any(keyword is matches[0] for keyword in node.keywords)]
            need(len(calls) == 1 and isinstance(calls[0].func, ast.Name) and calls[0].func.id == 'dict')
            calls[0].keywords.remove(matches[0])
        for node in ast.walk(tree):
            for name in ('col_offset', 'end_col_offset'):
                if hasattr(node, name): setattr(node, name, 0)
        class Literals(ast.NodeTransformer):
            def visit_Constant(self, node):
                return ast.copy_location(ast.Constant(value=None), node)
        return ast.dump(Literals().visit(tree), include_attributes=True)

    need(positioned(raw, True) == positioned(original, False))
    old_tree, new_tree = ast.parse(original.decode('ascii')), ast.parse(raw.decode('ascii'))
    old_defs = [node for node in old_tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))]
    new_defs = [node for node in new_tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))]
    need([node.name for node in old_defs] == [node.name for node in new_defs])
    old_lines, new_lines = original.splitlines(keepends=True), raw.splitlines(keepends=True)
    for old, new in zip(old_defs, new_defs):
        need((old.lineno, old.end_lineno) == (new.lineno, new.end_lineno))
        if old.name != 'main':
            need(b''.join(old_lines[old.lineno - 1:old.end_lineno]) ==
                 b''.join(new_lines[new.lineno - 1:new.end_lineno]))
    return raw, dict(complete_byte_inverse=True, complete_positioned_ast_inverse=True,
        unchanged_pc_definitions_byte_exact=True, main_only_identities_and_one_data_field=True,
        finite_edits=len(ledger), old_main_executed=False,
        derived_pc_bytes=len(raw), derived_pc_sha256=hashlib.sha256(raw).hexdigest())


def stage_methods(inputs, prior):
    old, new = fixed(inputs, prior), fixed(inputs, STAGE)
    old_tree, new_tree = ast.parse(old.decode('ascii')), ast.parse(new.decode('ascii'))
    old_defs = [node for node in old_tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))]
    new_defs = [node for node in new_tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))]
    old_lines, new_lines = old.splitlines(keepends=True), new.splitlines(keepends=True)
    need([node.name for node in old_defs] == [node.name for node in new_defs])
    for first, second in zip(old_defs, new_defs):
        need((first.lineno, first.end_lineno) == (second.lineno, second.end_lineno) and
             ast.dump(first, include_attributes=True) == ast.dump(second, include_attributes=True) and
             b''.join(old_lines[first.lineno - 1:first.end_lineno]) ==
             b''.join(new_lines[second.lineno - 1:second.end_lineno]))
    return dict(all_stage_classes_and_functions_byte_and_position_exact=True,
        compared_to_measured_v7_stage=list(prior), actual_mutex_stage_pin=list(STAGE),
        stage_functions_invoked=False, inner_seconds_unchanged=120)


def package_boundary(inputs):
    """Only new pure prepare/check_send; compare every actual published byte."""
    package = pure(PACKAGE_PARENT, inputs, PACKAGE_NAMES, '_mutex_stage_actual_package_boundary')
    reader_raw = fixed(inputs, package.DONOR)
    reader = package.select_module(reader_raw, package.DONOR[0],
        ('need', 'sha', 'metadata', 'read_fixed'), assignments=False)
    recipe = package.select_module(fixed(inputs, GENERATOR), GENERATOR[0],
        package.PURE['send'], classes=('Edit',))
    need(recipe.NEW_PHYSICAL == ROOT and recipe.ROOT == 'candidate/formal-send-fc-mutex-v1' and
         all(name not in recipe.__dict__ for name in ('main', 'publish', 'write_outputs')))
    outputs, facts, sources = recipe.prepare()
    need(set(outputs) == set(package.OUTPUT_NAMES['send']) and len(outputs) == 14 and
         tuple(facts['generator']) == GENERATOR and facts['input_count'] == len(sources) == 147 and
         package.actual_pin(GENERATION[0], outputs[GENERATION[0]]) == GENERATION and
         package.actual_pin(CATALOG[0], outputs[CATALOG[0]]) == CATALOG and
         package.actual_pin(FC_MANIFEST[0], outputs[FC_MANIFEST[0]]) == FC_MANIFEST and
         package.actual_pin(STAGE[0], outputs[STAGE[0]]) == STAGE)
    closure = package.check_send(outputs, facts, sources, recipe)
    for key, raw in sources.items():
        need(key not in inputs or inputs[key] == raw)
        inputs[key] = raw
    # Prepared is never evidence for published: all fourteen fixed artifacts
    # must already exist and be exact. No candidate writer is in this module.
    for key, prepared in outputs.items():
        actual = reader.read_fixed(key, (len(prepared), hashlib.sha256(prepared).hexdigest()))
        need(actual == prepared and (key not in inputs or inputs[key] == actual))
        inputs[key] = actual
    need(facts['scope'] == 'PC_SOURCE_ONLY_NOT_STAGED_NOT_RUN' and
         facts['physical_ordinary_root'] == ROOT and facts['output_count'] == 14 and
         facts['old_prepare_verify_main_called'] == facts['old_mains'] == facts['tests'] == 0 and
         all(facts[key] is False for key in ('device', 'staged', 'runtime', 'host', 'native',
             'rf', 'phone', 'filecenter_parent_deadline_verified', 'filecenter_media_mutex_device_verified',
             'blocking_file_io_preemption_verified', 'whole_owner_closure_verified', 'restore_verified')))
    closure.update(actual_package_outputs=14, actual_published_outputs_byte_exact=True,
        full_package_byte_inverse=True, new_recipe_only_pure_prepare=True,
        old_prepare_main_or_suite_called=False, writer_called=False,
        filecenter_parent_deadline_verified=False, filecenter_media_mutex_device_verified=False,
        blocking_file_io_preemption_verified=False, stage_runtime_verified=False,
        device_runtime_verified=False, full_owner_closure_verified=False)
    return package, closure


def load(inputs=None):
    inputs = {} if inputs is None else inputs
    fixed(inputs, PRIOR_ENTRY)
    measured = pure(MOTHER, inputs, MEASURED_NAMES, '_mutex_stage_measured_recipe')
    for pin in measured.BRIDGE_INPUTS: fixed(inputs, pin)
    v7_raw, inherited_proof = measured.derive(inputs[measured.MOTHER[0]])
    raw, proof = derive(v7_raw)
    value = types.ModuleType('_formal_send_fc_mutex_stage_v1_derived_entry')
    value.__file__ = str(BASE / SELF)
    exec(compile(raw, '<formal-send-mutex-stage-v1-derived-entry>', 'exec'), value.__dict__)
    need(value.SELF == SELF and value.CMD == CMD and value.TEST_CMD == TEST_CMD and value.ROOT == ROOT and
         value.CATALOG == CATALOG and value.STAGE == STAGE and
         value.ASSETS == ('candidate/formal-send-filecenter-deploy-v7/assets/asset-sources.json', 24365,
             '76368b95981aa206eeb2a7eaa929fb1263a3ffd94d78b8757422626baab3db73'))
    facts = dict(scope='SOURCE_PROVENANCE_NOT_RUNTIME', boundary_complete=False,
        new_assets_generated=False, asset_catalog_is_prerequisite_only=True,
        gui19_staged=False, fc9_staged=False, parent_started=False, owner_started=False,
        ui_started=False, rf_requested=False, filecenter_parent_deadline_verified=False,
        filecenter_media_mutex_device_verified=False, blocking_file_io_preemption_verified=False,
        inherited_pc_bridge=inherited_proof, new_pc_bridge=proof)
    value._MUTEX_STAGE_SOURCE_FACTS = facts
    inherited = value.payloads
    initial = dict(inputs)

    def payloads(snapshot):
        for key, data in initial.items():
            need(key not in snapshot or snapshot[key] == data)
            snapshot[key] = data
        for pin in (MOTHER, PRIOR_ENTRY, PACKAGE_PARENT) + measured.BRIDGE_INPUTS: fixed(snapshot, pin)
        original_methods = measured.target_methods(snapshot)
        actual_methods = stage_methods(snapshot, measured.STAGE)
        package, closure = package_boundary(snapshot)
        need(closure['full_package_byte_inverse'] is True and
             closure['ordinary_batch_files'] == 37 and closure['ordinary_batch_bytes'] == 1368142 and
             closure['fc9_sources'] == 9 and closure['fc9_bytes'] == 101682 and closure['fc9_cap'] == 131072)
        catalog = package.json.loads(snapshot[CATALOG[0]])
        separate = catalog['separate_asset_catalog']
        need((separate['source'], separate['bytes'], separate['sha256']) == value.ASSETS and
             separate['sender_count'] == 25 and separate['observer_count'] == 41)
        facts.update(boundary_complete=True, package_closure=closure,
            inherited_stage_methods=original_methods, actual_stage_methods=actual_methods,
            actual_generation_pin=list(GENERATION), actual_recipe_pin=list(GENERATOR),
            actual_fc_manifest_pin=list(FC_MANIFEST), ordinary_root=ROOT,
            actual_catalog_pin=list(CATALOG), readonly_asset_table_pin=list(value.ASSETS),
            sender_readonly_files=27, observer_readonly_files=41,
            original_inner_seconds=120, original_outer_seconds=180,
            original_carrier_seconds=200, original_launch_host_timeout_seconds=210)
        result = inherited(snapshot)
        facts['payload_source_prepared'] = True
        return result

    value.payloads = payloads
    return value


def main():
    # Only this independently derived carrier is dispatched. Its original
    # parser still defaults SOURCE and accepts only explicit --stage-device.
    return load().main()


if __name__ == '__main__':
    raise SystemExit(main())
