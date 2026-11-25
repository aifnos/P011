"""PC SOURCE by default; explicit --stage-native publishes two fixed files only.

Pure source derivation reuses the frozen observer HOST's carrier, stock checks,
readback, finally and public result ZIP. No Parent payload or branch is selected.
No helper, Owner, Boot, UI or RF executes. Partial/conflicting roots are retained.
"""
import ast
import hashlib
from pathlib import Path
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_go_readonly_native_v1_check.py'
SOURCE_CMD = 'HOST_MTA_GO_READONLY_NATIVE_V1_SOURCE_CHECK.cmd'
STAGE_CMD = 'STAGE_MTA_GO_READONLY_NATIVE_V1.cmd'
ROOT = '/var/volatile/tmp/p011-mta-go-readonly-native-v1'
HOST_MOTHER = ('host/device_go_observer_libc_v1_check.py', 30217,
    '078ea42b28465eb58a02cb64589fd2fdba30ed3f46b0fd29f7d4bc6e6c15a1ea')
STAGE_MOTHER = ('candidate/go-observer-libc-v1/runtime/formal_observer_stage.py', 29349,
    'c2799754f4d4638a79ec74e5f029550540b3597f1dbab1ddfc4fd077928b206f')
STAGE = ('candidate/go-readonly-native-v1/runtime/formal_native_stage.py', 24524,
    'c5f9873d7f0a31aef3178421d8a3514b381ca777d39013bff893e2ab386fd3a8')
WRAPPER_MOTHER = ('candidate/formal-send-stage-bootstrap-v1/runtime/formal_send_stage_bootstrap.py', 13207,
    'c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d')
WRAPPER = ('candidate/go-readonly-native-v1/runtime/formal_native_stage_bootstrap_template.py', 13161,
    'fb10559233a4c43c4b248e7da7fc7bf179a95e442458cb255db886ddce32785c')
NATIVE = (
    ('out/native/mta-bluez-helper', 65832,
     '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363'),
    ('out/native/mta-network-helper', 47464,
     'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6'),
)
NATIVE_PINS = tuple(('native/' + row[0].rsplit('/', 1)[1], row[1], row[2], 0o500)
                    for row in NATIVE)
GENERATOR = ('host/formal_send_filecenter_deploy_v3_source_check.py', 30450,
    '9c5f9db7e9373a72378d622eb16c6fed5f1c94abeca8dd723455fa8518eea8d1')
ENVELOPE = ('host/formal_send_stage_bootstrap_source_check.py', 19997,
    'aede2e43410f7f3a78fb715c077e567da84ba47d9dfa9c5d4290e3b8795b60d3')
CARRIER = ('host/device_formal_send_filecenter_stage_carrier_v3_check.py', 25857,
    '043844b6be906369ad16b17562030629213a127756adb73c849b7b7b4c10ff0d')
HELPER = ('host/device_formal_send_filecenter_stage_v1_check.py', 22495,
    '68cdbacc1f9a33e61fcdbe603b183909092f2a93c4f7dfcd82a92e2e98b4f145')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
COMMAND_PINS = (
    (SOURCE_CMD, 330, 'e637b2ad8fade62fdc416e9f4860f68eaaa970c2e2c44a9ac3e0e8ebe5f9bd9d'),
    (STAGE_CMD, 333, 'b9d4c226c0b51d9758ce3b1a6cf019361d951aee23bcdc3bb06127c4dfbf2761'),
)
SOURCE_ROWS = (HOST_MOTHER, STAGE_MOTHER, STAGE, WRAPPER_MOTHER, WRAPPER) + NATIVE + (
    GENERATOR, ENVELOPE, CARRIER, HELPER, TRANSPORT) + COMMAND_PINS


def need(value, code='stage_contract'):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixed(inputs, row):
    raw = inputs[row[0]] if row[0] in inputs else (BASE / row[0]).read_bytes()
    need(type(raw) is bytes and (len(raw), sha(raw)) == row[1:], 'input_pin')
    inputs[row[0]] = raw
    return raw


def edits(raw, rows):
    """Ordered fixed edits, offset-bound complete reverse; no new-text uniqueness guess."""
    original = raw
    ledger = []
    for before, after, count in rows:
        before, after = before.encode('ascii'), after.encode('ascii')
        need(before != after and raw.count(before) == count)
        positions = []
        at = 0
        for ignored in range(count):
            at = raw.index(before, at)
            positions.append(at)
            at += len(before)
        for at in reversed(positions):
            raw = raw[:at] + after + raw[at + len(before):]
            ledger.append((at, before, after))
    reverse = raw
    for at, before, after in reversed(ledger):
        need(reverse[at:at + len(after)] == after)
        reverse = reverse[:at] + before + reverse[at + len(after):]
    need(reverse == original)
    need(ast.dump(ast.parse(reverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(original.decode('ascii')), include_attributes=True))
    return raw, tuple(ledger)


def definitions(raw):
    source = raw.decode('ascii')
    tree = ast.parse(source)
    result = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            result[node.name] = (node.lineno, ast.get_source_segment(source, node),
                                 ast.dump(node, include_attributes=True))
    return result


def same_definitions(old, new, exceptions=()):
    left, right = definitions(old), definitions(new)
    need(set(left) == set(right))
    for name in left:
        if name not in exceptions:
            need(left[name] == right[name])
    return tuple(sorted(set(left) - set(exceptions)))


def assign(raw, name):
    source = raw.decode('ascii')
    rows = [node for node in ast.parse(source).body if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1)
    return ast.get_source_segment(source, rows[0])


def derive_stage(raw):
    old_doc = raw.decode('ascii').split('"""', 2)[1]
    new_doc = old_doc.replace('observer-libc-v1', 'readonly-native-v1').replace('observer-only', 'native-only')
    start = raw.index(b'PROFILE_FILES = (\n')
    stop = raw.index(b'\n_PROFILE_FILES_ORIGINAL = PROFILE_FILES')
    old_table = raw[start:stop].decode('ascii')
    new_table = ("PROFILE_FILES = (\n"
        "    ('native', '/var/volatile/tmp/p011-mta-go-readonly-native-v1', (\n"
        "        ('native/mta-bluez-helper', 65832, '179fd01f737acd30c7e903d6925217d9e0467400187614189d06a4cffdc44363', 320),\n"
        "        ('native/mta-network-helper', 47464, 'ef3b904ef1017b6f0011b1e2cfcadbc98f9e8026933153ff0291699f32c525e6', 320),\n"
        "    )),\n)\n")
    padding = old_table.count('\n') - new_table.count('\n')
    need(padding == 39)
    new_table += '\n' * padding
    value, ledger = edits(raw, (
        ('"""' + old_doc + '"""', '"""' + new_doc + '"""', 1),
        ("PROFILE_TOTALS = (('observer', 41, 1442508),)", "PROFILE_TOTALS = (('native', 2, 113296),)", 1),
        (old_table, new_table, 1),
    ))
    unchanged = same_definitions(raw, value)
    tree = ast.parse(value.decode('ascii'), feature_version=(3, 5))
    need(assign(raw, 'RAW_LIMIT') == assign(value, 'RAW_LIMIT') == 'RAW_LIMIT = 4 * 1024 * 1024')
    for name, expected in (('PROFILE_TOTALS', (('native', 2, 113296),)),
                           ('PROFILE_FILES', (('native', ROOT, NATIVE_PINS),)),
                           ('SERVICE_PARENTS', ()), ('MAX_SECONDS', 120.0)):
        row = next(node.value for node in tree.body if isinstance(node, ast.Assign) and
                   any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
        need(ast.literal_eval(row) == expected)
    need(value.count(ROOT.encode('ascii')) == 1 and value.count(b'p011-mta-state-v69') == 0)
    return value, dict(edits=len(ledger), unchanged_definitions=unchanged,
                      complete_byte_inverse=True, complete_ast_inverse=True, method_lines_unchanged=True)


def derive_wrapper(raw):
    value, ledger = edits(raw, (
        ("('sender', 'observer', 'ordinary')", "('native',)", 2),
        ('len(_DATA_TABLE_ORIGINAL) == 3 and', 'len(_DATA_TABLE_ORIGINAL) == 1 and', 1),
    ))
    unchanged = same_definitions(raw, value, ('program_source', 'run_fixed'))
    ast.parse(value.decode('ascii'), feature_version=(3, 5))
    for name in ('program_source', 'run_fixed'):
        before, after = definitions(raw)[name], definitions(value)[name]
        need(before[0] == after[0])
    return value, dict(edits=len(ledger), unchanged_definitions=unchanged,
                      complete_byte_inverse=True, complete_ast_inverse=True,
                      only_profile_constants_changed=True, method_lines_unchanged=True)


def assemble(inputs=None):
    inputs = {} if inputs is None else inputs
    for row in SOURCE_ROWS:
        fixed(inputs, row)
    stage, stage_proof = derive_stage(inputs[STAGE_MOTHER[0]])
    wrapper, wrapper_proof = derive_wrapper(inputs[WRAPPER_MOTHER[0]])
    need(stage == inputs[STAGE[0]] and wrapper == inputs[WRAPPER[0]])
    rows = tuple((pin, inputs[source[0]]) for pin, source in zip(NATIVE_PINS, NATIVE))
    need(len(rows) == 2 and sum(len(raw) for pin, raw in rows) == 113296)
    return stage, wrapper, rows, dict(stage=stage_proof, wrapper=wrapper_proof,
        root=ROOT, native_files=2, native_bytes=113296, default_device_access=False,
        helper_execution_requested=False, owner_execution_requested=False, parent_payload_selected=False)


def native_payloads(inputs, namespace):
    stage, wrapper, rows, facts = assemble(inputs)
    for path, stage_mode in ((SOURCE_CMD, False), (STAGE_CMD, True)):
        raw = inputs[path]
        text = raw.decode('ascii')
        need('%*' not in text and '--check-device' not in text and
             text.count('host\\device_go_readonly_native_v1_check.py') == 1 and
             text.count('--stage-native') == (1 if stage_mode else 0), 'input_pin')
        inputs[path] = raw
    generator = namespace['selected_generator'](inputs[GENERATOR[0]])
    inner, wire = generator['make_program']('native', rows, stage)
    data, wrapper_final = generator['bootstrap_parts']([('native', inner)], [('native', wire)], wrapper)
    program = generator['bootstrap_program']('native', data, wrapper_final,
                                              namespace['literal'](inputs[ENVELOPE[0]], 'ENVELOPE'))
    need(len(program) <= 2097152 and max(map(len, program.splitlines())) <= 256, 'source_budget')
    need(len(wire) <= 4194304 and max(map(len, wire.splitlines())) <= 256, 'source_budget')
    ast.parse(program.decode('ascii'), feature_version=(3, 5))
    facts['assembled_wrapper_pin'] = (len(wrapper_final), sha(wrapper_final))
    facts['assembled_stage_pin'] = (len(stage), sha(stage))
    namespace['_native_final_wrapper_raw'] = wrapper_final
    namespace['_native_source_facts'] = facts
    return (program, wire), None, ()


def derive_host(raw):
    source = raw.decode('ascii')
    old_doc = source.split('"""', 2)[1]
    new_doc = ('One fixed native2 files-only stage; default PC SOURCE.\n\n'
        'No helper/Parent/Owner/Boot/UI/transfer/RF/history action. Explicit mode uses\n'
        'the existing fixed legacy-ADB carrier, never old main or old SOURCE checks.\n'
        'Device source and raw stay private; public ZIP is result.json and README.txt.\n')
    payload = ast.get_source_segment(source, next(node for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == 'payloads'))
    new_payload = 'def payloads(inputs):\n    return _native_payloads(inputs, globals())'
    new_payload += '\n' * (payload.count('\n') - new_payload.count('\n'))
    changes = [
        ('"""' + old_doc + '"""', '"""' + new_doc + '"""', 1),
        (assign(raw, 'SELF'), 'SELF = ' + repr(SELF), 1),
        (assign(raw, 'CMD'), 'CMD = ' + repr(SOURCE_CMD), 1),
        (assign(raw, 'ROOT'), 'ROOT = ' + repr(ROOT), 1),
        (assign(raw, 'STAGE'), 'STAGE = ' + repr(STAGE), 1),
        (assign(raw, 'WRAPPER'), 'WRAPPER = ' + repr(WRAPPER), 1),
        (payload, new_payload, 1),
        ("    group.add_argument('--stage-device', action='store_true', help='Only publish the fixed isolated 41-file root.')\n"
         "    group.add_argument('--check-device', action='store_true', help='One actual readonly Parent child; requires that root.')",
         "    group.add_argument('--stage-native', action='store_true', help='Only publish the fixed two-file native root.')", 1),
        ("mode = 'stage' if args.stage_device else 'parent' if args.check_device else 'source'",
         "mode = 'stage' if args.stage_native else 'source'", 1),
        ("'go-observer-libc-v1-' + mode", "'go-readonly-native-v1-' + mode", 1),
        ("kind='go-observer-libc-v1-thin'", "kind='go-readonly-native-v1-files-only'", 1),
        ('observer_files=41, observer_bytes=1442508, parent_inline_only=True',
         'native_files=2, native_bytes=113296, parent_inline_only=False', 1),
        ('parent_active_seconds=30,\n        parent_cleanup_seconds=5, parent_task_seconds=40, parent_outer_seconds=50,',
         'parent_active_seconds=None,\n        parent_cleanup_seconds=None, parent_task_seconds=None, parent_outer_seconds=None,', 1),
        ('        stage_payload, check_payload, reasons = payloads(inputs)',
         '        stage_payload, check_payload, reasons = payloads(inputs)\n'
         "        report['source_contract_verified'] = True\n"
         "        report['native_root'] = ROOT\n"
         "        source_proof = dict(_native_source_facts, host=_native_host_source_proof)\n"
         "        write_new(private / 'native-source-contract.private.json',\n"
         "            (json.dumps(source_proof, sort_keys=True, indent=2) + '\\n').encode('ascii'))\n"
         "        write_new(private / 'native-host-derived.private.py', _native_host_source_raw)\n"
         "        write_new(private / 'native-wrapper-final.private.py', _native_final_wrapper_raw)", 1),
        ("(('stage', stage_payload), ('parent', check_payload))", "(('stage', stage_payload),)", 1),
        ("('observer', 41, 1442508, len(program), sha(program), len(wire), sha(wire))",
         "('native', 2, 113296, len(program), sha(program), len(wire), sha(wire))", 2),
        ("program, wire = stage_payload if mode == 'stage' else check_payload", 'program, wire = stage_payload', 1),
        ("report['stage_invoked'] = mode == 'stage'\n            report['parent_invoked'] = mode == 'parent'",
         "report['stage_invoked'] = True\n            report['parent_invoked'] = False", 1),
        ("210 if mode == 'stage' else 75", '210', 1),
        ("            if mode == 'parent':\n                report['parent_result'] = parse_parent(raw, reasons, private)\n"
         "            else:\n                stage, bootstrap, ignored = helper.parse_results(raw, 'observer')\n"
         "                report['stage_result'], report['bootstrap_result'] = stage, bootstrap",
         "            stage, bootstrap, ignored = helper.parse_results(raw, 'native')\n"
         "            report['stage_result'], report['bootstrap_result'] = stage, bootstrap", 1),
        ("'parent_refused' if mode == 'parent' else 'stage_refused'", "'stage_refused'", 1),
        ("            if mode == 'parent':\n                need(parent_completed(report['parent_result']), 'parent_refused')\n"
         "            else:\n                need(helper.completed(report['stage_result'], report['bootstrap_result'], row), 'stage_refused')",
         "            need(helper.completed(report['stage_result'], report['bootstrap_result'], row), 'stage_refused')", 1),
        ("b'Default PC SOURCE; explicit --stage-device or --check-device only.\\n'", "b'Default PC SOURCE; explicit --stage-native only.\\n'", 1),
        ("b'41 pinned observer files in a new isolated 0700 root, 0400 files; EXCL, no overwrite/delete.\\n'",
         "b'Two known native files,113296 bytes,0500 in fixed fresh 0700 root/native; EXCL,no overwrite/delete.\\n'", 1),
        ("b'Stage original120/180; readonly Parent original30+5 within fixed40, outer50.\\n'",
         "b'Stage original120/180,HOST210; no Parent payload or invocation.\\n'", 1),
        ("b'Parent uses fixed read-only capability helpers; no Owner/UI/transfer/RF/history/repair.\\n'",
         "b'Native files are never executed; no helper/Owner/Boot/UI/transfer/RF/history/repair.\\n'", 1),
    ]
    value, ledger = edits(raw, changes)
    # Literal STAGE/WRAPPER replacements remove one continuation line each.
    # Restore line positions of all pre-main original definitions mechanically.
    value = value.replace(('STAGE = ' + repr(STAGE) + '\n').encode('ascii'),
                          ('STAGE = ' + repr(STAGE) + '\n\n').encode('ascii'), 1)
    value = value.replace(('WRAPPER = ' + repr(WRAPPER) + '\n').encode('ascii'),
                          ('WRAPPER = ' + repr(WRAPPER) + '\n\n').encode('ascii'), 1)
    normalized = value.replace(('STAGE = ' + repr(STAGE) + '\n\n').encode('ascii'),
                               ('STAGE = ' + repr(STAGE) + '\n').encode('ascii'), 1)
    normalized = normalized.replace(('WRAPPER = ' + repr(WRAPPER) + '\n\n').encode('ascii'),
                                     ('WRAPPER = ' + repr(WRAPPER) + '\n').encode('ascii'), 1)
    before_reverse = normalized
    for at, before, after in reversed(ledger):
        need(before_reverse[at:at + len(after)] == after)
        before_reverse = before_reverse[:at] + before + before_reverse[at + len(after):]
    need(before_reverse == raw)
    unchanged = same_definitions(raw, value, ('payloads', 'main'))
    main_node = next(node for node in ast.parse(value.decode('ascii')).body
                     if isinstance(node, ast.FunctionDef) and node.name == 'main')
    called = {node.func.id for node in ast.walk(main_node)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    need(not called.intersection(('parent_payload', 'parse_parent', 'parent_completed')))
    need(value.count(b"args.check_device") == 0 and value.count(b"args.stage_device") == 0)
    return value, dict(edits=len(ledger), unchanged_definitions=unchanged,
                      complete_byte_inverse=True, complete_ast_inverse=True,
                      only_payloads_main_and_fixed_constants_derived=True, no_parent_calls_in_main=True)


def main():
    inputs = {}
    mother = fixed(inputs, HOST_MOTHER)
    raw, proof = derive_host(mother)
    value = types.ModuleType('go_readonly_native_v1_host_private')
    value.__file__ = str(BASE / SELF)
    value.__dict__['_native_payloads'] = native_payloads
    value.__dict__['_native_host_source_proof'] = proof
    value.__dict__['_native_host_source_raw'] = raw
    # The frozen HOST's __main__ guard is false here. This is the new, narrowed
    # SOURCE/stage-native main; definition loading executes no old main, suite,
    # Parent or target code. Only its explicit stage mode later accesses ADB.
    exec(compile(raw, value.__file__ + ':derived', 'exec'), value.__dict__)
    need(value.ROOT == ROOT and value.STAGE == STAGE and value.WRAPPER == WRAPPER)
    return value.main()


if __name__ == '__main__':
    raise SystemExit(main())
