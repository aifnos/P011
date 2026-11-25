"""Default SOURCE; explicit original receive-only phone window on Scope75.

One frozen PC carrier is mechanically derived in memory. No graph generation,
runtime rewrite, old main, model, build or automatic phone/device invocation.
The original PHONE/schema/trace/READY/Trial/deadlines/close/PASS remain intact.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_scope_dispatch_v1_check.py'
CMDS = ('HOST_MTA_PHONE_SCOPE_DISPATCH_V1_SOURCE_ONLY.cmd',
        'TEST_MTA_PHONE_SCOPE_DISPATCH_V1.cmd')
MOTHER = ('host/device_phone_publication_progress_v1_check.py', 11107,
          '3cfeabcefc04da268ebc55c8a153f0a1adc5357b9893f8278f6aeec6b9d96c6b')
DEFINITIONS = ('host/formal_receive_scope_dispatch_v1_definitions.py', 178958,
               'bcf738217c0821a14d732872cb1520e0e090f507272e588f8659d40b07bf28e3')
RUNNER = ('candidate/receive-scope-dispatch-graph-v1/runtime/mta_formal_receive_session.py', 79281,
          '70a348bbe1288edbd3fdf2f26c774289372bd81510a4d15809a0e5ff8e1905a7')
GRAPH_GENERATION = ('candidate/receive-scope-dispatch-graph-v1/graph-generation.json', 2858,
                    'b64314a64f8ef7cc9463a8ca39d7db14c973b80f6e71ce88b45c2b033834433a')
READ_ME = (b'Scope dispatch75 receive-only phone observation. Default SOURCE: no ADB or RF.\n'
    b'Explicit --check-device requires Root fresh baseline, new phone readiness and actual native READY.\n'
    b'Physical root p011-mta-rx-scope-v0001; exclusive phone command marker and result namespace.\n'
    b'Actual75 payload4193464 within4MiB (840 spare), flat260, mechanical6/business1, 6 changed/69 exact.\n'
    b'Existing Owner and Scope dispatch deltas are graph inputs, not new phone business methods.\n'
    b'Phone28352, strict five-field schema5907, trace14820 and retained window projection unchanged.\n'
    b'Five cached publication DATA fields do not promote readiness, Trial, authentication or success.\n'
    b'Original Startup10, Publication120, native READY15, phone120, peer15, observation135.\n'
    b'Original Owner600/cleanup60, alarm780/host790, private-first exits/raw and stock finalizer remain.\n'
    b'No automatic accept/send, HTTP, UI, Guardian, records handling or full network restoration claim.\n'
    b'No old graph/main/tests, generator, runtime rewrite, new model or binary build invoked.\n'
    b'No-RF Startup evidence does not substitute for this phone window or CONNECT/TLS/file acceptance.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def assignment_region(raw, name):
    tree = ast.parse(raw.decode('utf-8'))
    rows = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'scope_phone_assignment_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno - 1:rows[0].end_lineno])


def derive(raw):
    """Only six PC bindings and eleven exact destination-side literals; full inverse."""
    need(type(raw) is bytes and (len(raw), digest(raw)) == MOTHER[1:], 'scope_phone_mother_pin')
    candidate, edits = raw, []

    def change(before, after):
        nonlocal candidate
        need(type(before) is bytes and type(after) is bytes and before != after and
             candidate.count(before) == 1 and candidate.count(after) == 0, 'scope_phone_exact_forward')
        candidate = candidate.replace(before, after, 1)
        edits.append((before, after))

    for name, value in (('SELF', SELF), ('CMDS', CMDS), ('DEFINITIONS', DEFINITIONS),
                        ('RUNNER', RUNNER), ('GRAPH_GENERATION', GRAPH_GENERATION), ('READ_ME', READ_ME)):
        change(assignment_region(candidate, name), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    for before, after in (
        (b'b"definitions.STATE_ALIAS == \'/tmp/p011-mta-rx-progress-v1\'"',
         b'b"definitions.STATE_ALIAS == \'/tmp/p011-mta-rx-scope-v0001\'"'),
        (b'b"definitions.STATE_ROOT == \'/var/volatile/tmp/p011-mta-rx-progress-v1\'"',
         b'b"definitions.STATE_ROOT == \'/var/volatile/tmp/p011-mta-rx-scope-v0001\'"'),
        (b"b'definitions.PAYLOAD_BYTES == 4193272 and len(definitions.ORIGIN_SOURCE_PINS) == 230,'",
         b"b'definitions.PAYLOAD_BYTES == 4193464 and len(definitions.ORIGIN_SOURCE_PINS) == 260,'"),
        (b"b'sum(row[2] for row in payload) == 4193272 <= 4194304,'",
         b"b'sum(row[2] for row in payload) == 4193464 <= 4194304,'"),
        (b"b'payload_bytes=4193272, payload_remaining_bytes=1032,'",
         b"b'payload_bytes=4193464, payload_remaining_bytes=840,'"),
        (b"b'flat_origin_pins=230, mechanical_closures=6,'",
         b"b'flat_origin_pins=260, mechanical_closures=6,'"),
        (b'b"selected_graph=\'publication-progress-v1\'"', b'b"selected_graph=\'scope-dispatch-v1\'"'),
        (b"b'publication_progress_runner_configured=True,'", b"b'scope_dispatch_runner_configured=True,'"),
        (b'b"\'phone-publication-progress-v1-\' + mode"', b'b"\'phone-scope-dispatch-v1-\' + mode"'),
        (b'b"schema=\'p011-phone-publication-progress-v1\'"', b'b"schema=\'p011-phone-scope-dispatch-v1\'"'),
        (b'b\'p011-phone-publication-progress-v1; \'', b'b\'p011-phone-scope-dispatch-v1; \''),
    ):
        change(before, after)
    restored = candidate
    for before, after in reversed(edits):
        need(restored.count(after) == 1, 'scope_phone_exact_reverse')
        restored = restored.replace(after, before, 1)
    need(restored == raw and ast.dump(ast.parse(restored.decode('utf-8')), include_attributes=False) ==
         ast.dump(ast.parse(raw.decode('utf-8')), include_attributes=False), 'scope_phone_full_byte_ast_inverse')
    old_tree, new_tree = ast.parse(raw.decode('utf-8')), ast.parse(candidate.decode('utf-8'))
    old_defs = {node.name: node for node in old_tree.body if isinstance(node, ast.FunctionDef)}
    new_defs = {node.name: node for node in new_tree.body if isinstance(node, ast.FunctionDef)}
    need(set(old_defs) == set(new_defs) and all(ast.dump(old_defs[name], include_attributes=False) ==
         ast.dump(new_defs[name], include_attributes=False) for name in old_defs if name != 'derive_host'),
         'scope_phone_other_definitions_unchanged')
    old_lines, new_lines = raw.splitlines(keepends=True), candidate.splitlines(keepends=True)
    need(all(b''.join(old_lines[node.lineno - 1:node.end_lineno]) ==
         b''.join(new_lines[new_defs[name].lineno - 1:new_defs[name].end_lineno])
         for name, node in old_defs.items() if name != 'derive_host'), 'scope_phone_other_definition_bytes')
    need(len(edits) == 17, 'scope_phone_exact_seventeen_pc_edits')
    return candidate


def prepare():
    raw = (BASE / MOTHER[0]).read_bytes()
    derived = derive(raw)
    tree = ast.parse(derived.decode('utf-8'))
    need(len(tree.body) > 1 and isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test, include_attributes=False) == ast.dump(
             ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False),
         'scope_phone_only_entry_guard_removed')
    tree.body.pop()
    selected = types.ModuleType('fixed_phone_scope_dispatch_v1_composition')
    selected.__file__ = str(BASE / SELF)
    exec(compile(tree, selected.__file__, 'exec'), selected.__dict__)
    driver = selected.prepare()
    need(driver.SELF == SELF and driver.CMDS == CMDS and driver.DEFINITIONS == DEFINITIONS,
         'scope_phone_effective_driver_bindings')
    driver.INPUTS[MOTHER[0]] = raw
    original_inputs = driver.publication_inputs

    def publication_inputs():
        need(driver.fixed(MOTHER) == raw, 'scope_phone_mother_preserved')
        original_inputs()

    driver.publication_inputs = publication_inputs
    return driver


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'scope_phone_explicit_mode')
    return prepare().main()


if __name__ == '__main__':
    raise SystemExit(main())
