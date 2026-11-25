"""Default SOURCE; explicit original receive-only phone window on FC HTTP cap75.

Reuse the frozen Scope shell's pure derive, then mechanically bind its exact
publication carrier to the new immutable receive graph. No old main, generator,
model, build, test or automatic device/phone invocation. PHONE/schema/trace,
native READY, Trial, deadlines, cancellation and close/PASS remain intact.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_fc_http_cap_v1_check.py'
CMDS = ('HOST_MTA_PHONE_FC_HTTP_CAP_V1_CHECK.cmd',
        'TEST_MTA_PHONE_FC_HTTP_CAP_V1.cmd')
MOTHER = ('host/device_phone_scope_dispatch_v1_check.py', 8118,
          '663627350f72f5ec2df6a2ce2912051371ec5c80ff337020809a9ee2fce0bd31')
PUBLICATION_MOTHER = ('host/device_phone_publication_progress_v1_check.py', 11107,
                      '3cfeabcefc04da268ebc55c8a153f0a1adc5357b9893f8278f6aeec6b9d96c6b')
DEFINITIONS = ('host/formal_receive_fc_http_cap_v1_definitions.py', 169842,
               'c43f342a7c7ccafe5e2780de7f4068bdfe84195579b5f1c6e970d78ad19abfc2')
RUNNER = ('candidate/receive-fc-http-cap-graph-v1/runtime/mta_formal_receive_session.py', 79281,
          '1b0fe8a2959d81fa25eb66bad258965c2980380f5811c0e3562c448ea0a70333')
GRAPH_GENERATION = ('candidate/receive-fc-http-cap-graph-v1/graph-generation.json', 3479,
                    '925365e5186ff272082d0b2b084a31dce1a7189bedfdc719c3aa7d0b2112babe')
READ_ME = (b'FC HTTP cap75 receive-only phone observation. Default SOURCE: no ADB or RF.\n'
    b'Explicit --check-device requires Root fresh baseline, new phone readiness and actual native READY.\n'
    b'Physical root p011-mta-rx-fccap-v0001; exclusive phone command marker and result namespace.\n'
    b'Actual75 payload4193464 within4MiB (840 spare), flat274, mechanical6, 6 changed/69 exact.\n'
    b'Separate FC9 sources113832 within131072; exactly two FC HTTP business sources are checked.\n'
    b'Existing Owner/Scope changes and HTTP cap sources are inputs, not new phone business methods.\n'
    b'Phone28352, strict five-field schema5907, trace14820 and retained window projection unchanged.\n'
    b'Five cached publication DATA fields do not promote readiness, Trial, authentication or success.\n'
    b'Original Startup10, Publication120, native READY15, phone120, peer15, observation135.\n'
    b'Original Owner600/cleanup60, alarm780/host790, private-first exits/raw and stock finalizer remain.\n'
    b'No automatic accept/send, HTTP, UI, Guardian, records handling or full network restoration claim.\n'
    b'No old main/tests, graph verifier, generator, runtime rewrite, new model or binary build invoked.\n'
    b'Prior HTTP HOST evidence does not substitute for new root Stage or this actual phone window.\n'
    b'New phone readiness is still required; SOURCE cannot certify READY/CONNECT/TLS/file acceptance.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def assignment_region(raw, name):
    tree = ast.parse(raw.decode('utf-8'))
    rows = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'fc_http_cap_phone_assignment_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno - 1:rows[0].end_lineno])


def derive(raw):
    """Six PC bindings, nine destination literals and one four-constant insertion."""
    need(type(raw) is bytes, 'fc_http_cap_phone_scope_carrier')
    candidate, edits = raw, []

    def change(before, after):
        nonlocal candidate
        need(type(before) is bytes and type(after) is bytes and before != after and
             candidate.count(before) == 1 and candidate.count(after) == 0,
             'fc_http_cap_phone_exact_forward')
        candidate = candidate.replace(before, after, 1)
        edits.append((before, after))

    for name, value in (('SELF', SELF), ('CMDS', CMDS), ('DEFINITIONS', DEFINITIONS),
                        ('RUNNER', RUNNER), ('GRAPH_GENERATION', GRAPH_GENERATION), ('READ_ME', READ_ME)):
        change(assignment_region(candidate, name), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    for before, after in (
        (b'b"definitions.STATE_ALIAS == \'/tmp/p011-mta-rx-scope-v0001\'"',
         b'b"definitions.STATE_ALIAS == \'/tmp/p011-mta-rx-fccap-v0001\'"'),
        (b'b"definitions.STATE_ROOT == \'/var/volatile/tmp/p011-mta-rx-scope-v0001\'"',
         b'b"definitions.STATE_ROOT == \'/var/volatile/tmp/p011-mta-rx-fccap-v0001\'"'),
        (b"b'definitions.PAYLOAD_BYTES == 4193464 and len(definitions.ORIGIN_SOURCE_PINS) == 260,'",
         b"b'definitions.PAYLOAD_BYTES == 4193464 and len(definitions.ORIGIN_SOURCE_PINS) == 274,'"),
        (b"b'flat_origin_pins=260, mechanical_closures=6,'",
         b"b'flat_origin_pins=274, mechanical_closures=6,'"),
        (b'b"selected_graph=\'scope-dispatch-v1\'"', b'b"selected_graph=\'fc-http-cap-v1\'"'),
        (b"b'scope_dispatch_runner_configured=True,'", b"b'fc_http_cap_runner_configured=True,'"),
        (b'b"\'phone-scope-dispatch-v1-\' + mode"', b'b"\'phone-fc-http-cap-v1-\' + mode"'),
        (b'b"schema=\'p011-phone-scope-dispatch-v1\'"', b'b"schema=\'p011-phone-fc-http-cap-v1\'"'),
        (b'b\'p011-phone-scope-dispatch-v1; \'', b'b\'p011-phone-fc-http-cap-v1; \''),
    ):
        change(before, after)
    budget_before = b'    for before, after in (\n'
    budget_after = (
        b'    for before, after in (\n'
        b"        (b'sum(row[2] for row in fc) == 113690 <= 131072,',\n"
        b"         b'sum(row[2] for row in fc) == 113832 <= 131072,'),\n"
        b"        (b'filecenter_sources=9, filecenter_bytes=113690,',\n"
        b"         b'filecenter_sources=9, filecenter_bytes=113832,'),\n"
        b"        (b'definitions.BUSINESS_CLOSURE_COUNT == 1 and',\n"
        b"         b'definitions.BUSINESS_CLOSURE_COUNT == 2 and'),\n"
        b"        (b'business_closures=1, observer_closures=1,',\n"
        b"         b'filecenter_http_business_sources=2, observer_closures=1,'),\n"
    )
    change(budget_before, budget_after)
    restored = candidate
    for before, after in reversed(edits):
        need(restored.count(after) == 1, 'fc_http_cap_phone_exact_reverse')
        restored = restored.replace(after, before, 1)
    need(restored == raw and ast.dump(ast.parse(restored.decode('utf-8')), include_attributes=False) ==
         ast.dump(ast.parse(raw.decode('utf-8')), include_attributes=False),
         'fc_http_cap_phone_full_byte_ast_inverse')
    old_tree, new_tree = ast.parse(raw.decode('utf-8')), ast.parse(candidate.decode('utf-8'))
    old_defs = {node.name: node for node in old_tree.body if isinstance(node, ast.FunctionDef)}
    new_defs = {node.name: node for node in new_tree.body if isinstance(node, ast.FunctionDef)}
    need(set(old_defs) == set(new_defs) and all(ast.dump(old_defs[name], include_attributes=False) ==
         ast.dump(new_defs[name], include_attributes=False) for name in old_defs if name != 'derive_host'),
         'fc_http_cap_phone_other_definitions_unchanged')
    old_lines, new_lines = raw.splitlines(keepends=True), candidate.splitlines(keepends=True)
    need(all(b''.join(old_lines[node.lineno - 1:node.end_lineno]) ==
         b''.join(new_lines[new_defs[name].lineno - 1:new_defs[name].end_lineno])
         for name, node in old_defs.items() if name != 'derive_host'),
         'fc_http_cap_phone_other_definition_bytes')
    need(len(edits) == 16, 'fc_http_cap_phone_exact_sixteen_pc_edits')
    return candidate


def without_entry(raw, code):
    tree = ast.parse(raw.decode('utf-8'))
    need(len(tree.body) > 1 and isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test, include_attributes=False) == ast.dump(
             ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False), code)
    tree.body.pop()
    return tree


def prepare():
    scope_raw = (BASE / MOTHER[0]).read_bytes()
    publication_raw = (BASE / PUBLICATION_MOTHER[0]).read_bytes()
    need((len(scope_raw), digest(scope_raw)) == MOTHER[1:] and
         (len(publication_raw), digest(publication_raw)) == PUBLICATION_MOTHER[1:],
         'fc_http_cap_phone_frozen_mothers')
    scope = types.ModuleType('fixed_phone_fc_http_cap_v1_scope_deriver')
    scope.__file__ = str(BASE / MOTHER[0])
    exec(compile(without_entry(scope_raw, 'fc_http_cap_phone_scope_entry_guard'),
                 scope.__file__, 'exec'), scope.__dict__)
    need(scope.MOTHER == PUBLICATION_MOTHER, 'fc_http_cap_phone_scope_actual_mother')
    original_scope_carrier = scope.derive(publication_raw)
    derived = derive(original_scope_carrier)
    selected = types.ModuleType('fixed_phone_fc_http_cap_v1_composition')
    selected.__file__ = str(BASE / SELF)
    exec(compile(without_entry(derived, 'fc_http_cap_phone_composition_entry_guard'),
                 selected.__file__, 'exec'), selected.__dict__)
    driver = selected.prepare()
    need(driver.SELF == SELF and driver.CMDS == CMDS and driver.DEFINITIONS == DEFINITIONS and
         selected.RUNNER == RUNNER and selected.GRAPH_GENERATION == GRAPH_GENERATION,
         'fc_http_cap_phone_effective_driver_bindings')
    driver.INPUTS[MOTHER[0]] = scope_raw
    driver.INPUTS[PUBLICATION_MOTHER[0]] = publication_raw
    original_inputs = driver.publication_inputs

    def publication_inputs():
        need(driver.fixed(MOTHER) == scope_raw and
             driver.fixed(PUBLICATION_MOTHER) == publication_raw,
             'fc_http_cap_phone_mothers_preserved')
        original_inputs()

    driver.publication_inputs = publication_inputs
    return driver


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'fc_http_cap_phone_explicit_mode')
    return prepare().main()


if __name__ == '__main__':
    raise SystemExit(main())
