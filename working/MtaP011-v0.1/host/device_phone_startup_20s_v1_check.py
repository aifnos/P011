"""Independent authorized prepare20 phone shell; default SOURCE, no new window.

Only fixed graph/root/provenance/report bindings derive the frozen FC phone
recipe. PHONE, strict schema, trace, actual READY15, one120/peer15, Trial,
Owner600+cleanup60, alarm780/HOST790, cancellation and close/PASS stay exact.
Preparation20 applies in reading/importing; collector10 is a separate child
cap, both bounded by the retained original Owner deadline with no renewal.
No old main/test, generator, graph build, profiler or automatic ADB is invoked.
Device mode is only the original explicit option, after new phone readiness.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_startup_20s_v1_check.py'
CMDS = ('HOST_MTA_PHONE_STARTUP_20S_V1_CHECK.cmd',
        'TEST_MTA_PHONE_STARTUP_20S_V1.cmd')
MOTHER = ('host/device_phone_fc_http_cap_v1_check.py', 10020,
          '36cee1b7247e616d81b2657b28542805f06a52c0ce65b3276bb8dda4c9e2c216')
DEFINITIONS = ('host/formal_receive_startup_20s_v1_definitions.py', 297239,
               '49a56e7e809f2f515ca66735a38adf68d162aea1697e8d6a17cd74d0f68c61ca')
RUNNER = ('candidate/receive-startup-20s-graph-v1/runtime/mta_formal_receive_session.py', 79281,
          'fe0aa4d5b00ef071ac213056c4db6215527c0ac2df78be471b2dcc7721453554')
GRAPH_GENERATION = ('candidate/receive-startup-20s-graph-v1/graph-generation.json', 4018,
                    '050b47d1ef6e28035f84d446a098279785fd55cda487cd0c514eb25c575dc563')
GRAPH_RECIPE = ('candidate/receive-startup-20s-graph-v1/generate_graph.py', 41819,
                'e3b690ff769187c48d87448198371d8025ed8fcdd9ae78678f8e17cf56e338d8')
SEED_GENERATOR = ('candidate/receive-startup-20s-v1/generate_seed.py', 8560,
                  '313186ad15e4a6eb6c8d148c08a99044c572f7bb105b2fd8ade774214e11f84c')
SEED_DELTA = ('candidate/receive-startup-20s-v1/exactsource-delta.json', 1823,
              '935415b58c9ee53ac860398bd89819eac6a1a9e8492cb9ad9bdd7b81823c4a3f')
SEED_FACTORY = ('candidate/receive-startup-20s-v1/runtime/mta_client_receive_factory.py', 99675,
                '32784fee80f5e74d8e49e4a517e5dc5d45f297c0ad2f5bad42b343b81872da4d')
READ_ME = (b'Independent authorized prepare20 receive-only phone observation. Default SOURCE: no ADB or RF.\n'
    b'Explicit --check-device requires Root fresh baseline, new phone readiness and actual native READY.\n'
    b'Physical root p011-mta-rx-prep20-v001; exclusive phone command marker and result namespace.\n'
    b'Actual75 payload4193768 within4MiB (536 spare), flat304, mechanical6, 6 changed/69 exact.\n'
    b'Exactly one new business constant STARTUP_READ_SECONDS; inherited profile DATA is separately validated.\n'
    b'Prior Owner/Scope/FC HTTP business and complete mechanical/manifests provenance remain validated.\n'
    b'Separate unchanged FC9 sources113832 within131072; no new phone business method or profiler field.\n'
    b'Phone28352, strict five-field schema5907, trace14820 and retained window projection unchanged.\n'
    b'Five cached publication DATA fields do not promote readiness, Trial, authentication or success.\n'
    b'Preparation20 only in reading/importing, then separate collector10; both retain original Owner cap.\n'
    b'Publication120, actual native READY15, one phone120, peer15 and observation135 are unchanged.\n'
    b'Original Owner600/cleanup60, alarm780/host790, private-first exits/raw and stock finalizer remain.\n'
    b'Notify click only after this run actual typed native READY; no fabricated user confirmation.\n'
    b'No automatic accept/send, HTTP, UI, Guardian, records handling or full network restoration claim.\n'
    b'Captured-and-cancelled is classification, not CONNECT/TLS/file-transfer or phone compatibility PASS.\n'
    b'No old main/tests, generator, graph build, runtime rewrite, profiler or binary build invoked.\n'
    b'Prior SOURCE/Startup evidence does not substitute for this actual phone window or new device-root checks.\n'
    b'New phone readiness is required; SOURCE or source authoring does not request or open a device window.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def assignment_region(raw, name, function=None):
    tree = ast.parse(raw.decode('ascii'))
    body = tree.body
    if function is not None:
        functions = [node for node in body if isinstance(node, ast.FunctionDef) and node.name == function]
        need(len(functions) == 1, 'phone_prepare20_local_function')
        body = functions[0].body
    rows = [node for node in body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'phone_prepare20_assignment_unique')
    node = rows[0]
    return b''.join(raw.splitlines(keepends=True)[node.lineno - 1:node.end_lineno]), node.value


def without_entry(raw, code):
    tree = ast.parse(raw.decode('ascii'))
    need(len(tree.body) > 1 and isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test, include_attributes=False) == ast.dump(
             ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False), code)
    tree.body.pop()
    return tree


def derive(raw):
    """Eighteen finite recipe edits; full inverse, only derive() body changes."""
    need(type(raw) is bytes and (len(raw), digest(raw)) == MOTHER[1:], 'phone_prepare20_frozen_recipe')
    candidate, edits = raw, []

    def change(before, after, count=1):
        nonlocal candidate
        need(type(before) is bytes and type(after) is bytes and before != after and
             candidate.count(before) == count and candidate.count(after) == 0,
             'phone_prepare20_exact_forward')
        candidate = candidate.replace(before, after)
        edits.append((before, after, count))

    for name, value in (('SELF', SELF), ('CMDS', CMDS), ('DEFINITIONS', DEFINITIONS),
                        ('RUNNER', RUNNER), ('GRAPH_GENERATION', GRAPH_GENERATION), ('READ_ME', READ_ME)):
        region, unused = assignment_region(candidate, name)
        change(region, (name + ' = ' + repr(value) + '\n').encode('ascii'))
    for before, after, count in (
        (b"definitions.STATE_ALIAS == \\'/tmp/p011-mta-rx-fccap-v0001\\'",
         b"definitions.STATE_ALIAS == \\'/tmp/p011-mta-rx-prep20-v001\\'", 1),
        (b"definitions.STATE_ROOT == \\'/var/volatile/tmp/p011-mta-rx-fccap-v0001\\'",
         b"definitions.STATE_ROOT == \\'/var/volatile/tmp/p011-mta-rx-prep20-v001\\'", 1),
        (b'definitions.PAYLOAD_BYTES == 4193464 and len(definitions.ORIGIN_SOURCE_PINS) == 274,',
         b'definitions.PAYLOAD_BYTES == 4193768 and len(definitions.ORIGIN_SOURCE_PINS) == 304,', 1),
        (b'flat_origin_pins=274, mechanical_closures=6,', b'flat_origin_pins=304, mechanical_closures=6,', 1),
        (b"selected_graph=\\'fc-http-cap-v1\\'", b"selected_graph=\\'startup-20s-v1\\'", 1),
        (b'fc_http_cap_runner_configured=True,', b'startup_20s_runner_configured=True,', 1),
        (b'phone-fc-http-cap-v1-', b'phone-startup-20s-v1-', 1),
        (b"schema=\\'p011-phone-fc-http-cap-v1\\'", b"schema=\\'p011-phone-startup-20s-v1\\'", 1),
        (b'p011-phone-fc-http-cap-v1; ', b'p011-phone-startup-20s-v1; ', 1),
    ):
        change(before, after, count)

    region, value = assignment_region(candidate, 'budget_after', 'derive')
    budget = ast.literal_eval(value)
    need(type(budget) is bytes and budget.count(b'definitions.BUSINESS_CLOSURE_COUNT == 2 and') == 1 and
         budget.count(b'filecenter_http_business_sources=2, observer_closures=1,') == 1,
         'phone_prepare20_frozen_budget_insertion')
    budget = budget.replace(b'definitions.BUSINESS_CLOSURE_COUNT == 2 and',
                            b'definitions.BUSINESS_CLOSURE_COUNT == 1 and', 1)
    budget = budget.replace(b'filecenter_http_business_sources=2, observer_closures=1,',
        b'business_closures=1, inherited_profile_cache_verified=True, observer_closures=1,', 1)
    budget += (
        b"        (b'startup_preparation_max_seconds=10,',\n"
        b"         b'startup_preparation_max_seconds=20, collector_max_seconds=10,'),\n")
    change(region, ('    budget_after = ' + repr(budget) + '\n').encode('ascii'))

    anchor = b"    budget_before = b'    for before, after in (\\n'\n"
    extra = (
        b'    for before, after in (\n'
        b'        (b"b\'sum(row[2] for row in payload) == 4193464 <= 4194304,\'",\n'
        b'         b"b\'sum(row[2] for row in payload) == 4193768 <= 4194304,\'"),\n'
        b'        (b"b\'payload_bytes=4193464, payload_remaining_bytes=840,\'",\n'
        b'         b"b\'payload_bytes=4193768, payload_remaining_bytes=536,\'"),\n'
        b'    ):\n'
        b'        change(before, after)\n')
    change(anchor, extra + anchor)
    change(b"need(len(edits) == 16, 'fc_http_cap_phone_exact_sixteen_pc_edits')",
           b"need(len(edits) == 18, 'phone_prepare20_exact_eighteen_pc_edits')")

    restored = candidate
    for before, after, count in reversed(edits):
        need(restored.count(after) == count, 'phone_prepare20_exact_reverse')
        restored = restored.replace(after, before)
    need(len(edits) == 18 and restored == raw and
         ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'phone_prepare20_full_recipe_inverse')
    old_defs = {node.name: node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    new_defs = {node.name: node for node in ast.parse(candidate).body if isinstance(node, ast.FunctionDef)}
    old_lines, new_lines = raw.splitlines(keepends=True), candidate.splitlines(keepends=True)
    need(set(old_defs) == set(new_defs) and all(
         ast.dump(node, include_attributes=False) == ast.dump(new_defs[name], include_attributes=False) and
         b''.join(old_lines[node.lineno - 1:node.end_lineno]) ==
         b''.join(new_lines[new_defs[name].lineno - 1:new_defs[name].end_lineno])
         for name, node in old_defs.items() if name != 'derive'),
         'phone_prepare20_all_other_recipe_helpers_byte_exact')
    return candidate


def prepare():
    pins = (MOTHER, DEFINITIONS, RUNNER, GRAPH_GENERATION, GRAPH_RECIPE,
            SEED_GENERATOR, SEED_DELTA, SEED_FACTORY)
    need(all(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and 0 < pin[1] <= 2097152 and type(pin[2]) is str and
             len(pin[2]) == 64 and all(char in '0123456789abcdef' for char in pin[2]) for pin in pins),
         'phone_prepare20_final_graph_pins')
    raw = (BASE / MOTHER[0]).read_bytes()
    selected_raw = derive(raw)
    selected = types.ModuleType('fixed_phone_startup_20s_v1_recipe')
    selected.__file__ = str(BASE / SELF)
    exec(compile(without_entry(selected_raw, 'phone_prepare20_only_recipe_entry_removed'),
                 selected.__file__, 'exec'), selected.__dict__)
    driver = selected.prepare()
    need(driver.SELF == SELF and driver.CMDS == CMDS and driver.DEFINITIONS == DEFINITIONS and
         selected.RUNNER == RUNNER and selected.GRAPH_GENERATION == GRAPH_GENERATION,
         'phone_prepare20_effective_driver_bindings')
    driver.INPUTS[MOTHER[0]] = raw
    original_inputs = driver.publication_inputs

    def publication_inputs():
        need(driver.fixed(MOTHER) == raw, 'phone_prepare20_recipe_preserved')
        for pin in (GRAPH_RECIPE, SEED_GENERATOR, SEED_DELTA, SEED_FACTORY):
            driver.fixed(pin)
        original_inputs()

    driver.publication_inputs = publication_inputs
    return driver


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'phone_prepare20_explicit_mode')
    return prepare().main()


if __name__ == '__main__':
    raise SystemExit(main())
