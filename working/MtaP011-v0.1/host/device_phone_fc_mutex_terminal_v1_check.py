"""Independent FC mutex terminal-only phone shell; default SOURCE, no window.

The frozen terminal recipe is prepared without its entry/main. Only its real
Startup20 graph bindings and finite HOST budget/report literals derive here.
Prepare20 and new mutex counts are distinct; the original terminal module,
strict nine-field parser, HANDOFF_TRACE_RESULT, unavailable exception coverage,
phone/READY/peer15/Trial/IO/cancel/close/PASS policies remain unchanged.
SOURCE neither stages nor requests a phone window. DEVICE retains only the
original explicit option, after new readiness and this run native READY.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_fc_mutex_terminal_v1_check.py'
CMDS = ('HOST_MTA_PHONE_FC_MUTEX_TERMINAL_V1_CHECK.cmd',
        'TEST_MTA_PHONE_FC_MUTEX_TERMINAL_V1.cmd')
MOTHER = ('host/device_phone_terminal_20s_v1_check.py', 14665,
          '008d8abbdd54b4a8caad36c5511395e465934f996e3420c3758884543c5d7e4a')
STARTUP_RECIPE = ('host/device_phone_startup_20s_v1_check.py', 11931,
                  '7ca5f37ae5508fe996966886159e8053ff672dd68793420c2ef92679743bdd96')
DEFINITIONS = ('host/formal_receive_fc_mutex_v1_definitions.py', 574969,
               '4fce39627676c7f359dfd031ce8edb19e232c1a5981806895014829a4fbb8dfd')
RUNNER = ('candidate/receive-fc-mutex-graph-v1/runtime/mta_formal_receive_session.py', 79281,
          '3264be86704d8ba467a4d949dbe7a8141c24e2a2b60d486687f4b72816ab8f36')
GRAPH_GENERATION = ('candidate/receive-fc-mutex-graph-v1/graph-generation.json', 4365,
                    '57d30394018a7fd5f149193ea13a01e08e28c220a9429759e9e61b938d450418')
GRAPH_RECIPE = ('candidate/receive-fc-mutex-graph-v1/generate_graph.py', 43011,
                '98ad07f8dabe99fdfdca601da63138dc6bbd62fcf7dcbc277c65a648162534c8')
TERMINAL = ('candidate/receive-handoff-terminal-v1/runtime/handoff_terminal.py', 15049,
            'c77db43cb42d60f624b96bacb92e5a8c03b943faf82921059ab4d04b15085c97')
PHONE_SELECTOR = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
                  '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
FLAT_COUNT = 319
ROOT_NAME = 'p011-mta-rx-mlock1-v001'
PAYLOAD_BYTES = 4193768
FILECENTER_BYTES = 115400
PREPARE20_BUSINESS_COUNT = 1
MUTEX_BUSINESS_COUNT = 1
READ_ME = (b'Independent FC mutex terminal-only receive phone observation. Default SOURCE: no ADB/RF/window.\n'
    b'Explicit --check-device requires Root fresh baseline, new phone readiness and actual native READY.\n'
    b'Actual receive-fc-mutex graph, physical p011-mta-rx-mlock1-v001 root and 319 flat origins are fixed.\n'
    b'75 payload4193768 within4MiB (536 spare), six mechanical closures and 6 changed/69 exact roles.\n'
    b'Separate FC9/115400 within131072 (15672 spare); only mutex Companion changes, all other eight stay.\n'
    b'Retained prepare20 business1 and new mutex business1 are separately checked; profile cached DATA stays.\n'
    b'Original Owner/Scope/FC HTTP/cache/prepare20 provenance remains; no new phone business method.\n'
    b'Terminal15049 and strict nine-field receive-handoff-terminal-v1 parser remain unchanged.\n'
    b'HANDOFF_TRACE_RESULT stays; exception_events_observed=False and installed/restored=False are real coverage.\n'
    b'Empty exception events mean unobserved, not no errors; unknown terminal projection remains FAIL.\n'
    b'Original existing-hook refusal, finally close_trace and identity/actor/radio terminal projection remain.\n'
    b'Phone28352, strict five-field publication schema5907 and five cached publication DATA fields stay.\n'
    b'Preparation20 applies in reading/importing; collector10 is separate, within the original Owner cap.\n'
    b'Publication120, READY15, phone120, peer15, observation135, Owner600/cleanup60 and native TTL stay.\n'
    b'Alarm780/HOST790, original IO, cancellation, finalizer and all strict close/PASS predicates stay.\n'
    b'Notify click only after this run actual typed native READY; no fabricated readiness or user reply.\n'
    b'No peer60, automatic accept/send, HTTP/UI, profiler, record handling or full restore acceptance.\n'
    b'No full FC deadline, blocking-file-IO preemption, CONNECT/TLS/file-transfer or phone acceptance claim.\n'
    b'Pure graph/host byte and position-AST inverse only; no old main/tests, writer or graph build is called.\n'
    b'Private first raw/exits, source snapshots and public two-member seal stay; SOURCE never opens a window.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def function_region(raw, name):
    rows = [node for node in ast.parse(raw.decode('ascii')).body
            if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(rows) == 1 and not rows[0].decorator_list, 'mutex_phone_function_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno - 1:rows[0].end_lineno])


def assignment_region(raw, name):
    rows = [node for node in ast.parse(raw.decode('ascii')).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'mutex_phone_assignment_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno - 1:rows[0].end_lineno])


def without_entry(raw):
    tree = ast.parse(raw.decode('ascii'))
    need(len(tree.body) > 1 and isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test, include_attributes=False) == ast.dump(
             ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False),
         'mutex_phone_only_entry_removed')
    tree.body.pop()
    return tree


def derive_graph_recipe(raw):
    """Four graph pins, nine bytes literals and one finite budget insertion only."""
    candidate, edits = raw, []

    def change(before, after):
        nonlocal candidate
        need(type(before) is bytes and type(after) is bytes and before != after and
             candidate.count(before) == 1 and candidate.count(after) == 0, 'mutex_phone_exact_forward')
        candidate = candidate.replace(before, after, 1)
        edits.append((before, after))

    for name, value in (('DEFINITIONS', DEFINITIONS), ('RUNNER', RUNNER),
                        ('GRAPH_GENERATION', GRAPH_GENERATION), ('GRAPH_RECIPE', GRAPH_RECIPE)):
        change(assignment_region(candidate, name), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    bindings = (
        (b"definitions.STATE_ALIAS == \\'/tmp/p011-mta-rx-prep20-v001\\'",
         ("definitions.STATE_ALIAS == \\'/tmp/" + ROOT_NAME + "\\'").encode('ascii')),
        (b"definitions.STATE_ROOT == \\'/var/volatile/tmp/p011-mta-rx-prep20-v001\\'",
         ("definitions.STATE_ROOT == \\'/var/volatile/tmp/" + ROOT_NAME + "\\'").encode('ascii')),
        (b'definitions.PAYLOAD_BYTES == 4193768 and len(definitions.ORIGIN_SOURCE_PINS) == 304,',
         ('definitions.PAYLOAD_BYTES == ' + str(PAYLOAD_BYTES) + ' and len(definitions.ORIGIN_SOURCE_PINS) == ' +
          str(FLAT_COUNT) + ',').encode('ascii')),
        (b'flat_origin_pins=304, mechanical_closures=6,',
         ('flat_origin_pins=' + str(FLAT_COUNT) + ', mechanical_closures=6,').encode('ascii')),
        (b"selected_graph=\\'startup-20s-v1\\'", b"selected_graph=\\'fc-mutex-v1\\'"),
        (b'startup_20s_runner_configured=True,', b'fc_mutex_runner_configured=True,'),
        (b'phone-terminal-20s-v1-', b'phone-fc-mutex-terminal-v1-'),
        (b"schema=\\'p011-phone-terminal-20s-v1\\'", b"schema=\\'p011-phone-fc-mutex-terminal-v1\\'"),
        (b'p011-phone-terminal-20s-v1; ', b'p011-phone-fc-mutex-terminal-v1; '),
    )
    for before, after in bindings:
        nodes = [node for node in ast.walk(ast.parse(candidate.decode('ascii')))
                 if isinstance(node, ast.Constant) and type(node.value) is bytes and node.value == before]
        need(len(nodes) == 1, 'mutex_phone_one_real_driver_literal')
        literal = ast.get_source_segment(candidate.decode('ascii'), nodes[0]).encode('ascii')
        change(literal, repr(after).encode('ascii'))
    gate = (b'definitions.BUSINESS_CLOSURE_COUNT == 1 and\n'
            b'             definitions.MUTEX_BUSINESS_CLOSURE_COUNT == 1 and\n'
            b"             definitions.BUSINESS_EXPECTED == definitions.CURRENT_EXPECTED['BUSINESS_EXPECTED'] and")
    budget_edits = (
        (b"b'sum(row[2] for row in fc) == 113832 <= 131072,'",
         ("b'sum(row[2] for row in fc) == " + str(FILECENTER_BYTES) + " <= 131072,'").encode('ascii')),
        (b"b'filecenter_sources=9, filecenter_bytes=113832,'",
         ("b'filecenter_sources=9, filecenter_bytes=" + str(FILECENTER_BYTES) + ",' ").rstrip().encode('ascii')),
        (b"         b'definitions.BUSINESS_CLOSURE_COUNT == 1 and'),\n",
         b'         ' + repr(gate).encode('ascii') + b'),\n'),
        (b'business_closures=1, inherited_profile_cache_verified=True, observer_closures=1,',
         b'business_closures=1, retained_prepare20_business_closures=1, new_mutex_business_closures=1, '
         b'inherited_profile_cache_verified=True, observer_closures=1,'),
    )
    extra = '    for before, after in (\n'
    extra += ''.join('        (' + repr(before) + ', ' + repr(after) + '),\n' for before, after in budget_edits)
    extra += ("    ):\n        need(budget.count(before) == 1, 'mutex_phone_budget_anchor')\n"
              '        budget = budget.replace(before, after, 1)\n')
    anchor = b"    change(region, ('    budget_after = ' + repr(budget) + '\\n').encode('ascii'))\n"
    change(anchor, extra.encode('ascii') + anchor)
    restored = candidate
    for before, after in reversed(edits):
        need(restored.count(after) == 1, 'mutex_phone_exact_reverse')
        restored = restored.replace(after, before, 1)
    need(len(edits) == 14 and restored == raw and
         ast.dump(ast.parse(restored), include_attributes=True) == ast.dump(ast.parse(raw), include_attributes=True),
         'mutex_phone_complete_byte_position_ast_inverse')
    old_defs = {node.name: node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    new_defs = {node.name: node for node in ast.parse(candidate).body if isinstance(node, ast.FunctionDef)}
    need(set(old_defs) == set(new_defs) and all(
         ast.dump(node, include_attributes=False) == ast.dump(new_defs[name], include_attributes=False) and
         function_region(raw, name) == function_region(candidate, name)
         for name, node in old_defs.items() if name != 'derive'), 'mutex_phone_other_recipe_helpers_byte_exact')
    return candidate


def prepare():
    pins = (MOTHER, STARTUP_RECIPE, DEFINITIONS, RUNNER, GRAPH_GENERATION, GRAPH_RECIPE, TERMINAL, PHONE_SELECTOR)
    need(all(type(pin) is tuple and len(pin) == 3 and type(pin[0]) is str and
             type(pin[1]) is int and 0 < pin[1] <= 2097152 and type(pin[2]) is str and len(pin[2]) == 64 and
             all(char in '0123456789abcdef' for char in pin[2]) for pin in pins) and
         FLAT_COUNT == 319 and PAYLOAD_BYTES == 4193768 and FILECENTER_BYTES == 115400 and
         PREPARE20_BUSINESS_COUNT == MUTEX_BUSINESS_COUNT == 1, 'mutex_phone_frozen_graph_bindings')
    raw = (BASE / MOTHER[0]).read_bytes()
    need((len(raw), digest(raw)) == MOTHER[1:], 'mutex_phone_frozen_terminal_mother')
    parent = types.ModuleType('fixed_phone_fc_mutex_terminal_v1_parent')
    parent.__file__ = str(BASE / MOTHER[0])
    exec(compile(without_entry(raw), parent.__file__, 'exec'), parent.__dict__)
    need(parent.BASE == BASE and parent.MOTHER == STARTUP_RECIPE and parent.TERMINAL == TERMINAL and
         parent.PHONE_SELECTOR == PHONE_SELECTOR, 'mutex_phone_terminal_original_bindings')
    original_recipe = parent.derive_recipe
    parent.SELF, parent.CMDS, parent.READ_ME = SELF, CMDS, READ_ME

    def recipe(startup_raw):
        # Original terminal six edits still prove their complete inverse. Then
        # only this new fourteen-edit graph binding touches the frozen recipe.
        return derive_graph_recipe(original_recipe(startup_raw))

    parent.derive_recipe = recipe
    driver = parent.prepare()
    need(driver.SELF == SELF and driver.CMDS == CMDS and driver.DEFINITIONS == DEFINITIONS and
         driver.PHONE_SELECTOR == PHONE_SELECTOR, 'mutex_phone_effective_terminal_graph_driver')
    driver.INPUTS[MOTHER[0]] = raw
    original_inputs = driver.publication_inputs

    def publication_inputs():
        need(driver.fixed(MOTHER) == raw, 'mutex_phone_terminal_mother_preserved')
        for pin in (DEFINITIONS, RUNNER, GRAPH_GENERATION, GRAPH_RECIPE):
            driver.fixed(pin)
        original_inputs()

    driver.publication_inputs = publication_inputs
    return driver


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'mutex_phone_only_original_explicit_mode')
    return prepare().main()


if __name__ == '__main__':
    raise SystemExit(main())
