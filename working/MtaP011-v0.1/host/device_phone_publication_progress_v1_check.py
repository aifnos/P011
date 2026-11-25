"""Default SOURCE; explicit original receive-only phone window, new DATA graph.

Pure frozen composition only. No old main, verifier, suite, build or automatic
device invocation. The original READY/120s/15s/cancel/close/PASS gates remain.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_publication_progress_v1_check.py'
CMDS = ('HOST_MTA_PHONE_PUBLICATION_PROGRESS_V1_SOURCE_ONLY.cmd',
        'TEST_MTA_PHONE_PUBLICATION_PROGRESS_V1.cmd')
MOTHER = ('host/device_phone_handoff_proc_freezer_v1_check.py', 34359,
          '9aa1d6b4460e9566e0600dac245f70caf34e7842b299db55f8dedfeb3711af4c')
DEFINITIONS = ('host/formal_receive_publication_progress_v1_definitions.py', 123101,
               '3ae9820d752c9ed2d7ea582ece3ae6e248a9a69596e047e2a3dd5ed6ae294e49')
RUNNER = ('candidate/receive-publication-progress-graph-v1/runtime/mta_formal_receive_session.py', 79281,
          'c867b9eb52a4cf6ac81367163f22d6d5bfbbed88595313802100960746119410')
PHONE = ('candidate/receive-publication-progress-v1/runtime/phone_discovery_session.py', 28352,
         'cdfcec298c2da5b2ec2eff931b06da4381c56ddcba39a163cb8b58dad4108d12')
SCHEMA = ('host/phone_publication_progress_v1_schema.py', 5907,
          '60e97088233ea1fd26abce7e54070c1f4c3166c5721e9f5c9478045d25eca9ee')
GRAPH_GENERATION = ('candidate/receive-publication-progress-graph-v1/graph-generation.json', 2867,
                    'ed6bf2d2f833749b8e44afdcdcf45ed726da9bb5871a0f6316c1c712359f6add')
READ_ME = (b'Publication progress75 receive-only phone observation. Default SOURCE: no ADB or RF.\n'
    b'Explicit --check-device requires Root fresh baseline, phone readiness and native READY.\n'
    b'New p011-mta-rx-progress-v1 physical/alias root; exclusive phone command marker.\n'
    b'Actual75 payload4193272 within4MiB (1032 spare), flat230, mechanical6/business1, 6 changed/69 exact.\n'
    b'Factory cached tuple DATA and phone28352 projection only; original full strict parser is delegated.\n'
    b'Five publication fields do not promote original known/readiness/Trial/success/closure results.\n'
    b'Unknown DATA retains all four values None; start has count0 and elapsed None.\n'
    b'Elapsed values are cached sample deltas, not live time or exact operation durations.\n'
    b'Original trace14820, READY15, phone120, peer15, observation135, Owner600/cleanup60, alarm780/host790.\n'
    b'Original native input guards, private-first raw/exits, source/result ZIP readback and stock finally remain.\n'
    b'No file acceptance/send, HTTP, UI, Guardian, records, cleanup or full network restoration certification.\n'
    b'Publication progress is diagnostic DATA, not compatibility/CONNECT/TLS/file-transfer acceptance.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def assignment_region(raw, name):
    parsed = ast.parse(raw.decode('utf-8'))
    rows = [node for node in parsed.body if isinstance(node, ast.Assign) and len(node.targets) == 1 and
            isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'new_host_assignment_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno-1:rows[0].end_lineno])


def derive_host(raw):
    """Finite PC identity/graph/report bindings plus one source hook; full inverse."""
    edits = []
    candidate = raw

    def change(before, after, count=1):
        nonlocal candidate
        need(type(before) is bytes and type(after) is bytes and candidate.count(before) == count,
             'new_host_exact_forward')
        candidate = candidate.replace(before, after)
        edits.append((before, after, count))

    for name, value in (('SELF', SELF), ('CMDS', CMDS), ('DEFINITIONS', DEFINITIONS), ('READ_ME', READ_ME)):
        change(assignment_region(candidate, name), (name + ' = ' + repr(value) + '\n').encode('ascii'))
    for before, after in (
        (b"definitions.STATE_ALIAS == '/tmp/p011-mta-rx-freezer-v1'", b"definitions.STATE_ALIAS == '/tmp/p011-mta-rx-progress-v1'"),
        (b"definitions.STATE_ROOT == '/var/volatile/tmp/p011-mta-rx-freezer-v1'", b"definitions.STATE_ROOT == '/var/volatile/tmp/p011-mta-rx-progress-v1'"),
        (b'definitions.PAYLOAD_BYTES == 4191766 and len(definitions.ORIGIN_SOURCE_PINS) == 208,',
         b'definitions.PAYLOAD_BYTES == 4193272 and len(definitions.ORIGIN_SOURCE_PINS) == 230,'),
        (b'sum(row[2] for row in payload) == 4191766 <= 4194304,', b'sum(row[2] for row in payload) == 4193272 <= 4194304,'),
        (b'definitions.verify_inputs(INPUTS) == definitions.MECHANICAL_CLOSURE_COUNT == 8 and',
         b'definitions.verify_inputs(INPUTS) == definitions.MECHANICAL_CLOSURE_COUNT == 6 and'),
        (b"('mta_client_executor', 'mta_client_state_bridge',\n                'mta_client_receive_factory', 'mta_client_receive_boot', 'mta_client_service_owner',\n                'runtime35/mta_client_proc', 'runtime35/mta_client_executor')",
         b"('mta_client_executor', 'mta_client_receive_factory', 'mta_client_state_bridge',\n                'mta_client_receive_boot', 'mta_client_service_owner', 'runtime35/mta_client_executor')"),
        (b'payload_bytes=4191766, payload_remaining_bytes=2538,', b'payload_bytes=4193272, payload_remaining_bytes=1032,'),
        (b'flat_origin_pins=208, mechanical_closures=8,', b'flat_origin_pins=230, mechanical_closures=6,'),
        (b'changed_payload_roles=7, exact_payload_roles=68,', b'changed_payload_roles=6, exact_payload_roles=69,'),
        (b"selected_graph='proc-freezer-v1'", b"selected_graph='publication-progress-v1'"),
        (b'ordinary_proc_freezer_runner_configured=True,', b'publication_progress_runner_configured=True,'),
        (b'79279,\n        \'68573f0c9053db3df42f71647d9765a6af9bda56f4913daeef52b79e907f1894\'',
         (str(RUNNER[1]) + ',\n        ' + repr(RUNNER[2])).encode('ascii')),
        (b"'phone-handoff-proc-freezer-v1-' + mode", b"'phone-publication-progress-v1-' + mode"),
        (b"schema='p011-phone-handoff-proc-freezer-v1'", b"schema='p011-phone-publication-progress-v1'"),
        (b'p011-phone-handoff-proc-freezer-v1; ', b'p011-phone-publication-progress-v1; '),
        (b'verify_reader(fixed(IO_DONOR), own)', b'verify_reader(fixed(IO_DONOR), PUBLICATION_DRIVER_RAW)'),
        (b'        own = read_fixed(SELF)\n', b'        own = read_fixed(SELF)\n        publication_inputs()\n'),
        (b"('elapsed_seconds',)+progress.STAGE_FIELDS)", b"('elapsed_seconds',)+progress.STAGE_FIELDS+PUBLICATION_FIELDS)"),
    ):
        change(before, after)
    restored = candidate
    for before, after, count in reversed(edits):
        need(restored.count(after) == count, 'new_host_exact_reverse')
        restored = restored.replace(after, before)
    need(restored == raw and ast.dump(ast.parse(restored.decode('utf-8')), include_attributes=False) ==
         ast.dump(ast.parse(raw.decode('utf-8')), include_attributes=False), 'new_host_full_byte_ast_inverse')
    original_defs = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(raw).body
                     if isinstance(node, ast.FunctionDef)}
    new_defs = {node.name: ast.dump(node, include_attributes=False) for node in ast.parse(candidate).body
                if isinstance(node, ast.FunctionDef)}
    need(set(original_defs) == set(new_defs) and all(original_defs[name] == new_defs[name]
         for name in original_defs if name not in ('main', 'compose')), 'all_other_host_definitions_preserved')
    return candidate


def prepare():
    raw = (BASE / MOTHER[0]).read_bytes()
    need((len(raw), digest(raw)) == MOTHER[1:], 'actual_phone_host_mother_pin')
    derived = derive_host(raw)
    tree = ast.parse(derived.decode('utf-8'))
    need(len(tree.body) > 1 and isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test, include_attributes=False) == ast.dump(
             ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False),
         'only_original_entry_guard_removed')
    tree.body.pop()
    driver = types.ModuleType('fixed_phone_publication_progress_v1_driver')
    driver.__file__ = str(BASE / SELF)
    exec(compile(tree, driver.__file__, 'exec'), driver.__dict__)
    driver.INPUTS[MOTHER[0]] = raw
    driver.PUBLICATION_DRIVER_RAW = derived
    original_compose = driver.compose

    def publication_inputs():
        need(driver.fixed(MOTHER) == raw, 'mother_readback')
        for pin in (SCHEMA, PHONE, GRAPH_GENERATION):
            driver.fixed(pin)
        schema = types.ModuleType('fixed_phone_publication_parser')
        schema.__file__ = str(BASE / SCHEMA[0])
        exec(compile(driver.INPUTS[SCHEMA[0]], schema.__file__, 'exec'), schema.__dict__)
        need('main' not in schema.__dict__ and schema.ORIGINAL == driver.PHONE_SELECTOR,
             'fixed_schema_delegates_original_parser')
        driver.fixed(schema.ORIGINAL)
        driver.PUBLICATION_SCHEMA = schema
        driver.PUBLICATION_FIELDS = schema.FIELDS

    def compose(definitions, helpers, payload, advert, progress, diagnostic, window):
        base, phone, program = original_compose(definitions, helpers, payload, advert, progress, diagnostic, window)
        need(definitions.RUNNER == RUNNER and progress.RUNTIME_V2 ==
             ('candidate/receive-handoff-progress-120s-v2/runtime/phone_discovery_session.py', 26305,
              '15540ef933e3c18853f8ab650e8ddc4aa902c2499eec3a7538f6f178e295ddf4'), 'original_phone_proof_first')
        old = ('SMOKE_PIN=' + repr(progress.RUNTIME_V2[1:]) + '\nSMOKE_ENCODED=(\n' +
               definitions._short_chunks(helpers, driver.INPUTS[progress.RUNTIME_V2[0]]) + '\n)\n').encode('ascii')
        new = ('SMOKE_PIN=' + repr(PHONE[1:]) + '\nSMOKE_ENCODED=(\n' +
               definitions._short_chunks(helpers, driver.INPUTS[PHONE[0]]) + '\n)\n').encode('ascii')
        values = []
        for origin in (phone, program):
            need(origin.count(old) == 1 and origin.count(new) == 0, 'phone_encoding_unique')
            selected = driver.bounded(origin.replace(old, new, 1))
            inverse = selected.replace(new, old, 1)
            need(selected.count(new) == 1 and inverse == origin and
                 ast.dump(ast.parse(inverse), include_attributes=False) == ast.dump(ast.parse(origin),
                     include_attributes=False), 'phone_complete_byte_ast_inverse')
            values.append(selected)
        progress.RUNTIME_V2 = PHONE
        progress.parse_smoke = lambda output, component, remote, trials: driver.PUBLICATION_SCHEMA.parse_smoke(
            output, component, remote, trials, driver.INPUTS[driver.PHONE_SELECTOR[0]])
        return base, values[0], values[1]

    driver.publication_inputs = publication_inputs
    driver.compose = compose
    return driver


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'explicit_phone_entry_mode')
    return prepare().main()


if __name__ == '__main__':
    raise SystemExit(main())
