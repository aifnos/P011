"""Independent terminal-only phone adapter; default SOURCE does not open a window.

The actual prepare20 graph, phone observer, READY15/phone120/peer15/observe135,
business identity/IO guards and every original close predicate stay unchanged.
Only the diagnostic module, strict diagnostic parser and unavailable trace
coverage predicates derive here. Empty events mean unobserved, not no errors.
No old entry, test, writer or device is called while selecting pure recipes.
Explicit DEVICE still requires a new phone readiness and this run native READY.
"""
import ast
import hashlib
from pathlib import Path
import sys
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_terminal_20s_v1_check.py'
CMDS = ('HOST_MTA_PHONE_TERMINAL_20S_V1_CHECK.cmd',
        'TEST_MTA_PHONE_TERMINAL_20S_V1.cmd')
MOTHER = ('host/device_phone_startup_20s_v1_check.py', 11931,
          '7ca5f37ae5508fe996966886159e8053ff672dd68793420c2ef92679743bdd96')
MOTHER_CMDS = (
    ('HOST_MTA_PHONE_STARTUP_20S_V1_CHECK.cmd', 203,
     '8b7249adddef5809a96fabe165557c549e68eb9e76184fa44f7e0861710bee56'),
    ('TEST_MTA_PHONE_STARTUP_20S_V1.cmd', 218,
     '4eb6716d1d0d0b3cba67a7e1725dc9a226553b5dcb7e0a1d6e1da4c86dbfca6f'),
)
PHONE_SELECTOR = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
                  '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
OLD_TRACE = ('candidate/receive-handoff-trace-v1/runtime/handoff_trace.py', 14820,
             '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657')
TERMINAL = ('candidate/receive-handoff-terminal-v1/runtime/handoff_terminal.py', 15049,
            'c77db43cb42d60f624b96bacb92e5a8c03b943faf82921059ab4d04b15085c97')
TERMINAL_GENERATOR = ('host/receive_handoff_terminal_v1_generate.py', 5914,
                      '28da59a285d8ab3d2849dcdd359387fab47b66f9616b0a42bad2c8227c6b2b9f')
READ_ME = (b'Independent prepare20 terminal-only receive phone observation. Default SOURCE: no ADB/RF/window.\n'
    b'Explicit --check-device requires Root fresh baseline, new phone readiness and actual native READY.\n'
    b'Actual prepare20 graph, physical prep20-v001 root, 304 flat origins and all prior phone inputs stay.\n'
    b'75 payload4193768 within4MiB (536 spare), six mechanical closures and unchanged FC9/113832 remain.\n'
    b'Only terminal diagnostic source15049, strict nine-field parser and its coverage gates are derived.\n'
    b'Schema receive-handoff-terminal-v1, exception_events_observed=False; events are unobserved, not absent errors.\n'
    b'No threading.settrace or sys.settrace is installed; actual installed/restored flags remain False.\n'
    b'Original existing-hook refusal, finally close_trace, identity/actor/radio terminal projection remain.\n'
    b'Parser keeps the original finite terminal/error vocabulary; unknown projection remains FAIL.\n'
    b'All byte/AST inverses preserve original phone, Trial, application identity/IO, READY and close checks.\n'
    b'Phone28352, strict five-field publication schema5907 and passive cached DATA fields remain unchanged.\n'
    b'Preparation20, collector10, Publication120, READY15, phone120, peer15, observation135 stay.\n'
    b'Owner600/cleanup60, alarm780/HOST790, native TTL and original cancel/finalizer predicates stay.\n'
    b'No accept/send, HTTP/UI, record handling, candidate business graph change or full network restore claim.\n'
    b'Captured-and-cancelled is classification, not CONNECT/TLS/file-transfer or phone compatibility acceptance.\n'
    b'Pure terminal source recipe inverse only; no old main/tests, generator writer or graph build is called.\n'
    b'Private first raw streams/exits, all source snapshots, source ZIP/readback and public seal stay.\n'
    b'This SOURCE evidence neither requests a phone window nor substitutes for a real new device test.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def function_region(raw, name):
    tree = ast.parse(raw.decode('ascii'))
    rows = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(rows) == 1 and not rows[0].decorator_list, 'terminal_function_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno-1:rows[0].end_lineno])


def assignment_region(raw, name):
    rows = [node for node in ast.parse(raw.decode('ascii')).body if isinstance(node, ast.Assign) and
            len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(rows) == 1, 'terminal_assignment_unique')
    return b''.join(raw.splitlines(keepends=True)[rows[0].lineno-1:rows[0].end_lineno])


def without_entry(raw):
    tree = ast.parse(raw.decode('ascii'))
    need(len(tree.body) > 1 and isinstance(tree.body[-1], ast.If) and
         ast.dump(tree.body[-1].test, include_attributes=False) == ast.dump(
             ast.parse("__name__ == '__main__'", mode='eval').body, include_attributes=False),
         'terminal_only_entry_removed')
    tree.body.pop()
    return tree


def finite_edits(raw, edits, changed_functions):
    """Exact finite changes, full byte/position AST inverse and other helper bytes."""
    candidate = raw
    for before, after in edits:
        need(type(before) is bytes and type(after) is bytes and before != after and
             candidate.count(before) == 1 and candidate.count(after) == 0, 'terminal_exact_forward')
        candidate = candidate.replace(before, after, 1)
    restored = candidate
    for before, after in reversed(edits):
        need(restored.count(after) == 1, 'terminal_exact_reverse')
        restored = restored.replace(after, before, 1)
    need(restored == raw and ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'terminal_complete_inverse')
    old_defs = {node.name: node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)}
    new_defs = {node.name: node for node in ast.parse(candidate).body if isinstance(node, ast.FunctionDef)}
    need(set(old_defs) == set(new_defs) and set(changed_functions) <= set(old_defs) and all(
         ast.dump(node, include_attributes=False) == ast.dump(new_defs[name], include_attributes=False) and
         function_region(raw, name) == function_region(candidate, name)
         for name, node in old_defs.items() if name not in changed_functions),
         'terminal_other_helpers_byte_exact')
    return candidate


def derive_recipe(raw):
    """Only three bindings and three exclusive result/schema/command literals."""
    need((len(raw), digest(raw)) == MOTHER[1:], 'terminal_prepare20_mother_pin')
    edits = [(assignment_region(raw, name), (name+' = '+repr(value)+'\n').encode('ascii'))
             for name, value in (('SELF', SELF), ('CMDS', CMDS), ('READ_ME', READ_ME))]
    edits += [
        (b'phone-startup-20s-v1-', b'phone-terminal-20s-v1-'),
        (b"schema=\\\\'p011-phone-startup-20s-v1\\\\'", b"schema=\\\\'p011-phone-terminal-20s-v1\\\\'"),
        (b'p011-phone-startup-20s-v1; ', b'p011-phone-terminal-20s-v1; '),
    ]
    need(len(edits) == 6, 'terminal_recipe_six_changes')
    return finite_edits(raw, edits, ('derive',))


def derive_parser(raw):
    """Keep real values; no schema translation or invented installed/restored flag."""
    need((len(raw), digest(raw)) == PHONE_SELECTOR[1:], 'terminal_actual_phone_parser_pin')
    original = function_region(raw, 'parse_trace')
    edits = [
        (b"'overflow_unknown', 'failure_codes', 'events', 'terminal'}",
         b"'overflow_unknown', 'failure_codes', 'events', 'terminal', 'exception_events_observed'}"),
        (b"value['schema'] != 'receive-handoff-trace-v1'",
         b"value['schema'] != 'receive-handoff-terminal-v1'"),
        (b"for name in ('thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown', 'overflow_unknown'):",
         b"for name in ('thread_trace_installed', 'thread_trace_hook_restored', 'trace_unknown', 'overflow_unknown', 'exception_events_observed'):"),
        (b"    failures = {'existing_trace', 'install_failed', 'hook_changed', 'current_hook_changed',\n",
         b"    if (value['exception_events_observed'] is not False or\n"
         b"            value['thread_trace_installed'] is not False or\n"
         b"            value['thread_trace_hook_restored'] is not False or\n"
         b"            value['overflow_unknown'] is not False or value['events'] != ()):\n"
         b"        raise ValueError('terminal_only_coverage')\n"
         b"    failures = {'existing_trace', 'install_failed', 'hook_changed', 'current_hook_changed',\n"),
    ]
    return finite_edits(original, edits, ('parse_trace',))


def derive_driver(raw):
    """Only unavailable diagnostic coverage gates/reporting within current main."""
    edits = [
        (b'        old_classification_root_created=False, gui_staging_requested=False, private_source_zip_readback=False)',
         b'        exception_events_observed=False, terminal_only_diagnostic=True,\n'
         b'        old_classification_root_created=False, gui_staging_requested=False, private_source_zip_readback=False)'),
        (b"            report['trace_result'] = progress.parse_trace(diagnostic, output)\n",
         b"            report['trace_result'] = progress.parse_trace(diagnostic, output)\n"
         b"            report['exception_events_observed'] = report['trace_result']['exception_events_observed']\n"),
        (b'        report.update(source_checked=True, target_bytes=len(program), target_sha256=digest(program),\n',
         b'        report.update(source_checked=True, target_bytes=len(program), target_sha256=digest(program),\n'
         b'            terminal_recipe_full_inverse_verified=True, terminal_parser_full_inverse_verified=True,\n'
         b'            terminal_driver_full_inverse_verified=True, terminal_carrier_full_inverse_verified=True,\n'),
        (b"         report.get('trace_result') is not None and report['trace_result']['thread_trace_installed'] is True and\n"
         b"         report['trace_result']['thread_trace_hook_restored'] is True and report['trace_result']['trace_unknown'] is False))",
         b"         report.get('trace_result') is not None and report['trace_result']['thread_trace_installed'] is False and\n"
         b"         report['trace_result']['thread_trace_hook_restored'] is False and\n"
         b"         report['trace_result']['exception_events_observed'] is False and report['trace_result']['trace_unknown'] is False))"),
    ]
    return finite_edits(raw, edits, ('main',))


def trace_block(definitions, helpers, inputs, pin):
    return ('TRACE_PIN='+repr(pin[1:])+'\nTRACE_ENCODED=(\n'+
            definitions._short_chunks(helpers, inputs[pin[0]])+'\n)\n').encode('ascii')


def prepare():
    raw = (BASE / MOTHER[0]).read_bytes()
    selected_raw = derive_recipe(raw)
    selected = types.ModuleType('fixed_phone_terminal_20s_v1_recipe')
    selected.__file__ = str(BASE / SELF)
    exec(compile(without_entry(selected_raw), selected.__file__, 'exec'), selected.__dict__)
    driver = selected.prepare()
    need(driver.SELF == SELF and driver.CMDS == CMDS and driver.PHONE_SELECTOR == PHONE_SELECTOR,
         'terminal_effective_driver_bindings')
    driver.INPUTS[MOTHER[0]] = raw
    original_inputs = driver.publication_inputs

    def publication_inputs():
        need(driver.fixed(MOTHER) == raw, 'terminal_prepare20_mother_preserved')
        for pin in MOTHER_CMDS+(OLD_TRACE, TERMINAL, TERMINAL_GENERATOR):
            driver.fixed(pin)
        recipe = driver.select_pure(TERMINAL_GENERATOR,
            ('make_source', 'ast_inverse', 'named', 'need', 'digest'),
            ('MOTHER', 'OUTPUT', 'REMOVE', 'RETURN', 'GUARD', 'OLD_PUBLIC', 'NEW_PUBLIC'))
        need(recipe.MOTHER == OLD_TRACE and recipe.OUTPUT == TERMINAL and
             recipe.make_source(driver.INPUTS[OLD_TRACE[0]]) == driver.INPUTS[TERMINAL[0]],
             'terminal_actual_runtime_complete_source_inverse')
        original_inputs()

    driver.publication_inputs = publication_inputs
    original_compose = driver.compose

    def compose(definitions, helpers, payload, advert, progress, diagnostic, window):
        need(progress.TRACE == OLD_TRACE, 'terminal_original_carrier_binding')
        base, phone, program = original_compose(definitions, helpers, payload, advert, progress, diagnostic, window)
        previous = trace_block(definitions, helpers, driver.INPUTS, OLD_TRACE)
        current = trace_block(definitions, helpers, driver.INPUTS, TERMINAL)
        outputs = []
        for original in (phone, program):
            need(original.count(previous) == 1 and original.count(current) == 0,
                 'terminal_carrier_encoding_unique')
            changed = driver.bounded(original.replace(previous, current, 1))
            inverse = changed.replace(current, previous, 1)
            need(changed.count(current) == 1 and inverse == original and
                 ast.dump(ast.parse(inverse.decode('ascii'), feature_version=(3, 5)), include_attributes=True) ==
                 ast.dump(ast.parse(original.decode('ascii'), feature_version=(3, 5)), include_attributes=True) and
                 driver.assignment_region(changed, 'ARTIFACT_ROWS') ==
                 driver.assignment_region(original, 'ARTIFACT_ROWS'), 'terminal_complete_carrier_inverse')
            outputs.append(changed)
        parser = derive_parser(driver.fixed(PHONE_SELECTOR))
        parser_tree = ast.parse(parser.decode('ascii'))
        need(len(parser_tree.body) == 1 and isinstance(parser_tree.body[0], ast.FunctionDef) and
             parser_tree.body[0].name == 'parse_trace', 'terminal_parser_only')
        exec(compile(parser_tree, str(BASE / SELF)+'#terminal-parser', 'exec'), progress.__dict__)
        progress.TRACE = TERMINAL
        return base, outputs[0], outputs[1]

    driver.compose = compose
    effective = derive_driver(driver.PUBLICATION_DRIVER_RAW)
    main_tree = ast.parse(function_region(effective, 'main').decode('ascii'))
    need(len(main_tree.body) == 1 and isinstance(main_tree.body[0], ast.FunctionDef) and
         main_tree.body[0].name == 'main', 'terminal_effective_main_only')
    driver.PUBLICATION_DRIVER_RAW = effective
    exec(compile(main_tree, str(BASE / SELF)+'#terminal-driver', 'exec'), driver.__dict__)
    return driver


def main():
    need(sys.argv[1:] in ([], ['--check-device']), 'terminal_explicit_mode')
    return prepare().main()


if __name__ == '__main__':
    raise SystemExit(main())
