"""Default SOURCE; explicit original phone observer on durable75/window v1.

Only the PC composition changes. Frozen pure builders/parsers, phone26305,
trace14820 and original READY/cancel/close phases stay. No old main or suite.
Device mode is for Root after fresh baseline, new phone readiness and native
READY; it may initialize the original receive network but never accepts files.
"""
import ast
import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import threading
import traceback
import types

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_phone_handoff_durable_window_v1_check.py'
CMDS = ('HOST_MTA_PHONE_HANDOFF_DURABLE_WINDOW_V1_CHECK.cmd',
        'TEST_MTA_PHONE_HANDOFF_DURABLE_WINDOW_V1.cmd')
DEFINITIONS = ('host/formal_receive_durable_state_v1_definitions.py', 45031,
    'b98c66604bdb250820630f1844e5ea4b0af9bbd260e05388478034e37254e43b')
IO_DONOR = ('host/device_receive_startup_readonly_v4_check.py', 27003,
    '4ed9c5eb9403f81d967cce91bf21d71e2230d82e49e7d8dfb1d178a353311cbf')
WINDOW_SELECTOR = ('host/device_receive_window_clock_v1_startup_check.py', 20955,
    'df818fcd7e9a28dfb88af123919cdc8fbbefcaaf6b7cfa42d48a68bc250de04d')
PHONE_SELECTOR = ('host/device_receive_handoff_progress_120s_v2_check.py', 39070,
    '2da874a8b53463986882576aac28222663503f64fd16cdbf8a430b8e422ce484')
ADVERT_SELECTOR = ('host/device_receive_advertise_smoke_v1_check.py', 15793,
    '7724e54273b042673cc9e9a1a2ba13185fab6db704dad7056079141f7d075041')
DIAGNOSTIC_SELECTOR = ('host/device_receive_advertise_smoke_v2_diagnostic.py', 19645,
    'c33a0e73569ddac453230e0ba509955a4b08a84742633b021c433b8dc77d6201')
PHONE_BASE = ('host/device_receive_phone_discovery_v1_check.py', 20192,
    '09fb7cd14876d04916db1aca0eaf40c437dadcf79b7bee1354f3cb1cb605bcbc')
COMPAT_BUILDER = ('host/device_receive_handoff_compat_v2_check.py', 19697,
    'bd67fe3fda00ff19388fe0646ef9dc3e20b56219be60c78516c633d4eaa246bb')
DURATION_BUILDER = ('host/device_receive_phone_discovery_120s_v1_check.py', 32996,
    'bff7904cb4b4a2cbf1743235c96f6de7af6e487baa322f4ef4d73306135ee31f')
OLD_PHONE_CARRIER = ('results/receive-handoff-classification-v1-source-20261005-230413-72ba5c75/private-advertise-target.py',
    2009162, '62806a2d95495224eb9fa96d6d6c0ded54d9bc5f88a336e81a0019d4eda4a51e')
OLD_PHONE_RUNNER = ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_formal_receive_session.py',
    79254, '3fe23e4e9d9e1c9900985ee04153ce4b479ca1f2bc194458b91a702cd4f8258f')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
    '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
INPUTS = {}
EVIDENCE = None
PARTIAL = set()
READ_ME = (b'Durable75/window v1 original phone handshake/cancel diagnostic only.\n'
    b'Default SOURCE: no ADB/runtime/phone/RF. Explicit --check-device only after Root obtains\n'
    b'fresh baseline and new phone readiness; notify click only after actual native READY.\n'
    b'Flat164 provenance/new9 closures; actual75/4191752 within4MiB, separate FC9/113690.\n'
    b'Pure frozen selectors only: no historical main, graph verifier, suite or generator.\n'
    b'Phone26305/trace14820, parsers, READY15/one120s/peer15 cancel and finalizer unchanged.\n'
    b'Startup10, Publication120, Owner600+cleanup60, alarm780/host790; no renewal.\n'
    b'Current durable root/bindings reused; no old classification root or GUI staging.\n'
    b'Whole carrier byte inverses preserve actual75 encoding outside the Runner/window overlay.\n'
    b'Window scalar projection is retained values only, not a new clock, deadline or permission.\n'
    b'Original native Windows identity/metadata gates retained; bounded returned input prefixes\n'
    b'and pin-rejected inputs saved. Raw stdout/stderr, exits and exceptions remain private.\n'
    b'Parsed COMPONENT retained before strict TRIAL; None/malformed Trial stays FAIL.\n'
    b'Original smoke PASS/closed/pending predicates unchanged; captured+cancelled is classification,\n'
    b'not phone compatibility/CONNECT/TLS/file-transfer/full-network-restoration acceptance.\n'
    b'Real Parent/F may initialize network; no accept/send/answer/file/HTTP/UI/Disconnect or cleanup.\n'
    b'Private source ZIP/readback and private result ZIP/readback precede public commit.\n')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def retain(name, raw):
    if EVIDENCE is not None:
        EVIDENCE._retain(name, raw)
    elif name in INPUTS:
        need(INPUTS[name] == raw, 'input_changed')
    else:
        INPUTS[name] = raw
    return raw


def read_observed_handle(name, handle, limit):
    """Retain only actual returned bytes, including a prefix on read failure."""
    collected = bytearray()
    try:
        while len(collected) < limit:
            chunk = handle.read(min(65536, limit-len(collected)))
            if not chunk:
                break
            collected.extend(chunk)
    except BaseException:
        PARTIAL.add(name)
        if EVIDENCE is not None:
            EVIDENCE.partial.add(name)
        retain(name, bytes(collected))
        raise
    raw = bytes(collected)
    retain(name, raw)
    return raw


def read_fixed(name, pin=None):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400): raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part; value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2 * 1024 * 1024:
        raise ValueError('fixed_file')
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        if os.name == 'nt':
            equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                     opened[3:6] == before[3:6])
        else: equal = opened == before
        if not equal: raise ValueError('fixed_identity')
        raw = read_observed_handle(name, handle, 2 * 1024 * 1024 + 1)
        if metadata(os.fstat(handle.fileno())) != opened: raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]: raise ValueError('fixed_changed')
    if pin is not None and (len(raw), digest(raw)) != pin: raise ValueError('fixed_pin')
    return raw


def fixed(pin):
    return read_fixed(pin[0], pin[1:])


def verify_reader(donor, own):
    """Inverse only bounded observed-read call; every native guard stays exact."""
    original = {row.name: row for row in ast.parse(donor).body if isinstance(row, ast.FunctionDef)
                and row.name in ('metadata', 'read_fixed')}
    selected = {row.name: row for row in ast.parse(own).body if isinstance(row, ast.FunctionDef)
                and row.name in ('metadata', 'read_fixed')}
    need(set(original) == set(selected) == {'metadata', 'read_fixed'}, 'io_function_inventory')
    edits = [row for row in ast.walk(selected['read_fixed']) if isinstance(row, ast.Assign) and
             len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and row.targets[0].id == 'raw']
    need(len(edits) == 1 and ast.dump(edits[0].value, include_attributes=False) == ast.dump(
        ast.parse('read_observed_handle(name, handle, 2 * 1024 * 1024 + 1)', mode='eval').body,
        include_attributes=False), 'io_read_overlay')
    edits[0].value = ast.parse('handle.read(2 * 1024 * 1024 + 1)', mode='eval').body
    need(all(ast.dump(original[name], include_attributes=False) ==
             ast.dump(selected[name], include_attributes=False) for name in original), 'io_complete_guard_inverse')


def select_pure(pin, names, constants=()):
    """Compile only exact selected functions and finite constant expressions."""
    raw = fixed(pin)
    tree = ast.parse(raw.decode('ascii'))
    functions = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name in names]
    need(len(functions) == len(names) and {row.name for row in functions} == set(names) and
         all(not row.decorator_list for row in functions) and 'main' not in names, 'pure_function_inventory')
    assignments = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
                   isinstance(row.targets[0], ast.Name) and row.targets[0].id in constants]
    need(len(assignments) == len(constants) and {row.targets[0].id for row in assignments} == set(constants),
         'pure_constant_inventory')
    for row in assignments:
        for node in ast.walk(row.value):
            need(isinstance(node, (ast.Constant, ast.Tuple, ast.List, ast.Dict, ast.Set, ast.Load,
                ast.Name, ast.BinOp, ast.Add, ast.Call, ast.keyword)), 'pure_constant_expression')
            if isinstance(node, ast.Name):
                need(node.id in constants or node.id == 'dict', 'pure_constant_name')
            if isinstance(node, ast.Call):
                need(isinstance(node.func, ast.Name) and node.func.id == 'dict' and not node.args and
                     all(type(key.arg) is str and isinstance(key.value, ast.Constant)
                         for key in node.keywords), 'pure_constant_call')
    module = types.ModuleType('selected_' + Path(pin[0]).stem)
    module.__file__ = str(BASE / pin[0])
    module.__dict__.update(BASE=BASE, ast=ast, hashlib=hashlib, json=json, math=math,
        re=re, types=types, Path=Path, subprocess=subprocess, threading=threading)
    exec(compile(ast.Module(body=assignments+functions, type_ignores=[]), module.__file__, 'exec'), module.__dict__)
    need('main' not in module.__dict__, 'archived_main_forbidden')
    return module


def phone_interfaces():
    advert = select_pure(ADVERT_SELECTOR, ('make_source', 'exit_marker'), ('TARGET', 'SMOKE'))
    phone = select_pure(PHONE_BASE, ('make_source',), ('RUNTIME_V2',))
    compat = select_pure(COMPAT_BUILDER, ('make_source',), ('TRACE',))
    compat.load_phone = lambda: (phone, INPUTS[PHONE_BASE[0]])
    duration = select_pure(DURATION_BUILDER, ('make_source',), ('RUNTIME_V2', 'OLD_RUNTIME'))
    duration.load_base_host = lambda: (compat, INPUTS[COMPAT_BUILDER[0]])
    constants = ('SELF', 'RUNTIME_V2', 'PREVIOUS_PROGRESS_RUNTIME', 'PREVIOUS_PROGRESS_HOST',
        'DURATION_RUNTIME', 'OLD_RUNTIME', 'TRACE', 'FLAGS', 'PROGRESS_BOOL', 'STAGE_OPTIONAL_BOOL',
        'STAGE_FIELDS', 'FACTORY_PHASES', 'OBS_BOOL', 'TERMINAL_BOOL', 'REASONS', 'READY_VALUE')
    progress = select_pure(PHONE_SELECTOR, ('make_source', 'parse_trace', 'parse_smoke',
        'parse_observation', 'parse_ready', 'collect_ready_pipe', 'dispatch_live', 'source_fragment',
        'verify_progress_inputs', 'parse_progress', 'write_new'), constants)
    progress.load_base_host = lambda: (duration, INPUTS[DURATION_BUILDER[0]])
    diagnostic = select_pure(DIAGNOSTIC_SELECTOR, ('derived_text', 'one_literal', 'parse_trials',
        'original_closed', 'validate_original_error', 'parse_inner'), ('INNER',))
    for pin in (advert.SMOKE, diagnostic.INNER, progress.RUNTIME_V2, progress.PREVIOUS_PROGRESS_RUNTIME,
                progress.PREVIOUS_PROGRESS_HOST, progress.DURATION_RUNTIME, progress.OLD_RUNTIME, progress.TRACE):
        fixed(pin)
    need(progress.SELF == PHONE_SELECTOR[0] and progress.verify_progress_inputs(INPUTS, advert) == 1,
         'unchanged_phone_observer_proof')
    need(progress.RUNTIME_V2[1:] == (26305,
        '15540ef933e3c18853f8ab650e8ddc4aa902c2499eec3a7538f6f178e295ddf4') and
        progress.TRACE[1:] == (14820,
        '990cbf387893706e263abc43aa4fdc728782c4a0a88de531d5a1a53274862657'), 'actual_observer_trace_pins')
    return advert, progress, diagnostic


def assignment_region(raw, name):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and len(row.targets) == 1 and
            isinstance(row.targets[0], ast.Name) and row.targets[0].id == name]
    need(len(rows) == 1, 'carrier_assignment_inventory')
    lines = raw.splitlines(keepends=True)
    return b''.join(lines[rows[0].lineno-1:rows[0].end_lineno])


def runner_block(definitions, helpers, pin):
    return ('RUNNER_PIN=' + repr(pin[1:]) + '\nRUNNER_ENCODED=(\n' +
        definitions._short_chunks(helpers, INPUTS[pin[0]]) + '\n)\n').encode('ascii')


def bounded(raw):
    need(type(raw) is bytes and len(raw) <= 2097152 and max(map(len, raw.splitlines())) <= 256,
         'carrier_original_budget')
    ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    return raw


def compose(definitions, helpers, payload, advert, progress, diagnostic, window):
    old = fixed(OLD_PHONE_CARRIER)
    fixed(OLD_PHONE_RUNNER)
    base = bounded(definitions.make_source(helpers, INPUTS, payload, False))
    phone = bounded(progress.make_source(definitions, advert, diagnostic, helpers, INPUTS, payload))
    old_runner = runner_block(definitions, helpers, OLD_PHONE_RUNNER)
    durable_runner = runner_block(definitions, helpers, definitions.RUNNER)
    old_roles, durable_roles = assignment_region(old, 'ARTIFACT_ROWS'), assignment_region(base, 'ARTIFACT_ROWS')
    need(old.count(old_runner) == old.count(old_roles) == phone.count(durable_runner) ==
         phone.count(durable_roles) == 1, 'phone_graph_regions_unique')
    expected = old.replace(old_runner, durable_runner, 1).replace(old_roles, durable_roles, 1)
    need(phone == expected and phone.replace(durable_roles, old_roles, 1).replace(
         durable_runner, old_runner, 1) == old, 'phone_current_graph_complete_byte_inverse')
    need(definitions.RUNNER == window.OLD_CORE, 'window_runner_base')
    new_runner = runner_block(definitions, helpers, window.NEW_CORE)
    anchor = b'detail=fixed_error_details(smoke._RETAINED.failures)\n'
    addition = b'retained=smoke._RETAINED\n' + window.PROJECTION
    need(phone.count(anchor) == 1, 'window_projection_anchor')
    program = bounded(phone.replace(durable_runner, new_runner, 1).replace(anchor, addition+anchor, 1))
    need(program.count(new_runner) == program.count(addition+anchor) == 1 and
         program.replace(addition+anchor, anchor, 1).replace(new_runner, durable_runner, 1) == phone and
         assignment_region(program, 'ARTIFACT_ROWS') == durable_roles,
         'window_complete_carrier_inverse_runtime75_unchanged')
    return base, phone, program


def collect_receipts(private, report, fresh):
    """A receipt read failure is FAIL evidence, not an escape from sealing."""
    prior_known = report.get('remote_status_known') is True and type(report.get('remote_exit')) is int
    prior_remote = report.get('remote_exit')
    try:
        prefix = private / '01-phone-discovery'
        for tag in ('stdout', 'stderr'):
            path = Path(str(prefix)+'.'+tag+'.raw')
            if path.exists():
                raw = path.read_bytes()
                report[tag+'_bytes'], report[tag+'_sha256'] = len(raw), digest(raw)
                if tag == 'stdout':
                    text = raw.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
                    exits = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', text, re.M)
                    report['remote_exit'] = int(exits[0]) if len(exits) == 1 else 'UNKNOWN'
                    report['remote_status_known'] = len(exits) == 1
        path = Path(str(prefix)+'.host-exit')
        if path.exists():
            value = path.read_text(encoding='ascii').strip()
            report['host_exit'] = int(value) if re.fullmatch(r'-?\d+', value) else 'TIMEOUT' if value == 'TIMEOUT' else 'UNKNOWN'
    except OSError as failure:
        report['receipt_error'] = type(failure).__name__
        report['error'] = report.get('error') or type(failure).__name__
        # Keep an earlier strict parsed observation. An incomplete raw receipt
        # reread does not create a new reliable numeric remote observation.
        report['remote_exit'] = prior_remote if prior_known else 'UNKNOWN'
        report['remote_status_known'] = prior_known
        report['receipt_readback_verified'] = False
        report['passed'] = False
        diagnostic = traceback.format_exc().encode('utf-8')
        target = private / 'receipt-error.private.txt'
        if fresh is not None:
            fresh(target, diagnostic)
        else:
            with target.open('xb') as stream:
                need(stream.write(diagnostic) == len(diagnostic), 'unsealed_receipt_error_write')
        return False
    report['receipt_readback_verified'] = True
    return True


def main():
    global EVIDENCE
    need(sys.argv[1:] in ([], ['--check-device']), 'fixed_entry_modes')
    device = sys.argv[1:] == ['--check-device']
    mode = 'device' if device else 'source'
    out = BASE / 'results' / ('phone-handoff-durable-window-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    sealer = helpers = definitions = program = base = phone = None
    report = dict(schema='p011-phone-handoff-durable-window-v1', mode=mode, passed=False,
        error=None, source_checked=False, source_preserved=False, host_exit='NOT_RUN', remote_exit='NOT_RUN',
        remote_status_known=False, device_invoked=False, target_execution_requested=False,
        component=None, trial_facts=None, diagnostic_complete=False, device_outcome='NOT_RUN',
        f_process_retained_observed=None, decryption_attempt_observed=None, frame_claim_observed=None,
        connect_observed=None, tls_observed=None,
        live_ready_forwarded=False, phone_discovery_user_confirmed=False, phone_tested=False,
        automatic_receive_action_requested=device, consent_accept_requested=False, send_requested=False,
        http_action_requested=False, ui_requested=False, guardian_requested=False, pending_handled=False,
        full_network_restore_verified=False, wifi_connection_verified=False, file_transfer_verified=False,
        old_main_called=False, old_tests_replayed=0, historical_graph_verifier_called=False,
        selected_graph='durable-state-v1', window_runner_selected=True,
        original_activity_seconds=600, original_cleanup_seconds=60, startup_preparation_max_seconds=10,
        publication_preparation_max_seconds=120, preparation_max_seconds=15, phone_opportunity_seconds=120,
        handshake_phase_max_seconds=15, observation_max_seconds=135, observation_row_max=320,
        observation_busy_max=2000, remote_alarm_seconds=780, host_timeout_seconds=790,
        source_cap=2097152, target_line_cap=256, payload_cap=4194304, filecenter_cap=131072,
        old_classification_root_created=False, gui_staging_requested=False, private_source_zip_readback=False)
    try:
        need(sys.platform == 'win32' and BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'),
             'fixed_pc_identity')
        raw = fixed(SEALER)
        selected_sealer = types.ModuleType('fixed_phone_private_first_sealer')
        exec(compile(raw, str(BASE / SEALER[0]), 'exec'), selected_sealer.__dict__)
        need(all(callable(getattr(selected_sealer, name, None)) for name in
                 ('fresh', 'InputEvidence', 'seal_result')), 'actual_sealer_interfaces')
        sealer = selected_sealer
        EVIDENCE = sealer.InputEvidence(INPUTS)
        EVIDENCE.partial.update(PARTIAL)
        own = read_fixed(SELF)
        for path in CMDS:
            read_fixed(path)
        verify_reader(fixed(IO_DONOR), own)
        definitions_raw = fixed(DEFINITIONS)
        definitions = types.ModuleType('current_durable_phone_graph')
        definitions.__file__ = str(BASE / DEFINITIONS[0])
        exec(compile(definitions_raw, definitions.__file__, 'exec'), definitions.__dict__)
        need(definitions.STATE_ALIAS == '/tmp/p011-mta-rx-durable-v1' and
             definitions.STATE_ROOT == '/var/volatile/tmp/p011-mta-rx-durable-v1' and
             definitions.PAYLOAD_BYTES == 4191752 and len(definitions.ORIGIN_SOURCE_PINS) == 164,
             'actual_current_graph')
        helpers, checker_raw = definitions.load_checker()
        need(definitions.CHECKER == IO_DONOR and checker_raw == INPUTS[IO_DONOR[0]] and
             helpers.BASE == BASE and tuple(helpers.BOOL_FIELDS)[-1] == 'interactive_window_requested',
             'actual_schema_checker')
        for pin in definitions.ORIGIN_SOURCE_PINS:
            fixed(pin)
        for pin in (definitions.MANIFEST, definitions.PRIVATE_MANIFEST, definitions.RUNNER,
                    definitions.TRANSPORT, definitions.ORIGINAL_MANIFEST, definitions.OLD_PRIVATE_MANIFEST):
            fixed(pin)
        ordinary = definitions.manifest_rows(INPUTS[definitions.MANIFEST[0]])
        private_rows = definitions.manifest_rows(INPUTS[definitions.PRIVATE_MANIFEST[0]], private=True)
        payload = ordinary + definitions.HELPERS + private_rows + (definitions.WPA, definitions.MONITOR)
        need(len(ordinary) == len(private_rows) == 35 and len(payload) == 75 and
             len({row[0] for row in payload}) == 75 and sum(row[2] for row in payload) == 4191752 <= 4194304,
             'actual75_original_budget')
        for name, path, size, sha in payload:
            fixed((path, size, sha))
        fc = definitions.FILECENTER_SOURCE_PINS
        need(type(fc) is tuple and len(fc) == 9 and sum(row[2] for row in fc) == 113690 <= 131072,
             'original_fc9_budget')
        for name, path, size, sha in fc:
            fixed((path, size, sha))
        need(definitions.verify_inputs(INPUTS) == 9, 'new_flat_nine_closures')
        window = select_pure(WINDOW_SELECTOR, ('need', 'digest', 'replay', 'function_bytes', 'verify_overlay_inputs'),
            ('CORE_HOST', 'OLD_CORE', 'OLD_NAV', 'PREFIX', 'NEW_CORE', 'NEW_NAV', 'GENERATOR', 'DELTA',
             'GENERATION', 'EDITS', 'GUARDS', 'PROJECTION', 'FACTS'))
        window.verify_overlay_inputs(fixed, INPUTS)
        advert, progress, diagnostic = phone_interfaces()
        base, phone, program = compose(definitions, helpers, payload, advert, progress, diagnostic, window)
        for name, raw in (('private-durable-base-target.py', base), ('private-durable-phone-base-target.py', phone),
                          ('private-phone-target.py', program)):
            sealer.fresh(out / name, raw)
        report.update(source_checked=True, target_bytes=len(program), target_sha256=digest(program),
            target_max_line_bytes=max(map(len, program.splitlines())), payload_role_count=75,
            payload_bytes=4191752, payload_remaining_bytes=2552, filecenter_sources=9, filecenter_bytes=113690,
            flat_origin_pins=164, mechanical_closures=9, observer_closures=1,
            original_io_guards_inverse_verified=True, pure_selector_only=True,
            phone_observer_bytes=progress.RUNTIME_V2[1], phone_observer_sha256=progress.RUNTIME_V2[2],
            trace_bytes=progress.TRACE[1], trace_sha256=progress.TRACE[2],
            carrier_graph_full_inverse_verified=True, carrier_window_full_inverse_verified=True,
            runtime75_encoding_unchanged=True, window_overlay=dict(window.FACTS))
        if device:
            transport = helpers.load_transport(INPUTS[definitions.TRANSPORT[0]])
            adb = transport.Adb(private)
            command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(780);'
                'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-phone-handoff-durable-window-v1; '
                'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
            report.update(device_invoked=True, target_execution_requested=True)
            print('PHONE_DISCOVERY_LOG_DIR=' + str(out), flush=True)
            output, live_ready = progress.dispatch_live(transport, adb, private, program, command, 790)
            report['live_ready_forwarded'] = len(live_ready) == 1
            remote, component = helpers.parse_result(output)
            report.update(remote_status_known=True, remote_exit=remote, component=component)
            report['trace_result'] = progress.parse_trace(diagnostic, output)
            # Preserve COMPONENT first. Strict None/malformed TRIAL cannot become
            # a startup exception shortcut or a captured-handshake PASS.
            report['trial_facts'] = definitions.parse_trial_facts(output)
            remote, component, smoke, inner, missing, busy, opportunity = progress.parse_observation(
                definitions, advert, diagnostic, helpers, output)
            need(missing is False, 'strict_trial_required')
            report.update(diagnostic_complete=True, smoke_complete=smoke['complete'], reason=smoke['reason'],
                handshake_progress=progress.parse_progress(diagnostic, output, smoke), phone_window=opportunity,
                observation_lock_busy_count=busy, inner_error_projection=inner,
                handshake_stage_observations=[dict((name, row[name]) for name in
                    ('elapsed_seconds',)+progress.STAGE_FIELDS) for row in smoke['observations']],
                device_outcome='PHONE_DISCOVERY_OPPORTUNITY_PASS' if smoke['complete'] else
                    'PHONE_DISCOVERY_OPPORTUNITY_FAIL')
            report['f_process_retained_observed'] = (True if any(row['f_process_retained'] is True
                for row in smoke['observations']) else None if any(row['progress_unknown']
                for row in smoke['observations']) else False)
            report['decryption_attempt_observed'] = any(row['decrypt_attempted'] for row in smoke['observations'])
            report['frame_claim_observed'] = any(row['frame_claimed'] for row in smoke['observations'])
            for key, value in smoke['flags'].items():
                report[key] = value
            if smoke['terminal'] is not None:
                for key, value in smoke['terminal'].items():
                    report['terminal_' + key] = value
            if report.get('terminal_handoff_received') is True:
                report['device_outcome'] = 'HANDOFF_CAPTURED_CANCELLED'
            sealer.fresh(out / 'private-observation.json',
                (json.dumps(dict(smoke=smoke, inner=inner), sort_keys=True, indent=2)+'\n').encode('ascii'))
    except BaseException as failure:
        report['error'] = type(failure).__name__
        if sealer is not None:
            sealer.fresh(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
        else:
            with (private / 'unsealed-host-error.private.txt').open('xb') as stream:
                raw = traceback.format_exc().encode('utf-8')
                need(stream.write(raw) == len(raw), 'unsealed_error_write')
    finally:
        collect_receipts(private, report, sealer.fresh if sealer is not None else None)
        try:
            need(sealer is not None and EVIDENCE is not None, 'private_sealer_required')
            sealer.fresh(private / 'remote-exit', (str(report['remote_exit'])+'\n').encode('ascii'))
            kept = all(read_fixed(path) == raw for path, raw in tuple(INPUTS.items()))
            EVIDENCE.snapshot(out, lambda name: name)
            report['source_preserved'] = (kept and not EVIDENCE.partial and not EVIDENCE.changed_attempts and
                program is not None and all((out/'private-inputs'/path).read_bytes() == raw
                    for path, raw in INPUTS.items()) and
                all((out/name).read_bytes() == raw for name, raw in (
                    ('private-durable-base-target.py', base), ('private-durable-phone-base-target.py', phone),
                    ('private-phone-target.py', program))))
        except BaseException as failure:
            report['source_preserved'] = False
            report['error'] = report['error'] or type(failure).__name__
            if sealer is not None:
                try:
                    EVIDENCE.snapshot(out, lambda name: name)
                except BaseException as snapshot_failure:
                    report['snapshot_error'] = type(snapshot_failure).__name__
                    sealer.fresh(private / 'snapshot-error.private.txt', traceback.format_exc().encode('utf-8'))
                sealer.fresh(private / 'evidence-error.private.txt', traceback.format_exc().encode('utf-8'))
    report['source_count'] = len(INPUTS)
    report['input_pins'] = [dict(path=path, bytes=len(raw), sha256=digest(raw),
        complete=path not in PARTIAL and (EVIDENCE is None or path not in EVIDENCE.partial))
        for path, raw in INPUTS.items()]
    report['passed'] = (report['source_checked'] and report['source_preserved'] and report['error'] is None and
        (not device or report['host_exit'] == 0 and report.get('stderr_bytes') == 0 and
         report['remote_status_known'] and report['remote_exit'] == 0 and report.get('smoke_complete') is True and
         report.get('trace_result') is not None and report['trace_result']['thread_trace_installed'] is True and
         report['trace_result']['thread_trace_hook_restored'] is True and report['trace_result']['trace_unknown'] is False))
    if sealer is None:
        # Do not execute a rejected sealer. Preserve the actual boot inputs,
        # including a returned prefix, using only same-run exclusive writes.
        for path, raw in INPUTS.items():
            target = out / 'private-inputs' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                need(stream.write(raw) == len(raw), 'unsealed_input_write')
            need(target.read_bytes() == raw, 'unsealed_input_readback')
        with (private / 'unsealed-failure-result.json').open('xb') as stream:
            raw = (json.dumps(report, sort_keys=True, indent=2)+'\n').encode('ascii')
            need(stream.write(raw) == len(raw), 'unsealed_result_write')
        print(json.dumps(dict(passed=False, mode=mode, result_dir=str(out), public_result_zip=None)))
        return 1
    # Retain and read back every source/target member before the public seal.
    try:
        import zipfile
        members = [('private-inputs/'+path, raw) for path, raw in sorted(INPUTS.items())]
        members += [(name, raw) for name, raw in (('private-durable-base-target.py', base),
            ('private-durable-phone-base-target.py', phone), ('private-phone-target.py', program)) if raw is not None]
        private_zip = out / 'private-source.zip'
        with zipfile.ZipFile(private_zip, 'x', zipfile.ZIP_DEFLATED) as archive:
            for name, raw in members:
                archive.writestr(name, raw)
        with zipfile.ZipFile(private_zip) as archive:
            need(archive.namelist() == [name for name, raw in members] and archive.testzip() is None and
                 all(archive.read(name) == raw for name, raw in members), 'private_source_zip_readback')
        report.update(private_source_zip_readback=True, private_source_zip_bytes=private_zip.stat().st_size,
                      private_source_zip_sha256=digest(private_zip.read_bytes()))
    except BaseException as failure:
        report['passed'] = False
        report['error'] = report['error'] or type(failure).__name__
        sealer.fresh(private / 'private-source-seal-error.private.txt', traceback.format_exc().encode('utf-8'))
    sealed = sealer.seal_result(out, report, READ_ME)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode, result_dir=str(out),
        device_outcome=sealed['report']['device_outcome'], public_result_zip=str(sealed['archive'])
        if sealed['archive'] else None, zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
