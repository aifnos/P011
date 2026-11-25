"""Fixed P011 Owner _context model microbenchmark; default PC SOURCE only.

Explicit --check-device measures old/new unchanged method ASTs on field models.
It starts no Owner lifecycle, runtime graph, UI, phone, Stage or RF operation.
The device's real elapsed/process CPU clocks measure only this model workload;
they do not certify actual startup performance or a future ten-second margin.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import traceback
import types
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_receive_owner_dispatch_bench_v1_check.py'
CMDS = ('HOST_MTA_RECEIVE_OWNER_DISPATCH_BENCH_V1_CHECK.cmd',
        'TEST_MTA_RECEIVE_OWNER_DISPATCH_BENCH_V1.cmd')
MOTHER = ('host/device_formal_send_repair_prerequisite_roots_v1_check.py', 16667,
          '94325f0c0f666c88e198dec11a18efce39daf3d1463c925c9ee51bbe649450fd')
READ_DONOR = ('host/receive_owner_dispatch_v1_host_check.py', 11929,
              '099bc322a0efe447b6cda16b3aecae59c57a5fb54723f5d5e108ccb3478c018d')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
SEALER = ('host/host_artifact_seal_v1.py', 6784,
          '30b9cbf6b20ce10232f356d0464f0803c94fc8bee2250055c3434aae9c5126c7')
MAKER = ('host/receive_owner_dispatch_bench_v1_target.py', 18243,
         'f03657eb4ab0331337b7431ad53c9d373f13b13b7ad4294826d995624757bdad')
OWNER_PINS = (
    ('candidate/receive-publication-progress-graph-v1/runtime/mta_client_service_owner.py',
     107026, 'a33b1a4c015bda42fc8ab8ba447fd5f331181df1a5b4240fc82f455dc2b74da7'),
    ('candidate/receive-owner-dispatch-v1/runtime/mta_client_service_owner.py',
     107104, '22aa94d8d5ae2a1dd75c5c98635d80020b318f7071ea84c5c3cb3d85e2805adf'))
PURE_NAMES = ('sha', 'need', 'write_new', 'literal', 'probe_definitions',
              'compressed_budget', 'receipt', 'run_readonly', 'stock_identity')
README = (b'Default SOURCE only; explicit --check-device bounded Owner _context field-model benchmark.\n'
    b'The unchanged original/new actual method ASTs run in separate ordinary type namespaces.\n'
    b'Four ABBA groups, sixteen blocks of 8192 calls, 128 warmup calls for each side.\n'
    b'Real device monotonic/process CPU clocks are required; absent or malformed CPU evidence fails.\n'
    b'Alarm30 is set before the exact fixed stdin read; HOST45. No fallback command or retry.\n'
    b'Source<=48000 and line<=256; original receipt stdout<=65536; raw streams remain private.\n'
    b'Only the unique MODEL_RESULT line is parsed; possible stdin source echo is not model evidence.\n'
    b'Original pinned stock probes run before and in finally after; stock identity must remain exact.\n'
    b'PASS is bounded model/stock/source evidence, not startup completion, RF, transfer or recovery.\n'
    b'No Owner constructor/lifecycle, other method bodies, runtime graph, Stage, UI or phone is called.\n'
    b'Private inputs, target, stdout/stderr and host/remote exits are sealed before public result.\n')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


def read_fixed(name):
    if (type(name) is not str or not name or '\\' in name or
            PurePosixPath(name).is_absolute() or re.fullmatch(r'[A-Za-z0-9_./-]+', name) is None or
            any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('fixed_path')
    path = BASE
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or
                getattr(value, 'st_file_attributes', 0) & 0x400):
            raise ValueError('fixed_ancestor')
    for index, part in enumerate(name.split('/')):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise ValueError('fixed_link')
        if index < len(name.split('/')) - 1 and not stat.S_ISDIR(value.st_mode):
            raise ValueError('fixed_ancestor')
    if not stat.S_ISREG(value.st_mode) or not 0 < value.st_size <= 2097152:
        raise ValueError('fixed_file')
    metadata = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_nlink,
                          v.st_size, v.st_mtime_ns, v.st_ctime_ns)
    before = metadata(value)
    with path.open('rb') as handle:
        opened = metadata(os.fstat(handle.fileno()))
        equal = (opened[:2] == before[:2] and stat.S_IFMT(opened[2]) == stat.S_IFMT(before[2]) and
                 opened[3:6] == before[3:6]) if os.name == 'nt' else opened == before
        if not equal:
            raise ValueError('fixed_identity')
        raw = handle.read(2097153)
        if metadata(os.fstat(handle.fileno())) != opened:
            raise ValueError('fixed_changed')
    if metadata(path.lstat()) != before or len(raw) != before[4]:
        raise ValueError('fixed_changed')
    return raw


def declarations(raw, name, path):
    tree = ast.parse(raw, feature_version=(3, 5))
    need(not any(isinstance(node, ast.If) for node in tree.body), 'unexpected_source_guard')
    value = types.ModuleType(name)
    value.__file__ = str(BASE / path)
    exec(compile(tree, value.__file__, 'exec'), value.__dict__)
    return value


def readonly_definitions(raw):
    tree = ast.parse(raw, feature_version=(3, 5))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in PURE_NAMES]
    need(tuple(node.name for node in nodes) == PURE_NAMES and all(not node.decorator_list for node in nodes),
         'fixed_readonly_definitions')
    value = types.ModuleType('fixed_owner_dispatch_bench_readonly')
    value.__dict__.update(BASE=BASE, Path=Path, subprocess=subprocess, re=re,
                         base64=base64, zlib=zlib, ast=ast, types=types, hashlib=hashlib)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<fixed-readonly-bench-definitions>',
                 'exec'), value.__dict__)
    need('main' not in value.__dict__ and 'source_contract' not in value.__dict__, 'old_main_forbidden')
    return value


def source_contract(inputs):
    donor = ast.parse(inputs[READ_DONOR[0]], feature_version=(3, 5))
    own = ast.parse(inputs[SELF], feature_version=(3, 5))
    before = [node for node in donor.body if isinstance(node, ast.FunctionDef) and node.name == 'read_fixed']
    after = [node for node in own.body if isinstance(node, ast.FunctionDef) and node.name == 'read_fixed']
    need(len(before) == len(after) == 1 and ast.dump(before[0], include_attributes=False) ==
         ast.dump(after[0], include_attributes=False), 'fixed_read_definition_inverse')
    helpers = readonly_definitions(inputs[MOTHER[0]])
    baseline = 'PINS=' + repr(helpers.literal(inputs[TRANSPORT[0]], 'PINS')) + '\n' + \
               helpers.literal(inputs[TRANSPORT[0]], 'PROBE')
    helpers.compressed_budget(baseline)
    maker = declarations(inputs[MAKER[0]], 'fixed_owner_dispatch_bench_maker', MAKER[0])
    need(maker.PINS == OWNER_PINS and maker.SCHEMA == 'p011-owner-dispatch-bench-v1-model' and
         maker.CALLS_PER_BLOCK == 8192 and maker.GROUPS == 4 and maker.CALL_COUNT == 131072 and
         maker.WARMUP_EACH == 128 and maker.TARGET_LIMIT == 48000 and
         maker.TARGET_MAX_LINE == 256 and maker.OUTPUT_LIMIT == 65536 and
         maker.RESULT_PREFIX == 'MODEL_RESULT=', 'fixed_model_contract')
    original = maker.make_source({row[0]: inputs[row[0]] for row in OWNER_PINS})
    program = original + b"\nprint('MTA_REMOTE_OK')\n"
    need(type(original) is bytes and 0 < len(program) <= 48000 <= 2097152 and
         max(map(len, program.splitlines())) <= 256, 'target_budget')
    ast.parse(program.decode('ascii'), feature_version=(3, 5))
    return helpers, maker, original, program


def run_bench(adb, probe, helpers, maker, private, program, report):
    label = 'owner-dispatch-bench'
    stem = '%02d-%s' % (adb.index + 1, label)
    command = ('/usr/bin/python3.5 -I -B -c "import signal,sys;signal.alarm(30);'
        'exec(sys.stdin.buffer.read(' + str(len(program)) + '))" p011-owner-dispatch-bench-v1; '
        'r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    need(len(command) <= 3500, 'fixed_command_budget')
    report['bench_invoked'] = True
    try:
        output = probe.Adb.run(adb, label, ['shell', command], timeout=45, input_data=program)
    finally:
        report['bench_receipt'], derived = helpers.receipt(private, stem)
    current = report['bench_receipt']
    need(current['host_exit'] == 0 and current['stderr_bytes'] == 0 and
         current['remote_status_known'] and current['remote_exit'] == 0 and
         derived.splitlines().count('MTA_REMOTE_OK') == 1, 'bench_remote_result')
    need(type(output) is bytes and (private / (stem + '.stdout.raw')).read_bytes() == output and
         current['stdout_sha256'] == sha(output), 'bench_raw_identity')
    rows = [line for line in derived.splitlines() if line.startswith(maker.RESULT_PREFIX)]
    need(len(rows) == 1, 'unique_model_result')
    # Do not feed possible echoed stdin source to the strict measurement parser.
    selected = (rows[0] + '\n').encode('ascii')
    value = maker.parse(selected)
    helpers.write_new(private / 'model-result.selected.private.raw', selected)
    report['model_measurement'] = value
    report['model_wall_and_process_cpu_verified'] = True
    totals = {}
    for side in ('A', 'B'):
        blocks = [row for row in value['blocks'] if row['side'] == side]
        calls = sum(row['calls'] for row in blocks)
        wall = sum(row['elapsed_seconds'] for row in blocks)
        cpu = sum(row['process_cpu_seconds'] for row in blocks)
        totals[side] = dict(calls=calls, elapsed_seconds=wall, process_cpu_seconds=cpu,
                           elapsed_seconds_per_call=wall / calls, process_cpu_seconds_per_call=cpu / calls)
    report['model_totals'] = totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true')
    args = parser.parse_args()
    mode = 'device-model' if args.check_device else 'source'
    out = BASE / 'results' / ('receive-owner-dispatch-bench-v1-' + mode + '-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4))
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'; private.mkdir()
    inputs, sealer, evidence = {}, None, None
    helpers = maker = program = original = adb = probe = before = after = None
    report = dict(schema='p011-owner-dispatch-bench-v1-check', mode=mode, passed=False,
        error=None, source_checked=False, source_preserved=False, source_count=0,
        device_invoked=False, bench_invoked=False, bench_receipt=None,
        baseline_before_receipt=None, baseline_after_receipt=None,
        stock_identity_ok=None, stock_unchanged=None, wifi_connected_before=None, wifi_connected_after=None,
        model_configured=True, model_wall_and_process_cpu_verified=False,
        model_measurement=None, model_totals=None, requested_blocks=16, requested_calls_per_block=8192,
        requested_call_count=131072, requested_warmup_each=128, original_alarm_seconds=30,
        host_timeout_seconds=45, target_source_cap=48000, target_line_cap=256,
        original_source_cap=2097152, original_stdout_cap=65536,
        actual_owner_lifecycle_called=False, other_method_bodies_called=False,
        runtime_graph_executed=False, stage_invoked=False, ui_invoked=False, phone_invoked=False,
        rf_action_requested=False, device_business_writes=False, old_main_called=False, old_tests_replayed=0,
        actual_startup_performance_verified=False, startup_completion_verified=False,
        physical_close_verified=False, interoperability_verified=False, full_network_restore_verified=False)

    def read(path, pin=None):
        raw = read_fixed(path)
        if evidence is not None:
            evidence._retain(path, raw)
        else:
            inputs[path] = raw
        if pin is not None:
            need((len(raw), sha(raw)) == pin, 'fixed_input_pin')
        return raw

    try:
        need(sys.platform == 'win32' and BASE == Path(r'D:\project\P011\working\MtaP011-v0.1'),
             'fixed_windows_workspace')
        seal_raw = read(SEALER[0], SEALER[1:])
        sealer = declarations(seal_raw, 'fixed_owner_dispatch_bench_sealer', SEALER[0])
        evidence = sealer.InputEvidence(inputs)
        for path, size, checksum in (MOTHER, READ_DONOR, TRANSPORT, MAKER) + OWNER_PINS:
            read(path, (size, checksum))
        read(SELF)
        for path in CMDS:
            read(path)
        helpers, maker, original, program = source_contract(inputs)
        helpers.write_new(private / 'benchmark-original.source.private.py', original)
        helpers.write_new(private / 'benchmark.source.private.py', program)
        report.update(source_checked=True, original_target_bytes=len(original), original_target_sha256=sha(original),
            target_bytes=len(program), target_sha256=sha(program), target_max_line_bytes=max(map(len, program.splitlines())))
        evidence.snapshot(out, lambda name: name)
        if args.check_device:
            probe = helpers.probe_definitions(inputs[TRANSPORT[0]])
            report['device_invoked'] = True
            adb = probe.Adb(private)
            before = helpers.run_readonly(adb, probe, private, 'stock-before', probe.source(), report, 'baseline_before_receipt')
            helpers.write_new(private / 'stock-before.private.json', (json.dumps(before, sort_keys=True) + '\n').encode('ascii'))
            need(helpers.stock_identity(before, probe.PINS), 'stock_baseline')
            report['wifi_connected_before'] = before['capabilities']['wifi_connected']
            run_bench(adb, probe, helpers, maker, private, program, report)
    except BaseException as failure:
        report['error'] = type(failure).__name__
        if sealer is not None:
            sealer.fresh(private / 'host-error.private.txt', traceback.format_exc().encode('utf-8'))
    finally:
        if adb is not None:
            try:
                after = helpers.run_readonly(adb, probe, private, 'stock-after', probe.source(), report, 'baseline_after_receipt')
                helpers.write_new(private / 'stock-after.private.json', (json.dumps(after, sort_keys=True) + '\n').encode('ascii'))
                report['stock_identity_ok'] = (before is not None and helpers.stock_identity(before, probe.PINS) and
                                               helpers.stock_identity(after, probe.PINS))
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                report['wifi_connected_after'] = after['capabilities']['wifi_connected']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException as failure:
                report['error'] = report['error'] or type(failure).__name__
                if sealer is not None:
                    sealer.fresh(private / 'stock-after-error.private.txt', traceback.format_exc().encode('utf-8'))
        if evidence is not None:
            try:
                evidence.snapshot(out, lambda name: name)
                report['source_preserved'] = (bool(inputs) and not evidence.partial and all(
                    read_fixed(path) == raw and (out / 'private-inputs' / path).read_bytes() == raw
                    for path, raw in inputs.items()) and program is not None and original is not None and
                    (private / 'benchmark.source.private.py').read_bytes() == program and
                    (private / 'benchmark-original.source.private.py').read_bytes() == original)
            except BaseException as failure:
                report['error'] = report['error'] or type(failure).__name__
                report['source_preserved'] = False
                sealer.fresh(private / 'evidence-error.private.txt', traceback.format_exc().encode('utf-8'))
    report['source_count'] = len(inputs)
    report['passed'] = (report['error'] is None and report['source_checked'] and report['source_preserved'] and
        (not args.check_device or report['bench_invoked'] and report['model_wall_and_process_cpu_verified'] and
         report['stock_identity_ok'] is True and report['stock_unchanged'] is True))
    report['checker_exit'] = 0 if report['passed'] else 1
    report['input_pins'] = [dict(path=path, bytes=len(raw), sha256=sha(raw)) for path, raw in inputs.items()]
    if sealer is None:
        print(json.dumps(dict(passed=False, mode=mode, result_dir=str(out), error=report['error']), sort_keys=True))
        return 1
    sealed = sealer.seal_result(out, report, README)
    print(json.dumps(dict(passed=sealed['report']['passed'], mode=mode, result_dir=str(out),
        public_result_zip=str(sealed['archive']) if sealed['archive'] else None,
        zip_sha256=sealed['archive_sha256']), sort_keys=True))
    return sealed['host_exit']


if __name__ == '__main__':
    raise SystemExit(main())
