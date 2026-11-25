"""Fixed prerequisite-root metadata observation; default PC SOURCE only.

Explicit --check-device reuses only the pinned P011 probe's target selection,
Adb and stock source definitions. It takes two lstat samples of the three roots
from the actual v6 Stage literal. No Stage/service/Owner/Boot is imported or
executed. No root is opened, listed, created, archived, repaired or admitted.
Public ready/missing/unsuitable is metadata evidence, never full inventory,
restoration, Safety, radio or transfer acceptance. Raw streams stay private.
"""
import argparse
import ast
import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import stat
import subprocess
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_repair_prerequisite_roots_v1_check.py'
HOST_CMD = 'HOST_MTA_FORMAL_SEND_REPAIR_PREREQUISITE_ROOTS_V1.cmd'
TEST_CMD = 'TEST_MTA_FORMAL_SEND_REPAIR_PREREQUISITE_ROOTS_V1.cmd'
STAGE = ('candidate/formal-send-filecenter-deploy-v6/runtime/formal_send_stage.py', 37417,
         '49e9f972d093d7f7749f5dd4a38558a73cc0e36ea894e558455238aeb8f840da')
TRANSPORT = ('host/device_probe.py', 8759,
             'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
EXPECTED_ROOTS = (
    ('sender', '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets'),
    ('observer', '/var/volatile/tmp/p011-mta-go-observer-libc-v1'),
    ('ordinary', '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v6'))
BODY = r'''
import errno,os,stat
calls=0
def sample(path):
 global calls
 calls+=1
 try:value=os.lstat(path)
 except OSError as error:
  if type(error.errno)is int and error.errno==errno.ENOENT:return ('missing',None)
  return ('error',error.errno if type(error.errno)is int and 1<=error.errno<=4095 else None)
 return ('metadata',tuple(getattr(value,key) for key in
  ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')))
first=tuple(sample(path) for role,path in ROOTS)
second=tuple(sample(path) for role,path in ROOTS)
print('RESULT='+repr(dict(samples=tuple((role,a,b) for (role,path),a,b in zip(ROOTS,first,second)),
 lstat_calls=calls,device_writes=False,directory_opened=False,inventory_read=False,
 stage_invoked=False,radio_operations=False,full_inventory_verified=False,safety_admitted=False)))
'''
FALSE_FIELDS = ('device_writes', 'directory_opened', 'inventory_read', 'stage_invoked',
                'radio_operations', 'full_inventory_verified', 'safety_admitted')
ERRORS = frozenset(('input_pin', 'source_contract', 'source_budget', 'remote_result',
                    'stock_baseline', 'stock_changed', 'source_changed', 'host_transport'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if value is not True:
        raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_changed')
    need(path.read_bytes() == raw, 'source_changed')


def fixed(inputs, row):
    relative, size, checksum = row
    raw = (BASE / relative).read_bytes()
    need((len(raw), sha(raw)) == (size, checksum), 'input_pin')
    inputs[relative] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    matches = [node.value for node in tree.body if isinstance(node, ast.Assign) and
               any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(matches) == 1, 'source_contract')
    return ast.literal_eval(matches[0])


def probe_definitions(raw):
    # No old probe module/main/run_probe or business module is imported.
    tree = ast.parse(raw.decode('utf-8'))
    names = {'select_target', 'Adb', 'source'}
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
             and node.name in names]
    need(len(nodes) == 3 and {node.name for node in nodes} == names, 'source_contract')
    module = types.ModuleType('repair_prerequisite_roots_probe_private')
    module.__dict__.update(Path=Path, subprocess=subprocess, re=re, base64=base64,
                           zlib=zlib, ast=ast, ADB=Path('C:/Program Files/ADB/adb.exe'),
                           PINS=literal(raw, 'PINS'), PROBE=literal(raw, 'PROBE'))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<fixed-readonly-probe-definitions>',
                 'exec'), module.__dict__)
    return module


def compressed_budget(source):
    payload = base64.b64encode(zlib.compress(source.encode('utf-8'))).decode('ascii')
    command = ('python3 -B -c "import base64,zlib;exec(zlib.decompress(base64.b64decode(\'' +
               payload + '\')));print(\'MTA_REMOTE_OK\')"; r=$?; printf \'\\nMTA_REMOTE_EXIT=%s\\n\' "$r"')
    need(len(command) <= 3500, 'source_budget')
    ast.parse(source, feature_version=(3, 5))


def source_contract(inputs):
    stage = fixed(inputs, STAGE)
    transport = fixed(inputs, TRANSPORT)
    table = literal(stage, 'PROFILE_FILES')
    roots = tuple((row[0], row[1]) for row in table)
    need(len(table) == 3 and roots == EXPECTED_ROOTS, 'source_contract')
    program = 'ROOTS=' + repr(roots) + '\n' + BODY
    compressed_budget(program)
    # SOURCE authenticates the actual stock-probe literal without executing it.
    baseline = 'PINS=' + repr(literal(transport, 'PINS')) + '\n' + literal(transport, 'PROBE')
    compressed_budget(baseline)
    return roots, program


def receipt(private, stem):
    value = dict(host_exit=None, remote_exit=None, remote_status_known=False,
                 stdout_bytes=0, stdout_sha256=sha(b''), stderr_bytes=0, stderr_sha256=sha(b''))
    path = private / (stem + '.host-exit')
    if path.exists():
        text = path.read_text(encoding='ascii').strip()
        value['host_exit'] = int(text) if re.fullmatch(r'-?\d+', text) else 'TIMEOUT'
    stdout = b''
    for stream in ('stdout', 'stderr'):
        path = private / (stem + '.' + stream + '.raw')
        if path.exists():
            raw = path.read_bytes()
            value[stream + '_bytes'], value[stream + '_sha256'] = len(raw), sha(raw)
            if stream == 'stdout':
                stdout = raw
    derived = stdout.decode('utf-8', 'replace').replace('\r\r\n', '\n').replace('\r\n', '\n')
    matches = re.findall(r'^MTA_REMOTE_EXIT=(-?\d+)$', derived, re.M)
    if len(matches) == 1 and len(matches[0]) <= 12:
        value['remote_status_known'], value['remote_exit'] = True, int(matches[0])
    write_new(private / (stem + '.remote-exit'),
              (str(value['remote_exit']) if value['remote_status_known'] else 'UNKNOWN').encode('ascii'))
    need(len(stdout) <= 65536, 'remote_result')
    return value, derived


def run_readonly(adb, probe, private, label, source, report, field):
    compressed_budget(source)
    stem = '%02d-%s' % (adb.index + 1, label)
    try:
        result = probe.Adb.python(adb, label, source, timeout=45)
    finally:
        report[field], derived = receipt(private, stem)
    current = report[field]
    need(current['host_exit'] == 0 and current['stderr_bytes'] == 0 and
         current['remote_status_known'] and current['remote_exit'] == 0 and
         derived.splitlines().count('MTA_REMOTE_OK') == 1 and
         len([line for line in derived.splitlines() if line.startswith('RESULT=')]) == 1,
         'remote_result')
    return result


def stock_identity(value, pins):
    need(type(value) is dict and set(value) == {'stock', 'capabilities'} and
         type(value['stock']) is dict and type(value['capabilities']) is dict and
         type(value['stock'].get('processes')) is list and
         type(value['capabilities'].get('wifi_connected')) is bool, 'stock_baseline')
    rows = value['stock']['processes']
    return (value['stock'].get('hashes') == pins and
        all(len([row for row in rows if type(row) is dict and row.get('name') == name]) == 1
            for name in ('Z03', 'control_engine', 'weston')) and
        all(row.get('exe') == '/usr/bin/' + row['name'] for row in rows
            if type(row) is dict and row.get('name') in ('Z03', 'control_engine')))


def classify(value):
    need(type(value) is dict and set(value) == {'samples', 'lstat_calls'} | set(FALSE_FIELDS)
         and type(value['lstat_calls']) is int and value['lstat_calls'] == 6
         and all(value[field] is False for field in FALSE_FIELDS)
         and type(value['samples']) is tuple and len(value['samples']) == 3, 'remote_result')
    rows = []
    for actual, expected in zip(value['samples'], EXPECTED_ROOTS):
        need(type(actual) is tuple and len(actual) == 3 and actual[0] == expected[0], 'remote_result')
        for sample in actual[1:]:
            need(type(sample) is tuple and len(sample) == 2 and sample[0] in
                 ('missing', 'error', 'metadata'), 'remote_result')
            if sample[0] == 'metadata':
                need(type(sample[1]) is tuple and len(sample[1]) == 9 and
                     all(type(item) is int and -(1 << 63) <= item < (1 << 64)
                         for item in sample[1]), 'remote_result')
            elif sample[0] == 'missing':
                need(sample[1] is None, 'remote_result')
            else:
                need(sample[1] is None or type(sample[1]) is int and 1 <= sample[1] <= 4095,
                     'remote_result')
        first, second = actual[1:]
        stable = first == second
        suitable = (stable and first[0] == 'metadata' and
                    first[1][2] == stat.S_IFDIR | 0o700 and
                    first[1][3:5] == (0, 0) and first[1][5] >= 1)
        status = 'missing' if stable and first[0] == 'missing' else 'ready' if suitable else 'unsuitable'
        rows.append(dict(role=actual[0], status=status, samples_stable=stable,
                         evidence='ROOT_METADATA_ONLY', inventory_verified=False, safety_admitted=False))
    prerequisite = 'unsuitable' if any(row['status'] == 'unsuitable' for row in rows[:2]) else (
        'missing' if any(row['status'] == 'missing' for row in rows[:2]) else 'ready')
    return rows, prerequisite


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-device', action='store_true', help='Only two lstat samples per fixed root, with stock before/after.')
    args = parser.parse_args()
    mode = 'device-readonly' if args.check_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('formal-send-repair-prerequisite-roots-v1-' + mode + '-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = {}
    adb = probe = before = after = None
    report = dict(kind='formal-send-repair-prerequisite-roots-v1', mode=mode, passed=False,
        source_complete=False, source_preserved=False, input_count=0, device_invoked=False,
        roots_observed=False, lstat_calls=0, prerequisite_status=None, root_statuses=None,
        stock_identity_ok=None, stock_unchanged=None, wifi_connected_before=None, wifi_connected_after=None,
        baseline_before_receipt=None, baseline_after_receipt=None, roots_receipt=None,
        evidence='PC_SOURCE_ONLY' if mode == 'source' else 'P011_ROOT_METADATA_ONLY',
        device_writes=False, directory_opened=False, inventory_read=False, stage_invoked=False,
        owner_started=False, ui_started=False, radio_operations=False, inventory_verified=False,
        safety_admitted=False, restoration_verified=False, production_admitted=False,
        old_tests_run=0, error_code=None)
    try:
        roots, program = source_contract(inputs)
        for path in (SELF, HOST_CMD, TEST_CMD):
            inputs[path] = (BASE / path).read_bytes()
        write_new(private / 'roots.source.private.py', program.encode('ascii'))
        report['source_complete'] = True
        if mode != 'source':
            probe = probe_definitions(inputs[TRANSPORT[0]])
            report['device_invoked'] = True
            adb = probe.Adb(private)
            before = run_readonly(adb, probe, private, 'stock-before', probe.source(), report, 'baseline_before_receipt')
            write_new(private / 'stock-before.private.json', (json.dumps(before, sort_keys=True) + '\n').encode('ascii'))
            need(stock_identity(before, probe.PINS), 'stock_baseline')
            report['wifi_connected_before'] = before['capabilities']['wifi_connected']
            value = run_readonly(adb, probe, private, 'roots', program, report, 'roots_receipt')
            write_new(private / 'roots.samples.private.json', (json.dumps(value, sort_keys=True) + '\n').encode('ascii'))
            report['root_statuses'], report['prerequisite_status'] = classify(value)
            report['roots_observed'], report['lstat_calls'] = True, value['lstat_calls']
    except BaseException as error:
        report['error_code'] = (error.args[0] if type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERRORS else
            'host_transport' if type(error) is RuntimeError else 'unexpected')
    finally:
        if adb is not None:
            try:
                after = run_readonly(adb, probe, private, 'stock-after', probe.source(), report, 'baseline_after_receipt')
                write_new(private / 'stock-after.private.json', (json.dumps(after, sort_keys=True) + '\n').encode('ascii'))
                report['stock_identity_ok'] = before is not None and stock_identity(before, probe.PINS) and stock_identity(after, probe.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                report['wifi_connected_after'] = after['capabilities']['wifi_connected']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None:
                    report['error_code'] = 'stock_changed'
        preserved = bool(inputs)
        inventory = {}
        for path, raw in inputs.items():
            try:
                destination = out / 'private-inputs' / path
                write_new(destination, raw)
                inventory[path] = dict(bytes=len(raw), sha256=sha(raw))
                preserved = preserved and destination.read_bytes() == raw and (BASE / path).read_bytes() == raw
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        write_new(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['passed'] = (report['source_complete'] and report['source_preserved'] and report['error_code'] is None
        and (mode == 'source' or report['roots_observed'] and report['stock_identity_ok'] is True and report['stock_unchanged'] is True))
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE; explicit --check-device readonly root metadata only.\n'
        b'Two lstat samples each of sender, observer, ordinary roots from pinned v6 Stage.\n'
        b'No root open/list/hash/create/archive/permissions repair, Stage/business/RF action.\n'
        b'ready means root metadata suitable only; never full inventory or Safety admission.\n'
        b'ordinary target missing is separate from sender/observer prerequisites missing.\n'
        b'PASS means observation/stock/source evidence complete, not roots ready or transfer success.\n'
        b'Private raw stdout/stderr/host and remote exits retained. ZIP exactly result+README.\n')
    write_new(out / 'result.json', result)
    write_new(out / 'README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', readme)
    with zipfile.ZipFile(out / 'RESULTS.zip') as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == result and archive.read('README.txt') == readme, 'source_changed')
    code = 0 if report['passed'] else 1
    write_new(out / 'checker-exit.txt', (str(code) + '\n').encode('ascii'))
    print(json.dumps(dict(passed=report['passed'], mode=mode, result_dir=str(out)), sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
