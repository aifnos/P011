"""One fixed ordinary-v4 files-only stage; default PC SOURCE.

No Owner/UI/Parent/transfer/RF/history action. Explicit modes use the existing fixed
legacy-ADB carrier, never its old main or old SOURCE checks. Device source and
raw bytes stay private; public ZIP has only result.json and README.txt.
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
import types
import zipfile
import zlib

BASE = Path(__file__).resolve().parents[1]
SELF = 'host/device_formal_send_filecenter_ordinary_v4_check.py'
CMD = 'STAGE_MTA_FORMAL_SEND_FILECENTER_ORDINARY_V4.cmd'
ROOT = '/var/volatile/tmp/p011-mta-formal-send-filecenter-deploy-v4'
CATALOG = ('candidate/formal-send-filecenter-deploy-v4/assets/ordinary-source-manifest.json',
    20642, '5cd52fe1b7a11103a7675f1250691b1aaa42de93ed15ca22f0a7b30d1ff43125')
ASSETS = ('candidate/formal-send-filecenter-deploy-v4/assets/asset-sources.json',
    24267, 'be76740f8d7283e2db5806790c87997dee24a0911beb1306d7c9833086745ec0')
OBSERVER = ('candidate/go-observer-libc-v1/assets/observer-source-catalog.json',
    15861, '8aaadd3f5a32b184bb851b422781ae8038d699d3e9555cb479cd49f4d090648a')
STAGE = ('candidate/formal-send-filecenter-deploy-v4/runtime/formal_send_stage.py',
    37417, 'eea92666ea575937bb54c29158af1f6ffc83bde7a909d9cc61125b22e50a938a')
ORIGINAL_STAGE = ('candidate/formal-send-filecenter-deploy-v3/runtime/formal_send_stage.py',
    37426, '875591a3624181ab3e0a455ac104660e68f261d46c42721f36609dea4baf7f91')

GENERATOR = ('host/formal_send_filecenter_deploy_v3_source_check.py',
    30450, '9c5f9db7e9373a72378d622eb16c6fed5f1c94abeca8dd723455fa8518eea8d1')
ENVELOPE = ('host/formal_send_stage_bootstrap_source_check.py',
    19997, 'aede2e43410f7f3a78fb715c077e567da84ba47d9dfa9c5d4290e3b8795b60d3')
WRAPPER = ('candidate/formal-send-stage-bootstrap-v1/runtime/formal_send_stage_bootstrap.py',
    13207, 'c304c4abc854425b51b0f8c8bae3c90361fbfcef5413414a107df9e530169f7d')
CARRIER = ('host/device_formal_send_filecenter_stage_carrier_v3_check.py',
    25857, '043844b6be906369ad16b17562030629213a127756adb73c849b7b7b4c10ff0d')
HELPER = ('host/device_formal_send_filecenter_stage_v1_check.py',
    22495, '68cdbacc1f9a33e61fcdbe603b183909092f2a93c4f7dfcd82a92e2e98b4f145')
TRANSPORT = ('host/device_probe.py', 8759,
    'e7a841ec250adb083c643250bae3a6ac07412e775c4bef98f935f6d1c9fa9348')
ERRORS = frozenset(('input_pin', 'catalog_shape', 'stage_contract', 'source_budget',
    'source_changed', 'stock_baseline', 'stock_changed', 'carrier_result', 'carrier_files',
    'stage_refused', 'remote_status_unknown', 'host_transport'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if not value:
        raise ValueError(code)


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_changed')
    need(path.read_bytes() == raw, 'source_changed')


def fixed(inputs, row):
    path, size, digest = row
    raw = (BASE / path).read_bytes()
    need((len(raw), sha(raw)) == (size, digest), 'input_pin')
    inputs[path] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(rows) == 1, 'stage_contract')
    return ast.literal_eval(rows[0])


def module(raw, path, name):
    # Fixed helper definitions only. Their __main__ blocks cannot run here.
    value = types.ModuleType(name)
    value.__file__ = str(BASE / path)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def selected_generator(raw):
    names = {'literal', 'digest', 'encoded_chunks', 'frame', 'make_program',
             'replace_assignment', 'bootstrap_parts', 'bootstrap_program'}
    tree = ast.parse(raw.decode('ascii'))
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in selected} == names and len(selected) == len(names), 'stage_contract')
    namespace = dict(ast=ast, base64=base64, hashlib=hashlib, zlib=zlib,
        LINE=96, MAX_PROGRAM=2097152, MAX_WIRE=4194304, MAX_RAW=4194304,
        STAGE=STAGE, PROGRAM_BODY=literal(raw, 'PROGRAM_BODY'))
    # Only the eight byte/AST-envelope helpers execute on PC. No target classes,
    # old main/source_check/graph_contracts/test method execute.
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<fixed-byte-generator>', 'exec'), namespace)
    return namespace



def payloads(inputs):
    for row in (CATALOG, ASSETS, OBSERVER, STAGE, ORIGINAL_STAGE, GENERATOR,
                ENVELOPE, WRAPPER, CARRIER, HELPER, TRANSPORT):
        fixed(inputs, row)
    catalog = json.loads(inputs[CATALOG[0]])
    assets = json.loads(inputs[ASSETS[0]])
    observer = json.loads(inputs[OBSERVER[0]])
    need(catalog['physical_ordinary_root'] == ROOT + '/runtime' and
        catalog['ordinary_batch_files'] == 37 and catalog['ordinary_batch_bytes'] == 1346543 and
        assets['sender_root'] == '/var/volatile/tmp/p011-mta-go-send-filecenter-v3-assets' and
        assets['observer_root'] == observer['root'] == '/var/volatile/tmp/p011-mta-go-observer-libc-v1' and
        observer['source_count'] == 41 and observer['source_bytes'] == 1442508, 'catalog_shape')
    items = [row for row in catalog['sources'] if not row['reused_sender_asset']]
    items += catalog['startup_sources'] + catalog['helper_sources']
    rows = []
    for item in items:
        need(item['physical_target'].startswith(ROOT + '/') and
            item['mode'] in (0o400, 0o500, 0o700), 'catalog_shape')
        raw = fixed(inputs, (item['source'], item['bytes'], item['sha256']))
        pin = (item['physical_target'][len(ROOT) + 1:], len(raw), sha(raw), item['mode'])
        rows.append((pin, raw))
    need(len(rows) == 37 and sum(len(raw) for pin, raw in rows) == 1346543 and
         len(set(pin[0] for pin, raw in rows)) == 37, 'catalog_shape')
    stage = inputs[STAGE[0]]
    table = literal(stage, 'PROFILE_FILES')
    need(literal(stage, 'PROFILE_TOTALS') == (('sender', 27, 2402458),
         ('observer', 41, 1442508), ('ordinary', 37, 1346543)) and
         literal(stage, 'MAX_SECONDS') == 120.0 and
         table[2] == ('ordinary', ROOT, tuple(pin for pin, raw in rows)), 'stage_contract')
    # Reuse fixed sender/observer inventories as readonly prerequisites. Do not
    # reread their source payloads, republish their roots, or rerun their suites.
    sender_rows = []
    for item in assets['sender_sources'] + [assets['sender_manifest'], assets['wpa']]:
        need(item['target'].startswith(assets['sender_root'] + '/'), 'catalog_shape')
        sender_rows.append((item['target'][len(assets['sender_root']) + 1:],
                            item['bytes'], item['sha256'], int(item.get('mode', '0400'), 8)))
    observer_rows = tuple(('runtime/' + item['module'] + '.py',
        item['bytes'], item['sha256'], 0o400) for item in observer['files'])
    need(table[:2] == (('sender', assets['sender_root'], tuple(sender_rows)),
         ('observer', observer['root'], observer_rows)), 'stage_contract')
    old_tree = ast.parse(inputs[ORIGINAL_STAGE[0]].decode('utf-8'), feature_version=(3, 5))
    new_tree = ast.parse(stage.decode('utf-8'), feature_version=(3, 5))
    shape = lambda tree: [ast.dump(node, include_attributes=False) for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))]
    need(shape(old_tree) == shape(new_tree), 'stage_contract')
    generator = selected_generator(inputs[GENERATOR[0]])
    inner, wire = generator['make_program']('ordinary', tuple(rows), stage)
    wrapper = inputs[WRAPPER[0]]
    old = b'len(_DATA_TABLE_ORIGINAL) == 3 and'
    need(wrapper.count(old) == 1, 'stage_contract')
    wrapper = wrapper.replace(old, b'len(_DATA_TABLE_ORIGINAL) == 1 and')
    data, wrapper = generator['bootstrap_parts']([('ordinary', inner)], [('ordinary', wire)], wrapper)
    program = generator['bootstrap_program']('ordinary', data, wrapper, literal(inputs[ENVELOPE[0]], 'ENVELOPE'))
    need(len(program) <= 2097152 and max(map(len, program.splitlines())) <= 256 and
        len(wire) <= 4194304 and max(map(len, wire.splitlines())) <= 256, 'source_budget')
    ast.parse(program.decode('ascii'), feature_version=(3, 5))
    return program, wire

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-device', action='store_true', help='Only publish ordinary v4; readonly sender/observer prerequisites.')
    args = parser.parse_args()
    mode = 'stage' if args.stage_device else 'source'
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
    out = BASE / 'results' / ('formal-send-filecenter-ordinary-v4-' + mode + '-' + stamp)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'private-raw'
    private.mkdir()
    inputs = {}; helper = carrier = transport = adb = before = after = root = launch = row = leaf = None
    report = dict(kind='formal-send-filecenter-ordinary-v4-thin', mode=mode, passed=False, source_complete=False,
        source_preserved=False, input_count=0, stage_invoked=False, parent_invoked=False,
        device_invoked=False, device_execution_unknown=False, stock_identity_ok=None, stock_unchanged=None,
        baseline_before_receipt=None, baseline_after_receipt=None, wifi_connected_before=None,
        wifi_connected_after=None, carrier_create_receipt=None, carrier_launch_receipt=None,
        carrier_after_receipt=None, carrier_resources_closed=False, carrier_files_stable=False,
        push_receipts=[], stage_result=None, bootstrap_result=None, parent_result=None,
        source_programs=[], carrier_shell_limit=4096, program_limit=2097152, wire_limit=4194304,
        target_line_limit=256, ordinary_files=37, ordinary_bytes=1346543,
        sender_readonly_prerequisite=True, observer_readonly_prerequisite=True, ui_assets_restaged=False,
        stage_inner_seconds=120, stage_outer_seconds=180,
        rf_requested=False, owner_started=False, ui_started=False, restoration_verified=False,
        production_admitted=False, pending_handled=False, old_tests_run=0, error_code=None)
    try:
        stage_payload = payloads(inputs)
        inputs[SELF] = (BASE / SELF).read_bytes()
        inputs[CMD] = (BASE / CMD).read_bytes()
        helper = module(inputs[HELPER[0]], HELPER[0], 'ordinary_v4_helper_private')
        carrier = module(inputs[CARRIER[0]], CARRIER[0], 'ordinary_v4_carrier_private')
        for label, (program, wire) in (('stage', stage_payload),):
            write_new(private / (label + '.bootstrap.py'), program)
            write_new(private / (label + '.wire.raw'), wire)
            current_row = ('ordinary', 37, 1346543, len(program), sha(program), len(wire), sha(wire))
            for phase in ('create', 'launch', 'inspect'):
                # Check actual generated carrier shell length with nine-field integer
                # metadata, not a large payload on PTY stdin. Never execute it on PC.
                sample_meta = (66328, 123456789, 16832, 0, 0, 2, 4096, 1770000000000000000, 1770000000000000000)
                sample_files = tuple((name, (66328, 123456789 + n, 33152, 0, 0, 1,
                    current_row[3 if n == 0 else 5], 1770000000000000000, 1770000000000000000))
                    for n, name in enumerate(('bootstrap.py', 'wire.raw')))
                source = carrier.target_source(phase, 'p011-mta-stage-carrier-v3-' + 'f' * 24,
                    current_row, None if phase == 'create' else sample_meta,
                    sample_files if phase == 'inspect' else None)
                ast.parse(source, feature_version=(3, 5))
                carrier.compressed_command(source)
            report['source_programs'].append(dict(mode=label, bytes=len(program), sha256=sha(program),
                wire_bytes=len(wire), wire_sha256=sha(wire), max_line=max(map(len, program.splitlines()))))
        report['source_complete'] = True
        for path, raw in inputs.items():
            write_new(out / 'private-inputs' / path, raw)
        if mode != 'source':
            transport = helper.load_transport(inputs[TRANSPORT[0]])
            report['device_invoked'] = True
            adb = transport.Adb(private)
            before = carrier.baseline(helper, adb, transport, private, 'before', report)
            need(helper.stock_identity(before, transport.PINS), 'stock_baseline')
            program, wire = stage_payload
            row = ('ordinary', 37, 1346543, len(program), sha(program), len(wire), sha(wire))
            leaf = 'p011-mta-stage-carrier-v3-' + secrets.token_hex(12)
            remote = '/var/volatile/tmp/' + leaf
            write_new(private / 'carrier-root.private', remote.encode('ascii'))
            report['device_execution_unknown'] = True
            receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-create',
                carrier.target_source('create', leaf, row), 30)
            report['carrier_create_receipt'] = receipt
            root = carrier.carrier_result(raw, 'create')
            write_new(private / 'carrier-create.private.json', (json.dumps(root, sort_keys=True) + '\n').encode('ascii'))
            need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'] and receipt['remote_exit'] == 0 and root['carrier_created'] and
                root['resources_closed'] and root['opened_fds'] == root['closed_fds'], 'carrier_result')
            for name, data in (('bootstrap.py', program), ('wire.raw', wire)):
                path = private / 'carrier-inputs' / name
                write_new(path, data)
                label = 'push-' + name.split('.')[0]
                stem = '%02d-%s' % (adb.index + 1, label)
                try:
                    adb.run(label, ['push', str(path), remote + '/' + name], timeout=45)
                finally:
                    receipt, ignored = helper.raw_receipt(private, stem, 'MTA_PUSH_REMOTE_EXIT')
                    report['push_receipts'].append(receipt)
                need(receipt['host_exit'] == 0 and path.read_bytes() == data, 'carrier_files')
            report['stage_invoked'] = mode == 'stage'
            receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-launch',
                carrier.target_source('launch', leaf, row, root['root_metadata']), 210)
            report['carrier_launch_receipt'] = receipt
            if receipt['remote_status_known'] and type(receipt['host_exit']) is int:
                report['device_execution_unknown'] = False
            # Save actual remote exit before expecting any component projection.
            stage, bootstrap, ignored = helper.parse_results(raw, 'ordinary')
            report['stage_result'], report['bootstrap_result'] = stage, bootstrap
            launch = carrier.carrier_result(raw, 'launch')
            write_new(private / 'carrier-launch.private.json', (json.dumps(launch, sort_keys=True) + '\n').encode('ascii'))
            report['carrier_resources_closed'] = launch['resources_closed']
            report['carrier_files_stable'] = launch['files_stable']
            need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                receipt['remote_status_known'], 'remote_status_unknown')
            need(receipt['remote_exit'] == 0 and launch['resources_closed'] and launch['files_stable'] and
                launch['stdin_regular_verified'] and launch['stdin_closed'],
                'stage_refused')
            need(helper.completed(report['stage_result'], report['bootstrap_result'], row), 'stage_refused')
    except BaseException as error:
        report['error_code'] = (error.args[0] if type(error) is ValueError and len(error.args) == 1 and
            type(error.args[0]) is str and error.args[0] in ERRORS else
            'host_transport' if type(error) is RuntimeError else 'unexpected')
    finally:
        if adb is not None:
            if root is not None and root['carrier_created']:
                try:
                    receipt, raw, error = carrier.run_target(helper, adb, private, 'carrier-after',
                        carrier.target_source('inspect', leaf, row, root['root_metadata'],
                            launch['files'] if launch is not None else None), 30)
                    report['carrier_after_receipt'] = receipt
                    value = carrier.carrier_result(raw, 'inspect')
                    need(error is None and receipt['host_exit'] == 0 and receipt['stderr_bytes'] == 0 and
                        receipt['remote_status_known'] and receipt['remote_exit'] == 0 and value['resources_closed'] and
                        value['files_stable'] and (launch is None or value['files'] == launch['files']), 'carrier_files')
                except BaseException:
                    if report['error_code'] is None:
                        report['error_code'] = 'carrier_files'
            try:
                after = carrier.baseline(helper, adb, transport, private, 'after', report)
                report['stock_identity_ok'] = before is not None and helper.stock_identity(before, transport.PINS) and \
                    helper.stock_identity(after, transport.PINS)
                report['stock_unchanged'] = before is not None and before['stock'] == after['stock']
                need(report['stock_identity_ok'] and report['stock_unchanged'], 'stock_changed')
            except BaseException:
                if report['error_code'] is None:
                    report['error_code'] = 'stock_baseline'
        inventory = {}; preserved = bool(inputs)
        for path, raw in inputs.items():
            try:
                destination = out / 'private-inputs' / path
                if not destination.exists():
                    write_new(destination, raw)
                inventory[path] = dict(bytes=len(raw), sha256=sha(raw))
                preserved = destination.read_bytes() == raw and (BASE / path).read_bytes() == raw and preserved
            except BaseException:
                preserved = False
        report['source_preserved'], report['input_count'] = preserved, len(inputs)
        write_new(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
    report['passed'] = report['source_complete'] and report['source_preserved'] and report['error_code'] is None
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    readme = (b'Default PC SOURCE; explicit --stage-device ordinary v4 only.\n'
        b'37 fixed files, new isolated root. Existing sender27/observer41 inventories read only.\n'
        b'EXCL files/dirs, original full pin readback; partial/conflict untouched.\n'
        b'No sender/observer republish, Parent/Owner/UI/RF/helper/phone/history action.\n'
        b'No 19UI stage/build. Source2MiB, wire4MiB, line256; original120/180 and carrier200.\n'
        b'Private carrier/payload/input/raw stdout/stderr/exits retained; ZIP exactly result+README.\n'
        b'PC envelope check is not device admission or whole Owner/UI acceptance.\n')
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
