"""Pure AST/literal/JSON/bytes SOURCE check, never imports or executes business.

This independently fixed composition keeps the original sender canonical root.
It does NOT grant replacement of an existing different deployed inventory.
No wire/program assembly, tests, WSL, native, transport or device invocation.
"""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
SELF = 'host/formal_send_filecenter_source_check.py'
CMD = 'HOST_MTA_FORMAL_SEND_FILECENTER_SOURCE_CHECK.cmd'
OLD_BOOT = ('candidate/formal-send-v1/runtime/mta_client_receive_boot.py',
    19217, 'db3c016b2d4a296b029cf1a7cd41da5595d677dd9ab7aa9fb2a477ba44afb2c4')
OLD_OWNER = ('candidate/formal-send-v1/runtime/mta_client_service_owner.py',
    46866, '60a5010c02d9e545b437877a939f73eb93fb1262dfeec37e3bf8d714ecf553bc')
DUPLEX_OUTER = ('candidate/duplex-window-v1/runtime/formal_send_session.py',
    24023, '154a073f88d50c4c71ec7562f830f4e91a459e7e67508a7e24369611df1964e7')
CATALOG = ('candidate/formal-send-v1/assets/ordinary-source-manifest.json',
    18219, '0aff3d932addb257962cb1aa89857784ddaaec945d34ee75c43e95fab15d2fb1')
FC_RECIPE = ('host/device_receive_filecenter_v1_check.py',
    67179, 'da6a5a4dd78ef03156d1b4675e1081f4dbda5b6c9d4623cc9ddc549a5f564510')
STORAGE = ('candidate/receive-directory-fd-v1/runtime/mta_storage.py',
    55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1')
# Author-frozen source identity only; not a deployed or runtime admission seal.
NEW_BOOT = ('candidate/formal-send-filecenter-v1/runtime/mta_client_receive_boot.py',
    19511, 'bcef49b2cf70565725eb7e853183be64f6d07f91133bea81a1e845f636ad0631')
NEW_OWNER = ('candidate/formal-send-filecenter-v1/runtime/mta_client_service_owner.py',
    82369, '4772f6975f8f09699e4dcf269a6ed4bdbb7a6ac429b8dca03a3a1193745a4fce')
NEW_OUTER = ('candidate/formal-send-filecenter-v1/runtime/formal_send_session.py',
    24023, 'c5e9f1d1ec2c2cc7bc722769e1c701a8d5a7c6102ac92ccd6d9c66d00123fee7')
FILECENTER = (
    ('mta_toolbox_json', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py',
     3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'),
    ('mta_toolbox_minhttp', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py',
     9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'),
    ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py',
     9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'),
    ('mta_toolbox_metrics', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py',
     4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'),
    ('mta_toolbox_audio', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py',
     9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'),
    ('mta_toolbox_server', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py',
     19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'),
    ('mta_filecenter_audio', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_audio.py',
     8773, 'dd559da62af71042b11ada6ba26ee574548daace3650b9a9e99f8dbfe737d154'),
    ('mta_filecenter_storage', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_storage.py',
     4581, '19013d117ffc041d7be0f6f1101a65ef9acfba45ffe7bb815264f596556cf169'),
    ('mta_filecenter_companion', 'candidate/receive-filecenter-v1/runtime/mta_filecenter_companion.py',
     23598, '06508a083f2865b143c2ada6f52b86f87f9514c57b878bb1ece59c24f73c8813'),
)
SOURCE_CAP = 2097152
FILECENTER_CAP = 131072
ERROR_CODES = frozenset(('fixed_path', 'source_link', 'source_file', 'source_identity', 'source_changed',
    'source_pin', 'pins_not_frozen', 'literal_shape', 'boot_contract', 'catalog_contract',
    'ordinary_contract', 'storage_only_change', 'boot_body_changed', 'owner_contract',
    'filecenter_contract', 'outer_contract', 'outer_body_changed', 'source_count', 'snapshot_readback'))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, code):
    if not value:
        raise ValueError(code)


def read_fixed(name, size=None, sha=None):
    need(type(name) is str and re.fullmatch('[A-Za-z0-9_./-]+', name) is not None and
         not name.startswith('/') and all(piece not in ('', '.', '..') for piece in name.split('/')), 'fixed_path')
    path = BASE
    for piece in name.split('/'):
        path /= piece
        item = path.lstat()
        need(not stat.S_ISLNK(item.st_mode) and not getattr(item, 'st_file_attributes', 0) & 0x400, 'source_link')
    need(stat.S_ISREG(item.st_mode) and 0 < item.st_size <= SOURCE_CAP, 'source_file')
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    meta = lambda value: tuple(getattr(value, field) for field in fields)
    before = meta(item)
    with path.open('rb') as stream:
        opened = meta(os.fstat(stream.fileno()))
        cross_same = (before[:2] == opened[:2] and stat.S_IFMT(before[2]) == stat.S_IFMT(opened[2]) and
                      before[3:8] == opened[3:8]) if os.name == 'nt' else before == opened
        need(cross_same, 'source_identity')
        raw = stream.read(SOURCE_CAP + 1)
        need(meta(os.fstat(stream.fileno())) == opened, 'source_changed')
    need(meta(path.lstat()) == before and len(raw) == before[6], 'source_changed')
    need((size is None or len(raw) == size) and (sha is None or digest(raw) == sha), 'source_pin')
    return raw


def assignment(tree, name):
    values = [node.value for node in tree.body if isinstance(node, ast.Assign) and
              any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    need(len(values) == 1, 'literal_shape')
    return values[0]


def literal(tree, name):
    return ast.literal_eval(assignment(tree, name))


def parse(raw):
    return ast.parse(raw.decode('utf-8'), feature_version=(3, 5))


def body_without_doc(tree):
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and type(body[0].value.value) is str:
        body.pop(0)
    return body


def boot_contracts(old, new, source_rows):
    old_pins = tuple((row['module'], row['bytes'], row['sha256']) for row in source_rows)
    need(len(old_pins) == 32 and len(set(row[0] for row in old_pins)) == 32 and
         literal(old, 'SOURCE_PINS') == old_pins, 'boot_contract')
    expected = tuple(('mta_storage', STORAGE[1], STORAGE[2]) if row[0] == 'mta_storage' else row for row in old_pins)
    need(literal(new, 'SOURCE_PINS') == expected and
         [index for index, pair in enumerate(zip(old_pins, expected)) if pair[0] != pair[1]] == [3],
         'storage_only_change')
    # Normalize only the one source pin assignment; every non-doc AST node must stay original.
    new_pin = assignment(new, 'SOURCE_PINS')
    old_pin = assignment(old, 'SOURCE_PINS')
    for node in new.body:
        if isinstance(node, ast.Assign) and node.value is new_pin:
            node.value = old_pin
    need([ast.dump(node, include_attributes=False) for node in body_without_doc(old)] ==
         [ast.dump(node, include_attributes=False) for node in body_without_doc(new)], 'boot_body_changed')
    return expected


def pin_neutral(raw):
    for name in ('BOOT_PIN', 'OWNER_PIN'):
        pattern = rb'(?m)^' + name.encode('ascii') + rb' = \([^\n]+\)$'
        need(len(re.findall(pattern, raw)) == 1, 'outer_contract')
        raw = re.sub(pattern, name.encode('ascii') + b' = (FIXED_PIN)', raw)
    return raw


def source_contracts(inputs):
    old_boot, new_boot = parse(inputs[OLD_BOOT[0]]), parse(inputs[NEW_BOOT[0]])
    old_owner, new_owner = parse(inputs[OLD_OWNER[0]]), parse(inputs[NEW_OWNER[0]])
    old_outer, new_outer = parse(inputs[DUPLEX_OUTER[0]]), parse(inputs[NEW_OUTER[0]])
    recipe = parse(inputs[FC_RECIPE[0]])
    catalog = json.loads(inputs[CATALOG[0]])
    need(catalog['schema'] == 'p011-formal-send-v1-ordinary-source-catalog' and catalog['source_count'] == 32 and
         len(catalog['sources']) == 32 and catalog['original_per_source_cap_bytes'] == SOURCE_CAP and
         catalog['original_boot_load_seconds'] == 10, 'catalog_contract')
    expected = boot_contracts(old_boot, new_boot, catalog['sources'])
    need(literal(new_owner, 'BOOT_PIN') == NEW_BOOT[1:] and
         literal(new_owner, 'BOOT_MODULES') == tuple(row[0] for row in expected) and
         literal(new_owner, 'BOOT_MODULES') == literal(old_owner, 'BOOT_MODULES') and
         literal(new_owner, 'BOOT_SCHEMA') == literal(old_owner, 'BOOT_SCHEMA') and
         literal(new_owner, 'ROOT') == literal(old_owner, 'ROOT'), 'owner_contract')
    pins = tuple((name, size, sha) for name, path, size, sha in FILECENTER)
    need(literal(recipe, 'FILECENTER_SOURCES') == FILECENTER and
         literal(recipe, 'FILECENTER_SOURCE_BYTES') == 91295 and
         literal(recipe, 'FILECENTER_SOURCE_CAP') == FILECENTER_CAP and
         literal(new_owner, 'FILECENTER_PINS') == pins and
         literal(new_owner, 'FILECENTER_MAX_SOURCE') == FILECENTER_CAP and
         sum(row[2] for row in FILECENTER) == 91295 <= FILECENTER_CAP, 'filecenter_contract')
    need(literal(new_outer, 'BOOT_PIN') == NEW_BOOT[1:] and literal(new_outer, 'OWNER_PIN') == NEW_OWNER[1:] and
         literal(old_outer, 'BOOT_PIN') == OLD_BOOT[1:] and literal(old_outer, 'OWNER_PIN') == OLD_OWNER[1:],
         'outer_contract')
    need(pin_neutral(inputs[NEW_OUTER[0]]) == pin_neutral(inputs[DUPLEX_OUTER[0]]), 'outer_body_changed')
    return catalog


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'snapshot_readback')
        stream.flush()
        os.fsync(stream.fileno())
    need(path.read_bytes() == raw, 'snapshot_readback')


def finite_error(error):
    if (type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str and
            error.args[0] in ERROR_CODES):
        return error.args[0]
    return {ValueError: 'host_value', OSError: 'host_io', SyntaxError: 'host_syntax',
            KeyError: 'host_key', TypeError: 'host_type'}.get(type(error), 'host_unknown')


def main():
    if sys.argv[1:]:
        return 2
    out = BASE / 'results' / ('formal-send-filecenter-source-' +
        datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    out.mkdir(parents=True, exist_ok=False)
    inputs, traces = {}, []
    report = dict(kind='formal-send-filecenter-v1-source', passed=False, source_preserved=False,
        source_inputs=0, ordinary_count=32, ordinary_changed_roles=[], filecenter_count=9,
        filecenter_bytes=91295, filecenter_cap=FILECENTER_CAP, per_source_cap=SOURCE_CAP,
        boot_load_seconds=10, new_runtime_ast_count=0, old_contract_ast_count=0,
        filecenter_recipe_ast_count=0, unchanged_runtime_ast_count=0,
        boot_body_only_storage_pin=False, owner_filecenter_pins=False,
        outer_only_two_pins=False, runtime=False, tests=False, old_tests=False,
        wire_assembled=False, graph_executed=False, boot_started=False, owner_started=False,
        filecenter_started=False, guardian_verified=False, native=False, rf=False, device=False,
        phone=False, production_admitted=False, restoration_verified=False,
        existing_root_replacement_authorized=False, outer_exit_observed=False,
        error_code=None, checker_decision=None)
    try:
        for pin in (NEW_BOOT, NEW_OWNER, NEW_OUTER):
            need(type(pin[1]) is int and type(pin[2]) is str and re.fullmatch('[0-9a-f]{64}', pin[2]) is not None,
                 'pins_not_frozen')
        for pin in (NEW_BOOT, NEW_OWNER, NEW_OUTER, OLD_BOOT, OLD_OWNER, DUPLEX_OUTER, CATALOG, FC_RECIPE, STORAGE):
            inputs[pin[0]] = read_fixed(*pin)
        catalog = source_contracts(inputs)
        report.update(new_runtime_ast_count=3, old_contract_ast_count=3, filecenter_recipe_ast_count=1,
                      boot_body_only_storage_pin=True, owner_filecenter_pins=True, outer_only_two_pins=True)
        for row in catalog['sources']:
            raw = read_fixed(row['source'], row['bytes'], row['sha256'])
            inputs[row['source']] = raw
        for name, path, size, sha in FILECENTER:
            inputs[path] = read_fixed(path, size, sha)
        for name in (SELF, CMD):
            inputs[name] = read_fixed(name)
        need(len(inputs) == 52, 'source_count')
        report['ordinary_changed_roles'] = ['mta_storage']
        report['ordinary_source_bytes'] = sum(row['bytes'] for row in catalog['sources']) - 14335 + STORAGE[1]
        traces.append('SOURCE_CONTRACTS=ordinary32_storage_only,filecenter9,outer2pins\n')
    except Exception as error:
        report['error_code'] = finite_error(error)
        traces.append('SOURCE_ERROR_KIND=' + type(error).__name__ + '\n')
    inventory = {}
    try:
        for name, raw in inputs.items():
            save(out / 'private-inputs' / name, raw)
            inventory[name] = dict(bytes=len(raw), sha256=digest(raw))
        save(out / 'private-inputs.json', (json.dumps(inventory, sort_keys=True, indent=2) + '\n').encode('ascii'))
        report['source_preserved'] = len(inputs) == 52 and all(
            read_fixed(name, len(raw), digest(raw)) == raw and
            (out / 'private-inputs' / name).read_bytes() == raw for name, raw in inputs.items())
    except Exception as error:
        if report['error_code'] is None:
            report['error_code'] = finite_error(error)
        traces.append('SOURCE_SNAPSHOT_ERROR_KIND=' + type(error).__name__ + '\n')
    report['source_inputs'] = len(inputs)
    report['passed'] = report['error_code'] is None and report['source_preserved']
    report['checker_decision'] = 0 if report['passed'] else 1
    traces.append('SOURCE_CHECKER_DECISION=' + str(report['checker_decision']) + '\n')
    save(out / 'private-source-trace.raw', ''.join(traces).encode('ascii'))
    save(out / 'checker-decision.raw', (str(report['checker_decision']) + '\n').encode('ascii'))
    save(out / 'business-exit.raw', b'NOT_RUN_BUSINESS\n')
    save(out / 'device-exit.raw', b'NOT_RUN_DEVICE\n')
    result = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii')
    note = (b'Pure SOURCE only. AST/literal/JSON and full byte/size/SHA readback of three new sources, '
        b'the old Boot/Owner, passed duplex sender outer, old32 actual ordinary sources, replacement '
        b'original DirectoryBinding storage and original9 FileCenter sources. Boot32 changes only '
        b'ordinary storage pin; its non-doc AST is otherwise original. New sender outer changes '
        b'only Boot/Owner pin lines, with all other bytes original. FC9 totals91295/cap131072 and '
        b'per-source2MiB/Boot10s are not enlarged. No eval/exec/import of business or old HOST recipe, '
        b'no tests/WSL/wire/program assembly/staging/Boot/Owner/FileCenter/guardian/native/RF/device/phone '
        b'or restore/admission. Shared original canonical sender root does not authorize replacement '
        b'of deployed complete different inventory. This check cannot prove actual DirectoryBinding '
        b'IO or Companion/guardian APIs work on P011. All52 source bytes, fixed path inventory and '
        b'checker-emitted source trace are PRIVATE; trace is not business stdout/stderr or outer exit. '
        b'Public ZIP has only result.json and README.txt; no runtime credentials/user data.\n')
    save(out / 'result.json', result)
    save(out / 'README.txt', note)
    bundle = out / 'SOURCE_RESULTS.zip'
    with zipfile.ZipFile(bundle, 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', result)
        archive.writestr('README.txt', note)
    with zipfile.ZipFile(bundle) as archive:
        need(archive.namelist() == ['result.json', 'README.txt'] and archive.testzip() is None and
             archive.read('result.json') == result and archive.read('README.txt') == note, 'snapshot_readback')
    print(json.dumps(dict(passed=report['passed'], result_dir=str(out),
        zip_bytes=bundle.stat().st_size, zip_sha256=digest(bundle.read_bytes())), sort_keys=True))
    return report['checker_decision']


if __name__ == '__main__':
    raise SystemExit(main())
