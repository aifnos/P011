"""SOURCE-only mechanical Receiver/FileCenter v1 graph generator.

Reads pinned bytes and JSON/AST literals. Imports/executes no project definition,
runner, checker, test or device code. Fixed fresh outputs only; --write is PC-only.
The 75-role payload and separate fixed nine-source FileCenter budgets stay original.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/formal_receive_ui_v1_definitions.py', 10721,
            '9450c13671d0f2c9ff113f1b369ce4a83175aace2834585b74ff3e2f1bd33bc8')
SOURCE_OWNER = ('candidate/formal-receive-filecenter-owner-v1/runtime/mta_client_service_owner.py',
                107037, '6eb891d71b5e935c6bbfdaf4a19621889cdf7c7ee5c56fcd4bcc08f89473f5a2')
STORAGE_SOURCE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py',
                  10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4')
COMPANION_SOURCE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py',
                    33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284')
FC_ORIGINAL = ('candidate/formal-send-filecenter-deploy-v3/assets/filecenter-source-manifest.json',
               2466, '14d57b5aea7c49df0f87b6338044c86ccd155583994e83c8158c5217d7f48e1d')
PAYLOAD_SOURCE = ('host/device_formal_receive_v3_check.py', 46256,
                  '212619ac677d8887c9ede6b968c2f0f8ba084448cfcd6cbf36c359359cbdb8e0')
PREFIX = 'candidate/formal-receive-filecenter-v1/runtime/'
DEFINITIONS = 'host/formal_receive_filecenter_v1_definitions.py'
MANIFEST = 'host/formal_receive_filecenter_v1_definition_manifest.json'
PRIVATE_MANIFEST = 'host/formal_receive_filecenter_v1_private_source_manifest.json'
ROOT_BEFORE = b'p011-mta-formal-receive-ui-v1'
ROOT_AFTER = b'p011-mta-formal-receive-filecenter-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory',
           'minhttp', 'mta_client_receive_boot', 'mta_client_service_owner')
inputs = {}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(pin):
    raw = (BASE / pin[0]).read_bytes()
    need((len(raw), digest(raw)) == tuple(pin[1:]), 'source_pin:' + pin[0])
    inputs[pin[0]] = raw
    return raw


def literal(raw, name):
    tree = ast.parse(raw.decode('utf-8'))
    rows = [row for row in tree.body if isinstance(row, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == name for target in row.targets)]
    need(len(rows) == 1, 'literal:' + name)
    return ast.literal_eval(rows[0].value)


def replace(raw, before, after, count=1):
    need(raw.count(before) == count, 'replacement:' + before[:64].decode('ascii'))
    return raw.replace(before, after)


def roots(raw, count):
    return replace(raw, ROOT_BEFORE, ROOT_AFTER, count)


def json_raw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def pin(name, raw):
    return name, len(raw), digest(raw)


def named_pin_copy(raw, name, before, after, count=1):
    return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                   repr((name, after[1], after[2])).encode('ascii'), count)


def fresh_write(path, raw):
    target = BASE / path
    need(not target.exists(), 'fresh_output:' + path)
    need(target.parent.resolve().is_relative_to(BASE.resolve()), 'workspace_output')
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_write')
    need(target.read_bytes() == raw, 'source_readback')


TEMPLATE = r'''"""Mechanical Receiver/FileCenter v1 graph; original 75 roles and fixed budgets.

The Owner binds the real retained Receiver module passed by FixedSession.
FileCenter nine sources are separately pinned memory inputs, not protocol roles.
This graph is SOURCE preparation, not UI/guardian/RF/phone/restoration acceptance.
"""
import ast
import hashlib
import json
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = @ORIGINAL@
MANIFEST = @MANIFEST@
RUNNER = @RUNNER@
STATE_ALIAS = '/tmp/p011-mta-formal-receive-filecenter-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-filecenter-v1'
CHANGED = @CHANGED@
EXECUTOR_PIN = @EXECUTOR@
PRIVATE_MANIFEST = @PRIVATE@
SOURCE_OWNER = @OWNER@
STORAGE_SOURCE = @STORAGE@
COMPANION_SOURCE = @COMPANION@
FILECENTER_SOURCES = @FILECENTER@
FILECENTER_SOURCE_PINS = FILECENTER_SOURCES
PAYLOAD_BYTES = @PAYLOAD@


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), digest(raw)) != pin[1:]:
        raise ValueError('receive_filecenter_source_pin')
    return raw


ORIGINAL_RAW = read_pin(ORIGINAL)
_old = types.ModuleType('fixed_original_receive_ui_definitions')
_old.__file__ = str(BASE / ORIGINAL[0])
exec(compile(ORIGINAL_RAW, _old.__file__, 'exec'), _old.__dict__)
CHECKER, TRANSPORT = _old.CHECKER, _old.TRANSPORT
BASE_ORIGINAL, BASE_ORIGINAL_RAW = _old.ORIGINAL, _old.ORIGINAL_RAW
OLD_PRIVATE_MANIFEST = _old.PRIVATE_MANIFEST
OLD_PRIVATE_RAW = read_pin(OLD_PRIVATE_MANIFEST)
_old_private = json.loads(OLD_PRIVATE_RAW.decode('ascii'))
HELPERS, WPA, MONITOR = _old.HELPERS, _old.WPA, _old.MONITOR
MODULE_NAMES, PRIVATE_MODULE_NAMES = _old.MODULE_NAMES, _old.PRIVATE_MODULE_NAMES
TRIAL_BOOL_FIELDS, TRIAL_REASONS = _old.TRIAL_BOOL_FIELDS, _old.TRIAL_REASONS
TRIAL_FIELDS = _old.TRIAL_FIELDS
TARGET_COMMON, TARGET_SERVICE = _old.TARGET_COMMON, _old.TARGET_SERVICE
load_checker, _short_chunks = _old.load_checker, _old._short_chunks
parse_trial_facts = _old.parse_trial_facts
ORIGINAL_MANIFEST = _old.MANIFEST
ORIGINAL_MANIFEST_RAW = read_pin(ORIGINAL_MANIFEST)
_old_rows = _old.manifest_rows(ORIGINAL_MANIFEST_RAW)
ORIGIN_SOURCE_PINS = tuple((path, size, sha) for name, path, size, sha in _old_rows
                           if name in CHANGED) + (_old.RUNNER, OLD_PRIVATE_MANIFEST,
                                                 SOURCE_OWNER, STORAGE_SOURCE, COMPANION_SOURCE)


def manifest_rows(raw, private=False):
    value = json.loads(raw.decode('ascii'))
    original = _old_private if private else json.loads(ORIGINAL_MANIFEST_RAW.decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != original['schema'] or
            type(value['sources']) is not list or len(value['sources']) != len(original['sources']) or
            private and value['previous_manifest_sha256'] != OLD_PRIVATE_MANIFEST[2]):
        raise ValueError('receive_filecenter_manifest_shape')
    rows = []
    for row, before in zip(value['sources'], original['sources']):
        name = before['module']
        changed = name == 'mta_client_executor' if private else name in CHANGED
        if not changed:
            if row != before: raise ValueError('receive_filecenter_unchanged_role')
        elif (type(row) is not dict or set(row) != set(before) or row['module'] != name or
              row['path'] != 'candidate/formal-receive-filecenter-v1/runtime/' + name + '.py' or
              type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152 or
              type(row['sha256']) is not str or len(row['sha256']) != 64 or
              any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('receive_filecenter_changed_role')
        if private and name == 'mta_client_executor' and (
                row['path'], row['bytes'], row['sha256']) != EXECUTOR_PIN:
            raise ValueError('receive_filecenter_private_executor')
        rows.append(('runtime35/' + name if private else name, row['path'], row['bytes'], row['sha256']))
    names = tuple('runtime35/' + name for name in PRIVATE_MODULE_NAMES) if private else MODULE_NAMES
    if tuple(row[0] for row in rows) != names: raise ValueError('receive_filecenter_role_order')
    return tuple(rows)


def verify_inputs(inputs):
    """Only seven generated sources; no old graph execution or suite replay."""
    rows = {name: (path, size, sha) for name, path, size, sha in manifest_rows(inputs[MANIFEST[0]])}
    old_rows = {name: (path, size, sha) for name, path, size, sha in _old_rows}
    private = {name: (path, size, sha) for name, path, size, sha in
               manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)}
    if private['runtime35/mta_client_executor'] != rows['mta_client_executor'] or (
            rows['mta_client_executor'] != EXECUTOR_PIN):
        raise ValueError('receive_filecenter_executor_domains')
    if 'runtime35/mta_client_service_owner' in private:
        raise ValueError('receive_filecenter_private_owner')
    if (inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW or
            inputs[OLD_PRIVATE_MANIFEST[0]] != OLD_PRIVATE_RAW):
        raise ValueError('receive_filecenter_original_manifest_changed')
    def replace(raw, before, after, count=1):
        if raw.count(before) != count: raise ValueError('receive_filecenter_replacement_count')
        return raw.replace(before, after)
    def roots(raw, count):
        return replace(raw, b'p011-mta-formal-receive-ui-v1',
                       b'p011-mta-formal-receive-filecenter-v1', count)
    def pin_copy(raw, name, count=1):
        before, after = old_rows[name], rows[name]
        return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                       repr((name, after[1], after[2])).encode('ascii'), count)
    f_before, f_after = old_rows['mta_client_executor'], rows['mta_client_executor']
    old_f, new_f = f_before[2].encode('ascii'), f_after[2].encode('ascii')
    old_private, new_private = OLD_PRIVATE_MANIFEST[2].encode('ascii'), PRIVATE_MANIFEST[2].encode('ascii')
    expected = {}
    expected['mta_client_executor'] = roots(inputs[f_before[0]], 1)
    expected['mta_client_state_bridge'] = replace(inputs[old_rows['mta_client_state_bridge'][0]], old_f, new_f)
    factory = replace(replace(roots(inputs[old_rows['mta_client_receive_factory'][0]], 2),
                              old_private, new_private), old_f, new_f)
    expected['mta_client_receive_factory'] = replace(factory,
        ("('mta_client_executor', " + str(f_before[1]) + ", F_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F_SHA)").encode('ascii'))
    expected['minhttp'] = inputs[old_rows['minhttp'][0]]
    boot = replace(replace(roots(inputs[old_rows['mta_client_receive_boot'][0]], 2),
                           old_private, new_private), old_f, new_f)
    boot = replace(boot,
        ("('mta_client_executor', " + str(f_before[1]) + ", F37_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F37_SHA)").encode('ascii'), 2)
    for name in ('mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp'):
        boot = pin_copy(boot, name)
    expected['mta_client_receive_boot'] = boot
    before, after = old_rows['mta_client_receive_boot'], rows['mta_client_receive_boot']
    owner = replace(roots(inputs[SOURCE_OWNER[0]], 2),
        ('BOOT_PIN = ' + repr(before[1:])).encode('ascii'),
        ('BOOT_PIN = ' + repr(after[1:])).encode('ascii'))
    fc_before = next(ast.literal_eval(row.value) for row in ast.parse(inputs[SOURCE_OWNER[0]]).body
                     if isinstance(row, ast.Assign) and
                     any(isinstance(target, ast.Name) and target.id == 'FILECENTER_PINS' for target in row.targets))
    for name, path, size, sha in FILECENTER_SOURCES:
        if name in ('mta_filecenter_storage', 'mta_filecenter_companion'):
            old = next(row for row in fc_before if row[0] == name)
            owner = replace(owner, repr(old).encode('ascii'), repr((name, size, sha)).encode('ascii'))
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha): raise ValueError('receive_filecenter_memory_source_pin')
    if len(FILECENTER_SOURCES) != 9 or sum(row[2] for row in FILECENTER_SOURCES) != 113690:
        raise ValueError('receive_filecenter_memory_source_budget')
    expected['mta_client_service_owner'] = owner
    runner = roots(inputs[_old.RUNNER[0]], 2)
    for name in CHANGED:
        runner = pin_copy(runner, name, 2 if name == 'mta_client_executor' else 1)
    expected[RUNNER[0]] = runner
    for name, raw in expected.items():
        path = RUNNER[0] if name == RUNNER[0] else rows[name][0]
        if inputs[path] != raw: raise ValueError('receive_filecenter_nonmechanical_change')
        ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
    return len(expected)


@MAKE_SOURCE@
'''


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_source_generation_only')
    original_raw = read_pin(ORIGINAL)
    old_manifest_pin = literal(original_raw, 'MANIFEST')
    old_private_pin = literal(original_raw, 'PRIVATE_MANIFEST')
    old_runner_pin = literal(original_raw, 'RUNNER')
    ordinary = json.loads(read_pin(old_manifest_pin).decode('ascii'))
    private = json.loads(read_pin(old_private_pin).decode('ascii'))
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    need(len(ordinary['sources']) == len(private['sources']) == 35, 'original_role_count')
    need(all(row['module'] != 'mta_client_service_owner' for row in private['sources']),
         'original_private_no_service_owner')
    old_sources = {name: read_pin(old_rows[name]) for name in CHANGED}
    old_runner = read_pin(old_runner_pin)
    owner_raw = read_pin(SOURCE_OWNER)
    read_pin(STORAGE_SOURCE)
    read_pin(COMPANION_SOURCE)
    payload_source = read_pin(PAYLOAD_SOURCE)
    helpers = literal(payload_source, 'HELPERS')
    wpa, monitor = literal(payload_source, 'WPA'), literal(payload_source, 'MONITOR')
    fc_original = json.loads(read_pin(FC_ORIGINAL).decode('ascii'))
    fc_rows = []
    for row in fc_original['sources']:
        value = dict(row)
        if value['module'] == 'mta_filecenter_storage':
            value.update(source=STORAGE_SOURCE[0], bytes=STORAGE_SOURCE[1], sha256=STORAGE_SOURCE[2])
        elif value['module'] == 'mta_filecenter_companion':
            value.update(source=COMPANION_SOURCE[0], bytes=COMPANION_SOURCE[1], sha256=COMPANION_SOURCE[2])
        read_pin((value['source'], value['bytes'], value['sha256']))
        fc_rows.append((value['module'], value['source'], value['bytes'], value['sha256']))
    fc_rows = tuple(fc_rows)
    need(len(fc_rows) == 9 and sum(row[2] for row in fc_rows) == 113690 < 131072, 'filecenter_budget')
    outputs = {}
    def put(name, raw):
        outputs[PREFIX + name + '.py'] = raw
        return (PREFIX + name + '.py', len(raw), digest(raw))
    new_rows = dict(old_rows)
    new_rows['mta_client_executor'] = put('mta_client_executor', roots(old_sources['mta_client_executor'], 1))
    new_private = copy.deepcopy(private)
    new_private['previous_manifest_sha256'] = old_private_pin[2]
    for row in new_private['sources']:
        if row['module'] == 'mta_client_executor':
            row.update(path=new_rows[row['module']][0], bytes=new_rows[row['module']][1],
                       sha256=new_rows[row['module']][2])
    private_raw = json_raw(new_private)
    outputs[PRIVATE_MANIFEST] = private_raw
    old_f, new_f = old_rows['mta_client_executor'][2].encode('ascii'), new_rows['mta_client_executor'][2].encode('ascii')
    private_before, private_after = old_private_pin[2].encode('ascii'), digest(private_raw).encode('ascii')
    bridge = replace(old_sources['mta_client_state_bridge'], old_f, new_f)
    new_rows['mta_client_state_bridge'] = put('mta_client_state_bridge', bridge)
    factory = replace(replace(roots(old_sources['mta_client_receive_factory'], 2),
                              private_before, private_after), old_f, new_f)
    factory = replace(factory,
        ("('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(new_rows['mta_client_executor'][1]) + ", F_SHA)").encode('ascii'))
    new_rows['mta_client_receive_factory'] = put('mta_client_receive_factory', factory)
    new_rows['minhttp'] = put('minhttp', old_sources['minhttp'])
    boot = replace(replace(roots(old_sources['mta_client_receive_boot'], 2),
                           private_before, private_after), old_f, new_f)
    boot = replace(boot,
        ("('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F37_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(new_rows['mta_client_executor'][1]) + ", F37_SHA)").encode('ascii'), 2)
    for name in ('mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp'):
        boot = named_pin_copy(boot, name, old_rows[name], new_rows[name])
    new_rows['mta_client_receive_boot'] = put('mta_client_receive_boot', boot)
    owner = replace(roots(owner_raw, 2),
        ('BOOT_PIN = ' + repr(old_rows['mta_client_receive_boot'][1:])).encode('ascii'),
        ('BOOT_PIN = ' + repr(new_rows['mta_client_receive_boot'][1:])).encode('ascii'))
    fc_before = literal(owner_raw, 'FILECENTER_PINS')
    for name in ('mta_filecenter_storage', 'mta_filecenter_companion'):
        before = next(row for row in fc_before if row[0] == name)
        after = next((row[0], row[2], row[3]) for row in fc_rows if row[0] == name)
        owner = replace(owner, repr(before).encode('ascii'), repr(after).encode('ascii'))
    need(literal(owner, 'FILECENTER_PINS') == tuple((name, size, sha) for name, path, size, sha in fc_rows),
         'owner_filecenter_pins')
    need(literal(owner, 'FILECENTER_MAX_SOURCE') == 131072, 'owner_filecenter_cap')
    new_rows['mta_client_service_owner'] = put('mta_client_service_owner', owner)
    runner = roots(old_runner, 2)
    for name in CHANGED:
        runner = named_pin_copy(runner, name, old_rows[name], new_rows[name],
                                2 if name == 'mta_client_executor' else 1)
    runner_pin = put('mta_formal_receive_session', runner)
    new_ordinary = copy.deepcopy(ordinary)
    for row in new_ordinary['sources']:
        if row['module'] in CHANGED:
            after = new_rows[row['module']]
            row.update(path=after[0], bytes=after[1], sha256=after[2])
    ordinary_raw = json_raw(new_ordinary)
    outputs[MANIFEST] = ordinary_raw
    fc_repr = '(\n' + ''.join('    ' + repr(row) + ',\n' for row in fc_rows) + ')'
    make_source = original_raw.decode('utf-8')[original_raw.decode('utf-8').index('def make_source('):].rstrip()
    values = {'ORIGINAL': repr(ORIGINAL), 'MANIFEST': repr(pin(MANIFEST, ordinary_raw)),
              'RUNNER': repr(runner_pin), 'CHANGED': repr(CHANGED),
              'EXECUTOR': repr(new_rows['mta_client_executor']),
              'PRIVATE': repr(pin(PRIVATE_MANIFEST, private_raw)), 'OWNER': repr(SOURCE_OWNER),
              'STORAGE': repr(STORAGE_SOURCE), 'COMPANION': repr(COMPANION_SOURCE),
              'FILECENTER': fc_repr, 'MAKE_SOURCE': make_source,
              'PAYLOAD': str(sum(row['bytes'] for row in new_ordinary['sources']) +
                             sum(row['bytes'] for row in new_private['sources']) +
                             sum(row[2] for row in helpers) + wpa[2] + monitor[2])}
    definitions = TEMPLATE
    for key, value in values.items():
        need(definitions.count('@' + key + '@') == 1, 'definitions_token:' + key)
        definitions = definitions.replace('@' + key + '@', value)
    need('@' not in definitions, 'definitions_unexpanded')
    outputs[DEFINITIONS] = definitions.encode('utf-8')
    role_pins = literal(runner, 'ROLE_PINS')
    private_pins = literal(runner, 'PRIVATE_PINS')
    need(role_pins == tuple((row['module'], row['bytes'], row['sha256']) for row in new_ordinary['sources']),
         'ordinary_closure')
    need(private_pins == tuple((row['module'], row['bytes'], row['sha256']) for row in new_private['sources']),
         'private_closure')
    need(literal(runner, 'HELPER_PINS') == tuple((name, size, sha) for name, path, size, sha in helpers),
         'helper_closure')
    need(literal(runner, 'WPA_PIN') == (wpa[0], wpa[2], wpa[3]) and
         literal(runner, 'MONITOR_PIN') == (monitor[0], monitor[2], monitor[3]), 'asset_closure')
    need(literal(owner, 'BOOT_PIN') == new_rows['mta_client_receive_boot'][1:], 'owner_boot_closure')
    need(literal(factory, 'SOURCE_MANIFEST_SHA') == literal(boot, 'CLIENT_MANIFEST_SHA') == digest(private_raw),
         'private_manifest_closure')
    need(literal(factory, 'F_SHA') == literal(boot, 'F37_SHA') == new_rows['mta_client_executor'][2],
         'executor_closure')
    need(literal(owner, 'ROOT') == literal(boot, 'ROOT') ==
         literal(runner, 'STATE_ALIAS') == '/tmp/p011-mta-formal-receive-filecenter-v1', 'alias_closure')
    need(literal(boot, 'PHYSICAL_ROOT') == literal(runner, 'STATE_ROOT') ==
         literal(factory, 'ASSET_PHYSICAL_ROOT') == '/var/volatile/tmp/p011-mta-formal-receive-filecenter-v1',
         'physical_closure')
    payload = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in new_ordinary['sources'])
    payload += helpers
    payload += tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256'])
                     for row in new_private['sources'])
    payload += (wpa, monitor)
    total = 0
    for name, path, size, sha in payload:
        raw = outputs[path] if path in outputs else read_pin((path, size, sha))
        need((len(raw), digest(raw)) == (size, sha), 'actual_payload_source')
        total += len(raw)
    need(len(payload) == 75 and total <= 4 * 1024 * 1024, 'actual_payload_budget')
    need(literal(outputs[DEFINITIONS], 'PAYLOAD_BYTES') == total, 'definitions_actual_payload_bytes')
    syntax = []
    for path, raw in outputs.items():
        if path.endswith('.py'):
            ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
            syntax.append(path)
    need(len(syntax) == 8 and len(outputs) == 10, 'source_output_count')
    for path in outputs:
        need(not (BASE / path).exists(), 'fresh_source_set:' + path)
    for path, raw in outputs.items():
        fresh_write(path, raw)
    report = dict(kind='receive_filecenter_v1_source_generation', source_only=True,
        graph_executed=False, old_tests_executed=False, device_access=False,
        ordinary_count=35, private_count=35, private_service_owner_added=False,
        actual_payload_count=len(payload), actual_payload_bytes=total, payload_cap=4194304,
        payload_headroom=4194304-total, filecenter_source_count=9,
        filecenter_source_bytes=113690, filecenter_cap=131072,
        filecenter_in_protocol_payload=False, source_syntax=syntax,
        outputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in outputs.items()],
        inputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in sorted(inputs.items())])
    area = 'results/receive-filecenter-v1-source-generate-' + uuid.uuid4().hex[:12]
    report_raw = json_raw(report)
    fresh_write(area + '/result.json', report_raw)
    with zipfile.ZipFile(BASE / area / 'SOURCE_RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('result.json', report_raw)
        for path, raw in outputs.items():
            archive.writestr(path, raw)
        archive.write(__file__, 'host/generate_formal_receive_filecenter_v1.py')
    print(json.dumps(dict(result=area+'/result.json', zip=area+'/SOURCE_RESULTS.zip',
                         actual_payload_bytes=total, headroom=4194304-total,
                         source_files=7, definitions=pin(DEFINITIONS, outputs[DEFINITIONS]),
                         outputs=report['outputs']), ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
