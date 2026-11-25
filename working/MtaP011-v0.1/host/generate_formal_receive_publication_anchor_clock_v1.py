"""Fixed PC-only Publication anchor-clock graph and definitions generator.

Default SOURCE validates pinned bytes in memory without writing. Explicit
--write creates fresh seven-runtime/two-manifest/definitions outputs and a
SOURCE_RESULTS.zip. Original definitions supply pure verify_inputs only; no
checker/runner/test/Owner/main/device is executed. A pinned external affected
HOST result is provenance, not full Publication/Owner/native IO acceptance.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import types
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
GENERATOR_ORIGIN = ('host/generate_formal_receive_filecenter_v1.py', 24053,
                    '99e078f9e47a2034566ddd4cf6aaf1fd5f08991f6a3a027acbbc506984968de6')
GENERATOR_PARENT = ('host/generate_formal_receive_startup_anchor_clock_v1.py', 25473,
                    '89d656908cd1d955e515d804c3a509b16d4e535354f21e6dd3790e1dc192dc45')
ORIGINAL = ('host/formal_receive_startup_anchor_clock_v1_definitions.py', 14863,
            'e437decd608149a3489340f4e0761bdf0772233862092b57198e0ae5cf488cea')
PAYLOAD_SOURCE = ('host/device_formal_receive_v3_check.py', 46256,
                  '212619ac677d8887c9ede6b968c2f0f8ba084448cfcd6cbf36c359359cbdb8e0')
# Single-block delta starts from the current packaged 91901-byte Factory.
FACTORY_DELTA = ('candidate/receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py', 94385,
                 '2933d86ab3ce25b20b4efc0eea7733770b2209cc5c5ac062c52793bfceb6da79')
DELTA_SPEC = ('candidate/receive-publication-anchor-clock-v1/exactsource-delta.json', 9829,
              'f65512055f7c232d01d920e33508579b889762a0b614a0100ba372fbe230feec')
HOST_TEST_PIN = ('tests/test_receive_publication_anchor_clock_v1.py', 22471,
                 'fb776d793f4a0d4a146cdfd7804c33dfda06bc4e7553ad1c31c816631183f5c1')
HOST_CHECK_PIN = ('host/receive_publication_anchor_clock_v1_host_check.py', 6601,
                  '7cb319ef6e0354db3be131d0bf697dc3a0d81f6556a9ee098e6536810d69041f')
HOST_RESULT_PIN = ('results/receive-publication-anchor-clock-v1-host-20261005-113156-69a7f166/result.json',
                   2721, '571b3683692eb49ba03ed0fc869a96e4b199c501441c0dc7ab9344555b3ca91c')
HOST_ZIP_PIN = ('results/receive-publication-anchor-clock-v1-host-20261005-113156-69a7f166/public-result.zip',
                1729, '1e09b922cff8165ef149f481d255f864b0d3594e3f4e7fabd5c5e94cb24d3805')
PREFIX = 'candidate/formal-receive-publication-anchor-clock-v1/runtime/'
DEFINITIONS = 'host/formal_receive_publication_anchor_clock_v1_definitions.py'
MANIFEST = 'host/formal_receive_publication_anchor_clock_v1_definition_manifest.json'
PRIVATE_MANIFEST = 'host/formal_receive_publication_anchor_clock_v1_private_source_manifest.json'
ROOT_BEFORE = b'p011-mta-receive-startup-anchor-clock-v1'
ROOT_AFTER = b'p011-mta-receive-publication-anchor-clock-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory',
           'minhttp', 'mta_client_receive_boot', 'mta_client_service_owner')
inputs = {}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(pin):
    need(type(pin) is tuple and len(pin) == 3 and type(pin[1]) is int and
         pin[1] > 0 and type(pin[2]) is str and len(pin[2]) == 64 and
         all(char in '0123456789abcdef' for char in pin[2]) and
         pin[2] != '0' * 64, 'frozen_pin_required')
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
    need(raw.count(before) == count, 'replacement_count')
    return raw.replace(before, after)


def roots(raw, count):
    return replace(raw, ROOT_BEFORE, ROOT_AFTER, count)


def named_pin(raw, name, before, after, count=1):
    return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                   repr((name, after[1], after[2])).encode('ascii'), count)


def function_text(raw, name):
    text = raw.decode('utf-8')
    rows = [row for row in ast.parse(text).body
            if isinstance(row, ast.FunctionDef) and row.name == name]
    need(len(rows) == 1, 'function:' + name)
    return ast.get_source_segment(text, rows[0])


def json_raw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def pin(path, raw):
    return path, len(raw), digest(raw)


def fresh_write(path, raw):
    target = BASE / path
    need(not target.exists(), 'fresh_output:' + path)
    need(target.parent.resolve().is_relative_to(BASE.resolve()), 'workspace_output')
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_write')
    need(target.read_bytes() == raw, 'source_readback')


def business_factory(before, after, spec_raw, before_pin):
    need(len(spec_raw) <= 65536, 'delta_spec_budget')
    spec = json.loads(spec_raw.decode('ascii'))
    need(type(spec) is dict and set(spec) == {'schema', 'evidence', 'source', 'candidate', 'replacements'} and
         spec['schema'] == 'p011-publication-anchor-clock-source-delta-v1' and
         spec['evidence'] == 'READBACK_BYTE_INVERSE_ONLY' and
         spec['source'] == list(before_pin) and spec['candidate'] == list(FACTORY_DELTA), 'delta_spec_shape')
    rows = spec['replacements']
    need(type(rows) is list and len(rows) == 1, 'delta_spec_rows')
    forward = before
    for row in rows:
        need(type(row) is dict and set(row) == {'name', 'before', 'after', 'count'} and
             type(row['name']) is str and 0 < len(row['name']) <= 64 and
             type(row['before']) is str and type(row['after']) is str and
             row['before'] != row['after'] and len(row['before']) > 0 and len(row['after']) > 0 and
             type(row['count']) is int and row['count'] == 1, 'delta_spec_row')
        forward = replace(forward, row['before'].encode('utf-8'), row['after'].encode('utf-8'), row['count'])
    need(forward == after, 'business_delta_forward')
    inverse = after
    for row in reversed(rows):
        inverse = replace(inverse, row['after'].encode('utf-8'), row['before'].encode('utf-8'), row['count'])
    need(inverse == before, 'business_delta_inverse')
    return after


VERIFY = r'''def verify_inputs(inputs):
    """Retain the actual current Startup closure, then one Publication block."""
    if _old.verify_inputs(inputs) != 7:
        raise ValueError('publication_anchor_parent_graph')
    for path, size, sha in ORIGIN_SOURCE_PINS:
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha):
            raise ValueError('publication_anchor_origin_pin')
    rows = {name: (path, size, sha) for name, path, size, sha in manifest_rows(inputs[MANIFEST[0]])}
    old_rows = {name: (path, size, sha) for name, path, size, sha in _old_rows}
    private = {name: (path, size, sha) for name, path, size, sha in
               manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)}
    if (private['runtime35/mta_client_executor'] != rows['mta_client_executor'] or
            rows['mta_client_executor'] != EXECUTOR_PIN or 'runtime35/mta_client_service_owner' in private or
            inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW or
            inputs[OLD_PRIVATE_MANIFEST[0]] != OLD_PRIVATE_RAW):
        raise ValueError('publication_anchor_original_domains')
    def replace(raw, before, after, count=1):
        if raw.count(before) != count: raise ValueError('publication_anchor_replacement_count')
        return raw.replace(before, after)
    def roots(raw, count):
        return replace(raw, b'p011-mta-receive-startup-anchor-clock-v1',
                       b'p011-mta-receive-publication-anchor-clock-v1', count)
    def pin_copy(raw, name, count=1):
        before, after = old_rows[name], rows[name]
        return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                       repr((name, after[1], after[2])).encode('ascii'), count)
    spec_raw = inputs[DELTA_SPEC[0]]
    if len(spec_raw) > 65536: raise ValueError('publication_anchor_delta_budget')
    spec = json.loads(spec_raw.decode('ascii'))
    baseline = old_rows['mta_client_receive_factory']
    if (type(spec) is not dict or set(spec) != {'schema', 'evidence', 'source', 'candidate', 'replacements'} or
            spec['schema'] != 'p011-publication-anchor-clock-source-delta-v1' or
            spec['evidence'] != 'READBACK_BYTE_INVERSE_ONLY' or
            spec['source'] != list(baseline) or spec['candidate'] != list(FACTORY_DELTA) or
            type(spec['replacements']) is not list or len(spec['replacements']) != 1):
        raise ValueError('publication_anchor_delta_spec')
    business = inputs[baseline[0]]
    for row in spec['replacements']:
        if (type(row) is not dict or set(row) != {'name', 'before', 'after', 'count'} or
                type(row['name']) is not str or not 0 < len(row['name']) <= 64 or
                type(row['before']) is not str or type(row['after']) is not str or
                not row['before'] or not row['after'] or row['before'] == row['after'] or
                type(row['count']) is not int or row['count'] != 1):
            raise ValueError('publication_anchor_delta_row')
        business = replace(business, row['before'].encode('utf-8'), row['after'].encode('utf-8'), row['count'])
    if business != inputs[FACTORY_DELTA[0]]: raise ValueError('publication_anchor_delta_forward')
    inverse = business
    for row in reversed(spec['replacements']):
        inverse = replace(inverse, row['after'].encode('utf-8'), row['before'].encode('utf-8'), row['count'])
    if inverse != inputs[baseline[0]]: raise ValueError('publication_anchor_delta_inverse')
    f_before, f_after = old_rows['mta_client_executor'], rows['mta_client_executor']
    old_f, new_f = f_before[2].encode('ascii'), f_after[2].encode('ascii')
    old_private, new_private = OLD_PRIVATE_MANIFEST[2].encode('ascii'), PRIVATE_MANIFEST[2].encode('ascii')
    expected = {}
    expected['mta_client_executor'] = roots(inputs[f_before[0]], 1)
    expected['mta_client_state_bridge'] = replace(inputs[old_rows['mta_client_state_bridge'][0]], old_f, new_f)
    factory = replace(replace(roots(business, 2), old_private, new_private), old_f, new_f)
    expected['mta_client_receive_factory'] = replace(factory,
        ("('mta_client_executor', " + str(f_before[1]) + ", F_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F_SHA)").encode('ascii'))
    expected['minhttp'] = inputs[old_rows['minhttp'][0]]
    boot = replace(replace(roots(inputs[old_rows['mta_client_receive_boot'][0]], 2), old_private, new_private), old_f, new_f)
    boot = replace(boot,
        ("('mta_client_executor', " + str(f_before[1]) + ", F37_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F37_SHA)").encode('ascii'), 2)
    for name in ('mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp'):
        boot = pin_copy(boot, name)
    expected['mta_client_receive_boot'] = boot
    owner = replace(roots(inputs[old_rows['mta_client_service_owner'][0]], 2),
        ('BOOT_PIN = ' + repr(old_rows['mta_client_receive_boot'][1:])).encode('ascii'),
        ('BOOT_PIN = ' + repr(rows['mta_client_receive_boot'][1:])).encode('ascii'))
    expected['mta_client_service_owner'] = owner
    runner = roots(inputs[_old.RUNNER[0]], 2)
    for name in CHANGED: runner = pin_copy(runner, name, 2 if name == 'mta_client_executor' else 1)
    expected[RUNNER[0]] = runner
    for name, raw in expected.items():
        path = RUNNER[0] if name == RUNNER[0] else rows[name][0]
        if inputs[path] != raw: raise ValueError('publication_anchor_nonmechanical_change')
        ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
    return len(expected)
'''


def main():
    need(sys.argv[1:] in ([], ['--write']), 'source_or_explicit_write_only')
    write = sys.argv[1:] == ['--write']
    need(FACTORY_DELTA[1] > 0 and len(FACTORY_DELTA[2]) == 64 and
         FACTORY_DELTA[2] != '0' * 64 and DELTA_SPEC[1] > 0 and
         len(DELTA_SPEC[2]) == 64 and DELTA_SPEC[2] != '0' * 64,
         'publication_clock_inputs_unsealed')
    # Refuse unsealed or mismatched inputs before creating any output.
    read_pin(FACTORY_DELTA)
    read_pin(DELTA_SPEC)
    host_result = json.loads(read_pin(HOST_RESULT_PIN).decode('ascii'))
    for host_pin in (HOST_TEST_PIN, HOST_CHECK_PIN, HOST_ZIP_PIN): read_pin(host_pin)
    need(type(host_result) is dict and host_result.get('passed') is True and
         host_result.get('host_exit') == host_result.get('test_exit') == 0 and
         host_result.get('methods_requested') == 1 and host_result.get('timed_out') is False and
         host_result.get('source_unchanged') is True and
         all(host_result.get(key) is False for key in ('complete_owner_verified',
             'complete_publication_verified', 'native_fd_content_IO_verified',
             'device', 'phone', 'rf', 'performance_measured')),
         'external_affected_host_evidence')
    for host_pin in (HOST_TEST_PIN, HOST_CHECK_PIN, FACTORY_DELTA, DELTA_SPEC):
        need(dict(path=host_pin[0], bytes=host_pin[1], sha256=host_pin[2]) in
             host_result['sources'], 'external_affected_host_sources')
    origin_generator = read_pin(GENERATOR_ORIGIN)
    read_pin(GENERATOR_PARENT)  # retain this frozen helper; never execute it.
    original_raw = read_pin(ORIGINAL)
    current = types.ModuleType('fixed_current_publication_baseline_definitions')
    current.__file__ = str(BASE / ORIGINAL[0])
    exec(compile(original_raw, current.__file__, 'exec'), current.__dict__)
    # Only frozen definition constants and pure verify_inputs are used.
    for source_pin in current.ORIGIN_SOURCE_PINS: read_pin(source_pin)
    ordinary_pin = literal(original_raw, 'MANIFEST')
    private_pin = literal(original_raw, 'PRIVATE_MANIFEST')
    runner_before = literal(original_raw, 'RUNNER')
    ordinary = json.loads(read_pin(ordinary_pin).decode('ascii'))
    private = json.loads(read_pin(private_pin).decode('ascii'))
    need(current.RUNNER == runner_before and current.MANIFEST == ordinary_pin and
         current.PRIVATE_MANIFEST == private_pin and current.PAYLOAD_BYTES == 4166862,
         'actual_current_graph_binding')
    need(len(ordinary['sources']) == len(private['sources']) == 35, 'role_count')
    need(all(row['module'] != 'mta_client_service_owner' for row in private['sources']), 'private_no_owner')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    before = {name: read_pin(old_rows[name]) for name in CHANGED}
    old_runner = read_pin(runner_before)
    business = business_factory(before['mta_client_receive_factory'], read_pin(FACTORY_DELTA),
                                read_pin(DELTA_SPEC), old_rows['mta_client_receive_factory'])
    payload_source = read_pin(PAYLOAD_SOURCE)
    helpers = literal(payload_source, 'HELPERS')
    wpa, monitor = literal(payload_source, 'WPA'), literal(payload_source, 'MONITOR')
    fc_rows = literal(original_raw, 'FILECENTER_SOURCES')
    need(len(fc_rows) == 9 and sum(row[2] for row in fc_rows) == 113690 < 131072, 'filecenter_budget')
    for name, path, size, sha in fc_rows: read_pin((path, size, sha))
    outputs, new_rows = {}, dict(old_rows)
    def put(name, raw):
        path = PREFIX + name + '.py'; outputs[path] = raw
        return pin(path, raw)
    new_rows['mta_client_executor'] = put('mta_client_executor', roots(before['mta_client_executor'], 1))
    new_private = copy.deepcopy(private)
    new_private['previous_manifest_sha256'] = private_pin[2]
    for row in new_private['sources']:
        if row['module'] == 'mta_client_executor':
            after = new_rows[row['module']]
            row.update(path=after[0], bytes=after[1], sha256=after[2])
    private_raw = json_raw(new_private); outputs[PRIVATE_MANIFEST] = private_raw
    old_f, new_f = old_rows['mta_client_executor'][2].encode('ascii'), new_rows['mta_client_executor'][2].encode('ascii')
    private_before, private_after = private_pin[2].encode('ascii'), digest(private_raw).encode('ascii')
    new_rows['mta_client_state_bridge'] = put('mta_client_state_bridge', replace(before['mta_client_state_bridge'], old_f, new_f))
    factory = replace(replace(roots(business, 2), private_before, private_after), old_f, new_f)
    factory = replace(factory, ("('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F_SHA)").encode('ascii'),
                      ("('mta_client_executor', " + str(new_rows['mta_client_executor'][1]) + ", F_SHA)").encode('ascii'))
    new_rows['mta_client_receive_factory'] = put('mta_client_receive_factory', factory)
    new_rows['minhttp'] = put('minhttp', before['minhttp'])
    boot = replace(replace(roots(before['mta_client_receive_boot'], 2), private_before, private_after), old_f, new_f)
    boot = replace(boot, ("('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F37_SHA)").encode('ascii'),
                   ("('mta_client_executor', " + str(new_rows['mta_client_executor'][1]) + ", F37_SHA)").encode('ascii'), 2)
    for name in ('mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp'):
        boot = named_pin(boot, name, old_rows[name], new_rows[name])
    new_rows['mta_client_receive_boot'] = put('mta_client_receive_boot', boot)
    owner = replace(roots(before['mta_client_service_owner'], 2),
                    ('BOOT_PIN = ' + repr(old_rows['mta_client_receive_boot'][1:])).encode('ascii'),
                    ('BOOT_PIN = ' + repr(new_rows['mta_client_receive_boot'][1:])).encode('ascii'))
    new_rows['mta_client_service_owner'] = put('mta_client_service_owner', owner)
    runner = roots(old_runner, 2)
    for name in CHANGED:
        runner = named_pin(runner, name, old_rows[name], new_rows[name], 2 if name == 'mta_client_executor' else 1)
    runner_pin = put('mta_formal_receive_session', runner)
    # Reverse every mechanical delta. Only the separately pinned Publication
    # anchors block changes business from the actual packaged current Factory.
    need(replace(outputs[new_rows['mta_client_executor'][0]], ROOT_AFTER, ROOT_BEFORE) == before['mta_client_executor'], 'executor_inverse')
    need(replace(outputs[new_rows['mta_client_state_bridge'][0]], new_f, old_f) == before['mta_client_state_bridge'], 'bridge_inverse')
    factory_inverse = replace(factory,
        ("('mta_client_executor', " + str(new_rows['mta_client_executor'][1]) + ", F_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F_SHA)").encode('ascii'))
    factory_inverse = replace(replace(replace(factory_inverse, new_f, old_f), private_after, private_before), ROOT_AFTER, ROOT_BEFORE, 2)
    need(factory_inverse == business and outputs[new_rows['minhttp'][0]] == before['minhttp'], 'factory_minhttp_inverse')
    boot_inverse = boot
    for name in reversed(('mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp')):
        boot_inverse = named_pin(boot_inverse, name, new_rows[name], old_rows[name])
    boot_inverse = replace(boot_inverse,
        ("('mta_client_executor', " + str(new_rows['mta_client_executor'][1]) + ", F37_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(old_rows['mta_client_executor'][1]) + ", F37_SHA)").encode('ascii'), 2)
    boot_inverse = replace(replace(replace(boot_inverse, new_f, old_f), private_after, private_before), ROOT_AFTER, ROOT_BEFORE, 2)
    need(boot_inverse == before['mta_client_receive_boot'], 'boot_inverse')
    owner_inverse = replace(owner, ('BOOT_PIN = ' + repr(new_rows['mta_client_receive_boot'][1:])).encode('ascii'),
                            ('BOOT_PIN = ' + repr(old_rows['mta_client_receive_boot'][1:])).encode('ascii'))
    need(replace(owner_inverse, ROOT_AFTER, ROOT_BEFORE, 2) == before['mta_client_service_owner'], 'owner_inverse')
    runner_inverse = runner
    for name in reversed(CHANGED):
        runner_inverse = named_pin(runner_inverse, name, new_rows[name], old_rows[name], 2 if name == 'mta_client_executor' else 1)
    need(replace(runner_inverse, ROOT_AFTER, ROOT_BEFORE, 2) == old_runner, 'runner_inverse')
    new_ordinary = copy.deepcopy(ordinary)
    for row in new_ordinary['sources']:
        if row['module'] in CHANGED:
            after = new_rows[row['module']]; row.update(path=after[0], bytes=after[1], sha256=after[2])
    ordinary_raw = json_raw(new_ordinary); outputs[MANIFEST] = ordinary_raw
    payload = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in new_ordinary['sources']) + helpers
    payload += tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in new_private['sources']) + (wpa, monitor)
    total = 0
    for name, path, size, sha in payload:
        raw = outputs[path] if path in outputs else read_pin((path, size, sha))
        need((len(raw), digest(raw)) == (size, sha), 'actual_payload_pin'); total += len(raw)
    need(len(payload) == 75 and total <= 4194304, 'actual_payload_budget')
    # The current closure sees its actual old Runner, never the new overlay.
    for row in ordinary['sources'] + private['sources']:
        read_pin((row['path'], row['bytes'], row['sha256']))
    need(inputs[runner_before[0]] == old_runner and current.verify_inputs(inputs) == 7 and
         inputs[runner_before[0]] == old_runner, 'actual_current_graph_inverse')
    need(literal(runner, 'ROLE_PINS') == tuple((row['module'], row['bytes'], row['sha256']) for row in new_ordinary['sources']), 'ordinary_pins')
    need(literal(runner, 'PRIVATE_PINS') == tuple((row['module'], row['bytes'], row['sha256']) for row in new_private['sources']), 'private_pins')
    need(literal(runner, 'HELPER_PINS') == tuple((name, size, sha) for name, path, size, sha in helpers), 'helper_pins')
    need(literal(runner, 'WPA_PIN') == (wpa[0], wpa[2], wpa[3]) and literal(runner, 'MONITOR_PIN') == (monitor[0], monitor[2], monitor[3]), 'asset_pins')
    need(literal(owner, 'FILECENTER_PINS') == tuple((name, size, sha) for name, path, size, sha in fc_rows) and
         literal(owner, 'FILECENTER_MAX_SOURCE') == 131072, 'filecenter_original_pins')
    need(literal(owner, 'BOOT_PIN') == new_rows['mta_client_receive_boot'][1:] and
         literal(factory, 'SOURCE_MANIFEST_SHA') == literal(boot, 'CLIENT_MANIFEST_SHA') == digest(private_raw), 'boot_manifest_closure')
    need(literal(factory, 'F_SHA') == literal(boot, 'F37_SHA') == new_rows['mta_client_executor'][2], 'executor_closure')
    need(literal(owner, 'ROOT') == literal(boot, 'ROOT') == literal(runner, 'STATE_ALIAS') == '/tmp/' + ROOT_AFTER.decode('ascii'), 'alias_closure')
    need(literal(boot, 'PHYSICAL_ROOT') == literal(runner, 'STATE_ROOT') == literal(factory, 'ASSET_PHYSICAL_ROOT') == '/var/volatile/tmp/' + ROOT_AFTER.decode('ascii'), 'physical_closure')
    need(literal(before['mta_client_executor'], 'ROOT') == literal(outputs[new_rows['mta_client_executor'][0]], 'ROOT') and
         literal(before['mta_client_executor'], 'PHYSICAL_ROOT') == literal(outputs[new_rows['mta_client_executor'][0]], 'PHYSICAL_ROOT'), 'client_roots_unchanged')
    template = literal(origin_generator, 'TEMPLATE')
    old_verify = template[template.index('def verify_inputs('):template.index('\n\n\n@MAKE_SOURCE@')]
    template = replace(template.encode('utf-8'), old_verify.encode('utf-8'), b'@VERIFY@')
    # Only the original FC template's two header roots and role path move.
    # Runtime baseline is current Startup-anchor; this pure header template
    # is still FC-v1. Insert VERIFY after header roots/path move so its actual
    # current baseline remains byte-exact.
    template = replace(template, b'p011-mta-formal-receive-filecenter-v1', ROOT_AFTER, 2)
    template = replace(template, b'candidate/formal-receive-filecenter-v1/runtime/', PREFIX.encode('ascii'))
    template = replace(template, b'@VERIFY@', VERIFY.rstrip().encode('utf-8')).decode('utf-8')
    origin_block = "ORIGIN_SOURCE_PINS = tuple((path, size, sha) for name, path, size, sha in _old_rows\n                           if name in CHANGED) + (_old.RUNNER, OLD_PRIVATE_MANIFEST,\n                                                 SOURCE_OWNER, STORAGE_SOURCE, COMPANION_SOURCE)"
    new_origin = "FACTORY_DELTA = @FACTORY_DELTA@\nDELTA_SPEC = @DELTA_SPEC@\nGENERATOR_ORIGIN = @GENERATOR_ORIGIN@\nGENERATOR_PARENT = @GENERATOR_PARENT@\nHOST_TEST_PIN = @HOST_TEST_PIN@\nHOST_CHECK_PIN = @HOST_CHECK_PIN@\nHOST_RESULT_PIN = @HOST_RESULT_PIN@\nHOST_ZIP_PIN = @HOST_ZIP_PIN@\nORIGIN_SOURCE_PINS = tuple(dict.fromkeys(tuple(_old.ORIGIN_SOURCE_PINS) +\n    tuple((path, size, sha) for name, path, size, sha in _old_rows if name in CHANGED) +\n    (ORIGINAL, _old.ORIGINAL, _old.ORIGINAL_MANIFEST, _old.OLD_PRIVATE_MANIFEST,\n     _old.RUNNER, ORIGINAL_MANIFEST, OLD_PRIVATE_MANIFEST,\n     FACTORY_DELTA, DELTA_SPEC, GENERATOR_ORIGIN, GENERATOR_PARENT,\n     HOST_TEST_PIN, HOST_CHECK_PIN, HOST_RESULT_PIN, HOST_ZIP_PIN)))\nSOURCE_PINS = ORIGIN_SOURCE_PINS"
    template = replace(template.encode('utf-8'), origin_block.encode('utf-8'), new_origin.encode('utf-8')).decode('utf-8')
    values = dict(ORIGINAL=repr(ORIGINAL), MANIFEST=repr(pin(MANIFEST, ordinary_raw)), RUNNER=repr(runner_pin),
                  CHANGED=repr(CHANGED), EXECUTOR=repr(new_rows['mta_client_executor']), PRIVATE=repr(pin(PRIVATE_MANIFEST, private_raw)),
                  OWNER=repr(literal(original_raw, 'SOURCE_OWNER')), STORAGE=repr(literal(original_raw, 'STORAGE_SOURCE')),
                  COMPANION=repr(literal(original_raw, 'COMPANION_SOURCE')), FILECENTER=repr(fc_rows), PAYLOAD=str(total),
                  MAKE_SOURCE=function_text(original_raw, 'make_source'), FACTORY_DELTA=repr(FACTORY_DELTA),
                  DELTA_SPEC=repr(DELTA_SPEC), GENERATOR_ORIGIN=repr(GENERATOR_ORIGIN),
                  GENERATOR_PARENT=repr(GENERATOR_PARENT), HOST_TEST_PIN=repr(HOST_TEST_PIN),
                  HOST_CHECK_PIN=repr(HOST_CHECK_PIN), HOST_RESULT_PIN=repr(HOST_RESULT_PIN),
                  HOST_ZIP_PIN=repr(HOST_ZIP_PIN))
    for key, value in values.items():
        token = '@' + key + '@'; need(template.count(token) == 1, 'template_token:' + key); template = template.replace(token, value)
    need('@' not in template, 'unexpanded_template')
    outputs[DEFINITIONS] = template.encode('utf-8')
    need(literal(outputs[DEFINITIONS], 'PAYLOAD_BYTES') == total, 'definitions_actual_payload')
    syntax = []
    for path, raw in outputs.items():
        if path.endswith('.py'):
            ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5)); syntax.append(path)
    need(len(outputs) == 10 and len(syntax) == 8, 'output_count')
    report = dict(kind='receive_publication_anchor_clock_v1_source', source_only=True, generated=write,
                  graph_executed=False, old_tests_executed=False, device_access=False,
                  original_current_graph_verified=True, original_runner_preserved=True,
                  business_delta_blocks=1, business_delta_schema='p011-publication-anchor-clock-source-delta-v1',
                  affected_host_test_executed_by_generator=False, external_affected_host_evidence_passed=True,
                  complete_publication_verified=False, complete_owner_verified=False,
                  native_IO_verified=False, phone_verified=False, performance_measured=False,
                  external_host_result_pin=HOST_RESULT_PIN, external_host_zip_pin=HOST_ZIP_PIN,
                  ordinary_count=35, private_count=35, private_owner_added=False, actual_payload_count=len(payload),
                  actual_payload_bytes=total, payload_cap=4194304, headroom=4194304-total,
                  filecenter_source_count=9, filecenter_source_bytes=113690, filecenter_cap=131072,
                  source_syntax=syntax, outputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in outputs.items()],
                  inputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in sorted(inputs.items())])
    if write:
        for path in outputs: need(not (BASE / path).exists(), 'fresh_source_set:' + path)
        for path, raw in outputs.items(): fresh_write(path, raw)
        area = 'results/receive-publication-anchor-clock-v1-source-' + uuid.uuid4().hex[:24]
        fresh_write(area + '/result.json', json_raw(report))
        for path, raw in inputs.items(): fresh_write(area + '/private-inputs/' + path, raw)
        with zipfile.ZipFile(BASE / area / 'SOURCE_RESULTS.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('result.json', json_raw(report))
            for path, raw in outputs.items(): archive.writestr(path, raw)
            archive.write(__file__, 'host/generate_formal_receive_publication_anchor_clock_v1.py')
        report.update(result=area + '/result.json', zip=area + '/SOURCE_RESULTS.zip')
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()

