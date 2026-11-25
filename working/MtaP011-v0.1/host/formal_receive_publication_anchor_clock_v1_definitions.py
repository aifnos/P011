"""Mechanical Receiver/FileCenter v1 graph; original 75 roles and fixed budgets.

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
ORIGINAL = ('host/formal_receive_startup_anchor_clock_v1_definitions.py', 14863, 'e437decd608149a3489340f4e0761bdf0772233862092b57198e0ae5cf488cea')
MANIFEST = ('host/formal_receive_publication_anchor_clock_v1_definition_manifest.json', 7980, 'de379cac69169f15d214dcc038bbc7473409ac5e49f8a6b509aed7333b4c8485')
RUNNER = ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_formal_receive_session.py', 79246, '71b42ad391844cc67b86c019f80d96ade720dbe4be73270f12ce6210bf5ba5a6')
STATE_ALIAS = '/tmp/p011-mta-receive-publication-anchor-clock-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-publication-anchor-clock-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp', 'mta_client_receive_boot', 'mta_client_service_owner')
EXECUTOR_PIN = ('candidate/formal-receive-publication-anchor-clock-v1/runtime/mta_client_executor.py', 117761, '34eddfee126c771776808e64a746f2186f61065cfce9a0c2e59e23e85d67ae23')
PRIVATE_MANIFEST = ('host/formal_receive_publication_anchor_clock_v1_private_source_manifest.json', 8157, '5cf980445a86633655c6316b5822052eb337e835584096a6dcff5dac52404695')
SOURCE_OWNER = ('candidate/formal-receive-filecenter-owner-v1/runtime/mta_client_service_owner.py', 107037, '6eb891d71b5e935c6bbfdaf4a19621889cdf7c7ee5c56fcd4bcc08f89473f5a2')
STORAGE_SOURCE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4')
COMPANION_SOURCE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py', 33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284')
FILECENTER_SOURCES = (('mta_toolbox_json', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'), ('mta_toolbox_minhttp', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py', 9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'), ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'), ('mta_toolbox_metrics', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py', 4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'), ('mta_toolbox_audio', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'), ('mta_toolbox_server', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py', 19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'), ('mta_filecenter_audio', 'candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082, '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'), ('mta_filecenter_storage', 'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4'), ('mta_filecenter_companion', 'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py', 33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284'))
FILECENTER_SOURCE_PINS = FILECENTER_SOURCES
PAYLOAD_BYTES = 4169378


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
FACTORY_DELTA = ('candidate/receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py', 94385, '2933d86ab3ce25b20b4efc0eea7733770b2209cc5c5ac062c52793bfceb6da79')
DELTA_SPEC = ('candidate/receive-publication-anchor-clock-v1/exactsource-delta.json', 9829, 'f65512055f7c232d01d920e33508579b889762a0b614a0100ba372fbe230feec')
GENERATOR_ORIGIN = ('host/generate_formal_receive_filecenter_v1.py', 24053, '99e078f9e47a2034566ddd4cf6aaf1fd5f08991f6a3a027acbbc506984968de6')
GENERATOR_PARENT = ('host/generate_formal_receive_startup_anchor_clock_v1.py', 25473, '89d656908cd1d955e515d804c3a509b16d4e535354f21e6dd3790e1dc192dc45')
HOST_TEST_PIN = ('tests/test_receive_publication_anchor_clock_v1.py', 22471, 'fb776d793f4a0d4a146cdfd7804c33dfda06bc4e7553ad1c31c816631183f5c1')
HOST_CHECK_PIN = ('host/receive_publication_anchor_clock_v1_host_check.py', 6601, '7cb319ef6e0354db3be131d0bf697dc3a0d81f6556a9ee098e6536810d69041f')
HOST_RESULT_PIN = ('results/receive-publication-anchor-clock-v1-host-20261005-113156-69a7f166/result.json', 2721, '571b3683692eb49ba03ed0fc869a96e4b199c501441c0dc7ab9344555b3ca91c')
HOST_ZIP_PIN = ('results/receive-publication-anchor-clock-v1-host-20261005-113156-69a7f166/public-result.zip', 1729, '1e09b922cff8165ef149f481d255f864b0d3594e3f4e7fabd5c5e94cb24d3805')
ORIGIN_SOURCE_PINS = tuple(dict.fromkeys(tuple(_old.ORIGIN_SOURCE_PINS) +
    tuple((path, size, sha) for name, path, size, sha in _old_rows if name in CHANGED) +
    (ORIGINAL, _old.ORIGINAL, _old.ORIGINAL_MANIFEST, _old.OLD_PRIVATE_MANIFEST,
     _old.RUNNER, ORIGINAL_MANIFEST, OLD_PRIVATE_MANIFEST,
     FACTORY_DELTA, DELTA_SPEC, GENERATOR_ORIGIN, GENERATOR_PARENT,
     HOST_TEST_PIN, HOST_CHECK_PIN, HOST_RESULT_PIN, HOST_ZIP_PIN)))
SOURCE_PINS = ORIGIN_SOURCE_PINS


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
              row['path'] != 'candidate/formal-receive-publication-anchor-clock-v1/runtime/' + name + '.py' or
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


def make_source(checker, inputs, payload, use_ui):
    if use_ui is not False:
        raise ValueError('compat_headless_only')
    modules = tuple(sorted(set(MODULE_NAMES + PRIVATE_MODULE_NAMES + (
        'fixed_formal_ui_session', 'fixed_formal_ui_runner', 'fixed_formal_ui_assets',
        'fixed_formal_receive_monitor', 'fixed_startup_readonly_diagnostic',
        'startup_readonly_private_owner', 'threading', 'socket', 'subprocess', 'types'))))
    lines = ['USE_UI=False', 'ERROR_MODULES=(']
    lines.extend('    ' + repr(name) + ',' for name in modules)
    lines.extend((')', 'RESULT_REASONS=('))
    lines.extend('    ' + repr(name) + ',' for name in
                 tuple(dict.fromkeys(tuple(checker.REASONS) + TRIAL_REASONS)))
    lines.append(')')
    lines.extend(('RUNNER_PIN=' + repr(RUNNER[1:]), 'RUNNER_ENCODED=(',
                  _short_chunks(checker, inputs[RUNNER[0]]), ')', 'ARTIFACT_ROWS=('))
    for name, path, size, sha in payload:
        lines.extend(('    (' + repr(name) + ',' + str(size) + ',' + repr(sha) + ',(',
                      _short_chunks(checker, inputs[path]), '    )),'))
    lines.append(')')
    raw = ('\n'.join(lines) + '\n' + TARGET_COMMON + TARGET_SERVICE).encode('ascii')
    if len(raw) > 2097152 or any(len(line) > 256 for line in raw.splitlines()):
        raise ValueError('target_source_budget')
    return raw
