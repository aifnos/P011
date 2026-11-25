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
ORIGINAL = ('host/formal_receive_publication_anchor_clock_v1_definitions.py', 15660, '8a7ab2f16aca4b9af2660c2eb9331e9883e7f7f165e14deaf16db1195a9b68b4')
MANIFEST = ('host/formal_receive_profile_classification_clock_v1_definition_manifest.json', 8004, 'e67fb9d0d0643c0c7f7796639aa38af455d00a1e5d62f393a11d94192df427d4')
RUNNER = ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_formal_receive_session.py', 79254, '3fe23e4e9d9e1c9900985ee04153ce4b479ca1f2bc194458b91a702cd4f8258f')
STATE_ALIAS = '/tmp/p011-mta-receive-profile-classification-clock-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-receive-profile-classification-clock-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp', 'mta_client_receive_boot', 'mta_client_service_owner')
EXECUTOR_PIN = ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_client_executor.py', 117765, 'd7f67463aa6587bb512bfae188e1cb1fffd2eb3763de93081912b99c473906cf')
PRIVATE_MANIFEST = ('host/formal_receive_profile_classification_clock_v1_private_source_manifest.json', 8161, '36c7ae14fa432ed9590951c67a26f570cf77fa508ca6d31520c4cf11412aa05f')
SOURCE_OWNER = ('candidate/formal-receive-filecenter-owner-v1/runtime/mta_client_service_owner.py', 107037, '6eb891d71b5e935c6bbfdaf4a19621889cdf7c7ee5c56fcd4bcc08f89473f5a2')
STORAGE_SOURCE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4')
COMPANION_SOURCE = ('candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py', 33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284')
FILECENTER_SOURCES = (('mta_toolbox_json', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_json.py', 3069, 'e32cf4433b966714a16e725e405052fa905715ce108b80199f8d50904abe5c7c'), ('mta_toolbox_minhttp', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_minhttp.py', 9303, '6f8ec322fe8bb9522b9cc5ab1b52d844c17d366eaf7e176634b5760089bc3f93'), ('mta_toolbox_storage', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_storage.py', 9114, 'd9fa92a795729d88f6fac27705a2883adba8aac72423b4ebcd9220ffb78ddb51'), ('mta_toolbox_metrics', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_metrics.py', 4080, 'e56808ec3bc7c751e5dff43a053294595bb719cad658a44eb378932142b7a679'), ('mta_toolbox_audio', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_audio.py', 9045, 'c4ea432c8c6e972a28134f352fa75ff773827fd4a41e205865c9309f96a63432'), ('mta_toolbox_server', 'integration/ToolboxMta-v0.1/runtime/mta_toolbox_server.py', 19732, 'fab0c1afa6fc85a30de711b4f4d94467e03911e836ce292b73e8796ead8a9bc6'), ('mta_filecenter_audio', 'candidate/filecenter-deadline-v2/runtime/mta_filecenter_audio.py', 15082, '898e5373f6ec4789eaf756ffd01731646bcafb7b0f35019731403a2e881147af'), ('mta_filecenter_storage', 'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_storage.py', 10757, 'ca4368153d5af2f9a076feb85f82df321e867db3f6a523d9d82f32b371e484f4'), ('mta_filecenter_companion', 'candidate/filecenter-close-seal-v1/runtime/mta_filecenter_companion.py', 33508, 'e38fa8dc20e6730ab68c580d92866a7a71ceb420a00c3ac38e04d94b0316b284'))
FILECENTER_SOURCE_PINS = FILECENTER_SOURCES
PAYLOAD_BYTES = 4172818


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
FACTORY_DELTA = ('candidate/receive-profile-classification-clock-v1/runtime/mta_client_receive_factory.py', 97801, '8cf46d17fda24cc2199e8900a0dfdd9d980b2247808c87801c00426db6158c37')
DELTA_SPEC = ('candidate/receive-profile-classification-clock-v1/exactsource-delta.json', 4360, '676ff4a410e882dc75c7750d7b5e02d110919ca41b5e14895141b1c3d1a6d7ae')
GENERATOR_ORIGIN = ('host/generate_formal_receive_filecenter_v1.py', 24053, '99e078f9e47a2034566ddd4cf6aaf1fd5f08991f6a3a027acbbc506984968de6')
GENERATOR_PARENT = ('host/generate_formal_receive_publication_anchor_clock_v1.py', 29631, 'b7f6ef9019eeb683a191e186615f1d76a7b49f4a8783109011ace32e8e972561')
HOST_TEST_PIN = ('tests/test_receive_profile_classification_clock_v1.py', 27430, 'af393f6151ce073fe56e0f68d7240cd705720518933db59b13a6c5687af98a3e')
HOST_CHECK_PIN = ('host/receive_profile_classification_clock_v1_host_check.py', 7214, '1a3cb420f6157b06515a86fafd099dd3d21de7599ace5b49d6f9202df7c5a7e5')
HOST_RESULT_PIN = ('results/receive-profile-classification-clock-v1-host-20261005-121124-ea0c7987/result.json', 3148, 'a19b588b0d20f6d783db825e915cc043fac897234d9e914bfd1662d6b562422f')
HOST_ZIP_PIN = ('results/receive-profile-classification-clock-v1-host-20261005-121124-ea0c7987/public-result.zip', 1932, '1002c0049fe118d5bfe39099e297d13f774c09f9a8d3b76789f6c3cdd306a6f2')
SOURCE_GENERATOR = ('host/generate_formal_receive_profile_classification_clock_v1.py', 35004, '9c8270ca7b4ecab4fb8d30099a257aedde24a039d87fdc71ed98ca5010643478')
PAYLOAD_SOURCE = ('host/device_formal_receive_v3_check.py', 46256, '212619ac677d8887c9ede6b968c2f0f8ba084448cfcd6cbf36c359359cbdb8e0')
ORIGIN_SOURCE_PINS = tuple(dict.fromkeys(tuple(_old.ORIGIN_SOURCE_PINS) +
    tuple((path, size, sha) for name, path, size, sha in _old_rows if name in CHANGED) +
    (ORIGINAL, _old.RUNNER, ORIGINAL_MANIFEST, OLD_PRIVATE_MANIFEST,
     FACTORY_DELTA, DELTA_SPEC, GENERATOR_PARENT, PAYLOAD_SOURCE, SOURCE_GENERATOR,
     ('HOST_MTA_RECEIVE_PROFILE_CLASSIFICATION_CLOCK_V1_CHECK.cmd', 267, 'a4e9923e1dbc119c0915005a10fde0061194e9581e99e7d6404440c6e62c23ed'),
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
              row['path'] != 'candidate/formal-receive-profile-classification-clock-v1/runtime/' + name + '.py' or
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
    """Keep the actual parent Publication closure, then one classification block."""
    if len(_old.ORIGIN_SOURCE_PINS) != 69 or _old.verify_inputs(inputs) != 7:
        raise ValueError('classification_parent_graph')
    for path, size, sha in ORIGIN_SOURCE_PINS:
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha):
            raise ValueError('classification_origin_pin')
    rows = {name: (path, size, sha) for name, path, size, sha in manifest_rows(inputs[MANIFEST[0]])}
    old_rows = {name: (path, size, sha) for name, path, size, sha in _old_rows}
    private = {name: (path, size, sha) for name, path, size, sha in
               manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)}
    if (len(rows) != 35 or len(private) != 35 or
            private['runtime35/mta_client_executor'] != rows['mta_client_executor'] or
            rows['mta_client_executor'] != EXECUTOR_PIN or 'runtime35/mta_client_service_owner' in private or
            inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW or
            inputs[OLD_PRIVATE_MANIFEST[0]] != OLD_PRIVATE_RAW):
        raise ValueError('classification_original_domains')
    def replace(raw, before, after, count=1):
        if raw.count(before) != count: raise ValueError('classification_replacement_count')
        return raw.replace(before, after)
    def roots(raw, count):
        return replace(raw, b'p011-mta-receive-publication-anchor-clock-v1',
                       b'p011-mta-receive-profile-classification-clock-v1', count)
    def pin_copy(raw, name, count=1):
        before, after = old_rows[name], rows[name]
        return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                       repr((name, after[1], after[2])).encode('ascii'), count)
    spec_raw = inputs[DELTA_SPEC[0]]
    if len(spec_raw) > 65536: raise ValueError('classification_delta_budget')
    spec = json.loads(spec_raw.decode('ascii'))
    baseline = old_rows['mta_client_receive_factory']
    if (type(spec) is not dict or set(spec) != {'schema', 'evidence', 'source', 'candidate', 'replacements'} or
            spec['schema'] != 'p011-profile-classification-clock-source-delta-v1' or
            spec['evidence'] != 'READBACK_BYTE_INVERSE_ONLY' or
            spec['source'] != list(baseline) or spec['candidate'] != list(FACTORY_DELTA) or
            type(spec['replacements']) is not list or len(spec['replacements']) != 1):
        raise ValueError('classification_delta_spec')
    row = spec['replacements'][0]
    if (type(row) is not dict or set(row) != {'name', 'before', 'after', 'count'} or
            row['name'] != 'live_profile_classification_metadata_clock' or
            type(row['before']) is not str or type(row['after']) is not str or
            not row['before'] or not row['after'] or row['before'] == row['after'] or
            type(row['count']) is not int or row['count'] != 1):
        raise ValueError('classification_delta_row')
    business = replace(inputs[baseline[0]], row['before'].encode('utf-8'), row['after'].encode('utf-8'))
    if business != inputs[FACTORY_DELTA[0]]: raise ValueError('classification_delta_forward')
    if replace(business, row['after'].encode('utf-8'), row['before'].encode('utf-8')) != inputs[baseline[0]]:
        raise ValueError('classification_delta_inverse')
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
        if inputs[path] != raw: raise ValueError('classification_nonmechanical_change')
        ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
    payload = tuple((name, path, size, sha) for name, (path, size, sha) in rows.items()) + HELPERS
    payload += tuple((name, path, size, sha) for name, (path, size, sha) in private.items()) + (WPA, MONITOR)
    total = 0
    for name, path, size, sha in payload:
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha): raise ValueError('classification_payload_pin')
        total += len(raw)
    if (len(payload) != 75 or total != PAYLOAD_BYTES or total > 4194304 or
            len(FILECENTER_SOURCES) != 9 or sum(row[2] for row in FILECENTER_SOURCES) != 113690 or
            sum(row[2] for row in FILECENTER_SOURCES) > 131072):
        raise ValueError('classification_original_budget')
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
