"""PC-only mechanical classification-clock graph preparation.

Default SOURCE checks real pinned bytes in memory. Explicit --write creates
fresh seven-runtime/two-manifest/definitions files and a readback-verified
SOURCE_RESULTS.zip. Only the parent's pure definitions/verify_inputs execute;
no archived generator main, checker, test, Runner, Owner, IO or device runs.
The pinned narrow HOST result does not establish failure-order equivalence,
complete Owner/native IO acceptance or P011 performance improvement.
"""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import types
import uuid
import zipfile


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/formal_receive_publication_anchor_clock_v1_definitions.py', 15660,
            '8a7ab2f16aca4b9af2660c2eb9331e9883e7f7f165e14deaf16db1195a9b68b4')
GENERATOR_PARENT = ('host/generate_formal_receive_publication_anchor_clock_v1.py', 29631,
                    'b7f6ef9019eeb683a191e186615f1d76a7b49f4a8783109011ace32e8e972561')
PAYLOAD_SOURCE = ('host/device_formal_receive_v3_check.py', 46256,
                  '212619ac677d8887c9ede6b968c2f0f8ba084448cfcd6cbf36c359359cbdb8e0')
FACTORY_DELTA = ('candidate/receive-profile-classification-clock-v1/runtime/mta_client_receive_factory.py', 97801,
                 '8cf46d17fda24cc2199e8900a0dfdd9d980b2247808c87801c00426db6158c37')
DELTA_SPEC = ('candidate/receive-profile-classification-clock-v1/exactsource-delta.json', 4360,
              '676ff4a410e882dc75c7750d7b5e02d110919ca41b5e14895141b1c3d1a6d7ae')
HOST_TEST_PIN = ('tests/test_receive_profile_classification_clock_v1.py', 27430,
                 'af393f6151ce073fe56e0f68d7240cd705720518933db59b13a6c5687af98a3e')
HOST_CHECK_PIN = ('host/receive_profile_classification_clock_v1_host_check.py', 7214,
                  '1a3cb420f6157b06515a86fafd099dd3d21de7599ace5b49d6f9202df7c5a7e5')
HOST_CMD_PIN = ('HOST_MTA_RECEIVE_PROFILE_CLASSIFICATION_CLOCK_V1_CHECK.cmd', 267,
                'a4e9923e1dbc119c0915005a10fde0061194e9581e99e7d6404440c6e62c23ed')
HOST_RESULT_PIN = ('results/receive-profile-classification-clock-v1-host-20261005-121124-ea0c7987/result.json', 3148,
                   'a19b588b0d20f6d783db825e915cc043fac897234d9e914bfd1662d6b562422f')
HOST_ZIP_PIN = ('results/receive-profile-classification-clock-v1-host-20261005-121124-ea0c7987/public-result.zip', 1932,
                '1002c0049fe118d5bfe39099e297d13f774c09f9a8d3b76789f6c3cdd306a6f2')
SELF_PATH = 'host/generate_formal_receive_profile_classification_clock_v1.py'
PREFIX = 'candidate/formal-receive-profile-classification-clock-v1/runtime/'
DEFINITIONS = 'host/formal_receive_profile_classification_clock_v1_definitions.py'
MANIFEST = 'host/formal_receive_profile_classification_clock_v1_definition_manifest.json'
PRIVATE_MANIFEST = 'host/formal_receive_profile_classification_clock_v1_private_source_manifest.json'
ROOT_BEFORE = b'p011-mta-receive-publication-anchor-clock-v1'
ROOT_AFTER = b'p011-mta-receive-profile-classification-clock-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory',
           'minhttp', 'mta_client_receive_boot', 'mta_client_service_owner')
SCHEMA = 'p011-profile-classification-clock-source-delta-v1'
inputs = {}


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return path, len(raw), digest(raw)


def read_pin(source_pin):
    need(type(source_pin) is tuple and len(source_pin) == 3 and
         type(source_pin[0]) is str and type(source_pin[1]) is int and source_pin[1] > 0 and
         type(source_pin[2]) is str and len(source_pin[2]) == 64 and
         all(char in '0123456789abcdef' for char in source_pin[2]) and
         source_pin[2] != '0' * 64, 'frozen_pin_required')
    target = BASE / source_pin[0]
    need(target.resolve().is_relative_to(BASE.resolve()), 'workspace_input')
    raw = target.read_bytes()
    need((len(raw), digest(raw)) == source_pin[1:], 'source_pin:' + source_pin[0])
    if source_pin[0] in inputs:
        need(inputs[source_pin[0]] == raw, 'input_changed:' + source_pin[0])
    inputs[source_pin[0]] = raw
    return raw


def node_text(raw, name, kind=ast.Assign):
    text = raw.decode('utf-8')
    rows = [row for row in ast.parse(text).body if isinstance(row, kind) and
            (row.name == name if kind is ast.FunctionDef else
             any(isinstance(target, ast.Name) and target.id == name for target in row.targets))]
    need(len(rows) == 1, 'node:' + name)
    return ast.get_source_segment(text, rows[0]).encode('utf-8')


def literal(raw, name):
    return ast.literal_eval(ast.parse(node_text(raw, name).decode('utf-8')).body[0].value)


def replace(raw, before, after, count=1):
    need(type(before) is bytes and before and raw.count(before) == count, 'replacement_count')
    return raw.replace(before, after)


def roots(raw, count):
    return replace(raw, ROOT_BEFORE, ROOT_AFTER, count)


def named_pin(raw, name, before, after, count=1):
    return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                   repr((name, after[1], after[2])).encode('ascii'), count)


def json_raw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def fresh_write(path, raw):
    target = BASE / path
    need(not target.exists() and target.parent.resolve().is_relative_to(BASE.resolve()),
         'fresh_workspace_output:' + path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('xb') as handle:
        need(handle.write(raw) == len(raw), 'source_write')
    need(target.read_bytes() == raw, 'source_readback:' + path)


def business_factory(before, after, spec_raw, before_pin):
    need(len(spec_raw) <= 65536, 'delta_spec_budget')
    spec = json.loads(spec_raw.decode('ascii'))
    need(type(spec) is dict and set(spec) == {'schema', 'evidence', 'source', 'candidate', 'replacements'} and
         spec['schema'] == SCHEMA and spec['evidence'] == 'READBACK_BYTE_INVERSE_ONLY' and
         spec['source'] == list(before_pin) and spec['candidate'] == list(FACTORY_DELTA), 'delta_spec_shape')
    rows = spec['replacements']
    need(type(rows) is list and len(rows) == 1, 'delta_spec_rows')
    row = rows[0]
    need(type(row) is dict and set(row) == {'name', 'before', 'after', 'count'} and
         row['name'] == 'live_profile_classification_metadata_clock' and
         type(row['before']) is str and type(row['after']) is str and
         row['before'] and row['after'] and row['before'] != row['after'] and
         type(row['count']) is int and row['count'] == 1, 'delta_spec_row')
    old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
    need(replace(before, old, new) == after, 'business_delta_forward')
    need(replace(after, new, old) == before, 'business_delta_inverse')
    # Both strings must belong to the actual complete _live_profile body.
    old_body = node_text(before, '_live_profile', ast.FunctionDef)
    new_body = node_text(after, '_live_profile', ast.FunctionDef)
    need(old_body.count(old.rstrip(b'\n')) == new_body.count(new.rstrip(b'\n')) == 1,
         'actual_profile_block')
    need(replace(old_body, old.rstrip(b'\n'), new.rstrip(b'\n')) == new_body,
         'actual_profile_block_forward')
    need(replace(new_body, new.rstrip(b'\n'), old.rstrip(b'\n')) == old_body,
         'actual_profile_block_inverse')
    return after


VERIFY = r'''def verify_inputs(inputs):
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
'''


def main():
    need(sys.argv[1:] in ([], ['--write']), 'source_or_explicit_write_only')
    write = sys.argv[1:] == ['--write']
    # Seal the narrow evidence and actual parent before any output can exist.
    read_pin(FACTORY_DELTA)
    read_pin(DELTA_SPEC)
    host_result = json.loads(read_pin(HOST_RESULT_PIN).decode('ascii'))
    for source_pin in (HOST_TEST_PIN, HOST_CHECK_PIN, HOST_CMD_PIN, HOST_ZIP_PIN, GENERATOR_PARENT):
        read_pin(source_pin)
    need(type(host_result) is dict and host_result.get('passed') is True and
         host_result.get('host_exit') == host_result.get('test_exit') == 0 and
         host_result.get('methods_requested') == 1 and host_result.get('timed_out') is False and
         host_result.get('source_unchanged') is True and
         host_result.get('old_tests_run') == 0 and
         all(host_result.get(key) is False for key in ('candidate_packaged', 'complete_live_profile_executed',
             'complete_owner_verified', 'complete_publication_verified', 'native_fd_content_IO_verified',
             'device', 'phone', 'rf', 'performance_measured')), 'external_affected_host_evidence')
    for source_pin in (HOST_TEST_PIN, HOST_CHECK_PIN, FACTORY_DELTA, DELTA_SPEC):
        need(dict(path=source_pin[0], bytes=source_pin[1], sha256=source_pin[2]) in
             host_result['sources'], 'external_affected_host_sources')
    need(type(host_result['sources']) is list and len(host_result['sources']) == 8,
         'external_affected_host_source_count')
    for source in host_result['sources']:
        need(type(source) is dict and set(source) == {'path', 'bytes', 'sha256'},
             'external_affected_host_source_shape')
        read_pin((source['path'], source['bytes'], source['sha256']))
    original_raw = read_pin(ORIGINAL)
    current = types.ModuleType('fixed_actual_publication_parent_definitions')
    current.__file__ = str(BASE / ORIGINAL[0])
    exec(compile(original_raw, current.__file__, 'exec'), current.__dict__)
    # This module loads frozen definitions. Only its pure verify_inputs is called.
    need(len(current.ORIGIN_SOURCE_PINS) == 69, 'actual_parent_origin_count')
    for source_pin in current.ORIGIN_SOURCE_PINS:
        read_pin(source_pin)
    ordinary_pin, private_pin, runner_before = (literal(original_raw, name) for name in
                                                ('MANIFEST', 'PRIVATE_MANIFEST', 'RUNNER'))
    ordinary = json.loads(read_pin(ordinary_pin).decode('ascii'))
    private = json.loads(read_pin(private_pin).decode('ascii'))
    need(current.MANIFEST == ordinary_pin and current.PRIVATE_MANIFEST == private_pin and
         current.RUNNER == runner_before and current.PAYLOAD_BYTES == 4169378 and
         literal(original_raw, 'CHANGED') == CHANGED, 'actual_parent_graph_binding')
    need(len(ordinary['sources']) == len(private['sources']) == 35, 'role_count')
    need(all(row['module'] != 'mta_client_service_owner' for row in private['sources']), 'private_no_owner')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']}
    before = {name: read_pin(old_rows[name]) for name in CHANGED}
    old_runner = read_pin(runner_before)
    business = business_factory(before['mta_client_receive_factory'], inputs[FACTORY_DELTA[0]],
                                inputs[DELTA_SPEC[0]], old_rows['mta_client_receive_factory'])
    payload_source = read_pin(PAYLOAD_SOURCE)
    helpers = literal(payload_source, 'HELPERS')
    wpa, monitor = literal(payload_source, 'WPA'), literal(payload_source, 'MONITOR')
    need((helpers, wpa, monitor) == (current.HELPERS, current.WPA, current.MONITOR), 'parent_helpers')
    fc_rows = literal(original_raw, 'FILECENTER_SOURCES')
    need(len(fc_rows) == 9 and sum(row[2] for row in fc_rows) == 113690 < 131072, 'filecenter_budget')
    for name, path, size, sha in fc_rows:
        read_pin((path, size, sha))
    for row in ordinary['sources'] + private['sources']:
        read_pin((row['path'], row['bytes'], row['sha256']))
    parent_payload = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in ordinary['sources']) + helpers
    parent_payload += tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in private['sources']) + (wpa, monitor)
    parent_total = 0
    for name, path, size, sha in parent_payload:
        parent_total += len(read_pin((path, size, sha)))
    need(len(parent_payload) == 75 and parent_total == current.PAYLOAD_BYTES and
         parent_total <= 4194304, 'actual_parent_payload')
    need(current.verify_inputs(inputs) == 7 and inputs[runner_before[0]] == old_runner,
         'actual_parent_graph_verified')
    source_generator = pin(SELF_PATH, Path(__file__).read_bytes())
    read_pin(source_generator)
    outputs, new_rows = {}, dict(old_rows)
    def put(name, raw):
        path = PREFIX + name + '.py'
        outputs[path] = raw
        return pin(path, raw)
    new_rows['mta_client_executor'] = put('mta_client_executor', roots(before['mta_client_executor'], 1))
    new_private = copy.deepcopy(private)
    new_private['previous_manifest_sha256'] = private_pin[2]
    for row in new_private['sources']:
        if row['module'] == 'mta_client_executor':
            after = new_rows[row['module']]
            row.update(path=after[0], bytes=after[1], sha256=after[2])
    private_raw = json_raw(new_private)
    outputs[PRIVATE_MANIFEST] = private_raw
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
    # Reverse each actual transformed source; only classification changes business.
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
            after = new_rows[row['module']]
            row.update(path=after[0], bytes=after[1], sha256=after[2])
    ordinary_raw = json_raw(new_ordinary)
    outputs[MANIFEST] = ordinary_raw
    # Manifest inverse uses parent ordering/unchanged fields, never a broad overlay.
    ordinary_inverse, private_inverse = copy.deepcopy(new_ordinary), copy.deepcopy(new_private)
    for row, previous in zip(ordinary_inverse['sources'], ordinary['sources']):
        if row['module'] in CHANGED:
            row.update(path=previous['path'], bytes=previous['bytes'], sha256=previous['sha256'])
    for row, previous in zip(private_inverse['sources'], private['sources']):
        if row['module'] == 'mta_client_executor':
            row.update(path=previous['path'], bytes=previous['bytes'], sha256=previous['sha256'])
    private_inverse['previous_manifest_sha256'] = private['previous_manifest_sha256']
    need(json_raw(ordinary_inverse) == inputs[ordinary_pin[0]] and
         json_raw(private_inverse) == inputs[private_pin[0]], 'manifest_byte_inverse')
    payload = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in new_ordinary['sources']) + helpers
    payload += tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in new_private['sources']) + (wpa, monitor)
    total = 0
    for name, path, size, sha in payload:
        raw = outputs[path] if path in outputs else read_pin((path, size, sha))
        need((len(raw), digest(raw)) == (size, sha), 'actual_payload_pin')
        total += len(raw)
    need(len(payload) == 75 and total <= 4194304, 'actual_payload_budget')
    need(literal(runner, 'ROLE_PINS') == tuple((row['module'], row['bytes'], row['sha256']) for row in new_ordinary['sources']), 'ordinary_pins')
    need(literal(runner, 'PRIVATE_PINS') == tuple((row['module'], row['bytes'], row['sha256']) for row in new_private['sources']), 'private_pins')
    need(literal(runner, 'HELPER_PINS') == tuple((name, size, sha) for name, path, size, sha in helpers), 'helper_pins')
    need(literal(runner, 'WPA_PIN') == (wpa[0], wpa[2], wpa[3]) and
         literal(runner, 'MONITOR_PIN') == (monitor[0], monitor[2], monitor[3]), 'asset_pins')
    need(literal(owner, 'FILECENTER_PINS') == tuple((name, size, sha) for name, path, size, sha in fc_rows) and
         literal(owner, 'FILECENTER_MAX_SOURCE') == 131072, 'filecenter_original_pins')
    need(literal(owner, 'BOOT_PIN') == new_rows['mta_client_receive_boot'][1:] and
         literal(factory, 'SOURCE_MANIFEST_SHA') == literal(boot, 'CLIENT_MANIFEST_SHA') == digest(private_raw), 'boot_manifest_closure')
    need(literal(factory, 'F_SHA') == literal(boot, 'F37_SHA') == new_rows['mta_client_executor'][2], 'executor_closure')
    need(literal(owner, 'ROOT') == literal(boot, 'ROOT') == literal(runner, 'STATE_ALIAS') == '/tmp/' + ROOT_AFTER.decode('ascii'), 'alias_closure')
    need(literal(boot, 'PHYSICAL_ROOT') == literal(runner, 'STATE_ROOT') == literal(factory, 'ASSET_PHYSICAL_ROOT') == '/var/volatile/tmp/' + ROOT_AFTER.decode('ascii'), 'physical_closure')
    need(literal(before['mta_client_executor'], 'ROOT') == literal(outputs[new_rows['mta_client_executor'][0]], 'ROOT') and
         literal(before['mta_client_executor'], 'PHYSICAL_ROOT') == literal(outputs[new_rows['mta_client_executor'][0]], 'PHYSICAL_ROOT'), 'client_roots_unchanged')
    # Derive the header from the actual parent bytes. Leave its manifest_rows,
    # make_source, role definitions and all inherited caps byte-for-byte intact.
    definition_changes = []
    definitions_raw = original_raw
    def change(before_text, after_text, count=1):
        nonlocal definitions_raw
        definitions_raw = replace(definitions_raw, before_text, after_text, count)
        definition_changes.append((before_text, after_text, count))
    verify_stub = b"def verify_inputs(inputs):\n    raise ValueError('source_unexpanded_verify')"
    change(node_text(definitions_raw, 'verify_inputs', ast.FunctionDef), verify_stub)
    change(ROOT_BEFORE, ROOT_AFTER, 2)
    change(b'candidate/formal-receive-publication-anchor-clock-v1/runtime/', PREFIX.encode('ascii'), 3)
    values = dict(ORIGINAL=ORIGINAL, MANIFEST=pin(MANIFEST, ordinary_raw), RUNNER=runner_pin,
                  EXECUTOR_PIN=new_rows['mta_client_executor'], PRIVATE_MANIFEST=pin(PRIVATE_MANIFEST, private_raw),
                  PAYLOAD_BYTES=total, FACTORY_DELTA=FACTORY_DELTA, DELTA_SPEC=DELTA_SPEC,
                  GENERATOR_PARENT=GENERATOR_PARENT, HOST_TEST_PIN=HOST_TEST_PIN,
                  HOST_CHECK_PIN=HOST_CHECK_PIN, HOST_RESULT_PIN=HOST_RESULT_PIN, HOST_ZIP_PIN=HOST_ZIP_PIN)
    for name, value in values.items():
        change(node_text(definitions_raw, name), (name + ' = ' + repr(value)).encode('ascii'))
    origin = ('SOURCE_GENERATOR = ' + repr(source_generator) + '\n' +
              'PAYLOAD_SOURCE = ' + repr(PAYLOAD_SOURCE) + '\n' +
              "ORIGIN_SOURCE_PINS = tuple(dict.fromkeys(tuple(_old.ORIGIN_SOURCE_PINS) +\n"
              "    tuple((path, size, sha) for name, path, size, sha in _old_rows if name in CHANGED) +\n"
              "    (ORIGINAL, _old.RUNNER, ORIGINAL_MANIFEST, OLD_PRIVATE_MANIFEST,\n"
              "     FACTORY_DELTA, DELTA_SPEC, GENERATOR_PARENT, PAYLOAD_SOURCE, SOURCE_GENERATOR,\n"
              '     ' + repr(HOST_CMD_PIN) + ',\n' +
              "     HOST_TEST_PIN, HOST_CHECK_PIN, HOST_RESULT_PIN, HOST_ZIP_PIN)))")
    change(node_text(definitions_raw, 'ORIGIN_SOURCE_PINS'), origin.encode('ascii'))
    change(verify_stub, VERIFY.rstrip().encode('ascii'))
    definitions_inverse = definitions_raw
    for old_text, new_text, count in reversed(definition_changes):
        definitions_inverse = replace(definitions_inverse, new_text, old_text, count)
    need(definitions_inverse == original_raw, 'definitions_byte_inverse')
    need(node_text(definitions_raw, 'make_source', ast.FunctionDef) == node_text(original_raw, 'make_source', ast.FunctionDef),
         'make_source_unchanged')
    outputs[DEFINITIONS] = definitions_raw
    syntax = []
    for path, raw in outputs.items():
        if path.endswith('.py'):
            ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
            syntax.append(path)
    need(len(outputs) == 10 and len(syntax) == 8, 'output_count')
    combined = dict(inputs)
    combined.update(outputs)
    prepared = types.ModuleType('fixed_classification_prepared_definitions')
    prepared.__file__ = str(BASE / DEFINITIONS)
    exec(compile(definitions_raw, prepared.__file__, 'exec'), prepared.__dict__)
    # Pure byte-graph verification, not the real Runner/Owner business graph.
    need(prepared.verify_inputs(combined) == 7 and
         tuple(prepared.ORIGIN_SOURCE_PINS[:69]) == tuple(current.ORIGIN_SOURCE_PINS), 'prepared_pure_graph')
    for source_pin in prepared.ORIGIN_SOURCE_PINS:
        need(source_pin[0] in inputs and pin(source_pin[0], inputs[source_pin[0]]) == source_pin,
             'prepared_origin_actual_read')
    need(current.verify_inputs(inputs) == 7 and inputs[runner_before[0]] == old_runner,
         'actual_parent_runner_preserved')
    report = dict(kind='receive_profile_classification_clock_v1_SOURCE', source_only=True, generated=write,
                  graph_executed=False, old_tests_executed=False, device_access=False,
                  actual_parent_graph_verified=True, actual_parent_origin_count=69,
                  actual_parent_payload_count=len(parent_payload), actual_parent_payload_bytes=parent_total,
                  original_runner_preserved=True, business_delta_blocks=1, business_delta_schema=SCHEMA,
                  actual_profile_block_forward_inverse=True, runtime_mechanical_inverse=True,
                  manifest_byte_inverse=True, definitions_byte_inverse=True, prepared_pure_graph_verified=True,
                  affected_host_test_executed_by_generator=False, external_affected_host_evidence_passed=True,
                  complete_live_profile_executed=False, complete_publication_verified=False,
                  complete_owner_verified=False, native_IO_verified=False, phone_verified=False,
                  performance_measured=False, failure_order_equivalence_claimed=False,
                  classification_full_failure_effects_deferred=True, gui_navigation_uses_parent_publication=True,
                  external_host_result_pin=HOST_RESULT_PIN, external_host_zip_pin=HOST_ZIP_PIN,
                  ordinary_count=35, private_count=35, private_owner_added=False, actual_payload_count=len(payload),
                  actual_payload_bytes=total, payload_cap=4194304, headroom=4194304-total,
                  filecenter_source_count=9, filecenter_source_bytes=113690, filecenter_cap=131072,
                  prepared_origin_count=len(prepared.ORIGIN_SOURCE_PINS), source_syntax=syntax,
                  outputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in outputs.items()],
                  inputs=[dict(path=path, bytes=len(raw), sha256=digest(raw)) for path, raw in sorted(inputs.items())])
    if write:
        area = 'results/receive-profile-classification-clock-v1-source-' + uuid.uuid4().hex[:24]
        report.update(result=area + '/result.json', zip=area + '/SOURCE_RESULTS.zip',
                      source_zip_readback_required=True)
        report_raw = json_raw(report)
        members = {'result.json': report_raw, **outputs}
        members[SELF_PATH] = inputs[SELF_PATH]
        # Preserve SOURCE provenance bytes separately inside this new archive.
        for path, raw in sorted(inputs.items()):
            members['private-inputs/' + path] = raw
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path, raw in members.items():
                archive.writestr(path, raw)
        archive_raw = buffer.getvalue()
        # Validate every in-memory archive member before fresh disk writes.
        with zipfile.ZipFile(io.BytesIO(archive_raw), 'r') as archive:
            need(len(archive.namelist()) == len(members) and set(archive.namelist()) == set(members), 'source_zip_members')
            for path, raw in members.items():
                need(archive.read(path) == raw, 'source_zip_member:' + path)
        for path in tuple(outputs) + (report['result'], report['zip']):
            need(not (BASE / path).exists(), 'fresh_source_set:' + path)
        # Recheck source identities immediately before the only authorized write.
        for path, raw in tuple(inputs.items()):
            need((BASE / path).read_bytes() == raw, 'prewrite_input_changed:' + path)
        for path, raw in outputs.items():
            fresh_write(path, raw)
        fresh_write(report['result'], report_raw)
        fresh_write(report['zip'], archive_raw)
        with zipfile.ZipFile(BASE / report['zip'], 'r') as archive:
            need(len(archive.namelist()) == len(members) and set(archive.namelist()) == set(members), 'source_zip_readback_members')
            for path, raw in members.items():
                need(archive.read(path) == raw, 'source_zip_readback:' + path)
        report['source_zip_readback_verified'] = True
        report['source_zip_pin'] = pin(report['zip'], (BASE / report['zip']).read_bytes())
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))


if __name__ == '__main__':
    main()
