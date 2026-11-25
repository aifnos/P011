"""Thin Receive UI v1 runtime graph; mechanical roots/pins plus frozen socket core.

The actual Receive Owner remains canonical. UI adapter/builder/guardian binding
is separate; this module adds no UI/RF admission and runs no old graph or suite.
"""
import ast
import hashlib
import json
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/formal_receive_alias_clock_v1_definitions.py', 19468,
            '7bd0155ae2ddcb0892bf53e0429bd323b02046b8c5a365531fb929bce7e9e6e1')
MANIFEST = ('host/formal_receive_ui_v1_definition_manifest.json', 7847,
            'af571664cd04562a47733ad3aca0871ab6af72d2337d1303fd284b1ae57096ea')
RUNNER = ('candidate/formal-receive-ui-v1/runtime/mta_formal_receive_session.py', 79215,
          '8fc39ae5ab2f4219f4bece327f87ff0bfb0158619386fd00a3bac9b24170139c')
STATE_ALIAS = '/tmp/p011-mta-formal-receive-ui-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-ui-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge', 'mta_client_receive_factory',
           'minhttp', 'mta_client_receive_boot', 'mta_client_service_owner')
EXECUTOR_PIN = ('candidate/formal-receive-ui-v1/runtime/mta_client_executor.py', 117746,
                'a195089707f5988ef7587283f0ec816fc4e2d57d0715047d7e51330ff03a506c')
PRIVATE_MANIFEST = ('host/formal_receive_ui_v1_private_source_manifest.json', 8135,
                    '5f47efc9b8249bccb28e9d9ab2ae8c6a644805de33eee03697bde9520d6adb33')
SOCKET_OWNER = ('candidate/formal-receive-socket-close-v1/runtime/mta_client_service_owner.py', 78755,
                '7073b4140c62314416237428c1fdffb124407a9dab0043b9dd2f83e48e55992f')
MINHTTP_ORIGINAL = ('candidate/formal-receive-socket-close-v1/runtime/minhttp.py', 9690,
                    'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), digest(raw)) != pin[1:]:
        raise ValueError('receive_ui_source_pin')
    return raw


ORIGINAL_RAW = read_pin(ORIGINAL)
_old = types.ModuleType('fixed_original_receive_alias_clock_definitions')
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
                                                 SOCKET_OWNER, MINHTTP_ORIGINAL)


def manifest_rows(raw, private=False):
    value = json.loads(raw.decode('ascii'))
    original = _old_private if private else json.loads(ORIGINAL_MANIFEST_RAW.decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != original['schema'] or
            type(value['sources']) is not list or len(value['sources']) != len(original['sources']) or
            private and value['previous_manifest_sha256'] != OLD_PRIVATE_MANIFEST[2]):
        raise ValueError('receive_ui_manifest_shape')
    rows = []
    for row, before in zip(value['sources'], original['sources']):
        name = before['module']
        changed = name == 'mta_client_executor' if private else name in CHANGED
        if not changed:
            if row != before: raise ValueError('receive_ui_unchanged_role')
        elif (type(row) is not dict or set(row) != set(before) or row['module'] != name or
              row['path'] != 'candidate/formal-receive-ui-v1/runtime/' + name + '.py' or
              type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152 or
              type(row['sha256']) is not str or len(row['sha256']) != 64 or
              any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('receive_ui_changed_role')
        if private and name == 'mta_client_executor' and (
                row['path'], row['bytes'], row['sha256']) != EXECUTOR_PIN:
            raise ValueError('receive_ui_private_executor')
        rows.append(('runtime35/' + name if private else name, row['path'], row['bytes'], row['sha256']))
    names = tuple('runtime35/' + name for name in PRIVATE_MODULE_NAMES) if private else MODULE_NAMES
    if tuple(row[0] for row in rows) != names: raise ValueError('receive_ui_role_order')
    return tuple(rows)


def verify_inputs(inputs):
    """Only seven changed files: exact mechanical copies of retained sources."""
    rows = {name: (path, size, sha) for name, path, size, sha in manifest_rows(inputs[MANIFEST[0]])}
    old_rows = {name: (path, size, sha) for name, path, size, sha in _old_rows}
    private = {name: (path, size, sha) for name, path, size, sha in
               manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)}
    if private['runtime35/mta_client_executor'] != rows['mta_client_executor'] or (
            rows['mta_client_executor'] != EXECUTOR_PIN):
        raise ValueError('receive_ui_executor_domains')
    if (inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW or
            inputs[OLD_PRIVATE_MANIFEST[0]] != OLD_PRIVATE_RAW):
        raise ValueError('receive_ui_original_manifest_changed')
    old_root, new_root = b'p011-mta-formal-receive-alias-clock-v1', b'p011-mta-formal-receive-ui-v1'
    def replace(raw, before, after, count=1):
        if raw.count(before) != count: raise ValueError('receive_ui_replacement_count')
        return raw.replace(before, after)
    def roots(raw, count):
        return replace(raw, old_root, new_root, count)
    def pin_copy(raw, name, count=1):
        before, after = old_rows[name], rows[name]
        return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                       repr((name, after[1], after[2])).encode('ascii'), count)
    f_before, f_after = old_rows['mta_client_executor'], rows['mta_client_executor']
    old_f, new_f = f_before[2].encode('ascii'), f_after[2].encode('ascii')
    old_private, new_private = OLD_PRIVATE_MANIFEST[2].encode('ascii'), PRIVATE_MANIFEST[2].encode('ascii')
    expected = {}
    expected[CHANGED[0]] = roots(inputs[f_before[0]], 1)
    expected[CHANGED[1]] = replace(inputs[old_rows[CHANGED[1]][0]], old_f, new_f)
    factory = replace(replace(roots(inputs[old_rows[CHANGED[2]][0]], 2),
                              old_private, new_private), old_f, new_f)
    expected[CHANGED[2]] = replace(factory,
        ("('mta_client_executor', " + str(f_before[1]) + ", F_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F_SHA)").encode('ascii'))
    expected['minhttp'] = inputs[MINHTTP_ORIGINAL[0]]
    boot = replace(replace(roots(inputs[old_rows['mta_client_receive_boot'][0]], 2),
                           old_private, new_private), old_f, new_f)
    boot = replace(boot,
        ("('mta_client_executor', " + str(f_before[1]) + ", F37_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F37_SHA)").encode('ascii'), 2)
    for name in ('mta_client_state_bridge', 'mta_client_receive_factory', 'minhttp'):
        boot = pin_copy(boot, name)
    expected['mta_client_receive_boot'] = boot
    owner = roots(inputs[SOCKET_OWNER[0]], 2)
    owner = replace(owner,
        b'Isolated receive-socket-close-v1 SOURCE PATCH, NOT a runnable composition.\n'
        b'The original alias-clock roots/constants/BOOT pins are intentionally unchanged;\n'
        b'this patched Owner/minhttp pair has not been connected to a sealed graph/UI.\n',
        b'Receive UI v1 root/pin composition reuses the frozen socket-close source patch.\n'
        b'This source graph alone does not establish UI, RF or real-phone acceptance.\n')
    before, after = old_rows['mta_client_receive_boot'], rows['mta_client_receive_boot']
    expected['mta_client_service_owner'] = replace(owner,
        ('BOOT_PIN = ' + repr(before[1:])).encode('ascii'),
        ('BOOT_PIN = ' + repr(after[1:])).encode('ascii'))
    runner = roots(inputs[_old.RUNNER[0]], 2)
    for name in CHANGED:
        runner = pin_copy(runner, name, 2 if name == 'mta_client_executor' else 1)
    expected[RUNNER[0]] = runner
    for name, raw in expected.items():
        path = RUNNER[0] if name == RUNNER[0] else rows[name][0]
        if inputs[path] != raw: raise ValueError('receive_ui_nonmechanical_change')
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
