"""Thin v2 graph: exact startup-root closure, headless and source-pinned.

The frozen v1 Handoff bytes are reused. Executor changes only its fixed startup
source directory; CLIENT roots and token paths stay original. Private/ordinary
Executor are one exact source; Factory/Bridge/Boot/Owner/Session propagate pins.
"""
import ast
import hashlib
import json
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/formal_receive_compat_v1_definitions.py', 8029,
            '0a348aef9b10033bd0cde8a87b1cc2860f7c23d0a1afd9207ebb12667c101e12')
MANIFEST = ('host/formal_receive_compat_v2_definition_manifest.json', 7836,
            '52792735dbb1e3cb4a1e98bc5c55f1c07b9de75a90fc42fc1397370fc68b9478')
RUNNER = ('candidate/formal-receive-compat-v2/runtime/mta_formal_receive_session.py', 79223,
          '81286921ecca0a5f3c4609bb214d4bea460ccdbc406a2ef2b0a363403c3a0a42')
STATE_ALIAS = '/tmp/p011-mta-formal-receive-compat-v2'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-compat-v2'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge',
           'mta_client_receive_factory', 'mta_client_receive_boot', 'mta_client_service_owner')
EXECUTOR_PIN = ('candidate/formal-receive-compat-v2/runtime/mta_client_executor.py', 117750,
                '16c6dc977eb6ac5992c7fc93474703187d549bfc31e51ce09a9b58ffb369ae7c')
PRIVATE_MANIFEST = ('host/formal_receive_compat_v2_private_source_manifest.json', 8139,
                    '6e1d0a8976c1daab20069d66418c61ab174812cf0219d12e5180a129fa519a6b')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pin(pin):
    raw = (BASE / pin[0]).read_bytes()
    if len(raw) != pin[1] or digest(raw) != pin[2]:
        raise ValueError('compat_source_pin')
    return raw


ORIGINAL_RAW = read_pin(ORIGINAL)
_old = types.ModuleType('fixed_original_interactive_definitions')
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
                           if name in CHANGED) + (_old.RUNNER, OLD_PRIVATE_MANIFEST)


def manifest_rows(raw, private=False):
    value = json.loads(raw.decode('ascii'))
    original = _old_private if private else json.loads(ORIGINAL_MANIFEST_RAW.decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != original['schema'] or
            type(value['sources']) is not list or len(value['sources']) != len(original['sources']) or
            private and value['previous_manifest_sha256'] != OLD_PRIVATE_MANIFEST[2]):
        raise ValueError('compat_manifest_shape')
    rows = []
    for row, before in zip(value['sources'], original['sources']):
        name = before['module']
        changed = name == 'mta_client_executor' if private else name in CHANGED
        if not changed:
            if row != before:
                raise ValueError('compat_unchanged_role')
        elif (type(row) is not dict or set(row) != set(before) or row['module'] != name or
              row['path'] != 'candidate/formal-receive-compat-v2/runtime/' + name + '.py' or
              type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152 or
              type(row['sha256']) is not str or len(row['sha256']) != 64 or
              any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('compat_changed_role')
        if private and name == 'mta_client_executor' and (
                row['path'], row['bytes'], row['sha256']) != EXECUTOR_PIN:
            raise ValueError('compat_private_executor')
        rows.append(('runtime35/' + name if private else name, row['path'], row['bytes'], row['sha256']))
    names = tuple('runtime35/' + name for name in PRIVATE_MODULE_NAMES) if private else MODULE_NAMES
    if tuple(row[0] for row in rows) != names:
        raise ValueError('compat_role_order')
    return tuple(rows)


def verify_inputs(inputs):
    rows = {name: (path, size, sha) for name, path, size, sha in
            manifest_rows(inputs[MANIFEST[0]])}
    old_rows = {name: (path, size, sha) for name, path, size, sha in _old_rows}
    private = {name: (path, size, sha) for name, path, size, sha in
               manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)}
    if private['runtime35/mta_client_executor'] != rows['mta_client_executor'] or (
            rows['mta_client_executor'] != EXECUTOR_PIN):
        raise ValueError('compat_executor_domains')
    if (inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW or
            inputs[OLD_PRIVATE_MANIFEST[0]] != OLD_PRIVATE_RAW):
        raise ValueError('compat_original_manifest_changed')
    old_root, new_root = b'p011-mta-formal-receive-compat-v1', b'p011-mta-formal-receive-compat-v2'
    def replace(raw, before, after, count=1):
        if raw.count(before) != count:
            raise ValueError('compat_replacement_count')
        return raw.replace(before, after)
    def root_copy(raw):
        if old_root not in raw:
            raise ValueError('compat_missing_root')
        return raw.replace(old_root, new_root)
    def pin_copy(raw, name, count=1):
        before, after = old_rows[name], rows[name]
        return replace(raw, repr((name, before[1], before[2])).encode('ascii'),
                       repr((name, after[1], after[2])).encode('ascii'), count)
    f_before, f_after = old_rows['mta_client_executor'], rows['mta_client_executor']
    old_private, new_private = OLD_PRIVATE_MANIFEST[2].encode('ascii'), PRIVATE_MANIFEST[2].encode('ascii')
    old_f, new_f = f_before[2].encode('ascii'), f_after[2].encode('ascii')
    expected = {}
    expected[CHANGED[0]] = replace(inputs[f_before[0]],
        b'/var/volatile/tmp/p011-mta-formal-receive-v3/runtime35',
        b'/var/volatile/tmp/p011-mta-formal-receive-compat-v2/runtime35')
    expected[CHANGED[1]] = replace(inputs[old_rows[CHANGED[1]][0]], old_f, new_f)
    factory = replace(replace(root_copy(inputs[old_rows[CHANGED[2]][0]]),
                              old_private, new_private), old_f, new_f)
    expected[CHANGED[2]] = replace(factory,
        ("('mta_client_executor', " + str(f_before[1]) + ", F_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F_SHA)").encode('ascii'))
    boot = replace(replace(root_copy(inputs[old_rows[CHANGED[3]][0]]),
                           old_private, new_private), old_f, new_f)
    boot = replace(boot,
        ("('mta_client_executor', " + str(f_before[1]) + ", F37_SHA)").encode('ascii'),
        ("('mta_client_executor', " + str(f_after[1]) + ", F37_SHA)").encode('ascii'), 2)
    expected[CHANGED[3]] = pin_copy(pin_copy(boot, CHANGED[1]), CHANGED[2])
    owner = root_copy(inputs[old_rows[CHANGED[4]][0]])
    before, after = old_rows[CHANGED[3]], rows[CHANGED[3]]
    expected[CHANGED[4]] = replace(owner,
        ('BOOT_PIN = ' + repr(before[1:])).encode('ascii'),
        ('BOOT_PIN = ' + repr(after[1:])).encode('ascii'))
    session = root_copy(inputs[_old.RUNNER[0]])
    for name in CHANGED:
        session = pin_copy(session, name, 2 if name == 'mta_client_executor' else 1)
    expected[RUNNER[0]] = session
    for name, raw in expected.items():
        path = RUNNER[0] if name == RUNNER[0] else rows[name][0]
        if inputs[path] != raw:
            raise ValueError('compat_nonmechanical_change')
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
