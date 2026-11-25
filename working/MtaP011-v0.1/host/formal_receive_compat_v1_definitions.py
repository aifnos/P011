"""Thin headless definitions for a new receive compatibility graph.

Only the Handoff known-field projection changes business behavior. Factory,
Boot, Owner and Session receive independent roots and propagated exact pins.
Original helper/private/GO/envelope sources remain pinned and unchanged.
"""
import ast
import hashlib
import json
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/device_receive_interactive_v1_check.py', 51764,
            '85744bf1c282b55b997911222f9dfb83b5f3ffdb9badc956017ef551521c58ca')
MANIFEST = ('host/formal_receive_compat_v1_definition_manifest.json', 7822,
            '5ac1f4d0651ac5aaac5633386ae7345aa1c68ffe41ea29a8d471a678f2292f11')
RUNNER = ('candidate/formal-receive-compat-v1/runtime/mta_formal_receive_session.py', 79223,
          'f840afb285844cae5f37f4c737433775ff7b0c40d204314ba649823317b79f52')
STATE_ALIAS = '/tmp/p011-mta-formal-receive-compat-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-compat-v1'
CHANGED = ('mta_client_connect_handoff', 'mta_client_receive_factory',
           'mta_client_receive_boot', 'mta_client_service_owner')
OLD_SEGMENT = (b"                if type(document) is not dict or not set(document) <= _FIELDS:\n"
               b"                    _fail('invalid_event')\n"
               b"                info = protocol.P2pInfo.from_dict(document)")
NEW_SEGMENT = (b"                if type(document) is not dict:\n"
               b"                    _fail('invalid_event')\n"
               b"                # Unknown extension fields have no semantic or authority role.\n"
               b"                known = {field: document[field] for field in _FIELDS if field in document}\n"
               b"                info = protocol.P2pInfo.from_dict(known)")


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
CHECKER, PRIVATE_MANIFEST, TRANSPORT = _old.CHECKER, _old.PRIVATE_MANIFEST, _old.TRANSPORT
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
                           if name in CHANGED) + (_old.RUNNER,)


def manifest_rows(raw, private=False):
    if private:
        return _old.manifest_rows(raw, private=True)
    value = json.loads(raw.decode('ascii'))
    original = json.loads(ORIGINAL_MANIFEST_RAW.decode('ascii'))
    if (type(value) is not dict or set(value) != {'schema', 'sources'} or
            value['schema'] != original['schema'] or type(value['sources']) is not list or
            len(value['sources']) != len(original['sources'])):
        raise ValueError('compat_manifest_shape')
    rows = []
    for row, before in zip(value['sources'], original['sources']):
        name = before['module']
        if name not in CHANGED:
            if row != before:
                raise ValueError('compat_unchanged_role')
        elif (type(row) is not dict or set(row) != set(before) or row['module'] != name or
              row['path'] != 'candidate/formal-receive-compat-v1/runtime/' + name + '.py' or
              type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152 or
              type(row['sha256']) is not str or len(row['sha256']) != 64 or
              any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('compat_changed_role')
        rows.append((name, row['path'], row['bytes'], row['sha256']))
    if tuple(row[0] for row in rows) != MODULE_NAMES:
        raise ValueError('compat_role_order')
    return tuple(rows)


def verify_inputs(inputs):
    rows = {name: (path, size, sha) for name, path, size, sha in
            manifest_rows(inputs[MANIFEST[0]])}
    old_rows = {name: (path, size, sha) for name, path, size, sha in _old_rows}
    old_root, new_root = b'p011-mta-formal-receive-v3', b'p011-mta-formal-receive-compat-v1'
    def root_copy(raw):
        if old_root not in raw:
            raise ValueError('compat_missing_root')
        return raw.replace(old_root, new_root)
    def pin_copy(raw, name):
        before, after = old_rows[name], rows[name]
        old_pin = repr((name, before[1], before[2])).encode('ascii')
        new_pin = repr((name, after[1], after[2])).encode('ascii')
        if raw.count(old_pin) != 1:
            raise ValueError('compat_missing_pin')
        return raw.replace(old_pin, new_pin)
    expected = {}
    handoff = inputs[old_rows[CHANGED[0]][0]]
    if handoff.count(OLD_SEGMENT) != 1:
        raise ValueError('compat_capture_changed')
    expected[CHANGED[0]] = handoff.replace(OLD_SEGMENT, NEW_SEGMENT)
    expected[CHANGED[1]] = root_copy(inputs[old_rows[CHANGED[1]][0]])
    expected[CHANGED[2]] = pin_copy(pin_copy(
        root_copy(inputs[old_rows[CHANGED[2]][0]]), CHANGED[0]), CHANGED[1])
    owner = root_copy(inputs[old_rows[CHANGED[3]][0]])
    before, after = old_rows[CHANGED[2]], rows[CHANGED[2]]
    old_pin = ('BOOT_PIN = ' + repr(before[1:])).encode('ascii')
    new_pin = ('BOOT_PIN = ' + repr(after[1:])).encode('ascii')
    if owner.count(old_pin) != 1:
        raise ValueError('compat_owner_pin')
    expected[CHANGED[3]] = owner.replace(old_pin, new_pin)
    session = root_copy(inputs[_old.RUNNER[0]])
    for name in CHANGED:
        session = pin_copy(session, name)
    expected[RUNNER[0]] = session
    for name, raw in expected.items():
        path = RUNNER[0] if name == RUNNER[0] else rows[name][0]
        if inputs[path] != raw:
            raise ValueError('compat_nonmechanical_change')
        ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
    if inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW:
        raise ValueError('compat_original_manifest_changed')
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
