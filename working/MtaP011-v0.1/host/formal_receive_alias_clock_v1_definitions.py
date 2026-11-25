"""Single-variable fixed-alias clock graph; six-source mechanical closure.

Only Publication _Files metadata/readlink callbacks use the original cheap
identity/cancel/deadline guard. Startup and all private IO boundaries keep now.
"""
import ast
import hashlib
import json
from pathlib import Path
import types


BASE = Path(__file__).resolve().parents[1]
ORIGINAL = ('host/formal_receive_compat_v2_definitions.py', 9834,
            '9836f38f5fe48b7ef2e0f5a33f8b58a2ad80648c572410d54e7892f7d05e0b04')
MANIFEST = ('host/formal_receive_alias_clock_v1_definition_manifest.json', 7861,
            '199ea322f96f163d8dc0cafe89efa3f76423bafca5d9750224cee398b6ea0de8')
RUNNER = ('candidate/formal-receive-alias-clock-v1/runtime/mta_formal_receive_session.py', 79233,
          '79c91cdcdd2befd376c482cbe37b05356e2e4a56b65c29db42ec09745a8362d5')
STATE_ALIAS = '/tmp/p011-mta-formal-receive-alias-clock-v1'
STATE_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-alias-clock-v1'
CHANGED = ('mta_client_executor', 'mta_client_state_bridge',
           'mta_client_receive_factory', 'mta_client_receive_boot', 'mta_client_service_owner')
EXECUTOR_PIN = ('candidate/formal-receive-alias-clock-v1/runtime/mta_client_executor.py', 117755,
                '129f3f87f875e7b9ea11fcf0e89b8bf65a060783b1901a2e165f0e42bbf089f0')
PRIVATE_MANIFEST = ('host/formal_receive_alias_clock_v1_private_source_manifest.json', 8144,
                    'e4105054fa6c6a025a8dad6edd1cfb9545b22d41b1c6c1260d5212727e3aafc4')


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
              row['path'] != 'candidate/formal-receive-alias-clock-v1/runtime/' + name + '.py' or
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


FACTORY_ALIAS_REPLACEMENTS = (
    ("        self.receive_metadata = self.directory_identity_rows = None\n",
     "        self.receive_metadata = self.directory_identity_rows = None\n        # Fixed metadata-only alias callbacks never grant private IO or admission.\n        trial = self.operation.receive_trial\n        self._alias_trial, self._alias_owner = trial, trial.owner\n        self._alias_lock = self.state.lock\n        self._alias_refs = (handoff.helper, handoff.key, handoff.crypto, handoff.reader,\n                            self.operation.cancelled, self.session.cancelled)\n        self._alias_functions = _PUBLICATION_ALIAS_ORIGINALS\n        self._alias_codes = _PUBLICATION_ALIAS_CODES\n        self._alias_clock = self.alias_now\n"),
    ("        # Exact parents and definitions, not a caller's restoration/ready flag.\n",
     "        # Exact parents and definitions, not a caller's restoration/ready flag.\n        if (self._alias_functions is not _PUBLICATION_ALIAS_ORIGINALS or\n                self._alias_codes is not _PUBLICATION_ALIAS_CODES or\n                self.factory._alias_functions is not self._alias_functions or\n                self.factory._alias_codes is not self._alias_codes or\n                self.state.lock is not self._alias_lock or\n                any(current is not original or current.__code__ is not code for current, original, code in zip(\n                    (_PublicationAttempt.__init__, _PublicationAttempt.originals, _PublicationAttempt.now,\n                     _PublicationAttempt.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias),\n                    self._alias_functions, self._alias_codes)) or\n                getattr(self._alias_clock, '__self__', None) is not self or\n                getattr(self._alias_clock, '__func__', None) is not self._alias_functions[3]):\n            _fail('publication_owner_changed')\n        if self.files is not None and hasattr(self.files, 'alias_owner') and (\n                self.files.attempt is not self or type(self.files.alias_owner) is not _F_ORIGINALS[4] or\n                self.files.alias_owner.clock is not self._alias_clock or\n                self.files.alias_owner.io is not self.files.io or\n                getattr(self.files.alias_owner.check, '__self__', None) is not self.files.alias_owner or\n                getattr(self.files.alias_owner.check, '__func__', None) is not self._alias_functions[4] or\n                getattr(self.files.alias_owner._fixed_tmp_alias, '__self__', None) is not self.files.alias_owner or\n                getattr(self.files.alias_owner._fixed_tmp_alias, '__func__', None) is not self._alias_functions[5] or\n                self.files.alias_owner.deadline is not self.original_prepare_until):\n            _fail('publication_owner_changed')\n"),
    ("    def start(self):\n",
     "    def alias_now(self):\n        \"\"\"Metadata/readlink clock only; full now remains every IO boundary.\"\"\"\n        # No Trial inventory/JSON/DirectoryBinding check, profile cache or RF.\n        if self.state.lock is not self._alias_lock:\n            _fail('publication_owner_changed')\n        if (self._alias_functions is not _PUBLICATION_ALIAS_ORIGINALS or\n                self._alias_codes is not _PUBLICATION_ALIAS_CODES or\n                self.factory._alias_functions is not self._alias_functions or\n                self.factory._alias_codes is not self._alias_codes or\n                any(current is not original or current.__code__ is not code for current, original, code in zip(\n                    (_PublicationAttempt.__init__, _PublicationAttempt.originals, _PublicationAttempt.now,\n                     _PublicationAttempt.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias),\n                    self._alias_functions, self._alias_codes))):\n            _fail('publication_owner_changed')\n        with self._alias_lock:\n            _PUBLICATION_ALIAS_ORIGINALS[1](self)\n            state, op, session, handoff = self.state, self.operation, self.session, self.handoff\n            trial, owner = self._alias_trial, self._alias_owner\n            helper, key, crypto, reader, cancelled, session_cancelled = self._alias_refs\n            import mta_service as service\n            import mta_receive_trial as trials\n            if (type(state) is not service.State or type(op) is not service.Operation or\n                    type(session) is not handoffs.sessions.TransferSession or\n                    type(crypto) is not handoffs.crypto.OpenSslCrypto or type(key) is not handoffs.crypto.KeyPair or\n                    type(owner) is not trial._owner_type or\n                    owner._startup_namespace_original is not trial._owner_namespace or\n                    trial._owner_namespace.get('FixedStateServiceOwner') is not type(owner) or\n                    service.ReceiveConnectHandoff is not _HANDOFF_TYPE or\n                    service.State._receive_handoff_data_allowed is not handoff._data_authorizer_original or\n                    service.State._receive_handoff_data_allowed.__globals__ is not service.__dict__ or\n                    type(trial) is not trials.FixedReceiveTrial or\n                    state._receive_trial is not trial or state._receive_trial_original is not trial or\n                    op.receive_trial is not trial or trial.owner is not owner or trial._owner_original is not owner or\n                    trial.state is not state or trial.factory is not self.factory or\n                    owner.receive_trial is not trial or owner._receive_trial_original is not trial or\n                    owner.state is not state or owner.factory is not self.factory or\n                    owner.original_until is not trial.until or trial.until is not trial._until_original or\n                    trial.clock is not self.clock or owner.clock is not self.clock or\n                    trial.revoked is not False or trial.expired is not False or\n                    owner.stop_called is not False or owner.close_called is not False or\n                    handoff._failed is not False or handoff._cancelled is not False or\n                    handoff.clock is not handoff._clock_original or handoff.deadline is not handoff._deadline_original or\n                    state.operation is not op or state.session is not session or op.session is not session or\n                    state.worker is not self.worker or\n                    state.helper is not helper or op.helper is not helper or handoff.helper is not helper or\n                    state.key is not key or op.key is not key or handoff.key is not key or\n                    state.crypto is not crypto or op.crypto is not crypto or handoff.crypto is not crypto or\n                    helper.thread is not reader or handoff.reader is not reader or helper.closed is not False or\n                    key.closed is not False or key._owner is not crypto._lib or\n                    op.kind != 'receive' or op.consent is not True or state.closing is not False or\n                    type(self.epoch) is not int or not 1 <= self.epoch <= 9007199254740991 or\n                    type(state.native_epoch) is not int or type(op.epoch) is not int or\n                    state.native_epoch != self.epoch or op.epoch != self.epoch or\n                    session._worker is not self.worker or\n                    op.cancelled is not cancelled or session.cancelled is not session_cancelled or\n                    cancelled.is_set() or session_cancelled.is_set()):\n                _fail('publication_owner_changed')\n            value = self.clock()\n            if (not _number(value) or self.last is not None and value < self.last or\n                    handoff._last is not None and value < handoff._last or\n                    trial._last is not None and value < trial._last):\n                _fail('publication_clock')\n            if (self.until is not self.original_until or\n                    self.until != min(float(self.handoff_until), float(self.session_until)) or\n                    self.prepare_until is not self.original_prepare_until or\n                    self.prepare_until > self.until or value >= self.prepare_until or value >= self.until or\n                    value >= handoff.deadline or value >= session._task_deadline or value >= trial.until):\n                _fail('publication_expired')\n            self.last = float(value)\n            handoff._last = float(value)\n            return float(value)\n\n    def start(self):\n"),
    ("STARTUP_READONLY_SCHEMA = 'receive-startup-readonly-v1'\n",
     "_PUBLICATION_ALIAS_ORIGINALS = (_PublicationAttempt.__init__, _PublicationAttempt.originals,\n    _PublicationAttempt.now, _PublicationAttempt.alias_now, executor._ReadOwner.check,\n    executor._ReadOwner._fixed_tmp_alias)\n_PUBLICATION_ALIAS_CODES = tuple(function.__code__ for function in _PUBLICATION_ALIAS_ORIGINALS)\n\n\nSTARTUP_READONLY_SCHEMA = 'receive-startup-readonly-v1'\n"),
    ("        self.alias_owner = executor._ReadOwner(self.io, attempt.now, attempt.prepare_until)\n",
     "        clock = attempt._alias_clock if type(attempt) is _PublicationAttempt else attempt.now\n        self.alias_owner = executor._ReadOwner(self.io, clock, attempt.prepare_until)\n"),
    ("        self._startup_scope = None\n",
     "        self._startup_scope = None\n        self._alias_functions, self._alias_codes = _PUBLICATION_ALIAS_ORIGINALS, _PUBLICATION_ALIAS_CODES\n"),
)


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
    old_root, new_root = b'p011-mta-formal-receive-compat-v2', b'p011-mta-formal-receive-alias-clock-v1'
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
        b'/var/volatile/tmp/p011-mta-formal-receive-compat-v2/runtime35',
        b'/var/volatile/tmp/p011-mta-formal-receive-alias-clock-v1/runtime35')
    expected[CHANGED[1]] = replace(inputs[old_rows[CHANGED[1]][0]], old_f, new_f)
    factory = replace(replace(root_copy(inputs[old_rows[CHANGED[2]][0]]),
                              old_private, new_private), old_f, new_f)
    for before, after in FACTORY_ALIAS_REPLACEMENTS:
        factory = replace(factory, before.encode('ascii'), after.encode('ascii'))
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
