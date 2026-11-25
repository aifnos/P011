"""PC-only fresh mechanical graph writer; no tests, SOURCE entry or device IO.

The existing pure definitions supply interface constants only. Neither their
verify_inputs nor any checker/main/runtime function is called by this writer.
Every output is exclusive; the frozen business and historical files are read
only. Re-running --write on an existing output set refuses before any write.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
import types


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/formal-receive-durable-state-v1/'
RUNTIME = PREFIX + 'runtime/'
SELF = PREFIX + 'generate_mechanical.py'
DEFINITIONS = 'host/formal_receive_durable_state_v1_definitions.py'
MANIFEST = 'host/formal_receive_durable_state_v1_definition_manifest.json'
PRIVATE_MANIFEST = 'host/formal_receive_durable_state_v1_private_source_manifest.json'
SPEC = PREFIX + 'exactsource-mechanical-delta.json'
REPORT = PREFIX + 'generation.json'
ORIGINAL = ('host/formal_receive_profile_classification_clock_v1_definitions.py', 16712,
            '3a1cf025b4a088960e6d7a23f44ecac4ff7d3de35082d1c3795e52c377a9169e')
ROOT_BEFORE = 'p011-mta-receive-profile-classification-clock-v1'
ROOT_AFTER = 'p011-mta-rx-durable-v1'
BUSINESS = (
    ('mta_storage', 'candidate/receive-durable-result-v1/runtime/mta_storage.py', 56595,
     '365490e2dfe8a2c65d2b38fc8ae1a49747d09ed3b127677e9fe61e69866052d0'),
    ('mta_transport', 'candidate/receive-durable-result-v1/runtime/mta_transport.py', 41435,
     '9b05ef49059e9b06536de32186e7de1cfd531461d3e096eb266d49f760069f8e'),
    ('mta_client_control_frame', 'candidate/receive-durable-state-v1/runtime/mta_client_control_frame.py', 21203,
     '66eae58a95eaf8344934d15aca2685de1c176b8408a56786995e9f9078c6032c'),
    ('mta_client_executor', 'candidate/receive-durable-state-v1/runtime/mta_client_executor.py', 124794,
     '3882f633913567905c501c888a7ae80dba55615ee2f5ab9b297d016f469f6fcc'),
    ('mta_client_state_bridge', 'candidate/receive-durable-state-v1/runtime/mta_client_state_bridge.py', 21356,
     '239e353c336b678638502d1a3dd612e6ce5110c005b1a0228f697d3af56cdc29'))
BUSINESS_SPEC_PATHS = (
    'candidate/receive-durable-result-v1/exactsource-delta.json',
    'candidate/receive-durable-state-v1/executor-exactsource-delta.json',
    'candidate/receive-durable-state-v1/exactsource-control-bridge-delta.json')
CHANGED = tuple(row[0] for row in BUSINESS) + (
    'mta_client_receive_factory', 'mta_client_receive_boot', 'mta_client_service_owner')
PRIVATE_CHANGED = ('mta_storage', 'mta_transport', 'mta_client_control_frame', 'mta_client_executor')


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return path, len(raw), digest(raw)


def jraw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def read_pin(source):
    path, size, sha = source
    target = BASE / path
    need(target.resolve().is_relative_to(BASE.resolve()), 'input_scope')
    raw = target.read_bytes()
    need((len(raw), digest(raw)) == (size, sha), 'frozen_pin:' + path)
    return raw


def source_function(raw, name):
    text = raw.decode('utf-8')
    nodes = [node for node in ast.parse(text).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(nodes) == 1, 'source_function')
    return ast.get_source_segment(text, nodes[0])


def replay(raw, edits, inverse=False):
    for row in reversed(edits) if inverse else edits:
        before = row['after' if inverse else 'before'].encode('utf-8')
        after = row['before' if inverse else 'after'].encode('utf-8')
        need(before and raw.count(before) == row['count'], 'exact_replay_count:' + row['name'])
        raw = raw.replace(before, after)
    return raw


DEFINITION_TAIL = r'''

def manifest_rows(raw, private=False):
    value = json.loads(raw.decode('ascii'))
    original = json.loads((OLD_PRIVATE_RAW if private else ORIGINAL_MANIFEST_RAW).decode('ascii'))
    keys = {'schema', 'sources', 'previous_manifest_sha256'} if private else {'schema', 'sources'}
    if (type(value) is not dict or set(value) != keys or value['schema'] != original['schema'] or
            type(value['sources']) is not list or len(value['sources']) != 35 or
            private and value['previous_manifest_sha256'] != OLD_PRIVATE_MANIFEST[2]):
        raise ValueError('durable_manifest_shape')
    changed = PRIVATE_CHANGED if private else CHANGED
    rows = []
    for row, before in zip(value['sources'], original['sources']):
        name = before['module']
        if name not in changed:
            if row != before: raise ValueError('durable_unchanged_role')
        elif (type(row) is not dict or set(row) != set(before) or row['module'] != name or
              row['path'] != RUNTIME_PREFIX + name + '.py' or
              type(row['bytes']) is not int or not 0 < row['bytes'] <= 2097152 or
              type(row['sha256']) is not str or len(row['sha256']) != 64 or
              any(char not in '0123456789abcdef' for char in row['sha256'])):
            raise ValueError('durable_changed_role')
        rows.append(('runtime35/' + name if private else name, row['path'], row['bytes'], row['sha256']))
    names = tuple('runtime35/' + name for name in PRIVATE_MODULE_NAMES) if private else MODULE_NAMES
    if tuple(row[0] for row in rows) != names: raise ValueError('durable_role_order')
    return tuple(rows)


def _replay(raw, edits, inverse=False):
    if type(edits) is not list: raise ValueError('durable_delta_edits')
    for row in reversed(edits) if inverse else edits:
        if (type(row) is not dict or set(row) != {'name', 'before', 'after', 'count'} or
                type(row['name']) is not str or type(row['before']) is not str or
                type(row['after']) is not str or not row['before'] or not row['after'] or
                row['before'] == row['after'] or type(row['count']) is not int or row['count'] < 1):
            raise ValueError('durable_delta_edit')
        before = row['after' if inverse else 'before'].encode('utf-8')
        after = row['before' if inverse else 'after'].encode('utf-8')
        if raw.count(before) != row['count']: raise ValueError('durable_delta_count')
        raw = raw.replace(before, after)
    return raw


def verify_inputs(inputs):
    """Flat byte closure; no historical verify_inputs/test/main invocation."""
    for path, size, sha in ORIGIN_SOURCE_PINS:
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha): raise ValueError('durable_origin_pin')
    for path, size, sha in (MANIFEST, PRIVATE_MANIFEST, RUNNER):
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha): raise ValueError('durable_candidate_pin')
    rows = manifest_rows(inputs[MANIFEST[0]])
    private = manifest_rows(inputs[PRIVATE_MANIFEST[0]], private=True)
    ordinary_by_name = {name: (path, size, sha) for name, path, size, sha in rows}
    private_by_name = {name[len('runtime35/'):]: (path, size, sha) for name, path, size, sha in private}
    if (len(rows) != 35 or len(private) != 35 or
            any(private_by_name[name] != ordinary_by_name[name] for name in PRIVATE_CHANGED) or
            ordinary_by_name['mta_client_executor'] != EXECUTOR_PIN or
            'mta_client_service_owner' in private_by_name or
            inputs[ORIGINAL_MANIFEST[0]] != ORIGINAL_MANIFEST_RAW or
            inputs[OLD_PRIVATE_MANIFEST[0]] != OLD_PRIVATE_RAW):
        raise ValueError('durable_domains')
    spec_raw = inputs[DELTA_SPEC[0]]
    if len(spec_raw) > 131072: raise ValueError('durable_delta_budget')
    spec = json.loads(spec_raw.decode('ascii'))
    if (type(spec) is not dict or set(spec) != {'schema', 'evidence', 'root', 'business',
            'mechanical', 'manifests', 'guards', 'totals'} or
            spec['schema'] != 'p011-receive-durable-mechanical-source-delta-v1' or
            spec['evidence'] != 'MECHANICAL_READBACK_NOT_SOURCE_CHECKED' or
            spec['root'] != {'before': ROOT_BEFORE, 'after': ROOT_AFTER} or
            spec['guards'] != FIXED_GUARDS or spec['totals'] != FIXED_TOTALS or
            type(spec['business']) is not list or len(spec['business']) != 5 or
            type(spec['mechanical']) is not list or len(spec['mechanical']) != 9 or
            type(spec['manifests']) is not list or len(spec['manifests']) != 2):
        raise ValueError('durable_delta_shape')
    for entry, expected in zip(spec['business'], BUSINESS_EXPECTED):
        name, before_pin, after_pin, proof_pin = expected
        if (type(entry) is not dict or set(entry) != {'name', 'source', 'candidate', 'proof', 'replacements'} or
                entry['name'] != name or entry['source'] != list(before_pin) or
                entry['candidate'] != list(after_pin) or entry['proof'] != list(proof_pin)):
            raise ValueError('durable_business_identity')
        before, after = inputs[before_pin[0]], inputs[after_pin[0]]
        if (_replay(before, entry['replacements']) != after or
                _replay(after, entry['replacements'], True) != before):
            raise ValueError('durable_business_inverse')
    for entry, expected in zip(spec['mechanical'], MECHANICAL_EXPECTED):
        name, before_pin, after_pin = expected
        if (type(entry) is not dict or set(entry) != {'name', 'source', 'candidate', 'replacements'} or
                entry['name'] != name or entry['source'] != list(before_pin) or
                entry['candidate'] != list(after_pin)):
            raise ValueError('durable_mechanical_identity')
        before, after = inputs[before_pin[0]], inputs[after_pin[0]]
        if (_replay(before, entry['replacements']) != after or
                _replay(after, entry['replacements'], True) != before):
            raise ValueError('durable_mechanical_inverse')
        ast.parse(after.decode('utf-8'), filename=after_pin[0], feature_version=(3, 5))
    for entry, before_pin, after_pin, changes, is_private in zip(spec['manifests'],
            (ORIGINAL_MANIFEST, OLD_PRIVATE_MANIFEST), (MANIFEST, PRIVATE_MANIFEST),
            (CHANGED, PRIVATE_CHANGED), (False, True)):
        if (type(entry) is not dict or set(entry) != {'source', 'candidate', 'changes', 'private'} or
                entry['source'] != list(before_pin) or entry['candidate'] != list(after_pin) or
                entry['private'] is not is_private or type(entry['changes']) is not list or
                len(entry['changes']) != len(changes)):
            raise ValueError('durable_manifest_delta')
        before = json.loads(inputs[before_pin[0]].decode('ascii'))
        after = json.loads(inputs[after_pin[0]].decode('ascii'))
        forward, inverse = json.loads(inputs[before_pin[0]].decode('ascii')), json.loads(inputs[after_pin[0]].decode('ascii'))
        for row, name in zip(entry['changes'], changes):
            if type(row) is not dict or set(row) != {'name', 'before', 'after'} or row['name'] != name:
                raise ValueError('durable_manifest_delta_row')
            index = next(index for index, value in enumerate(before['sources']) if value['module'] == name)
            if row['before'] != before['sources'][index] or row['after'] != after['sources'][index]:
                raise ValueError('durable_manifest_delta_value')
            forward['sources'][index], inverse['sources'][index] = row['after'], row['before']
        if is_private:
            forward['previous_manifest_sha256'] = OLD_PRIVATE_MANIFEST[2]
            inverse['previous_manifest_sha256'] = before['previous_manifest_sha256']
        if (json_bytes(forward) != inputs[after_pin[0]] or
                json_bytes(inverse) != inputs[before_pin[0]]):
            raise ValueError('durable_manifest_inverse')
    payload = rows + HELPERS + private + (WPA, MONITOR)
    total = 0
    for name, path, size, sha in payload:
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha): raise ValueError('durable_payload_pin')
        total += len(raw)
    for name, path, size, sha in FILECENTER_SOURCES:
        raw = inputs[path]
        if (len(raw), digest(raw)) != (size, sha): raise ValueError('durable_filecenter_pin')
    if (len(payload) != 75 or total != PAYLOAD_BYTES or total > 4194304 or
            len(FILECENTER_SOURCES) != 9 or sum(row[2] for row in FILECENTER_SOURCES) != 113690 or
            sum(row[2] for row in FILECENTER_SOURCES) > 131072):
        raise ValueError('durable_original_budget')
    return len(MECHANICAL_EXPECTED)
'''


def build():
    old_raw = read_pin(ORIGINAL)
    old = types.ModuleType('fixed_existing_classification_interfaces')
    old.__file__ = str(BASE / ORIGINAL[0])
    exec(compile(old_raw, old.__file__, 'exec'), old.__dict__)
    old_manifest_raw, old_private_raw = read_pin(old.MANIFEST), read_pin(old.PRIVATE_MANIFEST)
    manifest, private = json.loads(old_manifest_raw), json.loads(old_private_raw)
    need(jraw(manifest) == old_manifest_raw and jraw(private) == old_private_raw, 'manifest_original_serialization')
    old_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in manifest['sources']}
    old_private_rows = {row['module']: (row['path'], row['bytes'], row['sha256']) for row in private['sources']}
    business = {name: (path, size, sha) for name, path, size, sha in BUSINESS}
    proof_pins = tuple(pin(path, (BASE / path).read_bytes()) for path in BUSINESS_SPEC_PATHS)
    proofs = [json.loads(read_pin(value)) for value in proof_pins]
    business_entries = []
    for name in tuple(row[0] for row in BUSINESS):
        source_pin, candidate_pin = old_rows[name], business[name]
        if name in ('mta_storage', 'mta_transport'):
            proof_pin = proof_pins[0]
            found = [entry for entry in proofs[0]['changes'] if entry['candidate'] == candidate_pin[0]]
            need(len(found) == 1 and found[0]['original'] == source_pin[0], 'business_storage_transport_origin')
            edits = found[0]['edits']
        elif name == 'mta_client_executor':
            proof_pin = proof_pins[1]
            value = proofs[1]
            need(value['original'] == source_pin[0] and value['candidate'] == candidate_pin[0], 'business_executor_origin')
            edits = value['edits']
        else:
            proof_pin = proof_pins[2]
            found = [entry for entry in proofs[2]['entries'] if entry['candidate'] == list(candidate_pin)]
            need(len(found) == 1 and found[0]['source'] == list(source_pin), 'business_codec_bridge_origin')
            edits = found[0]['replacements']
        edits = [dict(name=row.get('name', name + '_business_' + str(index)),
                      before=row['before'], after=row['after'], count=row.get('count', 1))
                 for index, row in enumerate(edits)]
        before, after = read_pin(source_pin), read_pin(candidate_pin)
        need(replay(before, edits) == after and replay(after, edits, True) == before, 'business_exact_inverse:' + name)
        business_entries.append(dict(name=name, source=list(source_pin), candidate=list(candidate_pin),
                                     proof=list(proof_pin), replacements=edits))

    outputs, new_pins, mechanical = {}, {}, []
    def create(name, source_pin, transforms):
        before = read_pin(source_pin)
        raw, edits = before, []
        for label, prior, after, count in transforms:
            row = dict(name=label, before=prior, after=after, count=count)
            raw = replay(raw, [row])
            edits.append(row)
        need(replay(raw, edits, True) == before, 'mechanical_inverse:' + name)
        path = RUNTIME + name + '.py'
        ast.parse(raw.decode('utf-8'), filename=path, feature_version=(3, 5))
        outputs[path] = raw
        new_pins[name] = pin(path, raw)
        mechanical.append(dict(name=name, source=list(source_pin), candidate=list(new_pins[name]), replacements=edits))
    def root_change(count):
        return ('isolation_root', ROOT_BEFORE, ROOT_AFTER, count)
    def sha_change(name, count=1):
        return (name + '_sha', old_rows[name][2], new_pins[name][2], count)
    def tuple_change(name, count=1):
        return (name + '_source_tuple', repr((name,) + old_rows[name][1:]),
                repr((name,) + new_pins[name][1:]), count)

    for name in ('mta_storage', 'mta_transport', 'mta_client_control_frame'):
        create(name, business[name], ())
    create('mta_client_executor', business['mta_client_executor'], (
        root_change(1), sha_change('mta_client_control_frame')))
    create('mta_client_state_bridge', business['mta_client_state_bridge'], (
        sha_change('mta_client_executor'), sha_change('mta_client_control_frame')))

    def bind_manifest(value, names, is_private):
        result = copy.deepcopy(value)
        changes = []
        for name in names:
            index = next(index for index, row in enumerate(result['sources']) if row['module'] == name)
            before = dict(result['sources'][index])
            path, size, sha = new_pins[name]
            after = dict(module=name, path=path, bytes=size, sha256=sha)
            result['sources'][index] = after
            changes.append(dict(name=name, before=before, after=after))
        if is_private: result['previous_manifest_sha256'] = old.PRIVATE_MANIFEST[2]
        return result, changes
    private_new, private_changes = bind_manifest(private, PRIVATE_CHANGED, True)
    outputs[PRIVATE_MANIFEST] = jraw(private_new)
    private_pin = pin(PRIVATE_MANIFEST, outputs[PRIVATE_MANIFEST])
    f_before, f_after = old_rows['mta_client_executor'], new_pins['mta_client_executor']
    create('mta_client_receive_factory', old_rows['mta_client_receive_factory'], (
        root_change(2), ('private_manifest_sha', old.PRIVATE_MANIFEST[2], private_pin[2], 1),
        sha_change('mta_client_executor'), sha_change('mta_client_control_frame', 2),
        ('executor_symbolic_tuple', repr(('mta_client_executor', f_before[1], 'F_SHA')).replace("'F_SHA'", 'F_SHA'),
         repr(('mta_client_executor', f_after[1], 'F_SHA')).replace("'F_SHA'", 'F_SHA'), 1),
        # The codec SHA constant changed above; its literal tuple still carries the old SHA.
        ('codec_symbolic_source_tuple', repr(('mta_client_control_frame', old_rows['mta_client_control_frame'][1], new_pins['mta_client_control_frame'][2])),
         repr(('mta_client_control_frame', new_pins['mta_client_control_frame'][1], new_pins['mta_client_control_frame'][2])), 1),
        tuple_change('mta_storage'), tuple_change('mta_transport')))
    create('mta_client_receive_boot', old_rows['mta_client_receive_boot'], (
        root_change(2), ('private_manifest_sha', old.PRIVATE_MANIFEST[2], private_pin[2], 1),
        sha_change('mta_client_executor'),
        ('executor_symbolic_tuple', repr(('mta_client_executor', f_before[1], 'F37_SHA')).replace("'F37_SHA'", 'F37_SHA'),
         repr(('mta_client_executor', f_after[1], 'F37_SHA')).replace("'F37_SHA'", 'F37_SHA'), 2),
        tuple_change('mta_storage'), tuple_change('mta_transport'), tuple_change('mta_client_control_frame'),
        tuple_change('mta_client_receive_factory'), tuple_change('mta_client_state_bridge')))
    create('mta_client_service_owner', old_rows['mta_client_service_owner'], (
        root_change(2), ('boot_pin', 'BOOT_PIN = ' + repr(old_rows['mta_client_receive_boot'][1:]),
                         'BOOT_PIN = ' + repr(new_pins['mta_client_receive_boot'][1:]), 1)))
    runner_changes = [root_change(2)] + [tuple_change(name, 2 if name in PRIVATE_CHANGED else 1) for name in CHANGED]
    create('mta_formal_receive_session', old.RUNNER, runner_changes)
    runner_pin = new_pins['mta_formal_receive_session']

    manifest_new, manifest_changes = bind_manifest(manifest, CHANGED, False)
    outputs[MANIFEST] = jraw(manifest_new)
    manifest_pin = pin(MANIFEST, outputs[MANIFEST])
    new_rows = tuple((row['module'], row['path'], row['bytes'], row['sha256']) for row in manifest_new['sources'])
    new_private_rows = tuple(('runtime35/' + row['module'], row['path'], row['bytes'], row['sha256']) for row in private_new['sources'])
    payload = new_rows + old.HELPERS + new_private_rows + (old.WPA, old.MONITOR)
    need(len(new_rows) == len(new_private_rows) == 35 and len(payload) == 75, 'role_counts')
    total = 0
    for name, path, size, sha in payload:
        raw = outputs[path] if path in outputs else read_pin((path, size, sha))
        need((len(raw), digest(raw)) == (size, sha), 'payload_identity')
        total += len(raw)
    need(total <= 4194304, 'payload_budget')
    need(old.FILECENTER_SOURCES == old.FILECENTER_SOURCE_PINS and len(old.FILECENTER_SOURCES) == 9 and
         sum(row[2] for row in old.FILECENTER_SOURCES) == 113690, 'filecenter_unchanged')
    guards = dict(role_count=75, ordinary_count=35, private_count=35, payload_cap=4194304,
                  source_cap=2097152, target_line_cap=256, filecenter_count=9, filecenter_cap=131072,
                  startup_seconds=10, prepare_seconds=120, owner_seconds=600, cleanup_seconds=60,
                  business_changed_roles=5, ordinary_changed_roles=8, private_changed_roles=4,
                  gui_changed=False, native_changed=False, resource_gates_changed=False,
                  historical_verifier_called=False, device_tested=False)
    totals = dict(payload_bytes=total, payload_remaining=4194304 - total, filecenter_bytes=113690)
    manifests = [dict(source=list(old.MANIFEST), candidate=list(manifest_pin), changes=manifest_changes, private=False),
                 dict(source=list(old.PRIVATE_MANIFEST), candidate=list(private_pin), changes=private_changes, private=True)]
    spec = dict(schema='p011-receive-durable-mechanical-source-delta-v1',
                evidence='MECHANICAL_READBACK_NOT_SOURCE_CHECKED', root=dict(before=ROOT_BEFORE, after=ROOT_AFTER),
                business=business_entries, mechanical=mechanical, manifests=manifests, guards=guards, totals=totals)
    outputs[SPEC] = jraw(spec)
    need(len(outputs[SPEC]) <= 131072, 'delta_budget')
    delta_pin = pin(SPEC, outputs[SPEC])
    generator_pin = pin(SELF, (BASE / SELF).read_bytes())
    source_pins = tuple(dict.fromkeys(tuple(old.ORIGIN_SOURCE_PINS) +
        (ORIGINAL, old.MANIFEST, old.PRIVATE_MANIFEST, old.RUNNER) + tuple(old_rows.values()) +
        tuple(old_private_rows.values()) + tuple(business.values()) + proof_pins + (generator_pin, delta_pin)))
    by_path = {}
    for value in source_pins:
        need(value[0] not in by_path or by_path[value[0]] == value, 'source_pin_conflict')
        by_path[value[0]] = value
        if value[0] != SPEC: read_pin(value)

    header = '\n'.join((
        '"""Flat mechanical durable receive graph; source preparation, not device acceptance."""',
        'import ast', 'import hashlib', 'import json', 'from pathlib import Path', 'import types', '',
        'BASE = Path(__file__).resolve().parents[1]', 'ORIGINAL = ' + repr(ORIGINAL),
        'MANIFEST = ' + repr(manifest_pin), 'PRIVATE_MANIFEST = ' + repr(private_pin),
        'RUNNER = ' + repr(runner_pin), 'EXECUTOR_PIN = ' + repr(new_pins['mta_client_executor']),
        'DELTA_SPEC = ' + repr(delta_pin), 'GENERATOR_PIN = ' + repr(generator_pin),
        'ORIGINAL_MANIFEST = ' + repr(old.MANIFEST), 'OLD_PRIVATE_MANIFEST = ' + repr(old.PRIVATE_MANIFEST),
        'RUNTIME_PREFIX = ' + repr(RUNTIME), 'ROOT_BEFORE = ' + repr(ROOT_BEFORE), 'ROOT_AFTER = ' + repr(ROOT_AFTER),
        "STATE_ALIAS = '/tmp/" + ROOT_AFTER + "'", "STATE_ROOT = '/var/volatile/tmp/" + ROOT_AFTER + "'",
        'CHANGED = ' + repr(CHANGED), 'PRIVATE_CHANGED = ' + repr(PRIVATE_CHANGED),
        'PAYLOAD_BYTES = ' + str(total), 'FIXED_GUARDS = ' + repr(guards), 'FIXED_TOTALS = ' + repr(totals),
        'ORIGIN_SOURCE_PINS = ' + repr(source_pins), 'SOURCE_PINS = ORIGIN_SOURCE_PINS',
        'BUSINESS_SOURCE_PINS = ' + repr(BUSINESS), 'BUSINESS_DELTA_PINS = ' + repr(proof_pins),
        'BUSINESS_EXPECTED = ' + repr(tuple((entry['name'], tuple(entry['source']), tuple(entry['candidate']), tuple(entry['proof'])) for entry in business_entries)),
        'MECHANICAL_EXPECTED = ' + repr(tuple((entry['name'], tuple(entry['source']), tuple(entry['candidate'])) for entry in mechanical)), '',
        'def digest(raw):', '    return hashlib.sha256(raw).hexdigest()', '',
        'def read_pin(source):', '    raw = (BASE / source[0]).read_bytes()',
        "    if (len(raw), digest(raw)) != source[1:]: raise ValueError('durable_source_pin')", '    return raw', '',
        'def json_bytes(value):', "    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\\n').encode('ascii')", '',
        'ORIGINAL_RAW = read_pin(ORIGINAL)', "_old = types.ModuleType('fixed_existing_classification_interfaces')",
        '_old.__file__ = str(BASE / ORIGINAL[0])', "exec(compile(ORIGINAL_RAW, _old.__file__, 'exec'), _old.__dict__)",
        'CHECKER, TRANSPORT = _old.CHECKER, _old.TRANSPORT',
        'BASE_ORIGINAL, BASE_ORIGINAL_RAW = _old.BASE_ORIGINAL, _old.BASE_ORIGINAL_RAW',
        'HELPERS, WPA, MONITOR = _old.HELPERS, _old.WPA, _old.MONITOR',
        'MODULE_NAMES, PRIVATE_MODULE_NAMES = _old.MODULE_NAMES, _old.PRIVATE_MODULE_NAMES',
        'TRIAL_BOOL_FIELDS, TRIAL_REASONS, TRIAL_FIELDS = _old.TRIAL_BOOL_FIELDS, _old.TRIAL_REASONS, _old.TRIAL_FIELDS',
        'TARGET_COMMON, TARGET_SERVICE = _old.TARGET_COMMON, _old.TARGET_SERVICE',
        'load_checker, _short_chunks = _old.load_checker, _old._short_chunks',
        'parse_trial_facts = _old.parse_trial_facts',
        'FILECENTER_SOURCES = _old.FILECENTER_SOURCES', 'FILECENTER_SOURCE_PINS = FILECENTER_SOURCES',
        'ORIGINAL_MANIFEST_RAW = read_pin(ORIGINAL_MANIFEST)', 'OLD_PRIVATE_RAW = read_pin(OLD_PRIVATE_MANIFEST)', ''))
    raw = (header + DEFINITION_TAIL + '\n\n' + source_function(old_raw, 'make_source') + '\n').encode('utf-8')
    ast.parse(raw.decode('utf-8'), filename=DEFINITIONS)
    outputs[DEFINITIONS] = raw
    report = dict(schema='p011-receive-durable-mechanical-generation-v1',
        status='MECHANICAL_GENERATED_NOT_SOURCE_CHECKED', totals=totals, guards=guards,
        ordinary_changed_roles=list(CHANGED), private_changed_roles=list(PRIVATE_CHANGED),
        source_origin_count=len(source_pins), runtime_definition_closure_count=len(mechanical),
        outputs=[list(pin(path, value)) for path, value in sorted(outputs.items())],
        source_check_executed=False, tests_executed=False, old_verifier_executed=False,
        device_tested=False, gui_included=False, file_transfer_tested=False, restoration_verified=False)
    outputs[REPORT] = jraw(report)
    return outputs, report


def main():
    need(sys.argv[1:] == ['--write'], 'explicit_fresh_write_required')
    outputs, report = build()
    # Resolve every destination and reject the whole set before the first write.
    for path in outputs:
        target = BASE / path
        need((path.startswith(PREFIX) or path in (DEFINITIONS, MANIFEST, PRIVATE_MANIFEST)) and
             target.resolve().is_relative_to(BASE.resolve()) and not target.exists(), 'fresh_output:' + path)
    for path, raw in outputs.items():
        target = BASE / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            need(handle.write(raw) == len(raw), 'mechanical_write')
        need(target.read_bytes() == raw, 'mechanical_readback:' + path)
    print(json.dumps(dict(status=report['status'], output_count=len(outputs), **report['totals']), sort_keys=True))


if __name__ == '__main__':
    main()
