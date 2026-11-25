"""PC-only finite publication-progress source derivation; no target execution.

Only Factory.__call__ gains cache-only tuple assignments. The phone observer
reads that tuple after its existing canonical active-attempt checks. Cached
sample deltas are not real-time/call durations, admission or closure evidence.
Default SOURCE plans writes nothing; --write creates four fresh artifacts.
This is not a 75-role package, phone parser integration or hardware test.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys


BASE = Path(__file__).resolve().parents[2]
PREFIX = 'candidate/receive-publication-progress-v1/'
SELF = PREFIX + 'generate.py'
FACTORY_SOURCE = ('candidate/receive-proc-freezer-v1/runtime/mta_client_receive_factory.py',
    97757, '051b1f6d1e1823be652f59695628d41f9d11c3d1da1896149dc4cfe3c7b207cb')
PHONE_SOURCE = ('candidate/receive-handoff-progress-120s-v2/runtime/phone_discovery_session.py',
    26305, '15540ef933e3c18853f8ab650e8ddc4aa902c2499eec3a7538f6f178e295ddf4')
FACTORY_TARGET = PREFIX + 'runtime/mta_client_receive_factory.py'
PHONE_TARGET = PREFIX + 'runtime/phone_discovery_session.py'
DELTA = PREFIX + 'publication-exactsource-delta.json'
GENERATION = PREFIX + 'publication-generation.json'
STEPS = ('start', 'io', 'sources', 'wpa', 'json_pin', 'profile', 'received',
         'identity', 'manifest', 'write', 'loader')
FIELDS = ('publication_step', 'publication_sources_done', 'publication_sample_elapsed',
          'publication_step_elapsed', 'publication_progress_unknown')
FACTORY_GROWTH_CAP = 2538


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return [path, len(raw), digest(raw)]


def scoped(relative):
    path = BASE / relative
    need(not path.is_symlink() and path.resolve().is_relative_to(BASE.resolve()), 'pc_path_scope')
    return path


def source_inputs():
    return (FACTORY_SOURCE, PHONE_SOURCE)


def load_inputs():
    inputs = {}
    for path, size, sha in source_inputs():
        raw = scoped(path).read_bytes()
        need((len(raw), digest(raw)) == (size, sha), 'frozen_source_pin')
        inputs[path] = raw
    inputs[SELF] = scoped(SELF).read_bytes()
    return inputs


def before(name, anchor, assignment):
    return dict(name=name, before=anchor, after=assignment + anchor)


def marker(step):
    return ("            attempt._prepdiag = ('" + step + "', attempt._prepdiag[1],\n"
            "                                 attempt._prepdiag[2], attempt.last)\n")


FACTORY_EDITS = (
    before('initialize_private_tuple', '        try:\n            attempt.start()\n',
           "        attempt._prepdiag = ('start', 0, None, None)\n"),
    before('original_start_return_sample', '            attempt.files = _Files(attempt)\n',
           "            attempt._prepdiag = ('io', 0, attempt.last, attempt.last)\n"),
    before('each_source_begin', "                raw = attempt.files.read(ASSET_PHYSICAL_ROOT + '/runtime35/' + name + '.py',\n",
           "                attempt._prepdiag = ('sources', attempt._prepdiag[1],\n"
           "                                     attempt._prepdiag[2], attempt.last)\n"),
    dict(name='each_verified_payload_completed',
         before='                payloads[name] = raw\n            attempt.payloads = payloads\n',
         after='                payloads[name] = raw\n'
               "                attempt._prepdiag = ('sources', attempt._prepdiag[1] + 1,\n"
               '                                     attempt._prepdiag[2], attempt._prepdiag[3])\n'
               '            attempt.payloads = payloads\n'),
    before('wpa_begin', "            attempt.wpa = attempt.files.read(ASSET_PHYSICAL_ROOT + '/native/mta-wpa-supplicant',\n", marker('wpa')),
    before('json_pin_begin', '            # JSON definitions are fixed bytes; do not re-execute the running F.\n', marker('json_pin')),
    before('live_profile_begin', '            attempt.profile = _live_profile(attempt)\n', marker('profile')),
    before('received_directory_begin', '            attempt.receive_metadata = executor._receive_directory(attempt.files.io,\n', marker('received')),
    before('directory_identity_begin', '            attempt.directory_identity_rows = attempt.received_directory.identity_rows()\n', marker('identity')),
    before('manifest_begin', '            with attempt.state.lock:\n                attempt.now()\n                metadata = ', marker('manifest')),
    before('original_write_begin', "            attempt.phase = 'write'; attempt.writer = _Writer(attempt)\n", marker('write')),
    before('original_loader_begin', "            attempt.phase = 'loader'; attempt.now()\n", marker('loader')),
)

PHONE_EMPTY = ("    {name}.update(publication_step=None, publication_sources_done=None,\n"
               "                 publication_sample_elapsed=None, publication_step_elapsed=None,\n"
               "                 publication_progress_unknown={unknown})\n")
PHONE_PROJECTION = """        # Private DATA only: no active methods, extra clock, IO or lock.
        progress = getattr(active, '_prepdiag', None)
        last = active.last
        if (type(progress) is not tuple or len(progress) != 4 or
                type(progress[0]) is not str or progress[0] not in
                ('start', 'io', 'sources', 'wpa', 'json_pin', 'profile', 'received',
                 'identity', 'manifest', 'write', 'loader') or
                type(progress[1]) is not int or not 0 <= progress[1] <= 35):
            return known
        step, completed, origin, entered = progress
        if step == 'start':
            if (completed != 0 or origin is not None or entered is not None or
                    getattr(active, '_prepdiag', None) is not progress or active.last is not last):
                return known
            known.update(publication_step=step, publication_sources_done=completed,
                         publication_progress_unknown=False)
            return known
        if (step == 'io' and completed != 0 or step not in ('io', 'sources') and completed != 35 or
                any(type(value) is not float for value in (origin, entered, last)) or
                not 0 <= origin <= entered <= last <= 1e12 or not 0 <= last - origin <= 300 or
                getattr(active, '_prepdiag', None) is not progress or active.last is not last):
            return known
        known.update(publication_step=step, publication_sources_done=completed,
                     publication_sample_elapsed=last - origin,
                     publication_step_elapsed=last - entered, publication_progress_unknown=False)
"""
PHONE_EDITS = (
    dict(name='private_unknown_defaults',
         before='    unknown.update(factory_phase=None, stage_unknown=True)\n',
         after='    unknown.update(factory_phase=None, stage_unknown=True)\n' +
               PHONE_EMPTY.format(name='unknown', unknown='True')),
    dict(name='private_known_defaults',
         before='    known.update(factory_phase=None, stage_unknown=False)\n',
         after='    known.update(factory_phase=None, stage_unknown=False)\n' +
               PHONE_EMPTY.format(name='known', unknown='True')),
    dict(name='finite_cached_projection_after_original_binding',
         before='        known.update(factory_active_present=True, factory_phase=active.phase,\n'
                '                     factory_ended=active.ended, factory_success=active.success)\n'
                '        return known\n',
         after='        known.update(factory_active_present=True, factory_phase=active.phase,\n'
               '                     factory_ended=active.ended, factory_success=active.success)\n' +
               PHONE_PROJECTION + '        return known\n'),
)


def transform(raw, edits):
    result, records = raw, []
    for entry in edits:
        old, new = entry['before'].encode('ascii'), entry['after'].encode('ascii')
        need(result.count(old) == 1 and result.count(new) == 0, 'forward_edit_unique:' + entry['name'])
        offset = result.index(old)
        result = result[:offset] + new + result[offset + len(old):]
        records.append(dict(entry, offset=offset))
    inverse = result
    for entry in reversed(records):
        old, new, offset = entry['before'].encode('ascii'), entry['after'].encode('ascii'), entry['offset']
        need(inverse[offset:offset + len(new)] == new, 'inverse_edit_offset')
        inverse = inverse[:offset] + old + inverse[offset + len(new):]
    need(inverse == raw, 'complete_byte_inverse')
    ast.parse(result.decode('ascii'), feature_version=(3, 5))
    need(ast.dump(ast.parse(inverse.decode('ascii')), include_attributes=True) ==
         ast.dump(ast.parse(raw.decode('ascii')), include_attributes=True), 'complete_ast_inverse')
    return result, records


def method_node(raw, class_name, method_name):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    parent = tree.body if class_name is None else [node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name]
    if class_name is not None:
        need(len(parent) == 1, 'single_actual_class')
        parent = parent[0].body
    nodes = [node for node in parent if isinstance(node, ast.FunctionDef) and node.name == method_name]
    need(len(nodes) == 1, 'single_actual_method')
    return nodes[0]


def is_diag_assignment(node):
    return (isinstance(node, ast.Assign) and len(node.targets) == 1 and
        isinstance(node.targets[0], ast.Attribute) and node.targets[0].attr == '_prepdiag' and
        isinstance(node.targets[0].value, ast.Name) and node.targets[0].value.id == 'attempt')


def original_call_ast(candidate_raw):
    """HOST proof seam: AST of actual candidate __call__, removing only 12 markers."""
    method = copy.deepcopy(method_node(candidate_raw, 'FixedReceiveDeploymentFactory', '__call__'))
    added = [node for node in ast.walk(method) if is_diag_assignment(node)]
    need(len(added) == 12 and all(not any(isinstance(child, ast.Call) for child in ast.walk(node))
                                for node in added), 'twelve_cache_only_assignments')
    class Strip(ast.NodeTransformer):
        def visit_Assign(self, node):
            return None if is_diag_assignment(node) else self.generic_visit(node)
    return Strip().visit(method)


def definitions(raw):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    return dict((node.name, ast.dump(node, include_attributes=False))
                for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def build_factory(raw):
    need((len(raw), digest(raw)) == FACTORY_SOURCE[1:], 'factory_original_pin')
    candidate, records = transform(raw, FACTORY_EDITS)
    need(0 < len(candidate) - len(raw) <= FACTORY_GROWTH_CAP, 'factory_75_payload_growth_cap')
    old_method = method_node(raw, 'FixedReceiveDeploymentFactory', '__call__')
    stripped = original_call_ast(candidate)
    need(ast.dump(stripped, include_attributes=False) == ast.dump(old_method, include_attributes=False),
         'actual_call_complete_business_ast_unchanged')
    old, new = definitions(raw), definitions(candidate)
    old_class = method_node(raw, 'FixedReceiveDeploymentFactory', '__call__')
    tree = ast.parse(candidate.decode('ascii'), feature_version=(3, 5))
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'FixedReceiveDeploymentFactory')
    cls.body = [copy.deepcopy(old_class) if isinstance(node, ast.FunctionDef) and node.name == '__call__'
                else node for node in cls.body]
    restored = dict((node.name, ast.dump(node, include_attributes=False)) for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef)))
    need(restored == old and set(new) == set(old), 'all_other_factory_definitions_unchanged')
    return candidate, records


def build_phone(raw):
    need((len(raw), digest(raw)) == PHONE_SOURCE[1:], 'phone_original_pin')
    candidate, records = transform(raw, PHONE_EDITS)
    old, new = definitions(raw), definitions(candidate)
    need(set(old) == set(new) and all(old[name] == new[name] for name in old if name != 'stage_progress'),
         'only_phone_stage_progress_definition_changed')
    return candidate, records


def assemble(inputs):
    """Pure byte/AST derivation from saved actual sources; does not import target code."""
    need(type(inputs) is dict and set(inputs) == {FACTORY_SOURCE[0], PHONE_SOURCE[0], SELF}, 'fixed_three_inputs')
    factory, factory_records = build_factory(inputs[FACTORY_SOURCE[0]])
    phone, phone_records = build_phone(inputs[PHONE_SOURCE[0]])
    facts = dict(schema='p011-receive-publication-progress-v1-generation',
        status='MECHANICALLY_DERIVED_NOT_HOST_OR_DEVICE_TESTED', generator=pin(SELF, inputs[SELF]),
        source_pins=[list(row) for row in source_inputs()], source_count=3,
        step_names=list(STEPS), phone_fields=list(FIELDS), source_completion_cap=35,
        tuple_attribute='_prepdiag', tuple_fields=['step', 'sources_done', 'origin_sample', 'step_start_sample'],
        origin='cached attempt.last after original attempt.start returns',
        time_semantics='successful cached sample deltas, not live time or exact call durations',
        initial_start_elapsed=None, factory_growth_bytes=len(factory) - FACTORY_SOURCE[1],
        factory_growth_cap=2538, original_finally_raise_write_loader_ast_unchanged=True,
        other_factory_definitions_unchanged=True, only_phone_stage_progress_changed=True,
        original_clock_io_lock_trace_calls_unchanged=True, malformed_diag_preserves_original_known=True,
        original_phone_parser_requires_new_finite_fields=True, role75_packaged=False,
        tests_executed=False, source_checked_by_host=False, device_executed=False,
        rf_started=False, phone_tested=False, admission=False, restoration_verified=False)
    delta = dict(schema='p011-receive-publication-progress-v1-exact-source-delta',
        generator=facts['generator'], source_pins=facts['source_pins'],
        edits=[dict(source=list(FACTORY_SOURCE), candidate=pin(FACTORY_TARGET, factory), records=factory_records),
               dict(source=list(PHONE_SOURCE), candidate=pin(PHONE_TARGET, phone), records=phone_records)])
    outputs = {FACTORY_TARGET: factory, PHONE_TARGET: phone,
               DELTA: (json.dumps(delta, sort_keys=True, indent=2) + '\n').encode('ascii')}
    facts['output_pins'] = [pin(path, raw) for path, raw in sorted(outputs.items())]
    outputs[GENERATION] = (json.dumps(facts, sort_keys=True, indent=2) + '\n').encode('ascii')
    return outputs, facts


def main():
    args = sys.argv[1:]
    need(args in ([], ['--write']), 'source_only_or_explicit_write')
    inputs = load_inputs()
    outputs, facts = assemble(inputs)
    if not args:
        print(json.dumps(dict(mode='SOURCE_PLAN_NO_WRITES', source_pins=facts['source_pins'],
            planned_bytes=dict((path, len(raw)) for path, raw in outputs.items()),
            factory_growth_bytes=facts['factory_growth_bytes'], factory_growth_cap=2538,
            output_written=False, future_output_pins_published=False, tests_executed=False), sort_keys=True))
        return 0
    for relative in outputs:
        need(relative.startswith(PREFIX) and not scoped(relative).exists(), 'fresh_output_only')
    for relative, raw in outputs.items():
        path = scoped(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'fresh_output_short_write')
        need(path.read_bytes() == raw, 'fresh_output_readback')
    need(load_inputs() == inputs, 'all_three_original_inputs_preserved')
    print(json.dumps(dict(status=facts['status'], outputs=[pin(path, raw) for path, raw in sorted(outputs.items())],
                         tests_executed=False, device_executed=False), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
