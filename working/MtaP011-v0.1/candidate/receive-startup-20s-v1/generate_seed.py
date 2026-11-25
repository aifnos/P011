"""Independent authorized prepare-20 seed, never a replacement of 10s history.

Only STARTUP_READ_SECONDS = 10.0 becomes 20.0 at equal byte length. All class
and function source bytes/position AST, identity/IO guards, cleanup and outer
caps remain exact. prepare() returns (outputs, facts, inputs) without writing;
only explicit --write publishes missing EXCL or accepts completely equal bytes.
No target module, old builder/test, device, runtime or phone is executed here.
"""
import ast
import hashlib
import json
from pathlib import Path
import stat
import sys

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/receive-startup-20s-v1/generate_seed.py'
FACTORY = 'candidate/receive-startup-20s-v1/runtime/mta_client_receive_factory.py'
DELTA = 'candidate/receive-startup-20s-v1/exactsource-delta.json'
MOTHER = ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_factory.py', 99675,
          '3f0ca3d039301a221fce10b5b72cb50e0bf6d374298656879ff748de61ec5cf5')
BEFORE, AFTER = 'STARTUP_READ_SECONDS = 10.0\n', 'STARTUP_READ_SECONDS = 20.0\n'
SOURCE_PAYLOAD, PAYLOAD_LIMIT = 4193768, 4194304


def need(value, code):
    if value is not True:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def jraw(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def scoped(path):
    need(type(path) is str and path and '\\' not in path and ':' not in path and
         not path.startswith('/') and all(p not in ('', '.', '..') for p in path.split('/')),
         'seed_path')
    for node in reversed((BASE,) + tuple(BASE.parents)):
        value = node.lstat()
        need(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and
             not getattr(value, 'st_file_attributes', 0) & 0x400, 'seed_base_ancestor')
    target = BASE
    parts = path.split('/')
    for index, part in enumerate(parts):
        target = target / part
        try:
            value = target.lstat()
        except FileNotFoundError:
            continue
        need(not stat.S_ISLNK(value.st_mode) and not getattr(value, 'st_file_attributes', 0) & 0x400,
             'seed_link')
        if index < len(parts) - 1:
            need(stat.S_ISDIR(value.st_mode), 'seed_ancestor')
    need(target.resolve().is_relative_to(BASE.resolve()), 'seed_scope')
    return target


def fixed(row):
    path = scoped(row[0])
    need(stat.S_ISREG(path.lstat().st_mode), 'seed_regular_source')
    raw = path.read_bytes()
    need((len(raw), digest(raw)) == row[1:], 'seed_frozen_mother')
    return raw


def definition_rows(raw):
    text = raw.decode('ascii')
    tree = ast.parse(text, feature_version=(3, 5))
    return tuple((type(node).__name__, node.name, ast.get_source_segment(text, node),
                  ast.dump(node, include_attributes=True)) for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)))


def derive(raw):
    need((len(raw), digest(raw)) == MOTHER[1:], 'seed_frozen_mother')
    before, after = BEFORE.encode('ascii'), AFTER.encode('ascii')
    need(len(before) == len(after) and raw.count(before) == 1 and raw.count(after) == 0,
         'seed_single_equal_length_constant')
    candidate = raw.replace(before, after, 1)
    restored = candidate.replace(after, before, 1)
    need(restored == raw and len(candidate) == len(raw), 'seed_complete_byte_inverse')
    need(ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'seed_complete_position_ast_inverse')
    original, current = (ast.parse(value.decode('ascii'), feature_version=(3, 5)) for value in (raw, candidate))
    need(len(original.body) == len(current.body), 'seed_module_inventory')
    changed = []
    for old, new in zip(original.body, current.body):
        if ast.dump(old, include_attributes=True) == ast.dump(new, include_attributes=True):
            continue
        need(isinstance(old, ast.Assign) and isinstance(new, ast.Assign) and len(old.targets) == 1 and
             ast.dump(old.targets[0], include_attributes=True) == ast.dump(new.targets[0], include_attributes=True) and
             isinstance(old.targets[0], ast.Name) and old.targets[0].id == 'STARTUP_READ_SECONDS' and
             ast.literal_eval(old.value) == 10.0 and type(ast.literal_eval(old.value)) is float and
             ast.literal_eval(new.value) == 20.0 and type(ast.literal_eval(new.value)) is float,
             'seed_only_authorized_float_assignment')
        changed.append(old.targets[0].id)
    need(changed == ['STARTUP_READ_SECONDS'] and definition_rows(candidate) == definition_rows(raw),
         'seed_all_class_function_bytes_position_ast_exact')
    need(SOURCE_PAYLOAD <= PAYLOAD_LIMIT and len(candidate.splitlines()) == len(raw.splitlines()),
         'seed_equal_length_payload_and_lines')
    return candidate


def prepare():
    raw = fixed(MOTHER)
    own = scoped(SELF).read_bytes()
    candidate = derive(raw)
    spec = dict(schema='p011-receive-startup-20s-v1-exactsource-delta',
        origin=dict(path=MOTHER[0], bytes=len(raw), sha256=digest(raw)),
        candidate=dict(path=FACTORY, bytes=len(candidate), sha256=digest(candidate)),
        business_delta_count=1, business_constants=['STARTUP_READ_SECONDS'], business_methods=[],
        byte_delta=0, later_definition_line_delta=0,
        replacements=[dict(before=BEFORE, after=AFTER, count=1)],
        complete_byte_inverse=True, complete_ast_inverse=True,
        all_class_function_bytes_unchanged=True, all_class_function_position_ast_unchanged=True,
        startup_prepare_seconds_before=10.0, startup_prepare_seconds_after=20.0,
        independent_candidate_only=True, original_10s_sources_and_history_unchanged=True,
        additional_clock_calls=0, additional_io_calls=0, guards_removed=False,
        io_boundaries_changed=False, permission_cache_created=False, profile_cache_changed=False,
        outer_60_plus_60_caps_changed=False, alarm240_changed=False, host250_changed=False,
        stage_close_caps_changed=False, original_factory_prepare_seconds_changed=False,
        source_payload_bytes=SOURCE_PAYLOAD, prospective_payload_bytes=SOURCE_PAYLOAD,
        prospective_payload_remaining=PAYLOAD_LIMIT - SOURCE_PAYLOAD,
        proc_dispatch_candidate_integrated=False, automatic_phone_window_requested=False,
        measured_performance_claim=False, device_executed=False, rf_executed=False)
    outputs = {FACTORY: candidate, DELTA: jraw(spec)}
    inputs = {MOTHER[0]: raw, SELF: own}
    need(all(scoped(path).read_bytes() == value for path, value in inputs.items()), 'seed_inputs_preserved')
    return outputs, spec, inputs


def write_outputs(outputs, inputs):
    need(type(outputs) is dict and set(outputs) == {FACTORY, DELTA} and
         all(type(raw) is bytes for raw in outputs.values()), 'seed_two_outputs')
    paths = {}
    for path, raw in outputs.items():
        target = scoped(path)
        if target.exists():
            need(stat.S_ISREG(target.lstat().st_mode) and target.read_bytes() == raw,
                 'seed_existing_not_identical')
        paths[path] = target
    need(all(scoped(path).read_bytes() == raw for path, raw in inputs.items()), 'seed_before_write_preserved')
    for path, raw in outputs.items():
        target = paths[path]
        if target.exists():
            need(scoped(path).read_bytes() == raw, 'seed_existing_changed')
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with scoped(path).open('xb') as stream:
                need(stream.write(raw) == len(raw), 'seed_exclusive_short_write')
        need(scoped(path).read_bytes() == raw, 'seed_output_readback')
    need(all(scoped(path).read_bytes() == raw for path, raw in inputs.items()), 'seed_after_write_preserved')


def main():
    need(sys.argv[1:] in ([], ['--write']), 'seed_plan_or_explicit_write')
    outputs, facts, inputs = prepare()
    if sys.argv[1:]:
        write_outputs(outputs, inputs)
    print(json.dumps(dict(mode='EXCL_OR_EXACT' if sys.argv[1:] else 'PURE_PLAN_NO_WRITES',
        outputs=[(path, len(raw), digest(raw)) for path, raw in outputs.items()],
        byte_delta=0, prospective_payload_bytes=facts['prospective_payload_bytes'],
        prospective_payload_remaining=facts['prospective_payload_remaining'],
        startup_prepare_seconds=facts['startup_prepare_seconds_after']), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
