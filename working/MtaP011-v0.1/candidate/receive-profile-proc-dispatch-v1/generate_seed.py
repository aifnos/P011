"""One immutable Startup proc-guard dispatch seed; explicit EXCL --write only.

The sole business change replaces _live_profile's six-entry Startup any(generator)
tail with the same ordered direct for. Publication and every clock/IO/cache remain
unchanged. prepare() only reads frozen source and derives bytes; no source module,
old builder, test, device or runtime method is executed.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/receive-profile-proc-dispatch-v1/generate_seed.py'
FACTORY = 'candidate/receive-profile-proc-dispatch-v1/runtime/mta_client_receive_factory.py'
DELTA = 'candidate/receive-profile-proc-dispatch-v1/exactsource-delta.json'
MOTHER = ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_factory.py', 99675,
          '3f0ca3d039301a221fce10b5b72cb50e0bf6d374298656879ff748de61ec5cf5')
SOURCE_PAYLOAD = 4193768
PAYLOAD_LIMIT = 4194304
BEFORE = (
    '                        clock.__func__ is not functions[3] or\n'
    '                        any(type(current) is not types.FunctionType or current is not original or\n'
    '                            current.__code__ is not code for current, original, code in zip(\n'
    '                                (_StartupReadScope.__init__, _StartupReadScope._originals, _StartupReadScope.check_active,\n'
    '                                 _StartupReadScope.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias),\n'
    '                                functions, codes))):\n'
    "                    _fail('startup_owner_changed')\n")
AFTER = (
    '                        clock.__func__ is not functions[3]):\n'
    "                    _fail('startup_owner_changed')\n"
    '                for current, original, code in zip(\n'
    '                        (_StartupReadScope.__init__, _StartupReadScope._originals, _StartupReadScope.check_active,\n'
    '                         _StartupReadScope.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias),\n'
    '                        functions, codes):\n'
    '                    if (type(current) is not types.FunctionType or current is not original or\n'
    '                            current.__code__ is not code):\n'
    "                        _fail('startup_owner_changed')\n")
EDITS = ((BEFORE, AFTER, 1),)


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


def function(raw):
    text = raw.decode('ascii')
    rows = [node for node in ast.parse(text, feature_version=(3, 5)).body
            if isinstance(node, ast.FunctionDef) and node.name == '_live_profile']
    need(len(rows) == 1 and not rows[0].decorator_list, 'seed_single_original_function')
    return ast.get_source_segment(text, rows[0])


def replay(raw, inverse=False):
    for before, after, count in reversed(EDITS) if inverse else EDITS:
        before, after = (after, before) if inverse else (before, after)
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == count, 'seed_exact_anchor')
        raw = raw.replace(before, after)
    return raw


def shape(node):
    return ast.dump(node, include_attributes=False)


def startup_branch(node):
    branches = [item for item in ast.walk(node) if isinstance(item, ast.If) and
                shape(item.test) == shape(ast.parse('type(attempt) is _StartupReadScope', mode='eval').body)]
    need(len(branches) == 1, 'seed_single_startup_branch')
    return branches[0]


def restore_dispatch(old_node, new_node):
    """Validate the sole finite rewrite, then restore the entire method AST."""
    original, current = startup_branch(old_node), startup_branch(new_node)
    need(len(original.body) == 1 and isinstance(original.body[0], ast.If) and
         len(current.body) == 2 and isinstance(current.body[0], ast.If) and
         isinstance(current.body[1], ast.For), 'seed_single_prefix_then_loop')
    old_if, new_if, loop = original.body[0], current.body[0], current.body[1]
    need(isinstance(old_if.test, ast.BoolOp) and isinstance(old_if.test.op, ast.Or) and
         isinstance(new_if.test, ast.BoolOp) and isinstance(new_if.test.op, ast.Or) and
         len(old_if.test.values) == len(new_if.test.values) + 1,
         'seed_tail_any_only')
    need([shape(v) for v in old_if.test.values[:-1]] == [shape(v) for v in new_if.test.values] and
         [shape(v) for v in old_if.body] == [shape(v) for v in new_if.body] and
         not old_if.orelse and not new_if.orelse, 'seed_all_prefix_short_circuit_and_fail_unchanged')
    call = old_if.test.values[-1]
    need(isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'any' and
         len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.GeneratorExp),
         'seed_original_any_generator')
    generator = call.args[0]
    need(len(generator.generators) == 1 and not generator.generators[0].ifs and
         not generator.generators[0].is_async and not loop.orelse and
         len(loop.body) == 1 and isinstance(loop.body[0], ast.If), 'seed_plain_ordered_for')
    comp, check = generator.generators[0], loop.body[0]
    need(shape(comp.target) == shape(loop.target) and shape(comp.iter) == shape(loop.iter) and
         shape(generator.elt) == shape(check.test) and not check.orelse and
         [shape(v) for v in check.body] == [shape(v) for v in old_if.body],
         'seed_same_fresh_tuple_type_is_code_and_first_failure')
    need(isinstance(loop.iter, ast.Call) and isinstance(loop.iter.func, ast.Name) and
         loop.iter.func.id == 'zip' and len(loop.iter.args) == 3 and not loop.iter.keywords and
         isinstance(loop.iter.args[0], ast.Tuple) and len(loop.iter.args[0].elts) == 6 and
         isinstance(loop.iter.args[1], ast.Name) and loop.iter.args[1].id == 'functions' and
         isinstance(loop.iter.args[2], ast.Name) and loop.iter.args[2].id == 'codes',
         'seed_exact_six_current_and_original_code_inputs')
    need(shape(original.orelse[0]) == shape(current.orelse[0]) and
         len(original.orelse) == len(current.orelse) == 1, 'seed_publication_branch_unchanged')
    restored = copy.deepcopy(new_node)
    branch = startup_branch(restored)
    branch.body[0].test.values.append(copy.deepcopy(call))
    branch.body.pop()
    need(shape(restored) == shape(old_node), 'seed_entire_method_ast_restored')
    return restored


def derive(raw):
    need((len(raw), digest(raw)) == MOTHER[1:], 'seed_frozen_mother')
    before = function(raw).encode('ascii')
    after = replay(before)
    need(replay(after, True) == before and raw.count(before) == 1,
         'seed_whole_function_byte_inverse')
    candidate = raw.replace(before, after, 1)
    restored = candidate.replace(after, before, 1)
    need(restored == raw and ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'seed_complete_byte_position_ast_inverse')
    old_node, new_node = (ast.parse(value.decode('ascii'), feature_version=(3, 5)).body[0]
                          for value in (before, after))
    restore_dispatch(old_node, new_node)
    for name, value in (('before', raw), ('after', candidate)):
        text = value.decode('ascii')
        rows = tuple((type(node).__name__, node.name, ast.get_source_segment(text, node))
                     for node in ast.walk(ast.parse(text, feature_version=(3, 5)))
                     if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != '_live_profile')
        if name == 'before':
            original_rows = rows
        else:
            need(rows == original_rows, 'seed_other_definition_bytes_unchanged')
    growth = len(candidate) - len(raw)
    need(growth == 42 and 0 < growth <= 536 and len(candidate) < 100000 and
         SOURCE_PAYLOAD + growth <= PAYLOAD_LIMIT, 'seed_actual_payload_spare536')
    need(len(candidate.splitlines()) - len(raw.splitlines()) == 2, 'seed_exact_two_line_delta')
    return candidate


def prepare():
    raw = fixed(MOTHER)
    own = scoped(SELF).read_bytes()
    candidate = derive(raw)
    growth = len(candidate) - len(raw)
    spec = dict(schema='p011-receive-profile-proc-dispatch-v1-exactsource-delta',
        origin=dict(path=MOTHER[0], bytes=len(raw), sha256=digest(raw)),
        candidate=dict(path=FACTORY, bytes=len(candidate), sha256=digest(candidate)),
        business_delta_count=1, business_methods=['_live_profile'], byte_delta=growth,
        later_definition_line_delta=len(candidate.splitlines()) - len(raw.splitlines()),
        replacements=[dict(before=before, after=after, count=count) for before, after, count in EDITS],
        complete_byte_inverse=True, complete_ast_inverse=True, entire_method_ast_restore=True,
        other_definition_bytes_unchanged=True, startup_proc_scan_rows=6,
        same_order_and_fresh_tuple_inputs=True, failure_short_circuit_preserved=True,
        prefix_guards_and_failure_code_unchanged=True, original_code_receipts_still_required=True,
        publication_branch_unchanged=True, unchanged_clock_io_and_cache=True,
        local_binding_delta=['current', 'original', 'code'], additional_clock_calls=0,
        additional_io_calls=0, guards_removed=False, deadlines_changed=False,
        io_boundaries_changed=False, permission_cache_created=False,
        source_payload_bytes=SOURCE_PAYLOAD, prospective_payload_bytes=SOURCE_PAYLOAD + growth,
        prospective_payload_remaining=PAYLOAD_LIMIT - SOURCE_PAYLOAD - growth,
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
        byte_delta=facts['byte_delta'], prospective_payload_bytes=facts['prospective_payload_bytes'],
        prospective_payload_remaining=facts['prospective_payload_remaining']), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
