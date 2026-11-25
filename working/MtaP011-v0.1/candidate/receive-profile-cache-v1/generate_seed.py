"""One immutable Factory cache-only seed; default pure plan, explicit --write.

Only _live_profile gains an empty tuple and six copies of existing last values.
No source module, test, device, clock, IO or old builder is executed here.
prepare() returns (outputs, facts, inputs); outputs are the Factory and delta.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys

BASE = Path(__file__).resolve().parents[2]
SELF = 'candidate/receive-profile-cache-v1/generate_seed.py'
FACTORY = 'candidate/receive-profile-cache-v1/runtime/mta_client_receive_factory.py'
DELTA = 'candidate/receive-profile-cache-v1/exactsource-delta.json'
MOTHER = ('candidate/receive-fc-http-cap-graph-v1/runtime/mta_client_receive_factory.py', 99371,
          'e1e02b700b51ca40dffc536622ab69647d58b93788b1458eb9db0f9cf017612b')
LABELS = ('python', 'proc', 'daemon', 'namespace', 'endpoint', 'continuity')
EDITS = (
    ('    files = attempt.files\n',
     '    attempt.profile_cache = ()\n    files = attempt.files\n', 1),
    ("    attempt.now(); names = os.listdir('/proc')\n",
     "    attempt.now()\n    attempt.profile_cache += (attempt.last,)\n    names = os.listdir('/proc')\n", 1),
    ("    if len(found) != 1: _fail('publication_daemon_data')\n",
     "    attempt.profile_cache += (attempt.last,)\n    if len(found) != 1: _fail('publication_daemon_data')\n", 1),
    ('    namespace_rows = []\n',
     '    attempt.profile_cache += (attempt.last,)\n    namespace_rows = []\n', 1),
    ("    unix = files.read('/proc/' + str(attempt.pid) + '/net/unix', 1048576, proc=True)[0]\n",
     "    attempt.profile_cache += (attempt.last,)\n    unix = files.read('/proc/' + str(attempt.pid) + '/net/unix', 1048576, proc=True)[0]\n", 1),
    ("    if not socket_refs: _fail('publication_endpoint_data')\n",
     "    if not socket_refs: _fail('publication_endpoint_data')\n    attempt.profile_cache += (attempt.last,)\n", 1),
    ("    return {'python_exe': PYTHON, 'python_sha': python_sha,\n",
     "    attempt.profile_cache += (attempt.last,)\n    return {'python_exe': PYTHON, 'python_sha': python_sha,\n", 1))


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


def replay(raw, edits, inverse=False):
    for row in reversed(edits) if inverse else edits:
        before, after, count = row
        before, after = (after, before) if inverse else (before, after)
        before, after = before.encode('ascii'), after.encode('ascii')
        need(raw.count(before) == count, 'seed_exact_anchor')
        raw = raw.replace(before, after)
    return raw


def cache_target(node):
    return (isinstance(node, ast.Attribute) and node.attr == 'profile_cache' and
            isinstance(node.value, ast.Name) and node.value.id == 'attempt')


def remove_cache_assignments(node):
    current, removed = copy.deepcopy(node), []
    for item in current.body:
        if isinstance(item, ast.Assign) and len(item.targets) == 1 and cache_target(item.targets[0]):
            need(isinstance(item.value, ast.Tuple) and not item.value.elts, 'seed_empty_tuple_only')
            removed.append(item)
        elif isinstance(item, ast.AugAssign) and cache_target(item.target):
            need(isinstance(item.op, ast.Add) and isinstance(item.value, ast.Tuple) and
                 len(item.value.elts) == 1 and isinstance(item.value.elts[0], ast.Attribute) and
                 item.value.elts[0].attr == 'last' and isinstance(item.value.elts[0].value, ast.Name) and
                 item.value.elts[0].value.id == 'attempt', 'seed_existing_last_only')
            removed.append(item)
    need(len(removed) == 7 and isinstance(removed[0], ast.Assign) and
         all(isinstance(item, ast.AugAssign) for item in removed[1:]), 'seed_seven_top_level_assignments')
    current.body = [item for item in current.body if item not in removed]
    return current


def derive(raw):
    need((len(raw), digest(raw)) == MOTHER[1:], 'seed_frozen_mother')
    before = function(raw).encode('ascii')
    after = replay(before, EDITS)
    inverse = replay(after, EDITS, True)
    need(inverse == before and raw.count(before) == 1, 'seed_whole_function_byte_inverse')
    candidate = raw.replace(before, after, 1)
    restored = candidate.replace(after, before, 1)
    need(restored == raw and ast.dump(ast.parse(restored), include_attributes=True) ==
         ast.dump(ast.parse(raw), include_attributes=True), 'seed_complete_byte_position_ast_inverse')
    old_node, new_node = (ast.parse(value.decode('ascii'), feature_version=(3, 5)).body[0]
                          for value in (before, after))
    need(ast.dump(old_node, include_attributes=False) ==
         ast.dump(remove_cache_assignments(new_node), include_attributes=False),
         'seed_no_other_control_call_return_or_guard_delta')
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
    need(0 < growth <= 500 and len(candidate) < 100000 and 4193464 + growth <= 4194304,
         'seed_actual_payload_spare840')
    return candidate


def prepare():
    raw = fixed(MOTHER)
    own = scoped(SELF).read_bytes()
    candidate = derive(raw)
    growth = len(candidate) - len(raw)
    spec = dict(schema='p011-receive-profile-cache-v1-exactsource-delta',
        origin=dict(path=MOTHER[0], bytes=len(raw), sha256=digest(raw)),
        candidate=dict(path=FACTORY, bytes=len(candidate), sha256=digest(candidate)),
        business_delta_count=1, business_methods=['_live_profile'], byte_delta=growth,
        later_definition_line_delta=len(candidate.splitlines()) - len(raw.splitlines()),
        replacements=[dict(before=before, after=after, count=count) for before, after, count in EDITS],
        complete_byte_inverse=True, complete_ast_inverse=True, other_definition_bytes_unchanged=True,
        cache_field='profile_cache', cache_labels=list(LABELS), cache_initial_tuple=True,
        cache_append_count=6, cached_original_last_only=True, no_other_call_or_control_delta=True,
        additional_clock_calls=0, additional_io_calls=0, guards_removed=False,
        deadlines_changed=False, io_boundaries_changed=False, permission_cache_created=False,
        source_payload_bytes=4193464, prospective_payload_bytes=4193464 + growth,
        prospective_payload_remaining=4194304 - 4193464 - growth,
        precise_wall_time_claim=False, measured_performance_claim=False,
        device_executed=False, rf_executed=False)
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
