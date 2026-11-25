"""Pure maker/parser for the actual Startup proc inner-guard model benchmark.

Only the pinned _live_profile Startup branch body is selected: the original
If or the candidate If+For, wrapped without editing its AST nodes in guard().
Neither the whole profile nor its outer guards, lifecycle, clock or IO runs.
Independent ordinary type realms provide fresh function/code identities only.
The parent owns the pre-stdin alarm, real stock probes, transport and raw logs.
This is inner-guard model elapsed/process CPU, never startup/RF acceptance.
"""
import ast
import base64
import copy
import hashlib
import math
import zlib

PINS = (
    ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_factory.py',
     99675, '3f0ca3d039301a221fce10b5b72cb50e0bf6d374298656879ff748de61ec5cf5'),
    ('candidate/receive-profile-proc-dispatch-v1/runtime/mta_client_receive_factory.py',
     99717, '3349e76e6da45d4948edde640e44829bb1eeb554156b91c686f2a6b655422b47'))
SCHEMA = 'p011-profile-proc-dispatch-bench-v1-model'
CALLS_PER_BLOCK = 8192
GROUPS = 4
CALL_COUNT = 131072
WARMUP_EACH = 128
AST_SOURCE_LIMIT = 2 * 1024 * 1024
TARGET_LIMIT = 48000
TARGET_MAX_LINE = 256
OUTPUT_LIMIT = 65536
RESULT_PREFIX = 'MODEL_RESULT='
ROW_FIELDS = frozenset(('group', 'position', 'side', 'calls', 'elapsed_start',
                       'elapsed_end', 'cpu_start', 'cpu_end', 'elapsed_seconds',
                       'process_cpu_seconds'))
SCOPE = dict(actual_owner_lifecycle_called=False, other_method_bodies_called=False,
             real_io_called=False, rf_called=False, ui_called=False,
             startup_certified=False, interoperability_certified=False,
             alarm_cancelled=False, model_only=True, inner_guard_model_only=True)


def _need(value, code):
    if value is not True:
        raise ValueError(code)


def _shape(node):
    return ast.dump(node, include_attributes=False)


def _startup(node):
    wanted = _shape(ast.parse('type(attempt) is _StartupReadScope', mode='eval').body)
    rows = [value for value in ast.walk(node) if isinstance(value, ast.If) and
            _shape(value.test) == wanted]
    _need(len(rows) == 1, 'fixed_startup_branch_unique')
    return rows[0]


def _tree(raw):
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    methods = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
               node.name == '_live_profile']
    _need(len(methods) == 1 and not methods[0].decorator_list, 'fixed_whole_profile_unique')
    return methods[0], _startup(methods[0])


def _contract(old, new, before, after):
    """Check the finite rewrite; only a deep copy is restored for comparison."""
    _need(len(before.body) == 1 and isinstance(before.body[0], ast.If) and
          len(after.body) == 2 and isinstance(after.body[0], ast.If) and
          isinstance(after.body[1], ast.For), 'fixed_original_if_candidate_if_for')
    original, prefix, loop = before.body[0], after.body[0], after.body[1]
    _need(isinstance(original.test, ast.BoolOp) and isinstance(original.test.op, ast.Or) and
          isinstance(prefix.test, ast.BoolOp) and isinstance(prefix.test.op, ast.Or) and
          len(original.test.values) == len(prefix.test.values) + 1 and
          [_shape(value) for value in original.test.values[:-1]] ==
          [_shape(value) for value in prefix.test.values] and
          [_shape(value) for value in original.body] == [_shape(value) for value in prefix.body] and
          not original.orelse and not prefix.orelse, 'fixed_all_prefix_guards_and_failure')
    call = original.test.values[-1]
    _need(isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'any' and
          len(call.args) == 1 and not call.keywords and isinstance(call.args[0], ast.GeneratorExp),
          'fixed_original_any_generator')
    generator = call.args[0]
    _need(len(generator.generators) == 1 and not generator.generators[0].ifs and
          not generator.generators[0].is_async and not loop.orelse and
          len(loop.body) == 1 and isinstance(loop.body[0], ast.If), 'fixed_direct_ordered_loop')
    comp, check = generator.generators[0], loop.body[0]
    _need(_shape(comp.target) == _shape(loop.target) and _shape(comp.iter) == _shape(loop.iter) and
          _shape(generator.elt) == _shape(check.test) and not check.orelse and
          [_shape(value) for value in check.body] == [_shape(value) for value in original.body],
          'fixed_same_current_type_identity_code_and_first_failure')
    _need(isinstance(loop.iter, ast.Call) and isinstance(loop.iter.func, ast.Name) and
          loop.iter.func.id == 'zip' and len(loop.iter.args) == 3 and not loop.iter.keywords and
          isinstance(loop.iter.args[0], ast.Tuple) and len(loop.iter.args[0].elts) == 6 and
          isinstance(loop.iter.args[1], ast.Name) and loop.iter.args[1].id == 'functions' and
          isinstance(loop.iter.args[2], ast.Name) and loop.iter.args[2].id == 'codes',
          'fixed_six_fresh_function_and_code_receipts')
    _need(len(before.orelse) == len(after.orelse) == 1 and
          _shape(before.orelse[0]) == _shape(after.orelse[0]), 'fixed_publication_branch_unchanged')
    restored = copy.deepcopy(new)
    _startup(restored).body = copy.deepcopy(before.body)
    _need(_shape(restored) == _shape(old), 'fixed_entire_profile_ast_restored')


def _fragment(raw, method):
    """Retain the whole method's bytes and positions; it is parsed, never run."""
    lines = raw.decode('ascii').splitlines(keepends=True)
    _need(type(method.lineno) is int and type(method.end_lineno) is int and
          1 <= method.lineno <= method.end_lineno <= len(lines), 'fixed_method_span')
    result = ['\n'] * method.end_lineno
    result[method.lineno - 1:method.end_lineno] = lines[method.lineno - 1:method.end_lineno]
    source = ''.join(result)
    rows = ast.parse(source, feature_version=(3, 5)).body
    _need(len(rows) == 1 and isinstance(rows[0], ast.FunctionDef) and
          ast.dump(rows[0], include_attributes=True) == ast.dump(method, include_attributes=True),
          'whole_profile_source_node_unchanged')
    return source


def _literal(name, value):
    raw = value.encode('ascii')
    _need(0 < len(raw) <= AST_SOURCE_LIMIT, 'ast_source_budget')
    payload = base64.b64encode(zlib.compress(raw)).decode('ascii')
    parts = [repr(payload[index:index + 128]) for index in range(0, len(payload), 128)]
    _need(parts and all(len(part) + 4 <= TARGET_MAX_LINE for part in parts), 'literal_budget')
    return (name + ' = zlib.decompress(base64.b64decode(\n' +
            ''.join('    ' + part + '\n' for part in parts) + ')).decode(\'ascii\')\n')


TARGET_BODY = r'''
import ast, math, sys, time, types

def need(value, code):
    if value is not True:
        raise RuntimeError(code)

def finite(value):
    return type(value) is float and math.isfinite(value) and value >= 0.0

def guard_code(source, candidate):
    tree = ast.parse(source)
    need(len(tree.body) == 1 and type(tree.body[0]) is ast.FunctionDef and
         tree.body[0].name == '_live_profile', 'model_whole_profile_ast_only')
    wanted = ast.dump(ast.parse('type(attempt) is _StartupReadScope', mode='eval').body)
    rows = [node for node in ast.walk(tree.body[0]) if type(node) is ast.If and ast.dump(node.test) == wanted]
    need(len(rows) == 1, 'model_inner_startup_unique')
    selected = rows[0].body
    need((not candidate and len(selected) == 1 and type(selected[0]) is ast.If) or
         (candidate and len(selected) == 2 and type(selected[0]) is ast.If and type(selected[1]) is ast.For),
         'model_exact_inner_guard_inventory')
    original = tuple(ast.dump(node, include_attributes=True) for node in selected)
    wrapper = ast.parse('def guard(attempt, files, clock, functions, codes):\n    pass\n').body[0]
    # Python 3.5 Module accepts body only. Selected nodes are never edited.
    wrapper.body = list(selected)
    need(tuple(ast.dump(node, include_attributes=True) for node in wrapper.body) == original,
         'model_inner_nodes_unedited')
    return compile(ast.Module(body=[wrapper]), '<actual-startup-inner-guard-only>', 'exec')

def model_fail(code):
    raise RuntimeError(code)

DUMMY_SOURCE = """
def __init__(*args):
    raise RuntimeError('model_lifecycle_called')
def _originals(*args):
    raise RuntimeError('model_lifecycle_called')
def check_active(*args):
    raise RuntimeError('model_clock_called')
def alias_now(*args):
    raise RuntimeError('model_clock_called')
def check(*args):
    raise RuntimeError('model_io_called')
def _fixed_tmp_alias(*args):
    raise RuntimeError('model_io_called')
"""

def make_guard_model(code, label):
    module = types.ModuleType('fixed_profile_proc_inner_guard_model_' + label)
    namespace = module.__dict__
    namespace.update(types=types, _fail=model_fail)
    # Fresh definitions/code receipts per realm. Their bodies are NEVER called.
    exec(compile(DUMMY_SOURCE, '<identity-only-dummy-functions-' + label + '>', 'exec'), namespace)
    names = ('__init__', '_originals', 'check_active', 'alias_now', 'check', '_fixed_tmp_alias')
    functions = tuple(namespace[name] for name in names)
    codes = tuple(value.__code__ for value in functions)
    scope_type = type('_StartupReadScope', (object,), {name: namespace[name] for name in names[:4]})
    read_owner_type = type('_ReadOwner', (object,), {name: namespace[name] for name in names[4:]})
    files_type = type('InnerGuardFilesDataOnly', (object,), {})
    namespace.update(_StartupReadScope=scope_type, executor=types.SimpleNamespace(_ReadOwner=read_owner_type),
                     _STARTUP_ALIAS_ORIGINALS=functions, _STARTUP_ALIAS_CODES=codes)
    attempt, files = object.__new__(scope_type), object.__new__(files_type)
    attempt._files_original = files
    attempt._alias_functions, attempt._alias_codes = functions, codes
    clock = types.MethodType(functions[3], attempt)
    exec(code, namespace)
    guard = namespace['guard']
    need(type(scope_type) is type and type(read_owner_type) is type and type(files_type) is type and
         type(attempt) is scope_type and type(files) is files_type and
         type(guard) is types.FunctionType and guard.__globals__ is namespace and
         all(type(value) is types.FunctionType and value.__globals__ is namespace and
             value.__code__ is receipt for value, receipt in zip(functions, codes)), 'model_normal_fresh_bindings')
    return guard, attempt, files, clock, functions, codes

need(sys.version_info[:2] == (3, 5), 'model_target_python_version')
elapsed_clock = getattr(time, 'monotonic', None)
cpu_clock = getattr(time, 'process_time', None)
need(callable(elapsed_clock) and callable(cpu_clock), 'model_cpu_clock_unavailable')
models = (make_guard_model(guard_code(ORIGINAL_PROFILE_SOURCE, False), 'A'),
          make_guard_model(guard_code(CANDIDATE_PROFILE_SOURCE, True), 'B'))
need(models[0][0].__globals__ is not models[1][0].__globals__ and
     type(models[0][1]) is not type(models[1][1]) and
     all(left is not right for left, right in zip(models[0][4], models[1][4])) and
     all(left is not right for left, right in zip(models[0][5], models[1][5])), 'model_independent_namespaces')
for function, attempt, files, clock, functions, codes in models:
    for unused in range(WARMUP_EACH):
        returned = function(attempt, files, clock, functions, codes)
    need(returned is None and attempt._files_original is files and
         attempt._alias_functions is functions and attempt._alias_codes is codes, 'model_warmup_normal')

rows = []
previous_elapsed = previous_cpu = None
for group in range(GROUPS):
    for position, side in enumerate('ABBA'):
        function, attempt, files, clock, functions, codes = models[0 if side == 'A' else 1]
        elapsed_start = elapsed_clock()
        cpu_start = cpu_clock()
        # One actual inner-guard AST call, not a whole profile/lifecycle call.
        for unused in range(CALLS_PER_BLOCK):
            function(attempt, files, clock, functions, codes)
        cpu_end = cpu_clock()
        elapsed_end = elapsed_clock()
        need(all(finite(value) for value in (elapsed_start, elapsed_end, cpu_start, cpu_end)), 'model_clock_finite')
        need(elapsed_end >= elapsed_start and cpu_end >= cpu_start and
             (previous_elapsed is None or elapsed_start >= previous_elapsed) and
             (previous_cpu is None or cpu_start >= previous_cpu), 'model_clock_monotonic')
        elapsed = elapsed_end - elapsed_start
        cpu = cpu_end - cpu_start
        need(finite(elapsed) and finite(cpu) and 0.0 < elapsed <= 30.0 and cpu <= 30.0, 'model_duration')
        need(attempt._files_original is files and attempt._alias_functions is functions and
             attempt._alias_codes is codes, 'model_fields_unchanged')
        rows.append(dict(group=group, position=position, side=side, calls=CALLS_PER_BLOCK,
                         elapsed_start=elapsed_start, elapsed_end=elapsed_end, cpu_start=cpu_start,
                         cpu_end=cpu_end, elapsed_seconds=elapsed, process_cpu_seconds=cpu))
        previous_elapsed, previous_cpu = elapsed_end, cpu_end
need(len(rows) == 16 and sum(row['calls'] for row in rows) == CALL_COUNT, 'model_fixed_work')
need(sum(row['elapsed_seconds'] for row in rows) <= 30.0 and
     sum(row['process_cpu_seconds'] for row in rows) <= 30.0, 'model_total_duration')
result = dict(schema=SCHEMA, complete=True, python_version=tuple(sys.version_info[:3]),
              clock_scope='MONOTONIC_ELAPSED_AND_PROCESS_CPU', cpu_clock_available=True,
              groups=GROUPS, order='ABBA', calls_per_block=CALLS_PER_BLOCK,
              call_count=CALL_COUNT, warmup_each=WARMUP_EACH, warmup_calls=2 * WARMUP_EACH,
              blocks=tuple(rows), scope=SCOPE)
output = 'MODEL_RESULT=' + repr(result)
need(len(output.encode('ascii')) <= OUTPUT_LIMIT, 'model_output_budget')
print(output)
'''


def make_source(inputraws):
    """Return source bytes only; the parent supplies exactly the two frozen inputs."""
    _need(type(inputraws) is dict and set(inputraws) == {row[0] for row in PINS}, 'fixed_input_keys')
    parsed = []
    for path, size, checksum in PINS:
        raw = inputraws[path]
        _need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) ==
              (size, checksum), 'fixed_source_pin')
        parsed.append(_tree(raw))
    old, before = parsed[0]
    new, after = parsed[1]
    _contract(old, new, before, after)
    original = _fragment(inputraws[PINS[0][0]], old)
    candidate = _fragment(inputraws[PINS[1][0]], new)
    header = ('import base64, zlib\nSCHEMA=' + repr(SCHEMA) + '\n' +
              'CALLS_PER_BLOCK=8192\nGROUPS=4\nCALL_COUNT=131072\nWARMUP_EACH=128\nOUTPUT_LIMIT=65536\n' +
              'SCOPE={\n' + ''.join('    ' + repr(key) + ': ' + repr(value) + ',\n'
                                   for key, value in SCOPE.items()) + '}\n')
    source = (header + _literal('ORIGINAL_PROFILE_SOURCE', original) +
              _literal('CANDIDATE_PROFILE_SOURCE', candidate) + TARGET_BODY).encode('ascii')
    _need(0 < len(source) <= TARGET_LIMIT and max(map(len, source.splitlines())) <= TARGET_MAX_LINE, 'target_budget')
    ast.parse(source.decode('ascii'), feature_version=(3, 5))
    return source


def _finite(value):
    return type(value) is float and math.isfinite(value) and value >= 0.0


def parse(raw):
    """Strict MODEL_RESULT parser; original bytes/exit status stay parent-owned."""
    _need(type(raw) is bytes and 0 < len(raw) <= OUTPUT_LIMIT, 'model_raw_budget')
    text = raw.decode('ascii').replace('\r\r\n', '\n').replace('\r\n', '\n')
    lines = [line for line in text.split('\n') if line]
    result_lines = [line for line in lines if line.startswith(RESULT_PREFIX)]
    extras = [line for line in lines if not line.startswith(RESULT_PREFIX)]
    _need(len(result_lines) == 1 and
          (extras == [] or extras == ['MTA_REMOTE_OK', 'MTA_REMOTE_EXIT=0']), 'model_result_framing')
    value = ast.literal_eval(result_lines[0][len(RESULT_PREFIX):])
    expected = {'schema', 'complete', 'python_version', 'clock_scope', 'cpu_clock_available',
                'groups', 'order', 'calls_per_block', 'call_count', 'warmup_each',
                'warmup_calls', 'blocks', 'scope'}
    _need(type(value) is dict and set(value) == expected and value['schema'] == SCHEMA and
          type(value['schema']) is str and value['complete'] is True and
          value['clock_scope'] == 'MONOTONIC_ELAPSED_AND_PROCESS_CPU' and
          type(value['clock_scope']) is str and value['cpu_clock_available'] is True and
          value['order'] == 'ABBA' and type(value['order']) is str, 'model_schema')
    for field, count in (('groups', GROUPS), ('calls_per_block', CALLS_PER_BLOCK),
                         ('call_count', CALL_COUNT), ('warmup_each', WARMUP_EACH),
                         ('warmup_calls', 2 * WARMUP_EACH)):
        _need(type(value[field]) is int and value[field] == count, 'model_work_schema')
    version = value['python_version']
    _need(type(version) is tuple and len(version) == 3 and all(type(part) is int for part in version) and
          version[:2] == (3, 5) and 0 <= version[2] <= 99, 'model_target_version')
    _need(type(value['scope']) is dict and set(value['scope']) == set(SCOPE) and
          all(value['scope'][key] is wanted for key, wanted in SCOPE.items()), 'model_scope')
    blocks = value['blocks']
    _need(type(blocks) is tuple and len(blocks) == 16, 'model_block_count')
    previous_elapsed = previous_cpu = None
    for index, row in enumerate(blocks):
        _need(type(row) is dict and set(row) == ROW_FIELDS and
              type(row['group']) is int and row['group'] == index // 4 and
              type(row['position']) is int and row['position'] == index % 4 and
              type(row['side']) is str and row['side'] == 'ABBA'[index % 4] and
              type(row['calls']) is int and row['calls'] == CALLS_PER_BLOCK, 'model_block_identity')
        times = ('elapsed_start', 'elapsed_end', 'cpu_start', 'cpu_end', 'elapsed_seconds', 'process_cpu_seconds')
        _need(all(_finite(row[field]) for field in times), 'model_block_finite')
        _need(row['elapsed_end'] >= row['elapsed_start'] and row['cpu_end'] >= row['cpu_start'] and
              row['elapsed_seconds'] == row['elapsed_end'] - row['elapsed_start'] and
              row['process_cpu_seconds'] == row['cpu_end'] - row['cpu_start'] and
              0.0 < row['elapsed_seconds'] <= 30.0 and row['process_cpu_seconds'] <= 30.0 and
              (previous_elapsed is None or row['elapsed_start'] >= previous_elapsed) and
              (previous_cpu is None or row['cpu_start'] >= previous_cpu), 'model_block_clock')
        previous_elapsed, previous_cpu = row['elapsed_end'], row['cpu_end']
    _need(sum(row['calls'] for row in blocks) == CALL_COUNT and
          sum(row['elapsed_seconds'] for row in blocks) <= 30.0 and
          sum(row['process_cpu_seconds'] for row in blocks) <= 30.0, 'model_fixed_total')
    return value
