"""Pure PC maker/parser for one bounded P011 Owner dispatch microbenchmark.

No filesystem, process, transport or benchmark is invoked by importing this
module.  The parent supplies two already retained fixed source byte strings,
sets the target's 30-second alarm before stdin read, and owns raw/stock/sealing.
Only the actual original/new _context method bodies are called on field models.
This measures model elapsed/process CPU, never startup or RF acceptance.
"""
import ast
import base64
import hashlib
import math
import zlib

PINS = (
    ('candidate/receive-publication-progress-graph-v1/runtime/mta_client_service_owner.py',
     107026, 'a33b1a4c015bda42fc8ab8ba447fd5f331181df1a5b4240fc82f455dc2b74da7'),
    ('candidate/receive-owner-dispatch-v1/runtime/mta_client_service_owner.py',
     107104, '22aa94d8d5ae2a1dd75c5c98635d80020b318f7071ea84c5c3cb3d85e2805adf'))
SCHEMA = 'p011-owner-dispatch-bench-v1-model'
METHOD_NAMES = (
    '_seal_filecenter_directories', '_filecenter_directory_current', 'create_filecenter',
    '_filecenter_definitions_current', '_filecenter_current', '_capture_filecenter_partial',
    '_filecenter_partial_current', '_close_filecenter', '_filecenter_closed')
CALLS_PER_BLOCK = 8192
GROUPS = 4
WARMUP_EACH = 128
CALL_COUNT = 131072
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
             alarm_cancelled=False, model_only=True)


def _need(value, code):
    if value is not True:
        raise ValueError(code)


def _tree(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    owners = [node for node in tree.body if isinstance(node, ast.ClassDef) and
              node.name == 'FixedStateServiceOwner']
    errors = [node for node in tree.body if isinstance(node, ast.ClassDef) and
              node.name == 'ServiceOwnerError']
    fails = [node for node in tree.body if isinstance(node, ast.FunctionDef) and
             node.name == '_fail']
    _need(len(owners) == len(errors) == len(fails) == 1, 'fixed_owner_inventory')
    wanted = ('__init__', '_context') + METHOD_NAMES
    methods = {node.name: node for node in owners[0].body if isinstance(node, ast.FunctionDef)
               and node.name in wanted}
    _need(len(methods) == len(wanted) and set(methods) == set(wanted) and
          all(not node.decorator_list for node in methods.values()), 'fixed_method_inventory')
    return tree, owners[0], errors[0], fails[0], methods


def _fragment(raw, owner, selected, top=()):
    """Retain each selected node's original bytes/locations, not an unparse."""
    lines = raw.decode('utf-8').splitlines(keepends=True)
    last = max(node.end_lineno for node in tuple(top) + tuple(selected))
    result = ['\n'] * last
    _need(owner.lineno == 255 and lines[254] == 'class FixedStateServiceOwner(object):\n',
          'fixed_owner_header')
    result[254] = lines[254]
    for node in tuple(top) + tuple(selected):
        _need(type(node.lineno) is int and type(node.end_lineno) is int and
              1 <= node.lineno <= node.end_lineno <= len(lines), 'fixed_node_span')
        result[node.lineno - 1:node.end_lineno] = lines[node.lineno - 1:node.end_lineno]
    source = ''.join(result)
    parsed = ast.parse(source, feature_version=(3, 5))
    rebuilt_owner = [node for node in parsed.body if isinstance(node, ast.ClassDef) and
                     node.name == 'FixedStateServiceOwner']
    _need(len(rebuilt_owner) == 1, 'fragment_owner_unique')
    rebuilt = {node.name: node for node in rebuilt_owner[0].body if isinstance(node, ast.FunctionDef)}
    _need(set(rebuilt) == {node.name for node in selected}, 'fragment_method_inventory')
    for node in selected:
        _need(ast.dump(rebuilt[node.name], include_attributes=True) ==
              ast.dump(node, include_attributes=True), 'method_node_unchanged')
    for node in top:
        matches = [value for value in parsed.body if isinstance(value, type(node)) and
                   getattr(value, 'name', None) == node.name]
        _need(len(matches) == 1 and ast.dump(matches[0], include_attributes=True) ==
              ast.dump(node, include_attributes=True), 'failure_node_unchanged')
    return source


def _literal(name, value):
    # Fixed source is decoded/parsed outside timing; bound stdin echo as well.
    raw = value.encode('utf-8')
    _need(0 < len(raw) <= AST_SOURCE_LIMIT, 'ast_source_budget')
    payload = base64.b64encode(zlib.compress(raw)).decode('ascii')
    parts = [repr(payload[index:index + 128]) for index in range(0, len(payload), 128)]
    _need(parts and all(len(part) + 4 <= TARGET_MAX_LINE for part in parts), 'literal_budget')
    return (name + ' = zlib.decompress(base64.b64decode(\n' +
            ''.join('    ' + part + '\n' for part in parts) + ')).decode(\'utf-8\')\n')


TARGET_BODY = r'''
import ast, math, sys, time, types

def need(value, code):
    if value is not True:
        raise RuntimeError(code)

def finite(value):
    return type(value) is float and math.isfinite(value) and value >= 0.0

def common_code(source):
    tree = ast.parse(source)
    owner = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'FixedStateServiceOwner']
    errors = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ServiceOwnerError']
    fails = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_fail']
    need(len(owner) == len(errors) == len(fails) == 1, 'model_definition_inventory')
    methods = [n for n in owner[0].body if isinstance(n, ast.FunctionDef)]
    need(len(methods) == 10 and set(n.name for n in methods) == set(('__init__',) + METHOD_NAMES), 'model_method_inventory')
    # Python 3.5 Module accepts body only.  No selected node is edited/fixed.
    return compile(ast.Module(body=errors + fails + methods), '<fixed-owner-common-definitions>', 'exec')

def context_code(source):
    tree = ast.parse(source)
    owner = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'FixedStateServiceOwner']
    need(len(owner) == 1 and len(owner[0].body) == 1, 'model_context_unique')
    node = owner[0].body[0]
    need(type(node) is ast.FunctionDef and node.name == '_context', 'model_context_definition')
    return compile(ast.Module(body=[node]), '<fixed-owner-context-definition>', 'exec')

def make_model(common, context, label):
    module = types.ModuleType('fixed_owner_dispatch_model_' + label)
    namespace = module.__dict__
    boot = types.ModuleType('fixed_owner_dispatch_boot_' + label)
    namespace.update(types=types, sys=types.SimpleNamespace(modules={'mta_client_receive_boot': boot}))
    exec(common, namespace)
    exec(context, namespace)
    names = ('__init__', '_context') + METHOD_NAMES
    cls = type('FixedStateServiceOwner', (object,), {name: namespace[name] for name in names})
    namespace['FixedStateServiceOwner'] = cls
    owner = object.__new__(cls)
    owner._startup_owner_type_original = cls
    owner._startup_namespace_original = namespace
    owner.filecenter_owner_module = owner._filecenter_owner_module_original = module
    rows = tuple((name, namespace[name], namespace[name].__code__) for name in METHOD_NAMES)
    owner.filecenter_owner_methods = owner._filecenter_owner_methods_original = rows
    owner.filecenter_ticket = owner._filecenter_ticket_original = object()
    owner.io = owner.original_io = object()
    owner.until = owner.original_until = 42.75
    owner.clock = object()
    owner.loader = types.SimpleNamespace(_original_until=owner.until, clock=owner.clock)
    owner.boot = boot
    owner.network_observer_spec = owner._network_observer_spec_original = object()
    owner.receive_trial_requested = owner._receive_trial_requested_original = False
    owner.receive_barrier = owner._receive_barrier_original = object()
    owner.receive_trial = owner._receive_trial_original = object()
    owner._receive_barrier_ticket = owner._receive_barrier_ticket_original = object()
    owner._receive_trial_ticket = owner._receive_trial_ticket_original = object()
    owner.receive_trial_revoke_rows = owner._receive_trial_revoke_rows_original = []
    owner.pid = None
    need(type(cls) is type and type(owner) is cls and len(rows) == 9, 'model_normal_type')
    need(all(type(value) is types.FunctionType and value.__globals__ is namespace and
             getattr(cls, name) is value and value.__code__ is code for name, value, code in rows), 'model_bindings')
    return namespace['_context'], owner

need(sys.version_info[:2] == (3, 5), 'model_target_python_version')
elapsed_clock = getattr(time, 'monotonic', None)
cpu_clock = getattr(time, 'process_time', None)
need(callable(elapsed_clock) and callable(cpu_clock), 'model_cpu_clock_unavailable')
common = common_code(COMMON_SOURCE)
models = (make_model(common, context_code(ORIGINAL_CONTEXT_SOURCE), 'A'),
          make_model(common, context_code(CANDIDATE_CONTEXT_SOURCE), 'B'))
need(models[0][0].__globals__ is not models[1][0].__globals__ and
     models[0][1]._startup_owner_type_original is not models[1][1]._startup_owner_type_original, 'model_independent_namespaces')
for function, owner in models:
    for unused in range(WARMUP_EACH):
        returned = function(owner)
    need(returned is None and owner.pid is None, 'model_warmup_normal')

rows = []
previous_elapsed = previous_cpu = None
for group in range(GROUPS):
    for position, side in enumerate('ABBA'):
        function, owner = models[0 if side == 'A' else 1]
        elapsed_start = elapsed_clock()
        cpu_start = cpu_clock()
        # Exactly one actual _context call per iteration; no clock/IO here.
        for unused in range(CALLS_PER_BLOCK):
            function(owner)
        cpu_end = cpu_clock()
        elapsed_end = elapsed_clock()
        need(all(finite(value) for value in (elapsed_start, elapsed_end, cpu_start, cpu_end)), 'model_clock_finite')
        need(elapsed_end >= elapsed_start and cpu_end >= cpu_start and
             (previous_elapsed is None or elapsed_start >= previous_elapsed) and
             (previous_cpu is None or cpu_start >= previous_cpu), 'model_clock_monotonic')
        elapsed = elapsed_end - elapsed_start
        cpu = cpu_end - cpu_start
        need(finite(elapsed) and finite(cpu) and 0.0 < elapsed <= 30.0 and cpu <= 30.0, 'model_duration')
        need(owner.pid is None, 'model_pid_unchanged')
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
    """Return target bytes; inputs are exactly the two fixed path -> bytes rows."""
    _need(type(inputraws) is dict and set(inputraws) == {row[0] for row in PINS}, 'fixed_input_keys')
    parsed = []
    for path, size, checksum in PINS:
        raw = inputraws[path]
        _need(type(raw) is bytes and (len(raw), hashlib.sha256(raw).hexdigest()) ==
              (size, checksum), 'fixed_source_pin')
        parsed.append(_tree(raw))
    old_tree, old_owner, old_error, old_fail, old_methods = parsed[0]
    new_tree, new_owner, new_error, new_fail, new_methods = parsed[1]
    _need(ast.dump(old_error, include_attributes=False) == ast.dump(new_error, include_attributes=False) and
          ast.dump(old_fail, include_attributes=False) == ast.dump(new_fail, include_attributes=False), 'failure_definition_unchanged')
    common_names = ('__init__',) + METHOD_NAMES
    _need(all(ast.dump(old_methods[name], include_attributes=False) ==
              ast.dump(new_methods[name], include_attributes=False) for name in common_names), 'common_definitions_unchanged')
    _need((old_methods['_context'].lineno, old_methods['_context'].end_lineno) == (332, 359) and
          (new_methods['_context'].lineno, new_methods['_context'].end_lineno) == (332, 361), 'fixed_context_span')
    common = _fragment(inputraws[PINS[0][0]], old_owner,
                       tuple(old_methods[name] for name in common_names), (old_error, old_fail))
    original = _fragment(inputraws[PINS[0][0]], old_owner, (old_methods['_context'],))
    candidate = _fragment(inputraws[PINS[1][0]], new_owner, (new_methods['_context'],))
    # Long fixed tuples/dicts are emitted one item per line, not a giant line.
    header = ('import base64, zlib\nSCHEMA=' + repr(SCHEMA) + '\nMETHOD_NAMES=(\n' +
              ''.join('    ' + repr(name) + ',\n' for name in METHOD_NAMES) + ')\n' +
              'CALLS_PER_BLOCK=8192\nGROUPS=4\nWARMUP_EACH=128\nCALL_COUNT=131072\nOUTPUT_LIMIT=65536\n' +
              'SCOPE={\n' + ''.join('    ' + repr(key) + ': ' + repr(value) + ',\n' for key, value in SCOPE.items()) + '}\n')
    source = (header + _literal('COMMON_SOURCE', common) + _literal('ORIGINAL_CONTEXT_SOURCE', original) +
              _literal('CANDIDATE_CONTEXT_SOURCE', candidate) + TARGET_BODY).encode('ascii')
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
