"""One actual Scope method, with an explicit pre-IO continuation boundary.

The complete old/new _originals ASTs are compiled unchanged.  Normal type
models and fixture-only attribute/zip seams record the changed guard.  After
the guard and files=None branch, a stubbed _startup_owner_type raises a fixed
boundary sentinel; all remaining Owner/Scope IO and lifecycle are unexecuted.
This is not full-method execution, device evidence or measured performance.
"""
import ast
import builtins
import copy
import hashlib
import json
import os
import types
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SNAPSHOT_ENV = 'P011_SCOPE_DISPATCH_SNAPSHOT_ROOT'
RECEIPT_ENV = 'P011_SCOPE_DISPATCH_RECEIPT'
SELECTOR = ('tests.test_receive_scope_dispatch_v1.ReceiveScopeDispatchV1Test.'
            'test_originals_dispatch_equivalence')
OWNER_NAMES = ('_context', '_now', '_startup_readonly', 'close')
SCOPE_NAMES = ('__init__', '_originals', 'check_active', 'alias_now')
READ_NAMES = ('check', '_fixed_tmp_alias')
PREFIX_CASES = ('functions_identity', 'codes_identity', 'pins_identity', 'source_pins_identity',
                'lock_identity', 'scope_type', 'owner_methods_identity', 'owner_methods_type',
                'owner_methods_length', 'owner_codes_identity', 'owner_codes_type', 'owner_codes_length')
CLOCK_CASES = ('self_wrong', 'self_absent', 'func_wrong', 'func_absent', 'self_exception', 'func_exception')
SHAPE_CASES = ('functions_short', 'codes_short', 'functions_long', 'codes_long',
               'clock_index_missing', 'functions_noniter', 'codes_noniter', 'zip_row_short', 'zip_row_long')
CODE_CASES = ('owner_code_exception', 'scope_code_exception', 'owner_identity_before_code',
              'scope_identity_before_code', 'owner_code_missing', 'scope_code_missing')
EXPECTED_RECEIPT = {
    'schema': 'p011-receive-scope-dispatch-v1-host-receipt',
    'selector': 'tests.test_receive_scope_dispatch_v1.ReceiveScopeDispatchV1Test.test_originals_dispatch_equivalence',
    'passed': True,
    'source_pins': (
        ('candidate/receive-owner-dispatch-graph-v1/runtime/mta_client_receive_factory.py',
         99257, '0103f047e9598767f9e9162cf8833f0420c171f7552c31ed28e107e6a91c6cb0'),
        ('candidate/receive-scope-dispatch-v1/runtime/mta_client_receive_factory.py',
         99371, '7c4ee1b5dabf869301be940e0330968b683bde2e8d7d45add83f63c474c70f15'),
        ('candidate/receive-scope-dispatch-v1/generate.py',
         11297, '52fb3a632d170bbd0b8617203de66069a23de065311da79a4a70fd86b35ec2ab'),
        ('candidate/receive-scope-dispatch-v1/exactsource-delta.json',
         3469, 'be87cdbd4830f79164787277d4c189b577fb7854d6ee125bd2d4e14434a4d768')),
    'source_inputs_preserved': True,
    'methods': 1,
    'cases': 67,
    'actual_method_calls': 134,
    'guard_continuation_cases': 6,
    'guard_rejection_cases': 38,
    'original_non_guard_exception_cases': 23,
    'full_method_ast_compiled': True,
    'whole_method_execution_verified': False,
    'execution_scope': 'FIRST_GUARD_AND_FILES_NONE_TO_STUBBED_STARTUP_OWNER_TYPE',
    'owner_rows': 4,
    'scope_rows': 6,
    'eager_tuple_order_verified': True,
    'tuple_getter_counts_verified': True,
    'first_failure_short_circuit_verified': True,
    'original_exception_objects_verified': True,
    'original_clock_tail_verified': True,
    'byte_delta': 114,
    'fixed_source_byte_ast_inverse_verified': True,
    'other_definitions_unchanged_verified': True,
    'actual_owner_scope_constructor_called': False,
    'remaining_method_body_executed': False,
    'real_io_permissions_verified': False,
    'device_executed': False,
    'rf_executed': False,
    'measured_performance_claim': False}


def fixed_inputs():
    root = Path(os.environ.get(SNAPSHOT_ENV, str(BASE))).resolve()
    inputs = {}
    for path, size, checksum in EXPECTED_RECEIPT['source_pins']:
        raw = (root / path).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, checksum):
            raise ValueError('scope_fixture_fixed_input_pin')
        inputs[path] = raw
    return root, inputs


def selected_code(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    scope = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_StartupReadScope']
    errors = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ReceivePublicationError']
    fails = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_fail']
    if len(scope) != 1 or len(errors) != 1 or len(fails) != 1:
        raise ValueError('scope_fixture_actual_definition_inventory')
    methods = [node for node in scope[0].body if isinstance(node, ast.FunctionDef) and node.name == '_originals']
    if len(methods) != 1:
        raise ValueError('scope_fixture_originals_unique')
    # The entire original method node, not a body projection or edited copy.
    selected = ast.Module(body=copy.deepcopy(errors + fails + methods), type_ignores=[])
    return compile(selected, '<fixed-scope-originals-fixture>', 'exec'), methods[0]


def cases():
    result = [('valid', False), ('valid', True)]
    result.extend(('row', (family, index, field)) for family, count in (('O', 4), ('S', 6))
                  for index in range(count) for field in ('identity', 'code'))
    result.extend(('prefix', name) for name in PREFIX_CASES)
    result.extend(('clock', name) for name in CLOCK_CASES)
    result.extend(('eager', family) for family in ('O', 'S'))
    result.extend(('getter', name) for name in ('owner_methods', 'owner_codes', 'functions', 'codes'))
    result.extend(('iter', name) for name in ('functions_iter', 'codes_iter', 'functions_next', 'codes_next'))
    result.extend(('shape', name) for name in SHAPE_CASES)
    result.extend(('code', name) for name in CODE_CASES)
    result.extend(('zip', name) for name in ('constructor_exception', 'next_exception'))
    if len(result) != 67:
        raise ValueError('scope_fixture_fixed_cases')
    return tuple(result)


def run_originals(code, case):
    trace, reads = [], {}
    callback = RuntimeError('fixed_scope_callback')
    boundary = RuntimeError('fixed_scope_continuation_boundary')
    faults = dict(class_get=None, field_get=None, clock=None, zip=None)

    def ordinary_method(self, *args):
        raise AssertionError('fixture_other_method_body_called')

    def normal_function(name):
        return types.FunctionType(ordinary_method.__code__, namespace, name)

    class Getter:
        def __init__(self, family, index, value):
            self.family, self.index, self.value = family, index, value
        def __get__(self, instance, cls):
            trace.append('get.' + self.family + str(self.index))
            if faults['class_get'] == (self.family, self.index):
                raise callback
            return self.value

    watched = {'_alias_functions', '_alias_codes', '_alias_owner_methods',
               '_alias_owner_codes', '_alias_clock'}

    def read_attribute(self, name):
        if name in watched:
            reads[name] = reads.get(name, 0) + 1
            trace.append('field.' + name + ':' + str(reads[name]))
            if faults['field_get'] == (name, reads[name]):
                raise callback
        return object.__getattribute__(self, name)

    class Clock:
        @property
        def __self__(self):
            trace.append('clock.self')
            if faults['clock'] == 'self_exception':
                raise callback
            if faults['clock'] == 'self_absent':
                raise AttributeError('fixed_clock_self_absent')
            return object() if faults['clock'] == 'self_wrong' else scope
        @property
        def __func__(self):
            trace.append('clock.func')
            if faults['clock'] == 'func_exception':
                raise callback
            if faults['clock'] == 'func_absent':
                raise AttributeError('fixed_clock_func_absent')
            return object() if faults['clock'] == 'func_wrong' else scope_cells[3].value

    class CodeProbe:
        def __init__(self, family):
            self.family = family
        @property
        def __code__(self):
            trace.append('code.' + self.family)
            raise callback

    class FaultIterable:
        def __init__(self, items, label, phase):
            self.items, self.label, self.phase = items, label, phase
        def __iter__(self):
            trace.append('iter.' + self.label)
            if self.phase == 'iter':
                raise callback
            return FaultIterator(self.items, self.label)
        def __getitem__(self, index):
            trace.append('item.' + self.label + ':' + str(index))
            return self.items[index]

    class FaultIterator:
        def __init__(self, items, label):
            self.items, self.label, self.index = items, label, 0
        def __iter__(self):
            return self
        def __next__(self):
            trace.append('next.' + self.label + ':' + str(self.index))
            if self.index == 2:
                raise callback
            value = self.items[self.index]
            self.index += 1
            return value

    class ZipTrace:
        def __init__(self, iterator, family):
            self.iterator, self.family, self.index = iterator, family, 0
        def __iter__(self):
            trace.append('zip.iter.' + self.family)
            return self
        def __next__(self):
            trace.append('row.' + self.family + ':' + str(self.index))
            if faults['zip'] == 'next_exception' and self.family == 'O' and self.index == 2:
                raise callback
            try:
                value = next(self.iterator)
            except StopIteration:
                trace.append('stop.' + self.family)
                raise
            index, self.index = self.index, self.index + 1
            if self.family == 'O' and index == 1 and faults['zip'] == 'zip_row_short':
                return value[:2]
            if self.family == 'O' and index == 1 and faults['zip'] == 'zip_row_long':
                return value + (None,)
            return value

    def traced_zip(*args):
        family = 'O' if len(args[0]) == 4 else 'S'
        trace.append('zip.' + family)
        if faults['zip'] == 'constructor_exception' and family == 'O':
            raise callback
        return ZipTrace(builtins.zip(*args), family)

    def continuation(owner):
        trace.append('continuation')
        raise boundary

    namespace = dict(__name__='fixed_scope_fixture', zip=traced_zip,
                     _startup_owner_type=continuation)
    exec(code, namespace)
    owner_functions = [normal_function(name) for name in OWNER_NAMES]
    scope_functions = [normal_function(name) for name in SCOPE_NAMES]
    scope_functions[1] = namespace['_originals']
    read_functions = [normal_function(name) for name in READ_NAMES]
    owner_cells = [Getter('O', index, value) for index, value in enumerate(owner_functions)]
    scope_cells = [Getter('S', index, value) for index, value in enumerate(scope_functions + read_functions)]
    owner_type = type('FixtureOwner', (object,), dict(zip(OWNER_NAMES, owner_cells)))
    scope_type = type('_StartupReadScope', (object,),
                      dict(list(zip(SCOPE_NAMES, scope_cells[:4])) + [('__getattribute__', read_attribute)]))
    read_type = type('FixtureReadOwner', (object,), dict(zip(READ_NAMES, scope_cells[4:])))
    namespace['_StartupReadScope'] = scope_type
    namespace['executor'] = types.SimpleNamespace(_ReadOwner=read_type)
    owner = object.__new__(owner_type)
    scope = object.__new__(scope_type)
    owner.lock = object()
    scope.owner, scope.owner_type, scope._alias_lock = owner, owner_type, owner.lock
    owner_methods, owner_codes = tuple(owner_functions), tuple(value.__code__ for value in owner_functions)
    functions = tuple(scope_functions + read_functions)
    codes = tuple(value.__code__ for value in functions)
    scope.owner_methods = scope._alias_owner_methods = owner_methods
    scope._alias_owner_codes = scope._alias_owner_codes_original = owner_codes
    scope._alias_functions, scope._alias_codes = functions, codes
    pins = object()
    scope._alias_pins = scope._alias_pins_original = pins
    namespace.update(_STARTUP_ALIAS_ORIGINALS=functions, _STARTUP_ALIAS_CODES=codes, SOURCE_PINS=pins)
    scope._alias_clock, scope.files = Clock(), None
    category, detail = case
    expected_kind, expected_callback, reached = None, False, False

    def bind_functions(value):
        scope._alias_functions = namespace['_STARTUP_ALIAS_ORIGINALS'] = value

    def bind_codes(value):
        scope._alias_codes = namespace['_STARTUP_ALIAS_CODES'] = value

    if category == 'valid':
        reached = True
    elif category == 'row':
        family, index, field = detail
        cells = owner_cells if family == 'O' else scope_cells
        if field == 'identity':
            cells[index].value = normal_function('changed_identity')
        elif family == 'O':
            changed = list(owner_codes)
            changed[index] = object()
            scope._alias_owner_codes = scope._alias_owner_codes_original = tuple(changed)
        else:
            changed = list(codes)
            changed[index] = object()
            bind_codes(tuple(changed))
        expected_kind = 'ReceivePublicationError'
    elif category == 'prefix':
        if detail == 'functions_identity': scope._alias_functions = tuple(list(functions))
        elif detail == 'codes_identity': scope._alias_codes = tuple(list(codes))
        elif detail == 'pins_identity': scope._alias_pins = object()
        elif detail == 'source_pins_identity': namespace['SOURCE_PINS'] = object()
        elif detail == 'lock_identity': owner.lock = object()
        elif detail == 'scope_type': namespace['_StartupReadScope'] = type('OtherScope', (object,), {})
        elif detail == 'owner_methods_identity': scope.owner_methods = tuple(list(owner_methods))
        elif detail == 'owner_methods_type': scope.owner_methods = scope._alias_owner_methods = list(owner_methods)
        elif detail == 'owner_methods_length': scope.owner_methods = scope._alias_owner_methods = owner_methods[:3]
        elif detail == 'owner_codes_identity': scope._alias_owner_codes = tuple(list(owner_codes))
        elif detail == 'owner_codes_type': scope._alias_owner_codes = scope._alias_owner_codes_original = list(owner_codes)
        elif detail == 'owner_codes_length': scope._alias_owner_codes = scope._alias_owner_codes_original = owner_codes[:3]
        expected_kind = 'ReceivePublicationError'
    elif category == 'clock':
        faults['clock'] = detail
        expected_kind = 'RuntimeError' if detail.endswith('exception') else 'ReceivePublicationError'
        expected_callback = detail.endswith('exception')
    elif category == 'eager':
        cells = owner_cells if detail == 'O' else scope_cells
        cells[0].value = normal_function('earlier_identity_reject')
        faults['class_get'] = (detail, 3 if detail == 'O' else 5)
        expected_kind, expected_callback = 'RuntimeError', True
    elif category == 'getter':
        faults['field_get'] = {'owner_methods': ('_alias_owner_methods', 4),
            'owner_codes': ('_alias_owner_codes', 4), 'functions': ('_alias_functions', 2),
            'codes': ('_alias_codes', 2)}[detail]
        expected_kind, expected_callback = 'RuntimeError', True
    elif category == 'iter':
        label, phase = detail.split('_')
        if label == 'functions': bind_functions(FaultIterable(functions, label, phase))
        else: bind_codes(FaultIterable(codes, label, phase))
        expected_kind, expected_callback = 'RuntimeError', True
    elif category == 'shape':
        if detail == 'functions_short': bind_functions(functions[:5]); reached = True
        elif detail == 'codes_short': bind_codes(codes[:5]); reached = True
        elif detail == 'functions_long': bind_functions(functions + (normal_function('ignored_extra'),)); reached = True
        elif detail == 'codes_long': bind_codes(codes + (object(),)); reached = True
        elif detail == 'clock_index_missing': bind_functions(functions[:3]); expected_kind = 'IndexError'
        elif detail == 'functions_noniter': bind_functions(object()); expected_kind = 'TypeError'
        elif detail == 'codes_noniter': bind_codes(object()); expected_kind = 'TypeError'
        else: faults['zip'] = detail; expected_kind = 'ValueError'
    elif category == 'code':
        family = 'O' if detail.startswith('owner_') else 'S'
        cells, originals = (owner_cells, owner_methods) if family == 'O' else (scope_cells, functions)
        index = 2 if family == 'O' else 4
        changed = list(originals)
        if detail.endswith('identity_before_code'):
            cells[index].value = CodeProbe(family)
            expected_kind = 'ReceivePublicationError'
        else:
            value = CodeProbe(family) if detail.endswith('exception') else object()
            cells[index].value = changed[index] = value
            if family == 'O': scope.owner_methods = scope._alias_owner_methods = tuple(changed)
            else: bind_functions(tuple(changed))
            expected_kind = 'RuntimeError' if detail.endswith('exception') else 'AttributeError'
            expected_callback = detail.endswith('exception')
    elif category == 'zip':
        faults['zip'] = detail
        expected_kind, expected_callback = 'RuntimeError', True
    else:
        raise AssertionError('fixture_unhandled_case')

    trace.clear()
    reads.clear()
    caught = None
    try:
        namespace['_originals'](scope, detail if category == 'valid' else False)
    except BaseException as error:
        caught = error
    if reached:
        if caught is not boundary or trace.count('continuation') != 1:
            raise AssertionError(('fixture_continuation_boundary', case, trace))
    else:
        if caught is None or type(caught).__name__ != expected_kind or 'continuation' in trace:
            raise AssertionError(('fixture_first_failure', case, caught, trace))
        if expected_kind == 'ReceivePublicationError' and caught.args != ('startup_owner_changed',):
            raise AssertionError('fixture_original_failure_code')
        if expected_callback and caught is not callback:
            raise AssertionError('fixture_original_exception_object_replaced')
    # Independently check eager tuples, once-only zip arguments and short circuit.
    for family, count in (('O', 4), ('S', 6)):
        call = 'zip.' + family
        if call in trace:
            events = ['get.' + family + str(index) for index in range(count)]
            positions = [trace.index(event) for event in events]
            if positions != sorted(positions) or max(positions) >= trace.index(call):
                raise AssertionError('fixture_tuple_not_eager_ordered')
            if any(trace.count(event) != 1 for event in events) or trace.count(call) != 1:
                raise AssertionError('fixture_tuple_getter_repeated')
    if category == 'prefix' and any(event.startswith('get.') or event.startswith('zip.') for event in trace):
        raise AssertionError('fixture_prefix_did_not_short_circuit')
    if category == 'row':
        family, index, field = detail
        if trace.count('row.' + family + ':' + str(index)) != 1 or any(
                event.startswith('row.' + family + ':') and int(event.rsplit(':', 1)[1]) > index for event in trace):
            raise AssertionError('fixture_row_did_not_short_circuit')
        if family == 'O' and any(event.startswith('get.S') for event in trace):
            raise AssertionError('fixture_second_tuple_evaluated_after_first_reject')
        if any(event.startswith('clock.') for event in trace):
            raise AssertionError('fixture_clock_after_row_reject')
    if category == 'eager':
        family = detail
        if 'zip.' + family in trace or 'get.' + family + str(3 if family == 'O' else 5) not in trace:
            raise AssertionError('fixture_later_getter_must_precede_row_reject')
    if category == 'code' and detail.endswith('identity_before_code') and any(event.startswith('code.') for event in trace):
        raise AssertionError('fixture_identity_must_precede_code_getter')
    if category == 'clock':
        if 'stop.O' not in trace or 'stop.S' not in trace or trace.count('clock.self') != 1:
            raise AssertionError('fixture_clock_before_complete_scans')
        if detail.startswith('self_') and 'clock.func' in trace:
            raise AssertionError('fixture_clock_func_after_self_failure')
        if detail.startswith('func_') and trace.index('clock.self') >= trace.index('clock.func'):
            raise AssertionError('fixture_clock_tail_order')
    if category == 'valid':
        expected_reads = {'_alias_functions': 3, '_alias_codes': 2,
                          '_alias_owner_methods': 4, '_alias_owner_codes': 4, '_alias_clock': 2}
        if reads != expected_reads or trace[-1] != 'continuation':
            raise AssertionError(('fixture_normal_tuple_getter_counts', reads, expected_reads))
    return (type(caught).__name__, caught.args, caught is callback, caught is boundary, tuple(trace))


class ReceiveScopeDispatchV1Test(unittest.TestCase):
    def test_originals_dispatch_equivalence(self):
        root, inputs = fixed_inputs()
        pins = EXPECTED_RECEIPT['source_pins']
        generator = dict(__name__='fixed_scope_dispatch_plan', __file__=str(root / pins[2][0]))
        exec(compile(inputs[pins[2][0]], str(root / pins[2][0]), 'exec'), generator)
        outputs, facts = generator['prepare'](inputs[pins[0][0]])
        self.assertEqual(tuple(row['path'] for row in outputs), (pins[1][0], pins[3][0]))
        self.assertEqual(tuple(row['raw'] for row in outputs), (inputs[pins[1][0]], inputs[pins[3][0]]))
        self.assertEqual(facts['byte_delta'], 114)
        original, old_method = selected_code(inputs[pins[0][0]])
        candidate, new_method = selected_code(inputs[pins[1][0]])
        self.assertEqual(ast.dump(old_method.body[1], include_attributes=False),
                         ast.dump(new_method.body[4], include_attributes=False))
        exercised = cases()
        self.assertEqual(len(exercised), EXPECTED_RECEIPT['cases'])
        for case in exercised:
            self.assertEqual(run_originals(original, case), run_originals(candidate, case), msg=repr(case))
        self.assertEqual(fixed_inputs()[1], inputs)
        destination = os.environ.get(RECEIPT_ENV)
        if destination:
            raw = (json.dumps(EXPECTED_RECEIPT, sort_keys=True, indent=2) + '\n').encode('utf-8')
            self.assertLessEqual(len(raw), 8192)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                self.assertEqual(handle.write(raw), len(raw))
                handle.flush()
                os.fsync(handle.fileno())
