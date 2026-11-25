"""One actual _context method fixture; no Owner construction or device IO.

The original and candidate method ASTs are compiled unchanged.  Host-only
objects supply their existing fields and record dispatch; no surrounding
runtime/graph main is imported.  These semantic fixtures do not certify real
permissions, live IO, device performance, startup completion or RF admission.
"""
import ast
import copy
import hashlib
import json
import os
import types
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SNAPSHOT_ENV = 'P011_OWNER_DISPATCH_SNAPSHOT_ROOT'
RECEIPT_ENV = 'P011_OWNER_DISPATCH_RECEIPT'
SELECTOR = ('tests.test_receive_owner_dispatch_v1.ReceiveOwnerDispatchV1Test.'
            'test_context_original_and_dispatch_equivalence')
PINS = (
    ('candidate/receive-publication-progress-graph-v1/runtime/mta_client_service_owner.py',
     107026, 'a33b1a4c015bda42fc8ab8ba447fd5f331181df1a5b4240fc82f455dc2b74da7'),
    ('candidate/receive-owner-dispatch-v1/runtime/mta_client_service_owner.py',
     107104, '22aa94d8d5ae2a1dd75c5c98635d80020b318f7071ea84c5c3cb3d85e2805adf'),
    ('candidate/receive-owner-dispatch-v1/generate.py',
     9170, '0a1219c79bcf53283873a2c79128e0da6ec4d8330f50852adc126dfd46405b40'),
    ('candidate/receive-owner-dispatch-v1/exactsource-delta.json',
     2189, '49d87f845578545103ab516c46a25e39a62dc3c0bd9003c205b42254ac7203dc'))
METHOD_NAMES = (
    '_seal_filecenter_directories', '_filecenter_directory_current', 'create_filecenter',
    '_filecenter_definitions_current', '_filecenter_current', '_capture_filecenter_partial',
    '_filecenter_partial_current', '_close_filecenter', '_filecenter_closed')
PREFIX_CASES = ('owner_type', 'init_globals', 'own_identity', 'own_type', 'own_namespace',
                'own_class', 'methods_identity', 'methods_type', 'methods_length',
                'methods_pointer_malformed')
OWNER_CASES = ('io_identity', 'until_identity', 'loader_until_identity', 'loader_clock_identity',
               'boot_identity', 'network_spec_identity', 'receive_trial_type',
               'receive_trial_identity', 'barrier_identity', 'trial_identity',
               'barrier_ticket_identity', 'trial_ticket_identity', 'revoke_rows_identity',
               'pid_mismatch')


def fixed_inputs():
    root = Path(os.environ.get(SNAPSHOT_ENV, str(BASE))).resolve()
    result = {}
    for relative, size, expected in PINS:
        raw = (root / relative).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, expected):
            raise ValueError('fixture_fixed_source_pin')
        result[relative] = raw
    return root, result


def selected_code(raw):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    owner = [n for n in tree.body if isinstance(n, ast.ClassDef) and
             n.name == 'FixedStateServiceOwner']
    if len(owner) != 1:
        raise ValueError('fixture_owner_unique')
    wanted = ('__init__', '_context') + METHOD_NAMES
    methods = [n for n in owner[0].body if isinstance(n, ast.FunctionDef) and n.name in wanted]
    if len(methods) != len(wanted) or {n.name for n in methods} != set(wanted):
        raise ValueError('fixture_method_inventory')
    errors = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'ServiceOwnerError']
    fails = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_fail']
    if (len(errors), len(fails)) != (1, 1):
        raise ValueError('fixture_original_failure_unique')
    # Only pure code/error definitions are loaded; none of the other method
    # bodies, including the real __init__, will be called by this fixture.
    selected = ast.Module(body=copy.deepcopy(errors + fails + methods), type_ignores=[])
    return compile(selected, '<fixed-owner-context-fixture>', 'exec'), tree


def cases():
    result = [('valid', 'pid_none'), ('valid', 'pid_set'), ('valid', 'own_none')]
    result.extend(('method', (index, field)) for index in range(9)
                  for field in ('type', 'identity', 'globals', 'code'))
    result.extend(('prefix', name) for name in PREFIX_CASES)
    result.append(('ticket', 'ticket_identity'))
    result.extend(('owner', name) for name in OWNER_CASES)
    result.extend(('malformed', name) for name in
                  ('row_short', 'row_long', 'getattr_type', 'getattr_absent'))
    result.extend(('callback', name) for name in ('getattr_exception', 'pid_exception'))
    if len(result) != 70:
        raise ValueError('fixture_case_count')
    return tuple(result)


def run_context(code, case):
    trace, fault = [], {'name': None}
    sentinel = RuntimeError('fixed_fixture_callback')

    class RecordingMeta(type):
        def __getattribute__(cls, name):
            if name in METHOD_NAMES:
                trace.append(name)
                if name == fault['name']:
                    raise sentinel
            return type.__getattribute__(cls, name)

    class Modules(dict):
        def get(self, key, default=None):
            trace.append('boot.get')
            return dict.get(self, key, default)

    class Io(object):
        actual = 7
        throwing = False
        def pid(self):
            trace.append('io.pid')
            if self.throwing:
                raise sentinel
            return self.actual

    module = types.ModuleType('fixed_owner_context_fixture')
    namespace = module.__dict__
    boot = types.ModuleType('fixed_fixture_boot')
    modules = Modules(mta_client_receive_boot=boot)
    namespace.update(types=types, sys=types.SimpleNamespace(modules=modules))
    exec(code, namespace)
    cls = RecordingMeta('FixedStateServiceOwner', (object,),
                        {name: namespace[name] for name in ('__init__', '_context') + METHOD_NAMES})
    namespace['FixedStateServiceOwner'] = cls
    owner = object.__new__(cls)
    owner._startup_owner_type_original = cls
    owner._startup_namespace_original = namespace
    owner.filecenter_owner_module = owner._filecenter_owner_module_original = module
    method_rows = tuple((name, namespace[name], namespace[name].__code__) for name in METHOD_NAMES)
    owner.filecenter_owner_methods = owner._filecenter_owner_methods_original = method_rows
    owner.filecenter_ticket = owner._filecenter_ticket_original = object()
    owner.io = owner.original_io = Io()
    owner.until = owner.original_until = float('42.75')
    owner.clock = object()
    owner.loader = types.SimpleNamespace(_original_until=owner.original_until, clock=owner.clock)
    owner.boot = boot
    owner.network_observer_spec = owner._network_observer_spec_original = object()
    owner.receive_trial_requested = owner._receive_trial_requested_original = False
    owner.receive_barrier = owner._receive_barrier_original = object()
    owner.receive_trial = owner._receive_trial_original = object()
    owner._receive_barrier_ticket = owner._receive_barrier_ticket_original = object()
    owner._receive_trial_ticket = owner._receive_trial_ticket_original = object()
    owner.receive_trial_revoke_rows = owner._receive_trial_revoke_rows_original = []
    owner.pid = 7
    category, value = case
    expected_methods = list(METHOD_NAMES)
    expected_tail = ['boot.get', 'io.pid']
    expected_kind, expected_code = None, None
    expected_callback_identity = None

    if category == 'valid':
        if value == 'pid_none':
            owner.pid = None
            expected_tail = ['boot.get']
        elif value == 'own_none':
            owner.filecenter_owner_module = owner._filecenter_owner_module_original = None
    elif category == 'method':
        index, field = value
        rows = list(method_rows)
        name, original, original_code = rows[index]
        if field == 'type':
            rows[index] = (name, object(), original_code)
        elif field == 'identity':
            setattr(cls, name, types.FunctionType(original_code, namespace))
        elif field == 'globals':
            foreign = types.FunctionType(original_code, {})
            setattr(cls, name, foreign)
            rows[index] = (name, foreign, original_code)
        elif field == 'code':
            original.__code__ = namespace['_fail'].__code__
        owner.filecenter_owner_methods = owner._filecenter_owner_methods_original = tuple(rows)
        expected_methods = list(METHOD_NAMES[:index + (field != 'type')])
        expected_tail = []
        expected_kind, expected_code = 'ServiceOwnerError', 'filecenter_original_changed'
    elif category == 'prefix':
        if value == 'owner_type':
            subclass = RecordingMeta('DifferentOwner', (cls,), {})
            other = object.__new__(subclass)
            other.__dict__.update(owner.__dict__)
            owner = other
        elif value == 'init_globals':
            cls.__init__ = types.FunctionType(namespace['__init__'].__code__, {})
        elif value == 'own_identity':
            owner.filecenter_owner_module = None
        elif value == 'own_type':
            owner.filecenter_owner_module = owner._filecenter_owner_module_original = object()
        elif value == 'own_namespace':
            owner.filecenter_owner_module = owner._filecenter_owner_module_original = types.ModuleType('foreign')
        elif value == 'own_class':
            namespace['FixedStateServiceOwner'] = object
        elif value == 'methods_identity':
            owner.filecenter_owner_methods = tuple(list(method_rows))
        elif value == 'methods_type':
            owner.filecenter_owner_methods = owner._filecenter_owner_methods_original = list(method_rows)
        elif value == 'methods_length':
            owner.filecenter_owner_methods = owner._filecenter_owner_methods_original = method_rows[:-1]
        elif value == 'methods_pointer_malformed':
            owner.filecenter_owner_methods = method_rows[:-1] + (('malformed',),)
        expected_methods, expected_tail = [], []
        expected_kind, expected_code = 'ServiceOwnerError', 'filecenter_original_changed'
    elif category == 'ticket':
        owner.filecenter_ticket = object()
        expected_tail = []
        expected_kind, expected_code = 'ServiceOwnerError', 'filecenter_original_changed'
    elif category == 'owner':
        changes = {
            'io_identity': (owner, 'io', Io()),
            'until_identity': (owner, 'until', float('42.75')),
            'loader_until_identity': (owner.loader, '_original_until', float('42.75')),
            'loader_clock_identity': (owner.loader, 'clock', object()),
            'network_spec_identity': (owner, 'network_observer_spec', object()),
            'receive_trial_identity': (owner, '_receive_trial_requested_original', True),
            'barrier_identity': (owner, 'receive_barrier', object()),
            'trial_identity': (owner, 'receive_trial', object()),
            'barrier_ticket_identity': (owner, '_receive_barrier_ticket', object()),
            'trial_ticket_identity': (owner, '_receive_trial_ticket', object()),
            'revoke_rows_identity': (owner, 'receive_trial_revoke_rows', [])}
        if value in changes:
            target, key, changed = changes[value]
            setattr(target, key, changed)
        elif value == 'boot_identity':
            modules['mta_client_receive_boot'] = types.ModuleType('different_boot')
        elif value == 'receive_trial_type':
            owner.receive_trial_requested = owner._receive_trial_requested_original = 0
        elif value == 'pid_mismatch':
            owner.io.actual = 8
        expected_tail = ([] if value in OWNER_CASES[:4] else
                         ['boot.get', 'io.pid'] if value == 'pid_mismatch' else ['boot.get'])
        expected_kind, expected_code = 'ServiceOwnerError', 'owner_changed'
    elif category == 'malformed':
        rows = list(method_rows)
        name, function, function_code = rows[4]
        if value == 'row_short':
            rows[4] = (name, function)
        elif value == 'row_long':
            rows[4] = (name, function, function_code, None)
        elif value == 'getattr_type':
            rows[4] = (None, function, function_code)
        elif value == 'getattr_absent':
            rows[4] = ('fixed_missing_method', function, function_code)
        owner.filecenter_owner_methods = owner._filecenter_owner_methods_original = tuple(rows)
        expected_methods, expected_tail = list(METHOD_NAMES[:4]), []
        expected_kind = ('ValueError' if value in ('row_short', 'row_long') else
                         'TypeError' if value == 'getattr_type' else 'AttributeError')
    elif category == 'callback':
        if value == 'getattr_exception':
            fault['name'] = METHOD_NAMES[4]
            expected_methods, expected_tail = list(METHOD_NAMES[:5]), []
        else:
            owner.io.throwing = True
        expected_kind, expected_callback_identity = 'RuntimeError', True

    trace.clear()
    caught, returned = None, None
    try:
        returned = namespace['_context'](owner)
    except BaseException as error:
        caught = error
    outcome = (returned, None if caught is None else type(caught).__name__,
               None if caught is None else getattr(caught, 'code', None),
               () if caught is None else caught.args, tuple(trace))
    expected = (expected_kind, expected_code, tuple(expected_methods + expected_tail))
    observed = (outcome[1], outcome[2], outcome[4])
    if observed != expected or returned is not None:
        raise AssertionError(('fixture_dispatch_result', case, observed, expected))
    if expected_callback_identity is True and caught is not sentinel:
        raise AssertionError('fixture_original_callback_exception_replaced')
    return outcome


class ReceiveOwnerDispatchV1Test(unittest.TestCase):
    def test_context_original_and_dispatch_equivalence(self):
        root, inputs = fixed_inputs()
        namespace = dict(__name__='fixed_owner_dispatch_generator',
                         __file__=str(root / PINS[2][0]))
        exec(compile(inputs[PINS[2][0]], str(root / PINS[2][0]), 'exec'), namespace)
        outputs, facts = namespace['prepare'](inputs[PINS[0][0]])
        self.assertEqual(tuple(row['path'] for row in outputs), (PINS[1][0], PINS[3][0]))
        self.assertEqual(tuple(row['raw'] for row in outputs),
                         (inputs[PINS[1][0]], inputs[PINS[3][0]]))
        self.assertEqual(facts['byte_delta'], 78)
        original, old_tree = selected_code(inputs[PINS[0][0]])
        candidate, new_tree = selected_code(inputs[PINS[1][0]])
        old_context = namespace['owner_context'](old_tree)
        new_context = namespace['owner_context'](new_tree)
        generator = [n for n in ast.walk(old_context) if isinstance(n, ast.GeneratorExp)][0]
        loop = [n for n in ast.walk(new_context) if isinstance(n, ast.For)][0]
        self.assertEqual(ast.dump(generator.elt, include_attributes=False),
                         ast.dump(loop.body[0].test, include_attributes=False))
        self.assertEqual(ast.dump(generator.generators[0].target, include_attributes=False),
                         ast.dump(loop.target, include_attributes=False))
        self.assertEqual(ast.dump(generator.generators[0].iter, include_attributes=False),
                         ast.dump(loop.iter, include_attributes=False))
        exercised = cases()
        for case in exercised:
            self.assertEqual(run_context(original, case), run_context(candidate, case),
                             msg=repr(case))
        # Read back exactly these PC source snapshots, not any target resource.
        self.assertEqual(fixed_inputs()[1], inputs)
        receipt = dict(schema='p011-receive-owner-dispatch-v1-host-receipt', selector=SELECTOR,
            passed=True, source_pins=PINS, source_inputs_preserved=True,
            methods=1, cases=70, actual_context_calls=140, accepted_cases=3,
            guard_rejection_cases=61, original_non_guard_exception_cases=6,
            nine_method_fields_per_index=4, original_check_order_verified=True,
            original_failure_short_circuit_verified=True, byte_delta=78,
            fixed_source_byte_ast_inverse_verified=True,
            device_executed=False, rf_executed=False, surrounding_runtime_executed=False,
            real_io_permissions_verified=False, measured_performance_claim=False)
        destination = os.environ.get(RECEIPT_ENV)
        if destination:
            raw = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode('utf-8')
            self.assertLessEqual(len(raw), 8192)
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                self.assertEqual(handle.write(raw), len(raw))
                handle.flush()
                os.fsync(handle.fileno())
