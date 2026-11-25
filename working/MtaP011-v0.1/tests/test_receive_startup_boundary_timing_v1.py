"""One HOST-only actual-function contract; no device or complete Owner proof.

The three affected function bodies are copied by AST from pinned old/current
sources. Definition/context, 35-file/WPA/profile/import and close dependencies
are explicit fixtures. Subject bodies are not patched or replaced at runtime.
This file has only been authored; explicit unittest execution is ROOT-owned.
"""
import ast
import copy
import hashlib
import json
import math
from pathlib import Path
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
OLD = ('candidate/formal-receive-startup-alias-clock-v1/runtime/mta_client_receive_factory.py',
       89379, '4a1043e3eb3fbcc3e80927b64640d80c350c38d4bd2c6ecf73eeff68bf15c35d')
CURRENT = ('candidate/receive-startup-boundary-timing-v1/runtime/mta_client_receive_factory.py',
           89974, 'b4803dea9eeb9421d773a991e1fc7315dfd7990c42ae629879bfa06b912bdc81')
SPEC = ('candidate/receive-startup-boundary-timing-v1/exactsource-delta.json',
        3209, '35981ad265cf131ade91ea6fdf422e347b11a6190ad6b4f450694c8a9853b565')
FIELDS = ('startup_boundary_init', 'startup_boundary_private_sources',
          'startup_boundary_wpa', 'startup_boundary_profile', 'startup_boundary_postimport')


def pinned_bytes(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('boundary_contract_source_pin')
    return raw


def actual_bodies(raw):
    """Exact functions only, not module imports, main, graph or old suite."""
    tree = ast.parse(raw)
    classes = {row.name: row for row in tree.body if isinstance(row, ast.ClassDef)}
    scope = classes['_StartupReadScope']
    factory = classes['FixedReceiveDeploymentFactory']
    chosen = []
    for source, name in ((scope, '__init__'), (scope, 'check_active'),
                         (factory, 'startup_readonly')):
        matches = [row for row in source.body if isinstance(row, ast.FunctionDef) and row.name == name]
        if len(matches) != 1:
            raise ValueError('boundary_contract_function_selection')
        chosen.append(copy.deepcopy(matches[0]))
    functions = [row for row in tree.body if isinstance(row, ast.FunctionDef) and row.name == '_number']
    constants = {'F_SHA', 'SOURCE_PINS', 'SOURCE_MANIFEST_SHA', 'BASELINE_MANIFEST',
                 'STARTUP_READ_SECONDS', 'ASSET_PHYSICAL_ROOT', 'WPA_BYTES', 'WPA_SHA'}
    assignments = [copy.deepcopy(row) for row in tree.body if isinstance(row, ast.Assign) and
                   len(row.targets) == 1 and isinstance(row.targets[0], ast.Name) and
                   row.targets[0].id in constants]
    if len(functions) != 1 or {row.targets[0].id for row in assignments} != constants:
        raise ValueError('boundary_contract_literal_selection')
    return compile(ast.fix_missing_locations(ast.Module(
        body=assignments + copy.deepcopy(functions) + chosen, type_ignores=[])),
        '<actual-startup-boundary-functions>', 'exec')


class OriginalCheckError(RuntimeError):
    pass


class MetadataCopyError(RuntimeError):
    pass


def exercise(program, mode, copy_fault):
    """Only original check/clock and explicit fixture IO counts are observed."""
    counts = dict(owner_now=0, clock=0, originals=0, validate=0, reads=0,
                  profile=0, importer=0, close=0, metadata_fault=0)
    original_error = OriginalCheckError('fixture original check')
    metadata_error = MetadataCopyError('fixture scalar copy')
    namespace = dict(math=math, types=types)
    executor = types.ModuleType('fixture_executor')
    namespace['executor'] = executor

    def fail(code):
        if code != 'startup_expired' or mode != 'expired':
            raise AssertionError('unexpected subject failure: ' + code)
        raise original_error

    namespace['_fail'] = fail
    exec(program, namespace)
    pins = namespace['SOURCE_PINS']
    if type(pins) is not tuple or len(pins) != 35:
        raise AssertionError('fixed35 fixture source')
    executor.MODULES = tuple(row[0] for row in pins)

    class Owner:
        def _context(self):
            return None

        def _now(self):
            counts['owner_now'] += 1
            number = counts['owner_now']
            if number == 2 and mode == 'before_clock':
                raise original_error
            counts['clock'] += 1
            value = 10.0 if number == 1 else (
                20.25 if mode == 'expired' else 15.0 if number == 2 else 15.25)
            self.last = value
            return value

        def _startup_readonly(self):
            return None

        def close(self):
            return None

    owner = Owner()
    owner.state, owner.service, owner.loader = object(), object(), object()
    owner.worker, owner.pid, owner.clock, owner.lock = object(), 123, object(), object()
    owner.original_until = owner.until = 600.0
    owner.received_directory = object()
    owner._startup_module_original = object()
    owner._startup_collect_original = object()
    owner._startup_collection_type_original = type('FixtureCollection', (), {})
    owner.startup_scope = owner._startup_scope_original = None
    owner.startup_called, owner.last = True, None

    class ScopeFixture:
        def __setattr__(self, name, value):
            # A corrupt/unwritable measurement destination is a dependency
            # fault, not a replacement of the three subject function bodies.
            if name == FIELDS[-1] and value is not None and copy_fault:
                counts['metadata_fault'] += 1
                raise metadata_error
            object.__setattr__(self, name, value)

        def _originals(self, active):
            if active is not True or self.owner is not owner:
                raise AssertionError('fixture original scope binding')
            counts['originals'] += 1

        def alias_now(self):
            raise AssertionError('boundary metadata must not call alias clock')

    # Install exact extracted bodies once into a declared dependency fixture.
    # Never alter a subject body during or between its operations.
    ScopeFixture.__init__ = namespace['__init__']
    ScopeFixture.check_active = namespace['check_active']
    namespace['_StartupReadScope'] = ScopeFixture
    namespace['_STARTUP_ALIAS_ORIGINALS'] = ()  # Guard/context is explicitly fixture-only.
    namespace['_STARTUP_ALIAS_CODES'] = ()

    def owner_type(value):
        if value is not owner:
            raise AssertionError('fixture owner object')
        return Owner, Owner.__dict__

    namespace['_startup_owner_type'] = owner_type

    class IoFixture:
        def validate(self):
            counts['validate'] += 1

    class FilesFixture:
        def __init__(self, scope):
            self.attempt, self.io, self.read_names = scope, IoFixture(), []
            self.closed_once = False

        def read(self, path, size, sha, private=False, binary=False):
            if private is not True:
                raise AssertionError('fixture fixed private read')
            counts['reads'] += 1
            if len(self.read_names) < 35:
                name, expected_size, expected_sha = pins[len(self.read_names)]
                if (path, size, sha, binary) != (
                        namespace['ASSET_PHYSICAL_ROOT'] + '/runtime35/' + name + '.py',
                        expected_size, expected_sha, False):
                    raise AssertionError('fixture fixed35 read order')
                self.read_names.append(name)
                self.attempt.last = 11.0 + len(self.read_names) / 100.0
            else:
                if (path, size, sha, binary) != (
                        namespace['ASSET_PHYSICAL_ROOT'] + '/native/mta-wpa-supplicant',
                        namespace['WPA_BYTES'], namespace['WPA_SHA'], True):
                    raise AssertionError('fixture fixed WPA read')
                self.read_names.append('WPA')
                self.attempt.last = 13.0
            # Content/pin IO is a fixture, never a full file verification claim.
            return b'x' * size, None

        def close(self):
            counts['close'] += 1
            if self.closed_once:
                raise AssertionError('fixture close called again')
            self.closed_once = True
            return True

        def closed(self):
            return self.closed_once

    namespace['_Files'] = FilesFixture

    def profile(scope):
        counts['profile'] += 1
        scope.last = 14.0  # Most recent original IO clock, not profile-return wall-time.
        return {'status_manifest': {'fixture': True}}

    namespace['_live_profile'] = profile

    def importer(rows, paths, source_pins, running, _retained_modules):
        counts['importer'] += 1
        if (source_pins != pins or running is not executor or
                tuple(name for name, raw in rows) != executor.MODULES or
                tuple(name for name, path in paths) != executor.MODULES or
                type(_retained_modules) is not dict):
            raise AssertionError('fixture importer original inputs')
        for name in executor.MODULES:
            _retained_modules[name] = executor if name == 'mta_client_executor' else types.ModuleType(name)
        return _retained_modules

    executor._import_verified_sources = importer
    factory = types.SimpleNamespace(_startup_scope=None)
    owner.factory = owner._startup_factory_original = factory
    caught, returned = None, None
    try:
        returned = namespace['startup_readonly'](factory, owner)
    except BaseException as error:
        caught = error
    scope = factory._startup_scope
    if scope is not owner.startup_scope or scope is not owner._startup_scope_original:
        raise AssertionError('original retained scope lost')
    return dict(scope=scope, returned=returned, caught=caught, original_error=original_error,
                metadata_error=metadata_error, counts=counts,
                data=tuple(getattr(scope, name, None) for name in FIELDS))


class ReceiveStartupBoundaryTimingV1Contract(unittest.TestCase):
    def test_actual_startup_boundaries_preserve_original_call_and_error(self):
        old, current, spec_raw = (pinned_bytes(pin) for pin in (OLD, CURRENT, SPEC))
        spec = json.loads(spec_raw.decode('ascii'))
        self.assertEqual(spec['source'], list(OLD))
        self.assertEqual(spec['candidate'], list(CURRENT))
        self.assertEqual(spec['schema'], 'p011-startup-boundary-timing-source-delta-v1')
        self.assertEqual(len(spec['replacements']), 5)
        forward = old
        for row in spec['replacements']:
            before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
            self.assertEqual((row['count'], forward.count(before)), (1, 1))
            forward = forward.replace(before, after, 1)
        self.assertEqual(forward, current)
        inverse = current
        for row in reversed(spec['replacements']):
            before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
            self.assertEqual(inverse.count(after), 1)
            inverse = inverse.replace(after, before, 1)
        self.assertEqual(inverse, old)
        old_program, current_program = actual_bodies(old), actual_bodies(current)
        for mode, copy_fault in (('success', False), ('success', True),
                                 ('expired', False), ('expired', True), ('before_clock', False)):
            with self.subTest(mode=mode, metadata_copy_fault=copy_fault):
                a, b = (exercise(program, mode, copy_fault) for program in (old_program, current_program))
                counts_a, counts_b = a['counts'].copy(), b['counts'].copy()
                counts_a.pop('metadata_fault'); counts_b.pop('metadata_fault')
                self.assertEqual(counts_a, counts_b)  # No new check, clock or fixture IO.
                self.assertEqual((counts_b['reads'], counts_b['validate'], counts_b['profile'],
                                  counts_b['importer'], counts_b['close']), (36, 1, 1, 1, 1))
                self.assertEqual(a['data'], (None,) * 5)
                self.assertEqual(b['data'][:4], (10.0, 11.35, 13.0, 14.0))
                self.assertIs(b['scope'].prepare_until, b['scope'].original_prepare_until)
                self.assertEqual(b['scope'].prepare_until, 20.0)
                self.assertEqual(b['scope'].phase, 'read_closed')
                self.assertEqual((b['scope'].read_ended, b['scope'].files.closed()), (True, True))
                self.assertEqual(b['counts']['metadata_fault'], int(copy_fault))
                if mode == 'success':
                    self.assertIsNone(a['caught']); self.assertIsNone(b['caught'])
                    self.assertIs(b['returned'], b['scope'])
                    self.assertTrue(b['scope'].success)
                    self.assertEqual((counts_b['owner_now'], counts_b['clock'], counts_b['originals']), (3, 3, 3))
                    self.assertEqual(b['scope'].last, 15.25)
                    self.assertEqual(b['data'][-1], None if copy_fault else 15.0)
                else:
                    self.assertIs(a['caught'], a['original_error'])
                    self.assertIs(b['caught'], b['original_error'])
                    self.assertIsNot(b['caught'], b['metadata_error'])
                    self.assertIs(b['scope'].failure, b['original_error'])
                    self.assertEqual(b['scope'].failures, [b['original_error']])
                    self.assertFalse(b['scope'].success)
                    self.assertEqual((counts_b['owner_now'], counts_b['originals']), (2, 2))
                    if mode == 'expired':
                        self.assertEqual((counts_b['clock'], b['scope'].last), (2, 20.25))
                        self.assertEqual(b['data'][-1], None if copy_fault else 20.25)
                    else:
                        self.assertEqual((counts_b['clock'], b['scope'].last, b['data'][-1]), (1, 14.0, 14.0))


if __name__ == '__main__':
    unittest.main(verbosity=2)
