"""HOST-only contract of the complete pinned _live_profile proc rewrite.

Only the two complete real methods _stat_data/_live_profile are AST-loaded;
the Factory module and old suites are not run. Explicit memory IO, platform,
Files and Owner fixtures use two synthetic root PIDs so the second iteration
actually executes the changed Startup guard. No native Files/FD close, real
identity/admission, device IO, RF or timing is tested. CPU exports model only
the actual inner guard; they do not measure the complete profile or Startup.
"""
import ast
import copy
import errno
import hashlib
import json
from pathlib import Path
import re
import stat
import types
import unittest
import zlib

BASE = Path(__file__).resolve().parents[1]
MOTHER = ('candidate/receive-profile-cache-graph-v1/runtime/mta_client_receive_factory.py', 99675,
          '3f0ca3d039301a221fce10b5b72cb50e0bf6d374298656879ff748de61ec5cf5')
CANDIDATE = ('candidate/receive-profile-proc-dispatch-v1/runtime/mta_client_receive_factory.py', 99717,
             '3349e76e6da45d4948edde640e44829bb1eeb554156b91c686f2a6b655422b47')
DELTA = ('candidate/receive-profile-proc-dispatch-v1/exactsource-delta.json', 2921,
         '071dd1f19d35c81df736631a3bfaaa695b28d74f441f68cc866fa3b00a32001a')
SEED = ('candidate/receive-profile-proc-dispatch-v1/generate_seed.py', 13116,
        '6aff0915c1df41eff9f81503062b4da254b3c489f0650e217b0d3c34729da605')
PINS = (MOTHER, CANDIDATE, DELTA, SEED)
PYTHON, DAEMON = '/usr/bin/python3.5', '/usr/sbin/wpa_supplicant'
PROC, OTHER_PROC = '/proc/77', '/proc/78'


def read_pin(row):
    path = BASE
    for part in row[0].split('/'):
        path = path / part
        value = path.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
            raise AssertionError('HOST input is a link')
    if not stat.S_ISREG(value.st_mode):
        raise AssertionError('HOST input is not a regular file')
    raw = path.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != row[1:]:
        raise AssertionError('HOST input pin changed: ' + row[0])
    return raw


def shape(node):
    return ast.dump(node, include_attributes=False)


def source_nodes(raw):
    rows = [node for node in ast.parse(raw.decode('ascii'), feature_version=(3, 5)).body
            if isinstance(node, ast.FunctionDef) and node.name in ('_stat_data', '_live_profile')]
    if tuple(node.name for node in rows) != ('_stat_data', '_live_profile') or any(
            node.decorator_list for node in rows):
        raise AssertionError('complete two-method source required')
    return rows


def startup_branch(node):
    expected = shape(ast.parse('type(attempt) is _StartupReadScope', mode='eval').body)
    rows = [item for item in ast.walk(node) if isinstance(item, ast.If) and shape(item.test) == expected]
    if len(rows) != 1:
        raise AssertionError('one exact Startup branch required')
    return rows[0]


# This loop source can be transported with cpu_model_source() to Python 3.5.
# Caller supplies an explicitly labelled identity-shaped CPU fixture realm.
# No clock/timer, path, IO, native authority or permission cache is created.
CPU_LOOP_SOURCE = '''def cpu_guard_model_run(check, rounds, attempt, files, clock, functions, codes):
    if type(rounds) is not int or not 1 <= rounds <= 1000000:
        raise ValueError('bounded CPU model rounds')
    total = 0
    for index in range(rounds):
        if check(attempt, files, clock, functions, codes) is not True:
            raise AssertionError('CPU model guard did not return True')
        total += 1
    return total
'''


def cpu_model_source(raw):
    """Actual inner Startup guard plus pure loop; not a whole-IO benchmark."""
    branch = startup_branch(source_nodes(raw)[1])
    lines = raw.decode('ascii').splitlines(keepends=True)
    selected = lines[branch.body[0].lineno - 1:branch.body[-1].end_lineno]
    if not selected or any(line.strip() and not line.startswith(' ' * 16) for line in selected):
        raise AssertionError('actual guard source indentation changed')
    body = ''.join(line[12:] if line.strip() else line for line in selected)
    text = ('def cpu_guard_model(attempt, files, clock, functions, codes):\n' +
            body + '    return True\n\n' + CPU_LOOP_SOURCE)
    ast.parse(text, feature_version=(3, 5))
    return text.encode('ascii')


class HostProfileError(ValueError):
    """Fixture failure code, never native Owner authority."""


class HostFlow(object):
    """All OS/read/clock effects below are in-memory ledger entries."""
    def __init__(self, case='success'):
        self.case, self.trace, self.counts = case, [], {}
        self.mutated = False

    def hit(self, operation, path):
        self.trace.append((operation, path))
        key = operation, path
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.case == 'alias-clock-raises' and operation == 'clock.alias':
            raise OSError(errno.EIO, 'explicit HOST clock fixture failure')

    def mutate(self, owner, realm):
        """One deliberate fault after the first comm read, before PID two."""
        if self.mutated:
            return
        self.mutated = True
        self.hit('fixture-mutation', self.case)
        scope_type = realm['_StartupReadScope']
        if self.case == 'owner-files':
            owner.files = object()
        elif self.case == 'owner-io':
            owner.files.alias_owner.io = object()
        elif self.case == 'owner-deadline':
            owner.files.alias_owner.deadline = object()
        elif self.case == 'alias-clock-identity':
            owner._alias_clock = owner.alias_now
        elif self.case == 'startup-prefix-poison':
            owner._files_original = object()
            flow = self
            class CurrentTuplePoison(object):
                def __get__(self, instance, owner_type):
                    flow.hit('unexpected-current-tuple', 'prefix must short circuit')
                    raise AssertionError('fresh tuple evaluated after failing prefix')
            scope_type._originals = CurrentTuplePoison()
        elif self.case == 'current-type':
            flow = self
            class CodePoison(object):
                @property
                def __code__(self):
                    flow.hit('unexpected-code-read', 'type must short circuit')
                    raise AssertionError('code read after failing FunctionType guard')
            scope_type.__init__ = CodePoison()
        elif self.case == 'current-identity':
            original = scope_type.alias_now
            scope_type.alias_now = types.FunctionType(original.__code__, original.__globals__,
                original.__name__, original.__defaults__, original.__closure__)
        elif self.case == 'current-code':
            def alternate(self):
                return 'HOST replacement code must not execute'
            realm['executor']._ReadOwner._fixed_tmp_alias.__code__ = alternate.__code__


class HostFiles(object):
    """Logical fixture reads; real _Files/open/fstat/close are NOT run."""
    def __init__(self, owner, realm):
        self.attempt, self.realm, self.io = owner, realm, object()
        self.alias_owner = realm['executor']._ReadOwner(self.io, owner._alias_clock, owner.original_prepare_until)

    def read(self, path, limit, expected=None, private=False, binary=False, proc=False, magic=False):
        owner, flow = self.attempt, self.attempt.flow
        flow.hit('read', path)
        flow.trace.append(('read-options', (path, limit, expected, private, binary, proc, magic)))
        owner.now()
        values = {
            PYTHON: b'\x7fELF-HOST-python-image',
            DAEMON: b'\x7fELF-HOST-daemon-image',
            PROC + '/exe': b'\x7fELF-HOST-daemon-image',
            PROC + '/comm': b'wpa_supplicant\n',
            OTHER_PROC + '/comm': b'kworker/HOST\n',
            PROC + '/stat': ('77 (wpa_supplicant) S ' + '0 ' * 18 + '12345\n').encode('ascii'),
            PROC + '/cmdline': b'/usr/sbin/wpa_supplicant\0-iwlan0\0',
            PROC + '/status': b'Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n',
            '/proc/42/net/unix': (
                b'Num RefCount Protocol Flags Type St Inode Path\n'
                b'0000000000000000: 00000002 00000000 00000000 0002 01 9001 /run/wpa_supplicant/wlan0\n')}
        if path not in values:
            raise AssertionError('unexpected HOST read: ' + path)
        raw = values[path]
        if len(raw) > limit:
            raise AssertionError('fixture exceeds real read budget')
        owner.now()
        if path == PROC + '/comm' and flow.counts[('read', path)] == 1:
            flow.mutate(owner, self.realm)
        return raw, (1, 2, stat.S_IFREG | 0o500, 0, 0, 1, len(raw), 0, 0, 0)


class HostOs(object):
    def __init__(self, flow):
        self.flow = flow

    def listdir(self, path):
        self.flow.hit('listdir', path)
        if path == '/proc':
            return ['78', '77']
        if path in (PROC + '/ns', '/proc/self/ns'):
            return ['mnt', 'net', 'pid', 'user']
        if path == PROC + '/fd':
            return ['3']
        raise AssertionError('unexpected HOST listdir: ' + path)

    def stat(self, path, follow_symlinks=True):
        self.flow.hit('stat', (path, follow_symlinks))
        if path not in (PROC, OTHER_PROC) or follow_symlinks is not False:
            raise AssertionError('unexpected HOST stat')
        return (1, 2, stat.S_IFDIR | 0o700, 0, 0, 1, 0, 0, 0, 0)

    def readlink(self, path):
        self.flow.hit('readlink', path)
        if path == PROC + '/exe':
            return DAEMON
        if path == PROC + '/fd/3':
            return 'socket:[9001]'
        for root in (PROC + '/ns/', '/proc/self/ns/'):
            if path.startswith(root) and path[len(root):] in ('mnt', 'net', 'pid', 'user'):
                return path[len(root):] + ':[101]'
        raise AssertionError('unexpected HOST readlink: ' + path)


def run_whole(raw, flow):
    """Execute complete actual methods with explicit fake IO/held identities."""
    class HostLinuxIo(object):
        def validate(self):
            flow.hit('io.validate', 'HOST-fixture')

    class HostReadOwner(object):
        def __init__(self, io, clock, deadline):
            self.io, self.clock, self.deadline = io, clock, deadline
        def check(self):
            raise AssertionError('native alias check must not be called by HOST fixture')
        def _fixed_tmp_alias(self):
            raise AssertionError('native alias path must not be called by HOST fixture')

    class HostStartupScope(object):
        def __init__(self):
            self.flow, self.pid, self.last, self.now_values = flow, 42, None, []
            self.original_prepare_until = object()
            self.profile_cache = ('stale HOST data',)
        def _originals(self):
            raise AssertionError('native startup originals must not be called')
        def check_active(self):
            raise AssertionError('native active guard must not be called')
        def now(self):
            return self.tick('clock.now')
        def alias_now(self):
            return self.tick('clock.alias')
        def different_alias(self):
            return self.tick('clock.different')
        def tick(self, operation):
            self.flow.hit(operation, 'HOST-existing-call')
            self.last = 100.0 + len(self.now_values) * 0.001
            self.now_values.append(self.last)
            return self.last

    def fail(code):
        raise HostProfileError(code)

    functions = (HostStartupScope.__init__, HostStartupScope._originals, HostStartupScope.check_active,
                 HostStartupScope.alias_now, HostReadOwner.check, HostReadOwner._fixed_tmp_alias)
    codes = tuple(value.__code__ for value in functions)
    if flow.case == 'functions-length':
        functions = functions[:5]
    if flow.case == 'codes-length':
        codes = codes[:5]
    realm = dict(__name__='HOST_PROC_DISPATCH_FIXTURES_NOT_NATIVE', re=re, hashlib=hashlib,
        stat=stat, errno=errno, zlib=zlib, types=types, sys=types.SimpleNamespace(version_info=(3, 5, 5)),
        os=HostOs(flow), executor=types.SimpleNamespace(_LinuxIo=HostLinuxIo, _ReadOwner=HostReadOwner,
                                                     _meta=lambda value: value),
        _Files=HostFiles, _StartupReadScope=HostStartupScope, _PublicationAttempt=type('UnusedPublication', (), {}),
        _F_ORIGINALS=(None, None, None, None, HostReadOwner),
        _STARTUP_ALIAS_ORIGINALS=functions, _STARTUP_ALIAS_CODES=codes,
        PYTHON=PYTHON, MAX_IMAGE=16777216, MAX_ENTRIES=4096,
        _NAMESPACES=frozenset(('cgroup', 'ipc', 'mnt', 'net', 'pid', 'pid_for_children', 'user', 'uts')),
        _path=lambda value: value in (DAEMON, '/run/wpa_supplicant/wlan0'), _fail=fail)
    owner = HostStartupScope()
    owner._alias_functions, owner._alias_codes = functions, codes
    owner._alias_clock = owner.different_alias if flow.case == 'clock-function' else owner.alias_now
    owner.files = owner._files_original = HostFiles(owner, realm)
    exec(compile(ast.Module(body=source_nodes(raw), type_ignores=[]),
                 'HOST-whole-profile-explicit-two-PID-IO-owner-fixtures', 'exec'), realm)
    value, failure = None, None
    try:
        value = realm['_live_profile'](owner)
    except (HostProfileError, OSError) as error:
        failure = type(error).__name__, str(error)
    return owner, value, failure, realm


class ReceiveProfileProcDispatchHost(unittest.TestCase):
    def test_complete_method_and_only_startup_guard_inverse(self):
        inputs = {row[0]: read_pin(row) for row in PINS}
        before, after = inputs[MOTHER[0]], inputs[CANDIDATE[0]]
        spec = json.loads(inputs[DELTA[0]].decode('ascii'))
        self.assertEqual(spec['origin'], dict(path=MOTHER[0], bytes=MOTHER[1], sha256=MOTHER[2]))
        self.assertEqual(spec['candidate'], dict(path=CANDIDATE[0], bytes=CANDIDATE[1], sha256=CANDIDATE[2]))
        self.assertEqual(spec['business_methods'], ['_live_profile'])
        self.assertEqual(spec['byte_delta'], 42)
        self.assertEqual(spec['later_definition_line_delta'], 2)
        self.assertEqual(spec['prospective_payload_remaining'], 494)
        self.assertEqual(len(spec['replacements']), 1)
        restored = after
        for edit in reversed(spec['replacements']):
            old, new = edit['before'].encode('ascii'), edit['after'].encode('ascii')
            self.assertEqual(edit['count'], 1)
            self.assertEqual(restored.count(new), 1)
            restored = restored.replace(new, old, 1)
        self.assertEqual(restored, before)
        self.assertEqual(ast.dump(ast.parse(restored), include_attributes=True),
                         ast.dump(ast.parse(before), include_attributes=True))
        old_node, new_node = source_nodes(before)[1], copy.deepcopy(source_nodes(after)[1])
        old_branch, new_branch = startup_branch(old_node), startup_branch(new_node)
        self.assertEqual(len(old_branch.body), 1)
        self.assertEqual(len(new_branch.body), 2)
        old_if, new_if, loop = old_branch.body[0], new_branch.body[0], new_branch.body[1]
        self.assertIsInstance(loop, ast.For)
        self.assertEqual([shape(value) for value in old_if.test.values[:-1]],
                         [shape(value) for value in new_if.test.values])
        call = old_if.test.values[-1]
        self.assertEqual(call.func.id, 'any')
        generator = call.args[0]
        self.assertIsInstance(generator, ast.GeneratorExp)
        self.assertEqual(len(generator.generators), 1)
        self.assertEqual(shape(generator.generators[0].target), shape(loop.target))
        self.assertEqual(shape(generator.generators[0].iter), shape(loop.iter))
        self.assertEqual(shape(generator.elt), shape(loop.body[0].test))
        self.assertEqual([shape(value) for value in old_if.body], [shape(value) for value in new_if.body])
        self.assertEqual([shape(value) for value in old_if.body], [shape(value) for value in loop.body[0].body])
        self.assertEqual(shape(old_branch.orelse[0]), shape(new_branch.orelse[0]))
        self.assertFalse(loop.orelse)
        new_branch.body = copy.deepcopy(old_branch.body)
        self.assertEqual(shape(old_node), shape(new_node))
        self.assertTrue(all(read_pin(row) == inputs[row[0]] for row in PINS))

    def test_two_pid_whole_flow_success_and_bounded_short_circuits(self):
        before, after = read_pin(MOTHER), read_pin(CANDIDATE)
        cases = (
            ('success', None),
            ('owner-files', 'publication_owner_changed'),
            ('owner-io', 'publication_owner_changed'),
            ('owner-deadline', 'publication_owner_changed'),
            ('alias-clock-identity', 'publication_owner_changed'),
            ('startup-prefix-poison', 'startup_owner_changed'),
            ('functions-length', 'startup_owner_changed'),
            ('codes-length', 'startup_owner_changed'),
            ('clock-function', 'startup_owner_changed'),
            ('current-type', 'startup_owner_changed'),
            ('current-identity', 'startup_owner_changed'),
            ('current-code', 'startup_owner_changed'),
            ('alias-clock-raises', 'explicit HOST clock fixture failure'))
        for case, expected in cases:
            with self.subTest(explicit_HOST_fixture=case):
                old_flow, new_flow = HostFlow(case), HostFlow(case)
                old, old_value, old_failure, old_realm = run_whole(before, old_flow)
                new, new_value, new_failure, new_realm = run_whole(after, new_flow)
                self.assertEqual(new_flow.trace, old_flow.trace)
                self.assertEqual(new.now_values, old.now_values)
                self.assertEqual(new.profile_cache, old.profile_cache)
                self.assertEqual(new_value, old_value)
                self.assertEqual(new_failure, old_failure)
                self.assertTrue(new_flow.mutated)
                self.assertIn(('read', PROC + '/comm'), new_flow.trace)
                self.assertNotIn(('unexpected-current-tuple', 'prefix must short circuit'), new_flow.trace)
                self.assertNotIn(('unexpected-code-read', 'type must short circuit'), new_flow.trace)
                if expected is None:
                    self.assertIsNone(new_failure)
                    self.assertEqual(new_flow.counts[('clock.alias', 'HOST-existing-call')], 1)
                    self.assertIn(('read', OTHER_PROC + '/comm'), new_flow.trace)
                    self.assertEqual(len(new.profile_cache), 6)
                    self.assertIs(new_value['status_authenticated'], False)
                else:
                    self.assertIsNone(new_value)
                    self.assertNotIn(('stat', (OTHER_PROC, False)), new_flow.trace)
                    self.assertNotIn(('read', OTHER_PROC + '/comm'), new_flow.trace)
                    self.assertEqual(len(new.profile_cache), 1)
                    if case == 'alias-clock-raises':
                        self.assertEqual(new_failure[0], 'OSError')
                        self.assertIn(expected, new_failure[1])
                    else:
                        self.assertEqual(new_failure, ('HostProfileError', expected))
        self.assertEqual(read_pin(MOTHER), before)
        self.assertEqual(read_pin(CANDIDATE), after)

    def test_reusable_pure_cpu_model_contract(self):
        """Tiny callable contract, no timer: guard model != whole profile cost."""
        for pin in (MOTHER, CANDIDATE):
            with self.subTest(actual_guard_source=pin[0]):
                raw = read_pin(pin)
                source = cpu_model_source(raw)
                tree = ast.parse(source.decode('ascii'), feature_version=(3, 5))
                self.assertEqual(tuple(node.name for node in tree.body), ('cpu_guard_model', 'cpu_guard_model_run'))
                names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
                self.assertTrue(names.isdisjoint({'os', 'time', 'open', 'print', 'socket', 'threading'}))
                flow = HostFlow()
                owner, value, failure, realm = run_whole(raw, flow)
                self.assertIsNone(failure)
                self.assertIs(value['status_authenticated'], False)
                cache, last, clocks = owner.profile_cache, owner.last, tuple(owner.now_values)
                flow.trace[:] = []
                exec(compile(source, 'HOST-actual-inner-guard-pure-CPU-model', 'exec'), realm)
                args = (owner, owner.files, owner._alias_clock, owner._alias_functions, owner._alias_codes)
                for rounds in (1, 3):
                    self.assertEqual(realm['cpu_guard_model_run'](realm['cpu_guard_model'], rounds, *args), rounds)
                for rounds in (False, 0, 1000001):
                    with self.assertRaises(ValueError):
                        realm['cpu_guard_model_run'](realm['cpu_guard_model'], rounds, *args)
                self.assertEqual(flow.trace, [])
                self.assertIs(owner.profile_cache, cache)
                self.assertEqual(owner.last, last)
                self.assertEqual(tuple(owner.now_values), clocks)
                self.assertEqual(read_pin(pin), raw)


if __name__ == '__main__':
    unittest.main()
