"""HOST-only cache contract of the complete pinned original _live_profile body.

The two complete real methods are AST-loaded, not the Factory module or an old
suite. Every OS/read/owner/platform boundary is an explicit in-memory fixture.
One synthetic root PID deliberately covers the original first-PID flow, both
namespace/config modes, and failures at all cache prefixes. Extra-PID alias
guards, real _Files/FD closes, device timing, native admission and RF are NOT
tested. This is DATA assignment/trace equivalence, never device acceptance.
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
MOTHER = ('candidate/receive-fc-http-cap-graph-v1/runtime/mta_client_receive_factory.py', 99371,
          'e1e02b700b51ca40dffc536622ab69647d58b93788b1458eb9db0f9cf017612b')
CANDIDATE = ('candidate/receive-profile-cache-v1/runtime/mta_client_receive_factory.py', 99675,
             '7ec346f3e9e6d6339eba1f74e48464106a9aaca68072dcf4e5321d2b4e86c943')
DELTA = ('candidate/receive-profile-cache-v1/exactsource-delta.json', 3003,
         '5246070b70cd2a21cd1294d3b1a210a3a1fdedae7d9ad64a91318090e5ccfea4')
SEED = ('candidate/receive-profile-cache-v1/generate_seed.py', 10715,
        '724a4f3fb9851c57c76b4709102f5ecba4f61fe9d512521600de5fa5c0b6aa01')
V2_PROJECTION = ('host/receive_startup_retained_v2_projection.py', 21095,
                 'ba0a54148c700ac28c5ee090490696dac0aec419ba440ad7be0642938b7a9912')
PROFILE_PROJECTION = ('host/receive_profile_cache_v1_projection.py', 8250,
                      '5bf3b440ccbc15fac60cae98cac9cf0f16b041ad73594ef37633962731eaedc1')
RETAINED_TARGET = ('results/receive-fc-http-cap-v1-startup-device-20261006-135639-eb79c456/private-startup-target.py',
                   2011600, '5de2906940f5fb759111724e482e9ec9d0d25c9a8456b1719fa9c56eb097cdbd')
LABELS = ('python', 'proc', 'daemon', 'namespace', 'endpoint', 'continuity')
PYTHON = '/usr/bin/python3.5'
DAEMON = '/usr/sbin/wpa_supplicant'
PID = 77
PROC = '/proc/77'
OWNER_PID = 42


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
        raise AssertionError('HOST frozen input pin changed: ' + row[0])
    return raw


def source_nodes(raw):
    rows = [node for node in ast.parse(raw.decode('ascii'), feature_version=(3, 5)).body
            if isinstance(node, ast.FunctionDef) and node.name in ('_stat_data', '_live_profile')]
    if tuple(node.name for node in rows) != ('_stat_data', '_live_profile') or any(
            node.decorator_list for node in rows):
        raise AssertionError('two whole original methods required')
    return rows


class HostPublicationError(ValueError):
    """Fixture exception; never a native publication/readiness receipt."""


class HostFlow(object):
    """All IO and the clock are memory-only explicit fixtures."""
    def __init__(self, failure=None, mode='disabled', no_daemon=False):
        self.failure, self.no_daemon = failure, no_daemon
        self.trace, self.counts = [], {}
        self.namespaces = ('cgroup', 'mnt') if mode == 'disabled' else ('mnt', 'net', 'pid', 'user')
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        config = b'# CONFIG_NAMESPACES is not set\n'
        self.config = compressor.compress(config) + compressor.flush()

    def hit(self, operation, path):
        self.trace.append((operation, path))
        key = operation, path
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.failure == (operation, path, self.counts[key]):
            raise OSError(errno.EIO, 'explicit HOST IO fixture failure')


class HostOwner(object):
    """Synthetic data owner, not _StartupReadScope or native Owner authority."""
    def __init__(self, flow):
        self.flow, self.pid = flow, OWNER_PID
        self.last, self.now_values = None, []
        self.profile_cache = ('stale HOST data must be reset',)
        self._alias_clock, self._alias_functions, self._alias_codes = self.now, (), ()
        self.files = HostFiles(self)

    def now(self):
        self.flow.hit('clock', 'HOST-existing-call')
        self.last = 100.0 + len(self.now_values) * 0.001
        self.now_values.append(self.last)
        return self.last


class HostFiles(object):
    """Logical reads are fake; actual _Files/open/fstat/close are not executed."""
    def __init__(self, owner):
        self.owner = owner

    def read(self, path, limit, expected=None, private=False, binary=False, proc=False, magic=False):
        owner, flow = self.owner, self.owner.flow
        flow.hit('read', path)
        flow.trace.append(('read-options', (path, limit, expected, private, binary, proc, magic)))
        owner.now()
        stat_line = (str(PID) + ' (wpa_supplicant) S ' + '0 ' * 18 + '12345\n').encode('ascii')
        values = {
            PYTHON: b'\x7fELF-HOST-python-image',
            DAEMON: b'\x7fELF-HOST-daemon-image',
            PROC + '/exe': b'\x7fELF-HOST-daemon-image',
            PROC + '/comm': b'other\n' if flow.no_daemon else b'wpa_supplicant\n',
            PROC + '/stat': stat_line,
            PROC + '/cmdline': b'/usr/sbin/wpa_supplicant\0-iwlan0\0',
            PROC + '/status': b'Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n',
            '/proc/config.gz': flow.config,
            '/proc/42/net/unix': (
                b'Num RefCount Protocol Flags Type St Inode Path\n'
                b'0000000000000000: 00000002 00000000 00000000 0002 01 9001 /run/wpa_supplicant/wlan0\n')}
        if path not in values:
            raise AssertionError('unexpected HOST read boundary: ' + path)
        raw = values[path]
        if len(raw) > limit:
            raise AssertionError('fixture exceeds real read budget')
        owner.now()
        identity = (1, 2, stat.S_IFREG | 0o500, 0, 0, 1, len(raw), 0, 0, 0)
        return raw, identity


class HostOs(object):
    def __init__(self, flow):
        self.flow = flow

    def listdir(self, path):
        self.flow.hit('listdir', path)
        if path == '/proc':
            return [str(PID)]
        if path in (PROC + '/ns', '/proc/self/ns'):
            return list(self.flow.namespaces)
        if path == PROC + '/fd':
            return ['3']
        raise AssertionError('unexpected HOST listdir boundary: ' + path)

    def stat(self, path, follow_symlinks=True):
        self.flow.hit('stat', (path, follow_symlinks))
        if path != PROC or follow_symlinks is not False:
            raise AssertionError('unexpected HOST stat boundary')
        return (1, 2, stat.S_IFDIR | 0o700, 0, 0, 1, 0, 0, 0, 0)

    def readlink(self, path):
        self.flow.hit('readlink', path)
        if path == PROC + '/exe':
            return DAEMON
        if path == PROC + '/fd/3':
            return 'socket:[9001]'
        for root in (PROC + '/ns/', '/proc/self/ns/'):
            if path.startswith(root) and path[len(root):] in self.flow.namespaces:
                name = path[len(root):]
                return name + ':[101]'
        raise AssertionError('unexpected HOST readlink boundary: ' + path)


def run_whole(raw, flow):
    """AST-exec only the complete two real methods in a labelled fake realm."""
    owner = HostOwner(flow)

    class HostLinuxIo(object):
        def validate(self):
            flow.hit('io.validate', 'HOST-fixture')

    def fail(code):
        raise HostPublicationError(code)

    realm = dict(__name__='HOST_PROFILE_CACHE_FIXTURES_NOT_NATIVE', re=re, hashlib=hashlib,
        stat=stat, errno=errno, zlib=zlib, types=types,
        sys=types.SimpleNamespace(version_info=(3, 5, 5)), os=HostOs(flow),
        executor=types.SimpleNamespace(_LinuxIo=HostLinuxIo, _meta=lambda value: value),
        PYTHON=PYTHON, MAX_IMAGE=16777216, MAX_ENTRIES=4096,
        _NAMESPACES=frozenset(('cgroup', 'ipc', 'mnt', 'net', 'pid', 'pid_for_children', 'user', 'uts')),
        _path=lambda value: value in (DAEMON, '/run/wpa_supplicant/wlan0'), _fail=fail)
    exec(compile(ast.Module(body=source_nodes(raw), type_ignores=[]),
                 'HOST-whole-profile-with-explicit-IO-owner-fixtures', 'exec'), realm)
    value, failure = None, None
    try:
        value = realm['_live_profile'](owner)
    except (HostPublicationError, OSError) as error:
        failure = type(error).__name__, str(error)
    return owner, value, failure


class ReceiveProfileCacheWholeFlowHost(unittest.TestCase):
    def test_whole_profile_cache_contract(self):
        """Only new cache DATA; original calls/control/results/errors remain."""
        inputs = {row[0]: read_pin(row) for row in (MOTHER, CANDIDATE, DELTA, SEED)}
        before, after = inputs[MOTHER[0]], inputs[CANDIDATE[0]]
        spec = json.loads(inputs[DELTA[0]].decode('ascii'))
        self.assertEqual(spec['origin'], dict(path=MOTHER[0], bytes=MOTHER[1], sha256=MOTHER[2]))
        self.assertEqual(spec['candidate'], dict(path=CANDIDATE[0], bytes=CANDIDATE[1], sha256=CANDIDATE[2]))
        self.assertEqual(spec['byte_delta'], 304)
        self.assertEqual(spec['cache_labels'], list(LABELS))
        self.assertEqual(spec['business_methods'], ['_live_profile'])
        self.assertEqual(spec['additional_clock_calls'], 0)
        self.assertEqual(spec['additional_io_calls'], 0)
        restored = after
        for edit in reversed(spec['replacements']):
            old, new = edit['before'].encode('ascii'), edit['after'].encode('ascii')
            self.assertEqual(restored.count(new), edit['count'])
            restored = restored.replace(new, old)
        self.assertEqual(restored, before)
        self.assertEqual(ast.dump(ast.parse(restored), include_attributes=True),
                         ast.dump(ast.parse(before), include_attributes=True))
        original_node, selected_node = source_nodes(before)[1], copy.deepcopy(source_nodes(after)[1])
        kept, removed = [], []
        for item in selected_node.body:
            target = item.targets[0] if isinstance(item, ast.Assign) and len(item.targets) == 1 else (
                item.target if isinstance(item, ast.AugAssign) else None)
            if (isinstance(target, ast.Attribute) and target.attr == 'profile_cache' and
                    isinstance(target.value, ast.Name) and target.value.id == 'attempt'):
                removed.append(item)
            else:
                kept.append(item)
        self.assertEqual(len(removed), 7)
        self.assertIsInstance(removed[0], ast.Assign)
        self.assertEqual(ast.dump(removed[0].value, include_attributes=False),
                         ast.dump(ast.parse('()', mode='eval').body, include_attributes=False))
        for item in removed[1:]:
            self.assertIsInstance(item, ast.AugAssign)
            self.assertIsInstance(item.op, ast.Add)
            self.assertEqual(ast.dump(item.value, include_attributes=False),
                             ast.dump(ast.parse('(attempt.last,)', mode='eval').body, include_attributes=False))
        selected_node.body = kept
        self.assertEqual(ast.dump(original_node, include_attributes=False),
                         ast.dump(selected_node, include_attributes=False))
        cases = (
            ('success-config', None, 'disabled', False, 6),
            ('success-full4', None, 'full', False, 6),
            ('fail-prefix0', ('read', PYTHON, 1), 'disabled', False, 0),
            ('fail-prefix1', ('listdir', '/proc', 1), 'disabled', False, 1),
            ('fail-prefix2', ('read', PROC + '/stat', 1), 'disabled', False, 2),
            ('fail-prefix3', ('listdir', PROC + '/ns', 1), 'disabled', False, 3),
            ('fail-prefix4', ('read', '/proc/42/net/unix', 1), 'disabled', False, 4),
            ('fail-prefix5', ('read', PROC + '/stat', 2), 'disabled', False, 5),
            ('original-guard-still-fails', None, 'disabled', True, 2))
        for label, injected, mode, no_daemon, count in cases:
            with self.subTest(explicit_HOST_fixture=label):
                original_flow = HostFlow(injected, mode, no_daemon)
                selected_flow = HostFlow(injected, mode, no_daemon)
                original, original_value, original_failure = run_whole(before, original_flow)
                selected, selected_value, selected_failure = run_whole(after, selected_flow)
                self.assertEqual(selected_flow.trace, original_flow.trace)
                self.assertEqual(selected.now_values, original.now_values)
                self.assertEqual(selected_value, original_value)
                self.assertEqual(selected_failure, original_failure)
                self.assertIs(type(selected.profile_cache), tuple)
                self.assertEqual(len(selected.profile_cache), count)
                self.assertLessEqual(len(selected.profile_cache), 6)
                self.assertTrue(all(type(value) is float and value in selected.now_values
                                    for value in selected.profile_cache))
                self.assertEqual(tuple(sorted(selected.profile_cache)), selected.profile_cache)
                if count == 6:
                    self.assertIsNone(selected_failure)
                    self.assertIs(selected_value['status_authenticated'], False)
                else:
                    self.assertIsNotNone(selected_failure)
                if no_daemon:
                    self.assertEqual(selected_failure, ('HostPublicationError', 'publication_daemon_data'))
        self.assertTrue(all(read_pin(row) == inputs[row[0]] for row in (MOTHER, CANDIDATE, DELTA, SEED)))


def projection_module(row):
    """Actual pinned pure projection; never the target/device program."""
    raw = read_pin(row)
    tree = ast.parse(raw.decode('ascii'), feature_version=(3, 5))
    if any(isinstance(node, ast.If) for node in tree.body):
        raise AssertionError('projection must have no entry guard to execute')
    module = types.ModuleType('HOST_actual_pinned_projection_only')
    module.__file__ = str(BASE / row[0])
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module, raw


def projection_fixture(cache=(), missing=False, wrong_identity=False):
    """Identity-shaped HOST held graph, NOT actual private Owner authority.

The actual copied V2 context is evaluated, not replaced with a fake result.
Its cached check_active function raises if called: this is a passive reader.
"""
    session = types.ModuleType('HOST_identity_fixture_session')
    system = types.ModuleType('HOST_identity_fixture_sys')
    own_module = types.ModuleType('HOST_identity_fixture_owner')
    factory_module = types.ModuleType('HOST_identity_fixture_factory')

    def never_called(self):
        raise AssertionError('projection called a HOST clock/active guard')

    check = types.FunctionType(never_called.__code__, factory_module.__dict__, 'check_active')
    scope_type = type('HOSTScopeIdentityFixture', (), {'check_active': check})
    factory_type = type('HOSTFactoryIdentityFixture', (), {})
    owner_type = type('HOSTOwnerIdentityFixture', (), {})
    session_type = type('HOSTSessionIdentityFixture', (), {})
    originals, codes = (check,) * 6, (check.__code__,) * 6
    factory_module.__dict__.update(_StartupReadScope=scope_type, FixedReceiveDeploymentFactory=factory_type,
                                   _STARTUP_ALIAS_ORIGINALS=originals, _STARTUP_ALIAS_CODES=codes)
    loader = types.SimpleNamespace(modules={'mta_client_receive_factory': factory_module})
    system.modules = {'mta_client_receive_factory': factory_module}
    if wrong_identity:
        system.modules['mta_client_receive_factory'] = types.ModuleType('HOST_wrong_identity')
    retained, owner, scope, factory = session_type(), owner_type(), scope_type(), factory_type()
    own_module.FixedStateServiceOwner = owner_type
    session.FixedSession, session._RETAINED, session.sys = session_type, retained, system
    retained.__dict__.update(owner=owner, loader=loader, owner_module=own_module, startup_scope=scope)
    owner.__dict__.update(loader=loader, _startup_namespace_original=own_module.__dict__,
                          _startup_owner_type_original=owner_type, factory=factory, startup_scope=scope,
                          _startup_scope_original=scope, _startup_factory_original=factory)
    factory._startup_scope = scope
    scope.__dict__.update(owner=owner, factory=factory, _alias_functions=originals, _alias_codes=codes)
    if not missing:
        scope.profile_cache = cache
    return retained, session


class ReceiveProfileProjectionIntegrationHost(unittest.TestCase):
    def test_actual_v2_and_profile_injection_full_inverse(self):
        """Real sealed whole target is parsed/recomposed as bytes, NEVER run."""
        v2, v2_raw = projection_module(V2_PROJECTION)
        profile, profile_raw = projection_module(PROFILE_PROJECTION)
        selected = read_pin(RETAINED_TARGET)
        anchor = b'retained=session._RETAINED\n'
        v2_fragment = v2.target_fragment(v2_raw)
        self.assertEqual(selected.count(anchor + v2_fragment), 1)
        original = selected.replace(anchor + v2_fragment, anchor, 1)
        self.assertEqual(v2.inject(original, v2_raw), selected)
        fragment = profile.target_fragment(profile_raw)
        combined = profile.inject(selected, profile_raw)
        self.assertEqual(combined.count(anchor + fragment), 1)
        self.assertEqual(combined.replace(anchor + fragment, anchor, 1), selected)
        self.assertLessEqual(len(combined), 2097152)
        self.assertLessEqual(max(map(len, combined.splitlines())), 256)
        self.assertLessEqual(len(fragment), 16384)
        ast.parse(original.decode('ascii'), feature_version=(3, 5))
        ast.parse(selected.decode('ascii'), feature_version=(3, 5))
        ast.parse(combined.decode('ascii'), feature_version=(3, 5))
        with self.assertRaises(ValueError):
            profile.inject(combined, profile_raw)
        context = '_private_startup_retained_context_v2'
        def context_source(raw):
            text = raw.decode('ascii')
            rows = [node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == context]
            self.assertEqual(len(rows), 1)
            return ast.get_source_segment(text, rows[0])
        self.assertEqual(context_source(v2_raw), context_source(profile_raw))
        self.assertEqual(read_pin(RETAINED_TARGET), selected)
        self.assertEqual(read_pin(V2_PROJECTION), v2_raw)
        self.assertEqual(read_pin(PROFILE_PROJECTION), profile_raw)

    def test_actual_passive_reader_and_strict_parser_data_contract(self):
        """Real reader/parser on labelled HOST identities; never native PASS."""
        profile, raw = projection_module(PROFILE_PROJECTION)
        reader = profile._private_startup_profile_cache_v1
        unknown = dict(available=False, unknown=True, labels=None, values=None, cached_count=None)
        for count in (0, 1, 4, 6):
            with self.subTest(cached_HOST_prefix=count):
                cached = tuple(float(index) for index in range(1, count + 1))
                retained, session = projection_fixture(cached)
                value = reader(retained, session)
                expected = dict(available=True, unknown=False, labels=LABELS,
                                values=cached + (None,) * (6 - count), cached_count=count)
                self.assertEqual(value, expected)
                wire = (profile.PREFIX + repr(value) + '\r\r\n').encode('ascii')
                self.assertEqual(profile.parse_private(wire), expected)
                self.assertIs(session._RETAINED, retained)
                self.assertIs(retained.startup_scope.profile_cache, cached)
        for name, fixture in (
                ('missing', projection_fixture(missing=True)),
                ('wrong-identity', projection_fixture((1.0,), wrong_identity=True)),
                ('not-tuple', projection_fixture([1.0])),
                ('over-six', projection_fixture((1.0,) * 7)),
                ('not-float', projection_fixture((1,))),
                ('not-finite', projection_fixture((float('nan'),)))):
            with self.subTest(unknown_HOST_reason=name):
                value = reader(*fixture)
                self.assertEqual(value, unknown)
                self.assertEqual(profile.parse_private((profile.PREFIX + repr(value) + '\n').encode('ascii')), unknown)
        valid = dict(available=True, unknown=False, labels=LABELS,
                     values=(1.0, None, None, None, None, None), cached_count=1)
        malformed_values = (
            dict(valid, cached_count=True),
            dict(valid, cached_count=7),
            dict(valid, labels=list(LABELS)),
            dict(valid, labels=('wrong',) + LABELS[1:]),
            dict(valid, values=(1, None, None, None, None, None)),
            dict(valid, values=(-1.0, None, None, None, None, None)),
            dict(valid, values=(1.0, 2.0, None, None, None, None)),
            dict(valid, values=(1.0, None)),
            dict(valid, unknown=True),
            dict(valid, ready=True),
            dict(unknown, cached_count=0))
        wires = [(profile.PREFIX + repr(value) + '\n').encode('ascii') for value in malformed_values]
        good = (profile.PREFIX + repr(valid) + '\n').encode('ascii')
        wires.extend((b'', good + good,
            (profile.PREFIX + "{'available': True, 'available': True, 'unknown': False, 'labels': None, 'values': None, 'cached_count': None}\n").encode('ascii'),
            (profile.PREFIX + "{'available': True, 'unknown': False, 'labels': None, 'values': (1 + 1,), 'cached_count': 1}\n").encode('ascii')))
        for index, wire in enumerate(wires):
            with self.subTest(strict_reject=index):
                with self.assertRaises(ValueError):
                    profile.parse_private(wire)
        self.assertEqual(read_pin(PROFILE_PROJECTION), raw)


if __name__ == '__main__':
    unittest.main()
