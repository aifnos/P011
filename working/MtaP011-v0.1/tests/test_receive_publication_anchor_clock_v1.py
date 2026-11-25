"""One affected HOST contract, not actual Publication/Owner/device proof.

When ROOT selects the one method, execute only the pinned actual Files bodies
and executor metadata/readlink helpers. Publication clocks, Factory binding,
Received directory and FD/content IO below are explicit narrow fixtures; they
do not authenticate a handoff, run the production graph or measure performance.
The unchanged Startup branch is compared as DATA, not executed or retested.
"""
import ast
import copy
from contextlib import contextmanager
import errno
import hashlib
import json
import math
from pathlib import Path
import stat
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
OLD = ('candidate/formal-receive-startup-anchor-clock-v1/runtime/mta_client_receive_factory.py',
       91901, '0799fe739a9a3de15fd15453d7ddf6df4c49e411ea30c2c0d9911ab73b1b29c8')
FACTORY = ('candidate/receive-publication-anchor-clock-v1/runtime/mta_client_receive_factory.py',
           94385, '2933d86ab3ce25b20b4efc0eea7733770b2209cc5c5ac062c52793bfceb6da79')
SPEC = ('candidate/receive-publication-anchor-clock-v1/exactsource-delta.json',
        9829, 'f65512055f7c232d01d920e33508579b889762a0b614a0100ba372fbe230feec')
EXECUTOR = ('candidate/formal-receive-startup-anchor-clock-v1/runtime/mta_client_executor.py',
            117757, 'fc723a7479d4b2d142b9024a2003de0eb5fcd0b907a4a0c6f91e7af2c2a7d3e2')


def pinned_bytes(pin):
    raw = (BASE / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('publication_anchor_contract_source_pin')
    return raw


def selected(tree, functions=(), classes=None, assignments=()):
    """Copy exact selected definitions; no imports/main/old suite execution."""
    nodes, found = [], set()
    for row in tree.body:
        if isinstance(row, ast.FunctionDef) and row.name in functions:
            nodes.append(copy.deepcopy(row)); found.add(row.name)
        elif isinstance(row, ast.ClassDef) and row.name in (classes or {}):
            cls = copy.deepcopy(row)
            cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and
                        n.name in classes[row.name]]
            if {n.name for n in cls.body} != set(classes[row.name]):
                raise ValueError('publication_anchor_contract_method_selection')
            nodes.append(cls); found.add(row.name)
        elif isinstance(row, ast.Assign) and any(isinstance(t, ast.Name) and
                t.id in assignments for target in row.targets for t in ast.walk(target)):
            nodes.append(copy.deepcopy(row))
            found.update(t.id for target in row.targets for t in ast.walk(target)
                         if isinstance(t, ast.Name))
    if found != set(functions) | set(classes or {}) | set(assignments):
        raise ValueError('publication_anchor_contract_definition_selection')
    return compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                   '<actual-publication-anchor-selected-bodies>', 'exec')


def method(tree, name):
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == '_Files')
    return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)


class Rejected(ValueError):
    pass


def fail(code):
    raise Rejected(code)


class PublicationFixture(object):
    """No production authority: these clocks only count actual Files calls."""
    def __init__(self, fixture):
        self.fixture = fixture

    def originals(self):
        return None

    def now(self):
        return self.fixture.full(self)

    def alias_now(self):
        return self.fixture.metadata(self)

    def close_parent_originals(self):
        return self.fixture.close_allowed


@contextmanager
def environment(ft, et):
    calls = dict(full=0, metadata=0, injected=0, open=0, read=0,
                 close=0, fstat=0, sha=0, received_check=0)
    tick, hook, reject, reject_at = [10.0], [None], [False], [None]
    events, inodes, opened, offsets, contents = [], {}, {}, {}, {}
    root_row = next(n for n in ft.body if isinstance(n, ast.Assign) and
                    any(isinstance(t, ast.Name) and t.id == 'ASSET_PHYSICAL_ROOT' for t in n.targets))
    root = ast.literal_eval(root_row.value)
    links = {'/tmp': '/var/tmp', '/var/tmp': '/var/volatile/tmp'}

    def record(kind):
        calls[kind] += 1
        events.append((kind, calls['full']))

    def full(scope):
        record('full')
        if reject[0] or calls['full'] == reject_at[0]: fail('fixture_full_rejected')
        if tick[0] >= scope.prepare_until: fail('publication_expired')
        return tick[0]

    def metadata(scope):
        record('metadata')
        if tick[0] >= scope.prepare_until: fail('publication_expired')
        return tick[0]

    def value(path):
        if path in contents:
            mode = stat.S_IFREG | (0o400 if path.startswith(root + '/') else 0o644)
            size = len(contents[path])
        else:
            mode = stat.S_IFLNK | 0o777 if path in links else stat.S_IFDIR | (
                0o1777 if path in ('/var/volatile', '/var/volatile/tmp') else 0o755)
            if path == root or path.startswith(root + '/'): mode = stat.S_IFDIR | 0o700
            size = len(links.get(path, ''))
        dev, ino, uid, gid = 1, inodes.setdefault(path, len(inodes) + 1), 0, 0
        if path == '/mnt/data': dev, ino, uid, gid = 66328, 21, 1000, 1000
        return types.SimpleNamespace(st_dev=dev, st_ino=ino, st_mode=mode,
            st_uid=uid, st_gid=gid, st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)

    class MetadataIo:
        def stat(self, path):
            events.append(('stat', path, calls['full']))
            row = value(path)
            if hook[0] is not None: hook[0](path)
            return row

        def readlink(self, path):
            events.append(('readlink', path, calls['full']))
            return links[path]

    def fake_open(path, flags):
        record('open')
        if path not in contents: raise OSError(errno.ENOENT, 'HOST fixture content absent')
        fd = 100 + calls['open']
        if fd in opened: raise AssertionError('fixture_fd_collision')
        opened[fd], offsets[fd] = path, 0
        return fd

    def fake_fstat(fd):
        record('fstat')
        if fd not in opened: raise OSError(errno.EBADF, 'HOST fixture closed FD')
        return value(opened[fd])

    def fake_read(fd, count):
        record('read')
        raw = contents[opened[fd]]
        chunk = raw[offsets[fd]:offsets[fd] + count]
        offsets[fd] += len(chunk)
        return chunk

    def fake_close(fd):
        record('close')
        if fd not in opened: raise OSError(errno.EBADF, 'HOST fixture duplicate close')
        del opened[fd]; del offsets[fd]
        return None

    def observed_sha(raw):
        record('sha')
        return hashlib.sha256(raw)

    executor = types.ModuleType('fixture_executor_metadata')
    executor.__dict__.update(_fail=fail, math=math, stat=stat)
    exec(selected(et, functions=('_uint', '_finite', '_meta', '_path'),
        classes={'_ReadOwner': ('__init__', 'check', '_fixed_tmp_alias')}), executor.__dict__)
    executor._LinuxIo = MetadataIo
    executor.DeploymentLoader = type('FixtureDeploymentLoader', (), {})
    executor.LoadedDeployment = type('FixtureLoadedDeployment', (), {})
    executor.ClientExecutor = type('FixtureClientExecutor', (), {})

    class Directory:
        def check(self):
            calls['received_check'] += 1
            return self

        def identity_rows(self):
            # Exact DATA needed by the original Received ancestor branch only.
            return ((), (), ('data', 66328, 21, stat.S_IFDIR | 0o755, 1000, 1000), (), (), ())

    class Factory: pass
    Publication = type('_PublicationAttempt', (), {name: getattr(PublicationFixture, name)
        for name in ('__init__', 'originals', 'now', 'alias_now', 'close_parent_originals')})
    functions = (Publication.__init__, Publication.originals, Publication.now,
                 Publication.alias_now, executor._ReadOwner.check, executor._ReadOwner._fixed_tmp_alias)
    codes = tuple(fn.__code__ for fn in functions)
    fixture = types.SimpleNamespace(full=full, metadata=metadata, close_allowed=True)
    scope = Publication(fixture); factory = Factory(); factory._active = scope
    scope.factory = factory
    scope._alias_functions = factory._alias_functions = functions
    scope._alias_codes = factory._alias_codes = codes
    scope._alias_clock = scope.alias_now
    scope.prepare_until = scope.original_prepare_until = 20.0
    scope.received_directory = Directory()
    ns = dict(__name__='fixture_actual_publication_files', _fail=fail, executor=executor,
        stat=stat, errno=errno, math=math, types=types,
        os=types.SimpleNamespace(stat=lambda path, follow_symlinks=False: MetadataIo().stat(path),
            open=fake_open, fstat=fake_fstat, read=fake_read, close=fake_close,
            O_RDONLY=0, O_CLOEXEC=0, O_NOFOLLOW=0),
        hashlib=types.SimpleNamespace(sha256=observed_sha),
        _PublicationAttempt=Publication, _StartupReadScope=type('UnexecutedStartupFixture', (), {}),
        FixedReceiveDeploymentFactory=Factory, _PUBLICATION_ALIAS_ORIGINALS=functions,
        _PUBLICATION_ALIAS_CODES=codes,
        _F_ORIGINALS=(executor, executor.DeploymentLoader, executor.LoadedDeployment,
                      executor.ClientExecutor, executor._ReadOwner))
    exec(selected(ft, functions=('_path', '_close_identity'),
        classes={'_Files': ('__init__', '_alias', 'anchors', 'read', 'close_row', 'close', 'closed')},
        assignments=('ASSET_PHYSICAL_ROOT', 'PYTHON', 'MAX_PROFILE_FILES', 'MAX_ENTRIES', 'MAX_IMAGE')), ns)
    Files = ns['_Files']; files = Files(scope); scope.files = files
    try:
        yield types.SimpleNamespace(scope=scope, files=files, Publication=Publication,
            Factory=Factory, factory=factory, executor=executor, calls=calls, events=events,
            tick=tick, hook=hook, reject=reject, reject_at=reject_at, root=root, contents=contents,
            opened=opened, fixture=fixture, functions=functions)
    finally:
        # Mutated code cells belong to explicit fixture functions; restore them
        # even after a failed assertion so no later subcase inherits mutation.
        for fn, code in zip(functions, codes): fn.__code__ = code


class ReceivePublicationAnchorClockV1Contract(unittest.TestCase):
    def test_actual_publication_anchor_density_io_and_refusals(self):
        old, current, spec_raw, executor = (pinned_bytes(pin) for pin in (OLD, FACTORY, SPEC, EXECUTOR))
        spec = json.loads(spec_raw.decode('ascii'))
        self.assertEqual(set(spec), {'schema', 'evidence', 'source', 'candidate', 'replacements'})
        self.assertEqual(spec['source'], list(OLD)); self.assertEqual(spec['candidate'], list(FACTORY))
        self.assertEqual(spec['schema'], 'p011-publication-anchor-clock-source-delta-v1')
        self.assertEqual(spec['evidence'], 'READBACK_BYTE_INVERSE_ONLY')
        self.assertEqual(len(spec['replacements']), 1)
        row = spec['replacements'][0]
        self.assertEqual(set(row), {'name', 'before', 'after', 'count'})
        self.assertEqual(row['name'], 'publication_fixed_anchor_metadata_clock')
        self.assertIs(type(row['count']), int)
        before, after = row['before'].encode('ascii'), row['after'].encode('ascii')
        self.assertEqual((row['count'], old.count(before), current.count(after)), (1, 1, 1))
        self.assertEqual(old.replace(before, after, 1), current)
        self.assertEqual(current.replace(after, before, 1), old)
        ft_old, ft_new, et = (ast.parse(raw) for raw in (old, current, executor))

        # No Startup execution: compare its unchanged guard byte text and AST.
        marker, end = '                # Only the retained Startup', '                clock()\n'
        guard_old = old[old.index(marker.encode()):]
        guard_new = current[current.index(marker.encode()):]
        self.assertEqual(guard_old[:guard_old.index(end.encode()) + len(end)],
                         guard_new[:guard_new.index(end.encode()) + len(end)])
        old_anchor, new_anchor = method(ft_old, 'anchors'), method(ft_new, 'anchors')
        old_loop = next(n for n in old_anchor.body if isinstance(n, ast.For))
        new_loop = next(n for n in new_anchor.body if isinstance(n, ast.For))
        old_select = next(n for n in old_loop.body if isinstance(n, ast.If))
        new_select = next(n for n in new_loop.body if isinstance(n, ast.If))
        self.assertEqual([ast.dump(n, include_attributes=False) for n in old_select.orelse],
                         [ast.dump(n, include_attributes=False) for n in new_select.orelse[0].body])
        for name in ('__init__', '_alias', 'read', 'close_row', 'close', 'closed'):
            self.assertEqual(ast.dump(method(ft_old, name), include_attributes=False),
                             ast.dump(method(ft_new, name), include_attributes=False))

        # Same actual ancestor stat/readlink order and returned metadata, with
        # only the new Publication fixed/deep branch changing clock density.
        paths = ('/proc/123/comm', '/usr/bin/python3.5', 'PRIVATE',
                 '/mnt/data/p011-toolbox/user/Received/file.txt', '/opt/fixture/deep/leaf',
                 '/proc/config.gz', '/usr/bin', 'LOOKALIKE')
        for path_name in paths:
            snapshots = []
            for ft in (ft_old, ft_new):
                with environment(ft, et) as e:
                    path = e.root + '/runtime35/unused.py' if path_name == 'PRIVATE' else (
                        e.root + '-other/runtime35/unused.py' if path_name == 'LOOKALIKE' else path_name)
                    d = len(path.split('/')) - 1
                    value = e.files.anchors(path)
                    io = [v[:2] for v in e.events if v[0] in ('stat', 'readlink')]
                    snapshots.append((value, io, e.calls.copy()))
            a, b = snapshots
            with self.subTest(anchor=path_name):
                self.assertEqual(a[:2], b[:2])
                if path_name in ('/proc/123/comm', '/usr/bin/python3.5', 'PRIVATE'):
                    self.assertEqual(a[2]['full'] - b[2]['full'], d - 2)
                    self.assertEqual(b[2]['metadata'] - a[2]['metadata'], d - 1)
                else:
                    self.assertEqual(a[2], b[2])
                self.assertEqual(a[2]['received_check'], 1 if path_name.startswith('/mnt/data/') else 0)

        for boundary in ('entry', 'exit'):
            with environment(ft_new, et) as e:
                if boundary == 'entry': e.reject[0] = True
                else:
                    def reject_exit(path):
                        if path == '/proc/123': e.reject[0] = True
                    e.hook[0] = reject_exit
                with self.subTest(full_boundary=boundary):
                    with self.assertRaisesRegex(Rejected, 'fixture_full_rejected'):
                        e.files.anchors('/proc/123/comm')
                    self.assertEqual(e.calls['full'], 1 if boundary == 'entry' else 2)
                    self.assertEqual(len([v for v in e.events if v[0] == 'stat']),
                                     0 if boundary == 'entry' else 3)
                    self.assertEqual(e.calls['open'], 0)

        # Actual read/open/fstat/two nonempty chunks/EOF/hash/original close
        # bodies; descriptor numbers and content are fixtures, not kernel proof.
        read_snapshots = []
        for ft in (ft_old, ft_new):
            with environment(ft, et) as e:
                path, raw = '/proc/123/comm', b'x' * 65540
                e.contents[path] = raw
                value, meta = e.files.read(path, 65545, hashlib.sha256(raw).hexdigest(), proc=True)
                self.assertEqual(value, raw)
                expected_full = 17 if ft is ft_old else 15
                self.assertEqual(e.calls['full'], expected_full)
                self.assertEqual((e.calls['open'], e.calls['read'], e.calls['sha'], e.calls['close']), (1, 3, 1, 1))
                positions = {kind: [v[1] for v in e.events if v[0] == kind]
                             for kind in ('open', 'fstat', 'read', 'sha', 'close')}
                self.assertEqual(positions, dict(open=[5 if ft is ft_old else 4],
                    fstat=[5, 13, 17, 17] if ft is ft_old else [4, 12, 15, 15],
                    read=[7, 9, 11] if ft is ft_old else [6, 8, 10],
                    sha=[16 if ft is ft_old else 14], close=[expected_full]))
                self.assertFalse(e.opened)
                self.assertIs(e.files.rows[-1]['closed'], True)
                self.assertIs(e.files.rows[-1]['unknown'], False)
                self.assertIs(e.files.close(), True); self.assertIs(e.files.close(), True)
                self.assertEqual(e.calls['close'], 1)
                read_snapshots.append((value, meta,
                    [v[:2] if v[0] in ('stat', 'readlink') else (v[0],)
                     for v in e.events if v[0] not in ('full', 'metadata')]))
        self.assertEqual(read_snapshots[0], read_snapshots[1])
        # Fail selected actual full guards, not merely an early anchors failure:
        # open-before, retained-fstat-after, first-chunk-after and final anchors
        # return before SHA. Late/opened mock descriptors still use old close.
        for ordinal, opened_count, read_count in ((4, 0, 0), (5, 1, 0), (7, 1, 1), (14, 1, 3)):
            with environment(ft_new, et) as e:
                e.contents['/proc/123/comm'] = b'x' * 65540
                e.reject_at[0] = ordinal
                with self.subTest(read_full_guard=ordinal):
                    with self.assertRaisesRegex(Rejected, 'fixture_full_rejected'):
                        e.files.read('/proc/123/comm', 65545, proc=True)
                    self.assertEqual(e.calls['full'], ordinal)
                    self.assertEqual((e.calls['open'], e.calls['read'], e.calls['close']),
                                     (opened_count, read_count, opened_count))
                    self.assertEqual(e.calls['sha'], 0)
                    self.assertFalse(e.opened)
                    if opened_count:
                        self.assertIs(e.files.rows[-1]['closed'], True)
                        self.assertIs(e.files.rows[-1]['unknown'], False)
                    else:
                        self.assertIs(e.files.pending, True)
                        self.assertIs(e.files.rows[-1]['unknown'], True)
        with environment(ft_new, et) as e:
            e.contents['/proc/123/comm'] = b'x'
            with self.assertRaisesRegex(Rejected, 'publication_pin_changed'):
                e.files.read('/proc/123/comm', 10, '0' * 64, proc=True)
            self.assertEqual((e.calls['sha'], e.calls['close']), (1, 1))
            self.assertFalse(e.opened)
            self.assertIs(e.files.rows[-1]['closed'], True)

        mutations = ('callback', 'alias_function', 'alias_code', 'originals_function', 'originals_code',
            'now_function', 'now_code', 'factory', 'factory_active', 'factory_functions', 'factory_codes',
            'alias_owner_type', 'alias_owner_clock', 'alias_owner_io', 'alias_owner_deadline',
            'scope_files', 'attempt', 'functions_empty', 'codes_empty', 'readowner_function', 'readowner_code')
        for mutation in mutations:
            with environment(ft_new, et) as e:
                injection_ns = dict(calls=e.calls)
                exec('def injected(self): calls["injected"] += 1; return 10.0', injection_ns)
                injected = injection_ns['injected']
                acted = [False]
                def mutate(path):
                    if path != '/' or acted[0]: return
                    acted[0] = True
                    if mutation == 'callback': e.scope._alias_clock = types.MethodType(injected, e.scope)
                    elif mutation == 'alias_function': e.Publication.alias_now = injected
                    elif mutation == 'alias_code': e.functions[3].__code__ = injected.__code__
                    elif mutation == 'originals_function': e.Publication.originals = injected
                    elif mutation == 'originals_code': e.functions[1].__code__ = injected.__code__
                    elif mutation == 'now_function': e.Publication.now = injected
                    elif mutation == 'now_code': e.functions[2].__code__ = injected.__code__
                    elif mutation == 'factory': e.scope.factory = types.SimpleNamespace(_active=e.scope)
                    elif mutation == 'factory_active': e.factory._active = object()
                    elif mutation == 'factory_functions': e.factory._alias_functions = ()
                    elif mutation == 'factory_codes': e.factory._alias_codes = ()
                    elif mutation == 'alias_owner_type': e.files.alias_owner = types.SimpleNamespace(clock=injected)
                    elif mutation == 'alias_owner_clock': e.files.alias_owner.clock = types.MethodType(injected, e.scope)
                    elif mutation == 'alias_owner_io': e.files.alias_owner.io = object()
                    elif mutation == 'alias_owner_deadline': e.files.alias_owner.deadline = 21.0
                    elif mutation == 'scope_files': e.scope.files = object()
                    elif mutation == 'attempt': e.files.attempt = types.SimpleNamespace(now=lambda: injected(e.scope))
                    elif mutation == 'functions_empty': e.scope._alias_functions = ()
                    elif mutation == 'codes_empty': e.scope._alias_codes = ()
                    elif mutation == 'readowner_function': e.executor._ReadOwner.check = injected
                    elif mutation == 'readowner_code': e.functions[4].__code__ = injected.__code__
                e.hook[0] = mutate
                with self.subTest(mid_stat_replacement=mutation):
                    with self.assertRaisesRegex(Rejected, 'publication_owner_changed'):
                        e.files.anchors('/proc/123/comm')
                    self.assertTrue(acted[0])
                    self.assertEqual((e.calls['injected'], e.calls['open']), (0, 0))
                    self.assertEqual(len([v for v in e.events if v[0] == 'stat']), 1)
                    self.assertEqual(e.scope.original_prepare_until, 20.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
