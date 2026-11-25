"""Fixed tmp-alias v11 SOURCE/Fake only; no actual OS, process or RF."""
import ast
import builtins
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).absolute().parents[1]
CANDIDATE = BASE / 'candidate/client-tmp-alias-v11/runtime'
sys.path.insert(0, str(BASE / 'runtime'))
import test_client_linux_provider as old_p
from test_client_files import Node, TOKEN, RUN
import test_client_executor as old_f


def load(name, path, alias=None):
    module = types.ModuleType(name); module.__file__ = str(path)
    namespace = dict(vars(builtins))
    original = builtins.__import__
    def private_import(name, *args, **kwargs):
        return alias if name == 'mta_client_tmp_alias' and alias is not None else original(name, *args, **kwargs)
    namespace['__import__'] = private_import
    module.__dict__['__builtins__'] = namespace
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


alias = load('v11_fixed_tmp_helper', CANDIDATE / 'mta_client_tmp_alias.py')
p = load('v11_private_provider', CANDIDATE / 'mta_client_linux_provider.py', alias)
f = load('v11_private_executor', CANDIDATE / 'mta_client_executor.py')
PHYSICAL_RUN = f.PHYSICAL_ROOT + '/client-' + TOKEN


class AliasIo(old_p.Io):
    def __init__(self, use_alias=True):
        old_p.Io.__init__(self)
        self.use_alias, self.link_hook = use_alias, None
        if use_alias:
            for path in tuple(self.nodes):
                if path.startswith(f.ROOT + '/'):
                    node = self.nodes.pop(path)
                    node.path = f.PHYSICAL_ROOT + path[len(f.ROOT):]
                    self.nodes[node.path] = node
            node = self.nodes.pop(f.ROOT)
            node.path = f.PHYSICAL_ROOT; self.nodes[node.path] = node
            self.add('/tmp', stat.S_IFLNK | 0o777, b'/var/tmp')
            self.add('/var', stat.S_IFDIR | 0o755)
            self.add('/var/tmp', stat.S_IFLNK | 0o777, b'/var/volatile/tmp')
            self.add('/var/volatile', stat.S_IFDIR | 0o1777)
            self.add('/var/volatile/tmp', stat.S_IFDIR | 0o1777)
        self.ops[:] = []

    def physical(self, path):
        if self.use_alias and (path == f.ROOT or path.startswith(f.ROOT + '/')):
            return f.PHYSICAL_ROOT + path[len(f.ROOT):]
        return path

    def stat(self, path):
        path = self.physical(path); self.event('stat', path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST absent')
        return self.nodes[path].metadata()

    def stat_root(self): return self.stat('/')

    def readlink(self, path):
        self.event('readlink', path)
        if self.link_hook: self.link_hook(self, path)
        return self.nodes[path].data.decode('ascii')

    def readlink_at(self, parent, name): return self.readlink(self.path(parent, name))

    def open(self, path, flags=None):
        return self._open(self.physical(path), p.ARM_READ if flags is None else flags, 0)


def manifest():
    old = old_p.manifest()
    value = dict((key, getattr(old, key)) for key in p._KEYS)
    value['status_manifest'] = dict(old.status_manifest)
    value['wpa_exe'] = PHYSICAL_RUN + '/native/mta-wpa-supplicant'
    return p.ProviderManifest(value, _manifest_sha256=old.manifest_sha256)


def provider(use_alias=True):
    io = AliasIo(use_alias)
    return p.LinuxClientInitProvider(manifest(), _io=io, _clock=lambda: 1.), io


def file_owner(mode=0o400, binary=False, physical=False, links=1):
    io = AliasIo()
    path = PHYSICAL_RUN if physical else RUN
    io.add(PHYSICAL_RUN + '/runtime', stat.S_IFDIR | 0o700)
    path += '/runtime/value.py'
    raw = b'\x7fELFHOST' if binary else b'# HOST synthetic only\\n'
    io.add(io.physical(path), stat.S_IFREG | mode, raw, links=links)
    return f._ReadOwner(io, lambda: 1., 3.), io, path, raw


def method_sources(raw):
    lines = raw.decode('utf-8').splitlines(True)
    result = {}
    def visit(nodes, prefix=''):
        for node in nodes:
            if isinstance(node, ast.ClassDef): visit(node.body, prefix + node.name + '.')
            elif isinstance(node, ast.FunctionDef):
                result[prefix + node.name] = ''.join(lines[node.lineno - 1:node.end_lineno]).encode('utf-8')
    visit(ast.parse(raw.decode('utf-8')).body)
    return result


class TmpAliasProviderV11Tests(unittest.TestCase):
    def setUp(self):
        p._OWNERS[:] = []
        for name in ('os.open', 'os.close', 'os.readlink', 'os.kill', 'os.fork',
                'socket.socket', 'subprocess.Popen', 'ctypes.CDLL'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS/RF forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))

    def test_source_python35_unmodified_method_bytes_and_twenty_module_order(self):
        sources = ((BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_executor.py',
            CANDIDATE / 'mta_client_executor.py', '1b2b07f45d3564b743dfa66921bf831962ec6c3754b25e35c384ab699de362a3',
            {'_LinuxIo.readlink', '_ReadOwner.anchors', '_ReadOwner._fixed_tmp_alias',
                '_ReadOwner.read_file', 'DeploymentLoader.load'}),
            (BASE / 'candidate/client-integrated-v9/runtime/mta_client_linux_provider.py',
            CANDIDATE / 'mta_client_linux_provider.py', '8bb5dfae34ab7cc4db772957781c8c9385bf6285250137351bac70de685798d6',
            {'ProviderManifest.__init__', '_ArmIo.stat_root', '_ArmIo.readlink_at',
                '_Ledger.__init__', '_Ledger._alias_identity', '_Ledger.close',
                'LinuxClientInitProvider.__init__', 'LinuxClientInitProvider._anchors',
                'LinuxClientInitProvider._verify_anchors', 'LinuxClientInitProvider._alias_check',
                'LinuxClientInitProvider._alias_fd', 'LinuxClientInitProvider._alias_open',
                'LinuxClientInitProvider._register_alias_directory', 'LinuxClientInitProvider._known_live_fd'}))
        for original_path, candidate_path, pin, changed in sources:
            original, candidate = original_path.read_bytes(), candidate_path.read_bytes()
            self.assertEqual(pin, hashlib.sha256(original).hexdigest())
            old_methods, new_methods = method_sources(original), method_sources(candidate)
            self.assertEqual(set(new_methods) - set(old_methods), changed - set(old_methods))
            for name, raw in old_methods.items():
                if name not in changed: self.assertEqual(raw, new_methods[name], name)
            ast.parse(candidate.decode('utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))
        self.assertEqual(20, len(f.MODULES))
        self.assertEqual(('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init'), f.MODULES[:4])
        self.assertEqual(old_f.f.MODULES, tuple(n for n in f.MODULES if n != 'mta_client_tmp_alias'))
        self.assertEqual(('/var/volatile/tmp/p011-mta-client-rfinit'), f.PHYSICAL_ROOT)

    def test_pure_constructors_and_manifest_planned_physical_only(self):
        io = AliasIo(); io.ops[:] = []
        value = manifest()
        p.LinuxClientInitProvider(value, _io=io)
        f.DeploymentLoader(TOKEN, 'b' * 64, _io=io)
        self.assertEqual([], io.ops)
        self.assertEqual(PHYSICAL_RUN + '/native/mta-wpa-supplicant', value.wpa_exe)
        self.assertEqual(RUN, value.run_dir); self.assertEqual(RUN + '/ctrl', value.ctrl_dir)
        self.assertEqual(RUN + '/client.conf', value.cfg)
        fields = dict((key, getattr(value, key)) for key in p._KEYS)
        fields['status_manifest'] = dict(value.status_manifest); fields['wpa_exe'] = RUN + '/native/mta-wpa-supplicant'
        with self.assertRaises(p.LinuxProviderError): p.ProviderManifest(fields, _manifest_sha256=value.manifest_sha256)
        self.assertNotIn(TOKEN, repr(value))

    def test_provider_seven_original_fds_five_logical_indices_and_fresh_verify(self):
        obj, io = provider(); obj._anchors(3.)
        self.assertEqual(5, len(obj._anchor_chain)); self.assertEqual(7, len(obj._ledger.rows))
        root = obj._anchor_chain[0][2]
        self.assertIs(obj._tmp_alias.authenticate(obj, root), obj._tmp_alias)
        self.assertIs(obj._anchor_chain[1][0], obj._tmp_alias.tmp_parent)
        self.assertIs(obj._anchor_chain[1][2], obj._tmp_alias.tmp_ticket)
        self.assertEqual(tuple(obj._ledger.rows[1:3]), obj._tmp_alias.prefix_tickets)
        self.assertIs(obj._run_anchor, obj._anchor_chain[3][2])
        self.assertIs(obj._ctrl_anchor, obj._anchor_chain[4][2])
        obj._verify_anchors(3.)
        self.assertTrue(obj._ledger.close_all())
        self.assertEqual(7, len(io.closed)); self.assertEqual(7, len(set(io.closed)))
        self.assertTrue(all(obj._ledger.ebadf(row) for row in obj._ledger.rows))
        obj._ledger.close_all(); self.assertEqual(7, len(io.closed))

    def test_ordinary_tmp_directory_keeps_five_originals(self):
        obj, io = provider(False); obj._anchors(3.)
        self.assertIsNone(obj._tmp_alias); self.assertEqual(5, len(obj._ledger.rows))
        self.assertEqual(5, len(obj._anchor_chain)); self.assertTrue(obj._ledger.close_all())

    def test_provider_changed_link_or_prefix_foreign_owner_stays_failed(self):
        for path, field, value in (('/tmp', 'data', b'/other'), ('/var/tmp', 'data', b'/other'),
                ('/var/volatile', 'mode', stat.S_IFDIR | 0o777), ('/var', 'uid', 1)):
            with self.subTest(path=path, field=field):
                obj, io = provider(); obj._anchors(3.); setattr(io.nodes[path], field, value)
                with self.assertRaises((p.LinuxProviderError, alias.TmpAliasError)): obj._verify_anchors(3.)
                self.assertTrue(obj._tmp_alias._unknown)
                setattr(io.nodes[path], field, b'/var/tmp' if path == '/tmp' else b'/var/volatile/tmp' if path == '/var/tmp' else 0)
                with self.assertRaises((p.LinuxProviderError, alias.TmpAliasError)): obj._verify_anchors(3.)
                self.assertEqual(7, len(obj._ledger.rows))

    def test_provider_partial_open_retains_originals_never_retries(self):
        obj, io = provider()
        io.faults[('open', '/var/volatile')] = OSError(errno.EIO, 'HOST prefix')
        with self.assertRaises(OSError): obj._anchors(3.)
        self.assertIsNotNone(obj._tmp_alias)
        self.assertEqual(1, len(obj._tmp_alias.prefix_tickets))
        before = tuple(io.opened)
        with self.assertRaises(p.LinuxProviderError): obj._anchors(3.)
        self.assertEqual(before, tuple(io.opened))
        self.assertEqual(3, len(obj._ledger.rows))  # Root, var, negative volatile attempt.
        self.assertTrue(obj._ledger.close_all()); self.assertEqual(2, len(io.closed))

    def test_provider_foreign_or_closed_callback_ticket_not_numeric_grant(self):
        obj, io = provider(); obj._anchors(3.)
        row = obj._ledger.rows[1]
        foreign = types.SimpleNamespace(fd=row.fd, unknown=False, closed=False, meta=row.meta)
        with self.assertRaises(p.LinuxProviderError): obj._alias_fd(foreign)
        self.assertTrue(obj._ledger.close(row))
        with self.assertRaises(p.LinuxProviderError): obj._alias_fd(row)

    def test_bootstrap_logical_and_physical_sources_share_exact_leaf_and_close(self):
        for physical in (False, True):
            with self.subTest(physical=physical):
                owner, io, path, raw = file_owner(physical=physical)
                result, row = owner.read_file(path, 1024, hashlib.sha256(raw).hexdigest(), True)
                self.assertEqual(raw, result); self.assertEqual(row['metadata'], f._meta(io.stat(path)))
                self.assertTrue(row['closed']); self.assertFalse(owner.pending)
                self.assertEqual(1, len(io.opened)); self.assertEqual(1, len(io.closed))
                owner.close(); self.assertEqual(1, len(io.closed))

    def test_bootstrap_physical_native_private_mode_and_nlink_not_system_exception(self):
        for mode, links, good in ((0o500, 1, True), (0o755, 1, False), (0o500, 2, False)):
            with self.subTest(mode=mode, links=links):
                owner, io, path, raw = file_owner(mode=mode, binary=True, physical=True, links=links)
                if good:
                    self.assertEqual(raw, owner.read_file(path, 1024, binary=True)[0])
                else:
                    with self.assertRaises(f.ExecutorError): owner.read_file(path, 1024, binary=True)
                self.assertEqual(1, len(io.closed)); self.assertFalse(owner.pending)

    def test_bootstrap_alias_change_and_leaf_mismatch_rejected_without_new_fd(self):
        owner, io, path, raw = file_owner()
        def changed(io, name):
            if name == '/var/tmp': io.nodes['/tmp'].data = b'/var/other'
        io.link_hook = changed
        with self.assertRaises(f.ExecutorError): owner.read_file(path, 1024, private=True)
        self.assertEqual([], io.opened)
        owner, io, path, raw = file_owner(physical=True)
        original = io.stat
        def wrong(path):
            value = original(path)
            if path.startswith(RUN + '/'): value.st_ino += 1
            return value
        io.stat = wrong
        with self.assertRaises(f.ExecutorError): owner.read_file(path, 1024, private=True)
        self.assertEqual(1, len(io.opened)); self.assertEqual(1, len(io.closed))

    def test_bootstrap_foreign_links_unsafe_dirs_and_source_mode_failclosed(self):
        for path, field, value in (('/tmp', 'uid', 1), ('/tmp', 'links', 2),
                ('/var/tmp', 'gid', 1), ('/var/volatile', 'mode', stat.S_IFDIR | 0o777)):
            with self.subTest(path=path, field=field):
                owner, io, source, raw = file_owner()
                setattr(io.nodes[path], field, value)
                with self.assertRaises(f.ExecutorError): owner.read_file(source, 1024, private=True)
                self.assertEqual([], io.opened)
        owner, io, source, raw = file_owner(mode=0o600, physical=True)
        with self.assertRaises(f.ExecutorError): owner.read_file(source, 1024)
        self.assertEqual(1, len(io.closed))

    def test_canonical_system_python_only_nlink2_else_rejected(self):
        for path, uid, good in (('/usr/bin/python3.5', 0, True),
                ('/usr/bin/other', 0, False), ('/usr/bin/python3.5', 1, False)):
            with self.subTest(path=path, uid=uid):
                io = AliasIo()
                io.add('/usr', stat.S_IFDIR | 0o755); io.add('/usr/bin', stat.S_IFDIR | 0o755)
                io.add(path, stat.S_IFREG | 0o755, b'\x7fELFHOST', uid=uid, links=2)
                owner = f._ReadOwner(io, lambda: 1., 3.)
                if good: owner.read_file(path, 1024, binary=True)
                else:
                    with self.assertRaises(f.ExecutorError): owner.read_file(path, 1024, binary=True)
                self.assertEqual(1, len(io.closed))

    def test_bootstrap_close_unknown_keeps_exact_owner_once(self):
        owner, io, path, raw = file_owner()
        original = io.close
        def close(fd): original(fd); raise OSError(errno.EIO, 'HOST close')
        io.close = close
        owner.read_file(path, 1024, private=True)
        row = owner.rows[0]
        self.assertTrue(owner.pending); self.assertFalse(row['closed']); self.assertTrue(row['attempted'])
        self.assertFalse(owner.close()); self.assertEqual(1, len(io.closed))

    def test_alias_directory_counters_are_not_identity_but_link_changes_are(self):
        owner, io, path, raw = file_owner()
        physical_dirs = ('/', '/var', '/var/volatile', '/var/volatile/tmp')
        def counters(io, name):
            for directory in physical_dirs:
                node = io.nodes[directory]
                node.links += 1; node.stamp += 1; node.data += b'counter'
        io.link_hook = counters
        self.assertEqual(raw, owner.read_file(path, 1024, private=True)[0])
        self.assertTrue(owner.rows[0]['closed']); self.assertFalse(owner.pending)
        for field, change in (('stamp', 1), ('ino', 1), ('data', b'/var/other')):
            with self.subTest(link_field=field):
                owner, io, path, raw = file_owner()
                calls = [0]
                def link_change(io, name):
                    calls[0] += 1
                    if calls[0] == 1:
                        node = io.nodes['/tmp']
                        setattr(node, field, getattr(node, field) + change if type(change) is int else change)
                io.link_hook = link_change
                with self.assertRaises(f.ExecutorError): owner.read_file(path, 1024, private=True)
                self.assertEqual([], io.opened)
        for leaf in ('mta_client_executor.py', 'mta_client_linux_provider.py'):
            ast.parse((CANDIDATE / leaf).read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))

    def test_provider_exact_alias_callback_and_verify_allow_only_directory_counters(self):
        obj, io = provider(); obj._anchors(3.)
        alias_rows = (obj._anchor_chain[0][2],) + obj._tmp_alias.prefix_tickets + (obj._tmp_alias.tmp_ticket,)
        paths = ('/', '/var', '/var/volatile', '/var/volatile/tmp')
        for row, path in zip(alias_rows, paths):
            node = io.nodes[path]
            node.links += 1; node.stamp += 1; node.data += b'counter'
            self.assertEqual(row.fd, obj._alias_fd(row))
            self.assertTrue(obj._known_live_fd(row.fd, p.baseline._metadata(io.fstat(row.fd))))
        obj._verify_anchors(3.)
        self.assertEqual(7, len(obj._ledger.rows)); self.assertEqual(5, len(obj._anchor_chain))
        self.assertEqual(4, len(obj._ledger._alias_rows))
        self.assertTrue(obj._ledger.close_all()); self.assertEqual(7, len(io.closed))
        self.assertTrue(all(obj._ledger.ebadf(row) for row in obj._ledger.rows))
        obj._ledger.close_all(); self.assertEqual(7, len(io.closed))
        for use_alias, path, field, delta in ((True, PHYSICAL_RUN, 'links', 1),
                (True, f.PHYSICAL_ROOT, 'links', 1), (True, PHYSICAL_RUN + '/ctrl', 'links', 1),
                (True, '/var', 'ino', 1), (True, '/var/volatile', 'mode', 0o002),
                (False, '/tmp', 'links', 1), (True, '/var/volatile/tmp', 'links', -1)):
            with self.subTest(alias=use_alias, path=path, field=field):
                obj, io = provider(use_alias); obj._anchors(3.)
                node = io.nodes[path]; setattr(node, field, getattr(node, field) + delta)
                with self.assertRaises((p.LinuxProviderError, alias.TmpAliasError)):
                    obj._verify_anchors(3.)
                affected = next(row for row in obj._ledger.rows if row.fd is not None and io.handles[row.fd][0].path == path)
                self.assertFalse(obj._known_live_fd(affected.fd, p.baseline._metadata(io.fstat(affected.fd))))
                self.assertFalse(obj._ledger.close(affected)); self.assertTrue(affected.unknown)
                self.assertNotIn(affected.fd, io.closed)
        obj, io = provider()
        io.faults[('open', '/var/volatile')] = OSError(errno.EIO, 'HOST prefix')
        with self.assertRaises(OSError): obj._anchors(3.)
        self.assertEqual(2, len(obj._ledger._alias_rows)); self.assertTrue(obj._tmp_alias._unknown)
        for path in ('/', '/var'): io.nodes[path].links += 1
        self.assertTrue(obj._ledger.close_all()); self.assertEqual(2, len(io.closed))
        ast.parse((CANDIDATE / 'mta_client_linux_provider.py').read_text(encoding='utf-8'), feature_version=(3, 5))
        ast.parse(Path(__file__).read_text(encoding='utf-8'), feature_version=(3, 5))


if __name__ == '__main__': unittest.main()
