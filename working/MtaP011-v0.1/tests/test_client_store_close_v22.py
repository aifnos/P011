"""Only new v22 closure consumption methods, exact private graph over FakeIO.

No old test method, actual filesystem/socket/process/ADB or recovery producer.
Fixtures below are whole-pin-gated definitions only, rebound to this graph.
"""
import ast
import builtins
from contextlib import ExitStack
import errno
import hashlib
import json
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/client-store-close-v22/runtime/mta_client_store.py'
ORIGINAL = BASE / 'candidate/client-durable-association-v18/runtime/mta_client_store.py'
ORIGINAL_SHA = '5ee1c184c3511bc3072e87409a88861713bfd249d79584df1d50fc1377964426'
OLD_GATE = ('        if len(inventories[0]) > coordination.MAX_RESOURCES + 1 or len(inventories[1]) > files.MAX_RESOURCES:\n'
            '            return False\n')
NEW_GATE = ('        if len(inventories[0]) > coordination.MAX_RESOURCES + 1 and not self._closed_fixed_alias_registry():\n'
            '            return False\n'
            '        if len(inventories[1]) > files.MAX_RESOURCES:\n'
            '            return False\n')
NAMES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_proc', 'mta_client_journal_codec', 'mta_client_coordination',
    'mta_client_files', 'mta_client_pending', 'mta_client_store')


def checked(path, pin):
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin: raise ValueError('HOST source pin mismatch')
    return raw


def private_graph():
    raw = checked(BASE / 'host/client_durable_connect_v19_source_manifest.json',
        '9c547fe0b30b899dc1b11beeb67d8815c4e98bd7db8da8c12a2d12cf775beec5')
    rows = json.loads(raw.decode('utf-8'))['sources']
    original_bytes, modules = {}, {}
    for row in rows:
        original_bytes[row['module']] = checked(BASE / row['path'], row['sha256'])
    original_import = builtins.__import__
    def scoped_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith(('mta_', 'p011_')):
            if level or name not in modules: raise ImportError('unloaded private graph dependency')
            return modules[name]
        if level: raise ImportError('relative private dependency')
        return original_import(name, globals, locals, fromlist, level)
    for row in rows:
        name = row['module']
        if name not in NAMES: continue
        path = SOURCE if name == 'mta_client_store' else BASE / row['path']
        raw = path.read_bytes() if name == 'mta_client_store' else original_bytes[name]
        module = types.ModuleType(name); module.__file__ = str(path)
        module.__builtins__ = dict(vars(builtins), __import__=scoped_import)
        modules[name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    if tuple(modules) != NAMES: raise ValueError('HOST private graph order')
    return modules, original_bytes['mta_client_store']


M, OLD_RAW = private_graph()
s, c, f, p, a, core = (M[name] for name in ('mta_client_store', 'mta_client_coordination',
    'mta_client_files', 'mta_client_pending', 'mta_client_tmp_alias', 'mta_p2p_client_init'))
FIXTURE = dict(errno=errno, stat=stat, types=types, core=core, ip=M['mta_ip'],
    f=f, a=a, proc=M['mta_client_proc'], __builtins__=vars(builtins))


def definitions(relative, pin, names):
    raw = checked(BASE / relative, pin)
    tree = ast.parse(raw.decode('utf-8'))
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names
                for target in node.targets):
            selected.append(node)
    found = {node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else node.targets[0].id for node in selected}
    if found != set(names): raise ValueError('HOST fixture definition selection')
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(module, relative, 'exec'), FIXTURE)


definitions('tests/test_client_files.py',
    'fdc138903fb5c78a219b7d1e11d5d02e0443307dc57d450d6fcaabb09ff02ab2',
    ('TOKEN', 'BASE', 'RUN', 'TARGET', 'PENDING', 'Node', 'FakeIo'))
definitions('tests/test_client_journal_transaction.py',
    '4c78dbb8c46b165f63801ccabebbd9b670c9602ba7c3fea89016cc17bac06d4a', ('Clock', 'CombinedIo'))
definitions('tests/test_client_tmp_alias_v11.py',
    '1c2f4d58adcbfa49d6fcc4174b2dd1c71baf64ff95cd76537a51ae0ff4c79862', ('AliasIo',))
definitions('tests/test_client_journal_codec.py',
    '33750c02cabfcce7bff46390744ae94bee43ec9ab8e6c7827365075070b3f385',
    ('BOOT', 'IDENTITY', 'STATION', 'RULES', 'actor', 'baseline'))
definitions('tests/test_client_pending.py',
    'bbf890d9989a4b73748cac496149f09782d9fa32491933a272ffa4a0d6cf7e3c', ('Reader',))


class ClientStoreCloseV22Tests(unittest.TestCase):
    def setUp(self):
        for cls in (c._LinuxIo, f._LinuxIo, p._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'stat_root',
                    'readlink_at', 'close', 'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for target in ('ctypes.CDLL', 'socket.socket', 'subprocess.Popen', 'os.open', 'os.kill', 'os.waitpid',
                'threading.Thread.start', 'time.sleep'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(M['mta_client_proc'].ProcReader, 'read_self',
            side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, alias=True, handoff=None):
        io, reader = FIXTURE['AliasIo'](alias), FIXTURE['Reader']()
        baseline = FIXTURE['baseline'](); reader.boot = baseline.boot
        owner = s.DurableClientInitStore(FIXTURE['TOKEN'], FIXTURE['IDENTITY'],
            _coordination_io=io, _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock)
        self.addCleanup(owner.close)
        locks = owner.acquire(FIXTURE['IDENTITY'], 3.0)
        if handoff:
            record = owner.commit(locks, core.Journal(FIXTURE['IDENTITY'], 'prepared', baseline, 10.0))
            self.assertTrue(owner.active_return(locks, record).complete())
            if handoff == 'active': locks = owner.acquire(FIXTURE['IDENTITY'], 3.0, locks)
        return owner, io, locks

    def closed(self, **options):
        owner, io, locks = self.make(**options)
        owner.close(); owner._begin_io(3.0)
        return owner, io, locks

    def test_actual_alias_eight_released_eight_ninth_and_ordinary_history(self):
        for alias, handoff, expected in ((True, None, 8), (True, 'released', 8), (True, 'active', 9),
                (False, None, 6), (False, 'active', 7)):
            with self.subTest(alias=alias, handoff=handoff):
                owner, io, locks = self.closed(alias=alias, handoff=handoff)
                self.assertEqual(expected, len(owner._coordination._inventory))
                self.assertEqual((6, 8, 256), (c.MAX_RESOURCES, c.FIXED_ALIAS_RESOURCES, f.MAX_RESOURCES))
                self.assertTrue(owner._inventory_closed())
                if alias:
                    self.assertTrue(owner._closed_fixed_alias_registry())
                    # Exact frozen original method on the same closed originals.
                    scope = dict(vars(s)); original_tree = ast.parse(OLD_RAW.decode('utf-8'))
                    original_class = next(n for n in original_tree.body if isinstance(n, ast.ClassDef)
                        and n.name == 'DurableClientInitStore')
                    original_method = next(n for n in original_class.body if isinstance(n, ast.FunctionDef)
                        and n.name == '_inventory_closed')
                    exec(compile(ast.Module(body=[original_method], type_ignores=[]), '<pinned original closure>', 'exec'), scope)
                    self.assertFalse(scope['_inventory_closed'](owner))
                if handoff:
                    self.assertFalse(owner._marker._binding_ticket.ready)
                    self.assertTrue(owner._marker._binding_ticket.unknown)  # Normal live-authority sealing, not FD unknown.
                    self.assertFalse(owner._marker._resource_pending)
                self.assertFalse(io.handles)
                self.assertEqual(locks._device.fd, io.closed[-1])
                before = (tuple(io.opened), tuple(io.closed), tuple(io.flocks), len(io.ops))
                self.assertTrue(owner._inventory_closed()); owner.close()
                self.assertEqual(before, (tuple(io.opened), tuple(io.closed), tuple(io.flocks), len(io.ops)))
                self.assertFalse(owner.status()['send_available']); self.assertFalse(owner.status()['receive_available'])
                self.assertIsNone(owner._restore_reader); self.assertFalse(owner._restore_verified)

    def test_negative_alias_registration_fd_unknown_and_unchanged_partial_boundaries(self):
        modes = ('partial_alias', 'unknown_alias', 'foreign_alias_owner', 'missing_prefix', 'duplicate_prefix',
            'foreign_prefix', 'extra_ticket', 'duplicate_inventory', 'foreign_lock_issuer', 'foreign_handoff_issuer',
            'handoff_unknown', 'foreign_epoch', 'unclosed', 'not_attempted', 'open_unknown', 'still_live',
            'marker_unknown', 'files_unknown', 'store_unknown', 'close_unknown', 'ordinary_nine')
        for mode in modes:
            with self.subTest(mode=mode):
                owner, io, locks = self.closed(alias=mode != 'ordinary_nine', handoff='active')
                co, alias, items = owner._coordination, owner._coordination._tmp_alias, owner._coordination._inventory
                target = co._handoff.new_ticket
                if mode == 'partial_alias': alias._prepared = False
                elif mode == 'unknown_alias': alias._unknown = True
                elif mode == 'foreign_alias_owner': alias._context = (object(),) + alias._context[1:]
                elif mode == 'missing_prefix': alias._volatile = None
                elif mode == 'duplicate_prefix': alias._volatile = alias._var
                elif mode == 'foreign_prefix':
                    copied = c._Fd(io, 'tmp_alias_var')
                    for field in c._Fd.__slots__: setattr(copied, field, getattr(alias._var, field))
                    alias._var = copied
                elif mode == 'extra_ticket': items.append(items[0])
                elif mode == 'duplicate_inventory': items[1] = items[2]
                elif mode == 'foreign_lock_issuer': object.__setattr__(co._locksets[0], '_issuer', object())
                elif mode == 'foreign_handoff_issuer': object.__setattr__(co._handoff.reacquired, '_issuer', object())
                elif mode == 'handoff_unknown': co._handoff.unknown = True
                elif mode == 'foreign_epoch': owner._journal_epoch = object()
                elif mode == 'unclosed': target.closed = False
                elif mode == 'not_attempted': target.attempted = False
                elif mode == 'open_unknown': target.opening_unknown = True
                elif mode == 'still_live': io.handles[target.fd] = [io.nodes[FIXTURE['RUN'].replace('/tmp', a.PHYSICAL_TMP) + '/journal.lock'], 0]
                elif mode == 'marker_unknown': owner._marker._resource_pending = True
                elif mode == 'files_unknown': owner._files._resource_pending = True
                elif mode == 'store_unknown': owner._unknown = True
                elif mode == 'close_unknown': owner._close_unknown = True
                else: items.extend((items[0], items[1]))
                before = (tuple(io.opened), tuple(io.closed), tuple(io.flocks))
                self.assertFalse(owner._inventory_closed())
                self.assertEqual(before, (tuple(io.opened), tuple(io.closed), tuple(io.flocks)))
                if mode == 'still_live': del io.handles[target.fd]
        # Preserve the original <=7 known-negative closed partial semantics.
        owner, io, locks = self.closed(alias=False)
        ticket = c._Fd(io, 'known_negative'); ticket.opening_unknown, ticket.closed = False, True
        owner._coordination._inventory.append(ticket)
        self.assertEqual(7, len(owner._coordination._inventory)); self.assertTrue(owner._inventory_closed())
        ticket.opening_unknown = True
        self.assertFalse(owner._inventory_closed())

    def test_source_reversible_only_closure_gate_and_python35_same_domain(self):
        raw = checked(ORIGINAL, ORIGINAL_SHA); self.assertEqual(raw, OLD_RAW)
        old, new = raw.decode('utf-8'), SOURCE.read_text(encoding='utf-8')
        start, end = new.index('    def _closed_fixed_alias_registry(self):\n'), new.index('    def _inventory_closed(self):\n')
        self.assertEqual(1, new.count(NEW_GATE))
        reversed_source = (new[:start] + new[end:]).replace(NEW_GATE, OLD_GATE)
        self.assertEqual(old, reversed_source)
        tree = ast.parse(new, feature_version=(3, 5)); ast.parse(Path(__file__).read_text(), feature_version=(3, 5))
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        self.assertEqual(ast.dump(ast.parse(old)), ast.dump(ast.parse(reversed_source)))
        self.assertIs(s.coordination, c); self.assertIs(s.files, f); self.assertIs(s.pending, p)
        self.assertIs(s.core, core); self.assertIs(s.codec.core, core); self.assertIs(c.core, core)
        self.assertIs(f.codec, s.codec); self.assertIs(p.coordination, c); self.assertIs(p.files, f)
        helper = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_closed_fixed_alias_registry')
        self.assertFalse({'open', 'close', 'validate', 'verify', 'authenticate', 'fstat', 'socket', 'flock', 'unlink', 'mkdir'} &
            {n.attr for n in ast.walk(helper) if isinstance(n, ast.Attribute)})


if __name__ == '__main__': unittest.main()
