"""Isolated nlink2 metadata compatibility; HOST FakeIO only, no real launch."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import stat
import types
import unittest

from tests import test_client_executor as ef
from tests import test_client_process_owner as op

BASE = Path(__file__).absolute().parents[1]
DIRECTORY = BASE / 'candidate/client-init-nlink2/runtime'
PYTHON = '/usr/bin/python3.5'
ORIGINAL_F = '79c633998bf3029b4fa2722605667ef01062fe6bdfebc6c13d83bd0bf4fbf134'
ORIGINAL_OWNER = '0a9a02c79e7e6603f86a7d7618f0b030a3c81d3581423801f22790e923839165'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


f = load('isolated_nlink2_executor', DIRECTORY / 'mta_client_executor.py')
p = load('isolated_nlink2_process_owner', DIRECTORY / 'mta_client_process_owner.py')


class OwnerKernel(op.FakeKernel):
    def __init__(self, clock, links=2, uid=0, gid=0):
        super(OwnerKernel, self).__init__(clock)
        self.links, self.uid, self.gid = links, uid, gid
    def open(self, path, flags):
        fd = super(OwnerKernel, self).open(path, flags)
        if path != '/dev/null':
            self.live[fd]['meta'].st_nlink = self.links
            self.live[fd]['meta'].st_uid = self.uid
            self.live[fd]['meta'].st_gid = self.gid
        return fd


class Nlink2Tests(unittest.TestCase):
    def reader(self, path=PYTHON, links=2, mode=0o755):
        clock = ef.Clock(); io = ef.FakeIo(clock); raw = b'\x7fELFHOST_ONLY'
        io.add(path, raw, mode); io.files[path][1].st_nlink = links
        return f._ReadOwner(io, clock, clock()+10), io, raw
    def owner(self, role='watchdog', path=PYTHON, links=2, uid=0, gid=0):
        clock = op.FakeClock(); kernel = OwnerKernel(clock, links, uid, gid)
        owner = p.DirectChildOwner(_os=kernel, _reader=op.FakeReader(), _clock=clock,
            _threads=lambda: 1, _flags=kernel.flags)
        ticket = owner.register(p.LaunchSpec(role, path, (path,), (), op.SHA), 3, 30.)
        return owner, ticket, kernel
    def test_f_canonical_system_binary2_hash_and_once_close(self):
        owner, io, raw = self.reader()
        data, row = owner.read_file(PYTHON, 1024, hashlib.sha256(raw).hexdigest(), binary=True)
        self.assertEqual(data, raw); self.assertEqual(row['metadata'][5], 2)
        self.assertTrue(row['closed']); self.assertTrue(owner.close())
        self.assertEqual(io.closes.count(row['fd']), 1)
    def test_f_private_binary2_and_all_source2_stay_rejected(self):
        for path, mode, private, binary in ((f.ROOT+'/client-'+'a'*32+'/native/wpa', 0o500, False, True),
            (f.ROOT+'/client-'+'a'*32+'/runtime/source.py', 0o400, True, False),
            ('/usr/share/source.py', 0o444, False, False)):
            with self.subTest(path_profile=('private' if private or path.startswith(f.ROOT) else 'system source')):
                owner, io, raw = self.reader(path, mode=mode)
                with self.assertRaisesRegex(f.ExecutorError, 'source_invalid'):
                    owner.read_file(path, 1024, binary=binary, private=private)
                self.assertTrue(owner.close()); self.assertEqual(len(io.closes), 1)
    def test_f_system_binary3_stays_rejected(self):
        owner, io, raw = self.reader(links=3)
        with self.assertRaisesRegex(f.ExecutorError, 'source_invalid'): owner.read_file(PYTHON, 1024, binary=True)
        self.assertTrue(owner.close()); self.assertEqual(len(io.closes), 1)
    def test_f_linkcount_change_keeps_original_unknown_reference(self):
        owner, io, raw = self.reader(); original_read = io.read
        def changed(fd, count):
            result = original_read(fd, count)
            io.fds[fd]['meta'] = types.SimpleNamespace(**dict(vars(io.fds[fd]['meta']), st_nlink=1))
            return result
        io.read = changed
        with self.assertRaisesRegex(f.ExecutorError, 'source_changed'): owner.read_file(PYTHON, 1024, binary=True)
        row = owner.rows[0]
        self.assertEqual(row['metadata'][5], 2); self.assertFalse(row['closed']); self.assertTrue(owner.pending)
        self.assertEqual(io.closes, []); self.assertIsNotNone(row['raw'])
    def test_owner_canonical_watchdog2_full_elf_hash_and_exact_inventory(self):
        owner, ticket, kernel = self.owner()
        record = owner._binary(ticket)
        self.assertEqual(record.metadata[5], 2); self.assertEqual(ticket.spec.sha, hashlib.sha256(kernel.binary).hexdigest())
        self.assertEqual(sum(call[0]=='fork' for call in kernel.calls), 0)
        self.assertTrue(owner.close_inventory(ticket)); self.assertEqual(kernel.closed.count(record.fd), 1)
        self.assertNotIn(3, kernel.closed)
    def test_owner_controller_private_watchdog_wrongpath_uid_gid_and3_rejected(self):
        cases=(('controller',PYTHON,2,0,0),('watchdog','/tmp/private/python',2,0,0),
            ('watchdog','/usr/bin/python3.5m',2,0,0),('watchdog',PYTHON,2,1,0),
            ('watchdog',PYTHON,2,0,1),('watchdog',PYTHON,3,0,0))
        for role,path,links,uid,gid in cases:
            with self.subTest(role=role,links=links,uid=uid,gid=gid,canonical=path==PYTHON):
                owner,ticket,kernel=self.owner(role,path,links,uid,gid)
                with self.assertRaisesRegex(p.ProcessOwnerError, 'binary_invalid'): owner._binary(ticket)
                self.assertTrue(owner.close_inventory(ticket))
                self.assertFalse(any(call[0]=='fork' for call in kernel.calls))
    def test_owner_watchdog2_wrong_full_hash_rejected_before_fork(self):
        owner,ticket,kernel=self.owner(); kernel.binary=b'\x7fELFDIFFERENT'
        with self.assertRaisesRegex(p.ProcessOwnerError, 'binary_invalid'): owner._binary(ticket)
        self.assertTrue(owner.close_inventory(ticket)); self.assertFalse(any(call[0]=='fork' for call in kernel.calls))
    def test_owner_linkcount_change_is_not_accepted_or_blind_closed(self):
        owner,ticket,kernel=self.owner()
        def hook(name,args):
            if name=='read': kernel.live[args[0]]['meta'].st_nlink=1
        kernel.hook=hook
        with self.assertRaisesRegex(p.ProcessOwnerError, 'binary_invalid'): owner._binary(ticket)
        record=ticket.fds[0]; self.assertEqual(record.metadata[5],2)
        self.assertFalse(owner.close_inventory(ticket)); self.assertTrue(ticket.unknown)
        self.assertFalse(record.closed); self.assertNotIn(record.fd,kernel.closed)
    def test_candidate_reverse_diff_exact_original_bytes_and_python35_ast(self):
        fraw=(DIRECTORY/'mta_client_executor.py').read_bytes()
        oraw=(DIRECTORY/'mta_client_process_owner.py').read_bytes()
        original_f=(BASE/'runtime/mta_client_executor.py').read_bytes()
        original_o=(BASE/'runtime/mta_client_process_owner.py').read_bytes()
        self.assertEqual(hashlib.sha256(original_f).hexdigest(),ORIGINAL_F)
        self.assertEqual(hashlib.sha256(original_o).hexdigest(),ORIGINAL_OWNER)
        fnew=b'            # Actual canonical system Python has two hard links; private inputs stay nlink1.\n            if (not stat.S_ISREG(metadata[2]) or metadata[3] != 0 or\n                    metadata[5] != 1 and not (binary and not private_anchor and metadata[5] == 2) or\n'
        fold=b'            if (not stat.S_ISREG(metadata[2]) or metadata[3] != 0 or metadata[5] != 1 or\n'
        onew=b"            # Only the observed root-owned canonical system watchdog Python may be nlink2.\n            meta[5] != 1 and not (ticket.spec.role == 'watchdog' and\n                ticket.spec.exe == '/usr/bin/python3.5' and meta[3:5] == (0, 0) and meta[5] == 2) or\n            not _int(before.st_size, 4, MAX_BINARY)):\n"
        oold=b'            meta[5] != 1 or not _int(before.st_size, 4, MAX_BINARY)):\n'
        self.assertEqual(fraw.count(fnew),1); self.assertEqual(oraw.count(onew),1)
        self.assertEqual(fraw.replace(fnew,fold),original_f); self.assertEqual(oraw.replace(onew,oold),original_o)
        ast.parse(fraw.decode('utf-8'),feature_version=(3,5)); ast.parse(oraw.decode('utf-8'),feature_version=(3,5))
        self.assertIsNot(ef.f,f); self.assertIsNot(op.p,p)


def isolated_old_methods(original, replacement_name, replacement, names):
    """Clone exact old methods into private globals, never patch old modules."""
    methods={'__module__':__name__}
    for key,value in vars(original).items():
        if type(value) is types.FunctionType and (not key.startswith('test_') or key in names):
            namespace=dict(value.__globals__); namespace[replacement_name]=replacement
            methods[key]=types.FunctionType(value.__code__,namespace,value.__name__,value.__defaults__,value.__closure__)
    return type('Affected'+original.__name__,(unittest.TestCase,),methods)


AffectedSourceTests=isolated_old_methods(ef.SourceTests,'f',f,(
    'test_full_manifest_graph_reads_every_pin_and_closes_once',
    'test_bools_version_and_native_permissions_rejected'))
AffectedProcessOwnerTests=isolated_old_methods(op.ProcessOwnerTests,'p',p,(
    'test_binary_pin_checked_on_actual_opened_fd',
    'test_binary_not_elf_or_writable_is_rejected',
    'test_binary_changes_during_hash_fail_closed'))


if __name__=='__main__': unittest.main()
