"""New HOST89 affected method, SOURCE only; never a target staging claim.

The full fixed 41-source graph is read as pinned bytes, not loaded/collected.
Stage89 executes its complete new algorithm on a real Linux temporary tree:
EXCL, same-FD write/readback, hash, chmod, fsync, close and EBADF are real.
Its target /tmp aliases, ARM/version validation are explicit private projection.
Parent89 executes its complete new algorithm with modeled ARM ELF, process,
pipe FD, EOF, wait and clock facts, and actual pure private packet definitions.
No old TestCase/test helper/test method is imported; no observer/helper process runs,
and no RF, native admission, production seal or restoration is asserted.
Only ROOT may perform the first AST/import/execution of this new test.
"""
import builtins
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
ASSETS = ('host/go_readonly_observer_v89_asset_sources.json', 9734,
          'b4a3bb3ce6571654b1bf998465e453669b0035a12b510cb4158144158d7ba5eb')
# Authors' frozen source pins; no runtime or earlier test is modified.
STAGE_SOURCE = ('candidate/go-send-observer-stage-v89/runtime/mta_go_readonly_stage.py', 29281,
                'f4c5a008ebf5c7e3ce086cb950c9b675b411c48f5ab23b7f318fd2f4b62ad940')
PARENT_SOURCE = ('candidate/go-send-observer-parent-v89/runtime/mta_go_readonly_parent.py', 41562,
                 '68a95f868d18c5fc007d711e5f165ee9d564c776119c23edba8c02f83fba47ff')
MARKER = ('HOST89_READONLY_OWNER new_methods=1 old_methods=0 cases=9 '
          'filesystem_host=true target_model=true parent_model=true '
          'device=false phone=false\n')
PHYSICAL = '/var/volatile/tmp/p011-mta-go-observer-v85'
ALIAS = '/tmp/p011-mta-go-observer-v85'


def _fixed(item):
    if type(item) is not tuple or len(item) != 3:
        raise AssertionError('HOST89 source not frozen')
    path, size, pin = item
    raw = (BASE / path).read_bytes()
    if (type(raw) is not bytes or len(raw) != size or
            hashlib.sha256(raw).hexdigest() != pin):
        raise AssertionError('HOST89 source identity changed')
    return raw


def _inputs():
    table = json.loads(_fixed(ASSETS).decode('ascii'))
    if (table['schema'] != 'p011-readonly-observer-v89-fixed-assets' or
            table['root'] != PHYSICAL or table['source_count'] != 41 or
            table['source_bytes'] != 1347741 or table['runtime_mode'] != '0700' or
            table['file_mode'] != '0400' or table['target_python'] != '/usr/bin/python3.5' or
            table['native_admission'] is not False or table['restoration_verified'] is not False or
            type(table['sources']) is not list or len(table['sources']) != 41):
        raise AssertionError('HOST89 asset table')
    raws = {}
    for row in table['sources']:
        if type(row) is not dict or set(row) != {'module', 'path', 'bytes', 'sha256'}:
            raise AssertionError('HOST89 source row')
        if row['module'] in raws:
            raise AssertionError('HOST89 duplicate source')
        raws[row['module']] = _fixed((row['path'], row['bytes'], row['sha256']))
    if sum(len(raw) for raw in raws.values()) != 1347741:
        raise AssertionError('HOST89 asset bytes')
    return raws, _fixed(STAGE_SOURCE), _fixed(PARENT_SOURCE)


def _module(name, raw, modules=None):
    """Complete definitions, no sys.modules writes and no mta fallback."""
    modules = {} if modules is None else modules
    original_import = builtins.__import__

    def private_import(target, globals=None, locals=None, fromlist=(), level=0):
        if level or target.startswith(('mta_', 'p011_')):
            if level or target not in modules:
                raise AssertionError('HOST89 no ordinary source fallback')
            return modules[target]
        return original_import(target, globals, locals, fromlist, level)

    value = types.ModuleType(name)
    value.__file__ = PHYSICAL + '/runtime/' + name + '.py'
    value.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def _data_domain(raws):
    modules = {}
    for name in ('p011_json', 'mta_ip', 'mta_p2p_client_init', 'mta_snapshot_data',
                 'mta_observer_packet'):
        modules[name] = _module(name, raws[name], modules)
    return modules


def _packet_data(modules, binding):
    """Complete valid primitive DATA, not a Snapshot/Actor/proof constructor."""
    codec, packet = modules['mta_snapshot_data'], modules['mta_observer_packet']
    station = (0, 1, 2, 'wlan0', 2)
    actors = tuple((pid, pid + 100, exe, 'a' * 64, ((pid, pid + 100, 'S'),))
        for pid, exe in ((1, '/usr/bin/Z03'), (2, '/usr/bin/control_engine'), (3, '/usr/bin/weston')))
    fields = ('11111111-2222-3333-4444-555555555555', tuple(sorted(codec._STOCK_PINS)),
        actors, station, 'b' * 64, 2412, (station,),
        ((), (), ((0, 255), (32766, 254), (32767, 253))), (), (), True)
    codec._full(fields)
    raw = codec._canonical([codec.DATA_SCHEMA, codec._pack(fields), codec._pack(codec._stable_key(fields))])
    decoded = codec.decode_snapshot(raw)
    result = dict(schema='p011-go-preflight-data-v85', binding=tuple(sorted(binding.items())),
        snapshot_raw=raw, stable_key_sha256=decoded.key_sha,
        helper_raw=tuple((path, b'{"event":"capabilities"}\n', b'') for path, pin in packet.HELPERS),
        lock_metadata=(1, 2, stat.S_IFREG | 0o600, 0, 0, 1, 0, 10, 20),
        source_manifest_sha256=packet.SOURCE_MANIFEST_SHA, source_count=38,
        active_until=binding['until'], cleanup_until=binding['cleanup_until'],
        rf_requested=False, restoration_verified=False, production_admitted=False)
    return packet.encode_result(result), raw


class _Clock(object):
    def __init__(self, value=1.0): self.value, self.calls = value, 0
    def __call__(self):
        self.calls += 1
        return self.value


def _metadata(ino, mode, size=0, nlink=1):
    return types.SimpleNamespace(st_dev=89, st_ino=ino, st_mode=mode,
        st_uid=0, st_gid=0, st_nlink=nlink, st_size=size, st_rdev=0,
        st_mtime_ns=1000000000 + ino, st_ctime_ns=2000000000 + ino)


def _nine(value):
    # atime may change on our own read; it is not an old-entry mutation claim.
    return tuple(getattr(value, name) for name in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class _StagePosix(object):
    """Actual POSIX syscalls; only fixed absolute anchor/platform projection."""
    def __init__(self, case, base, clock, fault=None):
        self.case, self.base, self.clock, self.fault = case, Path(base), clock, fault
        self.calls, self.opens, self.closes, self.close_counts, self.syncs = [], [], [], {}, []
        self.validated = 0
        self.read_faulted = self.late_returned = False
        self.file_fds = set()
        for path, mode in ((self.base, 0o755), (self.base / 'var', 0o755),
                           (self.base / 'var/volatile', 0o1777),
                           (self.base / 'var/volatile/tmp', 0o1777)):
            path.mkdir(exist_ok=True)
            path.chmod(mode)

    @property
    def root(self): return self.base / 'var/volatile/tmp' / PHYSICAL.rsplit('/', 1)[1]
    def _path(self, value):
        if not isinstance(value, str):
            raise AssertionError('HOST89 fixed path projection')
        if not value.startswith('/'):
            return value
        if value == '/': return str(self.base)
        if value == ALIAS or value.startswith(ALIAS + '/'):
            return str(self.root) + value[len(ALIAS):]
        if value == '/var' or value.startswith('/var/'):
            return str(self.base) + value
        raise AssertionError('HOST89 unexpected absolute syscall path')

    def validate(self):
        # These are real HOST Linux/root checks, not ARM/Python3.5 checks.
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise AssertionError('HOST89 real Linux root filesystem required')
        self.validated += 1
    def pid(self): return os.getpid()
    def stat(self, path, dir_fd=None):
        self.calls.append(('stat', path, dir_fd))
        if dir_fd is None and path in ('/tmp', '/var/tmp'):
            target = '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
            return _metadata(91 if path == '/tmp' else 92, stat.S_IFLNK | 0o777, len(target))
        return os.stat(self._path(path), dir_fd=dir_fd, follow_symlinks=False)
    def readlink(self, path):
        self.calls.append(('readlink', path))
        if path not in ('/tmp', '/var/tmp'):
            raise AssertionError('HOST89 alias projection role')
        return '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
    def fstat(self, fd): return os.fstat(fd)
    def open(self, path, flags, mode=0o777, dir_fd=None):
        self.calls.append(('open', path, flags, dir_fd))
        fd = os.open(self._path(path), flags, mode, dir_fd=dir_fd)
        self.opens.append(fd)
        if flags & os.O_CREAT:
            self.case.assertTrue(flags & os.O_EXCL)
            self.file_fds.add(fd)
            if self.fault == 'late_open' and not self.late_returned:
                self.late_returned = True
                self.clock.value = 121.0
        return fd
    def mkdir(self, path, mode, dir_fd=None):
        self.calls.append(('mkdir', path, mode, dir_fd))
        return os.mkdir(self._path(path), mode, dir_fd=dir_fd)
    def listdir(self, fd): return os.listdir(fd)
    def read(self, fd, count):
        raw = os.read(fd, count)
        if self.fault == 'readback' and fd in self.file_fds and raw and not self.read_faulted:
            self.read_faulted = True
            # Faulted syscall result, not patched Stage hash/readback algorithm.
            return bytes((raw[0] ^ 1,)) + raw[1:]
        return raw
    def write(self, fd, raw): return os.write(fd, raw)
    def seek(self, fd, off, whence): return os.lseek(fd, off, whence)
    def sync(self, fd):
        self.syncs.append(fd)
        return os.fsync(fd)
    def chmod(self, fd, mode): return os.fchmod(fd, mode)
    def close(self, fd):
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        # FD numbers may be reused across files: one count per original open.
        returned = os.close(fd)
        try: os.fstat(fd)
        except OSError as error:
            self.case.assertEqual(errno.EBADF, error.errno)
        else: raise AssertionError('HOST89 actual descriptor not closed')
        self.closes.append(fd)
        return returned
    def flags(self, fd):
        return (fcntl.fcntl(fd, fcntl.F_GETFL), fcntl.fcntl(fd, fcntl.F_GETFD))


@contextmanager
def _stage_fixture(case, source, fault=None):
    # tempfile owns only this new unique tree; never a managed target/workspace.
    with tempfile.TemporaryDirectory(prefix='p011-host89-') as directory:
        base = Path(directory).resolve()
        case.assertTrue(base.is_dir())
        clock = _Clock()
        io = _StagePosix(case, base, clock, fault)
        module = _module('mta_go_readonly_stage', source)
        module._LinuxIo = lambda: io
        module.time = types.SimpleNamespace(monotonic=clock)
        stage = module.FixedReadonlyObserverStage(121.0)
        try:
            yield module, stage, io, clock
        finally:
            # Continue known original closure even when a failed assertion fires.
            stage.close()
            case.assertEqual(len(io.opens), len(io.closes))
            case.assertEqual(sorted(io.opens), sorted(io.closes))


class _ModelPipe(object):
    """Bound methods/closed observation are originals, but no kernel pipe."""
    def __init__(self, io, fd, role):
        self.io, self.fd, self.role, self.closed = io, fd, role, False
        self.close_calls = 0
    def fileno(self): return self.fd
    def close(self):
        self.close_calls += 1
        returned = self.io.close(self.fd)
        self.closed = True
        return returned


class _ModelProcess(object):
    """No Popen call. A modeled direct-child ticket, poll and wait originals."""
    def __init__(self, io, out, err):
        self.io, self.stdout, self.stderr = io, out, err
        self.pid, self.returncode = 898989, None
        self.poll_calls = self.wait_calls = 0
    def poll(self):
        self.poll_calls += 1
        return self.returncode
    def wait(self, timeout=None):
        self.wait_calls += 1
        self.io.case.assertGreater(timeout, 0.0)
        self.io.case.assertTrue(all(row['eof'] for row in self.io.owner.process_attempt['pipes']))
        self.returncode = 1 if self.io.fault == 'nonzero' else 0
        return self.returncode


class _ParentModel(object):
    """Explicit ARM/source/FD/process/clock model; pure packet is real code."""
    def __init__(self, case, raws, clock, fault=None):
        self.case, self.raws, self.clock, self.fault = case, raws, clock, fault
        self.calls, self.live, self.close_counts, self.positions, self.buffers = [], {}, {}, {}, {}
        self.next_fd, self.spawn_calls, self.validate_calls = 100, 0, 0
        self.owner = self.process = None
        self.data_modules = _data_domain(raws)
        self.packet_raw = self.snapshot_raw = None
        self.close_error = OSError(errno.EIO, 'HOST modeled original close uncertainty')
        self.close_faulted = False
        self.file_metadata = {}
        for index, name in enumerate(raws):
            self.file_metadata[name] = _metadata(1000 + index, stat.S_IFREG | 0o400, len(raws[name]))
        # Synthetic ELF fixture only. It is not a HOST Python pin or ARM image.
        elf = bytearray(84)
        elf[:7] = b'\x7fELF\x01\x01\x01'
        struct.pack_into('<HHI', elf, 16, 3, 40, 1)
        struct.pack_into('<I', elf, 28, 52)
        struct.pack_into('<I', elf, 36, 0x05000400)
        struct.pack_into('<HHH', elf, 40, 52, 32, 1)
        self.python_raw = bytes(elf)
        self.python_metadata = _metadata(5000, stat.S_IFREG | 0o755, len(elf))

    def validate(self):
        self.calls.append(('validate',))
        self.validate_calls += 1
    def pid(self): return 8989
    def _file(self, path):
        if path == '/usr/bin/python3.5': return 'python', self.python_raw, self.python_metadata
        for prefix in (PHYSICAL + '/runtime/', ALIAS + '/runtime/'):
            if path.startswith(prefix) and path.endswith('.py'):
                name = path[len(prefix):-3]
                if name in self.raws: return name, self.raws[name], self.file_metadata[name]
        raise AssertionError('HOST89 unexpected modeled file role')
    def stat(self, path):
        self.calls.append(('stat', path))
        dirs = {'/': (1, 0o755), '/var': (2, 0o755), '/var/volatile': (3, 0o1777),
                '/var/volatile/tmp': (4, 0o1777), PHYSICAL: (5, 0o700),
                PHYSICAL + '/runtime': (6, 0o700), ALIAS: (5, 0o700),
                ALIAS + '/runtime': (6, 0o700), '/usr': (7, 0o755), '/usr/bin': (8, 0o755)}
        if path in dirs:
            ino, mode = dirs[path]
            return _metadata(ino, stat.S_IFDIR | mode, nlink=2)
        if path in ('/tmp', '/var/tmp'):
            target = '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
            return _metadata(9 if path == '/tmp' else 10, stat.S_IFLNK | 0o777, len(target))
        return self._file(path)[2]
    def readlink(self, path):
        self.calls.append(('readlink', path))
        if path not in ('/tmp', '/var/tmp'): raise AssertionError('HOST89 alias role')
        return '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
    def _fd(self, role, meta, raw=None):
        value = self.next_fd
        self.next_fd += 1
        self.live[value] = dict(role=role, metadata=meta, raw=raw, flags=os.O_RDONLY)
        self.positions[value] = 0
        return value
    def open(self, path):
        self.calls.append(('open', path))
        role, raw, metadata = self._file(path)
        return self._fd(role, metadata, raw)
    def fstat(self, fd):
        self.calls.append(('fstat', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST modeled closed descriptor')
        return self.live[fd]['metadata']
    def flags(self, fd):
        self.calls.append(('flags', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST modeled closed descriptor')
        return self.live[fd]['flags']
    def set_flags(self, fd, value):
        self.calls.append(('set_flags', fd, value))
        self.live[fd]['flags'] = value
        return 0
    def nonce(self):
        self.calls.append(('nonce',))
        return b'\xaa' * 16
    def spawn(self, argv, pythonfd):
        self.calls.append(('spawn', argv, pythonfd))
        self.spawn_calls += 1
        self.case.assertEqual(('/usr/bin/python3.5', '-I', '-B',
            PHYSICAL + '/runtime/mta_go_readonly_entry.py', '--collect'), argv[:5])
        self.case.assertEqual('python', self.live[pythonfd]['role'])
        args = dict(zip(argv[5::2], argv[6::2]))
        self.case.assertEqual({'--nonce', '--task-id', '--native-epoch', '--operation-epoch',
                              '--until', '--cleanup-until'}, set(args))
        binding = dict(nonce=args['--nonce'], task_id=args['--task-id'],
            native_epoch=int(args['--native-epoch']), operation_epoch=int(args['--operation-epoch']),
            until=float(args['--until']), cleanup_until=float(args['--cleanup-until']))
        if self.fault == 'binding': binding['task_id'] = 'c' * 32
        self.packet_raw, self.snapshot_raw = _packet_data(self.data_modules, binding)
        emitted = self.packet_raw
        if self.fault == 'truncated': emitted = emitted[:-1]
        if self.fault == 'tail': emitted += b'x'
        outfd = self._fd('stdout', _metadata(6000, stat.S_IFIFO | 0o600))
        errfd = self._fd('stderr', _metadata(6001, stat.S_IFIFO | 0o600))
        # Independent chunked stdout and stderr EOF through actual new drainer.
        self.buffers[outfd] = [emitted[:1024], emitted[1024:], b'']
        self.buffers[errfd] = [b'']
        out, err = _ModelPipe(self, outfd, 'stdout'), _ModelPipe(self, errfd, 'stderr')
        self.process = _ModelProcess(self, out, err)
        if self.fault == 'partial_pipe':
            # Process + actual returned stdout stay retained. No fabricated stderr.
            del self.live[errfd]
            self.process.stderr = None
        if self.fault == 'late_spawn': self.clock.value = self.owner.active_until
        return self.process
    def read(self, fd, count):
        self.calls.append(('read', fd, count))
        row = self.live[fd]
        if row['role'] in ('stdout', 'stderr'):
            if not self.buffers[fd]: raise AssertionError('HOST89 read after model EOF')
            raw = self.buffers[fd].pop(0)
            self.case.assertLessEqual(len(raw), count)
            return raw
        raw, off = row['raw'], self.positions[fd]
        value = raw[off:off + count]
        self.positions[fd] += len(value)
        return value
    def readable(self, fds, timeout):
        self.calls.append(('readable', fds, timeout))
        self.case.assertGreater(timeout, 0.0)
        return tuple(fd for fd in fds if self.buffers[fd])
    def close(self, fd):
        self.calls.append(('close', fd))
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        if self.fault == 'close_unknown' and self.live[fd]['role'] == 'stderr' and not self.close_faulted:
            self.close_faulted = True
            raise self.close_error
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST modeled closed descriptor')
        del self.live[fd]
        return None


def _parent_fixture(case, source, raws, fault=None):
    clock = _Clock()
    model = _ParentModel(case, raws, clock, fault)
    module = _module('mta_go_readonly_parent', source)
    # Production _context retains this exact private class/clock. Public ABI
    # still has no injection. No class or owner success gate is patched.
    class ProjectedLinuxIo(_ParentModel):
        def __init__(self):
            self.__dict__ = model.__dict__
    module._LinuxIo = ProjectedLinuxIo
    module.time = types.SimpleNamespace(monotonic=clock)
    parent = module.ReadonlyDataParent('b' * 32, 1, 1, 100.0, 80.0)
    model.owner = parent
    return module, parent, model, clock


class GoReadonlyOwner89Test(unittest.TestCase):
    def test_fixed_stage_and_private_parent(self):
        raws, stage_source, parent_source = _inputs()
        completed = []

        # 1: import/constructor/defaultmain have no platform/FD/process work.
        with self.subTest(domain='definitions_default'):
            with _stage_fixture(self, stage_source) as (module, stage, io, clock):
                self.assertEqual([], io.calls)
                self.assertEqual(0, clock.calls)
                self.assertEqual(0, module.main([]))
                self.assertEqual(2, module.main(['unexpected']))
                self.assertEqual([], io.calls)
                self.assertEqual(0, clock.calls)
                self.assertFalse(stage.called)
            module, parent, model, clock = _parent_fixture(self, parent_source, raws)
            self.assertEqual([], model.calls)
            self.assertEqual(0, clock.calls)
            self.assertEqual(0, module.main([]))
            with self.assertRaisesRegex(module.ReadonlyParentError, '^parent_no_command_entry$'):
                module.main(['unexpected'])
            self.assertEqual([], model.calls)
            self.assertEqual(0, clock.calls)
            self.assertIsNone(parent.period_original)
            self.assertTrue(parent.close())
            self.assertEqual([], model.calls)
            self.assertEqual(0, clock.calls)
            self.assertFalse(parent.status()['production_admitted'])
            completed.append('definitions_default')

        # 2: actual full fixed-source publication with no source definitions run.
        with self.subTest(domain='stage_real_posix'):
            with _stage_fixture(self, stage_source) as (module, stage, io, clock):
                self.assertIs(stage, stage.stage(raws))
                self.assertTrue(stage.success)
                self.assertTrue(stage.closed)
                self.assertEqual(47, len(stage.rows))
                self.assertEqual(41, len(stage.file_rows))
                self.assertEqual(41, len(stage.readback))
                self.assertEqual(1347741, sum(len(value) for value in raws.values()))
                self.assertEqual(['runtime'], sorted(os.listdir(io.root)))
                self.assertEqual(sorted(name + '.py' for name in raws), sorted(os.listdir(io.root / 'runtime')))
                self.assertEqual(0o700, stat.S_IMODE(os.lstat(io.root).st_mode))
                self.assertEqual(0o700, stat.S_IMODE(os.lstat(io.root / 'runtime').st_mode))
                for name, raw in raws.items():
                    path = io.root / 'runtime' / (name + '.py')
                    self.assertEqual(raw, path.read_bytes())
                    self.assertEqual(0o400, stat.S_IMODE(os.lstat(path).st_mode))
                self.assertEqual(85, len(io.syncs))  # Two per file + three directory fsync.
                self.assertTrue(all(row['close_called'] and row['closed'] and row['ebadf'] and
                                    not row['unknown'] for row in stage.rows))
                before = tuple(io.calls)
                with self.assertRaisesRegex(module.ReadonlyStageError, '^stage_once$'):
                    stage.stage(raws)
                self.assertEqual(before, tuple(io.calls))
                self.assertTrue(stage.close())
                self.assertFalse(stage.status()['resource_pending'])
                completed.append('stage_real_posix')

        # 3: fixed assets/old roots are fail-closed; no old tree adoption/repair.
        with self.subTest(domain='stage_existing_root'):
            with _stage_fixture(self, stage_source) as (module, stage, io, clock):
                io.root.mkdir(mode=0o700)
                sentinel = io.root / 'foreign.bin'
                sentinel.write_bytes(b'old private subtree preserved')
                sentinel.chmod(0o400)
                before = (_nine(os.lstat(sentinel)), sentinel.read_bytes(), sorted(os.listdir(io.root)))
                with self.assertRaisesRegex(module.ReadonlyStageError, '^stage_root_exists$'):
                    stage.stage(raws)
                self.assertEqual([], stage.mutations)
                self.assertEqual([], stage.file_rows)
                self.assertEqual(before, (_nine(os.lstat(sentinel)), sentinel.read_bytes(), sorted(os.listdir(io.root))))
                self.assertFalse(any(call[0] == 'open' and call[1] == PHYSICAL.rsplit('/', 1)[1]
                                     for call in io.calls))
                self.assertTrue(stage.closed)
            with _stage_fixture(self, stage_source) as (module, stage, io, clock):
                wrong = dict(raws)
                wrong['p011_json'] = b'x' * len(wrong['p011_json'])
                with self.assertRaisesRegex(module.ReadonlyStageError, '^stage_source_pin$'):
                    stage.stage(wrong)
                self.assertEqual([], stage.rows)
                self.assertEqual([], stage.mutations)
                self.assertFalse(io.root.exists())
            completed.append('stage_existing_root')

        # 4: readback failure retains exact partial file/tree; closes known FDs.
        with self.subTest(domain='stage_readback_fault'):
            with _stage_fixture(self, stage_source, 'readback') as (module, stage, io, clock):
                with self.assertRaisesRegex(module.ReadonlyStageError, '^stage_readback_changed$') as caught:
                    stage.stage(raws)
                self.assertIs(caught.exception, stage.failure)
                self.assertTrue(io.read_faulted)
                self.assertTrue(stage.root_created and stage.runtime_created)
                self.assertEqual(1, len(stage.file_rows))
                self.assertEqual(raws['p011_json'], (io.root / 'runtime/p011_json.py').read_bytes())
                self.assertEqual(0o600, stat.S_IMODE(os.lstat(io.root / 'runtime/p011_json.py').st_mode))
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in stage.rows))
                self.assertFalse(stage.success)
                self.assertEqual(['p011_json.py'], os.listdir(io.root / 'runtime'))
                closed = list(io.closes)
                self.assertTrue(stage.close())
                self.assertEqual(closed, io.closes)
                completed.append('stage_readback_fault')

        # 5: late open returns an actual FD; metadata/close survive active expiry.
        with self.subTest(domain='stage_late_open'):
            with _stage_fixture(self, stage_source, 'late_open') as (module, stage, io, clock):
                with self.assertRaisesRegex(module.ReadonlyStageError, '^stage_expired$') as caught:
                    stage.stage(raws)
                row = stage.file_rows[0]
                self.assertIs(caught.exception, stage.failure)
                self.assertTrue(io.late_returned)
                self.assertTrue(row['returned'])
                self.assertIsNotNone(row['identity'])
                self.assertIsNotNone(row['metadata'])
                self.assertTrue(row['close_called'] and row['closed'] and row['ebadf'])
                self.assertFalse(row['unknown'] or row['no_descriptor'])
                self.assertEqual(121.0, stage.original_until)
                self.assertTrue(stage.closed)
                self.assertEqual(0, os.lstat(io.root / 'runtime/p011_json.py').st_size)
                completed.append('stage_late_open')

        # 6: Actual Parent algorithms + complete pure Packet DATA, process model.
        with self.subTest(domain='parent_complete_packet'):
            module, parent, model, clock = _parent_fixture(self, parent_source, raws)
            before_modules = dict(sys.modules)
            data = parent.collect()
            self.assertIs(data, parent.result)
            self.assertIs(data, parent.report)
            self.assertIs(type(data), parent.modules['mta_observer_packet'].ObserverPacketData)
            self.assertEqual(5, len(parent.module_originals))
            self.assertEqual(9, len(parent.rows))
            self.assertEqual((31.0, 36.0), parent.period_original)
            self.assertIs(parent.active_until, parent.period_original[0])
            self.assertIs(parent.cleanup_until, parent.period_original[1])
            self.assertEqual(model.packet_raw, b''.join(parent.reader.parts))
            self.assertEqual(model.snapshot_raw, data.private_snapshot_ascii())
            self.assertEqual(hashlib.sha256(model.packet_raw).hexdigest(), data.packet_sha256)
            self.assertEqual(hashlib.sha256(model.python_raw).hexdigest(), parent.python_sha256)
            self.assertEqual(1, model.spawn_calls)
            self.assertEqual(1, model.process.wait_calls)
            self.assertEqual(0, model.process.poll_calls)
            self.assertTrue(parent.process_attempt['waited'] and parent.process_attempt['reaped'])
            self.assertTrue(all(row['eof'] and row['eof_ticket'][-1] == b''
                                for row in parent.process_attempt['pipes']))
            self.assertTrue(all(row['closed'] and not row['unknown'] for row in parent.rows))
            self.assertTrue(all(value == 1 for value in model.close_counts.values()))
            self.assertEqual({}, model.live)
            self.assertTrue(parent.status()['local_inventory_closed'])
            self.assertFalse(parent.status()['resource_pending'])
            self.assertTrue(parent.status()['report_observed'])
            for name in ('rf_requested', 'restoration_verified', 'production_admitted',
                         'source_authenticated_for_state'):
                self.assertIs(False, parent.status()[name])
            for name in parent.modules:
                self.assertIs(sys.modules.get(name), before_modules.get(name))
            before = (tuple(model.calls), clock.calls, model.spawn_calls, model.process.wait_calls)
            self.assertTrue(parent.close())
            with self.assertRaisesRegex(module.ReadonlyParentError, '^parent_already_attempted$'):
                parent.collect()
            self.assertEqual(before, (tuple(model.calls), clock.calls, model.spawn_calls, model.process.wait_calls))
            completed.append('parent_complete_packet')

        # 7: New Parent terminal consumer refuses bad child data/no retry.
        # Raw reader tests from87 are not replayed: each goes through collect().
        with self.subTest(domain='parent_terminal_refusal'):
            for fault, reason in (('truncated', 'packet_incomplete'), ('tail', 'packet_trailing_data'),
                                  ('binding', 'parent_packet_binding_or_stderr'), ('nonzero', 'parent_child_failed')):
                with self.subTest(terminal=fault):
                    module, parent, model, clock = _parent_fixture(self, parent_source, raws, fault)
                    # The child's encoder and Parent decoder are separate private
                    # class domains, so catch the latter only after it loads.
                    try: parent.collect()
                    except ValueError as error:
                        self.assertEqual(reason, str(error))
                        if fault in ('binding', 'nonzero'):
                            self.assertIs(type(error), module.ReadonlyParentError)
                        else:
                            self.assertIs(type(error), parent.modules['mta_observer_packet'].ObserverPacketError)
                        self.assertIs(error, parent.failure)
                    else: self.fail('HOST89 terminal data admitted')
                    self.assertIsNone(parent.result)
                    self.assertIsNone(parent.report)
                    self.assertTrue(parent.status()['failed'])
                    self.assertEqual(1, model.spawn_calls)
                    self.assertTrue(all(row['closed'] and not row['unknown'] for row in parent.rows))
                    self.assertEqual({}, model.live)
                    self.assertEqual(0 if fault == 'tail' else 1, model.process.wait_calls)
                    self.assertEqual(fault != 'tail', parent.process_attempt['reaped'])
                    self.assertEqual(fault == 'tail', parent.status()['resource_pending'])
                    before = (tuple(model.calls), clock.calls, model.process.wait_calls)
                    parent.close()
                    self.assertEqual(before, (tuple(model.calls), clock.calls, model.process.wait_calls))
                    self.assertEqual((31.0, 36.0), parent.period_original)
            completed.append('parent_terminal_refusal')

        # 8: First returned process/pipes retained before late/partial rejection.
        with self.subTest(domain='parent_spawn_late_partial'):
            for fault, reason in (('late_spawn', 'parent_expired'), ('partial_pipe', 'parent_pipe_missing')):
                with self.subTest(spawn=fault):
                    module, parent, model, clock = _parent_fixture(self, parent_source, raws, fault)
                    with self.assertRaisesRegex(module.ReadonlyParentError, '^' + reason + '$') as caught:
                        parent.collect()
                    self.assertIs(caught.exception, parent.failure)
                    self.assertIs(parent.process, model.process)
                    self.assertIs(parent.process_attempt['process'], model.process)
                    self.assertTrue(parent.process_attempt['called'] and parent.process_attempt['returned'])
                    out, err = parent.process_attempt['pipes']
                    self.assertIs(out['raw_original'], model.process.stdout)
                    self.assertIs(out['metadata'], out['metadata_original'])
                    self.assertTrue(out['closed'] and out['close_called'])
                    if fault == 'late_spawn':
                        self.assertIs(err['raw_original'], model.process.stderr)
                        self.assertIs(err['metadata'], err['metadata_original'])
                        self.assertTrue(err['closed'] and err['close_called'])
                        self.assertFalse(out['unknown'] or err['unknown'])
                    else:
                        self.assertIsNone(err['raw'])
                        self.assertTrue(err['unknown'])
                        self.assertFalse(err['closed'] or err['close_called'])
                    self.assertEqual({}, model.live)
                    self.assertEqual(1, model.spawn_calls)
                    self.assertEqual(0, model.process.wait_calls)
                    self.assertFalse(parent.process_attempt['reaped'])
                    self.assertTrue(parent.status()['resource_pending'])
                    self.assertIsNone(parent.result)
                    before = (tuple(model.calls), clock.calls)
                    self.assertFalse(parent.close())
                    self.assertEqual(before, (tuple(model.calls), clock.calls))
                    self.assertEqual((31.0, 36.0), parent.period_original)
            completed.append('parent_spawn_late_partial')

        # 9: Unknown close never becomes known after expiry/no-retry or FD reuse.
        with self.subTest(domain='parent_close_unknown'):
            module, parent, model, clock = _parent_fixture(self, parent_source, raws, 'close_unknown')
            with self.assertRaisesRegex(module.ReadonlyParentError, '^parent_inventory_pending$') as caught:
                parent.collect()
            self.assertIs(caught.exception, parent.failure)
            self.assertTrue(parent.process_attempt['reaped'])
            out, err = parent.process_attempt['pipes']
            self.assertTrue(out['closed'])
            self.assertTrue(err['close_called'] and err['unknown'])
            self.assertFalse(err['closed'])
            self.assertIs(err['close_failure'], model.close_error)
            self.assertIn(model.close_error, parent.close_errors)
            self.assertEqual(1, model.process.stderr.close_calls)
            self.assertEqual(1, model.close_counts[err['fd']])
            self.assertIsNone(parent.result)
            self.assertTrue(parent.status()['resource_pending'])
            failure, period = parent.failure, parent.period_original
            clock.value = parent.cleanup_until + 1.0
            before = (tuple(model.calls), clock.calls, model.process.wait_calls)
            self.assertFalse(parent.close())
            self.assertFalse(parent.close())
            self.assertEqual(before, (tuple(model.calls), clock.calls, model.process.wait_calls))
            self.assertIs(failure, parent.failure)
            self.assertIs(period, parent.period_original)
            self.assertEqual(1, model.process.stderr.close_calls)
            self.assertEqual(1, model.close_counts[err['fd']])
            self.assertEqual([err['fd']], list(model.live))
            completed.append('parent_close_unknown')

        self.assertEqual(9, len(completed))
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
