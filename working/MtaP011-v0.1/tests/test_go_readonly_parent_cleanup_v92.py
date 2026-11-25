"""SOURCE only: new Parent92 failure drain/reap, no old method replay.

Full Parent92 definitions and its new cleanup methods execute only when ROOT
runs this new method. ARM/platform/source metadata, process, pipe, FD and clock
are explicit models; no helper/Popen/kernel pipe/target work occurs. The five
private packet definitions and PacketReader rejection are actual algorithms.
No Parent89 TestCase, test method or helper is imported. Copied model shapes
are not old test dispatch. New Parent success/cleanup methods are never patched.
Failure cleanup never issues a report, task renewal, RF or restoration grant.
"""
import builtins
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
PHYSICAL = '/var/volatile/tmp/p011-mta-go-observer-v85'
ALIAS = '/tmp/p011-mta-go-observer-v85'
SOURCE_INPUTS = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 'runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'candidate/client-parent-cap-v33/runtime/mta_p2p_client_init.py', 71315,
     'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('mta_snapshot_data', 'candidate/go-send-observer-v85/runtime/mta_snapshot_data.py', 17217,
     'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
    ('mta_observer_packet', 'candidate/go-send-observer-entry-v87/runtime/mta_observer_packet.py', 13223,
     '6f2c882058ee30a630ac30e1a5b4e9277d04ee2e71c108b58966a0574bf74e7a'),
    ('mta_go_readonly_entry', 'candidate/go-send-observer-entry-v87-r2/runtime/mta_go_readonly_entry.py', 25537,
     '41ec9d93147b875bb38363f15e545962459e4eaba161ccc5fb7759ce6c5c7df9'),
)
PARENT_SOURCE = (
    'candidate/go-send-observer-parent-v92/runtime/mta_go_readonly_parent.py',
    50693, '417af52e6424320d1421f74110526e70edbdd0210e8f42e789ec1ed1e3b84cfa')
MARKER = ('HOST92_PARENT_CLEANUP new_methods=1 old_methods=0 cases=8 fixtures=11 '
          'parent_model=true pure_packet=true device=false phone=false\n')


def _fixed(value):
    if type(value) is not tuple or len(value) != 3:
        raise AssertionError('HOST92 SOURCE is not frozen')
    path, size, pin = value
    raw = (BASE / path).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, pin):
        raise AssertionError('HOST92 SOURCE identity changed')
    return raw


def _inputs():
    values = {}
    for name, path, size, pin in SOURCE_INPUTS:
        values[name] = _fixed((path, size, pin))
    return values, _fixed(PARENT_SOURCE)


def _module(name, raw, modules=None):
    """Complete definitions; no canonical sys.modules writes/fallback."""
    modules = {} if modules is None else modules
    original_import = builtins.__import__

    def private_import(target, globals=None, locals=None, fromlist=(), level=0):
        if level or target.startswith(('mta_', 'p011_')):
            if level or target not in modules:
                raise AssertionError('HOST92 no ordinary source fallback')
            return modules[target]
        return original_import(target, globals, locals, fromlist, level)

    value = types.ModuleType(name)
    value.__file__ = PHYSICAL + '/runtime/' + name + '.py'
    value.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def _data_domain(raws):
    modules = {}
    for name in ('p011_json', 'mta_ip', 'mta_p2p_client_init',
                 'mta_snapshot_data', 'mta_observer_packet'):
        modules[name] = _module(name, raws[name], modules)
    return modules


def _packet_data(modules, binding):
    """Valid pure primitive DATA; not a baseline/Actor/proof issuer."""
    codec, packet = modules['mta_snapshot_data'], modules['mta_observer_packet']
    station = (0, 1, 2, 'wlan0', 2)
    actors = tuple((pid, pid + 100, exe, 'a' * 64, ((pid, pid + 100, 'S'),))
                   for pid, exe in ((1, '/usr/bin/Z03'),
                                    (2, '/usr/bin/control_engine'), (3, '/usr/bin/weston')))
    fields = ('11111111-2222-3333-4444-555555555555', tuple(sorted(codec._STOCK_PINS)),
              actors, station, 'b' * 64, 2412, (station,),
              ((), (), ((0, 255), (32766, 254), (32767, 253))), (), (), True)
    codec._full(fields)
    raw = codec._canonical([codec.DATA_SCHEMA, codec._pack(fields),
                            codec._pack(codec._stable_key(fields))])
    data = codec.decode_snapshot(raw)
    result = dict(schema='p011-go-preflight-data-v85', binding=tuple(sorted(binding.items())),
        snapshot_raw=raw, stable_key_sha256=data.key_sha,
        helper_raw=tuple((path, b'{"event":"capabilities"}\n', b'')
                         for path, unused_pin in packet.HELPERS),
        lock_metadata=(1, 2, stat.S_IFREG | 0o600, 0, 0, 1, 0, 10, 20),
        source_manifest_sha256=packet.SOURCE_MANIFEST_SHA, source_count=38,
        active_until=binding['until'], cleanup_until=binding['cleanup_until'],
        rf_requested=False, restoration_verified=False, production_admitted=False)
    return packet.encode_result(result)


class _Clock(object):
    def __init__(self): self.value, self.calls = 1.0, 0
    def __call__(self):
        self.calls += 1
        return self.value


def _metadata(ino, mode, size=0, nlink=1):
    return types.SimpleNamespace(st_dev=92, st_ino=ino, st_mode=mode,
        st_uid=0, st_gid=0, st_nlink=nlink, st_size=size, st_rdev=0,
        st_mtime_ns=1000000000 + ino, st_ctime_ns=2000000000 + ino)


class _ModelPipe(object):
    """Synthetic FD/EOF/closed facts, genuine Python bound method identities."""
    def __init__(self, io, fd, role):
        self.io, self.fd, self.role, self.closed = io, fd, role, False
        self.close_calls = 0
    def fileno(self):
        if self.io.fault == 'unknown_pipe' and self.role == 'stdout':
            return None
        return self.fd
    def close(self):
        self.close_calls += 1
        value = self.io.close(self.fd)
        self.closed = True
        return value


class _ModelProcess(object):
    """No Popen: exact direct-child model with original poll/wait methods."""
    def __init__(self, io, out, err):
        self.io, self.stdout, self.stderr = io, out, err
        self.pid, self.returncode = 929292, None
        self.poll_calls = self.wait_calls = 0
        self.timeouts = []
    def poll(self):
        self.poll_calls += 1
        return self.returncode
    def wait(self, timeout=None):
        self.wait_calls += 1
        self.timeouts.append(timeout)
        self.io.case.assertEqual(1, self.wait_calls)
        self.io.case.assertGreater(timeout, 0.0)
        self.io.case.assertTrue(all(row['eof'] for row in self.io.owner.process_attempt['pipes']))
        if self.io.fault == 'wait_error':
            raise self.io.wait_error
        self.returncode = 0
        if self.io.fault == 'late_reap':
            self.io.clock.value = self.io.owner.cleanup_until
        return self.returncode


class _ParentModel(object):
    """Only syscalls/results are modeled; Parent92 cleanup/parser is original."""
    def __init__(self, case, raws, clock, fault):
        self.case, self.raws, self.clock, self.fault = case, raws, clock, fault
        self.calls, self.live, self.positions, self.buffers, self.close_counts = [], {}, {}, {}, {}
        self.next_fd, self.spawn_calls, self.validate_calls = 100, 0, 0
        self.owner = self.process = None
        self.data_modules = _data_domain(raws)
        self.packet_raw, self.first_output = None, None
        self.expired_read = self.close_faulted = False
        self.wait_error = subprocess.TimeoutExpired('HOST92 modeled original observer', 0.1)
        self.spawn_error = OSError(errno.EIO, 'HOST92 modeled original constructor failure')
        self.close_error = OSError(errno.EIO, 'HOST92 modeled original close uncertainty')
        self.file_metadata = dict((name, _metadata(1000 + i, stat.S_IFREG | 0o400, len(raw)))
                                  for i, (name, raw) in enumerate(raws.items()))
        # Exactly a synthetic ARM ELF shape, never HOST Python or target bytes.
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
    def pid(self): return 9292
    def _file(self, path):
        if path == '/usr/bin/python3.5':
            return 'python', self.python_raw, self.python_metadata
        for prefix in (PHYSICAL + '/runtime/', ALIAS + '/runtime/'):
            if path.startswith(prefix) and path.endswith('.py'):
                name = path[len(prefix):-3]
                if name in self.raws:
                    return name, self.raws[name], self.file_metadata[name]
        raise AssertionError('HOST92 unexpected modeled file role')
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
        if path not in ('/tmp', '/var/tmp'):
            raise AssertionError('HOST92 unexpected modeled alias')
        return '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
    def _fd(self, role, metadata, raw=None):
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.live[fd] = dict(role=role, metadata=metadata, raw=raw, flags=os.O_RDONLY)
        self.positions[fd] = 0
        return fd
    def open(self, path):
        self.calls.append(('open', path))
        role, raw, meta = self._file(path)
        return self._fd(role, meta, raw)
    def fstat(self, fd):
        self.calls.append(('fstat', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST92 modeled closed FD')
        return self.live[fd]['metadata']
    def flags(self, fd):
        self.calls.append(('flags', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST92 modeled closed FD')
        return self.live[fd]['flags']
    def set_flags(self, fd, value):
        self.calls.append(('set_flags', fd, value))
        self.live[fd]['flags'] = value
        return None
    def nonce(self):
        self.calls.append(('nonce',))
        return b'\xaa' * 16
    def spawn(self, argv, pythonfd):
        self.calls.append(('spawn', argv, pythonfd))
        self.spawn_calls += 1
        self.case.assertEqual(('/usr/bin/python3.5', '-I', '-B',
            PHYSICAL + '/runtime/mta_go_readonly_entry.py', '--collect'), argv[:5])
        self.case.assertEqual('python', self.live[pythonfd]['role'])
        if self.fault == 'spawn_error': raise self.spawn_error
        if self.fault == 'spawn_none': return None
        args = dict(zip(argv[5::2], argv[6::2]))
        self.case.assertEqual({'--nonce', '--task-id', '--native-epoch', '--operation-epoch',
                              '--until', '--cleanup-until'}, set(args))
        binding = dict(nonce=args['--nonce'], task_id=args['--task-id'],
            native_epoch=int(args['--native-epoch']), operation_epoch=int(args['--operation-epoch']),
            until=float(args['--until']), cleanup_until=float(args['--cleanup-until']))
        self.packet_raw = _packet_data(self.data_modules, binding)
        # Valid wire + trailing byte fails the actual PacketReader.feed once.
        malformed = self.packet_raw + b'x'
        self.first_output = self.packet_raw if self.fault in ('active_expired', 'wait_error') else malformed
        outfd = self._fd('stdout', _metadata(6000, stat.S_IFIFO | 0o600))
        errfd = self._fd('stderr', _metadata(6001, stat.S_IFIFO | 0o600))
        self.buffers[outfd] = [self.first_output, b'cleanup-only-tail', b'']
        self.buffers[errfd] = [b'cleanup-only-stderr', b'']
        if self.fault == 'wait_error':
            self.buffers[outfd], self.buffers[errfd] = [self.packet_raw, b''], [b'']
        if self.fault == 'byte_budget':
            self.buffers[outfd] = [malformed, b'b' * (262144 + 1), b'']
        out, err = _ModelPipe(self, outfd, 'stdout'), _ModelPipe(self, errfd, 'stderr')
        self.process = _ModelProcess(self, out, err)
        return self.process
    def read(self, fd, count):
        self.calls.append(('read', fd, count))
        row = self.live[fd]
        if row['role'] not in ('stdout', 'stderr'):
            raw, off = row['raw'], self.positions[fd]
            value = raw[off:off + count]
            self.positions[fd] += len(value)
            return value
        if self.fault == 'event_budget' and self.owner.cleanup_attempted:
            raise OSError(errno.EAGAIN, 'HOST92 modeled nonblocking drain pending')
        if not self.buffers[fd]: raise AssertionError('HOST92 modeled read after EOF')
        raw = self.buffers[fd].pop(0)
        if len(raw) > count:
            self.buffers[fd].insert(0, raw[count:])
            raw = raw[:count]
        self.case.assertLessEqual(len(raw), count)
        if self.fault == 'active_expired' and row['role'] == 'stdout' and not self.expired_read:
            self.expired_read = True
            self.clock.value = self.owner.active_until
        return raw
    def readable(self, fds, timeout):
        self.calls.append(('readable', fds, timeout))
        self.case.assertGreater(timeout, 0.0)
        if self.fault == 'cleanup_expired' and self.owner.cleanup_attempted:
            self.clock.value = self.owner.cleanup_until
            return ()
        return tuple(fd for fd in fds if self.buffers[fd])
    def close(self, fd):
        self.calls.append(('close', fd))
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        if (self.fault == 'close_unknown' and self.live[fd]['role'] == 'stderr'
                and not self.close_faulted):
            self.close_faulted = True
            raise self.close_error
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST92 modeled closed FD')
        del self.live[fd]
        return None


def _fixture(case, source, raws, fault):
    clock = _Clock()
    model = _ParentModel(case, raws, clock, fault)
    module = _module('mta_go_readonly_parent', source)

    class ProjectedLinuxIo(_ParentModel):
        def __init__(self): self.__dict__ = model.__dict__

    # Definition-domain private platform/clock seams, not public injection.
    module._LinuxIo = ProjectedLinuxIo
    module.time = types.SimpleNamespace(monotonic=clock)
    parent = module.ReadonlyDataParent('b' * 32, 1, 1, 100.0, 80.0)
    model.owner = parent
    return module, parent, model, clock


class GoReadonlyParentCleanup92Test(unittest.TestCase):
    def _failed(self, parent):
        try: parent.collect()
        except BaseException as error:
            self.assertIs(error, parent.failure)
            self.assertIsNone(parent.result)
            self.assertIsNone(parent.report)
            self.assertIsNone(parent.result_original)
            self.assertTrue(parent.ended)
            self.assertTrue(parent.cleanup_attempted)
            return error
        self.fail('HOST92 failure issued DATA')

    def _parser_original(self, parent, error):
        packet = parent.modules['mta_observer_packet']
        self.assertIs(type(error), packet.ObserverPacketError)
        self.assertEqual('packet_trailing_data', str(error))
        self.assertIs(error, parent.reader.failure)
        self.assertEqual([parent.process_attempt['pipes'][0]['read_values'][0]], parent.reader.parts)
        self.assertFalse(parent.reader.ended)
        self.assertIsNone(parent.reader.value)

    def _period_and_flags(self, parent):
        self.assertEqual((31.0, 36.0), parent.period_original)
        self.assertIs(parent.active_until, parent.period_original[0])
        self.assertIs(parent.cleanup_until, parent.period_original[1])
        self.assertEqual((100.0, 80.0), (parent.task_until, parent.service_until))
        status = parent.status()
        self.assertTrue(status['failed'])
        self.assertFalse(status['report_observed'])
        for name in ('rf_requested', 'restoration_verified', 'production_admitted',
                     'source_authenticated_for_state'):
            self.assertIs(status[name], False)

    def _no_retry(self, parent, model, clock):
        original_failure, period = parent.failure, parent.period_original
        before = (tuple(model.calls), clock.calls, model.spawn_calls,
                  None if model.process is None else model.process.wait_calls)
        self.assertEqual(parent.closed, parent.close())
        self.assertEqual(parent.closed, parent.close())
        with self.assertRaisesRegex(type(parent).__init__.__globals__['ReadonlyParentError'],
                                   '^parent_already_attempted$'):
            parent.collect()
        self.assertEqual(before, (tuple(model.calls), clock.calls, model.spawn_calls,
                                 None if model.process is None else model.process.wait_calls))
        self.assertIs(parent.failure, original_failure)
        self.assertIs(parent.period_original, period)

    def _reaped_and_known(self, parent, model):
        ticket = parent.process_attempt
        self.assertEqual(1, model.process.wait_calls)
        self.assertEqual(0, model.process.poll_calls)
        self.assertTrue(ticket['waited'] and ticket['reaped'] and ticket['wait_called'])
        self.assertIs(ticket['wait_ticket'], ticket['wait_ticket_original'])
        self.assertIs(ticket['wait_ticket'][0], model.process)
        self.assertIs(ticket['wait_ticket'][2], parent.process_methods[1])
        for row in ticket['pipes']:
            self.assertTrue(row['eof'])
            self.assertEqual(b'', row['eof_ticket'][-1])
            self.assertIs(row['eof_ticket'][0], model.process)
            self.assertIs(row['eof_ticket'][2], row)
            self.assertTrue(row['closed'] and row['close_called'])
            self.assertFalse(row['unknown'])
        self.assertTrue(all(row['closed'] and not row['unknown'] for row in parent.rows))
        self.assertEqual({}, model.live)
        self.assertTrue(all(count == 1 for count in model.close_counts.values()))

    def test_failure_cleanup_and_original_reap(self):
        raws, source = _inputs()
        completed, fixtures = [], 0
        with mock.patch('subprocess.Popen', side_effect=AssertionError('HOST92 no real Popen')) as popen, \
                mock.patch('os.kill', side_effect=AssertionError('HOST92 no kill')) as kill:
            # 1: actual parser failure; subsequent original EOF/read/wait cleanup.
            with self.subTest(domain='parser_failure'):
                module, parent, model, clock = _fixture(self, source, raws, 'parser_failure')
                error = self._failed(parent)
                self._parser_original(parent, error)
                self._reaped_and_known(parent, model)
                self.assertIsNone(parent.cleanup_error)
                self.assertTrue(parent.closed)
                self.assertFalse(parent.status()['resource_pending'])
                self.assertEqual(model.first_output, parent.reader.parts[0])
                self.assertEqual(b'cleanup-only-stderr', b''.join(parent.stderr_parts))
                self.assertGreater(parent.process_attempt['pipes'][0]['bytes'], parent.reader.size)
                self._period_and_flags(parent)
                self._no_retry(parent, model, clock)
                completed.append('parser_failure'); fixtures += 1

            # 2: active read returned late, but original 5s cleanup stays usable.
            with self.subTest(domain='active_expired'):
                module, parent, model, clock = _fixture(self, source, raws, 'active_expired')
                error = self._failed(parent)
                self.assertIs(type(error), module.ReadonlyParentError)
                self.assertEqual('parent_expired', str(error))
                self.assertTrue(model.expired_read)
                self.assertEqual(31.0, clock.value)
                self._reaped_and_known(parent, model)
                self.assertEqual(5.0, model.process.timeouts[0])
                self.assertEqual([], parent.reader.parts)
                self.assertIsNone(parent.cleanup_error)
                self.assertTrue(parent.closed)
                self._period_and_flags(parent)
                self._no_retry(parent, model, clock)
                completed.append('active_expired'); fixtures += 1

            # 3: no cleanup read/reap from an unknown returned stdout identity.
            with self.subTest(domain='unknown_pipe'):
                module, parent, model, clock = _fixture(self, source, raws, 'unknown_pipe')
                error = self._failed(parent)
                self.assertIs(type(error), module.ReadonlyParentError)
                self.assertEqual('parent_fd', str(error))
                out, err = parent.process_attempt['pipes']
                self.assertIs(out['raw_original'], model.process.stdout)
                self.assertIsNone(out['fd_original'])
                self.assertTrue(out['unknown'])
                self.assertFalse(out['close_called'] or out['closed'])
                self.assertTrue(err['closed'])
                self.assertEqual([], out['read_values'])
                self.assertEqual([], err['read_values'])
                self.assertEqual(0, model.process.wait_calls)
                self.assertFalse(parent.process_attempt['reaped'])
                self.assertTrue(parent.status()['resource_pending'])
                self.assertEqual(0, model.process.stdout.close_calls)
                self._period_and_flags(parent)
                self._no_retry(parent, model, clock)
                completed.append('unknown_pipe'); fixtures += 1

            # 4: original wait threw after 2EOF; cleanup must not call it again.
            with self.subTest(domain='wait_error'):
                module, parent, model, clock = _fixture(self, source, raws, 'wait_error')
                error = self._failed(parent)
                self.assertIs(error, model.wait_error)
                self.assertIs(error, parent.process_attempt['wait_error'])
                self.assertEqual(1, model.process.wait_calls)
                self.assertTrue(parent.process_attempt['wait_called'])
                self.assertFalse(parent.process_attempt['reaped'])
                self.assertTrue(all(row['eof'] for row in parent.process_attempt['pipes']))
                self.assertTrue(all(row['closed'] for row in parent.rows))
                self.assertEqual({}, model.live)
                self.assertTrue(parent.status()['resource_pending'])
                self._period_and_flags(parent)
                self._no_retry(parent, model, clock)
                completed.append('wait_error'); fixtures += 1

            # 5: shared byte/event/absolute cleanup bounds, no new quotas or TTL.
            for fault in ('byte_budget', 'event_budget', 'cleanup_expired'):
                with self.subTest(domain='cleanup_bounds', bound=fault):
                    module, parent, model, clock = _fixture(self, source, raws, fault)
                    error = self._failed(parent)
                    self._parser_original(parent, error)
                    self.assertIs(type(parent.cleanup_error), module.ReadonlyParentError)
                    if fault == 'byte_budget':
                        self.assertEqual('parent_pipe_budget', str(parent.cleanup_error))
                        self.assertEqual(module.MAX_PACKET + 1,
                                         parent.process_attempt['pipes'][0]['bytes'])
                    elif fault == 'event_budget':
                        self.assertIn(str(parent.cleanup_error),
                                      ('parent_select_budget', 'parent_read_budget'))
                        self.assertEqual(module.MAX_EVENTS,
                                         max(len(parent.waits), parent.read_attempts))
                    else:
                        self.assertEqual('parent_expired', str(parent.cleanup_error))
                        self.assertEqual(parent.cleanup_until, clock.value)
                    self.assertEqual(0, model.process.wait_calls)
                    self.assertFalse(parent.process_attempt['reaped'])
                    self.assertTrue(all(row['closed'] for row in parent.rows))
                    self.assertEqual({}, model.live)
                    self.assertTrue(parent.status()['resource_pending'])
                    self._period_and_flags(parent)
                    self._no_retry(parent, model, clock)
                    fixtures += 1
            completed.append('cleanup_bounds')

            # 6: late actual modeled reap is retained, never a report/success.
            with self.subTest(domain='late_reap'):
                module, parent, model, clock = _fixture(self, source, raws, 'late_reap')
                error = self._failed(parent)
                self._parser_original(parent, error)
                self._reaped_and_known(parent, model)
                self.assertIs(type(parent.cleanup_error), module.ReadonlyParentError)
                self.assertEqual('parent_expired', str(parent.cleanup_error))
                self.assertEqual(parent.cleanup_until, clock.value)
                self.assertIs(parent.failure, error)
                self.assertFalse(parent.closed)
                self.assertTrue(parent.unknown)
                self.assertTrue(parent.status()['resource_pending'])
                self._period_and_flags(parent)
                self._no_retry(parent, model, clock)
                completed.append('late_reap'); fixtures += 1

            # 7: called constructor failure / None result is unknown, not noFD.
            for fault in ('spawn_error', 'spawn_none'):
                with self.subTest(domain='spawn_unknown', shape=fault):
                    module, parent, model, clock = _fixture(self, source, raws, fault)
                    error = self._failed(parent)
                    ticket = parent.process_attempt
                    self.assertTrue(ticket['called'] and ticket['unknown'])
                    self.assertEqual(fault == 'spawn_none', ticket['returned'])
                    if fault == 'spawn_error':
                        self.assertIs(error, model.spawn_error)
                        self.assertIs(error, ticket['failure'])
                    else:
                        self.assertIs(error, ticket['failure'])
                        self.assertTrue(ticket['field_errors'])
                    self.assertIsNone(parent.process)
                    self.assertEqual(1, model.spawn_calls)
                    self.assertTrue(all(row['unknown'] and not row['closed']
                                        and not row['close_called'] for row in ticket['pipes']))
                    self.assertEqual({}, model.live) # No actual modeled pipe factory returned.
                    self.assertTrue(parent.status()['resource_pending'])
                    self._period_and_flags(parent)
                    self._no_retry(parent, model, clock)
                    fixtures += 1
            completed.append('spawn_unknown')

            # 8: known drain/reap does not erase a once-close original failure.
            with self.subTest(domain='close_unknown'):
                module, parent, model, clock = _fixture(self, source, raws, 'close_unknown')
                error = self._failed(parent)
                self._parser_original(parent, error)
                out, err = parent.process_attempt['pipes']
                self.assertTrue(parent.process_attempt['reaped'])
                self.assertEqual(1, model.process.wait_calls)
                self.assertTrue(out['closed'])
                self.assertTrue(err['close_called'] and err['unknown'])
                self.assertFalse(err['closed'])
                self.assertIs(err['close_failure'], model.close_error)
                self.assertIn(model.close_error, parent.close_errors)
                self.assertEqual(1, model.process.stderr.close_calls)
                self.assertEqual(1, model.close_counts[err['fd']])
                self.assertTrue(parent.status()['resource_pending'])
                before = (tuple(model.calls), model.process.stderr.close_calls)
                clock.value = parent.cleanup_until + 1.0
                self._no_retry(parent, model, clock)
                self.assertEqual(before, (tuple(model.calls), model.process.stderr.close_calls))
                self.assertEqual([err['fd']], list(model.live))
                self._period_and_flags(parent)
                completed.append('close_unknown'); fixtures += 1
            self.assertEqual((0, 0), (popen.call_count, kill.call_count))
        self.assertEqual(['parser_failure', 'active_expired', 'unknown_pipe', 'wait_error',
                          'cleanup_bounds', 'late_reap', 'spawn_unknown', 'close_unknown'], completed)
        self.assertEqual(11, fixtures)
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
