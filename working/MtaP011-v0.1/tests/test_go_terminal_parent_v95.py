"""HOST95 new terminal Parent with actual Linux pipes/child and real monotonic.
Target files/anchors/ARM image are explicit models. Original Parent methods,
private source loading, codec, select pump and cleanup execute unpatched.
Child simulates Entry terminal output; Entry/Body/Loader/ARM/helper, State,
RF, restoration, admission and phone do not execute. No old method replay.
"""
import base64
import builtins
import copy
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import sys
import time
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
PHYSICAL = '/var/volatile/tmp/p011-mta-go-observer-v85'
ALIAS = '/tmp/p011-mta-go-observer-v85'
SOURCE_INPUTS = (
  (
    "p011_json",
    "runtime/p011_json.py",
    8061,
    "fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88"
  ),
  (
    "mta_ip",
    "runtime/mta_ip.py",
    22049,
    "1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5"
  ),
  (
    "mta_p2p_client_init",
    "candidate/client-parent-cap-v33/runtime/mta_p2p_client_init.py",
    71315,
    "d3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa"
  ),
  (
    "mta_snapshot_data",
    "candidate/go-send-observer-v85/runtime/mta_snapshot_data.py",
    17217,
    "cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26"
  ),
  (
    "mta_observer_packet",
    "candidate/go-send-terminal-channel-v94/runtime/mta_observer_packet.py",
    48253,
    "004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f"
  ),
  (
    "mta_go_readonly_entry",
    "candidate/go-send-terminal-channel-v94/runtime/mta_go_readonly_entry.py",
    43263,
    "af87658a8a7bdf24f0c363a94a6e71c9cfb150f648e5af007e4e17f5d0fc0868"
  )
)
PARENT_SOURCE = ('candidate/go-send-terminal-parent-v95/runtime/mta_go_readonly_parent.py',
    64795, 'dbe62e66b3a42a0d0d9d9c0c60e950a253064e37d0a100b223f1f6cd84c76cd4')
SOURCE_MANIFEST = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
FALSE_KEYS = ('rf_requested', 'native_restore_verified', 'restoration_verified',
              'independent_restore_verified', 'production_admitted')
MARKER = ('HOST95_TERMINAL_PARENT new_methods=1 old_methods=0 cases=8 '
          'kernel_pipes=true child_model=true arm_source_model=true device=false phone=false\n')


def _fixed(row):
    path, count, pin = row
    raw = (BASE / path).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (count, pin):
        raise AssertionError('HOST95 fixed source identity changed')
    return raw


def _module(name, raw, modules=None):
    modules = {} if modules is None else modules
    original_import = builtins.__import__
    def private_import(target, globals=None, locals=None, fromlist=(), level=0):
        if level or target.startswith(('mta_', 'p011_')):
            if level or target not in modules:
                raise AssertionError('HOST95 no ordinary source fallback')
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


def _metadata(ino, mode, size=0, nlink=1):
    return types.SimpleNamespace(st_dev=92, st_ino=ino, st_mode=mode,
        st_uid=0, st_gid=0, st_nlink=nlink, st_size=size, st_rdev=0,
        st_mtime_ns=1000000000 + ino, st_ctime_ns=2000000000 + ino)


class _ParentModel(object):
    """Only syscalls/results are modeled; Parent95 source filesystem is original."""
    def __init__(self, case, raws, clock, fault):
        self.case, self.raws, self.clock, self.fault = case, raws, clock, fault
        self.calls, self.live, self.positions, self.buffers, self.close_counts = [], {}, {}, {}, {}
        self.next_fd, self.spawn_calls, self.validate_calls = 100, 0, 0
        self.owner = self.process = None
        self.data_modules = _data_domain(raws)
        self.packet_raw, self.first_output = None, None
        self.expired_read = self.close_faulted = False
        self.wait_error = subprocess.TimeoutExpired('HOST95 modeled original observer', 0.1)
        self.spawn_error = OSError(errno.EIO, 'HOST95 modeled original constructor failure')
        self.close_error = OSError(errno.EIO, 'HOST95 modeled original close uncertainty')
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
        raise AssertionError('HOST95 unexpected modeled file role')
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
            raise AssertionError('HOST95 unexpected modeled alias')
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
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST95 modeled closed FD')
        return self.live[fd]['metadata']
    def flags(self, fd):
        self.calls.append(('flags', fd))
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST95 modeled closed FD')
        return self.live[fd]['flags']
    def set_flags(self, fd, value):
        self.calls.append(('set_flags', fd, value))
        self.live[fd]['flags'] = value
        return None
    def nonce(self):
        self.calls.append(('nonce',))
        return b'\xaa' * 16
    def read(self, fd, count):
        self.calls.append(('read', fd, count))
        row = self.live[fd]
        if row['role'] not in ('stdout', 'stderr'):
            raw, off = row['raw'], self.positions[fd]
            value = raw[off:off + count]
            self.positions[fd] += len(value)
            return value
        raise AssertionError('HOST95 source FD unexpectedly a pipe')

    def close(self, fd):
        self.calls.append(('close', fd))
        self.close_counts[fd] = self.close_counts.get(fd, 0) + 1
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST95 modeled closed FD')
        del self.live[fd]
        return None
def _tag(value):
    # Independent primitive wire builder, not a native DATA constructor.
    if type(value) is tuple: return ['tuple', [_tag(item) for item in value]]
    if type(value) is bytes: return ['bytes', value.hex()]
    if value is None or type(value) in (str, bool, int): return value
    raise AssertionError('fixture tag accepts primitives only')


def _snapshot(modules):
    core, json = modules['mta_p2p_client_init'], modules['p011_json']
    boot = '01234567-89ab-cdef-0123-456789abcdef'
    hashes = tuple(sorted(core.STOCK_PINS))
    actors = (
        (101, 1001, '/usr/bin/Z03', 'a' * 64, ((101, 1001, 'S'),)),
        (202, 2002, '/usr/bin/control_engine', 'b' * 64, ((202, 2002, 'S'),)),
        (303, 3003, '/usr/bin/weston', 'c' * 64, ((303, 3003, 'S'),)),
    )
    station = (0, 257, 3, 'wlan0', 2)
    rules = ((0, 255), (32766, 254), (32767, 253))
    fields = (boot, hashes, actors, station, 'd' * 64, 2412, (station,),
              ((), (), rules), (), (), True)
    actors_key = tuple((a[0], a[1], a[2], a[3], tuple(t[:2] for t in a[4])) for a in actors)
    key = (boot, hashes, actors_key, station, 'd' * 64, 2412, (station,), (), (), rules, (), ())
    raw = (json.dumps(['p011-snapshot-data-v85', _tag(fields), _tag(key)],
                      ensure_ascii=True) + '\n').encode('ascii')
    key_raw = (json.dumps(['p011-snapshot-key-v85', _tag(key)], ensure_ascii=True) + '\n').encode('ascii')
    def origin(row): return dict(zip(('phy', 'wdev', 'ifindex', 'name', 'iftype'), row))
    def actor(row):
        return dict(pid=row[0], start=row[1], exe=row[2], argv_sha=row[3],
                    tasks=[list(t) for t in row[4]])
    tree = dict(boot=boot, stock_hashes=[dict(path=p, sha256=s) for p, s in hashes],
        stock_actors=[actor(a) for a in actors], station=origin(station),
        station_state_sha='d' * 64, station_frequency=2412, interfaces=[origin(station)],
        ipv4=dict(addresses=[], routes=[], rules=[dict(priority=a, table=b) for a, b in rules]),
        ipv6_addresses=[], ipv6_routes=[], station_completed=True)
    return raw, hashlib.sha256(key_raw).hexdigest(), tree


def _refresh(modules, fixture):
    # SHA/size DATA is recomputed only from THIS synthetic Journal raw, not
    # substituted into the production codec or presented as an IO receipt.
    json, value, journal, finish = (modules['p011_json'], fixture['value'],
                                    fixture['journal'], fixture['finish'])
    raw = json.dumps(journal, ensure_ascii=True, sort_keys=True).encode('ascii')
    metadata = (91, 92, 0o100600, 0, 0, 1, len(raw), 93, 94)
    finish['journal'] = dict(schema='p011-go-typed-live-v72', phase='reconciled',
        generation=journal['generation'], sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw), metadata=list(metadata),
        facts_key=[journal[k] for k in ('schema', 'run_token', 'candidate_sha',
                   'task_id', 'boot_id', 'issued_at', 'until')])
    finish_raw = ('GOFINISH84=' + json.dumps(finish, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
    value.update(finish_raw=finish_raw, finish_sha256=hashlib.sha256(finish_raw).hexdigest(),
        journal_raw=raw, journal_sha256=hashlib.sha256(raw).hexdigest(), journal_metadata=metadata)
    return fixture


def _fixture(modules, child=False):
    snapshot_raw, key_sha, tree = _snapshot(modules)
    binding = dict(nonce='9' * 32, task_id='3' * 32, native_epoch=7,
                   operation_epoch=7, until=140.0, cleanup_until=145.0)
    launch = dict(run='1' * 32, manifest='4' * 64, task='3' * 32, nonce='2' * 32,
        native_epoch=7, operation_epoch=7, until='100.0', candidate_sha='5' * 64, child_pid=42)
    limits = dict(task_until=100.0, service_until=120.0, go_cleanup_until=155.0,
                  service_cleanup_until=180.0)
    device, journal_lock = (71, 72, 0o100600, 0, 0, 1, 0, 73, 74), (81, 82, 0o100600, 0, 0, 1, 0, 83, 84)
    journal = dict(schema='p011-go-typed-live-v72', run_token=launch['run'],
        candidate_sha=launch['candidate_sha'], task_id=launch['task'], boot_id=tree['boot'],
        issued_at=1.0, until=100.0, phase='reconciled', generation=20,
        baseline=copy.deepcopy(tree), restored=copy.deepcopy(tree),
        interface_intent=None, owned=None, watchdog=None, controller=None,
        group_add=None, group_observed=None, cleanup_until=150.0, ip=None, dhcp=None)
    f_actor = dict(pid=42, start=4200, exe='/usr/bin/python3.5', argv_sha='6' * 64,
                   tasks=[[42, 4200, 'S'], [43, 4300, 'R']])
    finish = dict(schema='p011-go-finish-data-v93', provenance='returned_restore',
        binding=dict((k, launch[k]) for k in ('run', 'manifest', 'task', 'nonce',
                      'native_epoch', 'operation_epoch', 'until')), journal=None,
        cleanup_until=150.0, finished_at=130.0, device_lock_metadata=list(device),
        f_actor=[42, 4200, '6' * 64], f_actor_data=f_actor, children=[],
        children_outcomes=[], inventory_counts=[8, 12], business_failed_at_capture=True,
        native_full_inventory_export=False, independent_restore_verified=False, production_admitted=False)
    absences = [('f', 42, 4200, 2, 10, 10)]
    if child:
        actor = dict(pid=411, start=4110, exe='/fixed/controller', argv_sha='8' * 64,
                     tasks=[[411, 4110, 'S'], [412, 4120, 'R']])
        journal['controller'] = dict(phase='live', spec_sha='7' * 64, argv_sha='8' * 64,
                                     until=100.0, actor=actor)
        journal['interface_intent'] = dict(boot=tree['boot'], phy=0, name='mta01234567', sequence=1, port_id=2)
        journal['owned'] = dict(phy=0, wdev=258, ifindex=9, name='mta01234567', iftype=8)
        finish['children'] = [['controller', 411, 4110]]
        finish['children_outcomes'] = [dict(role='controller', fork_requested=True,
            fork_negative=False, waited=True, exit_verified=True, actor_present=True)]
        absences.append(('controller', 411, 4110, 2, 12, 12))
    value = dict(schema='p011-go-terminal-data-v94',
        binding=tuple(sorted(binding.items())), launch_binding=tuple(sorted(launch.items())),
        cleanup_limits=tuple(sorted(limits.items())), finish_raw=None, finish_sha256=None,
        journal_raw=None, journal_sha256=None, journal_metadata=None,
        device_lock_metadata=device, journal_lock_metadata=journal_lock,
        snapshot_raw=snapshot_raw, stable_key_sha256=key_sha, snapshot_round_count=2,
        absence_facts=tuple(absences), source_manifest_sha256=SOURCE_MANIFEST, source_count=38,
        active_until=140.0, cleanup_until=145.0)
    for key in FALSE_KEYS: value[key] = False
    return _refresh(modules, dict(binding=binding, launch=launch, limits=limits,
        journal=journal, finish=finish, value=value))



# Child has its own bounded HOST monotonic lifetime. It intentionally writes
# stdout and stderr before reading stdin to exercise actual kernel backpressure.
CHILD = r"""
import base64, os, select, sys, time
expected, output = [base64.b64decode(x) for x in sys.argv[1:3]]
mode = sys.argv[3]
deadline = time.monotonic() + 12.0
if mode == 'active_expired': time.sleep(1.0)
if mode == 'stderr': error = b'e' * 16384
else: error = b''
for fd, raw in ((1, output), (2, error)):
    os.set_blocking(fd, False)
    off = 0
    while off < len(raw):
        remaining = deadline - time.monotonic()
        if remaining <= 0: sys.exit(78)
        ready = select.select((), (fd,), (), min(0.1, remaining))[1]
        if not ready: continue
        try: count = os.write(fd, raw[off:])
        except BlockingIOError: continue
        except BrokenPipeError: sys.exit(79)
        if count <= 0: sys.exit(80)
        off += count
os.set_blocking(0, False)
parts = []
while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0: sys.exit(81)
    if not select.select((0,), (), (), min(0.1, remaining))[0]: continue
    try: raw = os.read(0, 65536)
    except BlockingIOError: continue
    if not raw: break
    parts.append(raw)
    if sum(map(len, parts)) > len(expected): sys.exit(82)
received = b''.join(parts)
if mode in ('normal', 'stderr', 'truncated_eof', 'wait_error'):
    if received != expected: sys.exit(83)
elif not expected.startswith(received): sys.exit(84)
sys.exit(0)
"""


class _RealProcess(subprocess.Popen):
    def __init__(self, model, request, output):
        self.model = model
        self.original_wait_calls = self.original_poll_calls = 0
        self.request_fd = self.output_fd = self.error_fd = None
        super().__init__((sys.executable, '-I', '-B', '-c', CHILD,
            base64.b64encode(request).decode('ascii'),
            base64.b64encode(output).decode('ascii'), model.fault),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, close_fds=True)
        self.request_fd, self.output_fd, self.error_fd = [
            stream.fileno() for stream in (self.stdin, self.stdout, self.stderr)]
        model.case.assertLess(max(self.request_fd, self.output_fd, self.error_fd), 100)
        for fd in (self.request_fd, self.output_fd):
            model.case.assertEqual(4096, fcntl.fcntl(fd, fcntl.F_SETPIPE_SZ, 4096))

    def poll(self):
        self.original_poll_calls += 1
        return super().poll()

    def wait(self, timeout=None):
        self.original_wait_calls += 1
        self.model.case.assertEqual(1, self.original_wait_calls)
        self.model.case.assertGreater(timeout, 0.0)
        self.model.case.assertTrue(all(
            row['eof'] for row in self.model.owner.process_attempt['pipes']))
        result = super().wait(timeout=timeout)
        if self.model.fault == 'wait_error':
            raise self.model.wait_error  # Physical reap occurred; original outcome unknown.
        return result


class _KernelIo(_ParentModel):
    def __init__(self, case, raws, fixture, mode):
        super().__init__(case, raws, None, mode)
        self.fixture, self.partial_writes, self.actual_writes = fixture, 0, []
        self.wait_error = subprocess.TimeoutExpired('HOST95 original wait uncertainty', 0.1)

    def pid(self): return os.getpid()
    def nonce(self):
        self.calls.append(('nonce',))
        return os.urandom(16)
    def fstat(self, fd):
        if fd >= 100: return super().fstat(fd)
        self.calls.append(('fstat', fd))
        return os.fstat(fd)
    def flags(self, fd):
        if fd >= 100: return super().flags(fd)
        self.calls.append(('flags', fd))
        return fcntl.fcntl(fd, fcntl.F_GETFL)
    def set_flags(self, fd, value):
        if fd >= 100: return super().set_flags(fd, value)
        self.calls.append(('set_flags', fd, value))
        return fcntl.fcntl(fd, fcntl.F_SETFL, value)
    def inheritable(self, fd):
        self.calls.append(('inheritable', fd))
        return False if fd >= 100 else os.get_inheritable(fd)
    def read(self, fd, count):
        if fd >= 100: return super().read(fd, count)
        self.calls.append(('read', fd, count))
        return os.read(fd, count)
    def write(self, fd, raw):
        self.calls.append(('write', fd, len(raw)))
        count = os.write(fd, raw)  # Actual syscall before any faulted result.
        self.actual_writes.append((fd, raw, count))
        if count < len(raw): self.partial_writes += 1
        if self.fault == 'write_unknown': return None
        if self.fault == 'write_zero': return 0
        return count
    def close(self, fd):
        if fd >= 100: return super().close(fd)
        self.calls.append(('close', fd))
        return os.close(fd)
    def ready(self, reads, writes, timeout):
        self.calls.append(('ready', reads, writes, timeout))
        selected = select.select(reads, writes, (), timeout)
        return selected[0], selected[1]
    def readable(self, reads, timeout):
        self.calls.append(('readable', reads, timeout))
        return select.select(reads, (), (), timeout)[0]
    def spawn(self, argv, pythonfd):
        self.calls.append(('spawn', argv, pythonfd)); self.spawn_calls += 1
        self.case.assertEqual(('/usr/bin/python3.5', '-I', '-B',
            PHYSICAL + '/runtime/mta_go_readonly_entry.py', '--collect', '--terminal'), argv[:6])
        self.case.assertEqual('python', self.live[pythonfd]['role'])
        args = dict(zip(argv[6::2], argv[7::2]))
        self.case.assertEqual({'--nonce', '--task-id', '--native-epoch', '--operation-epoch',
                              '--until', '--cleanup-until'}, set(args))
        binding = dict(nonce=args['--nonce'], task_id=args['--task-id'],
            native_epoch=int(args['--native-epoch']), operation_epoch=int(args['--operation-epoch']),
            until=float(args['--until']), cleanup_until=float(args['--cleanup-until']))
        value = copy.copy(self.fixture['value'])
        value.update(binding=tuple(sorted(binding.items())),
            active_until=binding['until'], cleanup_until=binding['cleanup_until'])
        self.packet_raw = self.owner.modules['mta_observer_packet'].encode_terminal_result(value)
        self.case.assertGreater(len(self.owner.request_raw), 4096)
        self.case.assertGreater(len(self.packet_raw), 4096)
        output = self.packet_raw
        if self.fault == 'parser_failure': output = b'NOTTERM94!!' + output[11:]
        if self.fault == 'truncated_eof': output = output[:-7]
        self.process = _RealProcess(self, self.owner.request_raw, output)
        return self.process


def _large_fixture(modules, mode):
    fixture = _fixture(modules)
    now = time.monotonic()
    # WSL may have just booted: expire this task without negative uptime DATA.
    if now <= 0.1: raise AssertionError('HOST95 host uptime unavailable')
    task, service = now - 0.001, now + 120.0
    cap = now + (5.7 if mode == 'active_expired' else 20.0)
    fixture['launch']['until'] = repr(task)
    fixture['limits'].update(task_until=task, service_until=service,
        go_cleanup_until=cap, service_cleanup_until=service + 60.0)
    fixture['journal'].update(issued_at=task - 0.001, until=task, cleanup_until=cap)
    fixture['finish']['binding']['until'] = repr(task)
    fixture['finish'].update(cleanup_until=cap, finished_at=now - 0.05)
    fixture['binding'].update(until=now + 0.2, cleanup_until=now + 0.3)
    fixture['value'].update(launch_binding=tuple(sorted(fixture['launch'].items())),
        cleanup_limits=tuple(sorted(fixture['limits'].items())),
        binding=tuple(sorted(fixture['binding'].items())), active_until=now + 0.2,
        cleanup_until=now + 0.3)
    codec = modules['mta_observer_packet']
    for count in range(1, 129):
        fixture['finish']['f_actor_data']['tasks'] = [
            [42 + i, 4200 + i, 'S'] for i in range(count)]
        _refresh(modules, fixture)
        # Actual production codec accepts exact lawful fields and production caps.
        request = codec.encode_terminal_request(fixture['binding'], fixture['launch'],
            fixture['value']['finish_raw'], fixture['limits'])
        if len(request) > 4096:
            if len(fixture['value']['finish_raw']) > 4096:
                raise AssertionError('HOST95 production finish cap exceeded')
            return fixture
    raise AssertionError('HOST95 no lawful backpressure fixture')


class GoTerminalParent95Test(unittest.TestCase):
    def test_three_pipe_terminal_and_failure_cleanup(self):
        raws = {name: _fixed((path, count, pin)) for name, path, count, pin in SOURCE_INPUTS}
        source = _fixed(PARENT_SOURCE)
        completed = []
        for mode in ('normal', 'stderr', 'truncated_eof', 'parser_failure',
                     'write_unknown', 'write_zero', 'active_expired', 'wait_error'):
            with self.subTest(case=mode):
                modules = _data_domain(raws)
                fixture = _large_fixture(modules, mode)
                model = _KernelIo(self, raws, fixture, mode)
                parent_module = _module('host95_parent', source)
                class ProjectedLinuxIo(_KernelIo):
                    def __init__(self): self.__dict__ = model.__dict__
                parent_module._LinuxIo = ProjectedLinuxIo
                launch, limits = fixture['launch'], fixture['limits']
                parent = parent_module.ReadonlyTerminalParent(launch['task'], 7, 7,
                    limits['task_until'], limits['service_until'], launch,
                    fixture['value']['finish_raw'], limits, fixture['finish']['cleanup_until'])
                model.owner = parent
                data, error = None, None
                try:
                    with mock.patch('os.kill', side_effect=AssertionError('HOST95 no kill')):
                        data = parent.collect()
                except BaseException as caught:
                    error = caught
                self.assertEqual(1, model.spawn_calls)
                self.assertIsNotNone(model.process)
                self.assertEqual(1, model.process.original_wait_calls)
                self.assertEqual(0, model.process.original_poll_calls)
                self.assertEqual(0, model.process.returncode)
                self.assertTrue(parent.ended and parent.close_attempted)
                self.assertEqual({}, model.live)
                self.assertTrue(parent._input_closed())
                for row in parent.process_attempt['pipes']:
                    self.assertTrue(row['eof'])
                    self.assertEqual(b'', row['eof_ticket'][-1])
                for stream in (model.process.stdin, model.process.stdout, model.process.stderr):
                    self.assertTrue(stream.closed)
                for fd in (model.process.request_fd, model.process.output_fd, model.process.error_fd):
                    with self.assertRaises(OSError) as badfd: os.fstat(fd)
                    self.assertEqual(errno.EBADF, badfd.exception.errno)
                self.assertTrue(all(row['closed'] and not row['unknown'] for row in parent.rows))
                if mode == 'normal':
                    self.assertIsNone(error)
                    self.assertIs(data, parent.result)
                    self.assertIs(data, parent.report)
                    self.assertIs(data, parent.reader.value)
                    self.assertEqual(fixture['value']['finish_raw'], data.private_finish_ascii())
                    self.assertTrue(parent.closed and parent._request_complete())
                    self.assertGreater(model.partial_writes, 0)
                    self.assertGreater(len(parent.write_ticket['attempts']), 1)
                    self.assertEqual(len(parent.request_raw), parent.write_ticket['offset'])
                    self.assertEqual(0, parent.stderr_bytes)
                else:
                    self.assertIsNotNone(error)
                    self.assertIs(error, parent.failure)
                    self.assertIsNone(parent.result)
                    self.assertIsNone(parent.report)
                    self.assertTrue(parent.cleanup_attempted)
                    if mode in ('write_unknown', 'write_zero'):
                        self.assertEqual('terminal_write_return', str(error))
                        self.assertTrue(parent.write_ticket['unknown'])
                        self.assertEqual(1, len(parent.write_ticket['attempts']))
                        self.assertEqual(1, len(model.actual_writes))
                        self.assertEqual(0, parent.write_ticket['offset'])
                    if mode == 'active_expired':
                        self.assertEqual('parent_expired', str(error))
                        self.assertTrue(parent.process_attempt['reaped'])
                    if mode == 'wait_error':
                        self.assertIs(error, model.wait_error)
                        self.assertIs(error, parent.process_attempt['wait_error'])
                        self.assertFalse(parent.closed)
                for key in ('rf_requested', 'native_restore_verified', 'independent_restore_verified',
                            'restoration_verified', 'production_admitted', 'source_authenticated_for_state'):
                    self.assertIs(False, parent.status()[key])
                before = (tuple(model.calls), model.process.original_wait_calls,
                          model.process.original_poll_calls, model.spawn_calls)
                self.assertEqual(parent.closed, parent.close())
                self.assertEqual(before, (tuple(model.calls), model.process.original_wait_calls,
                    model.process.original_poll_calls, model.spawn_calls))
                completed.append(mode)
        self.assertEqual(8, len(completed))
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
