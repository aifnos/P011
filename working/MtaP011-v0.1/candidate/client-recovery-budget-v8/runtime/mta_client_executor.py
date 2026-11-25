"""Private, single-thread CLIENT init executor and its fixed Popen parent.

Default main is source-only. No State/RF deployment is enabled by this module.
The reviewed manifest is local root-owned input, never an HTTP path/command.
Child STATUS messages are not parent wait/reap or restoration evidence.
"""
import builtins
import errno
import hashlib
import math
import os
import re
import select
import stat
import subprocess
import sys
import threading
import time
import types

ROOT = '/tmp/p011-mta-client-rfinit'
JSON_SHA = 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'
MODULES = ('p011_json', 'mta_ip', 'mta_p2p_client_init', 'mta_client_proc',
    'mta_client_caps', 'mta_client_caps_transport', 'mta_client_baseline',
    'mta_client_journal_codec', 'mta_client_coordination', 'mta_client_files',
    'mta_client_pending', 'mta_client_store', 'mta_client_process_owner',
    'mta_client_launch_registration', 'mta_client_two_phase_lease',
    'mta_p2p_client_ctrl', 'mta_client_wpa_status', 'mta_client_linux_provider',
    'mta_client_executor')
PREFIX, CANCEL = b'MTA_CLIENT_F ', b'CANCEL\n'
MAX_SOURCE, MAX_BINARY, MAX_RAW = 2097152, 16777216, 131072
_ENTRY_OWNERS = []  # exact owners survive exception reporting until process exit
_REASONS = frozenset(('not_started', 'source_only', 'unavailable', 'invalid_input',
    'unsupported_platform', 'invalid_clock', 'deadline', 'already_attempted',
    'manifest_invalid', 'source_invalid', 'source_changed', 'resource_unknown',
    'close_unknown', 'actor_unknown', 'assembly_unknown', 'control_invalid',
    'cancelled', 'eof', 'expired', 'watchdog', 'start_failed', 'restore_pending',
    'restored', 'spawn_unknown', 'pipe_unknown', 'frame_invalid', 'wait_unknown',
    'exit_unknown', 'child_pending', 'io_error', 'interrupted'))


class ExecutorError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _REASONS else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code): raise ExecutorError(code) from None


def _uint(value, low=0, high=(1 << 64) - 1):
    return type(value) is int and low <= value <= high


def _finite(value, low, high):
    return type(value) in (int, float) and low <= value <= high and math.isfinite(float(value))


def _token(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{32}', value) is not None


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _path(value):
    return type(value) is str and 1 < len(value) <= 256 and value.startswith('/') and \
        all(p not in ('', '.', '..') for p in value[1:].split('/')) and \
        all(32 <= ord(c) < 127 for c in value)


def _argv(deployment, mode, ttl_text):
    if mode not in ('--execute-client-init', '--watchdog') or type(ttl_text) is not str or \
            re.fullmatch(r'([1-9]|1[0-9]|20)(\.[0-9]{1,6})?', ttl_text) is None or \
            not _finite(float(ttl_text), .1, 20): _fail('invalid_input')
    pm = deployment.manifest
    return (pm.python_exe, '-B', pm.executor_path, mode, '--run-token', pm.run_token,
            '--manifest-sha256', deployment.manifest_sha, '--ttl', ttl_text)


def _entry_identity(actor, deployment, mode, ttl_text):
    argv = _argv(deployment, mode, ttl_text)
    digest = hashlib.sha256(b''.join(v.encode('ascii') + b'\0' for v in argv)).hexdigest()
    if actor.exe != deployment.manifest.python_exe or actor.argv_sha != digest:
        _fail('actor_unknown')


def _meta(value):
    result = tuple(getattr(value, n, None) for n in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(not _uint(v) for v in result): _fail('source_invalid')
    return result


def _public(reason='not_started', attempted=False, ready=False, done=False,
            pending=False, cancelled=False):
    return {'reason': reason, 'attempted': attempted, 'client_init_ready': ready,
        'done': done, 'resource_pending': pending, 'cancel_requested': cancelled,
        'send_available': False, 'receive_available': False,
        'association_verified': False, 'ip_ready': False, 'phone_tested': False}


class _LinuxIo(object):
    process_type = subprocess.Popen

    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or getattr(os, 'O_NOFOLLOW', None) != 0x8000 or
                getattr(os, 'O_CLOEXEC', None) != 0x80000): _fail('unsupported_platform')
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def open(self, path): return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, data): return os.write(fd, data)
    def fstat(self, fd): return os.fstat(fd)
    def close(self, fd): return os.close(fd)
    def ready(self, fds, seconds): return select.select(fds, (), (), seconds)[0]
    def popen(self, argv, executable_fd):
        return subprocess.Popen(argv, executable='/proc/self/fd/' + str(executable_fd),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=(executable_fd,),
            env={'LC_ALL': 'C', 'P011_CLIENT_EXECUTABLE_FD': str(executable_fd)}, shell=False)


class _ReadOwner(object):
    """Actual source file inventory; no close retry, path fallback or GC proof."""
    def __init__(self, io, clock, deadline):
        self.io, self.clock, self.deadline = io, clock, deadline
        self.rows, self.raw, self.last, self.pending = [], [], None, False

    def check(self):
        now = self.clock()
        if not _finite(now, 0, 1e12) or self.last is not None and now < self.last: _fail('invalid_clock')
        self.last = float(now)
        if now >= self.deadline: _fail('deadline')
        return float(now)

    def anchors(self, path, private=False):
        if not _path(path): _fail('source_invalid')
        values = []
        for index in range(len(path.split('/')) - 1):
            name = '/' if index == 0 else '/' + '/'.join(path.split('/')[1:index + 1])
            self.check(); value = _meta(self.io.stat(name))
            if not stat.S_ISDIR(value[2]) or value[3] != 0 or value[2] & 0o022 and name != '/tmp':
                _fail('source_invalid')
            if private and name.startswith(ROOT) and stat.S_IMODE(value[2]) != 0o700: _fail('source_invalid')
            values.append((name, value[:6]))
        return tuple(values)

    def read_file(self, path, limit, expected=None, private=False, binary=False, retain=False):
        self.check()
        if len(self.rows) >= 32: _fail('resource_unknown')
        private_anchor = private or path.startswith(ROOT + '/')
        before = self.anchors(path, private_anchor)
        row = {'fd': None, 'raw': None, 'metadata': None, 'unknown': True,
               'attempted': False, 'closed': False, 'path': path}
        self.rows.append(row)
        try:
            fd = self.io.open(path); row['fd'] = fd
            if not _uint(fd, 0, 0x7fffffff) or any(r is not row and not r['closed'] and r['fd'] == fd for r in self.rows):
                _fail('resource_unknown')
            metadata = _meta(self.io.fstat(fd)); row['metadata'] = metadata
            row['unknown'] = False
            # Actual canonical system Python has two hard links; private inputs stay nlink1.
            if (not stat.S_ISREG(metadata[2]) or metadata[3] != 0 or
                    metadata[5] != 1 and not (binary and not private_anchor and metadata[5] == 2) or
                    metadata[2] & 0o022 or private and stat.S_IMODE(metadata[2]) != 0o400 or
                    binary and not metadata[2] & 0o111 or binary and private_anchor and
                    stat.S_IMODE(metadata[2]) != 0o500 or not 1 <= metadata[6] <= limit): _fail('source_invalid')
            data = b''
            while True:
                self.check(); requested = min(65536, limit + 1 - len(data))
                part = self.io.read(fd, requested)
                if type(part) is not bytes or len(part) > requested: _fail('source_invalid')
                data += part
                if len(data) > limit: _fail('source_invalid')
                if not part: break
            row['raw'] = data; self.raw.append((path, data, metadata))
            if (len(data) != metadata[6] or _meta(self.io.fstat(fd)) != metadata or
                    _meta(self.io.stat(path)) != metadata or self.anchors(path, private_anchor) != before): _fail('source_changed')
            if expected is not None and hashlib.sha256(data).hexdigest() != expected: _fail('source_invalid')
            if binary and not data.startswith(b'\x7fELF'): _fail('source_invalid')
            return data, row
        except BaseException:
            if row['unknown']: self.pending = True
            raise
        finally:
            if not retain: self.close_row(row)

    def close_row(self, row):
        if row['attempted'] or row['closed']: return row['closed'] and not row['unknown']
        if row['unknown']: self.pending = True; return False
        row['attempted'] = True
        try:
            if _meta(self.io.fstat(row['fd'])) != row['metadata']: _fail('close_unknown')
            result = self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error: row['closed'] = result is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: self.pending = True
        if not row['closed']: self.pending = True
        return row['closed']

    def close(self):
        for row in self.rows: self.close_row(row)
        return not self.pending and all(r['closed'] and not r['unknown'] for r in self.rows)


class LoadedDeployment(object):
    def __init__(self, loader, modules, manifest, manifest_sha, run):
        self.loader, self.modules, self.manifest = loader, modules, manifest
        self.manifest_sha, self.run = manifest_sha, run
    def __repr__(self): return '<private verified CLIENT deployment>'


class DeploymentLoader(object):
    """Fixed private directory/graph only. A checksum does not approve RF use."""
    def __init__(self, run_token, manifest_sha256, _io=None, _clock=None):
        if not _token(run_token) or not _sha(manifest_sha256): _fail('invalid_input')
        self.token, self.expected = run_token, manifest_sha256
        self.io, self.clock = _io or _LinuxIo(), _clock or time.monotonic
        self.run = ROOT + '/client-' + run_token
        self.owner = self.value = None
        self.modules, self.failure, self.attempted = {}, None, False

    def load(self):
        if self.attempted: _fail('already_attempted')
        self.attempted = True
        now = self.clock()
        if not _finite(now, 0, 1e12): _fail('invalid_clock')
        self.owner = _ReadOwner(self.io, self.clock, now + 10)
        try:
            self.io.validate()
            json_raw = self.owner.read_file(self.run + '/runtime/p011_json.py', MAX_SOURCE, JSON_SHA, True)[0]
            codec = types.ModuleType('p011_json'); exec(json_raw, codec.__dict__)
            self.modules['p011_json'] = codec
            raw = self.owner.read_file(self.run + '/deployment.json', 65536, self.expected, True)[0]
            tree = codec.loads(raw.decode('utf-8'))
            if type(tree) is not dict or set(tree) != {'version', 'provider', 'sources'} or \
                    type(tree['version']) is not int or tree['version'] != 1 or type(tree['sources']) is not list:
                _fail('manifest_invalid')
            rows = tree['sources']
            if len(rows) != len(MODULES) or any(type(r) is not list or len(r) != 2 or
                    r[0] != name or not _sha(r[1]) for r, name in zip(rows, MODULES)) or rows[0][1] != JSON_SHA:
                _fail('manifest_invalid')
            source = {}
            for name, pin in rows:
                source[name] = self.owner.read_file(self.run + '/runtime/' + name + '.py', MAX_SOURCE, pin, True)[0]
            original = builtins.__import__
            def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name in MODULES:
                    if level or name not in self.modules: _fail('source_invalid')
                    return self.modules[name]
                if level or name.startswith(('mta_', 'p011_')): _fail('source_invalid')
                return original(name, globals, locals, fromlist, level)
            for name in MODULES[1:-1]:
                module = types.ModuleType(name); module.__file__ = self.run + '/runtime/' + name + '.py'
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                self.modules[name] = module  # retain before code/constructors
                exec(source[name], module.__dict__)
            pm = self.modules['mta_client_linux_provider'].ProviderManifest(tree['provider'], _manifest_sha256=self.expected)
            if pm.run_token != self.token or pm.executor_path != self.run + '/runtime/mta_client_executor.py' or \
                    pm.executor_sha != dict(rows)['mta_client_executor'] or pm.wpa_exe != self.run + '/native/mta-wpa-supplicant':
                _fail('manifest_invalid')
            self.owner.read_file(pm.python_exe, MAX_BINARY, pm.python_sha, binary=True)
            self.owner.read_file(pm.wpa_exe, MAX_BINARY, pm.wpa_sha, binary=True,
                                 private=False)
            self.value = LoadedDeployment(self, self.modules, pm, self.expected, self.run)
        except BaseException as error:
            self.failure = error; raise
        finally:
            if self.owner is not None and not self.owner.close():
                if self.failure is None: self.failure = ExecutorError('close_unknown')
        if self.failure is not None: _fail('close_unknown')
        return self.value

    def authenticate(self, value):
        if type(value) is not LoadedDeployment or value is not self.value or value.loader is not self or \
                self.failure is not None or self.owner is None or self.owner.pending or \
                any(r['unknown'] or not r['closed'] for r in self.owner.rows): _fail('source_invalid')
        return None


def _actor(observation, core, proc, single=False):
    if (type(observation) is not proc.ProcObservation or observation.kind != 'live_actor' or
            type(observation.actor) is not core.Actor or not observation.actor.live() or
            observation.same_boot is not True or observation.passes != 2 or type(observation.passes) is not int or
            observation.resource_pending is not False or observation.closed_count != observation.file_count or
            type(observation.file_count) is not int or observation.file_count < 1 or
            single and len(observation.actor.tasks) != 1): _fail('actor_unknown')
    return observation.actor


def _reader_closed(reader):
    """Observe original ProcReader inventory, never close or reset it."""
    if reader is None or reader._pending or reader._active or reader._files != reader._closed:
        return False
    attempt = reader._open_attempt
    if attempt is not None and not (attempt['registered'] or attempt['failed_without_fd']):
        return False
    if len(reader._fd_refs) != reader._files: return False
    for fs, fd in reader._fd_refs:
        try: fs.fstat(fd)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.EBADF: continue
        return False
    return True


def _observe(owner, proc, kind, *args):
    if len(owner.reader_rows) >= 4: _fail('resource_unknown')
    row = {'reader': None, 'call': None, 'result': None, 'returned': False}
    owner.reader_rows.append(row)  # before constructor/call, including exceptions
    reader = proc.ProcReader(timeout=3); row['reader'] = reader; owner.reader = reader
    row['call'] = getattr(reader, kind)
    value = row['call'](*args); row['result'], row['returned'] = value, True
    owner.observations.append(value)
    if not _reader_closed(reader): _fail('resource_unknown')
    return value


def _serialized(method):
    def invoke(self, *args, **kwargs):
        with self._mutex: return method(self, *args, **kwargs)
    return invoke


class _StdinControl(object):
    def __init__(self, io):
        self.io, self.raw, self.cancelled, self.reason = io, [], False, None
        self.metadata = _meta(io.fstat(0))
        if not stat.S_ISFIFO(self.metadata[2]): _fail('control_invalid')
        self.buffer = b''

    def poll(self):
        if self.cancelled: return True
        if _meta(self.io.fstat(0))[:6] != self.metadata[:6]: _fail('control_invalid')
        if not self.io.ready((0,), 0): return False
        raw = self.io.read(0, 8); self.raw.append(raw)
        if type(raw) is not bytes or len(raw) > 8: _fail('control_invalid')
        if not raw: self.cancelled, self.reason = True, 'eof'; return True
        self.buffer += raw
        if len(self.buffer) > len(CANCEL) or not CANCEL.startswith(self.buffer): _fail('control_invalid')
        if self.buffer == CANCEL: self.cancelled, self.reason = True, 'cancelled'
        return self.cancelled


class ClientExecutor(object):
    """Run existing assembly in this F; no synthetic fallback or orphan janitor."""
    def __init__(self, deployment=None, _io=None, _clock=None, _input=None, _emit=None,
                 _ttl_text=None, _environ=None):
        if deployment is not None and type(deployment) is not LoadedDeployment: _fail('invalid_input')
        self.deployment, self.io, self.clock = deployment, _io or _LinuxIo(), _clock or time.monotonic
        self.input, self.emit = _input, _emit
        self.ttl_text = _ttl_text
        self.environ = os.environ if _environ is None else _environ
        self.inherited_elf = None
        self.assembly = self.reader = self.finish = self.assembly_ticket = None
        self.reader_rows = []
        self.observations, self.raw, self.failures = [], [], []
        self.attempted = self.pending = self.done = self.cancel_requested = False
        self.reason, self.last = 'not_started', None
        self.init_ready = False

    def _now(self):
        now = self.clock()
        if not _finite(now, 0, 1e12) or self.last is not None and now < self.last: _fail('invalid_clock')
        self.last = float(now); return float(now)

    def _publish(self, ready=False):
        value = self.status(ready)
        if self.emit is not None: self.emit(value)
        return value

    def _cancelled(self):
        value = self.input.poll()
        if type(value) is not bool: _fail('control_invalid')
        self.cancel_requested = value
        if value and self.assembly is not None: self.assembly[0].request_stop()
        return value

    def _close_inherited_elf(self):
        # Parent exclusively issues this inherited copy. It is not an arbitrary
        # environment FD claim: exact opened/hashed Python metadata must match
        # the Loader's original source record after actual F argv authentication.
        text = self.environ.get('P011_CLIENT_EXECUTABLE_FD')
        row = {'fd': text, 'metadata': None, 'attempted': False, 'closed': False, 'unknown': True}
        self.inherited_elf = row
        if type(text) is not str or re.fullmatch('[1-9][0-9]{0,9}', text) is None or not 3 <= int(text) <= 0x7fffffff:
            _fail('resource_unknown')
        row['fd'] = int(text)
        pm = self.deployment.manifest
        records = [r for r in self.deployment.loader.owner.rows if r['path'] == pm.python_exe]
        if len(records) != 1 or records[0]['unknown'] or not records[0]['closed'] or \
                hashlib.sha256(records[0]['raw']).hexdigest() != pm.python_sha: _fail('source_invalid')
        original = records[0]['metadata']; row['metadata'] = _meta(self.io.fstat(row['fd']))
        if row['metadata'] != original or _meta(self.io.stat(pm.python_exe)) != original: _fail('source_changed')
        row['unknown'], row['attempted'] = False, True
        result = self.io.close(row['fd'])
        try: self.io.fstat(row['fd'])
        except OSError as error:
            row['closed'] = result is None and type(error.errno) is int and error.errno == errno.EBADF
        if not row['closed']: _fail('close_unknown')

    def _complete(self):
        provider, store, owner, bridge, lease = self.assembly
        self.finish = lease.finish_receipt  # preserve before any readback
        core = self.deployment.modules['mta_p2p_client_init']
        receipt = self.finish
        if (type(receipt) is not core.FinishReceipt or receipt.store is not store or
                receipt is not store._finish_receipt or receipt.complete is not True or
                receipt.normal_restored is not True or receipt.terminal_durable is not True or
                receipt.marker_state != 'absent_observed' or receipt.clear_durability != 'verified' or
                receipt.resources_closed is not True or receipt.resource_pending is not False or
                lease.cleanup_complete is not True or lease.pending is not False or
                store.authenticate_finish(receipt.locks, receipt.request_record, receipt, self._now() + 3) is not True or
                bridge.verify_closed() is not True): return False
        closed = provider.closed_resources(tuple(lease.handles.values()), self._now() + 3)
        self.raw.append(closed)
        if type(closed) is not core.CloseProof or closed.expected < len(lease.handles) or not closed.complete(): return False
        unknown_count = owner.status()['unknown_count']
        if type(unknown_count) is not int or unknown_count != 0: return False
        if self.inherited_elf is None or not self.inherited_elf['closed'] or self.inherited_elf['unknown']: return False
        try: self.io.fstat(self.inherited_elf['fd'])
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.EBADF:
                return all(r['returned'] and _reader_closed(r['reader']) for r in self.reader_rows)
        return False

    def run(self, ttl=20):
        if not _finite(ttl, 0.1, 20): _fail('invalid_input')
        if self.attempted: _fail('already_attempted')
        self.attempted = True
        if self.deployment is None: self.reason = 'unavailable'; return self._publish()
        self.deployment.loader.authenticate(self.deployment)
        modules = self.deployment.modules
        core, proc = modules['mta_p2p_client_init'], modules['mta_client_proc']
        try:
            self.io.validate()
            observed = _observe(self, proc, 'read_self')
            actor = _actor(observed, core, proc, True)
            ttl_text = self.ttl_text if self.ttl_text is not None else str(float(ttl))
            if float(ttl_text) != ttl: _fail('invalid_input')
            _entry_identity(actor, self.deployment, '--execute-client-init', ttl_text)
            self._close_inherited_elf()
            self.input = self.input if self.input is not None else _StdinControl(self.io)
            creator = modules['mta_client_linux_provider'].assemble
            self.assembly_ticket = {'creator': creator, 'returned': None, 'unknown': True}
            self.assembly = creator(self.deployment.manifest)
            self.assembly_ticket['returned'] = self.assembly
            if type(self.assembly) is not tuple or len(self.assembly) != 5: _fail('assembly_unknown')
            provider, store, owner, bridge, lease = self.assembly
            if (type(store) is not modules['mta_client_store'].DurableClientInitStore or
                    type(owner) is not modules['mta_client_process_owner'].DirectChildOwner or
                    type(bridge) is not modules['mta_client_linux_provider'].LinuxDirectChildLaunchBridge or
                    type(lease) is not modules['mta_client_linux_provider'].LinuxClientInitLease or
                    lease.provider is not provider or lease.store is not store or lease.bridge is not bridge or
                    bridge.owner is not owner or bridge.store is not store): _fail('assembly_unknown')
            self.assembly_ticket['unknown'] = False
            start = lease.start(ttl=ttl, cancelled=self._cancelled); self.raw.append(start)
            if type(start) is not dict or type(start.get('client_init_ready')) is not bool: _fail('assembly_unknown')
            self.pending = True
            if start['client_init_ready']:
                self.init_ready = True
                self.reason = 'not_started'; self._publish(True)
                while True:
                    if self._cancelled(): self.reason = self.input.reason or 'cancelled'; break
                    notice = provider.poll_requests()
                    if type(notice) is not bool: _fail('assembly_unknown')
                    if notice: self.reason = 'watchdog'; break
                    if lease.record is None or self._now() >= lease.record.deadline: self.reason = 'expired'; break
                    remaining = lease.record.deadline - self._now()
                    if remaining <= 0: self.reason = 'expired'; break
                    self.io.ready((0,), min(.05, remaining))
            else: self.reason = 'start_failed'
        except BaseException as error:
            self.failures.append(error)
            self.reason = error.code if type(error) is ExecutorError else 'io_error' if isinstance(error, Exception) else 'interrupted'
            self.pending = self.assembly_ticket is not None or any(not r['returned'] or
                r['reader'] is None or not _reader_closed(r['reader']) for r in self.reader_rows) or \
                self.inherited_elf is not None and not self.inherited_elf['closed']
        finally:
            if self.assembly_ticket is not None and not self.assembly_ticket['unknown']:
                try:
                    restored = self.assembly[4].restore(timeout=60); self.raw.append(restored)
                    self.done = self._complete()
                    self.pending = not self.done
                    self.reason = 'restored' if self.done else 'restore_pending'
                except BaseException as error:
                    self.failures.append(error); self.pending, self.done, self.reason = True, False, 'restore_pending'
        return self._publish()

    def status(self, ready=False):
        return _public(self.reason, self.attempted, ready and not self.done, self.done, self.pending, self.cancel_requested)


def watchdog(deployment, ttl=20, _io=None, _clock=None, _environ=None, _ttl_text=None):
    """Notification only. Never opens a Store, controls WPA or restores a lease."""
    if type(deployment) is not LoadedDeployment or not _finite(ttl, 0.1, 20): _fail('invalid_input')
    deployment.loader.authenticate(deployment)
    io, clock, env = _io or _LinuxIo(), _clock or time.monotonic, os.environ if _environ is None else _environ
    io.validate()
    numbers = []
    for name in ('P011_CLIENT_DEVICE_FD', 'P011_CLIENT_NOTIFY_FD'):
        value = env.get(name)
        if type(value) is not str or re.fullmatch('[1-9][0-9]{0,9}', value) is None or int(value) > 0x7fffffff:
            _fail('invalid_input')
        numbers.append(int(value))
    if numbers[0] == numbers[1]: _fail('invalid_input')
    device, notify = (_meta(io.fstat(n)) for n in numbers)
    if not stat.S_ISREG(device[2]) or device[3] != 0 or device[5] != 1 or stat.S_IMODE(device[2]) != 0o600 or \
            not stat.S_ISFIFO(notify[2]): _fail('source_invalid')
    proc, core = deployment.modules['mta_client_proc'], deployment.modules['mta_p2p_client_init']
    reader = proc.ProcReader(timeout=3); _ENTRY_OWNERS.append(reader)
    observation = reader.read_self()
    if not _reader_closed(reader): _fail('resource_unknown')
    actor = _actor(observation, core, proc, True)
    ttl_text = _ttl_text if _ttl_text is not None else str(float(ttl))
    if float(ttl_text) != ttl: _fail('invalid_input')
    _entry_identity(actor, deployment, '--watchdog', ttl_text)
    before = clock()
    if not _finite(before, 0, 1e12): _fail('invalid_clock')
    deadline, last = before + ttl, before
    while True:
        now = clock()
        if not _finite(now, 0, 1e12) or now < last: _fail('invalid_clock')
        last = now
        if now >= deadline: break
        io.ready((), min(.05, deadline - now))
    if _meta(io.fstat(numbers[0])) != device or _meta(io.fstat(numbers[1])) != notify: _fail('source_changed')
    if not _reader_closed(reader): _fail('resource_unknown')
    if io.write(numbers[1], b'R') != 1: _fail('control_invalid')
    return 0


class ParentExecutor(object):
    """Fixed Popen only, suitable for a future multithreaded State caller.

    No preexec_fn, os.fork, signal/kill, retry or fake external finalizer. The
    original Popen, stdin/stdout/stderr and binary FD survive unknown outcomes.
    """
    def __init__(self, deployment=None, _io=None, _clock=None):
        if deployment is not None and type(deployment) is not LoadedDeployment: _fail('invalid_input')
        self.deployment, self.io, self.clock = deployment, _io or _LinuxIo(), _clock or time.monotonic
        self.process = self.spawn_ticket = self.reader = self.file_owner = None
        self.reader_rows, self._mutex = [], threading.RLock()
        self.pipes, self.raw, self.frames, self.observations, self.failures = [], [], [], [], []
        self.attempted = self.pending = self.reaped = self.absent = self.closed = self.cancelled = False
        self.reason, self.exit_code, self.actor, self.boot = 'not_started', None, None, None
        self.last, self.buffers = None, {1: b'', 2: b''}
        self.wait_attempted = False
        self.eof = {1: False, 2: False}

    def _now(self):
        now = self.clock()
        if not _finite(now, 0, 1e12) or self.last is not None and now < self.last: _fail('invalid_clock')
        self.last = float(now); return float(now)

    @_serialized
    def start(self, ttl=20):
        if self.attempted: _fail('already_attempted')
        if not _finite(ttl, 0.1, 20): _fail('invalid_input')
        self.attempted = True
        if self.deployment is None: self.reason = 'unavailable'; return self.status()
        self.deployment.loader.authenticate(self.deployment); self.io.validate()
        modules, pm = self.deployment.modules, self.deployment.manifest
        try:
            before = _observe(self, modules['mta_client_proc'], 'read_self')
            _actor(before, modules['mta_p2p_client_init'], modules['mta_client_proc'])
            self.boot = before.boot
            argv = _argv(self.deployment, '--execute-client-init', str(float(ttl)))
            self.file_owner = _ReadOwner(self.io, self.clock, self._now() + 10)
            binary = self.file_owner.read_file(pm.python_exe, MAX_BINARY, pm.python_sha, binary=True, retain=True)[1]
            self.spawn_ticket = {'creator': self.io.popen, 'argv': argv, 'binary': binary, 'returned': None, 'unknown': True}
            value = self.io.popen(argv, binary['fd']); self.process = value; self.spawn_ticket['returned'] = value
            if type(value) is not self.io.process_type or not _uint(value.pid, 1, 0x7fffffff): _fail('spawn_unknown')
            for index, name in enumerate(('stdin', 'stdout', 'stderr')):
                pipe = getattr(value, name, None)
                row = {'pipe': pipe, 'fd': None, 'metadata': None, 'unknown': True, 'attempted': False, 'closed': False}
                self.pipes.append(row)
                if not callable(getattr(pipe, 'fileno', None)) or not callable(getattr(pipe, 'close', None)): _fail('pipe_unknown')
                row['fd'] = pipe.fileno()
                if not _uint(row['fd'], 0, 0x7fffffff) or row['fd'] == binary['fd'] or any(
                        r is not row and r['fd'] == row['fd'] for r in self.pipes): _fail('pipe_unknown')
                row['metadata'] = _meta(self.io.fstat(row['fd']))
                if not stat.S_ISFIFO(row['metadata'][2]): _fail('pipe_unknown')
                row['unknown'] = False
            self.spawn_ticket['unknown'] = False
            observed = _observe(self, modules['mta_client_proc'], 'read_actor', value.pid)
            actor = _actor(observed, modules['mta_p2p_client_init'], modules['mta_client_proc'], True)
            expected = hashlib.sha256(b''.join(v.encode('ascii') + b'\0' for v in argv)).hexdigest()
            if observed.boot != self.boot or actor.exe != pm.python_exe or actor.argv_sha != expected: _fail('actor_unknown')
            self.actor, self.pending, self.reason = actor, True, 'not_started'
        except BaseException as error:
            self.failures.append(error); self.pending, self.reason = True, 'spawn_unknown'
        return self.status()

    def _pipe_valid(self, row):
        if row['unknown'] or row['closed'] or row['attempted'] or row['pipe'].fileno() != row['fd'] or \
                _meta(self.io.fstat(row['fd'])) != row['metadata']: _fail('pipe_unknown')

    @_serialized
    def poll(self):
        if self.closed: return self.status()
        if self.process is None or self.spawn_ticket is None or self.spawn_ticket['unknown']: _fail('spawn_unknown')
        try:
            for index in (1, 2):
                if self.eof[index]: continue
                row = self.pipes[index]; self._pipe_valid(row)
                if not self.io.ready((row['fd'],), 0): continue
                data = self.io.read(row['fd'], 2049); self.raw.append((index, data))
                if type(data) is not bytes or len(data) > 2049 or sum(len(d) for unused, d in self.raw) > MAX_RAW: _fail('frame_invalid')
                if data == b'':
                    self.eof[index] = True
                    if index == 1 and self.buffers[index]: _fail('frame_invalid')
                    continue
                if index == 2: continue  # stderr is private evidence, never success
                self.buffers[index] += data
                while b'\n' in self.buffers[index]:
                    line, self.buffers[index] = self.buffers[index].split(b'\n', 1)
                    if not line.startswith(PREFIX) or len(line) > 2048 or len(self.frames) >= 2: _fail('frame_invalid')
                    value = self.deployment.modules['p011_json'].loads(line[len(PREFIX):].decode('ascii'))
                    sample = _public()
                    if type(value) is not dict or set(value) != set(sample) or value['reason'] not in _REASONS or any(
                            type(value[k]) is not bool for k in sample if k != 'reason') or any(value[k] for k in (
                            'send_available', 'receive_available', 'association_verified', 'ip_ready', 'phone_tested')):
                        _fail('frame_invalid')
                    if value['done'] and (value['reason'] != 'restored' or value['resource_pending'] or value['client_init_ready']):
                        _fail('frame_invalid')
                    self.frames.append(value)
                if len(self.buffers[index]) > 2048: _fail('frame_invalid')
        except BaseException as error:
            self.failures.append(error); self.pending, self.reason = True, 'frame_invalid'
        return self.status()

    @_serialized
    def cancel(self):
        if self.closed: return self.status()
        if self.cancelled: return self.status()
        self.cancelled = True
        try:
            if self.process is None or not self.pipes or self.spawn_ticket['unknown']: _fail('spawn_unknown')
            self._pipe_valid(self.pipes[0])
            if self.io.write(self.pipes[0]['fd'], CANCEL) != len(CANCEL): _fail('control_invalid')
        except BaseException as error:
            self.failures.append(error); self.pending, self.reason = True, 'pipe_unknown'
        return self.status()

    def _close_pipe(self, row):
        if row['attempted'] or row['closed']: return row['closed'] and not row['unknown']
        if row['unknown']: return False
        row['attempted'] = True
        try:
            if row['pipe'].fileno() != row['fd'] or _meta(self.io.fstat(row['fd'])) != row['metadata']: _fail('pipe_unknown')
            result = row['pipe'].close()
            # Popen owns Python file wrappers, not sockets. Their exact known
            # close contract raises ValueError from fileno after closed=True.
            if row['pipe'].closed is not True: _fail('close_unknown')
            try: row['pipe'].fileno()
            except ValueError: pass
            else: _fail('close_unknown')
            try: self.io.fstat(row['fd'])
            except OSError as error: row['closed'] = result is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: pass
        return row['closed']

    @_serialized
    def finish(self, timeout=25):
        if not _finite(timeout, 0.1, 90): _fail('invalid_input')
        if self.wait_attempted or self.reaped or self.closed: _fail('already_attempted')
        self.wait_attempted = True
        if self.process is None or self.spawn_ticket is None or self.spawn_ticket['unknown'] or self.actor is None:
            self.pending, self.reason = True, 'wait_unknown'; return self.status()
        end = self._now() + timeout
        try:
            # EOF asks the same F to restore. No signal or terminate fallback.
            if not self._close_pipe(self.pipes[0]): _fail('close_unknown')
            while True:
                remaining = end - self._now()
                if remaining <= 0: _fail('deadline')
                self.poll()  # drain both pipes while F is alive; never wait on full stderr
                if self.failures: _fail('frame_invalid')
                quantum = min(.05, remaining)
                try: code = self.process.wait(timeout=quantum)
                except subprocess.TimeoutExpired:
                    # Exact Popen wait timeout is known no-return, not an
                    # unknown creator/IO result. One finish deadline only.
                    self.io.ready(tuple(r['fd'] for r in self.pipes[1:] if not r['closed']), quantum)
                    continue
                break
            if type(code) is not int or not -255 <= code <= 255: _fail('wait_unknown')
            self.exit_code, self.reaped = code, True
            observed = _observe(self, self.deployment.modules['mta_client_proc'],
                                'read_absence', self.actor, self.boot)
            proc = self.deployment.modules['mta_client_proc']
            if (type(observed) is not proc.ProcObservation or observed.kind != 'absence' or observed.boot != self.boot or
                    observed.same_boot is not True or observed.passes != 2 or type(observed.passes) is not int or
                    observed.pid_path_absent is not True or observed.remaining_tasks != () or observed.resource_pending is not False or
                    observed.file_count != observed.closed_count): _fail('exit_unknown')
            self.absent = True
            while not all(self.eof.values()):
                remaining = end - self._now()
                if remaining <= 0: _fail('deadline')
                self.poll()
                if self.failures: _fail('frame_invalid')
                if not all(self.eof.values()): self.io.ready(tuple(self.pipes[i]['fd'] for i in (1, 2)
                    if not self.eof[i]), min(.05, remaining))
        except BaseException as error:
            self.failures.append(error); self.pending, self.reason = True, 'exit_unknown' if self.reaped else 'wait_unknown'
        finally:
            if self.reaped and self.absent:
                pipe_ok = True
                for row in self.pipes: pipe_ok = self._close_pipe(row) and pipe_ok
                file_ok = self.file_owner.close() if self.file_owner is not None else False
                reader_ok = all(r['returned'] and _reader_closed(r['reader']) for r in self.reader_rows)
                self.closed = pipe_ok and file_ok and reader_ok
        final = self.frames[-1] if self.frames else None
        good = self.reaped and self.absent and self.closed and not self.failures and self.exit_code == 0 and \
            final is not None and final['done'] is True and not final['resource_pending'] and not self.buffers[1] and \
            any(frame['client_init_ready'] is True for frame in self.frames) and all(self.eof.values())
        self.pending = not good; self.reason = 'restored' if good else 'child_pending'
        return self.status()

    @_serialized
    def status(self):
        value = _public(self.reason, self.attempted, False, self.reaped and self.absent and self.closed and not self.pending,
                        self.pending, self.cancelled)
        value.update({'parent_waited': self.reaped, 'parent_absence_verified': self.absent,
                      'parent_resources_closed': self.closed, 'frame_count': len(self.frames),
                      'stdout_eof_observed': self.eof[1], 'stderr_eof_observed': self.eof[2]})
        return value


def main(argv=None):
    """No default deployment. Fixed private entry is explicit, never STARTed."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print('{"reason":"source_only","done":false,"send_available":false,"receive_available":false}')
        return 0
    if type(args) not in (list, tuple) or len(args) != 7 or args[0] not in ('--execute-client-init', '--watchdog') or \
            args[1] != '--run-token' or args[3] != '--manifest-sha256' or args[5] != '--ttl': return 2
    try:
        if type(args[6]) is not str or re.fullmatch(r'([1-9]|1[0-9]|20)(\.[0-9]{1,6})?', args[6]) is None: _fail('invalid_input')
        ttl = float(args[6])
        if not _finite(ttl, .1, 20): _fail('invalid_input')
        loader = DeploymentLoader(args[2], args[4]); _ENTRY_OWNERS.append(loader)
        deployment = loader.load()
        if args[0] == '--watchdog': return watchdog(deployment, ttl, _ttl_text=args[6])
        def emit(value):
            data = deployment.modules['p011_json'].dumps(value, sort_keys=True)
            sys.stdout.write(PREFIX.decode('ascii') + data + '\n'); sys.stdout.flush()
        owner = ClientExecutor(deployment, _emit=emit, _ttl_text=args[6]); _ENTRY_OWNERS.append(owner)
        result = owner.run(ttl)
        return 0 if owner.init_ready and result['done'] and not result['resource_pending'] and not owner.failures else 1
    except BaseException:
        print('MTA_CLIENT_F {"reason":"unavailable","attempted":false,"client_init_ready":false,"done":false,"resource_pending":true,"cancel_requested":false,"send_available":false,"receive_available":false,"association_verified":false,"ip_ready":false,"phone_tested":false}')
        return 1


if __name__ == '__main__': sys.exit(main())
