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
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-client-rfinit'
RECEIVE_ROOT = '/mnt/data/p011-toolbox/user/Received'
JSON_SHA = 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'
MODULES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias', 'mta_p2p_client_init',
    'mta_client_resource_budget', 'mta_client_proc',
    'mta_client_caps', 'mta_client_caps_transport', 'mta_client_baseline',
    'mta_client_journal_codec', 'mta_client_coordination', 'mta_client_files',
    'mta_client_pending', 'mta_client_store', 'mta_client_process_owner',
    'mta_client_launch_registration', 'mta_client_two_phase_lease',
    'mta_p2p_client_ctrl', 'mta_client_wpa_status', 'mta_protocol',
    'mta_client_control_frame', 'mta_client_kernel_proof', 'mta_client_connection',
    'mta_client_linux_provider',
    'mta_client_executor', 'mta_dhcp', 'mta_dhcp_client_core', 'mta_dhcp_client',
    'mta_client_dora', 'mta_client_dynamic_ip', 'mta_client_peer',
    'mta_scoped_sockets', 'mta_storage', 'mta_transport', 'mta_client_transfer')
CONNECT_CODEC_SHA = '3cf4a9106389d9865ff77fed9f46c534288ce20df6841909b21eaa15f5bf1434'
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


# Diagnostics are stderr-only; never a parent success frame or authority.
_DIAG_GROUPS = frozenset(('none', 'not_recorded', 'other', 'executor', 'core',
    'provider', 'store', 'proc', 'coord', 'files', 'pending', 'launch', 'owner',
    'alias', 'baseline', 'caps', 'status', 'os', 'interrupt'))
_DIAG_RESULTS = frozenset(('not_recorded', 'returned', 'raised', 'passed', 'rejected'))
_DIAG_START_SITES = frozenset(('not_recorded', 'budget_executor', 'acquire',
    'initial_admission', 'initial_snapshot', 'prior_clear', 'initial_caps',
    'original_actors', 'active_executor', 'active_admission', 'active_deadline',
    'save_prepared', 'watchdog_role', 'baseline_after_watchdog', 'active_caps',
    'register_interface', 'save_interface_intent', 'fresh_interface_intent',
    'create_client', 'save_interface_owned', 'baseline_after_interface',
    'controller_role', 'baseline_after_controller', 'origin_up', 'live_actors',
    'status', 'baseline_after_status', 'save_ready', 'active_return', 'complete',
    'validate', 'self_actor', 'entry_identity', 'inherited_elf', 'assembly',
    'assembly_type', 'start', 'active_loop'))
_DIAG_RESTORE_SITES = frozenset(('not_recorded', 'restore', 'budget',
    'sealed_status', 'bridge_required', 'recovery_budget', 'known_locks',
    'executor', 'executor_role', 'self_actor', 'acquire', 'current',
    'current_admission', 'save_cleanup_intent', 'baseline_before_children',
    'bridge_cleanup', 'baseline_after_children', 'owned_identity',
    'origin_ready_delete', 'origin_absent', 'baseline_after_delete',
    'close_resources', 'close_proof', 'restore_reader', 'baseline_terminal',
    'save_cleanup_verified', 'finish_receipt', 'complete'))
_DIAG_COMPLETE_SITES = frozenset(('not_recorded', 'receipt_type', 'receipt_store',
    'receipt_issued', 'receipt_complete', 'normal_restored', 'terminal_durable',
    'marker_absent', 'clear_verified', 'resources_closed', 'receipt_no_pending',
    'lease_complete', 'lease_no_pending', 'finish_auth', 'bridge_closed',
    'provider_closed', 'close_proof_type', 'close_proof_count', 'close_proof_complete',
    'finish_deadline',
    'owner_status', 'owner_count_type', 'owner_no_unknown', 'inherited_present',
    'inherited_closed', 'inherited_known', 'inherited_ebadf', 'proc_closed', 'complete'))

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
    if mode not in ('--execute-client-init', '--watchdog') or type(ttl_text) is not str:
        _fail('invalid_input')
    if mode == '--execute-client-init':
        if re.fullmatch(r'300(\.0)?', ttl_text) is None: _fail('invalid_input')
        option = '--ttl'
    else:
        if re.fullmatch(r'[0-9]{1,12}(\.[0-9]{1,12})?', ttl_text) is None or \
                not _finite(float(ttl_text), 0, 1e12): _fail('invalid_input')
        option = '--until'
    pm = deployment.manifest
    return (pm.python_exe, '-B', pm.executor_path, mode, '--run-token', pm.run_token,
            '--manifest-sha256', deployment.manifest_sha, option, ttl_text)


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
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, data): return os.write(fd, data)
    def fstat(self, fd): return os.fstat(fd)
    def close(self, fd): return os.close(fd)
    def ready(self, fds, seconds): return select.select(fds, (), (), seconds)[0]
    def ready_write(self, fd, seconds): return select.select((), (fd,), (), seconds)[1]
    def pipe_buf(self, fd): return os.fpathconf(fd, 'PC_PIPE_BUF')
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
        alias = None
        if path == ROOT or path.startswith(ROOT + '/') or path == PHYSICAL_ROOT or path.startswith(PHYSICAL_ROOT + '/'):
            alias = self._fixed_tmp_alias()
            if alias is not None:
                values.append(('fixed_tmp_alias', alias))
                if path == ROOT or path.startswith(ROOT + '/'):
                    path = PHYSICAL_ROOT + path[len(ROOT):]
            elif path == PHYSICAL_ROOT or path.startswith(PHYSICAL_ROOT + '/'):
                _fail('source_invalid')
        for index in range(len(path.split('/')) - 1):
            name = '/' if index == 0 else '/' + '/'.join(path.split('/')[1:index + 1])
            self.check(); value = _meta(self.io.stat(name))
            physical_temporary = alias is not None and name in ('/var/volatile', '/var/volatile/tmp')
            if not stat.S_ISDIR(value[2]) or value[3] != 0 or value[2] & 0o022 and name != '/tmp' and not physical_temporary:
                _fail('source_invalid')
            if private and (name == ROOT or name.startswith(ROOT + '/') or
                    name == PHYSICAL_ROOT or name.startswith(PHYSICAL_ROOT + '/')) and \
                    (stat.S_IMODE(value[2]) != 0o700 or value[3:5] != (0, 0)): _fail('source_invalid')
            alias_directory = alias is not None and name in ('/', '/var', '/var/volatile', '/var/volatile/tmp')
            values.append((name, value[:5] if alias_directory else value[:6]))
        return tuple(values)

    def _fixed_tmp_alias(self):
        # Bootstrap cannot import the pinned common module before reading it.
        # Metadata/readlink only: no extra FD, fallback or generic link walk.
        def observed(name):
            self.check(); value = self.io.stat(name); row = _meta(value)
            if stat.S_ISLNK(row[2]):
                times = tuple(getattr(value, key, None) for key in ('st_mtime_ns', 'st_ctime_ns'))
                if any(not _uint(v) for v in times): _fail('source_invalid')
                return row + times
            return row
        first = observed('/tmp')
        if stat.S_ISDIR(first[2]): return None
        paths = ('/', '/tmp', '/var', '/var/tmp', '/var/volatile', '/var/volatile/tmp')
        modes = (None, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755,
            stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o1777, stat.S_IFDIR | 0o1777)
        before = []
        for name, mode in zip(paths, modes):
            row = observed(name)
            if row[3:5] != (0, 0) or mode is None and (not stat.S_ISDIR(row[2]) or row[2] & 0o022) or \
                    mode is not None and row[2] != mode or stat.S_ISLNK(row[2]) and row[5] != 1:
                _fail('source_invalid')
            if stat.S_ISDIR(row[2]) and row[5] < 1: _fail('source_invalid')
            before.append((name, row if stat.S_ISLNK(row[2]) else row[:5]))
        links = (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp'))
        for name, target in links:
            self.check()
            actual = self.io.readlink(name)
            if type(actual) is not str or actual != target or dict(before)[name][6] != len(target): _fail('source_invalid')
        for name, row in before:
            self.check()
            current = observed(name)
            if (current if stat.S_ISLNK(current[2]) else current[:5]) != row: _fail('source_changed')
        for name, target in links:
            self.check()
            actual = self.io.readlink(name)
            if type(actual) is not str or actual != target: _fail('source_changed')
        if first != before[1][1]: _fail('source_changed')
        return tuple(before)

    def read_file(self, path, limit, expected=None, private=False, binary=False, retain=False):
        self.check()
        # JSON bootstrap + deployment + every fixed source + Python/WPA ELF.
        # A source-read bound is not a network/cleanup credit quota.
        if len(self.rows) >= len(MODULES) + 4: _fail('resource_unknown')
        private_anchor = private or path.startswith(ROOT + '/') or path.startswith(PHYSICAL_ROOT + '/')
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
            paired = PHYSICAL_ROOT + path[len(ROOT):] if path.startswith(ROOT + '/') else \
                ROOT + path[len(PHYSICAL_ROOT):] if path.startswith(PHYSICAL_ROOT + '/') else None
            # Same authenticated alias must reach this exact opened entry.
            if paired is not None and stat.S_ISLNK(_meta(self.io.stat('/tmp'))[2]) and \
                    _meta(self.io.stat(paired)) != metadata: _fail('source_changed')
            # Actual canonical system Python has two hard links; private inputs stay nlink1.
            if (not stat.S_ISREG(metadata[2]) or metadata[3] != 0 or
                    metadata[5] != 1 and not (binary and not private_anchor and path == '/usr/bin/python3.5' and metadata[3:5] == (0, 0) and metadata[5] == 2) or
                    metadata[2] & 0o022 or private_anchor and not binary and stat.S_IMODE(metadata[2]) != 0o400 or
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
            if paired is not None and stat.S_ISLNK(_meta(self.io.stat('/tmp'))[2]) and \
                    _meta(self.io.stat(paired)) != metadata: _fail('source_changed')
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


def _receive_directory(io, clock, until):
    """Existing fixed user area only; no mkdir, alias traversal or UI path."""
    rows = []
    for name in ('/', '/mnt', '/mnt/data', '/mnt/data/p011-toolbox',
                 '/mnt/data/p011-toolbox/user', RECEIVE_ROOT):
        now = clock()
        if not _finite(now, 0, 1e12) or now >= until: _fail('deadline')
        row = _meta(io.stat(name))
        if not stat.S_ISDIR(row[2]) or row[3:5] != (0, 0) or row[2] & 0o022:
            _fail('source_invalid')
        if name in ('/mnt/data/p011-toolbox/user', RECEIVE_ROOT) and stat.S_IMODE(row[2]) != 0o700:
            _fail('source_invalid')
        # Child result directories deliberately change nlink/size, not identity.
        rows.append((name, row[:5]))
    return tuple(rows)


class LoadedDeployment(object):
    def __init__(self, loader, modules, manifest, manifest_sha, run, connect_binding=None,
                 receive_root=None, receive_metadata=None):
        self.loader, self.modules, self.manifest = loader, modules, manifest
        self.manifest_sha, self.run = manifest_sha, run
        self.connect_binding = connect_binding
        self.receive_root, self.receive_metadata = receive_root, receive_metadata
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
        self._connect_binding = self._connect_metadata = self._connect_wire = None

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
            if type(tree) is not dict or set(tree) != {'version', 'provider', 'sources', 'connect_binding', 'receive_root'} or \
                    type(tree['version']) is not int or tree['version'] != 3 or type(tree['sources']) is not list or \
                    type(tree['receive_root']) is not str or tree['receive_root'] != RECEIVE_ROOT:
                _fail('manifest_invalid')
            rows = tree['sources']
            if len(rows) != len(MODULES) or any(type(r) is not list or len(r) != 2 or
                    r[0] != name or not _sha(r[1]) for r, name in zip(rows, MODULES)) or rows[0][1] != JSON_SHA:
                _fail('manifest_invalid')
            source = {}
            for name, pin in rows:
                source[name] = self.owner.read_file(self.run + '/runtime/' + name + '.py', MAX_SOURCE, pin, True)[0]
            # Retain the exact running F module. Executing the verified file a
            # second time would produce foreign ClientExecutor identities.
            running = sys.modules.get(__name__)
            if (type(running) is not types.ModuleType or running.__dict__ is not globals() or
                    running.ClientExecutor is not ClientExecutor or running.DeploymentLoader is not DeploymentLoader):
                _fail('source_invalid')
            self.modules['mta_client_executor'] = running
            original = builtins.__import__
            def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name in MODULES:
                    if level or name not in self.modules: _fail('source_invalid')
                    return self.modules[name]
                if level or name.startswith(('mta_', 'p011_')): _fail('source_invalid')
                return original(name, globals, locals, fromlist, level)
            for name in MODULES:
                # Executor is already running in this process. It is still
                # hashed above; neither its position nor a last-row shortcut
                # may suppress the DHCP modules which follow it.
                if name in ('p011_json', 'mta_client_executor'): continue
                module = types.ModuleType(name); module.__file__ = self.run + '/runtime/' + name + '.py'
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                self.modules[name] = module  # retain before code/constructors
                exec(source[name], module.__dict__)
            if dict(rows)['mta_client_control_frame'] != CONNECT_CODEC_SHA: _fail('manifest_invalid')
            pm = self.modules['mta_client_linux_provider'].ProviderManifest(tree['provider'], _manifest_sha256=self.expected)
            self._connect_metadata = tree['connect_binding']
            binding = self.modules['mta_client_control_frame'].ControlBinding(self._connect_metadata)
            self._connect_binding, self._connect_wire = binding, binding._wire
            if binding.private_metadata()['run_token'] != pm.run_token or \
                    binding.private_metadata()['candidate_sha'] != pm.candidate_sha: _fail('manifest_invalid')
            if pm.run_token != self.token or pm.executor_path != self.run + '/runtime/mta_client_executor.py' or \
                    pm.executor_sha != dict(rows)['mta_client_executor'] or pm.wpa_exe != PHYSICAL_ROOT + '/client-' + self.token + '/native/mta-wpa-supplicant':
                _fail('manifest_invalid')
            self.owner.read_file(pm.python_exe, MAX_BINARY, pm.python_sha, binary=True)
            self.owner.read_file(pm.wpa_exe, MAX_BINARY, pm.wpa_sha, binary=True,
                                 private=False)
            receive_metadata = _receive_directory(self.io, self.owner.check, self.owner.deadline)
            self.value = LoadedDeployment(self, self.modules, pm, self.expected, self.run, binding,
                tree['receive_root'], receive_metadata)
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
        if value.connect_binding is not self._connect_binding or \
                _binding_for(value)._wire != self._connect_wire or \
                self.modules['mta_client_control_frame'].ControlBinding(self._connect_metadata)._wire != self._connect_wire:
            _fail('manifest_invalid')
        if value.receive_root != RECEIVE_ROOT or type(value.receive_metadata) is not tuple:
            _fail('manifest_invalid')
        return None


def _binding_for(deployment):
    codec = deployment.modules['mta_client_control_frame']
    value = deployment.connect_binding
    if type(value) is not codec.ControlBinding: _fail('manifest_invalid')
    fields = value.private_metadata()
    if fields['run_token'] != deployment.manifest.run_token or \
            fields['candidate_sha'] != deployment.manifest.candidate_sha: _fail('manifest_invalid')
    # Copy through the pinned validator; immutable original remains retained.
    if codec.ControlBinding(fields)._wire != value._wire: _fail('manifest_invalid')
    return value


def _actor(observation, core, proc, single=False):
    if (type(observation) is not proc.ProcObservation or observation.kind != 'live_actor' or
            type(observation.actor) is not core.Actor or not observation.actor.live() or
            observation.same_boot is not True or observation.passes != 2 or type(observation.passes) is not int or
            observation.resource_pending is not False or observation.closed_count != observation.file_count or
            type(observation.file_count) is not int or observation.file_count < 1 or
            single and len(observation.actor.tasks) != 1): _fail('actor_unknown')
    return observation.actor


def _reader_closed(reader, proc):
    """Original issuer's retained close facts; never probe a reused FD number."""
    return (type(reader) is proc.ProcReader and reader.history_closed() is True)


def _pure_proc_store(owner):
    """Separate process-local accounting only: no acquire, marker or RF call."""
    modules, pm = owner.deployment.modules, owner.deployment.manifest
    creator = modules['mta_client_store'].DurableClientInitStore
    ticket = {'creator': creator, 'returned': None, 'unknown': True}
    owner.proc_store_ticket = ticket
    store = creator(pm.run_token, pm.identity, _clock=owner.clock)
    ticket['returned'] = store  # retain before post-construction validation
    if type(store) is not creator or store._attempted or store._opened or store._unknown:
        _fail('assembly_unknown')
    owner.proc_store = store
    owner.proc_budget = store._resource_budget_v23
    ticket['unknown'] = False
    return store


def _observe(owner, proc, kind, *args):
    if len(owner.reader_rows) >= 4: _fail('resource_unknown')
    modules, store = owner.deployment.modules, owner.proc_store
    budget, deadline = owner.proc_budget, owner._proc_deadline
    if (proc is not modules['mta_client_proc'] or
            kind not in ('read_self', 'read_actor', 'read_absence') or
            type(store) is not modules['mta_client_store'].DurableClientInitStore or
            type(budget) is not modules['mta_client_resource_budget'].ResourceBudget or
            store._resource_budget_v23 is not budget or budget._store is not store or
            budget._mutex is not store._mutex or budget._epoch is not store._epoch or
            not _finite(deadline, 0, 1e12) or deadline >= 1e12): _fail('resource_unknown')
    creator = proc.ProcReader
    row = {'reader': None, 'creator': creator, 'budget': budget, 'deadline': deadline,
        'call': None, 'result': None, 'returned': False}
    owner.reader_rows.append(row)  # before constructor/call, including exceptions
    reader = creator(timeout=3, _clock=owner.clock, _fs=owner._proc_fs)
    row['reader'] = reader; owner.reader = reader
    if type(reader) is not creator: _fail('resource_unknown')
    budget.bind_reader(reader)  # original exact Store/RLock/epoch, before first IO
    row['call'] = getattr(reader, kind)
    value = row['call'](*args, _absolute_deadline=deadline)
    row['result'], row['returned'] = value, True
    owner.observations.append(value)
    if not _reader_closed(reader, proc): _fail('resource_unknown')
    return value


class _ProcEntry(object):
    """Watchdog's retained local ledger, not another network/restoration owner."""
    def __init__(self, deployment, clock, deadline, fs):
        self.deployment, self.clock, self._proc_deadline = deployment, clock, deadline
        self._proc_fs = fs
        self.proc_store = self.proc_budget = self.proc_store_ticket = self.reader = None
        self.reader_rows, self.observations = [], []


def _serialized(method):
    def invoke(self, *args, **kwargs):
        with self._mutex: return method(self, *args, **kwargs)
    return invoke


class _StdinControl(object):
    """Borrow original stdin; secret bytes stay only in the private decoder."""
    def __init__(self, io, codec, binding):
        if type(binding) is not codec.ControlBinding: _fail('control_invalid')
        self.io, self.codec, self.binding = io, codec, binding
        self.decoder = codec.ControlFrameDecoder(binding)
        self.raw, self.cancelled, self.reason = [], False, None
        self.metadata = _meta(io.fstat(0))
        if not stat.S_ISFIFO(self.metadata[2]): _fail('control_invalid')

    def poll(self):
        if self.cancelled: return True
        # Drain currently readable input before claiming CONNECT: queued CANCEL
        # or EOF wins. The frozen decoder bounds total bytes and duplicate nonce.
        calls = 0
        while True:
            if _meta(self.io.fstat(0))[:6] != self.metadata[:6]: _fail('control_invalid')
            if not self.io.ready((0,), 0): break
            calls += 1
            if calls > self.codec.MAX_TOTAL + 1: _fail('control_invalid')
            raw = self.io.read(0, self.codec.MAX_FRAME)
            if type(raw) is not bytes or len(raw) > self.codec.MAX_FRAME: _fail('control_invalid')
            if _meta(self.io.fstat(0))[:6] != self.metadata[:6]: _fail('control_invalid')
            try:
                state = self.decoder.feed(raw, eof=not raw)
            except BaseException:
                self.decoder.cancel()
                self.cancelled, self.reason = True, 'control_invalid'
                raise
            self.cancelled = state['cancel_requested']
            self.reason = ('eof' if state['reason'] == 'eof' else
                           'cancelled' if self.cancelled else None)
            if self.cancelled: return True
        return False

    def take_connect(self):
        if self.poll(): return None
        return self.decoder.take_connect()


class ClientExecutor(object):
    """Run existing assembly in this F; no synthetic fallback or orphan janitor."""
    def __init__(self, deployment=None, _io=None, _clock=None, _input=None, _emit=None,
                 _ttl_text=None, _environ=None, _proc_fs=None):
        if deployment is not None and type(deployment) is not LoadedDeployment: _fail('invalid_input')
        self.deployment, self.io, self.clock = deployment, _io or _LinuxIo(), _clock or time.monotonic
        self.input, self.emit = _input, _emit
        self.ttl_text = _ttl_text
        self.environ = os.environ if _environ is None else _environ
        self.inherited_elf = None
        self.assembly = self.reader = self.finish = self.assembly_ticket = None
        self.proc_store = self.proc_budget = self.proc_store_ticket = None
        self._proc_fs, self._proc_deadline = _proc_fs, None
        self.start_call_started = False
        self.recovery_until = None
        self.reader_rows = []
        self.observations, self.raw, self.failures = [], [], []
        self.attempted = self.pending = self.done = self.cancel_requested = False
        self.reason, self.last = 'not_started', None
        self.init_ready = False
        self._diagnostic_start = self._diagnostic_restore = self._diagnostic_complete = None
        self._diagnostic_start_reason = 'not_recorded'
        self._diagnostic_written = False
        self._complete_site = 'not_recorded'
        self.connect_request = self.connection_ticket = None
        self.dora_ticket = None
        self.ip_ticket = None
        self.peer_ticket = self.receive_ticket = None
        self.receive_prompt = self.receive_request = self.receive_decision = self.receive_result = None
        self.receive_outcome = 'not_started'
        self.receive_failure_original, self.receive_terminal_failures = None, []
        self.receive_events, self.output_metadata = [], None
        self._rx_counts, self._rx_last_counts, self._rx_last_times = {}, {}, {}
        self._rx_terminal = False
        self.connect_attempted = False
        self._connect_stop_reason = None
        self._stop_worker_v32 = threading.current_thread()
        self._stop_input_v32, self._stop_input_facts_v32 = None, None

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
        if self.connect_attempted and self._connect_stop_reason is not None: value = True
        if self.connect_attempted and not value and self.assembly is not None:
            record = self.assembly[4].record
            if record is None or self._now() >= record.deadline:
                value, self._connect_stop_reason = True, 'expired'
            else:
                # A stop notification is not a fresh phase/RF/Proc proof.
                # All original phase gates stay independent of this poll.
                linux = self.deployment.modules['mta_client_linux_provider']
                notice = linux.LinuxClientInitProvider.poll_executor_stop_v32(
                    self.assembly[0], self, record.deadline)
                if type(notice) is not bool: _fail('control_invalid')
                if notice: value, self._connect_stop_reason = True, 'watchdog'
        self.cancel_requested = value
        if value and self.assembly is not None: self.assembly[0].request_stop()
        return value

    def _run_private_dora(self):
        """Original DHCP grant and durable applied address; no guessed endpoint."""
        if self.dora_ticket is not None: _fail('already_attempted')
        modules = self.deployment.modules
        provider, unused, unused_owner, unused_bridge, lease = self.assembly
        receipt = provider._active_association_receipt
        creator = lease.create_private_dora
        ticket = {'creator': creator, 'receipt': receipt, 'returned': None,
            'runner': None, 'allocation': None, 'unknown': True}
        self.dora_ticket = ticket  # before creator, callbacks and first socket
        if type(receipt) is not modules['mta_client_connection'].AssociationReceipt:
            _fail('control_invalid')
        value = creator(receipt)
        ticket['returned'] = value
        if type(value) is not modules['mta_client_dora'].PrivateClientDora or value.lease is not lease:
            _fail('assembly_unknown')
        ticket['runner'] = value.run_sync
        allocation = ticket['runner'](_checkpoint=self._cancelled)
        ticket['allocation'] = allocation
        if allocation is None:
            if not self._cancelled(): _fail('control_invalid')
        elif type(allocation) is not modules['mta_client_dora'].LiveAllocation or allocation._issuer is not value:
            _fail('control_invalid')
        ticket['unknown'] = False
        if allocation is not None:
            dynamic = modules['mta_client_dynamic_ip']
            ip_ticket = {'creator': dynamic.ClientDynamicIp, 'dora': value,
                'allocation': allocation, 'returned': None, 'result': None, 'unknown': True}
            self.ip_ticket = ip_ticket  # Before constructor/intent or any address IO.
            ip_owner = ip_ticket['creator'](value, allocation, durable_commit=lease.commit_client_ip)
            ip_ticket['returned'] = ip_owner
            if (type(ip_owner) is not dynamic.ClientDynamicIp or
                    ip_owner is not provider._client_ip_owner_v28 or
                    ip_owner.lease is not lease or ip_owner.store is not lease.store): _fail('assembly_unknown')
            ip_ticket['result'] = ip_owner.start()
            result = ip_ticket['result']
            if (type(result) is not dynamic.DynamicIpRecord or result.phase != 'applied' or
                    lease.record.client_ip is None or
                    lease.record.client_ip.key() != result.key()): _fail('assembly_unknown')
            ip_ticket['unknown'] = False

    def _emit_receive(self, kind, payload, until):
        codec, binding = self.deployment.modules['mta_client_control_frame'], self.input.binding
        if self._rx_terminal or len(self.receive_events) >= codec.MAX_RX_EVENTS: _fail('control_invalid')
        frame = codec.encode_receive_event(binding, len(self.receive_events), kind, payload)
        ticket = {'kind': kind, 'wire': frame, 'write_attempted': False,
            'write_result': None, 'sent': False}
        self.receive_events.append(ticket)  # Retain before the actual borrowed-pipe write.
        if self.output_metadata is None:
            self.output_metadata = _meta(self.io.fstat(1))
            if not stat.S_ISFIFO(self.output_metadata[2]) or not _uint(self.io.pipe_buf(1), codec.MAX_RX_FRAME):
                _fail('pipe_unknown')
        while True:
            if self._now() >= until: _fail('deadline')
            if _meta(self.io.fstat(1))[:6] != self.output_metadata[:6]: _fail('pipe_unknown')
            actual = self.receive_ticket['returned'] if self.receive_ticket is not None else None
            if actual is not None and actual._running:
                if actual._cancelled(): _fail('cancelled')
            elif self.input.poll() or self.assembly[0].cancelled.is_set(): _fail('cancelled')
            remaining = until - self._now()
            if remaining <= 0: _fail('deadline')
            if self.io.ready_write(1, min(.05, remaining)): break
        # Each <=PIPE_BUF frame has one writer and one write; short/late output
        # is unknown, never retried or counted as a user decision.
        ticket['write_attempted'] = True
        ticket['write_result'] = self.io.write(1, frame)
        if type(ticket['write_result']) is not int or ticket['write_result'] != len(frame) or \
                self._now() >= until or _meta(self.io.fstat(1))[:6] != self.output_metadata[:6]:
            _fail('control_invalid')
        ticket['sent'] = True
        if kind == 'result': self._rx_terminal = True

    def _confirm_receive(self, request, original_until, cancelled):
        modules = self.deployment.modules
        codec = modules['mta_client_control_frame']
        owner = self.receive_ticket['returned']
        if (type(owner) is not modules['mta_client_transfer'].ClientTransferOwner or
                owner.executor is not self or owner.input is not self.input or
                original_until != owner.deadline or type(original_until) not in (int, float) or
                getattr(cancelled, '__self__', None) is not owner or
                getattr(cancelled, '__func__', None) is not modules['mta_client_transfer'].ClientTransferOwner._cancelled or
                self.receive_prompt is not None): _fail('control_invalid')
        checked = modules['mta_protocol'].validate_send_request(request)
        if type(request) is not dict or request != checked: _fail('control_invalid')
        self.receive_request = request  # Original Transport request before user interaction.
        until = min(original_until, self._now() + 30)
        self.receive_prompt = self.input.decoder.expect_receive(request, until)
        self._emit_receive('prompt', self.receive_prompt.private_data(), until)
        while True:
            # Actual lightweight stdin/watchdog/Event poll, not a cached bool or
            # full Proc traversal on every wait/chunk. It can only stop work.
            if cancelled(): self.receive_outcome = 'cancelled'; return False
            if self._now() >= until:
                self.receive_outcome = 'confirmation_timeout'; return False
            decision = self.input.decoder.take_receive_decision()
            if decision is not None:
                self.receive_decision = decision
                if (type(decision) is not codec.ReceiveDecision or decision._decoder is not self.input.decoder or
                        decision is not self.input.decoder._claimed_receive_decision or
                        decision.prompt is not self.receive_prompt or type(decision.accepted) is not bool):
                    _fail('control_invalid')
                if cancelled() or self._now() >= until:
                    self.receive_outcome = 'cancelled'; return False
                self.receive_outcome = 'accepted' if decision.accepted else 'refused'
                return decision.accepted
            remaining = until - self._now()
            if remaining <= 0:
                self.receive_outcome = 'confirmation_timeout'; return False
            self.io.ready((0,), min(.05, remaining))

    def _receive_progress(self, stage, count, total):
        codec = self.deployment.modules['mta_client_control_frame']
        if (self.receive_request is None or self.receive_outcome != 'accepted' or
                not _uint(count, 0, 513 * 1024 * 1024) or not _uint(total, 0, 513 * 1024 * 1024) or
                stage == 'files' and (total != self.receive_request['totalSize'] or count > total) or
                stage == 'download' and count > self.receive_request['totalSize'] + 1024 * 1024 or
                count < self._rx_counts.get(stage, 0)): _fail('control_invalid')
        self._rx_counts[stage] = count
        # Reserve the final result slot. Counts originate from native archive
        # download and CRC-checked extraction callbacks, not a UI timer.
        if len(self.receive_events) >= codec.MAX_RX_EVENTS - 1: return
        now = self._now()
        if (stage in self._rx_last_times and now - self._rx_last_times[stage] < .25 and
                count - self._rx_last_counts.get(stage, 0) < 262144 and count != total): return
        self._rx_last_times[stage], self._rx_last_counts[stage] = now, count
        self._emit_receive('progress', {'task_id': self.receive_request['taskId'],
            'stage': stage, 'count': count, 'total': total}, self.receive_ticket['returned'].deadline)

    def _receive_terminal(self, outcome, until):
        result = self.receive_result if outcome == 'committed' else None
        payload = {'outcome': outcome, 'task_id': self.receive_request['taskId'] if self.receive_request else '',
            'file_count': result['fileCount'] if result else 0, 'total_size': result['totalSize'] if result else 0,
            'peer_ack_verified': result['peer_ack_verified'] if result else False}
        self._emit_receive('result', payload, until)

    def _run_native_receive(self):
        """Single original worker; actual native endpoint and actual bytes only."""
        if self.peer_ticket is not None or self.receive_ticket is not None: _fail('already_attempted')
        modules = self.deployment.modules
        provider, store, unused, unused_bridge, lease = self.assembly
        ip_owner = self.ip_ticket['returned'] if self.ip_ticket is not None else None
        if self.ip_ticket is None or self.ip_ticket['unknown'] or \
                type(ip_owner) is not modules['mta_client_dynamic_ip'].ClientDynamicIp: _fail('assembly_unknown')
        creator = modules['mta_client_peer'].ClientPeerReader
        ticket = {'creator': creator, 'returned': None, 'result': None, 'unknown': True}
        self.peer_ticket = ticket
        native_peer = creator(ip_owner); ticket['returned'] = native_peer
        if type(native_peer) is not creator or provider._client_peer_owner_v29 is not native_peer:
            _fail('assembly_unknown')
        ticket['result'] = native_peer.read()
        if ticket['result'] is not None and type(ticket['result']) is not modules['mta_client_peer'].NeighborRecord:
            _fail('assembly_unknown')
        if native_peer.unknown or not all(a and c for a, c in native_peer.closed_facts()): _fail('resource_unknown')
        ticket['unknown'] = False
        if ticket['result'] is None:
            self.receive_outcome = 'unavailable'
            self._receive_terminal('unavailable', min(lease.record.deadline, ip_owner.handoff._until))
            return
        until = min(lease.record.deadline, ip_owner.handoff._until)
        if _receive_directory(self.io, self._now, until) != self.deployment.receive_metadata:
            _fail('source_changed')
        receiver_type = modules['mta_storage'].SafeZipReceiver
        owner_type = modules['mta_client_transfer'].ClientTransferOwner
        self.receive_ticket = {'receiver_creator': receiver_type, 'receiver': None,
            'creator': owner_type, 'returned': None, 'result': None, 'unknown': True}
        receiver = receiver_type(self.deployment.receive_root)
        self.receive_ticket['receiver'] = receiver
        if type(receiver) is not receiver_type or receiver.root != RECEIVE_ROOT: _fail('assembly_unknown')
        if _receive_directory(self.io, self._now, until) != self.deployment.receive_metadata:
            _fail('source_changed')
        owner = owner_type(native_peer, receiver, _executor=self)
        self.receive_ticket['returned'] = owner
        if type(owner) is not owner_type or provider._client_transfer_owner_v30 is not owner:
            _fail('assembly_unknown')
        self.receive_ticket['unknown'] = False
        try:
            result = owner.run(self._confirm_receive,
                lambda count: self._receive_progress('download', count, 0),
                lambda count, total: self._receive_progress('files', count, total))
            self.receive_ticket['result'] = self.receive_result = result
            if (type(result) is not dict or self.receive_request is None or
                    result.get('taskId') != self.receive_request['taskId'] or
                    type(result.get('peer_ack_verified')) is not bool or
                    result.get('fileCount') != self.receive_request['fileCount'] or
                    result.get('totalSize') != self.receive_request['totalSize']): _fail('control_invalid')
            self.receive_outcome = 'committed'
            self._receive_terminal('committed', until)
        except BaseException as failure:
            # Preserve the actual receive failure before trying diagnostic
            # output. A cancelled/unknown borrowed pipe may reject that output;
            # it cannot replace the original failure or become successful work.
            self.receive_failure_original = failure
            if (self.receive_outcome in ('refused', 'confirmation_timeout') and
                    type(failure) is modules['mta_transport'].Cancelled and self._now() < until):
                terminal_failed = False
                try: self._receive_terminal(self.receive_outcome, until)
                except BaseException as terminal_failure:
                    self.receive_terminal_failures.append(terminal_failure)
                    terminal_failed = True
                if terminal_failed: raise
                return
            self.receive_outcome = 'cancelled' if self.cancel_requested else 'failed'
            # Preserve original failure and original resource inventories. A
            # result frame is diagnostic/user state, never cleanup proof.
            if not self._rx_terminal and self._now() < until and not self.input.cancelled:
                try: self._receive_terminal(self.receive_outcome, until)
                except BaseException as terminal_failure:
                    self.receive_terminal_failures.append(terminal_failure)
            raise

    def _close_inherited_elf(self):
        # Parent exclusively issues this inherited copy. It is not an arbitrary
        # environment FD claim: exact opened/hashed Python metadata must match
        # the Loader's original source record after actual F argv authentication.
        text = self.environ.get('P011_CLIENT_EXECUTABLE_FD')
        row = {'fd': text, 'metadata': None, 'attempted': False, 'closed': False,
            'unknown': True, 'close_returned': False, 'close_result': None,
            'ebadf_error': None}
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
        row['close_returned'], row['close_result'] = True, result
        try: self.io.fstat(row['fd'])
        except OSError as error:
            row['ebadf_error'] = error
            row['closed'] = result is None and type(error.errno) is int and error.errno == errno.EBADF
        if not row['closed']: _fail('close_unknown')

    def _diagnostic_error(self, error):
        try:
            if type(error) is ExecutorError:
                return ('executor', error.code if type(error.code) is str and error.code in _REASONS else 'not_recorded')
            module = self.deployment.modules['mta_client_linux_provider']
            return module._diagnostic_error(error)
        except BaseException: return ('other', 'not_recorded')

    def _diagnostic_sample(self, source, sites, fallback, error=None):
        # Only fixed symbols survive. No repr/str, exception args or identifiers.
        try:
            module = self.deployment.modules['mta_client_linux_provider']
            groups = module._DIAGNOSTIC_GROUP_CODES
            core = self.deployment.modules['mta_p2p_client_init']
            result = {'site': fallback, 'stage': 'not_recorded', 'error_group': 'not_recorded',
                'error_code': 'not_recorded', 'result': 'not_recorded'}
            if type(source) is dict and set(source) == set(result):
                if type(source['site']) is str and source['site'] in sites: result['site'] = source['site']
                if type(source['stage']) is str and source['stage'] in core._STAGES | {'none', 'not_recorded', 'other'}:
                    result['stage'] = source['stage']
                if type(source['result']) is str and source['result'] in _DIAG_RESULTS:
                    result['result'] = source['result']
                group, code = source['error_group'], source['error_code']
                if (type(group) is str and group in _DIAG_GROUPS and type(code) is str and
                        code in (_REASONS | {'not_recorded'} if group == 'executor' else groups.get(group, ()))):
                    result['error_group'], result['error_code'] = group, code
            if error is not None:
                group, code = self._diagnostic_error(error)
                if (type(group) is str and group in _DIAG_GROUPS and type(code) is str and
                        code in (_REASONS | {'not_recorded'} if group == 'executor' else groups.get(group, ()))):
                    result['error_group'], result['error_code'] = group, code
                result['result'] = 'raised'
            return result
        except BaseException: return None

    def _freeze_start(self, site, error=None):
        try:
            if self._diagnostic_start is not None: return
            self._diagnostic_start_reason = self.reason if type(self.reason) is str and self.reason in _REASONS else 'not_recorded'
            source = (getattr(self.assembly[4], '_diagnostic_start', None) if
                self.assembly_ticket is not None and self.assembly_ticket['unknown'] is False else None)
            if source is not None:
                phase_reason = getattr(self.assembly[4], 'reason', None)
                codes = self.deployment.modules['mta_p2p_client_init']._CODES
                if type(phase_reason) is str and phase_reason in codes | {'not_recorded'}:
                    self._diagnostic_start_reason = phase_reason
            self._diagnostic_start = self._diagnostic_sample(source, _DIAG_START_SITES, site, error)
            if self._diagnostic_start is not None and error is None and source is None:
                self._diagnostic_start['result'] = 'returned'
        except BaseException: pass

    def _freeze_restore(self, error=None):
        try:
            source = getattr(self.assembly[4], '_diagnostic_restore', None)
            self._diagnostic_restore = self._diagnostic_sample(source, _DIAG_RESTORE_SITES, 'restore', error)
            if self._diagnostic_restore is not None and error is None and source is None:
                self._diagnostic_restore['result'] = 'returned'
        except BaseException: pass

    def _freeze_complete(self, error=None):
        try:
            source = {'site': self._complete_site, 'stage': 'not_recorded', 'error_group': 'none',
                'error_code': 'not_recorded', 'result': 'passed' if self.done else 'rejected'}
            self._diagnostic_complete = self._diagnostic_sample(source, _DIAG_COMPLETE_SITES,
                self._complete_site, error)
        except BaseException: pass

    def _write_diagnostics(self):
        # One existing stderr write after restore; no retry or new resource.
        try:
            if self._diagnostic_written: return
            self._diagnostic_written = True
            data = b''
            for event, sample in (('start', self._diagnostic_start), ('restore', self._diagnostic_restore),
                                  ('complete', self._diagnostic_complete)):
                if sample is None: continue
                line = ('MTA_CLIENT_DIAG event=' + event + ''.join(' ' + key + '=' + sample[key]
                    for key in ('site', 'stage', 'error_group', 'error_code', 'result')) +
                    (' reason=' + self._diagnostic_start_reason if event == 'start' else '') + '\n').encode('ascii')
                if len(line) > 384: return
                data += line
            line = ('MTA_CLIENT_DIAG event=final done=' + ('1' if self.done else '0') +
                ' pending=' + ('1' if self.pending else '0') + ' reason=' +
                (self.reason if type(self.reason) is str and self.reason in _REASONS else 'not_recorded') + '\n').encode('ascii')
            if len(line) > 384 or len(data + line) > 1536: return
            self.io.write(2, data + line)
        except BaseException: pass

    def _complete(self):
        provider, store, owner, bridge, lease = self.assembly
        self.finish = lease.finish_receipt  # preserve before any readback
        core = self.deployment.modules['mta_p2p_client_init']
        receipt = self.finish
        self._complete_site = 'receipt_type'
        if type(receipt) is not core.FinishReceipt: return False
        self._complete_site = 'receipt_store'
        if receipt.store is not store: return False
        self._complete_site = 'receipt_issued'
        if receipt is not store._finish_receipt: return False
        self._complete_site = 'receipt_complete'
        if receipt.complete is not True: return False
        self._complete_site = 'normal_restored'
        if receipt.normal_restored is not True: return False
        self._complete_site = 'terminal_durable'
        if receipt.terminal_durable is not True: return False
        self._complete_site = 'marker_absent'
        if receipt.marker_state != 'absent_observed': return False
        self._complete_site = 'clear_verified'
        if receipt.clear_durability != 'verified': return False
        self._complete_site = 'resources_closed'
        if receipt.resources_closed is not True: return False
        self._complete_site = 'receipt_no_pending'
        if receipt.resource_pending is not False: return False
        self._complete_site = 'lease_complete'
        if lease.cleanup_complete is not True: return False
        self._complete_site = 'lease_no_pending'
        if lease.pending is not False: return False
        self._complete_site = 'finish_auth'
        if not _finite(self.recovery_until, 0, 1e12) or self._now() >= self.recovery_until: return False
        if store.authenticate_finish(receipt.locks, receipt.request_record, receipt, self.recovery_until) is not True: return False
        self._complete_site = 'bridge_closed'
        if bridge.verify_closed(_absolute_deadline=self.recovery_until) is not True: return False
        self._complete_site = 'provider_closed'
        # Provider accepts a local IO slice (<=20), not the independent total
        # recovery scope. This quantum remains beneath the original total;
        # no new overall recovery deadline or network permission is issued.
        closed = provider.closed_resources(tuple(lease.handles.values()),
            min(self.recovery_until, self._now() + 3))
        self.raw.append(closed)
        self._complete_site = 'close_proof_type'
        if type(closed) is not core.CloseProof: return False
        self._complete_site = 'close_proof_count'
        if closed.expected < len(lease.handles): return False
        self._complete_site = 'close_proof_complete'
        if not closed.complete(): return False
        self._complete_site = 'owner_status'
        unknown_count = owner.status()['unknown_count']
        self._complete_site = 'owner_count_type'
        if type(unknown_count) is not int: return False
        self._complete_site = 'owner_no_unknown'
        if unknown_count != 0: return False
        self._complete_site = 'inherited_present'
        if self.inherited_elf is None: return False
        self._complete_site = 'inherited_closed'
        if not self.inherited_elf['closed']: return False
        self._complete_site = 'inherited_known'
        if self.inherited_elf['unknown']: return False
        self._complete_site = 'inherited_ebadf'
        row = self.inherited_elf
        error = row['ebadf_error']
        if (not row['attempted'] or not row['close_returned'] or row['close_result'] is not None or
                not isinstance(error, OSError) or type(error.errno) is not int or error.errno != errno.EBADF):
            return False
        self._complete_site = 'proc_closed'
        proc = self.deployment.modules['mta_client_proc']
        result = all(r['returned'] and r['budget'] is self.proc_budget and
            r['creator'] is proc.ProcReader and _reader_closed(r['reader'], proc) for r in self.reader_rows)
        if not result: return False
        # Passive status/history traversal can still consume the original
        # recovery window. Recheck before issuing success; never renew it.
        self._complete_site = 'finish_deadline'
        if self._now() >= self.recovery_until: return False
        self._complete_site = 'complete'
        return True

    def run(self, ttl=300):
        if type(ttl) not in (int, float) or ttl != 300: _fail('invalid_input')
        if self.attempted: _fail('already_attempted')
        self.attempted = True
        if self.deployment is None: self.reason = 'unavailable'; return self._publish()
        self.deployment.loader.authenticate(self.deployment)
        modules = self.deployment.modules
        core, proc = modules['mta_p2p_client_init'], modules['mta_client_proc']
        site = 'validate'
        try:
            self.io.validate()
            self._proc_deadline = self._now() + 10
            # assemble is pure. Its original Store must exist before the first
            # ProcReader; it grants neither INIT nor permission to recover.
            binding = _binding_for(self.deployment)
            site = 'assembly'
            creator = modules['mta_client_linux_provider'].assemble
            self.assembly_ticket = {'creator': creator, 'returned': None, 'unknown': True}
            self.assembly = creator(self.deployment.manifest, _connect_binding=binding)
            self.assembly_ticket['returned'] = self.assembly
            site = 'assembly_type'
            if type(self.assembly) is not tuple or len(self.assembly) != 5: _fail('assembly_unknown')
            provider, store, owner, bridge, lease = self.assembly
            if (type(provider) is not modules['mta_client_linux_provider'].LinuxClientInitProvider or
                    type(store) is not modules['mta_client_store'].DurableClientInitStore or
                    type(owner) is not modules['mta_client_process_owner'].DirectChildOwner or
                    type(bridge) is not modules['mta_client_linux_provider'].LinuxDirectChildLaunchBridge or
                    type(lease) is not modules['mta_client_linux_provider'].LinuxClientInitLease or
                    lease.provider is not provider or lease.store is not store or lease.bridge is not bridge or
                    bridge.owner is not owner or bridge.store is not store or
                    provider._store is not store or store._attempted or store._opened): _fail('assembly_unknown')
            self.proc_store, self.proc_budget = store, store._resource_budget_v23
            self.assembly_ticket['unknown'] = False
            site = 'self_actor'
            observed = _observe(self, proc, 'read_self')
            actor = _actor(observed, core, proc, True)
            ttl_text = self.ttl_text if self.ttl_text is not None else str(float(ttl))
            if float(ttl_text) != ttl: _fail('invalid_input')
            site = 'entry_identity'
            _entry_identity(actor, self.deployment, '--execute-client-init', ttl_text)
            site = 'inherited_elf'
            self._close_inherited_elf()
            self.input = self.input if self.input is not None else _StdinControl(
                self.io, modules['mta_client_control_frame'], binding)
            self._stop_input_v32 = self.input
            self._stop_input_facts_v32 = (self.input.decoder, self.input.codec,
                self.input.binding, self.input.io, self.input.metadata)
            site = 'start'
            if self._now() >= self._proc_deadline: _fail('deadline')
            # Record invocation before entering start; an exception after its
            # first mutation still belongs to the original restoration owner.
            self.start_call_started = True
            start = lease.start(ttl=ttl, cancelled=self._cancelled); self.raw.append(start)
            if type(start) is not dict or type(start.get('client_init_ready')) is not bool: _fail('assembly_unknown')
            self.pending = True
            if start['client_init_ready']:
                self.init_ready = True
                self.reason = 'not_started'
                self._freeze_start(site)
                self._publish(True)
                site = 'active_loop'
                while True:
                    if self._cancelled(): self.reason = self.input.reason or 'cancelled'; break
                    notice = provider.poll_requests()
                    if type(notice) is not bool: _fail('assembly_unknown')
                    if notice: self.reason = 'watchdog'; break
                    if lease.record is None or self._now() >= lease.record.deadline: self.reason = 'expired'; break
                    if not self.connect_attempted:
                        request = self.input.take_connect()
                        if request is not None:
                            self.connect_request = request  # original before validation/producer
                            codec = modules['mta_client_control_frame']
                            if type(request) is not codec.ConnectRequest or request.binding is not binding:
                                _fail('control_invalid')
                            self.connect_attempted = True
                            creator = lease.connect_p2p
                            self.connection_ticket = {'request': request, 'creator': creator,
                                'binding': binding, 'operation_epoch': None, 'returned': None, 'unknown': True}
                            if self._cancelled():
                                self.reason = self._connect_stop_reason or self.input.reason or 'cancelled'; break
                            epoch = binding.private_metadata()['operation_epoch']
                            self.connection_ticket['operation_epoch'] = epoch
                            result = creator(request, _checkpoint=self._cancelled)
                            self.connection_ticket['returned'] = result
                            if type(result) is not modules['mta_client_connection'].ConnectionObservation:
                                _fail('control_invalid')
                            self.connection_ticket['unknown'] = False
                            self.observations.append(result)  # private only, never stdout/raw projection
                            if self._cancelled():
                                self.reason = self._connect_stop_reason or self.input.reason or 'cancelled'; break
                            if self._now() >= lease.record.deadline: self.reason = 'expired'; break
                            self._run_private_dora()
                            if self._cancelled():
                                self.reason = self._connect_stop_reason or self.input.reason or 'cancelled'; break
                            if self.ip_ticket is not None and not self.ip_ticket['unknown']:
                                self._run_native_receive()
                            # Exactly one receive task per original session.
                            # Success/refusal/unavailable all enter original restore.
                            self.reason = 'cancelled' if self.cancel_requested else 'not_started'
                            break
                    remaining = lease.record.deadline - self._now()
                    if remaining <= 0: self.reason = 'expired'; break
                    self.io.ready((0,), min(.05, remaining))
            else:
                self.reason = 'start_failed'
                self._freeze_start(site)
        except BaseException as error:
            self.failures.append(error)
            self.reason = error.code if type(error) is ExecutorError else 'io_error' if isinstance(error, Exception) else 'interrupted'
            self.pending = self.start_call_started or self.assembly_ticket is not None and self.assembly_ticket['unknown'] or \
                any(not r['returned'] or not _reader_closed(r['reader'], proc) for r in self.reader_rows) or \
                self.inherited_elf is None or not self.inherited_elf['closed']
        finally:
            self._freeze_start(site, self.failures[-1] if self.failures else None)
            if self.start_call_started and self.assembly_ticket is not None and not self.assembly_ticket['unknown']:
                try:
                    self.recovery_until = self._now() + 60
                    restored = self.assembly[4].restore(timeout=60,
                        _absolute_deadline=self.recovery_until); self.raw.append(restored)
                    self._freeze_restore()
                    self.done = self._complete()
                    self._freeze_complete()
                    self.pending = not self.done
                    self.reason = 'restored' if self.done else 'restore_pending'
                except BaseException as error:
                    if self._complete_site == 'not_recorded':
                        self._freeze_restore(error)
                    else:
                        self._freeze_complete(error)
                    self.failures.append(error); self.pending, self.done, self.reason = True, False, 'restore_pending'
        self._write_diagnostics()
        return self._publish()

    def status(self, ready=False):
        return _public(self.reason, self.attempted, ready and not self.done, self.done, self.pending, self.cancel_requested)


def watchdog(deployment, until, _io=None, _clock=None, _environ=None, _until_text=None, _proc_fs=None):
    """Notify only; pure local accounting Store, never acquire/WPA/restore."""
    if type(deployment) is not LoadedDeployment or not _finite(until, 0, 1e12): _fail('invalid_input')
    deployment.loader.authenticate(deployment)
    io, clock, env = _io or _LinuxIo(), _clock or time.monotonic, os.environ if _environ is None else _environ
    io.validate()
    before = clock()
    if not _finite(before, 0, 1e12): _fail('invalid_clock')
    if not 0 < until - before <= 300: _fail('invalid_input')
    deadline, last = float(until), before  # Original issued cap, never now+TTL.
    entry = _ProcEntry(deployment, clock, min(deadline, before + 10), _proc_fs)
    _ENTRY_OWNERS.append(entry)  # before constructor and original inventory IO
    _pure_proc_store(entry)
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
    observation = _observe(entry, proc, 'read_self')
    reader = entry.reader
    actor = _actor(observation, core, proc, True)
    until_text = _until_text if _until_text is not None else str(float(until))
    if float(until_text) != until: _fail('invalid_input')
    _entry_identity(actor, deployment, '--watchdog', until_text)
    while True:
        now = clock()
        if not _finite(now, 0, 1e12) or now < last: _fail('invalid_clock')
        last = now
        if now >= deadline: break
        io.ready((), min(.05, deadline - now))
    if _meta(io.fstat(numbers[0])) != device or _meta(io.fstat(numbers[1])) != notify: _fail('source_changed')
    if not _reader_closed(reader, proc): _fail('resource_unknown')
    if io.write(numbers[1], b'R') != 1: _fail('control_invalid')
    return 0


class ParentExecutor(object):
    """Fixed Popen only, suitable for a future multithreaded State caller.

    No preexec_fn, os.fork, signal/kill, retry or fake external finalizer. The
    original Popen, stdin/stdout/stderr and binary FD survive unknown outcomes.
    """
    def __init__(self, deployment=None, _io=None, _clock=None, _handoff=None,
                 _handoff_type=None, _handoff_codec=None, _proc_fs=None):
        if deployment is not None and type(deployment) is not LoadedDeployment: _fail('invalid_input')
        if ((_handoff is None) != (_handoff_type is None) or
                (_handoff is None) != (_handoff_codec is None) or _handoff is not None and
                (type(_handoff_type) is not type or type(_handoff) is not _handoff_type or
                 _handoff.worker is not threading.current_thread() or
                 type(_handoff_codec) is not types.ModuleType or
                 _handoff_codec.protocol is not _handoff.claim_frame.__func__.__globals__.get('protocol'))):
            _fail('invalid_input')
        self.deployment, self.io, self.clock = deployment, _io or _LinuxIo(), _clock or time.monotonic
        self.process = self.spawn_ticket = self.reader = self.file_owner = None
        self.proc_store = self.proc_budget = self.proc_store_ticket = None
        self._proc_fs, self._proc_deadline = _proc_fs, None
        self.reader_rows, self._mutex = [], threading.RLock()
        self.pipes, self.raw, self.frames, self.observations, self.failures = [], [], [], [], []
        self.attempted = self.pending = self.reaped = self.absent = self.closed = self.cancelled = False
        self.reason, self.exit_code, self.actor, self.boot = 'not_started', None, None, None
        self.last, self.buffers = None, {1: b'', 2: b''}
        self.wait_attempted = False
        self.eof = {1: False, 2: False}
        # Trusted State factory seam only; neither type nor binding signs consent.
        self._connect_handoff, self._connect_type = _handoff, _handoff_type
        self._connect_worker = threading.current_thread() if _handoff is not None else None
        self._connect_state = _handoff.state if _handoff is not None else None
        self._connect_operation = _handoff.operation if _handoff is not None else None
        self._connect_claim = _handoff.claim_frame if _handoff is not None else None
        self._connect_check = _handoff._check if _handoff is not None else None
        self._connect_codec = _handoff_codec
        self._connect_protocol = _handoff_codec.protocol if _handoff_codec is not None else None
        self._connect_binding_type = _handoff_codec.ControlBinding if _handoff_codec is not None else None
        self._connect_encoder = _handoff_codec.encode_connect if _handoff_codec is not None else None
        self.connect_attempted = False
        self.connect_ticket = None
        self.receive_events, self.receive_prompt, self.receive_reply_ticket = [], None, None
        self.receive_result = None
        self.receive_counts = {'download': 0, 'files': 0}
        self.receive_state = 'not_started'

    def _now(self):
        now = self.clock()
        if not _finite(now, 0, 1e12) or self.last is not None and now < self.last: _fail('invalid_clock')
        self.last = float(now); return float(now)

    @_serialized
    def start(self, ttl=300):
        if self.attempted: _fail('already_attempted')
        if type(ttl) not in (int, float) or ttl != 300: _fail('invalid_input')
        self.attempted = True
        if self.deployment is None: self.reason = 'unavailable'; return self.status()
        self.deployment.loader.authenticate(self.deployment); self.io.validate()
        modules, pm = self.deployment.modules, self.deployment.manifest
        try:
            self._proc_deadline = self._now() + 10
            _pure_proc_store(self)
            before = _observe(self, modules['mta_client_proc'], 'read_self')
            _actor(before, modules['mta_p2p_client_init'], modules['mta_client_proc'])
            self.boot = before.boot
            argv = _argv(self.deployment, '--execute-client-init', str(float(ttl)))
            self.file_owner = _ReadOwner(self.io, self.clock, self._proc_deadline)
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
                    codec = self.deployment.modules['mta_client_control_frame']
                    if line.startswith(codec.RX_PREFIX):
                        self._receive_event(line + b'\n')
                        continue
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

    def _receive_event(self, wire):
        """Private IPC facts only; never F restoration or parent wait proof."""
        codec, binding = self.deployment.modules['mta_client_control_frame'], _binding_for(self.deployment)
        if (self.connect_ticket is None or self.connect_ticket['unknown'] or
                not self.connect_ticket['sent'] or self.receive_result is not None or
                len(self.receive_events) >= codec.MAX_RX_EVENTS): _fail('frame_invalid')
        event = codec.decode_receive_event(binding, wire)
        if event['sequence'] != len(self.receive_events): _fail('frame_invalid')
        payload, kind = event['payload'], event['kind']
        if kind == 'prompt':
            if self.receive_prompt is not None or self.receive_events: _fail('frame_invalid')
            prompt = codec.ReceivePrompt(binding, payload)
            if prompt.until > self._now() + 30: _fail('frame_invalid')
            self.receive_prompt = prompt
            self.receive_state = 'awaiting_confirmation'
        elif kind == 'progress':
            prompt, ticket = self.receive_prompt, self.receive_reply_ticket
            if (prompt is None or ticket is None or ticket['unknown'] or not ticket['sent'] or
                    ticket['accepted'] is not True or payload['task_id'] != prompt.task_id or
                    payload['count'] < self.receive_counts[payload['stage']] or
                    payload['stage'] == 'files' and payload['total'] != prompt.total_size or
                    payload['stage'] == 'download' and
                        (payload['total'] != 0 or payload['count'] > prompt.total_size + 1024 * 1024)):
                _fail('frame_invalid')
            self.receive_counts[payload['stage']] = payload['count']
            self.receive_state = 'receiving'
        elif kind == 'result':
            prompt = self.receive_prompt
            if prompt is None:
                if event['sequence'] != 0 or payload['outcome'] != 'unavailable' or payload['task_id'] != '':
                    _fail('frame_invalid')
            elif payload['task_id'] != prompt.task_id: _fail('frame_invalid')
            if payload['outcome'] == 'committed':
                ticket = self.receive_reply_ticket
                if (prompt is None or ticket is None or ticket['unknown'] or not ticket['sent'] or
                        ticket['accepted'] is not True or payload['file_count'] != prompt.file_count or
                        payload['total_size'] != prompt.total_size): _fail('frame_invalid')
            if payload['outcome'] == 'refused':
                ticket = self.receive_reply_ticket
                if ticket is None or ticket['unknown'] or not ticket['sent'] or ticket['accepted'] is not False:
                    _fail('frame_invalid')
            self.receive_result = dict(payload)
            self.receive_state = payload['outcome']
        self.receive_events.append({'wire': wire, 'value': event})

    @_serialized
    def answer_receive(self, exact_prompt, accepted):
        """One file-consent reply on the original worker/pipe; no RF grant."""
        codec = self.deployment.modules['mta_client_control_frame']
        if (type(exact_prompt) is not codec.ReceivePrompt or exact_prompt is not self.receive_prompt or
                type(accepted) is not bool or self.receive_reply_ticket is not None or
                self.receive_result is not None or self.receive_state != 'awaiting_confirmation' or
                self.failures or self.closed or self.cancelled or self.wait_attempted or
                self.connect_ticket is None or self.connect_ticket['unknown'] or not self.connect_ticket['sent'] or
                threading.current_thread() is not self._connect_worker or self._now() >= exact_prompt.until):
            _fail('control_invalid')
        self.deployment.loader.authenticate(self.deployment)
        binding = _binding_for(self.deployment)
        if exact_prompt.binding is not binding: _fail('control_invalid')
        self._pipe_valid(self.pipes[0])
        ticket = {'prompt': exact_prompt, 'accepted': accepted, 'frame': None,
            'write_attempted': False, 'write_return': None, 'sent': False, 'unknown': True}
        self.receive_reply_ticket = ticket  # Before encoder or original write.
        try:
            frame = codec.encode_receive_decision(binding, exact_prompt, accepted)
            ticket['frame'] = frame
            self._pipe_valid(self.pipes[0])
            if self._now() >= exact_prompt.until: _fail('deadline')
            ticket['write_attempted'] = True
            ticket['write_return'] = self.io.write(self.pipes[0]['fd'], frame)
            if type(ticket['write_return']) is not int or ticket['write_return'] != len(frame): _fail('control_invalid')
            self._pipe_valid(self.pipes[0])
            if self._now() >= exact_prompt.until: _fail('deadline')
            ticket['sent'], ticket['unknown'] = True, False
            self.receive_state = 'accepted' if accepted else 'refused_pending'
        except BaseException as error:
            self.failures.append(error); self.pending, self.reason = True, 'control_invalid'
        return self.receive_status()

    @_serialized
    def receive_status(self):
        """Local UI data, including private display names; do not public-archive."""
        value = {'state': self.receive_state, 'prompt': self.receive_prompt,
            'download_bytes': self.receive_counts['download'], 'verified_file_bytes': self.receive_counts['files'],
            'result': dict(self.receive_result) if self.receive_result is not None else None}
        # The exact prompt object must be returned to answer_receive. A copied
        # JSON/display payload cannot claim a current user-confirmation slot.
        return value

    def _handoff_current(self, handoff):
        if (handoff is None or handoff is not self._connect_handoff or
                type(handoff) is not self._connect_type or
                threading.current_thread() is not self._connect_worker or
                handoff.worker is not self._connect_worker or
                handoff.state is not self._connect_state or
                handoff.operation is not self._connect_operation or
                self._connect_codec.protocol is not self._connect_protocol or
                self._connect_codec.ControlBinding is not self._connect_binding_type or
                self._connect_codec.encode_connect is not self._connect_encoder or
                self._connect_claim.__func__.__globals__.get('protocol') is not self._connect_protocol):
            _fail('control_invalid')
        for current, original in ((handoff.claim_frame, self._connect_claim),
                                  (handoff._check, self._connect_check)):
            if (getattr(current, '__self__', None) is not handoff or
                    getattr(current, '__func__', None) is not getattr(original, '__func__', None)):
                _fail('control_invalid')
        # Handoff performs actual Operation/Session/helper/crypto/cancel checks.
        # Its registration is private, not a process-level security boundary.
        self._connect_check()

    @_serialized
    def send_connect(self, exact_handoff):
        """Once, from the registered actual worker; no arbitrary plaintext API."""
        if self.connect_attempted: _fail('already_attempted')
        if (self.failures or self.closed or self.cancelled or self.wait_attempted or self.process is None or
                self.spawn_ticket is None or self.spawn_ticket['unknown'] or self.actor is None or
                not self.frames or self.frames[-1]['client_init_ready'] is not True or self.frames[-1]['done']):
            _fail('control_invalid')
        if self._connect_handoff is None: _fail('unavailable')
        self.deployment.loader.authenticate(self.deployment)
        binding = _binding_for(self.deployment)
        codec = self.deployment.modules['mta_client_control_frame']
        with self._connect_state.lock:
            self._handoff_current(exact_handoff)
            self._pipe_valid(self.pipes[0])
            self.connect_attempted = True
            ticket = {'handoff': exact_handoff, 'worker': self._connect_worker,
                'claim': self._connect_claim, 'frame': None, 'binding': None,
                'decoder': None, 'request': None, 'write_attempted': False,
                'write_return': None, 'sent': False, 'unknown': True}
            self.connect_ticket = ticket  # before claim and all subsequent calls
            try:
                metadata = binding.private_metadata()
                frame = self._connect_claim(self._connect_codec, metadata['run_token'],
                    metadata['candidate_sha'], metadata['operation_id'])
                ticket['frame'] = frame  # save return before a second producer read
                ticket['binding'] = exact_handoff.binding
                self._handoff_current(exact_handoff)
                if type(frame) is not bytes or not 1 <= len(frame) <= codec.MAX_FRAME or \
                        type(ticket['binding']) is not self._connect_binding_type or \
                        ticket['binding']._wire != binding._wire: _fail('control_invalid')
                decoder = codec.ControlFrameDecoder(binding); ticket['decoder'] = decoder
                decoder.feed(frame)
                request = decoder.take_connect(); ticket['request'] = request
                if type(request) is not codec.ConnectRequest or request.binding is not binding:
                    _fail('control_invalid')
                self._pipe_valid(self.pipes[0])
                self._handoff_current(exact_handoff)
                ticket['write_attempted'] = True
                count = self.io.write(self.pipes[0]['fd'], frame)
                ticket['write_return'] = count
                if type(count) is not int or count != len(frame): _fail('control_invalid')
                self._pipe_valid(self.pipes[0])
                self._handoff_current(exact_handoff)
                ticket['sent'], ticket['unknown'] = True, False
            except BaseException as error:
                self.failures.append(error)
                self.pending, self.reason = True, 'control_invalid'
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
        self._proc_deadline = end  # same Parent finish scope, not a renewed Proc window
        resources = self.deployment.modules['mta_client_resource_budget']
        with self.proc_store._mutex:
            self.proc_store._resource_lane_v23 = resources.CLEANUP
            self.proc_budget.cancel()
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
                proc = self.deployment.modules['mta_client_proc']
                reader_ok = all(r['returned'] and r['budget'] is self.proc_budget and
                    r['creator'] is proc.ProcReader and _reader_closed(r['reader'], proc) for r in self.reader_rows)
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
            args[1] != '--run-token' or args[3] != '--manifest-sha256' or \
            args[5] != ('--until' if args[0] == '--watchdog' else '--ttl'): return 2
    try:
        pattern = r'[0-9]{1,12}(\.[0-9]{1,12})?' if args[0] == '--watchdog' else r'300(\.0)?'
        if type(args[6]) is not str or re.fullmatch(pattern, args[6]) is None: _fail('invalid_input')
        ttl = float(args[6])
        if not _finite(ttl, 0, 1e12): _fail('invalid_input')
        loader = DeploymentLoader(args[2], args[4]); _ENTRY_OWNERS.append(loader)
        deployment = loader.load()
        if args[0] == '--watchdog': return watchdog(deployment, ttl, _until_text=args[6])
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
