"""SOURCE v72 graph: current GO definitions with isolated typed IP/DHCP;
no old source/manifest/result is overwritten and no execution is claimed.

Fixed native GO source/ELF provenance, SOURCE-only bootstrap sub-slice.

Explicit load reads existing root-owned files only; construction has no IO.
The fixed graph includes planned native GO Store/kernel/bootstrap definitions;
until those are delivered it is deliberately incomplete, not a READY adapter.
Neutral CLIENT definitions supply Actor/Snapshot and process accounting only.
No CLIENT lease, association, caps projection or RF grant is consumed here.
"""
import builtins
import errno
import hashlib
import math
import os
import re
import stat
import struct
import sys
import threading
import time
import types

ROOT = '/var/volatile/tmp/p011-mta-go-session'
PYTHON = '/usr/bin/python3.5'
JSON_SHA = 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
MAX_SOURCE, MAX_BINARY, LOAD_SECONDS = 262144, 67108864, 10.0
MODULES = ('p011_json', 'mta_ip', 'mta_client_tmp_alias',
    'mta_p2p_client_init', 'mta_client_resource_budget', 'mta_client_proc',
    'mta_client_journal_codec', 'mta_client_coordination', 'mta_client_files',
    'mta_client_pending', 'mta_client_store', 'mta_go_process_owner',
    'mta_go_deployment', 'mta_go_executor', 'mta_ip_lease', 'mta_dhcp',
    'mta_go_bootstrap_store', 'mta_go_dhcp', 'mta_go_native', 'mta_go_bootstrap')
# Frozen, reviewed mechanical/accounting dependencies. Newly written GO source
# pins are supplied in the one original manifest, itself pinned by its caller.
# A matching checksum proves bytes, not user consent or permission to use RF.
NEUTRAL_PINS = (
    ('p011_json', JSON_SHA),
    ('mta_ip', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_client_tmp_alias', '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_p2p_client_init', '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b'),
    ('mta_client_resource_budget', '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e'),
    ('mta_client_proc', 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_client_journal_codec', '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    ('mta_client_coordination', '930e56d35ebf08d0b1c83fe7ccab843cbe6520ecd68c0799e9a07b2bbe40823f'),
    ('mta_client_files', '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864'),
    ('mta_client_pending', 'cfba740700268d5998eb3a91bf7cdc34d893fa8f0083377d716ea98950c3f5af'),
    ('mta_client_store', 'f328dcaa95ecfc5288c85a3715ecfdbdbdb8e83c83797b91cde3e334d188f4a2'),
    ('mta_ip_lease', '39373dba355557ee73cfac354bdbaa95eaf0ddde4e27313450edf0e74742f12c'),
    ('mta_dhcp', '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'))
_MANIFEST_KEYS = frozenset(('version', 'run_token', 'candidate_sha', 'task_id',
    'ifname', 'python_sha', 'sources', 'baseline_manifest'))


class GoSourceError(RuntimeError):
    def __init__(self, code):
        self.code = code; RuntimeError.__init__(self, code)


def _fail(code): raise GoSourceError(code) from None
def _hex(value, n): return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % n, value) is not None
def _uint(value): return type(value) is int and 0 <= value <= (1 << 64) - 1
def _time(value):
    if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
        _fail('invalid_clock')
    return float(value)
def canonical_until(text):
    """Same full-precision finite repr(float) contract as frozen CLIENT cap33.

    Text is the original argv binding; no rounded decimal or remaining TTL.
    Scientific notation is accepted only when it is float's exact canonical
    representation, e.g. full precision monotonic deadlines remain unchanged.
    """
    if type(text) is not str or not 1 <= len(text) <= 64: _fail('original_until_invalid')
    try: value = float(text)
    except (ValueError, OverflowError): _fail('original_until_invalid')
    value = _time(value)
    if not 0 < value < 1e12 or repr(value) != text: _fail('original_until_invalid')
    return value
def _meta(value):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns')
    row = tuple(getattr(value, n, None) for n in names)
    if any(not _uint(v) for v in row): _fail('metadata_unknown')
    return row


class _LinuxIo(object):
    def validate(self):
        if sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or \
                os.uname()[4] != 'armv7l' or getattr(os, 'O_NOFOLLOW', None) != 0x8000 or \
                getattr(os, 'O_CLOEXEC', None) != 0x80000:
            _fail('unsupported_platform')
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)


class _SourceRead(object):
    """Strong original file inventory before every native open; once close."""
    def __init__(self, io, clock, until):
        self.io, self.clock, self.until = io, clock, until
        self.rows, self.raw, self.last, self.unknown = [], [], None, False
    def check(self):
        value = _time(self.clock())
        if self.last is not None and value < self.last: _fail('clock_regressed')
        self.last = value
        if value >= self.until: _fail('deadline')
        return value
    def anchors(self, path):
        if type(path) is not str or not path.startswith('/') or \
                any(p in ('', '.', '..') for p in path[1:].split('/')):
            _fail('fixed_path_required')
        rows = []
        for index in range(len(path.split('/')) - 1):
            name = '/' if index == 0 else '/' + '/'.join(path.split('/')[1:index + 1])
            self.check(); metadata = _meta(self.io.stat(name))
            temporary = name in ('/var/volatile', '/var/volatile/tmp')
            if not stat.S_ISDIR(metadata[2]) or metadata[3:5] != (0, 0) or \
                    temporary and stat.S_IMODE(metadata[2]) != 0o1777 or \
                    not temporary and metadata[2] & 0o022 or \
                    (name == ROOT or name.startswith(ROOT + '/')) and stat.S_IMODE(metadata[2]) != 0o700:
                _fail('unsafe_source_directory')
            rows.append((name, metadata[:5]))
        return tuple(rows)
    def aliases(self):
        # The global GO/CLIENT device lock shares this exact physical tmp.
        rows = []
        for path, target in (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp')):
            self.check(); meta = _meta(self.io.stat(path))
            if meta[2] != stat.S_IFLNK | 0o777 or meta[3:6] != (0, 0, 1) or \
                    meta[6] != len(target) or self.io.readlink(path) != target:
                _fail('fixed_tmp_alias_changed')
            rows.append((path, target, meta))
        for path, target, meta in rows:
            self.check()
            if _meta(self.io.stat(path)) != meta or self.io.readlink(path) != target:
                _fail('fixed_tmp_alias_changed')
        return tuple(rows)
    def read_file(self, path, maximum, expected, binary=False):
        self.check()
        if len(self.rows) >= len(MODULES) + 5: _fail('file_inventory_limit')
        anchors, aliases = self.anchors(path), self.aliases()
        row = {'path': path, 'fd': None, 'metadata': None, 'raw': None,
            'returned': False, 'unknown': True, 'close_called': False, 'closed': False}
        self.rows.append(row)
        try:
            try: value = self.io.open(path)
            except OSError:
                row['unknown'], row['closed'] = False, True
                raise
            row['fd'], row['returned'] = value, True
            if type(value) is not int or not 0 <= value <= 0x7fffffff or \
                    any(r is not row and not r['closed'] and r['fd'] == value for r in self.rows):
                _fail('descriptor_unknown')
            before = _meta(self.io.fstat(value)); row['metadata'] = before
            if not stat.S_ISREG(before[2]) or before[3:5] != (0, 0) or before[2] & 0o022 or \
                    before[5] != 1 and not (path == PYTHON and binary and before[5] == 2) or \
                    not 1 <= before[6] <= maximum or \
                    path.startswith(ROOT + '/') and stat.S_IMODE(before[2]) != (0o500 if binary else 0o400) or \
                    binary and not before[2] & 0o111 or _meta(self.io.stat(path)) != before:
                _fail('source_file_invalid')
            row['unknown'] = False
            parts, length = [], 0
            while True:
                self.check(); count = min(65536, maximum + 1 - length)
                chunk = self.io.read(value, count)
                parts.append(chunk)  # Actual malformed/late return remains retained.
                if type(chunk) is not bytes or len(chunk) > count: _fail('source_read_invalid')
                length += len(chunk)
                if length > maximum: _fail('source_too_large')
                if not chunk: break
            raw = b''.join(parts); row['raw'] = raw; self.raw.append((path, raw, before))
            self.check()
            if length != before[6] or _meta(self.io.fstat(value)) != before or \
                    _meta(self.io.stat(path)) != before or self.anchors(path) != anchors or self.aliases() != aliases:
                _fail('source_changed')
            if hashlib.sha256(raw).hexdigest() != expected or binary and not raw.startswith(b'\x7fELF'):
                _fail('source_pin_mismatch')
            if binary and (len(raw) < 52 or raw[:7] != b'\x7fELF\x01\x01\x01' or \
                    struct.unpack_from('<H', raw, 16)[0] not in (2, 3) or \
                    struct.unpack_from('<H', raw, 18)[0] != 40 or \
                    struct.unpack_from('<I', raw, 20)[0] != 1 or \
                    struct.unpack_from('<H', raw, 40)[0] != 52 or \
                    struct.unpack_from('<I', raw, 36)[0] & 0xff000600 != 0x05000400):
                _fail('arm_eabihf_elf_required')
            return raw
        except BaseException:
            if row['unknown']: self.unknown = True
            raise
        finally: self.close_row(row)
    def close_row(self, row):
        if row['closed']: return not row['unknown']
        if row['close_called'] or row['unknown'] or not row['returned']: return False
        row['close_called'] = True
        try:
            if _meta(self.io.fstat(row['fd'])) != row['metadata']: _fail('descriptor_changed')
            result = self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['closed'] = result is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: self.unknown = True
        if not row['closed']: self.unknown = True
        return row['closed']
    def close(self):
        for row in self.rows: self.close_row(row)
        return not self.unknown and all(r['closed'] and not r['unknown'] for r in self.rows)


class GoManifest(object):
    """Pure immutable facts, not ready/permission; paths cannot be chosen by UI."""
    __slots__ = tuple(_MANIFEST_KEYS) + ('run', 'cfg', 'ctrl', 'wpa_exe', 'executor')
    def __init__(self, value, token):
        if type(value) is not dict or set(value) != _MANIFEST_KEYS or \
                type(value['version']) is not int or value['version'] != 1 or \
                value['run_token'] != token or not _hex(token, 32) or not _hex(value['candidate_sha'], 64) or \
                not _hex(value['python_sha'], 64) or type(value['task_id']) is not str or \
                re.fullmatch('[A-Za-z0-9_-]{1,96}', value['task_id']) is None or \
                type(value['ifname']) is not str or re.fullmatch('mta[0-9a-f]{8}', value['ifname']) is None:
            _fail('manifest_invalid')
        rows = value['sources']
        if type(rows) is not list or len(rows) != len(MODULES) or any(
                type(r) is not list or len(r) != 2 or r[0] != name or not _hex(r[1], 64)
                for name, r in zip(MODULES, rows)) or any(dict(rows).get(name) != pin for name, pin in NEUTRAL_PINS):
            _fail('source_graph_invalid')
        pins = value['baseline_manifest']
        if type(pins) is not list or len(pins) != 4 or any(type(r) is not list or len(r) != 2 or
                type(r[0]) is not str or not _hex(r[1], 64) for r in pins): _fail('manifest_invalid')
        run = ROOT + '/go-' + token
        for name in _MANIFEST_KEYS:
            item = tuple(tuple(r) for r in value[name]) if name in ('sources', 'baseline_manifest') else value[name]
            object.__setattr__(self, name, item)
        for name, item in (('run', run), ('cfg', run + '/go.conf'), ('ctrl', run + '/ctrl'),
                ('wpa_exe', run + '/native/mta-wpa-supplicant'), ('executor', run + '/runtime/mta_go_executor.py')):
            object.__setattr__(self, name, item)
    def __setattr__(self, *unused): raise AttributeError('immutable GO source facts')
    def __repr__(self): return '<private fixed GO manifest; not RF permission>'


class LoadedGoDeployment(object):
    __slots__ = ('loader', 'manifest', 'modules', 'source_raw', 'manifest_sha', 'worker', 'specs')
    def __init__(self, loader, manifest, modules, raw, manifest_sha, specs):
        for k, v in (('loader', loader), ('manifest', manifest), ('modules', modules),
                ('source_raw', raw), ('manifest_sha', manifest_sha),
                ('worker', threading.current_thread()), ('specs', specs)):
            object.__setattr__(self, k, v)
    def __setattr__(self, *unused): raise AttributeError('immutable original GO deployment')
    def __repr__(self): return '<private original GO fixed source/ELF readback>'
    @property
    def controller_spec(self): return self.specs[0]
    @property
    def watchdog_spec(self): return self.specs[1]


class GoDeploymentLoader(object):
    def __init__(self, run_token, manifest_sha, original_until, original_until_text,
                 _io=None, _clock=None):
        if not _hex(run_token, 32) or not _hex(manifest_sha, 64): _fail('invalid_source_input')
        self.token, self.expected = run_token, manifest_sha
        self.run, self.io, self.clock = ROOT + '/go-' + run_token, _io or _LinuxIo(), _clock or time.monotonic
        self.owner, self.value, self.failure, self.attempted = None, None, None, False
        self.modules, self.original_modules, self.launcher, self.runtime = {}, None, None, None
        until = canonical_until(original_until_text)
        if until != _time(original_until): _fail('original_until_invalid')
        self.original_until = self._original_until = until
        self.original_until_text = self._original_until_text = original_until_text
        self._specs = ()
        self._runtime_store, self._runtime_device = None, None
        # Clock only, no filesystem/native creator. Reject expiry BEFORE first
        # source IO, not after loading the complete graph and ELF artifacts.
        now = _time(self.clock())
        if not 0 < until - now <= 300: _fail('original_until_invalid')
    def _original_period(self):
        if self.original_until != self._original_until or \
                self.original_until_text is not self._original_until_text or \
                canonical_until(self.original_until_text) != self._original_until:
            _fail('original_period_changed')
        return self._original_until
    def load(self):
        if self.attempted: _fail('load_already_attempted')
        self.attempted = True
        until = self._original_period()
        now = _time(self.clock())
        if not 0 < until - now <= 300: _fail('original_until_invalid')
        self.owner = _SourceRead(self.io, self.clock, min(until, now + LOAD_SECONDS))
        try:
            self.io.validate()
            raw_json = self.owner.read_file(self.run + '/runtime/p011_json.py', MAX_SOURCE, JSON_SHA)
            codec = types.ModuleType('p011_json'); exec(raw_json, codec.__dict__)
            self.modules['p011_json'] = codec
            raw = self.owner.read_file(self.run + '/deployment.json', 65536, self.expected)
            tree = codec.loads(raw.decode('ascii'))
            if type(tree) is not dict or set(tree) != {'schema', 'go'} or tree['schema'] != 'p011-go-typed-live-v72':
                _fail('manifest_invalid')
            manifest = GoManifest(tree['go'], self.token)
            source = {}
            for name, pin in manifest.sources:
                source[name] = self.owner.read_file(self.run + '/runtime/' + name + '.py', MAX_SOURCE, pin)
            own = sys.modules.get(__name__)
            running = sys.modules.get('mta_go_executor')
            if type(own) is not types.ModuleType or own.__dict__ is not globals() or \
                    own.GoDeploymentLoader is not GoDeploymentLoader or type(running) is not types.ModuleType or \
                    running.__file__ != manifest.executor or \
                    running.bootstrap.__globals__ is not running.__dict__ or \
                    running.GoEntrySource.__module__ != running.__name__:
                _fail('wrong_running_f')
            self.modules['mta_go_deployment'], self.modules['mta_go_executor'] = own, running
            original_import = builtins.__import__
            def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name in MODULES:
                    if level or name not in self.modules: _fail('source_import_order')
                    return self.modules[name]
                if level or name.startswith(('mta_', 'p011_')): _fail('unlisted_source_import')
                return original_import(name, globals, locals, fromlist, level)
            for name in MODULES:
                if name in ('p011_json', 'mta_go_deployment', 'mta_go_executor'): continue
                module = types.ModuleType(name); module.__file__ = self.run + '/runtime/' + name + '.py'
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                self.modules[name] = module; exec(source[name], module.__dict__)
            core = self.modules['mta_p2p_client_init']
            pins = manifest.baseline_manifest
            if len(set(p for p, unused in pins)) != 4 or \
                    tuple(sorted(r for r in pins if r[0] != '/usr/sbin/wpa_cli')) != tuple(sorted(core.STOCK_PINS)) or \
                    sum(p == '/usr/sbin/wpa_cli' for p, unused in pins) != 1:
                _fail('stock_manifest_invalid')
            # These native ELF bytes are read/hashed, never executed by load.
            self.owner.read_file(PYTHON, MAX_BINARY, manifest.python_sha, True)
            wpa = self.owner.read_file(manifest.wpa_exe, WPA_BYTES, WPA_SHA, True)
            if len(wpa) != WPA_BYTES: _fail('wpa_size_mismatch')
            self.original_modules = tuple((name, self.modules[name]) for name in MODULES)
            # until is issued by the actual F runtime later, before ANY child IO.
            self.value = LoadedGoDeployment(self, manifest, self.modules, source, self.expected, self._specs)
        except BaseException as error:
            self.failure = error; raise
        finally:
            if self.owner is not None and not self.owner.close() and self.failure is None:
                self.failure = GoSourceError('source_close_unknown')
        if self.failure is not None: _fail('source_load_unknown')
        return self.value
    def authenticate(self, value):
        self._original_period()  # Pure original facts, cleanup remains possible at expiry.
        if type(value) is not LoadedGoDeployment or value is not self.value or value.loader is not self or \
                value.manifest_sha != self.expected or self.failure is not None or self.owner is None or \
                self.owner.unknown or not all(r['closed'] and not r['unknown'] for r in self.owner.rows) or \
                value.modules is not self.modules or set(self.modules) != set(MODULES) or \
                value.worker is not threading.current_thread() or \
                self.original_modules is None or any(self.modules.get(n) is not m for n, m in self.original_modules):
            _fail('foreign_source_deployment')
        if value.specs is not self._specs:
            _fail('original_launch_specs_changed')
        return None
    def bind_runtime(self, value, runtime, original_until, original_until_text):
        self.authenticate(value)
        module = self.modules['mta_go_bootstrap']
        stores = self.modules['mta_go_bootstrap_store']
        if type(runtime) is not module.GoBootstrap or runtime.deployment is not value or self.runtime is not None or \
                type(runtime.store) is not stores.GoBootstrapStore or runtime.store.owner is not runtime or \
                runtime.store.worker is not value.worker or runtime.store.run_token != self.token or \
                runtime.store.candidate_sha != value.manifest.candidate_sha or \
                canonical_until(original_until_text) != _time(original_until) or \
                original_until != self._original_until or original_until_text != self._original_until_text or \
                runtime.store.until != original_until:
            _fail('runtime_source_invalid')
        now = _time(self.clock())
        if not 0 < original_until - now <= 300: _fail('original_until_invalid')
        launch = self.modules['mta_go_process_owner']
        self.runtime, self._runtime_store = runtime, runtime.store
        pm = value.manifest
        controller = launch.LaunchSpec('controller', pm.wpa_exe,
            (pm.wpa_exe, '-Dnl80211', '-i' + pm.ifname, '-c' + pm.cfg, '-q'),
            (('PATH', '/usr/sbin:/usr/bin:/sbin:/bin'), ('LANG', 'C'), ('MTA_PRIVATE_P2P', '1')), WPA_SHA)
        watchdog = launch.LaunchSpec('watchdog', PYTHON,
            (PYTHON, '-B', pm.executor, '--go-watchdog', '--run-token', self.token,
             '--manifest-sha256', self.expected, '--until', original_until_text),
            (('PATH', '/usr/sbin:/usr/bin:/sbin:/bin'), ('LANG', 'C')), pm.python_sha)
        self._specs = (controller, watchdog)
        # This is the same original object issued by this actual loader. Its
        # initially empty specs are filled exactly once, not replaced with an
        # equal caller-created deployment/capability.
        object.__setattr__(value, 'specs', self._specs)
        return self._specs
    def register_launcher(self, value, launcher):
        self.authenticate(value)
        module = self.modules['mta_go_process_owner']
        if type(launcher) is not module.GoDirectChildOwner or launcher.deployment is not value or \
                self.launcher is not None or self.runtime is None or value.specs is not self._specs:
            _fail('launcher_source_invalid')
        self.launcher = launcher
    def authenticate_launch(self, value, launcher, spec, device_fd, deadline):
        self.authenticate(value)
        if launcher is not self.launcher or self.runtime is None or \
                self.runtime.store is not self._runtime_store or value.specs is not self._specs or \
                not any(spec is v for v in self._specs) or deadline != self.original_until:
            _fail('launch_source_invalid')
        # Concrete native Store checks its original device OFD, shared marker,
        # durable child intent and fixed original period. Return is NOT bool.
        receipt = self._runtime_store.launch_source_current(self.runtime, spec.role,
            device_fd, self.original_until)
        stores = self.modules['mta_go_bootstrap_store']
        if type(receipt) is not stores.GoChildIntent or receipt.store is not self._runtime_store or \
                receipt.owner is not self.runtime or receipt.role != spec.role or receipt.device_fd != device_fd:
            _fail('native_launch_intent_missing')
        if self._runtime_device is None: self._runtime_device = self._runtime_store.device
        elif self._runtime_device is not self._runtime_store.device: _fail('original_device_changed')
        return receipt
