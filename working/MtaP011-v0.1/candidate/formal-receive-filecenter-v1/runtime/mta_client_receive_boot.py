"""Fixed held-directory ordinary State definitions boot; SOURCE only, no admission.

The held-directory CLIENT F is canonical; the F37_SHA symbol is its legacy ABI name. Parent97 retains the ordinary
preflight role before Pub90; TerminalParent95 is a separate role before State96.
Both load their own pure definitions privately only on explicit collection.
No private RO observer graph or GO 25-definition F graph is imported here.
The other ordinary roles retain their order/source/path. Bridge93 replaces its
ordinary predecessor. load() starts no State, Server, helper, Parent collection,
file publication, observer staging or RF.

The GO Loader keeps its REAL fixed asset-root __file__, never the State path.
All other ordinary roles keep the independent formal-receive-v3 runtime path. Existing
trusted directories must be staged explicitly; this load cannot repair them.
Pub's bundle seal remains unset, and definitions do not issue send/receive/RF
admission or verified restoration. Original raw, failed modules and read/close
inventories remain retained. No arbitrary in-process tamper guarantee is made.
"""
import builtins
import errno
import hashlib
import math
import os
import re
import stat
import sys
import threading
import time
import types

ROOT = '/tmp/p011-mta-formal-receive-filecenter-v1'
PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-formal-receive-filecenter-v1'
RUNTIME = ROOT + '/runtime'
PHYSICAL_RUNTIME = PHYSICAL_ROOT + '/runtime'
MAX_SOURCE = 2 * 1024 * 1024
LOAD_SECONDS = 10.0
ARM_READ = 0x88000  # P011 O_RDONLY | O_NOFOLLOW(0x8000) | O_CLOEXEC(0x80000).
CLIENT_MANIFEST_SHA = '1ef5b0e3f3693312bfd31853fb1655ebd2613671a67952bea60c948af823d175'
F37_SHA = '2a6b596004f9f34ef46359f3cb82e4742b82025ff537d70296bb5c5dd8b083b5'
SOURCE_SCHEMA = 'sender-state-boot-v98-source'
GO_ASSET_ROOT = '/var/volatile/tmp/p011-mta-go-send-v76-assets'
GO_ASSET_RUNTIME = GO_ASSET_ROOT + '/runtime'

# Immutable ordinary source pins; private F source graphs remain separate.
SOURCE_PINS = (
    ('mta_client_executor', 117754, F37_SHA),
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_storage', 55562, 'ea3d3df1177019125c9b3124b8ebaf33196dd1013db95ac24580e1fe1a96c8d1'),
    ('mta_files', 10987, 'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('mta_crypto', 15274, '6fde6a60ec327895938a59990c4734a923dd5ff68bd5ee6979791df9a607e516'),
    ('mta_transfer_session', 20633, 'e7321ad446318f96bf84b1a94f0e5e3c76b1e973e28826f1c2514527b6967859'),
    ('mta_dhcp', 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
    ('mta_dhcp_server', 20515, 'a34fdbc07a96f2ed3337872612510aa2a8b72b970a193f58b8045c0653b8d8bc'),
    ('mta_scoped_sockets', 26339, 'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8'),
    ('mta_transport', 40223, '171efb7cdfabbe4ea826afc03df6b401d1ee2b55cf23810e1fc7fb7b11f89826'),
    ('mta_sender', 33949, 'da25d3359d0759f71d8a4483680e3a3d5376c9e745e85224dbaee2a672f0670a'),
    ('mta_send_worker', 43252, 'de0dd8c2c0fb3b45923199ccc987ae057046fa0244c6a405c3a254850f7e68e7'),
    ('mta_scan_handoff', 11515, '51af67e80cf64038160cf420ad08f4f255a15dd9577e14fdcdb44fc26711046a'),
    ('mta_wifi', 28459, '62322b09fe4fd96bf6d49d8a2f7ac416e9a9d4dadcb3df23a6330e3205bcd017'),
    ('minhttp', 9690, 'bf5648457b19b60ad0f17320f8bd0431064f9cb4edf0d238d82136000eb57235'),
    ('mta_client_control_frame', 20942, 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('mta_client_connect_handoff', 12229, 'c86ccf734d9370ce86c3532cdc58a488382a056dd6b1e2d45ab24d06f27a683d'),
    ('mta_client_tmp_alias', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_client_startup_readonly', 20426, '2e49f367ae1eb27e82c03ef675861639415ecbad9471a8c3a62b4999fd48ee73'),
    ('mta_client_receive_factory', 82682, '7d20081c5d8581616f0e3cf722cc91ed4b43afa78bea1479bd702eb4a5e3a41d'),
    ('mta_client_state_bridge', 21284, 'ad98d7180182955e699a510d4e4f49362a2fe1dec97c047b3b2b8d281675936b'),
    ('mta_go_deployment', 26543, 'e8dc91c0a44a48d6cecf066257e79185fe590385f98300d01835edddb8114efe'),
    ('mta_send_preparation', 28532, '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814'),
    ('mta_go_readonly_parent', 52873, '96873084af32bc8c7fe0c0a236ddb49f4b91b85677b1b9b966fe6c714c03724b'),
    ('mta_go_send_publication', 45133, '1f9d4f771d998d24677a6bc276526acaa96362a2ed508595690ad6ba19173f96'),
    ('mta_go_send_bridge', 87625, '027be64bf7b1b4f6ae57d09921b821e4cc77db44c602b9a5d99d901ed5736f02'),
    ('mta_go_readonly_terminal_parent', 66973, '42ef91c27805d080f80706097834c6a73e4d5fe7b7683533a60fb33e59025a7a'),
    ('mta_receive_radio_baseline', 3971, '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c'),
    ('mta_receive_network', 15860, '1d2b2e250d63376f070816262fde601af5cd6005fb4f5877812f3d20ab8675a6'),
    ('mta_receive_barrier', 24113, 'd2721874aa6971b0742c4ae4b1dea9ba9bee277046ddb7253c3975b3dd6bf397'),
    ('mta_receive_trial', 64493, 'b3ffef7c593d254c375f8f4f0f97aa97cb7027db03e88861db639294dd1de13a'),
    ('mta_service', 155732, '76f48871bb4c2a3b72bb308e9bef56b3d509f01ef45c7ac2808d210acedd6960'),
)
MODULES = tuple(row[0] for row in SOURCE_PINS)


def _source_paths(name):
    if name not in MODULES: _fail('source_role_unknown')
    if name == 'mta_go_deployment':
        path = GO_ASSET_RUNTIME + '/' + name + '.py'
        return path, path
    return PHYSICAL_RUNTIME + '/' + name + '.py', RUNTIME + '/' + name + '.py'


class ReceiveBootError(ValueError):
    def __init__(self, code):
        self.code = code
        ValueError.__init__(self, code)


def _fail(code):
    raise ReceiveBootError(code) from None


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


def _meta(value):
    result = tuple(getattr(value, name, None) for name in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        _fail('metadata_unknown')
    return result


class _LinuxIo(object):
    def validate(self):
        if sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or \
                os.uname()[4] != 'armv7l' or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000:
            _fail('unsupported_platform')
    def pid(self): return os.getpid()
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def open(self, path): return os.open(path, ARM_READ)
    def fstat(self, fd): return os.fstat(fd)
    def read(self, fd, count): return os.read(fd, count)
    def close(self, fd): return os.close(fd)


class BootSourceLoader(object):
    """One fixed definitions load on one original worker, never a State owner.

    Private IO/clock seams support explicit HOST models; they do not relax the
    default Linux ARM ABI or issue device/receive admission.
    """
    def __init__(self, original_until, _io=None, _clock=None):
        if not _finite(original_until): _fail('invalid_budget')
        self.until = self._original_until = float(original_until)
        self.io = self._io_original = _LinuxIo() if _io is None else _io
        self.clock = self._clock_original = time.monotonic if _clock is None else _clock
        if not callable(self.clock): _fail('invalid_clock')
        self.worker = threading.current_thread()
        self.pid = None
        self.deadline = self._original_deadline = None
        self.last = None
        self.rows, self.raw, self.modules, self.module_originals = [], [], {}, []
        self.attempted = self.ended = False
        self.pending = False
        self.failure = None
        self.factory_attempted = False
        self.factory_returned = None
        self.factory_failure = None
        self._root_original = None

    def _context(self):
        if self.io is not self._io_original or self.clock is not self._clock_original or \
                self.until is not self._original_until or threading.current_thread() is not self.worker:
            _fail('owner_changed')
        if self.pid is not None and self.io.pid() != self.pid: _fail('owner_changed')
        if self.deadline is not self._original_deadline: _fail('owner_changed')

    def check(self):
        self._context()
        now = self.clock()
        if not _finite(now) or self.last is not None and now < self.last: _fail('invalid_clock')
        self.last = float(now)
        cap = self.until if self.deadline is None else self.deadline
        if now >= cap: _fail('deadline')
        return float(now)

    def _anchors(self):
        self.check()
        paths = ('/', '/tmp', '/var', '/var/tmp', '/var/volatile', '/var/volatile/tmp',
                 PHYSICAL_ROOT, PHYSICAL_RUNTIME, GO_ASSET_ROOT, GO_ASSET_RUNTIME)
        modes = (None, stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755,
                 stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o1777, stat.S_IFDIR | 0o1777,
                 stat.S_IFDIR | 0o700, stat.S_IFDIR | 0o700,
                 stat.S_IFDIR | 0o700, stat.S_IFDIR | 0o700)
        result = []
        for path, mode in zip(paths, modes):
            self.check(); actual_stat = self.io.stat(path); row = _meta(actual_stat)
            if row[3:5] != (0, 0) or mode is None and (not stat.S_ISDIR(row[2]) or row[2] & 0o022) or \
                    mode is not None and row[2] != mode or row[5] < 1:
                _fail('unsafe_root')
            if stat.S_ISLNK(row[2]):
                times = tuple(getattr(actual_stat, key, None) for key in ('st_mtime_ns', 'st_ctime_ns'))
                if row[5] != 1 or any(type(item) is not int or not 0 <= item < (1 << 64) for item in times):
                    _fail('unsafe_root')
                target = '/var/tmp' if path == '/tmp' else '/var/volatile/tmp'
                self.check(); observed = self.io.readlink(path)
                if type(observed) is not str or observed != target or row[6] != len(target):
                    _fail('unsafe_root')
                result.append((path, row + times, target))
            else:
                result.append((path, row[:5], None))
        self.check()
        for virtual, physical in ((ROOT, PHYSICAL_ROOT), (RUNTIME, PHYSICAL_RUNTIME)):
            # Parent aliases are traversed; the final entry itself is not.
            if _meta(self.io.stat(virtual))[:5] != _meta(self.io.stat(physical))[:5]:
                _fail('root_changed')
        value = tuple(result)
        if self._root_original is None: self._root_original = value
        elif value != self._root_original: _fail('root_changed')
        return value

    def _close_row(self, row):
        self._context()  # close-only: expiry does not turn known FD into unknown.
        if not any(row is original for original in self.rows): return False
        if row['attempted']: return row['closed'] is True and row['unknown'] is False
        if row['unknown'] or type(row['fd']) is not int:
            self.pending = True
            return False
        row['attempted'] = True
        try:
            if _meta(self.io.fstat(row['fd'])) != row['metadata']: _fail('close_unknown')
            returned = self.io.close(row['fd'])
            row['close_return'] = returned
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['close_error'] = error
                row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException as error:
            row['close_failure'] = error
            row['unknown'] = True
        if row['closed'] is not True: self.pending = True
        return row['closed'] is True and row['unknown'] is False

    def _read_source(self, name, size, pin):
        self.check()
        if len(self.rows) >= len(SOURCE_PINS): _fail('file_budget')
        before = self._anchors()
        physical, virtual = _source_paths(name)
        path = physical
        row = {'path': path, 'fd': None, 'metadata': None, 'raw': None, 'unknown': True,
               'attempted': False, 'closed': False, 'open_called': False, 'open_error': None,
               'read_error': None, 'close_return': None, 'close_error': None, 'close_failure': None}
        self.rows.append(row)
        try:
            self.check(); row['open_called'] = True
            try: row['fd'] = self.io.open(path)
            except BaseException as error: row['open_error'] = error; raise
            if type(row['fd']) is not int or row['fd'] < 0 or any(other is not row and
                    other['fd'] == row['fd'] and not other['closed'] for other in self.rows):
                _fail('descriptor_unknown')
            meta = _meta(self.io.fstat(row['fd'])); row['metadata'] = meta; row['unknown'] = False
            if not stat.S_ISREG(meta[2]) or stat.S_IMODE(meta[2]) != 0o400 or \
                    meta[3:6] != (0, 0, 1) or meta[6] != size: _fail('source_shape')
            chunks, total = [], 0
            while total <= size:
                self.check(); count = min(65536, size + 1 - total)
                raw = self.io.read(row['fd'], count)
                self.check()
                if type(raw) is not bytes or len(raw) > count: _fail('source_shape')
                chunks.append(raw); total += len(raw)
                if not raw: break
            raw = b''.join(chunks); row['raw'] = raw; self.raw.append((name, raw))
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin or \
                    _meta(self.io.fstat(row['fd'])) != meta or _meta(self.io.stat(path)) != meta or \
                    _meta(self.io.stat(virtual)) != meta or self._anchors() != before:
                _fail('source_changed')
            return raw
        except BaseException as error:
            row['read_error'] = error
            raise
        finally:
            try:
                if not self._close_row(row): self.pending = True
            except BaseException as error:
                row['close_failure'] = error
                self.pending = True

    def _source_shape(self):
        if type(SOURCE_PINS) is not tuple or len(SOURCE_PINS) != 33 or \
                SOURCE_PINS[0] != ('mta_client_executor', 117754, F37_SHA): _fail('source_shape')
        names = []
        for row in SOURCE_PINS:
            if type(row) is not tuple or len(row) != 3 or type(row[0]) is not str or \
                    re.fullmatch('[a-z][a-z0-9_]{0,63}', row[0]) is None or \
                    type(row[1]) is not int or not 0 < row[1] <= MAX_SOURCE or \
                    type(row[2]) is not str or re.fullmatch('[0-9a-f]{64}', row[2]) is None:
                _fail('source_shape')
            names.append(row[0])
        if tuple(names) != MODULES or len(set(names)) != len(names): _fail('source_shape')

    def load(self):
        if self.attempted: _fail('already_attempted')
        self.attempted = True
        try:
            self._source_shape()
            now = self.check()
            self.deadline = self._original_deadline = min(self.until, now + LOAD_SECONDS)
            # No foreign canonical namespace is adopted or overwritten.
            for name, existing in tuple(sys.modules.items()):
                if type(name) is not str or not (name in MODULES or name.startswith(('mta_', 'p011_'))):
                    continue
                if name == __name__ and type(existing) is types.ModuleType and existing.__dict__ is globals():
                    continue  # the exact imported boot itself, not a source dependency.
                _fail('canonical_namespace_busy')
            self.check(); self.io.validate(); self.check()
            self.pid = self.io.pid()
            if type(self.pid) is not int or not 1 <= self.pid <= 0x7fffffff: _fail('owner_changed')
            self.check()
            original_import = builtins.__import__
            def pinned_import(name, globals=None, locals=None, fromlist=(), level=0):
                if type(name) is not str or level: _fail('source_import')
                if name in MODULES:
                    if name not in self.modules or sys.modules.get(name) is not self.modules[name]:
                        _fail('source_import')
                    return self.modules[name]
                if name.startswith(('mta_', 'p011_')): _fail('source_import')
                return original_import(name, globals, locals, fromlist, level)
            for name, size, pin in SOURCE_PINS:
                raw = self._read_source(name, size, pin)
                if self.pending: _fail('close_unknown')
                self.check()
                if name in sys.modules: _fail('canonical_namespace_busy')
                module = types.ModuleType(name)
                module.__file__ = _source_paths(name)[1]
                module.__dict__['__builtins__'] = dict(vars(builtins), __import__=pinned_import)
                self.modules[name] = module
                self.module_originals.append((name, module, module.__dict__))
                sys.modules[name] = module  # before exec; never silently undone on failure.
                exec(raw, module.__dict__)
                self.check()
            self._anchors()
        except BaseException as error:
            self.failure = error
            raise
        finally:
            for row in reversed(self.rows):
                try:
                    if not self._close_row(row): self.pending = True
                except BaseException as error:
                    self.pending = True
                    if self.failure is None: self.failure = error
            self.ended = True
        self.authenticate()
        return self

    def authenticate(self):
        self._context()
        if not self.attempted or not self.ended or self.failure is not None or self.pending or \
                len(self.rows) != len(SOURCE_PINS) or len(self.module_originals) != len(SOURCE_PINS) or \
                any(row['unknown'] or row['closed'] is not True for row in self.rows):
            _fail('source_unavailable')
        for name, module, original_dict in self.module_originals:
            if type(module) is not types.ModuleType or self.modules.get(name) is not module or \
                    sys.modules.get(name) is not module or module.__dict__ is not original_dict or \
                    module.__file__ != _source_paths(name)[1]:
                _fail('source_changed')
        if self.modules['mta_client_state_bridge'].PARENT_SOURCE_SHA != F37_SHA:
            _fail('source_changed')
        return self

    def create_fixed_factory(self):
        self.authenticate()
        if self.factory_attempted: _fail('already_attempted')
        self.factory_attempted = True
        creator = self.modules['mta_client_receive_factory'].FixedReceiveDeploymentFactory
        try: value = creator()
        except BaseException as error:
            self.factory_failure = error
            raise
        self.factory_returned = value  # retain before type/domain checks.
        if type(value) is not creator: _fail('factory_unknown')
        self.authenticate()
        return value


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        raise SystemExit('SOURCE only; no State, Server, helper or RF start entry')
    print('SOURCE98_STATE_BOOT definitions=false factory=false state=false service=false send=false receive=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
