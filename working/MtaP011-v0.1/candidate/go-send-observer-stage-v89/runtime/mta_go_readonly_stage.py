"""Fixed Observer85 files-only publication, SOURCE v89; no admission.

Import/default main only defines code. An explicit stage() accepts exactly the
41 fixed source byte strings below, not paths, factories, authority or leases.
It creates only a fresh absent Observer85 root/runtime, preserves every existing
root (including a sealed root), and never repairs, renames or removes anything.
The caller's original absolute cap is DATA, not an authorization certificate.

EXCL files are written and read back through the same retained descriptor,
fsynced and sealed 0400. Known original descriptors close once even after active
expiry; an actual None return plus typed EBADF is required. Unknown resources
and partial publication remain retained. Nothing starts Python/helpers, opens
the device lock, reads/deletes pending, imports the 41 definitions or grants RF.
Private HOST tests may project this module's internal system implementation in
an isolated namespace; the production constructor has no IO/path/clock seam.
"""
import errno
import hashlib
import math
import os
import stat
import sys
import threading
import time

ROOT = '/var/volatile/tmp/p011-mta-go-observer-v85'
RUNTIME = ROOT + '/runtime'
ALIAS = '/tmp/p011-mta-go-observer-v85'
ROOT_NAME = 'p011-mta-go-observer-v85'
SOURCE_MANIFEST_SHA = 'b4a3bb3ce6571654b1bf998465e453669b0035a12b510cb4158144158d7ba5eb'
SOURCE_BYTES = 1347741
MAX_STAGE_SECONDS = 120.0
MAX_ROWS = 47  # Six retained directory descriptors and 41 original files.
CHUNK = 65536
SOURCE_PINS = (
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_client_tmp_alias', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_p2p_client_init', 71315, 'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('mta_client_resource_budget', 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e'),
    ('mta_client_proc', 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_client_caps', 11821, 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
    ('mta_client_caps_transport', 19614, 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'),
    ('mta_client_baseline', 31338, 'e950877bd99ee7907c66ee237e3140960ac8e4d64f979310b82bfdab2fa271ea'),
    ('mta_client_journal_codec', 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    ('mta_client_coordination', 36295, '5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3'),
    ('mta_client_files', 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864'),
    ('mta_client_pending', 53132, 'deaf62f9830b951584b36100de0f88548bcd6356b7327c3be0fa8578b65aba8a'),
    ('mta_client_store', 74676, 'bc51d3c64d3c92a87da331c740d93cea7466c535c5a81969422a45b8c5b68f63'),
    ('mta_client_process_owner', 34361, 'c144bc197a8fd1d4fbbfc358ba0172a84f5c9070058732189e4709c8c801ffeb'),
    ('mta_client_launch_registration', 21679, '833d46f5717e0b7e9db0c5392a0eb93d812d039b4b946a57d49d5903534a1aa0'),
    ('mta_client_two_phase_lease', 27606, 'c227989ec5188c272ad0a212974d569572704d3bb07c4c61c72670abcd0981a5'),
    ('mta_p2p_client_ctrl', 18712, '793b784f1b39eca18001aa65a1f0d6cdbd6de466dc58b3cf2ada167f71d902b5'),
    ('mta_client_wpa_status', 39133, '47074a5af8d9f75746fa7cd72e1e42b50c8402fcbb612963f6523c875fe1c269'),
    ('mta_protocol', 17958, '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_client_control_frame', 20942, 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('mta_client_kernel_proof', 23702, '4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede'),
    ('mta_client_connection', 22494, 'ae2932252bbef16b89e6bf4614c2ebdb1721d507274dbd9b9fe4d9db1d0ff159'),
    ('mta_client_linux_provider', 174220, '5f080f8a0d53d7232ec95c303e0e84036d22d4e0927ac98dd3195291cf6d56ba'),
    ('mta_client_executor', 105182, 'f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e'),
    ('mta_dhcp', 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
    ('mta_dhcp_client_core', 12362, '13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa'),
    ('mta_dhcp_client', 24670, '794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0'),
    ('mta_client_dora', 48149, 'f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e'),
    ('mta_client_dynamic_ip', 32427, '01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a'),
    ('mta_client_peer', 31242, 'f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9'),
    ('mta_scoped_sockets', 26339, 'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8'),
    ('mta_storage', 14335, '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6'),
    ('mta_transport', 35209, '77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa'),
    ('mta_client_transfer', 30747, '8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184'),
    ('mta_client_readonly_baseline', 13934, 'c2052c39fdad148d25f83743476b95a51a88e7f9e16ec2235c91d4de6adc9aad'),
    ('mta_snapshot_data', 17217, 'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
    ('mta_go_readonly_preflight', 24992, '0c054e36463da86357d77e4d8cbb6f8be77e459e4632c920a713a29a8271d826'),
    ('mta_go_readonly_loader', 36535, '02235981f6b2b57159c5e3c99209e88ba18b7278b0fc4051a764ae625c1d220d'),
    ('mta_observer_packet', 13223, '6f2c882058ee30a630ac30e1a5b4e9277d04ee2e71c108b58966a0574bf74e7a'),
    ('mta_go_readonly_entry', 25537, '41ec9d93147b875bb38363f15e545962459e4eaba161ccc5fb7759ce6c5c7df9'),
)
_SOURCE_PINS_ORIGINAL = SOURCE_PINS


class ReadonlyStageError(ValueError):
    """Constant code only: raw sources and private paths are not error text."""
    pass


def _fail(code): raise ReadonlyStageError(code) from None


def _meta(value):
    result = tuple(getattr(value, name, None) for name in
                   ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        _fail('stage_metadata')
    return result


def _entry(value):
    times = tuple(getattr(value, name, None) for name in ('st_mtime_ns', 'st_ctime_ns'))
    if any(type(item) is not int or not -(1 << 63) <= item < (1 << 63) for item in times):
        _fail('stage_metadata')
    return _meta(value) + times


def _identity(meta): return meta[:2] + (stat.S_IFMT(meta[2]),) + meta[3:6]


class _LinuxIo(object):
    """Internal actual system implementation; never a caller authority hook."""
    def __init__(self): self.fcntl = None
    def validate(self):
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                sys.flags.optimize or os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000):
            _fail('stage_platform')
        import fcntl
        self.fcntl = fcntl
    def pid(self): return os.getpid()
    def stat(self, path, dir_fd=None): return os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    def fstat(self, fd): return os.fstat(fd)
    def readlink(self, path): return os.readlink(path)
    def open(self, path, flags, mode=0o777, dir_fd=None): return os.open(path, flags, mode, dir_fd=dir_fd)
    def mkdir(self, path, mode, dir_fd=None): return os.mkdir(path, mode, dir_fd=dir_fd)
    def listdir(self, fd): return os.listdir(fd)
    def read(self, fd, count): return os.read(fd, count)
    def write(self, fd, raw): return os.write(fd, raw)
    def seek(self, fd, offset, whence): return os.lseek(fd, offset, whence)
    def sync(self, fd): return os.fsync(fd)
    def chmod(self, fd, mode): return os.fchmod(fd, mode)
    def close(self, fd): return os.close(fd)
    def flags(self, fd):
        if self.fcntl is None: _fail('stage_platform')
        return (self.fcntl.fcntl(fd, self.fcntl.F_GETFL),
                self.fcntl.fcntl(fd, self.fcntl.F_GETFD))


class FixedReadonlyObserverStage(object):
    """One fixed files-only attempt. status() is DATA, never ready/restored."""
    def __init__(self, original_until):
        if type(original_until) is not float or not math.isfinite(original_until) or not 0 < original_until < 1e12:
            _fail('stage_cap')
        self.until = self.original_until = original_until
        self.io = self.io_original = _LinuxIo()
        self.clock = self.clock_original = time.monotonic
        self.worker = self.pid = self.issued_at = self.last = None
        self.rows = self.rows_original = []
        self.mutations = self.mutations_original = []
        self.file_rows = []
        self.raws = None
        self.anchors_original = None
        self.base = self.var = self.volatile = self.tmp = self.root = self.runtime = None
        self.called = self.ended = self.success = self.close_called = self.closed = False
        self.failure = self.close_failure = None
        self.root_created = self.runtime_created = False
        self.readback = None

    def _context(self):
        if (self.until is not self.original_until or self.io is not self.io_original or
                self.clock is not self.clock_original or SOURCE_PINS is not _SOURCE_PINS_ORIGINAL or
                self.rows is not self.rows_original or self.mutations is not self.mutations_original or
                threading.current_thread() is not self.worker or self.io.pid() != self.pid):
            _fail('stage_original')

    def _now(self):
        self._context()
        value = self.clock()
        if (type(value) not in (int, float) or not math.isfinite(float(value)) or
                not 0 <= value < 1e12 or self.last is not None and value < self.last):
            _fail('stage_clock')
        self.last = float(value)
        if value >= self.until: _fail('stage_expired')
        return float(value)

    def _sources(self, value):
        if (type(value) is not dict or len(SOURCE_PINS) != 41 or
                sum(row[1] for row in SOURCE_PINS) != SOURCE_BYTES or
                set(value) != set(row[0] for row in SOURCE_PINS)):
            _fail('stage_sources')
        rows = []
        for name, size, pin in SOURCE_PINS:
            self._now()
            raw = value[name]
            if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
                _fail('stage_source_pin')
            rows.append((name, raw))  # Immutable bytes retained, not a mutable caller mapping.
        self._now()
        self.raws = tuple(rows)

    def _anchors(self):
        values = []
        for path, mode in (('/', None), ('/var', 0o755), ('/var/volatile', 0o1777),
                           ('/var/volatile/tmp', 0o1777)):
            self._now(); meta = _meta(self.io.stat(path)); self._now()
            if (not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or meta[5] < 1 or
                    mode is None and meta[2] & 0o022 or
                    mode is not None and stat.S_IMODE(meta[2]) != mode):
                _fail('stage_anchor')
            values.append((path, meta[:5], None))
        for path, target in (('/tmp', '/var/tmp'), ('/var/tmp', '/var/volatile/tmp')):
            self._now(); actual = self.io.stat(path); meta = _entry(actual)
            self._now(); observed = self.io.readlink(path); self._now()
            if (meta[2] != stat.S_IFLNK | 0o777 or meta[3:6] != (0, 0, 1) or
                    meta[6] != len(target) or type(observed) is not str or observed != target):
                _fail('stage_alias')
            values.append((path, meta, observed))
        value = tuple(values)
        if self.anchors_original is None: self.anchors_original = value
        elif value != self.anchors_original: _fail('stage_anchor_changed')
        return value

    def _directory_identity(self, value, mode):
        meta = _meta(value)
        if (not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or meta[5] < 1 or
                mode is None and meta[2] & 0o022 or
                mode is not None and stat.S_IMODE(meta[2]) != mode):
            _fail('stage_directory')
        return meta[:5]

    def _row(self, kind, parent, name, flags, mode):
        if len(self.rows) >= MAX_ROWS: _fail('stage_inventory')
        row = dict(kind=kind, parent=parent, name=name, flags=flags, mode=mode,
                   fd=None, fd_original=None, metadata=None, identity=None,
                   open_called=False, returned=False, open_error=None,
                   no_descriptor=False, no_descriptor_reason=None, unknown=True, close_called=False,
                   close_result=None, close_error=None, closed=False, ebadf=False,
                   chmod_called=False, chmod_returned=False, sealed_entry=None,
                   chmod_result=None, raw=None, content_sha=None,
                   write_values=[], read_values=[], sync_values=[], seek_value=None)
        self.rows.append(row)
        return row

    def _adopt(self, row, fd):
        row['fd'] = row['fd_original'] = fd
        row['returned'] = True
        if (type(fd) is not int or fd < 0 or any(
                other is not row and other['returned'] and not other['closed'] and other['fd'] == fd
                for other in self.rows)):
            _fail('stage_descriptor')
        # Preserve close identity before a cap/postcondition can reject a late return.
        meta = _meta(self.io.fstat(fd))
        row['metadata'] = meta
        row['identity'] = meta[:5] if row['kind'] == 'directory' else _identity(meta)
        row['unknown'] = False

    def _open(self, row, parent_fd=None):
        self._now(); row['open_called'] = True
        try:
            value = self.io.open(row['name'], row['flags'], 0o600, dir_fd=parent_fd)
        except OSError as error:
            row['open_error'] = error
            # A synchronous original open OSError returned no descriptor. This is
            # known absence of an FD, not a fabricated physical close/EBADF.
            if type(error.errno) is int and row['fd'] is None and not row['returned']:
                row['no_descriptor'], row['unknown'], row['closed'] = True, False, True
                row['no_descriptor_reason'] = 'original_open_error'
            raise
        self._adopt(row, value)
        self._now()
        flags = self.io.flags(value); self._now()
        if (type(flags) is not tuple or len(flags) != 2 or any(type(v) is not int for v in flags) or
                flags[0] & os.O_ACCMODE != row['flags'] & os.O_ACCMODE or flags[1] & 1 != 1):
            _fail('stage_descriptor_flags')
        return value

    def _dir_current(self, row):
        self._now()
        if (not any(row is item for item in self.rows) or row['kind'] != 'directory' or
                row['unknown'] or not row['returned'] or row['close_called'] or row['closed'] or
                row['fd'] is not row['fd_original']):
            _fail('stage_directory_original')
        current = self._directory_identity(self.io.fstat(row['fd']), row['mode']); self._now()
        parent = row['parent']
        if parent is None:
            path = self.io.stat('/')
        else:
            parent_fd = self._dir_current(parent)
            self._now(); path = self.io.stat(row['name'], dir_fd=parent_fd)
        self._now()
        if current != row['identity'] or self._directory_identity(path, row['mode']) != row['identity']:
            _fail('stage_directory_changed')
        return row['fd']

    def _open_dir(self, parent, name, mode):
        self._now()
        parent_fd = None if parent is None else self._dir_current(parent)
        before = self._directory_identity(self.io.stat(name, dir_fd=parent_fd), mode)
        self._now()
        row = self._row('directory', parent, name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        self._open(row, parent_fd)
        if self._directory_identity(self.io.fstat(row['fd']), mode) != before or row['identity'] != before:
            _fail('stage_directory_changed')
        self._dir_current(row)
        return row

    def _fresh_directory(self, parent, name):
        if not ((parent is self.tmp and name == ROOT_NAME) or
                (parent is self.root and name == 'runtime')):
            _fail('stage_mutation_role')
        self._anchors(); parent_fd = self._dir_current(parent)
        self._now()
        try: self.io.stat(name, dir_fd=parent_fd)
        except OSError as error:
            self._now()
            if type(error.errno) is not int or error.errno != errno.ENOENT: raise
        else: _fail('stage_root_exists')
        ticket = dict(parent=parent, name=name, called=False, returned=False,
                      return_value=None, error=None, unknown=False)
        self.mutations.append(ticket)
        self._now(); ticket['called'] = True; ticket['unknown'] = True
        try:
            returned = self.io.mkdir(name, 0o700, dir_fd=parent_fd)
            ticket['return_value'] = returned
            ticket['returned'] = returned is None
            if returned is not None: _fail('stage_mkdir_return')
            ticket['unknown'] = False
            if parent is self.tmp: self.root_created = True
            else: self.runtime_created = True
        except BaseException as error:
            ticket['error'] = error
            if isinstance(error, OSError) and type(error.errno) is int and error.errno in (errno.EEXIST, errno.ENOENT):
                ticket['unknown'] = False
            raise
        self._now()
        return self._open_dir(parent, name, 0o700)

    def _file_current(self, row):
        self._now()
        if (not any(row is item for item in self.file_rows) or row['unknown'] or row['close_called'] or
                row['closed'] or not row['returned'] or row['fd'] is not row['fd_original']):
            _fail('stage_file_original')
        actual = _meta(self.io.fstat(row['fd'])); self._now()
        if _identity(actual) != row['identity']: _fail('stage_file_changed')
        return actual

    def _publish(self, name, raw):
        if self.runtime is None or not any(name == module + '.py' for module, size, pin in SOURCE_PINS):
            _fail('stage_file_role')
        self._anchors(); parent_fd = self._dir_current(self.runtime)
        row = self._row('file', self.runtime, name,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        self.file_rows.append(row); row['raw'] = raw
        try:
            self._open(row, parent_fd)
            before = row['metadata']
            if (not stat.S_ISREG(before[2]) or before[3:6] != (0, 0, 1) or
                    stat.S_IMODE(before[2]) != 0o600 or before[6] != 0):
                _fail('stage_new_file')
            position = 0
            while position < len(raw):
                self._anchors(); self._dir_current(self.runtime); self._file_current(row)
                self._now(); result = self.io.write(row['fd'], raw[position:position + CHUNK])
                row['write_values'].append(result)
                self._now()
                if type(result) is not int or not 1 <= result <= min(CHUNK, len(raw) - position):
                    _fail('stage_write_return')
                position += result
                actual = self._file_current(row)
                if actual[6] != position or stat.S_IMODE(actual[2]) != 0o600: _fail('stage_write_changed')
                row['metadata'] = actual
            self._now(); result = self.io.sync(row['fd']); row['sync_values'].append(result); self._now()
            if result is not None: _fail('stage_sync_return')
            self._now(); result = self.io.seek(row['fd'], 0, 0); row['seek_value'] = result; self._now()
            if type(result) is not int or result != 0: _fail('stage_seek_return')
            parts, total = [], 0
            while total <= len(raw):
                self._now(); count = min(CHUNK, len(raw) + 1 - total)
                part = self.io.read(row['fd'], count)
                row['read_values'].append(part); parts.append(part); self._now()
                if type(part) is not bytes or len(part) > count: _fail('stage_readback_return')
                total += len(part)
                if not part: break
            if b''.join(parts) != raw or self._file_current(row) != row['metadata']:
                _fail('stage_readback_changed')
            self._now(); row['chmod_called'] = True
            result = self.io.chmod(row['fd'], 0o400)
            row['chmod_result'] = result
            row['chmod_returned'] = result is None; self._now()
            if result is not None: _fail('stage_chmod_return')
            self._now(); result = self.io.sync(row['fd']); row['sync_values'].append(result); self._now()
            if result is not None: _fail('stage_sync_return')
            actual = self._file_current(row)
            if stat.S_IMODE(actual[2]) != 0o400 or actual[6] != len(raw): _fail('stage_seal_changed')
            row['metadata'] = actual
            row['content_sha'] = hashlib.sha256(raw).hexdigest()
            self._now(); row['sealed_entry'] = _entry(self.io.fstat(row['fd'])); self._now()
            parent_fd = self._dir_current(self.runtime)
            self._now(); path = _entry(self.io.stat(name, dir_fd=parent_fd)); self._now()
            if path != row['sealed_entry']: _fail('stage_seal_changed')
        finally:
            self._close_row(row)
        if not row['closed'] or row['unknown']: _fail('stage_file_close')

    def _layout(self):
        self._anchors()
        for row, expected in ((self.root, ('runtime',)),
                              (self.runtime, tuple(name + '.py' for name, size, pin in SOURCE_PINS))):
            fd = self._dir_current(row)
            self._now(); names = self.io.listdir(fd); self._now()
            if type(names) is not list or any(type(name) is not str for name in names) or sorted(names) != sorted(expected):
                _fail('stage_layout')
        self._now(); root_meta = _meta(self.io.stat(ROOT)); self._now()
        self._now(); alias_meta = _meta(self.io.stat(ALIAS)); self._now()
        self._now(); runtime_meta = _meta(self.io.stat(RUNTIME)); self._now()
        self._now(); alias_runtime = _meta(self.io.stat(ALIAS + '/runtime')); self._now()
        if root_meta[:5] != alias_meta[:5] or runtime_meta[:5] != alias_runtime[:5]: _fail('stage_alias_changed')
        facts = []
        for expected, row in zip(SOURCE_PINS, self.file_rows):
            name, size, pin = expected
            if (row['name'] != name + '.py' or row['sealed_entry'] is None or
                    row['content_sha'] != pin or not row['closed'] or row['unknown']):
                _fail('stage_seal_changed')
            fd = self._dir_current(self.runtime)
            self._now(); current = _entry(self.io.stat(row['name'], dir_fd=fd)); self._now()
            if current != row['sealed_entry']: _fail('stage_seal_changed')
            facts.append((name, size, pin, row, current))
        if len(facts) != 41: _fail('stage_inventory')
        self.readback = tuple(facts)  # DATA references, not an authority token.

    def _close_row(self, row):
        try:
            self._context()
            if not any(row is item for item in self.rows): return False
            if (row['open_called'] is False and row['returned'] is False and
                    row['fd'] is None and row['fd_original'] is None and row['metadata'] is None):
                # Pure pre-factory expiry/rejection has no descriptor to close.
                # Retain the original unused ticket, never manufacture EBADF.
                row['no_descriptor'], row['unknown'], row['closed'] = True, False, True
                row['no_descriptor_reason'] = 'factory_not_called'
                return True
            if row['no_descriptor']:
                return row['open_called'] and not row['returned'] and row['fd'] is None and row['closed'] and not row['unknown']
            if row['close_called']: return row['closed'] and not row['unknown']
            if row['unknown'] or not row['returned'] or row['fd'] is not row['fd_original']: return False
            row['close_called'] = True
            actual = _meta(self.io.fstat(row['fd']))
            if row['kind'] == 'directory':
                if self._directory_identity_from_close(actual, row['mode']) != row['identity']:
                    _fail('stage_close_identity')
            elif row['kind'] == 'file':
                if (_identity(actual) != row['identity'] or not stat.S_ISREG(actual[2]) or
                        not (stat.S_IMODE(actual[2]) == 0o600 or
                             row['chmod_called'] and stat.S_IMODE(actual[2]) == 0o400)):
                    _fail('stage_close_identity')
            else: _fail('stage_close_role')
            row['close_result'] = self.io.close(row['fd'])
            try: self.io.fstat(row['fd'])
            except OSError as error:
                row['ebadf'] = type(error.errno) is int and error.errno == errno.EBADF
                row['closed'] = row['close_result'] is None and row['ebadf']
            if not row['closed']: row['unknown'] = True
        except BaseException as error:
            row['close_error'] = error; row['unknown'] = True
            if self.close_failure is None: self.close_failure = error
        return row['closed'] and not row['unknown']

    def _directory_identity_from_close(self, meta, mode):
        # No clock/path/current-source reread: close only this retained original FD.
        if (not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or meta[5] < 1 or
                mode is None and meta[2] & 0o022 or
                mode is not None and stat.S_IMODE(meta[2]) != mode):
            _fail('stage_close_identity')
        return meta[:5]

    def close(self):
        if self.close_called: return self.closed
        self.close_called = True
        if not self.called:
            self.closed = not self.rows and not self.mutations
            return self.closed
        good = True
        for row in reversed(self.rows): good = self._close_row(row) and good
        self.closed = good and all(not row['unknown'] for row in self.mutations)
        return self.closed

    def stage(self, fixed41raws):
        if self.called or self.close_called: _fail('stage_once')
        self.called = True
        self.worker = threading.current_thread(); self.pid = self.io.pid()
        try:
            self.io.validate()
            issued = self._now(); self.issued_at = issued
            if not 0 < self.until - issued <= MAX_STAGE_SECONDS: _fail('stage_cap')
            self._sources(fixed41raws)  # Entire graph/pin validation before any mutation.
            self._anchors()
            self.base = self._open_dir(None, '/', None)
            self.var = self._open_dir(self.base, 'var', 0o755)
            self.volatile = self._open_dir(self.var, 'volatile', 0o1777)
            self.tmp = self._open_dir(self.volatile, 'tmp', 0o1777)
            self.root = self._fresh_directory(self.tmp, ROOT_NAME)
            self.runtime = self._fresh_directory(self.root, 'runtime')
            for name, raw in self.raws: self._publish(name + '.py', raw)
            self._layout()
            for row in (self.runtime, self.root, self.tmp):
                self._anchors(); fd = self._dir_current(row)
                self._now(); returned = self.io.sync(fd); row['sync_values'].append(returned); self._now()
                if returned is not None: _fail('stage_sync_return')
            self._layout(); self._now()
        except BaseException as error:
            if self.failure is None: self.failure = error
            raise
        finally:
            self.ended = True
            self.close()
        try:
            if not self.closed: _fail('stage_close_pending')
            self._now()
            self.success = True
            return self
        except BaseException as error:
            if self.failure is None: self.failure = error
            raise

    def status(self):
        return dict(evidence='GO_OBSERVER_FILES_V89_DATA_ONLY', attempted=self.called,
                    ended=self.ended, publication_complete=self.success,
                    files=len(self.file_rows), source_files=41, source_bytes=SOURCE_BYTES,
                    source_manifest_sha256=SOURCE_MANIFEST_SHA,
                    root_created=self.root_created, runtime_created=self.runtime_created,
                    descriptors_closed=self.closed, resource_pending=not self.closed,
                    failed=self.failure is not None or self.close_failure is not None,
                    admission=False, rf_requested=False, restored=False,
                    send_available=False, receive_available=False, phone_tested=False)


def main(argv=None):
    # Definitions/default entry only. Installation requires an explicit caller.
    args = sys.argv[1:] if argv is None else argv
    return 0 if not args else 2


if __name__ == '__main__': raise SystemExit(main())
