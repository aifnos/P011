"""Fixed append-only receive deployment publisher; no receive/RF admission.

The pure constructor creates no files, threads, leases or processes. Only the
original decrypted-but-unclaimed State handoff worker can call this factory.
Live platform/profile reads are deployment DATA, not AuthenticatedStatusReader
authority: the latter requires the actual single-thread F and remains unchanged.
Publication closure is not a Parent, Session, radio or restoration certificate.
Partial new directories and private original errors/inventories are retained.

v69-r2 keeps returned-FD close identity before the active-cap postcheck; pending
older publications forbid reuse, and known no-FD failures require actual errno.
"""
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
import zlib

import p011_json as json_codec
import mta_client_executor as executor
import mta_client_connect_handoff as handoffs
import mta_client_tmp_alias as tmp_alias


ASSET_ROOT = '/tmp/p011-mta-state-v69'
ASSET_PHYSICAL_ROOT = '/var/volatile/tmp/p011-mta-state-v69'
SOURCE_MANIFEST_SHA = '0ea4db9b3ac41d1036d5796602db48b7740f6c51f1f0281604d6d8ebeb19319c'
F_SHA = 'f3f7c9fb54e46f82b4321152dfac6f4ab9b037943c403d76716f8254700bb17e'
CODEC_SHA = 'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'
WPA_SHA = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
WPA_BYTES = 1351192
PYTHON = '/usr/bin/python3.5'
PREPARE_SECONDS = 120.0
MAX_PROFILE_FILES, MAX_ENTRIES, MAX_IMAGE = 512, 4096, 16777216
BASELINE_MANIFEST = (
    ('/usr/bin/Z03', 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a'),
    ('/usr/bin/control_engine', '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d'),
    ('/usr/bin/zyb_z03_launch.sh', '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'),
    ('/usr/sbin/wpa_cli', 'e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849'))
SOURCE_PINS = (
    ('p011_json', 8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 22049, '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_client_tmp_alias', 8827, '1a4a52bd0bae7add6ae42f66bd9827c43865a0170c666eaab00797d1f45f7f2f'),
    ('mta_p2p_client_init', 71315, 'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('mta_client_resource_budget', 16215, '56d6dbe2370279b1572a563e67fd3313bf942c0baa78fbd8e36cd973ba09839e'),
    ('mta_client_proc', 39384, 'ede5953c33ba4c17d3aecb1fffe8a9358589497b37e3109034d5e1de3eadb3d6'),
    ('mta_client_caps', 11821, 'c1792c2294fed5da16ec4a676423fbcbe53d44e9bc4ddadc1bc26fd45afe046c'),
    ('mta_client_caps_transport', 19614, 'df6b4cf3ede6039c684c6b689a8b61ffe1ba5b87259bb4a5581aa5c3ece84420'),
    ('mta_client_baseline', 29510, 'b74696eb4fa0586b254633f667eb588634700234cc30d8b49d5453e4592782bf'),
    ('mta_client_journal_codec', 17450, '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    ('mta_client_coordination', 36295, '5b8a4295a5479cb5693182085fc8d35c6041bb0f14d9efb660ec11f024a5eeb3'),
    ('mta_client_files', 28938, '30c07bb4a5a28ce02aa76f35650ee1c87af63617f445e554c3fd7f73a2705864'),
    ('mta_client_pending', 57246, '14e85b8297868a7a07d964a598bc3cbc665e1e6cf19d615466e165386a27f524'),
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
    ('mta_client_executor', 105182, F_SHA),
    ('mta_dhcp', 15719, '631987bd7307580af069f1978e440d21fbd449ecc62c83e0e06195c330f50176'),
    ('mta_dhcp_client_core', 12362, '13c03d181139fd9ead7ff3bf2bcbb4930669f1e795b17360da85834dc345e9fa'),
    ('mta_dhcp_client', 24670, '794421678866d04a10ca46fa9eb7e17174f24c4d9e705cf59016b457702003a0'),
    ('mta_client_dora', 48149, 'f17f8405b28799fda8ee8f3ea9d280f871cceb1e0c6b999fc855bcb652ab2f7e'),
    ('mta_client_dynamic_ip', 32427, '01476613eb965a05cd5441dfbfea53f15ce763da12213b76791ecdb23152199a'),
    ('mta_client_peer', 31242, 'f8a15d046b505a8c5117a5be19d2ee59f38096759be1b29a0310535ceea08ec9'),
    ('mta_scoped_sockets', 26339, 'b95cfbe724b43baf90511c9d2a4a39d869a40a57e78e2a87d398ea134f9f84b8'),
    ('mta_storage', 14335, '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6'),
    ('mta_transport', 35209, '77d9cd45936318315cf3343ab1bd2594c6a3381e33a7d0fdcfd853916063eefa'),
    ('mta_client_transfer', 30747, '8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184'))
_F_ORIGINALS = (executor, executor.DeploymentLoader, executor.LoadedDeployment,
                executor.ClientExecutor, executor._ReadOwner)
_HANDOFF_TYPE = handoffs.ReceiveConnectHandoff
_HANDOFF_CHECK = handoffs.ReceiveConnectHandoff._check
_NAMESPACES = frozenset(('cgroup', 'ipc', 'mnt', 'net', 'pid', 'pid_for_children', 'user', 'uts'))


class ReceivePublicationError(ValueError):
    pass


def _fail(code):
    raise ReceivePublicationError(code) from None


def _number(value):
    return type(value) in (int, float) and math.isfinite(float(value)) and 0 <= value < 1e12


def _path(value):
    return executor._path(value)


def _close_identity(meta):
    return meta[:2] + (stat.S_IFMT(meta[2]),) + meta[3:6]


def _same_tree(left, right):
    if type(left) is not type(right): return False
    if type(left) is dict:
        return set(left) == set(right) and all(_same_tree(left[k], right[k]) for k in left)
    if type(left) in (tuple, list):
        return len(left) == len(right) and all(_same_tree(a, b) for a, b in zip(left, right))
    return left == right


class _PublicationAttempt(object):
    def __init__(self, factory, handoff):
        # No IO or new clock authority. The caller retains this object first.
        self.factory, self.handoff = factory, handoff
        self.state, self.operation, self.session = handoff.state, handoff.operation, handoff.session
        self.bridge = getattr(self.operation, 'client_bridge', None)
        self.worker, self.pid, self.clock = handoff.worker, os.getpid(), handoff.clock
        self.handoff_until, self.session_until = handoff.deadline, self.session._task_deadline
        self.epoch, self.session_id, self.nonce = handoff.epoch, handoff._session_id, handoff.nonce
        self.until = self.original_until = None
        self.prepare_until = self.original_prepare_until = None
        self.last, self.token, self.operation_id = None, None, None
        self.phase, self.ended, self.success, self.failure = 'new', False, False, None
        self.files, self.writer, self.loader, self.value = None, None, None, None
        self.payloads, self.wpa, self.profile = None, None, None
        self.manifest_sha, self.closed_owners, self.closed_facts = None, None, None

    def originals(self):
        # Exact parents and definitions, not a caller's restoration/ready flag.
        factory, handoff, bridge = self.factory, self.handoff, self.bridge
        if (type(factory) is not FixedReceiveDeploymentFactory or
                factory._active is not self or not any(a is self for a in factory._attempts) or
                type(handoff) is not _HANDOFF_TYPE or handoffs.ReceiveConnectHandoff is not _HANDOFF_TYPE or
                handoff._check.__func__ is not _HANDOFF_CHECK or
                handoff.state is not self.state or handoff.operation is not self.operation or
                handoff.session is not self.session or handoff.worker is not self.worker or
                handoff.clock is not self.clock or self.clock is not time.monotonic or
                handoff.deadline is not self.handoff_until or self.session._task_deadline is not self.session_until or
                handoff.epoch != self.epoch or handoff._session_id != self.session_id or handoff.nonce != self.nonce or
                threading.current_thread() is not self.worker or os.getpid() != self.pid or
                self.operation.client_bridge is not bridge or bridge is None):
            _fail('publication_owner_changed')
        # Deferred import: boot must load factory before bridge, without cycles.
        import mta_client_state_bridge as bridges
        if (type(bridge) is not bridges.StateClientBridge or bridge._factory is not factory or
                bridge.handoff is not handoff or bridge.state is not self.state or
                bridge.operation is not self.operation or bridge.session is not self.session or
                bridge.worker is not self.worker or bridge.clock is not self.clock or
                bridge._executor is not executor or bridge.started is not True or bridge.running is not True or
                bridge.parent is not None or bridge.parent_ticket['started'] is not False or
                bridge.factory_ticket['started'] is not True or bridge.factory_ticket['returned'] is not None or
                bridge.factory_ticket['authenticated'] is not False or
                handoff._decrypt_attempted is not True or handoff._claimed is not False or
                handoff.binding is not None):
            _fail('publication_owner_changed')
        if (sys.modules.get('mta_client_executor') is not executor or
                type(executor) is not types.ModuleType or
                any(current is not original for current, original in zip(
                    (executor, executor.DeploymentLoader, executor.LoadedDeployment,
                     executor.ClientExecutor, executor._ReadOwner), _F_ORIGINALS)) or
                tuple(executor.MODULES) != tuple(n for n, size, sha in SOURCE_PINS) or
                executor.CONNECT_CODEC_SHA != CODEC_SHA or executor.RECEIVE_ROOT != '/mnt/data/p011-toolbox/user/Received'):
            _fail('publication_source_changed')

    def now(self):
        with self.state.lock:
            self.originals()
            self.handoff._check()
            value = self.clock()
            if not _number(value) or self.last is not None and value < self.last:
                _fail('publication_clock')
            self.last = float(value)
            if self.until is not None and (self.until is not self.original_until or
                    self.until != min(float(self.handoff_until), float(self.session_until)) or value >= self.until):
                _fail('publication_expired')
            if self.prepare_until is not None and (self.prepare_until is not self.original_prepare_until or
                    self.prepare_until > self.until or value >= self.prepare_until):
                _fail('publication_expired')
            return float(value)

    def start(self):
        if not _number(self.handoff_until) or not _number(self.session_until): _fail('publication_cap')
        value = self.now()
        self.until = self.original_until = min(float(self.handoff_until), float(self.session_until))
        if not 0 < self.until - value <= 300: _fail('publication_cap')
        self.prepare_until = self.original_prepare_until = min(self.until, value + PREPARE_SECONDS)
        self.now()
        self.token = os.urandom(16).hex()
        self.operation_id = os.urandom(16).hex()
        if not executor._token(self.token): _fail('publication_token')
        handoffs.protocol.validate_task_id(self.operation_id)
        self.now()

    def close_parent_originals(self):
        # Expiry/cancel never grants IO, but must not prevent known-FD close.
        return (type(self.factory) is FixedReceiveDeploymentFactory and
            any(a is self for a in self.factory._attempts) and self.factory._active is self and
            type(self.handoff) is _HANDOFF_TYPE and self.handoff.state is self.state and
            self.handoff.operation is self.operation and self.handoff.session is self.session and
            self.handoff.worker is self.worker and self.clock is self.handoff.clock and
            self.clock is time.monotonic and threading.current_thread() is self.worker and
            os.getpid() == self.pid and self.until is self.original_until and
            self.prepare_until is self.original_prepare_until)


class _Files(object):
    """Own bounded FD ledger for raw assets/live DATA; no Proc/STATUS grant."""
    def __init__(self, attempt):
        self.attempt = attempt
        self.rows, self.raw, self.pending, self.close_attempted = [], [], False, False
        self.io = executor._LinuxIo()
        # Existing exact metadata/readlink alias checker creates no FD.
        self.alias_owner = executor._ReadOwner(self.io, attempt.now, attempt.prepare_until)

    def _alias(self):
        self.attempt.now()
        value = self.alias_owner._fixed_tmp_alias()
        if value is None: _fail('publication_tmp_profile')
        return value

    def anchors(self, path):
        if not _path(path): _fail('publication_path')
        alias = self._alias() if path.startswith('/var/volatile/tmp/') else None
        rows = []
        for index in range(len(path.split('/')) - 1):
            name = '/' if index == 0 else '/' + '/'.join(path.split('/')[1:index + 1])
            self.attempt.now(); meta = executor._meta(os.stat(name, follow_symlinks=False))
            temporary = alias is not None and name in ('/var/volatile', '/var/volatile/tmp')
            if (not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or
                    meta[2] & 0o022 and not temporary): _fail('publication_path')
            if (name == ASSET_PHYSICAL_ROOT or name.startswith(ASSET_PHYSICAL_ROOT + '/')) and stat.S_IMODE(meta[2]) != 0o700:
                _fail('publication_asset_mode')
            rows.append((name, meta[:5]))
        return alias, tuple(rows)

    def read(self, path, limit, expected=None, private=False, binary=False, proc=False, magic=False):
        self.attempt.now()
        if self.close_attempted or len(self.rows) >= MAX_PROFILE_FILES: _fail('publication_read_budget')
        if type(limit) is not int or not 1 <= limit <= 67108864: _fail('publication_read_budget')
        anchors = self.anchors(path)
        flags = os.O_RDONLY | os.O_CLOEXEC | (0 if magic else os.O_NOFOLLOW)
        row = {'owner': self, 'path': path, 'flags': flags, 'fd': None, 'metadata': None,
            'identity': None, 'open_called': False, 'open_error': None, 'returned': False,
            'unknown': True, 'attempted': False, 'closed': False, 'close_result': None,
            'ebadf_error': None, 'close_error': None, 'raw': None}
        self.rows.append(row)
        try:
            self.attempt.now(); row['open_called'] = True
            try: fd = os.open(path, flags)
            except OSError as error:
                row['open_error'] = error
                # No returned FD is known absent only for an actual errno.
                known = type(error.errno) is int and 1 <= error.errno <= 4095
                row['unknown'], row['closed'] = not known, known
                raise
            row['fd'], row['returned'] = fd, True
            if type(fd) is not int or fd < 0 or any(r is not row and r['fd'] == fd and not r['closed'] for r in self.rows):
                _fail('publication_fd_unknown')
            meta = executor._meta(os.fstat(fd))
            row['metadata'], row['identity'], row['unknown'] = meta, _close_identity(meta), False
            # A late returned FD still needs its immediate original close identity.
            # This metadata read does not authorize any subsequent active read.
            self.attempt.now()
            if (not stat.S_ISREG(meta[2]) or meta[5] != 1 and not (path == PYTHON and binary and meta[5] == 2) or
                    not proc and (meta[3:5] != (0, 0) or meta[2] & 0o022 or not 1 <= meta[6] <= limit) or
                    private and stat.S_IMODE(meta[2]) != (0o500 if binary else 0o400) or
                    binary and not meta[2] & 0o111): _fail('publication_read_identity')
            parts, total = [], 0
            while total <= limit:
                self.attempt.now(); requested = min(65536, limit + 1 - total)
                chunk = os.read(fd, requested)
                row['incoming'] = chunk
                self.attempt.now()
                if type(chunk) is not bytes or len(chunk) > requested: _fail('publication_read_result')
                parts.append(chunk); total += len(chunk)
                if total > limit: _fail('publication_read_budget')
                if not chunk: break
            raw = b''.join(parts); row['raw'] = raw; self.raw.append((path, raw, meta))
            self.attempt.now()
            actual_path = os.stat(path, follow_symlinks=magic)
            if (executor._meta(os.fstat(fd)) != meta or executor._meta(actual_path) != meta or
                    self.anchors(path) != anchors or not proc and len(raw) != meta[6]): _fail('publication_read_changed')
            if expected is not None and hashlib.sha256(raw).hexdigest() != expected: _fail('publication_pin_changed')
            if binary and not raw.startswith(b'\x7fELF'): _fail('publication_elf')
            self.attempt.now()
            return raw, meta
        except BaseException:
            if row['unknown']: self.pending = True
            raise
        finally:
            if not self.close_row(row): self.pending = True

    def close_row(self, row):
        if (not self.attempt.close_parent_originals() or self.attempt.files is not self or
                type(row) is not dict or row['owner'] is not self or not any(r is row for r in self.rows)):
            return False
        if row['attempted'] or row['closed']: return row['closed'] is True and row['unknown'] is False
        if row['unknown'] or type(row['fd']) is not int or row['identity'] is None: return False
        row['attempted'] = True
        try:
            if _close_identity(executor._meta(os.fstat(row['fd']))) != row['identity']: _fail('publication_close_identity')
            row['close_result'] = os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error:
                row['ebadf_error'] = error
                row['closed'] = row['close_result'] is None and type(error.errno) is int and error.errno == errno.EBADF
            if row['closed'] is not True: row['unknown'] = True
        except BaseException as error:
            row['close_error'], row['unknown'] = error, True
        if not row['closed']: self.pending = True
        return row['closed'] is True and row['unknown'] is False

    def close(self):
        if self.close_attempted: return self.closed()
        self.close_attempted = True
        for row in reversed(self.rows):
            if not self.close_row(row): self.pending = True
        return self.closed()

    def closed(self):
        # Pure retained facts; no fstat of historical FD numbers.
        if self.pending or self.close_attempted is not True: return False
        for row in self.rows:
            if row['owner'] is not self or row['closed'] is not True or row['unknown'] is not False: return False
            if row['returned']:
                if (row['attempted'] is not True or row['close_result'] is not None or
                        type(row['ebadf_error']) is not OSError and not isinstance(row['ebadf_error'], OSError) or
                        row['ebadf_error'].errno != errno.EBADF or row['close_error'] is not None): return False
            elif (row['fd'] is not None or not isinstance(row['open_error'], OSError) or
                    type(row['open_error'].errno) is not int or not 1 <= row['open_error'].errno <= 4095 or
                    row['attempted'] is not False):
                return False
        return True


def _stat_data(raw, pid):
    # Strict live DATA continuity, not ProcObservation/Actor authority.
    if type(raw) is not bytes or not raw.endswith(b'\n') or b'\0' in raw or len(raw) > 32768:
        _fail('publication_proc_data')
    match = re.fullmatch(br'([1-9][0-9]*) \(([^\n]*)\) ([RSDTtWKP]) (.*)\n', raw)
    if match is None or int(match.group(1)) != pid or match.group(2) != b'wpa_supplicant':
        _fail('publication_proc_data')
    fields = match.group(4).split()
    if len(fields) < 19 or any(re.fullmatch(br'-?(0|[1-9][0-9]*)', v) is None for v in fields):
        _fail('publication_proc_data')
    start = int(fields[18])
    if not 0 < start < (1 << 64): _fail('publication_proc_data')
    return pid, start


def _live_profile(attempt):
    """Read current manifest data, without claiming STATUS/RF authentication."""
    files = attempt.files
    attempt.now(); executor._LinuxIo().validate()
    if tuple(sys.version_info[:3]) != (3, 5, 5): _fail('publication_platform')
    python, python_meta = files.read(PYTHON, MAX_IMAGE, binary=True)
    python_sha = hashlib.sha256(python).hexdigest()
    attempt.now(); names = os.listdir('/proc')
    if (type(names) is not list or len(names) > MAX_ENTRIES or len(set(names)) != len(names) or
            any(type(n) is not str for n in names)): _fail('publication_proc_names')
    found = []
    for name in sorted(names):
        attempt.now()
        if re.fullmatch('[1-9][0-9]{0,9}', name) is None: continue
        pid = int(name)
        if not 0 < pid <= 0x7fffffff: _fail('publication_proc_data')
        comm = files.read('/proc/' + name + '/comm', 128, proc=True)[0]
        if comm == b'wpa_supplicant\n': found.append(pid)
    if len(found) != 1: _fail('publication_daemon_data')
    pid = found[0]; root = '/proc/' + str(pid)
    before = _stat_data(files.read(root + '/stat', 32768, proc=True)[0], pid)
    command = files.read(root + '/cmdline', 32768, proc=True)[0]
    if not command or not command.endswith(b'\0'): _fail('publication_daemon_data')
    attempt.now(); daemon = os.readlink(root + '/exe'); attempt.now()
    if not _path(daemon) or daemon.rsplit('/', 1)[-1] != 'wpa_supplicant': _fail('publication_daemon_data')
    image, image_meta = files.read(daemon, MAX_IMAGE, binary=True)
    live_image, live_meta = files.read(root + '/exe', MAX_IMAGE, binary=True, magic=True)
    if live_image != image or live_meta != image_meta: _fail('publication_daemon_data')
    identity = files.read(root + '/status', 32768, proc=True)[0]; ids = {}
    for line in identity.splitlines():
        key, sep, value = line.partition(b':')
        if key not in (b'Uid', b'Gid'): continue
        values = value.split()
        if (key in ids or sep != b':' or len(values) != 4 or
                any(re.fullmatch(br'(0|[1-9][0-9]{0,9})', v) is None for v in values)):
            _fail('publication_daemon_data')
        numbers = tuple(int(v) for v in values)
        if len(set(numbers)) != 1 or numbers[0] > 0xffffffff: _fail('publication_daemon_data')
        ids[key] = numbers[0]
    if set(ids) != {b'Uid', b'Gid'}: _fail('publication_daemon_data')
    namespace_rows = []
    for path in (root + '/ns', '/proc/self/ns'):
        attempt.now(); names = os.listdir(path); attempt.now()
        if (type(names) is not list or not 1 <= len(names) <= 8 or len(set(names)) != len(names) or
                any(type(n) is not str or n not in _NAMESPACES for n in names)): _fail('publication_namespace_data')
        namespace_rows.append(tuple(sorted(names)))
    if namespace_rows[0] != namespace_rows[1]: _fail('publication_namespace_data')
    namespaces = []
    for name in namespace_rows[0]:
        pair = []
        for path in (root + '/ns/', '/proc/self/ns/'):
            attempt.now(); link = os.readlink(path + name); attempt.now(); pair.append(link)
        stem = 'pid' if name == 'pid_for_children' else name
        if pair[0] != pair[1] or type(pair[0]) is not str or re.fullmatch(stem + r':\[[1-9][0-9]{0,19}\]', pair[0]) is None:
            _fail('publication_namespace_data')
        namespaces.append((name, tuple(pair)))
    config_sha = None
    if {'mnt', 'net', 'pid', 'user'}.issubset(namespace_rows[0]): kind = 'full4_present'
    elif namespace_rows[0] == ('cgroup', 'mnt'):
        kind = 'namespaces_disabled_cgroup_mnt'
        packed = files.read('/proc/config.gz', 1048576, proc=True)[0]
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        config = decoder.decompress(packed, 1048577)
        if (len(config) > 1048576 or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or
                config.splitlines().count(b'# CONFIG_NAMESPACES is not set') != 1 or
                any(v.startswith(b'CONFIG_NAMESPACES=') for v in config.splitlines())):
            _fail('publication_namespace_data')
        config_sha = hashlib.sha256(config).hexdigest()
    else: _fail('publication_namespace_data')
    unix = files.read('/proc/net/unix', 1048576, proc=True)[0]
    lines = unix.splitlines()
    if (not unix.endswith(b'\n') or not lines or len(lines) > 4097 or
            lines[0].split() != [b'Num', b'RefCount', b'Protocol', b'Flags', b'Type', b'St', b'Inode', b'Path']):
        _fail('publication_endpoint_data')
    endpoints = []
    for line in lines[1:]:
        parts = line.split(None, 7)
        if len(parts) != 8 or not parts[7].endswith(b'/wlan0'): continue
        try: endpoint = parts[7].decode('ascii')
        except UnicodeError: _fail('publication_endpoint_data')
        if (not _path(endpoint) or len(endpoint) > 107 or parts[4] != b'0002' or
                re.fullmatch(br'[1-9][0-9]{0,19}', parts[6]) is None): _fail('publication_endpoint_data')
        endpoints.append((endpoint, int(parts[6])))
    if len(endpoints) != 1: _fail('publication_endpoint_data')
    endpoint, inode = endpoints[0]
    attempt.now(); descriptors = os.listdir(root + '/fd'); attempt.now()
    if (type(descriptors) is not list or len(descriptors) > 512 or len(set(descriptors)) != len(descriptors) or
            any(type(n) is not str or re.fullmatch('(0|[1-9][0-9]{0,9})', n) is None for n in descriptors)):
        _fail('publication_endpoint_data')
    socket_refs = []
    for name in descriptors:
        attempt.now(); link = os.readlink(root + '/fd/' + name); attempt.now()
        if link == 'socket:[' + str(inode) + ']': socket_refs.append(name)
    if not socket_refs: _fail('publication_endpoint_data')
    if (_stat_data(files.read(root + '/stat', 32768, proc=True)[0], pid) != before or
            files.read(root + '/comm', 128, proc=True)[0] != b'wpa_supplicant\n' or
            files.read(root + '/cmdline', 32768, proc=True)[0] != command): _fail('publication_daemon_changed')
    attempt.now()
    if os.readlink(root + '/exe') != daemon: _fail('publication_daemon_changed')
    for path, expected in ((root + '/ns', namespace_rows[0]), ('/proc/self/ns', namespace_rows[1]),
                           (root + '/fd', tuple(sorted(descriptors)))):
        attempt.now()
        if tuple(sorted(os.listdir(path))) != expected: _fail('publication_daemon_changed')
    for name, pair in namespaces:
        for path, expected in zip((root + '/ns/', '/proc/self/ns/'), pair):
            attempt.now()
            if os.readlink(path + name) != expected: _fail('publication_daemon_changed')
    attempt.now()
    return {'python_exe': PYTHON, 'python_sha': python_sha,
        'status_manifest': {'daemon_exe': daemon, 'daemon_sha256': hashlib.sha256(image).hexdigest(),
            'endpoint': endpoint, 'real_uid': ids[b'Uid'], 'real_gid': ids[b'Gid'],
            'namespace_kind': kind, 'config_sha256': config_sha},
        'python_metadata': python_meta, 'daemon_identity_data': before,
        'daemon_image_metadata': image_meta, 'endpoint_inode_data': inode,
        'namespace_data': tuple(namespaces), 'status_authenticated': False}


class _StageIo(object):
    def stat_root(self): return os.stat('/', follow_symlinks=False)
    def stat_at(self, fd, name): return os.stat(name, dir_fd=fd, follow_symlinks=False)
    def fstat(self, fd): return os.fstat(fd)
    def readlink_at(self, fd, name): return os.readlink(name, dir_fd=fd)


class _Writer(object):
    """EXCL append-only writer, separately bound to this original attempt."""
    def __init__(self, attempt):
        self.attempt, self.clock, self.until = attempt, attempt.now, attempt.prepare_until
        self.worker, self.pid = attempt.worker, attempt.pid
        self._io, self._tmp_alias = _StageIo(), None
        self.rows, self.writes, self.mutations = [], [], []
        self.root = self.tmp = self.private_root = self.run = self.runtime = self.native = self.ctrl = None
        self.entries_before = self.entries_after = None
        self.pending, self.close_attempted, self.stage_attempted = False, False, False
        self.run_name = 'client-' + attempt.token

    def check(self):
        a = self.attempt
        if (type(a) is not _PublicationAttempt or a.writer is not self or self.until is not a.prepare_until or
                self.worker is not a.worker or self.pid != a.pid or
                self.clock.__self__ is not a or self.clock.__func__ is not _PublicationAttempt.now):
            _fail('publication_writer_changed')
        self.clock()

    def identity(self, value, mode=None):
        meta = executor._meta(value)
        if not stat.S_ISDIR(meta[2]) or meta[3:5] != (0, 0) or meta[5] < 1: _fail('publication_directory')
        if mode is None and meta[2] & 0o022 or mode is not None and stat.S_IMODE(meta[2]) != mode:
            _fail('publication_directory')
        return meta[:5]

    def fd_of(self, row):
        self.check()
        if (not any(r is row for r in self.rows) or row['unknown'] or row['attempted'] or row['closed'] or
                type(row['fd']) is not int or row['kind'] != 'directory' or
                self.identity(self._io.fstat(row['fd']), row['mode']) != row['identity']):
            _fail('publication_directory_changed')
        parent = row['parent']
        actual = self._io.stat_root() if parent is None else self._io.stat_at(self.fd_of(parent), row['name'])
        if self.identity(actual, row['mode']) != row['identity']: _fail('publication_directory_changed')
        return row['fd']

    def open_dir(self, parent, name, mode=None):
        self.check()
        row = {'owner': self, 'kind': 'directory', 'parent': parent, 'name': name, 'mode': mode,
            'fd': None, 'metadata': None, 'identity': None, 'unknown': True,
            'attempted': False, 'closed': False, 'close_result': None, 'ebadf_error': None, 'close_error': None}
        self.rows.append(row)
        parent_fd = None if parent is None else self.fd_of(parent)
        before = self.identity(self._io.stat_root() if parent is None else self._io.stat_at(parent_fd, name), mode)
        self.check(); flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        row['fd'] = os.open('/', flags) if parent is None else os.open(name, flags, dir_fd=parent_fd)
        fd = row['fd']
        if type(fd) is not int or fd < 0 or any(r is not row and r['fd'] == fd and not r['closed'] for r in self.rows):
            _fail('publication_fd_unknown')
        row['metadata'] = executor._meta(self._io.fstat(fd))
        row['identity'] = self.identity(self._io.fstat(fd), mode); row['unknown'] = False
        self.check()
        actual = self._io.stat_root() if parent is None else self._io.stat_at(parent_fd, name)
        if self.identity(actual, mode) != before or row['identity'] != before: _fail('publication_directory_changed')
        return row

    def open_prefix(self, parent, name):
        if parent is self.root and name == 'var': return self.open_dir(parent, name, 0o755)
        if self._tmp_alias is not None and any(parent is p for p in self._tmp_alias.prefix_tickets) and name == 'volatile':
            return self.open_dir(parent, name, 0o1777)
        _fail('publication_directory')

    def authenticate(self):
        if self._tmp_alias is None or self._tmp_alias.authenticate(self, self.root) is not self._tmp_alias:
            _fail('publication_tmp_profile')
        fd = self.fd_of(self.tmp); self.check()
        try: self._io.stat_at(fd, 'p011-mta-p2p-device.pending')
        except OSError as error:
            self.check()
            if type(error.errno) is int and error.errno == errno.ENOENT: return
            raise
        _fail('publication_pending_exists')

    def prepare(self):
        self.root = self.open_dir(None, '/')
        self._tmp_alias = tmp_alias.FixedTmpAnchor(self, self._io, self.root, self.fd_of, self.open_prefix, self.check)
        if self._tmp_alias.prepare() is not self._tmp_alias: _fail('publication_tmp_profile')
        self.tmp = self.open_dir(self._tmp_alias.tmp_parent, 'tmp', 0o1777)
        if self._tmp_alias.bind_tmp(self.tmp) is not self._tmp_alias: _fail('publication_tmp_profile')
        self.authenticate()
        # The shared fixed root must already exist; never repair/create it.
        self.private_root = self.open_dir(self.tmp, 'p011-mta-client-rfinit', 0o700)

    def directory(self, parent, name):
        if not (parent is self.private_root and name == self.run_name or
                parent is self.run and name in ('runtime', 'native', 'ctrl')): _fail('publication_directory')
        self.authenticate(); fd = self.fd_of(parent)
        row = {'kind': 'mkdir', 'parent': parent, 'name': name, 'attempted': True, 'returned': False}
        self.mutations.append(row)
        self.check(); os.mkdir(name, 0o700, dir_fd=fd); row['returned'] = True; self.check()
        return self.open_dir(parent, name, 0o700)

    def entry_metadata(self, value):
        meta = executor._meta(value)
        times = tuple(getattr(value, k, None) for k in ('st_mtime_ns', 'st_ctime_ns'))
        if any(type(v) is not int or not -(1 << 63) <= v < (1 << 63) for v in times): _fail('publication_metadata')
        return meta + times

    def root_entries(self):
        self.authenticate(); fd = self.fd_of(self.private_root); names = os.listdir(fd)
        if (type(names) is not list or len(names) > MAX_ENTRIES or len(set(names)) != len(names) or
                any(type(n) is not str or not n or n in ('.', '..') or '/' in n or '\0' in n for n in names)):
            _fail('publication_root_entries')
        rows = []
        for name in sorted(names):
            self.check(); before = self.entry_metadata(self._io.stat_at(fd, name))
            self.fd_of(self.private_root); self.check()
            if self.entry_metadata(self._io.stat_at(fd, name)) != before: _fail('publication_root_changed')
            rows.append((name, before))
        self.check()
        if sorted(os.listdir(self.fd_of(self.private_root))) != sorted(names): _fail('publication_root_changed')
        return tuple(rows)

    def publish(self, parent, name, raw, mode):
        if (self.attempt.phase != 'write' or type(raw) is not bytes or not 1 <= len(raw) <= MAX_IMAGE or not (
                parent is self.runtime and name in tuple(n + '.py' for n, size, sha in SOURCE_PINS) and mode == 0o400 or
                parent is self.native and name == 'mta-wpa-supplicant' and mode == 0o500 or
                parent is self.run and name == 'deployment.json' and mode == 0o400)):
            _fail('publication_write_shape')
        self.authenticate(); fd = self.fd_of(parent)
        row = {'owner': self, 'kind': 'file', 'parent': parent, 'name': name, 'mode': mode, 'fd': None,
            'metadata': None, 'identity': None, 'unknown': True, 'attempted': False, 'closed': False,
            'close_result': None, 'ebadf_error': None, 'close_error': None, 'chmod_attempted': False,
            'chmod_returned': False, 'sealed_entry': None, 'content_sha256': None}
        self.rows.append(row); self.writes.append(row)
        try:
            self.check()
            row['fd'] = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=fd)
            if type(row['fd']) is not int or row['fd'] < 0 or any(r is not row and r['fd'] == row['fd'] and not r['closed'] for r in self.rows):
                _fail('publication_fd_unknown')
            meta = executor._meta(os.fstat(row['fd']))
            row['metadata'], row['identity'] = meta, _close_identity(meta)
            if not stat.S_ISREG(meta[2]) or meta[3:6] != (0, 0, 1) or stat.S_IMODE(meta[2]) != 0o600:
                _fail('publication_write_identity')
            row['unknown'] = False; self.check(); position = 0
            while position < len(raw):
                self.authenticate(); self.fd_of(parent); self.check()
                count = os.write(row['fd'], raw[position:position + 65536]); self.check()
                if type(count) is not int or not 1 <= count <= min(65536, len(raw) - position): _fail('publication_write_result')
                position += count; actual = executor._meta(os.fstat(row['fd'])); self.check()
                if _close_identity(actual) != row['identity'] or actual[6] != position or stat.S_IMODE(actual[2]) != 0o600:
                    _fail('publication_write_changed')
                row['metadata'] = actual
            self.check(); os.fsync(row['fd']); self.check()
            self.check(); os.lseek(row['fd'], 0, 0); self.check(); parts, total = [], 0
            while total <= len(raw):
                self.check(); chunk = os.read(row['fd'], min(65536, len(raw) + 1 - total)); self.check()
                if type(chunk) is not bytes: _fail('publication_read_result')
                parts.append(chunk); total += len(chunk)
                if not chunk: break
            if b''.join(parts) != raw or executor._meta(os.fstat(row['fd'])) != row['metadata']:
                _fail('publication_write_changed')
            self.check(); row['chmod_attempted'] = True
            os.fchmod(row['fd'], mode); row['chmod_returned'] = True; self.check()
            self.check(); os.fsync(row['fd']); self.check()
            meta = executor._meta(os.fstat(row['fd'])); self.check()
            if _close_identity(meta) != row['identity'] or stat.S_IMODE(meta[2]) != mode or meta[6] != len(raw):
                _fail('publication_write_changed')
            row['metadata'] = meta
            self.authenticate()
            row['sealed_entry'] = self.entry_metadata(os.fstat(row['fd']))
            row['content_sha256'] = hashlib.sha256(raw).hexdigest()
            if self.entry_metadata(self._io.stat_at(self.fd_of(parent), name)) != row['sealed_entry']:
                _fail('publication_write_changed')
        finally:
            if not self.close_row(row): self.pending = True
        if row['closed'] is not True or row['unknown'] is not False: _fail('publication_close_unknown')

    def verify(self):
        self.authenticate(); current = self.root_entries()
        if self.entries_before is None or set(dict(current)) != set(dict(self.entries_before)) | {self.run_name}:
            _fail('publication_root_changed')
        if any(dict(current)[name] != meta for name, meta in self.entries_before): _fail('publication_root_changed')
        self.entries_after = current
        for row, names in ((self.run, ('runtime', 'native', 'ctrl', 'deployment.json')),
                           (self.runtime, tuple(n + '.py' for n, size, sha in SOURCE_PINS)),
                           (self.native, ('mta-wpa-supplicant',)), (self.ctrl, ())):
            self.authenticate()
            if sorted(os.listdir(self.fd_of(row))) != sorted(names): _fail('publication_layout_changed')
        for row in self.writes:
            self.authenticate()
            if (row['closed'] is not True or row['unknown'] is not False or row['sealed_entry'] is None or
                    self.entry_metadata(self._io.stat_at(self.fd_of(row['parent']), row['name'])) != row['sealed_entry']):
                _fail('publication_write_changed')

    def stage(self, payloads, wpa, manifest):
        if self.stage_attempted: _fail('publication_already_attempted')
        self.stage_attempted = True
        self.prepare(); self.entries_before = self.root_entries()
        if len(self.entries_before) >= MAX_ENTRIES or self.run_name in dict(self.entries_before): _fail('publication_run_exists')
        self.run = self.directory(self.private_root, self.run_name)
        self.runtime = self.directory(self.run, 'runtime')
        self.native = self.directory(self.run, 'native'); self.ctrl = self.directory(self.run, 'ctrl')
        for name, size, sha in SOURCE_PINS:
            raw = payloads[name]
            if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
                _fail('publication_pin_changed')
            self.publish(self.runtime, name + '.py', raw, 0o400)
        if type(wpa) is not bytes or len(wpa) != WPA_BYTES or hashlib.sha256(wpa).hexdigest() != WPA_SHA:
            _fail('publication_pin_changed')
        self.publish(self.native, 'mta-wpa-supplicant', wpa, 0o500)
        self.publish(self.run, 'deployment.json', manifest, 0o400)
        self.verify()
        for row in (self.runtime, self.native, self.ctrl, self.run, self.private_root):
            self.authenticate(); fd = self.fd_of(row); self.check(); os.fsync(fd); self.check(); self.fd_of(row)
        self.verify()

    def close_row(self, row):
        if (not self.attempt.close_parent_originals() or self.attempt.writer is not self or
                type(row) is not dict or row['owner'] is not self or not any(r is row for r in self.rows)):
            return False
        if row['attempted']: return row['closed'] is True and row['unknown'] is False
        if row['unknown'] or type(row['fd']) is not int: return False
        row['attempted'] = True
        try:
            actual = executor._meta(os.fstat(row['fd']))
            if row['kind'] == 'directory':
                if self.identity(os.fstat(row['fd']), row['mode']) != row['identity']: _fail('publication_close_identity')
            elif row['kind'] == 'file':
                if (_close_identity(actual) != row['identity'] or row['mode'] not in (0o400, 0o500) or not (
                        stat.S_IMODE(actual[2]) == 0o600 or row['chmod_attempted'] is True and
                        stat.S_IMODE(actual[2]) == row['mode'])): _fail('publication_close_identity')
            else: _fail('publication_close_identity')
            row['close_result'] = os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error:
                row['ebadf_error'] = error
                row['closed'] = row['close_result'] is None and type(error.errno) is int and error.errno == errno.EBADF
            if row['closed'] is not True: row['unknown'] = True
        except BaseException as error: row['close_error'], row['unknown'] = error, True
        if row['closed'] is not True: self.pending = True
        return row['closed'] is True and row['unknown'] is False

    def close(self):
        if self.close_attempted: return self.closed()
        self.close_attempted = True
        for row in reversed(self.rows):
            if not self.close_row(row): self.pending = True
        return self.closed()

    def closed(self):
        return (self.close_attempted is True and self.pending is False and
            all(r['owner'] is self and r['closed'] is True and r['unknown'] is False and
                r['attempted'] is True and r['close_result'] is None and
                isinstance(r['ebadf_error'], OSError) and r['ebadf_error'].errno == errno.EBADF and
                r['close_error'] is None for r in self.rows))


class FixedReceiveDeploymentFactory(object):
    """Pure fixed factory; live data + Loader publication, never admission.

No caller paths, IO/clock hooks, profile hashes, readiness flags or credentials
are accepted. Full positive use requires the actual State/Session/handoff
chain; a HOST component fixture cannot manufacture that permission.
"""
    def __init__(self):
        self._attempts, self._active = [], None

    def __repr__(self):
        return '<private fixed receive publication factory>'

    def __call__(self, handoff):
        if type(handoff) is not _HANDOFF_TYPE: _fail('publication_handoff')
        if self._active is not None and self._active.ended is not True: _fail('publication_inflight')
        if any(self.closed_publication_facts(self, a.handoff) is None for a in self._attempts):
            _fail('publication_previous_pending')
        if len(self._attempts) >= 32 or any(a.handoff is handoff for a in self._attempts):
            _fail('publication_already_attempted')
        attempt = _PublicationAttempt(self, handoff)
        self._attempts.append(attempt); self._active = attempt  # Before any IO.
        try:
            attempt.start()
            attempt.files = _Files(attempt)
            attempt.files.io.validate(); attempt.now()
            payloads = {}
            for name, size, sha in SOURCE_PINS:
                raw = attempt.files.read(ASSET_PHYSICAL_ROOT + '/runtime35/' + name + '.py',
                                         size, sha, private=True)[0]
                if len(raw) != size: _fail('publication_pin_changed')
                payloads[name] = raw
            attempt.payloads = payloads
            attempt.wpa = attempt.files.read(ASSET_PHYSICAL_ROOT + '/native/mta-wpa-supplicant',
                                            WPA_BYTES, WPA_SHA, private=True, binary=True)[0]
            if len(attempt.wpa) != WPA_BYTES: _fail('publication_pin_changed')
            # JSON definitions are fixed bytes; do not re-execute the running F.
            if hashlib.sha256(payloads['p011_json']).hexdigest() != executor.JSON_SHA:
                _fail('publication_source_changed')
            attempt.profile = _live_profile(attempt)
            executor._receive_directory(attempt.files.io, attempt.now, attempt.prepare_until)
            with attempt.state.lock:
                attempt.now()
                metadata = {'version': 1, 'run_token': attempt.token, 'candidate_sha': SOURCE_MANIFEST_SHA,
                    'operation_id': attempt.operation_id, 'native_epoch': attempt.epoch,
                    'operation_epoch': attempt.epoch, 'gatt_session': attempt.session_id,
                    'nonce': attempt.nonce, 'receive_consent': True}
            run = executor.ROOT + '/client-' + attempt.token
            provider = {'version': 1, 'run_token': attempt.token, 'candidate_sha': SOURCE_MANIFEST_SHA,
                'ifname': 'mta' + attempt.token[:8], 'baseline_manifest': [list(r) for r in BASELINE_MANIFEST],
                'status_manifest': attempt.profile['status_manifest'],
                'wpa_exe': executor.PHYSICAL_ROOT + '/client-' + attempt.token + '/native/mta-wpa-supplicant',
                'wpa_sha': WPA_SHA, 'python_exe': PYTHON, 'python_sha': attempt.profile['python_sha'],
                'executor_path': run + '/runtime/mta_client_executor.py', 'executor_sha': F_SHA}
            tree = {'version': 3, 'provider': provider, 'sources': [[n, sha] for n, size, sha in SOURCE_PINS],
                'connect_binding': metadata, 'receive_root': executor.RECEIVE_ROOT}
            raw = json_codec.dumps(tree, sort_keys=True).encode('utf-8')
            if not 1 <= len(raw) <= 65536 or not _same_tree(json_codec.loads(raw.decode('utf-8')), tree):
                _fail('publication_manifest_data')
            attempt.manifest_sha = hashlib.sha256(raw).hexdigest()
            attempt.phase = 'write'; attempt.writer = _Writer(attempt)
            attempt.writer.stage(payloads, attempt.wpa, raw)
            attempt.phase = 'loader'; attempt.now()
            attempt.loader = executor.DeploymentLoader(attempt.token, attempt.manifest_sha,
                _clock=attempt.now, _parent_until_v33=attempt.original_until)
            value = attempt.loader.load(); attempt.value = value
            attempt.loader.authenticate(value)
            if (type(value) is not executor.LoadedDeployment or value.modules['mta_client_executor'] is not executor or
                    value.manifest.executor_sha != F_SHA or value.connect_binding.private_metadata() != metadata):
                _fail('publication_loader')
            attempt.now(); attempt.writer.verify()
        except BaseException as error:
            attempt.failure = error
            raise
        finally:
            # Original errors/unknown inventories survive; partial trees stay.
            if attempt.files is not None: attempt.files.close()
            if attempt.writer is not None: attempt.writer.close()
            attempt.ended, attempt.phase = True, 'ended'
            self._freeze_closed(attempt)
        if attempt.closed_facts is None:
            attempt.failure = ReceivePublicationError('publication_close_unknown')
            raise attempt.failure
        try:
            attempt.now()
        except BaseException as error:
            attempt.failure = error
            raise
        attempt.success = True
        return attempt.value

    def _freeze_closed(self, attempt):
        if attempt is not self._active or attempt.ended is not True: return
        owners = []
        if attempt.files is not None:
            if (type(attempt.files) is not _Files or attempt.files.attempt is not attempt or
                    attempt.files.closed() is not True): return
            owners.append((attempt.files, tuple(attempt.files.rows)))
        if attempt.writer is not None:
            if type(attempt.writer) is not _Writer or attempt.writer.attempt is not attempt or not attempt.writer.closed(): return
            owners.append((attempt.writer, tuple(attempt.writer.rows)))
        if attempt.loader is not None:
            if type(attempt.loader) is not executor.DeploymentLoader or attempt.loader.owner is None: return
            owner = attempt.loader.owner
            if (type(owner) is not executor._ReadOwner or owner.pending or
                    any(r['unknown'] or r['closed'] is not True for r in owner.rows)): return
            owners.append((owner, tuple(owner.rows)))
        attempt.closed_owners = tuple(owners)
        attempt.closed_facts = (self, attempt.handoff, attempt, attempt.bridge, attempt.session,
                                attempt.worker, attempt.pid, attempt.closed_owners, True)

    @classmethod
    def closed_publication_facts(cls, factory, handoff):
        """Passive original publication-FD closure only; no clock/IO/Parent."""
        if cls is not FixedReceiveDeploymentFactory or type(factory) is not cls or type(handoff) is not _HANDOFF_TYPE:
            return None
        matches = [a for a in factory._attempts if a.handoff is handoff]
        if len(matches) != 1: return None
        a = matches[0]; facts = a.closed_facts
        if (type(a) is not _PublicationAttempt or a.factory is not factory or a.ended is not True or
                type(facts) is not tuple or len(facts) != 9 or facts[0] is not factory or facts[1] is not handoff or
                facts[2] is not a or facts[3] is not a.bridge or facts[4] is not a.session or
                facts[5] is not a.worker or facts[6] != a.pid or type(facts[6]) is not int or
                facts[7] is not a.closed_owners or type(facts[7]) is not tuple or facts[8] is not True or
                a.handoff.state is not a.state or a.handoff.operation is not a.operation or
                a.handoff.session is not a.session or a.handoff.worker is not a.worker): return None
        expected = [] if a.files is None else [a.files]
        if a.writer is not None: expected.append(a.writer)
        if a.loader is not None: expected.append(a.loader.owner)
        if len(expected) != len(a.closed_owners): return None
        for original, pair in zip(expected, a.closed_owners):
            if type(pair) is not tuple or len(pair) != 2 or pair[0] is not original or type(pair[1]) is not tuple:
                return None
            rows = original.rows
            if len(rows) != len(pair[1]) or any(x is not y for x, y in zip(rows, pair[1])): return None
            if original is a.files:
                if type(original) is not _Files or original.attempt is not a or not original.closed(): return None
            elif original is a.writer:
                if type(original) is not _Writer or original.attempt is not a or not original.closed(): return None
            else:
                if (type(a.loader) is not executor.DeploymentLoader or type(original) is not executor._ReadOwner or
                        original.pending or any(r['unknown'] or r['closed'] is not True for r in rows)):
                    return None
        return facts

    def status(self):
        a = self._active
        closed = all(self.closed_publication_facts(self, original.handoff) is not None
                     for original in self._attempts)
        return {'kind': 'fixed-receive-publication-v69', 'attempted': a is not None,
            'ended': a is not None and a.ended is True,
            'profile_data_collected': a is not None and a.profile is not None,
            'deployment_published': a is not None and a.success is True,
            'publication_fds_closed': closed, 'resource_pending': not closed,
            'status_authenticated': False, 'rf_admission': False, 'parent_started': False,
            'receive_available': False, 'send_available': False, 'restoration_verified': False,
            'phone_tested': False}
