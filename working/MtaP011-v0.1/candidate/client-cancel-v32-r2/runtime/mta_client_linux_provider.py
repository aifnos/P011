"""Concrete, private ARM CLIENT RF-init adapter; not a transfer capability.

Constructors are pure. Explicit methods perform bounded Linux calls only for
the current B/Owner/bridge. V26 adds trusted F-only exact CLIENT DORA ownership
and original UDP closure; no GO/SCAN, public IP/endpoint or file-transfer API.
An externally reviewed fixed manifest is required; this is not its verifier.
Unknown originals stay strongly referenced and are never blindly reclosed.
"""
import errno
import hashlib
import math
import os
import re
import signal
import socket
import stat
import struct
import sys
import threading
import time

import mta_client_baseline as baseline
import mta_client_caps_transport as caps_transport
import mta_client_coordination as coordination
import mta_client_files as files
import mta_client_proc as proc
import mta_client_process_owner as processes
import mta_client_pending as pending
import mta_client_launch_registration as launches
import mta_client_store as stores
import mta_client_tmp_alias as tmp_alias
import mta_client_two_phase_lease as phases
import mta_client_wpa_status as original_status
import mta_p2p_client_init as core
import mta_client_connection as connection
import mta_client_kernel_proof as kernel_proof
import mta_client_control_frame as control_frame
import mta_client_resource_budget as resources

ARM_READ, ARM_DIR = 0x80000 | 0x8000, 0x80000 | 0x8000 | 0x4000
MAX_ROWS = 128  # Bounded exact ledger originals, including closed caps sockets.
MAX_OBSERVERS = sum(resources.SOURCE_PROFILE.count_limit(l, 'COLLECTOR') for l in (resources.PREPARATION_NETWORK, resources.CLEANUP))
MAX_PROC_CALLS = sum(resources.SOURCE_PROFILE.count_limit(l, 'PROC_CALL') for l in (resources.PREPARATION_NETWORK, resources.CLEANUP))
MAX_FD_RECEIPTS = sum(resources.SOURCE_PROFILE.count_limit(l, 'FD_RECEIPT') for l in (resources.PREPARATION_NETWORK, resources.CLEANUP))
MAX_KERNEL_READERS = sum(resources.SOURCE_PROFILE.count_limit(l, 'KERNEL_READER') for l in (resources.PREPARATION_NETWORK, resources.CLEANUP))
MAX_CAPS_READERS = sum(resources.SOURCE_PROFILE.count_limit(l, 'CAPS_READER') for l in (resources.PREPARATION_NETWORK, resources.CLEANUP))
MAX_ASSOCIATION_RECEIPTS = 32
_NL, _GENL = struct.Struct('<IHHII'), struct.Struct('<BBH')
_CRED = struct.Struct('=iII')
_OWNERS = []  # Registered before the first action, never discarded on failure.
_KEYS = frozenset(('version', 'run_token', 'candidate_sha', 'ifname', 'baseline_manifest',
    'status_manifest', 'wpa_exe', 'wpa_sha', 'python_exe', 'python_sha',
    'executor_path', 'executor_sha'))
_REASONS = frozenset(('not_started', 'unavailable', 'invalid_manifest', 'wrong_owner',
    'deadline', 'clock_unknown', 'platform', 'resource_unknown', 'close_unknown',
    'unsafe_directory', 'file_changed', 'config_exists', 'config_unknown', 'actor_unknown',
    'baseline_changed', 'kernel_reply', 'kernel_error', 'interface_unknown',
    'ambiguous_create', 'origin_changed', 'ctrl_unknown', 'ctrl_invalid', 'prior_blocked',
    'restore_unknown', 'child_stop_unknown', 'mutation_sealed', 'interrupted', 'io_error'))


class LinuxProviderError(RuntimeError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _REASONS else 'io_error'
        RuntimeError.__init__(self, self.code)


def _fail(code):
    raise LinuxProviderError(code) from None


# Passive diagnostics: approved literal codes only, never exception text.
# Caps literals are from the pinned df6b4cf3 transport; this is not a new probe.
_DIAGNOSTIC_CAPS_CODES = frozenset(('already_attempted', 'attribute_budget',
    'attribute_flags', 'binary_format', 'bound_port', 'caps_schema', 'clock_regressed',
    'deadline', 'dump_interrupted', 'duplicate_top_attribute', 'family_abi',
    'family_attribute', 'family_group_id', 'family_group_name', 'family_missing_attribute',
    'family_name', 'family_nested_attribute', 'family_nested_duplicate',
    'family_nested_index', 'family_operation', 'fragment_budget', 'generic_header',
    'inheritable_readback', 'interrupted', 'invalid_clock', 'invalid_clock_value',
    'invalid_done', 'invalid_factory', 'invalid_phy', 'invalid_receive', 'invalid_timeout',
    'message_after_terminal', 'message_budget', 'message_flags', 'message_identity',
    'missing_caps_fields', 'netlink_error', 'netlink_overrun', 'nonzero_attribute_padding',
    'not_kernel_peer', 'os_error', 'protocol_features_format', 'receive_budget',
    'receive_control', 'receive_truncated', 'scalar_format', 'short_send',
    'socket_close_unverified', 'socket_contract', 'split_not_supported', 'timeout_readback',
    'truncated_attribute', 'truncated_message', 'unexpected_read_error',
    'unreviewed_top_attribute', 'unsupported_platform', 'wiphy_generation_changed',
    'wiphy_identity', 'wiphy_name_format', 'wrong_family'))
_DIAGNOSTIC_GROUP_CODES = {
    'core': core._CODES, 'provider': _REASONS,
    'store': stores._CODES | stores._DURABLE_CODES, 'proc': proc._CODES,
    'coord': coordination._CODES, 'files': files._CODES, 'pending': pending._CODES,
    'launch': launches._CODES, 'owner': processes._CODES, 'alias': tmp_alias._CODES,
    'baseline': baseline._CODES, 'caps': _DIAGNOSTIC_CAPS_CODES,
    'status': original_status._REASONS,
    'none': frozenset(('not_recorded',)), 'other': frozenset(('not_recorded',)),
    'not_recorded': frozenset(('not_recorded',)), 'os': frozenset(('io_error',)),
    'interrupt': frozenset(('interrupted',))}
_DIAGNOSTIC_RESTORE_SITES = frozenset(('not_recorded', 'known_locks', 'executor',
    'executor_role', 'self_actor', 'acquire', 'current', 'current_admission',
    'save_cleanup_intent', 'baseline_before_children', 'bridge_cleanup',
    'baseline_after_children', 'owned_identity', 'origin_ready_delete', 'origin_absent',
    'baseline_after_delete', 'close_resources', 'close_proof', 'restore_reader',
    'baseline_terminal', 'save_cleanup_verified', 'finish_receipt', 'complete'))
_DIAGNOSTIC_OS_ERRORS = (OSError, BlockingIOError, ChildProcessError, ConnectionError,
    BrokenPipeError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError,
    FileExistsError, FileNotFoundError, InterruptedError, IsADirectoryError,
    NotADirectoryError, PermissionError, ProcessLookupError, TimeoutError)


def _diagnostic_error(error):
    """Pure fixed tuple; issuer classification is not restoration evidence."""
    try:
        if error is None: return ('none', 'not_recorded')
        table = ((core.ClientInitError, 'core'), (LinuxProviderError, 'provider'),
            (stores.PreparationError, 'store'), (stores.DurableStoreError, 'store'),
            (proc.ProcReadError, 'proc'), (coordination.CoordinationError, 'coord'),
            (files.ClientFileError, 'files'), (pending.PendingError, 'pending'),
            (launches.LaunchRegistrationError, 'launch'),
            (processes.ProcessOwnerError, 'owner'), (tmp_alias.TmpAliasError, 'alias'),
            (baseline.BaselineError, 'baseline'), (caps_transport.CapsTransportError, 'caps'),
            (original_status.WpaStatusError, 'status'))
        for exact_type, group in table:
            if type(error) is exact_type:
                code = error.code
                return (group, code) if type(code) is str and code in _DIAGNOSTIC_GROUP_CODES[group] else ('other', 'not_recorded')
        if type(error) in _DIAGNOSTIC_OS_ERRORS: return ('os', 'io_error')
        if type(error) in (KeyboardInterrupt, SystemExit, GeneratorExit):
            return ('interrupt', 'interrupted')
    except BaseException:
        pass
    return ('other', 'not_recorded')


def _int(value, low=0, high=0xffffffff):
    return type(value) is int and low <= value <= high


def _hex(value, length):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def _path(value):
    return type(value) is str and 1 < len(value) <= 256 and value.startswith('/') and \
        all(p not in ('', '.', '..') for p in value[1:].split('/')) and \
        all(32 <= ord(c) < 127 for c in value)


class ProviderManifest(object):
    """Private immutable normalization, not producer authentication or pin proof."""
    __slots__ = tuple(_KEYS) + ('run_dir', 'ctrl_dir', 'cfg', 'identity', 'manifest_sha256')

    def __init__(self, value, _manifest_sha256=None):
        if type(value) is not dict or set(value) != _KEYS or type(value['version']) is not int or \
                value['version'] != 1 or not _hex(value['run_token'], 32) or \
                not _hex(value['candidate_sha'], 64) or not _hex(_manifest_sha256, 64) or \
                type(value['ifname']) is not str or re.fullmatch('mta[0-9a-f]{8}', value['ifname']) is None:
            _fail('invalid_manifest')
        for name in ('wpa_exe', 'python_exe', 'executor_path'):
            if not _path(value[name]): _fail('invalid_manifest')
        for name in ('wpa_sha', 'python_sha', 'executor_sha'):
            if not _hex(value[name], 64): _fail('invalid_manifest')
        if type(value['status_manifest']) is not dict or value['wpa_sha'] != core.WPA_SHA or \
                value['wpa_exe'] == value['status_manifest'].get('daemon_exe'):
            _fail('invalid_manifest')
        pins = value['baseline_manifest']
        if type(pins) not in (tuple, list) or len(pins) != 4 or any(type(r) not in (tuple, list) or
                len(r) != 2 or not _path(r[0]) or not _hex(r[1], 64) for r in pins): _fail('invalid_manifest')
        pins = tuple(tuple(r) for r in pins)
        if len(set(r[0] for r in pins)) != 4 or \
                tuple(sorted(r for r in pins if r[0] != baseline.CLI)) != tuple(sorted(core.STOCK_PINS)):
            _fail('invalid_manifest')
        status = original_status._manifest(value['status_manifest'])
        run = '/tmp/' + coordination.BASE + '/' + coordination.RUN_PREFIX + value['run_token']
        physical_wpa = tmp_alias.PHYSICAL_TMP + '/' + coordination.BASE + '/' + \
            coordination.RUN_PREFIX + value['run_token'] + '/native/mta-wpa-supplicant'
        if value['wpa_exe'] != physical_wpa: _fail('invalid_manifest')
        for name in _KEYS:
            item = pins if name == 'baseline_manifest' else tuple(sorted(status.items())) if name == 'status_manifest' else value[name]
            object.__setattr__(self, name, item)
        for name, item in (('run_dir', run), ('ctrl_dir', run + '/ctrl'), ('cfg', run + '/client.conf'),
                           ('identity', core.Identity(value['candidate_sha'])), ('manifest_sha256', _manifest_sha256)):
            object.__setattr__(self, name, item)

    def __setattr__(self, name, value): raise AttributeError('private immutable manifest')
    def __repr__(self): return '<private CLIENT provider manifest>'


class _ArmIo(original_status._LinuxIo):
    def __init__(self): self._at = files._LinuxIo()
    def validate(self):
        super(_ArmIo, self).validate()
        if getattr(os, 'O_DIRECTORY', None) != 0x4000 or getattr(os, 'O_DIRECT', None) != 0x10000:
            _fail('platform')

    def flag(self, name): return getattr(os, name)
    def open_at(self, parent, name, flags, mode=0):
        # Existing reviewed FILES binding supplies libc openat on target Python.
        return self._at.open_at(parent, name, flags, mode)
    def stat_at(self, parent, name): return os.stat(name, dir_fd=parent, follow_symlinks=False)
    def stat_root(self): return self.stat('/')
    def readlink_at(self, parent, name): return os.readlink(name, dir_fd=parent)
    def write(self, fd, raw): return os.write(fd, raw)
    def fsync(self, fd): return os.fsync(fd)
    def seek(self, fd): return os.lseek(fd, 0, 0)
    def new_genl(self): return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
    def new_ctrl(self): return socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
    def kill(self, pid): return os.kill(pid, signal.SIGTERM)
    def pid(self): return os.getpid()


class _Row(object):
    def __init__(self, kind):
        self.kind, self.value, self.fd, self.meta = kind, None, None, None
        self.close_meta = None  # Only narrowly authenticated own ctrl rmdir.
        self.returned = self.attempted = self.closed = False
        self.unknown = True

    def __repr__(self): return '<private CLIENT resource>'


class _Ledger(object):
    def __init__(self, io):
        self.io, self.rows, self.pending = io, [], False
        self._alias_context, self._alias_rows = None, []
    def _alias_identity(self, row, actual):
        matches = tuple(item for item in self._alias_rows if item[0] is row)
        if not matches: return None
        context = self._alias_context
        if len(matches) != 1 or type(context) is not tuple or len(context) != 3: _fail('unsafe_directory')
        owner, helper, root = context
        if type(helper) is not tmp_alias.FixedTmpAnchor or owner._ledger is not self or owner._io is not self.io or \
                owner._tmp_alias is not helper or not owner._anchor_chain or root is not owner._anchor_chain[0][2] or \
                helper._context[0] is not owner or helper._context[1] is not self.io or helper._context[2] is not root or \
                not any(row is item for item in self.rows) or \
                row.kind != 'file' or row.meta is None or not stat.S_ISDIR(actual[2]) or \
                actual[3:5] != (0, 0) or actual[5] < 1 or actual[:5] != matches[0][1]: _fail('unsafe_directory')
        return matches[0][1]
    def new(self, kind):
        if len(self.rows) >= MAX_ROWS: _fail('resource_unknown')
        row = _Row(kind); self.rows.append(row); return row
    def adopt(self, row, value):
        row.value, row.returned = value, True
        row.fd = value if row.kind != 'socket' else value.fileno()
        if not _int(row.fd, 3, 0x7fffffff) or any(r is not row and not r.closed and r.fd == row.fd for r in self.rows):
            self.pending = True; _fail('resource_unknown')
        row.meta = baseline._metadata(self.io.fstat(row.fd))
        row.unknown = False; return row
    def open(self, path, flags):
        row = self.new('file')
        try: value = self.io.open(path, flags)
        except OSError: row.unknown = False; row.closed = True; raise
        except BaseException: self.pending = True; raise
        try: return self.adopt(row, value)
        except BaseException: self.pending = True; raise
    def open_at(self, parent, name, flags, mode=0):
        row = self.new('file')
        try: value = self.io.open_at(parent.fd, name, flags, mode)
        except OSError: row.unknown = False; row.closed = True; raise
        except BaseException: self.pending = True; raise
        try: return self.adopt(row, value)
        except BaseException: self.pending = True; raise
    def sock(self, creator):
        row = self.new('socket')
        try: value = creator()
        except OSError: row.unknown = False; row.closed = True; raise
        except BaseException: self.pending = True; raise
        row.value, row.returned = value, True  # Before fileno or other validation.
        try: return self.adopt(row, value)
        except BaseException: self.pending = True; raise
    def ebadf(self, row):
        if row.unknown or not row.closed: return False
        if row.fd is None: return row.returned is False
        try: self.io.fstat(row.fd)
        except OSError as e: return type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: pass
        return False
    def close(self, row):
        if row.attempted or row.closed: return self.ebadf(row)
        if row.unknown or row.meta is None: self.pending = True; return False
        row.attempted = True
        try:
            now = baseline._metadata(self.io.fstat(row.fd))
            alias_identity = self._alias_identity(row, now)
            expected = alias_identity if alias_identity is not None else (row.meta[:6] if row.close_meta is None else row.close_meta)
            if now[:len(expected)] != expected: _fail('close_unknown')
            result = row.value.close() if row.kind == 'socket' else self.io.close(row.fd)
            if result is not None or row.kind == 'socket' and row.value.fileno() != -1: _fail('close_unknown')
            try: self.io.fstat(row.fd)
            except OSError as e:
                row.closed = type(e.errno) is int and e.errno == errno.EBADF
            if not row.closed: _fail('close_unknown')
        except BaseException: row.unknown = self.pending = True
        return row.closed and not row.unknown
    def close_all(self):
        good = True
        for row in self.rows:
            try: good = self.close(row) and good
            except BaseException: self.pending = True; good = False
        return good and not self.pending
    def component_closed(self, row, attempted):
        # A pinned component is the single close owner, never close it again.
        row.attempted = attempted is True
        try:
            row.closed = row.attempted and row.value.fileno() == -1
            if row.closed:
                try: self.io.fstat(row.fd); row.closed = False
                except OSError as e: row.closed = type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: row.closed = False
        if not row.closed: row.unknown = self.pending = True
        return row.closed and not row.unknown


def _attr(kind, data):
    raw = struct.pack('<HH', len(data) + 4, kind) + data
    return raw + b'\0' * (-len(raw) % 4)


def _origin(body):
    fields = {}
    for kind, flags, value, raw in caps_transport._attrs(body):
        if kind in fields: _fail('kernel_reply')
        fields[kind] = (flags, value)
    if not {1, 3, 4, 5, 153}.issubset(fields): _fail('kernel_reply')
    values = []
    for kind, width in ((1, 4), (153, 8), (3, 4), (5, 4)):
        flags, raw = fields[kind]
        if flags or len(raw) != width: _fail('kernel_reply')
        values.append(struct.unpack('<Q' if width == 8 else '<I', raw)[0])
    flags, name = fields[4]
    if flags or not 2 <= len(name) <= 16 or name[-1:] != b'\0' or b'\0' in name[:-1]: _fail('kernel_reply')
    try: text = name[:-1].decode('ascii')
    except UnicodeError: _fail('kernel_reply')
    return core.Origin(values[0], values[1], values[2], text, values[3])


def _caps_core(decoded):
    """Explicit BI constraints for CLIENT init only, not GO/association proof."""
    c = caps_transport.caps
    if type(decoded) is not c.DecodedCaps or len(decoded.phys) != 1: _fail('interface_unknown')
    phys = []
    for phy in decoded.phys:
        if type(phy) is not c.Phy or not all((phy.iftypes_present, phy.software_iftypes_present,
                phy.combinations_present, phy.commands_present)) or 7 not in phy.commands: _fail('interface_unknown')
        combinations = []
        for combo in phy.combinations:
            if type(combo) is not c.Combination or not combo.radar_widths_present or not combo.radar_regions_present:
                _fail('interface_unknown')
            if type(combo.bi_policy) is not str or not (
                    combo.bi_policy == 'all_beacons_identical' and combo.bi_min_gcd_present is False and combo.bi_min_gcd is None or
                    combo.bi_policy == 'minimum_gcd' and combo.bi_min_gcd_present is True and type(combo.bi_min_gcd) is int and combo.bi_min_gcd == 1):
                _fail('interface_unknown')
            combinations.append({'max_interfaces': combo.maximum, 'num_channels': combo.channels,
                'limits': tuple({'max': row.maximum, 'types': row.types} for row in combo.limits),
                'radar_widths': combo.radar_widths, 'radar_regions': combo.radar_regions,
                'beacon_match': combo.beacon_match,
                'bi_policy': combo.bi_policy, 'bi_min_gcd': combo.bi_min_gcd})
        phys.append({'index': phy.index, 'iftypes': phy.iftypes, 'software_iftypes': phy.software_iftypes,
            'combinations': tuple(combinations), 'unknown_constraints': ()})
    return {'complete': True, 'phys': tuple(phys)}


class _Kernel(object):
    """One owned unicast socket. CREATE must receive ECHO and matching ACK."""
    def __init__(self, provider):
        self.p, self.row, self.family, self.port, self.seq = provider, None, None, None, 0
        self.requests, self.packets = [], []  # Private bounded diagnostic bytes.
    def open(self, deadline):
        if self.row is not None: return
        self.row = self.p._ledger.sock(self.p._io.new_genl)
        raw = self.row.value; raw.set_inheritable(False)
        if raw.get_inheritable() is not False: _fail('resource_unknown')
        raw.bind((0, 0)); endpoint = raw.getsockname()
        if type(endpoint) is not tuple or len(endpoint) != 2 or not _int(endpoint[0], 1) or endpoint[1] != 0:
            _fail('kernel_reply')
        self.port = endpoint[0]
        rows = self.request(16, 3, _attr(2, b'nl80211\0'), 0, deadline)
        if len(rows) != 1: _fail('kernel_reply')
        self.family = caps_transport._family(rows[0][1])
    def reserve(self):
        if self.seq >= 0xffffffff: _fail('kernel_reply')
        self.seq += 1; return self.seq
    def request(self, family, cmd, attrs, flags, deadline, sequence=None):
        self.p._now(deadline)
        sequence = self.reserve() if sequence is None else sequence
        if sequence != self.seq or not _int(self.port, 1): _fail('kernel_reply')
        version = 2 if family == 16 else 1
        dumping = flags & 0x300 == 0x300
        request = _NL.pack(20 + len(attrs), family, 1 | flags, sequence, self.port) + _GENL.pack(cmd, version, 0) + attrs
        credit = self.p._reserve_v23('LEGACY_REQUEST', len(request))
        self.p._resource_budget_v23.started(credit)
        self.requests.append(request)
        self.p._resource_budget_v23.returned(credit, request, (request,))
        self.p._resource_budget_v23.settle(credit)
        if self.row.value.sendto(request, (0, 0)) != len(request): _fail('kernel_reply')
        result, ack, done, total = [], False, False, 0
        for unused in range(64):
            remaining = self.p._now(deadline)
            self.row.value.settimeout(remaining)
            timeout = self.row.value.gettimeout()
            if type(timeout) not in (int, float) or not 0 < timeout <= remaining + 0.000000001: _fail('kernel_reply')
            credit = self.p._reserve_v23('LEGACY_PACKET', 262144)
            budget = self.p._resource_budget_v23; budget.started(credit)
            producer_failed = False
            try:
                returned = self.row.value.recvmsg(262144)
                budget.returned(credit, returned,
                    (returned[0],) if type(returned) is tuple and len(returned) == 4 and
                    type(returned[0]) is bytes else ())
                packet, ancillary, bits, sender = returned  # After exact original retention.
            except BaseException:
                producer_failed = True
                budget.mark_unknown(credit)
                raise
            finally:
                try: budget.settle(credit)
                except BaseException:
                    if not producer_failed: raise
            self.p._now(deadline)
            if type(packet) is not bytes or not packet or ancillary or bits or type(sender) is not tuple or sender != (0, 0):
                _fail('kernel_reply')
            self.packets.append(packet); total += len(packet)
            if total > 1048576: _fail('kernel_reply')
            at = 0
            while at < len(packet):
                if len(packet) - at < 16: _fail('kernel_reply')
                n, kind, nflags, seq, port = _NL.unpack_from(packet, at); end = at + ((n + 3) & ~3)
                if n < 16 or end > len(packet) or seq != sequence or port != self.port or nflags & 16:
                    _fail('kernel_reply')
                body = packet[at + 16:at + n]; at = end
                if kind == 2:
                    if ack or len(body) < 20 or body[4:20] != request[:16]: _fail('kernel_reply')
                    code = struct.unpack_from('<i', body)[0]
                    if code > 0 or code < -4095: _fail('kernel_reply')
                    if code: _fail('kernel_error')
                    if not flags & 4: _fail('kernel_reply')
                    ack = True
                elif kind == 3:
                    if done or not dumping or body not in (b'', b'\0' * 4): _fail('kernel_reply')
                    done = True
                else:
                    if kind != family or len(body) < 4 or body[1:4] != bytes((version, 0, 0)): _fail('kernel_reply')
                    result.append((body[0], body[4:]))
            if dumping:
                if done: return result
            elif flags & 8:
                if ack and len(result) == 1: return result
                if len(result) > 1: _fail('ambiguous_create')
            elif flags & 4:
                if ack and not result: return result
                if result: _fail('kernel_reply')
            elif len(result) == 1: return result
        _fail('kernel_reply')
    def interfaces(self, deadline):
        self.open(deadline)
        rows = self.request(self.family, 5, b'', 0x300, deadline)
        if not rows or len(rows) > 32 or any(cmd != 7 for cmd, body in rows): _fail('kernel_reply')
        result = tuple(_origin(body) for cmd, body in rows)
        for getter in (lambda r: r.name, lambda r: r.wdev, lambda r: r.ifindex):
            if len(set(getter(r) for r in result)) != len(result): _fail('kernel_reply')
        return result


class _ObservationIo(_ArmIo):
    """Only same-owner issued controller may be excluded from stock enumeration."""
    def __init__(self, provider, _deadline_owner=None):
        self.p, self._deadline_owner_v25 = provider, _deadline_owner
    def listdir(self, path):
        owner = object.__getattribute__(self, '_deadline_owner_v25')
        deadline = None
        if path == '/proc' and owner is not None:
            if type(owner) not in (_AuthenticatedCollector, original_status.AuthenticatedStatusReader):
                _fail('actor_unknown')
            if type(owner) is _AuthenticatedCollector:
                if owner.p is not self.p or owner._io is not self: _fail('actor_unknown')
            elif owner._io is not self or type(owner._source) is not original_status.LinuxStatusSource or \
                    owner._source._io is not self or owner._source._consumer not in (None, owner):
                _fail('actor_unknown')
            deadline = getattr(owner, '_deadline', None)  # Established producer cap, never now + remaining.
            if type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or not math.isfinite(float(deadline)):
                _fail('actor_unknown')
            self.p._now(deadline)
        names = self.p._io.listdir(path)
        if path != '/proc': return names
        if type(names) not in (list, tuple) or len(names) > 4096 or any(type(name) is not str for name in names):
            _fail('actor_unknown')
        excluded = self.p._private_pids(deadline)
        return [name for name in names if name not in excluded]
    def __getattribute__(self, name):
        if name in ('p', '_deadline_owner_v25', 'listdir', '__class__', '__dict__', '__getattribute__', 'validate'):
            return object.__getattribute__(self, name)
        return getattr(object.__getattribute__(self, 'p')._io, name)
    def validate(self): return self.p._io.validate()


class _AuthenticatedCollector(baseline.BaselineCollector):
    def __init__(self, provider, timeout):
        self.p, self.status_readers = provider, []
        super(_AuthenticatedCollector, self).__init__(provider.manifest.baseline_manifest,
            timeout=timeout, _io=_ObservationIo(provider, self), _clock=provider._clock,
            _reader=provider._new_proc_v24(timeout=timeout, _clock=provider._clock))
    def _open(self, path, flags=None):
        return super(_AuthenticatedCollector, self)._open(path, ARM_READ if flags is None else flags)
    def _status(self, unused_executable):
        remaining = self._deadline - self._now()
        if remaining < 0.1: _fail('deadline')
        row = {'reader': None, 'unknown': True, 'value': None}; self.status_readers.append(row)
        observation_io = _ObservationIo(self.p)
        source = original_status.LinuxStatusSource(dict(self.p.manifest.status_manifest),
            _io=observation_io, _clock=self.p._clock,
            _proc_reader=self.p._new_proc_v24(timeout=min(3, remaining), _clock=self.p._clock))
        row['source'] = source
        reader = self.p._status_factory(dict(self.p.manifest.status_manifest), source,
            timeout=min(3, remaining), _io=observation_io, _clock=self.p._clock)
        row['reader'] = reader
        observation_io._deadline_owner_v25 = reader  # Exact actual owner before any read_source call.
        result = reader.read_status(self._deadline); row['value'] = result
        state = reader.status()
        if type(result) is not dict or reader._result is not result or result.get('source_authenticated') is not True or \
                result.get('completed') is not True or not _int(result.get('frequency'), 2412, 2484) or \
                state.get('read_success') is not True or state.get('resource_pending') is not False or \
                state.get('socket_closed') is not True: _fail('baseline_changed')
        row['unknown'] = False
        return result['digest'], result['frequency']


class LinuxClientInitProvider(phases.TwoPhaseClientInitProvider):
    """Explicit trusted adapter; default manifest=None cannot perform actions."""
    _diagnostic_error = staticmethod(_diagnostic_error)
    def __init__(self, manifest=None, _io=None, _proc_factory=None, _collector_factory=None,
                 _status_factory=None, _caps_factory=None, _clock=None, _kernel_factory=None,
                 _connect_binding=None):
        if manifest is not None and type(manifest) is not ProviderManifest: _fail('invalid_manifest')
        if _connect_binding is not None and (type(_connect_binding) is not control_frame.ControlBinding or manifest is None or
                _connect_binding.private_metadata()['run_token'] != manifest.run_token or
                _connect_binding.private_metadata()['candidate_sha'] != manifest.candidate_sha): _fail('wrong_owner')
        self._connect_binding = _connect_binding
        self._connect_wire = None if _connect_binding is None else _connect_binding._wire
        self._connection_creation = None
        self._connection_last_context = None
        self._connection_issued_context = None
        self._association_receipts, self._active_association_receipt = [], None
        self._dora_v21_registration, self._dora_v26_creation = None, None
        self.manifest = manifest
        self._io, self._clock = _io or _ArmIo(), _clock or time.monotonic
        self._proc_factory = _proc_factory or proc.ProcReader
        self._collector_factory = _collector_factory or _AuthenticatedCollector
        self._status_factory = _status_factory or original_status.AuthenticatedStatusReader
        self._caps_factory = _caps_factory or caps_transport.ClientCapsReader
        self._kernel_factory = _kernel_factory or kernel_proof.ClientKernelReader
        self._kernel_readers = []  # Before-construction tickets; never discarded.
        self.cancelled = threading.Event()
        self._ledger, self._kernel = _Ledger(self._io), _Kernel(self)
        self._store = self._owner = self._bridge = self._lease = None
        self._owner_proc_reader_v24 = None
        self._self = self._boot = self._baseline_record = self._owned = self._intent = None
        self._proc_calls, self._collectors, self._caps_readers = [], [], []
        self._proc_readers_v24 = []  # Before-construction rows; never retired.
        self._tickets, self._prior, self._restores = {}, [], []
        self._run_anchor = self._ctrl_anchor = self._config = None
        self._anchor_chain, self._anchor_requested = [], False
        self._tmp_alias, self._anchor_deadline = None, None
        self._ctrl_deinit_observation = None
        self._fd_receipts = []
        self._ctrl = None
        self._connection = self._connection_event = self._connection_event_endpoint = None
        self._connection_event_requested = False
        self._ctrl_setup = self._ctrl_failed = self._ctrl_receive_unknown = False
        self._ctrl_incoming, self._ctrl_rights = [], []
        self._last = self._deadline = None
        self._started = self._sealed = self._close_requested = self._unknown = False
        self._create_requested = self._delete_requested = False
        self._reason = 'not_started'
        self._session_launch_v28 = None
        self._client_ip_owner_v28 = None
        self._client_peer_owner_v29 = None
        self._client_transfer_owner_v30 = None
    def __repr__(self): return '<private Linux CLIENT provider>'
    def _now(self, deadline=None):
        value = self._clock()
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)) or \
                self._last is not None and value < self._last: _fail('clock_unknown')
        self._last = float(value)
        if deadline is None: return float(value)
        if type(deadline) not in (int, float) or not math.isfinite(float(deadline)) or not 0 < deadline - value:
            _fail('deadline')
        remaining = float(deadline - value)
        if remaining > 20:
            store, lease = self._store, self._lease
            record = None if lease is None else lease.record
            canonical = None if store is None else store._canonical
            profile = None if store is None else store._session_profile
            if (profile is not core.FORMAL_SESSION_PROFILE or
                    store._session_profile_original_v28 is not profile or
                    type(record) is not core.Journal or canonical is None or
                    not core._same_journal(record, canonical.journal) or
                    record.session_profile != profile.name or record.deadline != deadline or
                    not record.issued_at <= value < record.deadline or
                    not 0 < record.deadline - record.issued_at <= profile.max_active_seconds or
                    record.stage in ('cleanup_intent', 'cleanup_verified', 'reconciled')):
                _fail('deadline')
            try:
                if (store.session_issued_v28(record, profile, deadline) is not True or
                        store._trusted_active_deadline_v28(deadline, value) != deadline): _fail('deadline')
            except Exception: _fail('deadline')
        # Validate the ORIGINAL active period above; peer IO only tightens it.
        remaining = min(remaining, self._peer_io_until_v29(deadline) - value)
        if remaining <= 0: _fail('deadline')
        return min(remaining, 20.0)
    def _peer_io_until_v29(self, deadline):
        """Pure native registered reader scope; never changes Journal/RF until."""
        if type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or not math.isfinite(float(deadline)):
            _fail('deadline')
        value = self._client_peer_owner_v29
        result = float(deadline)
        if value is not None:
            import mta_client_peer as peer
            if (type(value) is not peer.ClientPeerReader or value.provider is not self or
                    value.store is not self._store or value.lease is not self._lease):
                _fail('wrong_owner')
            result = peer.ClientPeerReader._io_until_for_provider(value, self, result)
        return self._transfer_io_until_v30(result)
    def _transfer_io_until_v30(self, deadline):
        value = self._client_transfer_owner_v30
        if value is None: return float(deadline)
        import mta_client_transfer as transfer
        if (type(value) is not transfer.ClientTransferOwner or value.provider is not self or
                value.store is not self._store or value.lease is not self._lease):
            _fail('wrong_owner')
        return transfer.ClientTransferOwner._io_until_for_provider(value, self, deadline)
    def _begin(self, deadline, mutating=False, allow_pending=False):
        if self.manifest is None or self._store is None: _fail('unavailable')
        if mutating and self._sealed: _fail('mutation_sealed')
        if not allow_pending and (not self._proc_namespace_registered_v24() or self._unknown or self._ledger.pending or self._ctrl_receive_unknown or any(r['unknown'] for r in
                self._proc_calls + self._collectors + self._caps_readers + self._kernel_readers + self._proc_readers_v24)): _fail('resource_unknown')
        self._now(deadline); self._deadline = self._peer_io_until_v29(deadline)
        if not self._started:
            if len(_OWNERS) >= 1 and not any(p is self for p in _OWNERS): _fail('resource_unknown')
            _OWNERS.append(self); self._started = True
            self._io.validate()
        if mutating and self._store.lock_valid(self._store._current_locks) is not True: _fail('wrong_owner')
    def attach(self, store, owner, bridge, lease=None):
        if self._store is not None or type(store) is not stores.DurableClientInitStore or \
                type(owner) is not processes.DirectChildOwner or type(bridge) is not LinuxDirectChildLaunchBridge or \
                bridge.store is not store or bridge.owner is not owner or bridge.provider is not self or \
                store._identity.key() != self.manifest.identity.key() or lease is not None and \
                (type(lease) is not LinuxClientInitLease or lease.provider is not self or lease.store is not store or lease.bridge is not bridge):
            _fail('wrong_owner')
        self._store, self._owner, self._bridge, self._lease = store, owner, bridge, lease
        self._owner_proc_reader_v24 = owner._reader  # Preserve even a failed bind original.
        store._resource_budget_v23.bind_provider(self)
        self._bind_proc_v24(owner._reader)
    def _bind_proc_v24(self, reader):
        if type(reader) is not proc.ProcReader or self._store is None: _fail('actor_unknown')
        budget = self._store._resource_budget_v23
        if reader._resource_budget_v24 is budget:
            if not any(r is reader for r in budget._readers): _fail('actor_unknown')
        else:
            budget.bind_reader(reader)
        return reader
    def _new_proc_v24(self, **kwargs):
        if self._store is None or getattr(self, '_resource_budget_v23', None) is not self._store._resource_budget_v23:
            _fail('wrong_owner')
        lane = self._store._resource_lane_v23
        if sum(old['lane'] == lane for old in self._proc_readers_v24) >= resources.SOURCE_PROFILE.count_limit(lane, 'PROC_GENERATION'):
            _fail('actor_unknown')
        row = {'reader': None, 'returned': False, 'unknown': True, 'lane': lane}
        self._proc_readers_v24.append(row)  # Retain even a malformed factory return.
        reader = self._proc_factory(**kwargs)
        row['reader'], row['returned'] = reader, True
        if any(old is not row and old['reader'] is reader for old in self._proc_readers_v24):
            _fail('actor_unknown')
        if type(reader) is not proc.ProcReader or reader._resource_budget_v24 is not None:
            _fail('actor_unknown')  # New factories cannot silently borrow an older reader.
        self._bind_proc_v24(reader)
        row['unknown'] = False
        return reader
    def specs(self, _until=None):
        if self.manifest is None: _fail('unavailable')
        if _until is None and self._session_launch_v28 is not None:
            return self._session_launch_v28['specs']
        m = self.manifest
        text = '0.0' if _until is None else str(float(_until))
        return (processes.LaunchSpec('watchdog', m.python_exe,
            (m.python_exe, '-B', m.executor_path, '--watchdog', '--run-token', m.run_token,
             '--manifest-sha256', m.manifest_sha256, '--until', text), (), m.python_sha),
            processes.LaunchSpec('controller', m.wpa_exe,
            (m.wpa_exe, '-Dnl80211', '-i' + m.ifname, '-c' + m.cfg, '-C' + m.ctrl_dir),
            (('MTA_PRIVATE_P2P', '1'),), m.wpa_sha))
    def session_specs(self, record):
        with self._store._mutex:
            if self._session_launch_v28 is not None: _fail('wrong_owner')
            profile = core._session_profile(self._store._session_profile)
            if (type(record) is not core.Journal or record is not self._lease.record or
                    self._store._canonical is None or
                    not core._same_journal(record, self._store._canonical.journal) or
                    record.stage != 'prepared' or record.session_profile != profile.name or
                    self._store.session_issued_v28(record, profile, record.deadline) is not True or
                    record.identity.key() != self.manifest.identity.key() or
                    not record.issued_at <= self._now() < record.deadline): _fail('wrong_owner')
            specs = self.specs(record.deadline)
            self._session_launch_v28 = {'record': record, 'store': self._store,
                'epoch': self._store._epoch, 'profile': profile,
                'issued_at': record.issued_at, 'until': record.deadline, 'specs': specs}
            return specs
    def _observe(self, pid=None, expected=None, absence=False, _absolute_deadline=None):
        deadline = self._deadline
        if _absolute_deadline is not None:
            if type(_absolute_deadline) not in (int, float) or not 0 <= _absolute_deadline < 1e12 or \
                    not math.isfinite(float(_absolute_deadline)): _fail('deadline')
            deadline = min(deadline, _absolute_deadline)
        if len(self._proc_calls) >= MAX_PROC_CALLS: _fail('actor_unknown')
        row = {'reader': None, 'value': None, 'unknown': True}; self._proc_calls.append(row)
        reader = self._new_proc_v24(timeout=min(3, self._now(deadline)), _clock=self._clock)
        row['reader'] = reader
        value = (reader.read_absence(expected, self._boot, _absolute_deadline=deadline) if absence else
            reader.read_self(_absolute_deadline=deadline) if pid is None else
            reader.read_actor(pid, expected, _absolute_deadline=deadline))
        row['value'] = value
        # Resource state is separate from an opaque/non-live actor result.
        if type(value) is proc.ProcObservation and value.resource_pending is False and \
                value.closed_count == value.file_count and self._remember_proc(reader, value):
            row['unknown'] = False
        if type(value) is not proc.ProcObservation or value.resource_pending is not False or value.same_boot is not True or \
                value.passes != 2 or value.closed_count != value.file_count: _fail('actor_unknown')
        if not absence and (value.kind != 'live_actor' or type(value.actor) is not core.Actor or not value.actor.live()):
            _fail('actor_unknown')
        if self._boot is not None and value.boot != self._boot: _fail('actor_unknown')
        row['unknown'] = False; return value
    def executor(self, deadline):
        self._begin(deadline)
        value = self._observe()
        if len(value.actor.tasks) != 1 or value.actor.pid != self._io.pid(): _fail('actor_unknown')
        if self._self is None: self._self, self._boot = value.actor, value.boot
        if value.actor.key() != self._self.key(): _fail('wrong_owner')
        return core.ExecutorProof('owner', value.actor, False)
    def _private_pids(self, _absolute_deadline=None):
        if _absolute_deadline is not None: self._now(_absolute_deadline)
        if self._owner is None: return ()
        result = []
        for child in self._owner._tickets:
            if child.spec.role != 'controller' or child.postexec is None: continue
            self._owner._exact(child)
            if child.waited:
                if child.exit_verified is not True: _fail('actor_unknown')
                continue
            if child.unknown or child.spec.exe != self.manifest.wpa_exe or child.spec.sha != self.manifest.wpa_sha:
                _fail('actor_unknown')
            observed = self._observe(child.pid, child.postexec, _absolute_deadline=_absolute_deadline)
            if observed.actor.key() != child.postexec.key(): _fail('actor_unknown')
            result.append(str(child.pid))
        return tuple(result)
    def snapshot(self, deadline):
        self._begin(deadline)
        if len(self._collectors) >= MAX_OBSERVERS: _fail('resource_unknown')
        row = {'reader': None, 'value': None, 'unknown': True}; self._collectors.append(row)
        reader = self._collector_factory(self, min(5, self._now(deadline))); row['reader'] = reader
        value = reader.collect(deadline); row['value'] = value
        state = reader.status()
        if type(value) is not core.Snapshot or state.get('read_success') is not True or \
                state.get('resource_pending') is not False or state.get('closed_count') != state.get('resource_count'):
            _fail('baseline_changed')
        if any(r is not row and r['value'] is value for r in self._collectors): _fail('baseline_changed')
        if self._boot is not None and value.boot != self._boot: _fail('baseline_changed')
        if self._baseline_record is None: self._baseline_record = value
        if not self._remember_collector(reader): _fail('close_unknown')
        row['unknown'] = False; return value
    def caps(self, deadline):
        self._begin(deadline)
        if self._baseline_record is None or len(self._caps_readers) >= MAX_CAPS_READERS: _fail('interface_unknown')
        row = {'reader': None, 'value': None, 'unknown': True, 'socket': None}; self._caps_readers.append(row)
        def creator(family, kind, protocol):
            if (family, kind, protocol) != (16, 3, 16) or row['socket'] is not None: _fail('interface_unknown')
            claimed = self._ledger.sock(self._io.new_genl); row['socket'] = claimed
            return claimed.value
        reader = self._caps_factory(self._baseline_record.station.phy, timeout=min(5, self._now(deadline)),
            clock=self._clock, socket_factory=creator)
        row['reader'] = reader
        try: value = reader.read(); row['value'] = value
        finally:
            if row['socket'] is not None:
                self._ledger.component_closed(row['socket'], reader._finished and reader._created)
                if row['socket'].closed: self._remember(self._io, row['socket'].fd, row['socket'])
        state = reader.status()
        if type(value) is not caps_transport.caps.DecodedCaps or state.get('read_success') is not True or state.get('socket_closed') is not True or \
                state.get('resource_pending') is not False: _fail('interface_unknown')
        row['unknown'] = False
        result = _caps_core(value)
        core.client_combo(result, self._baseline_record)
        return result
    def original_actors(self, baseline_value, deadline):
        self._begin(deadline)
        if type(baseline_value) is not core.Snapshot: _fail('baseline_changed')
        for actor in baseline_value.stock_actors:
            if self._observe(actor.pid, actor).actor.key() != actor.key(): _fail('actor_unknown')
        return True
    def register(self, role, identity, boot, deadline):
        self._begin(deadline, True)
        if type(identity) is not core.Identity or identity.key() != self.manifest.identity.key() or \
                boot != self._boot or role not in ('watchdog', 'controller') or role in self._tickets: _fail('wrong_owner')
        if role == 'controller': self._prepare_config(deadline)
        spec = next(s for s in self.specs() if s.role == role)
        ticket = core.Ticket(self.manifest.run_token, role, boot, spec.exe, spec.argv_sha)
        self._tickets[role] = ticket; return ticket
    def _anchors(self, deadline):
        self._anchor_deadline = deadline
        if self._anchor_requested:
            if self._ctrl_anchor is None: _fail('unsafe_directory')
            return self._verify_anchors(deadline)
        self._anchor_requested = True
        root = self._ledger.open('/', ARM_DIR)
        if not stat.S_ISDIR(root.meta[2]) or root.meta[3:5] != (0, 0) or root.meta[2] & 0o022:
            _fail('unsafe_directory')
        self._anchor_chain.append((None, '/', root))
        current = root
        if stat.S_ISLNK(baseline._metadata(self._io.stat_at(root.fd, 'tmp'))[2]):
            self._tmp_alias = tmp_alias.FixedTmpAnchor(self, self._io, root,
                self._alias_fd, self._alias_open, self._alias_check)
            self._ledger._alias_context = (self, self._tmp_alias, root)
            self._register_alias_directory(root, None, '/')
            self._tmp_alias.prepare()
            current = self._tmp_alias.tmp_parent
        for name, private in (('tmp', False), (coordination.BASE, True),
                              (coordination.RUN_PREFIX + self.manifest.run_token, True), ('ctrl', True)):
            self._now(deadline)
            before = baseline._metadata(self._io.stat_at(current.fd, name))
            child = self._ledger.open_at(current, name, ARM_DIR)
            mode = stat.S_IMODE(child.meta[2])
            self._anchor_chain.append((current, name, child))
            if before != child.meta or not stat.S_ISDIR(child.meta[2]) or child.meta[3:5] != (0, 0) or \
                    private and mode != 0o700 or not private and mode & 0o022 and not mode & stat.S_ISVTX:
                _fail('unsafe_directory')
            if name == 'tmp' and self._tmp_alias is not None:
                self._register_alias_directory(child, current, name)
                self._tmp_alias.bind_tmp(child)
            if name == coordination.RUN_PREFIX + self.manifest.run_token: self._run_anchor = child
            current = child
        self._ctrl_anchor = current
        self._verify_anchors(deadline)
    def _verify_anchors(self, deadline):
        self._anchor_deadline = deadline
        if len(self._anchor_chain) != 5 or self._ctrl_anchor is None: _fail('unsafe_directory')
        if self._tmp_alias is not None:
            self._tmp_alias.authenticate(self, self._anchor_chain[0][2])
        for parent, name, row in self._anchor_chain:
            self._now(deadline)
            actual = baseline._metadata(self._io.fstat(row.fd))
            path = self._io.stat('/') if parent is None else self._io.stat_at(parent.fd, name)
            width = 5 if self._ledger._alias_identity(row, actual) is not None else 6
            if row.unknown or row.closed or actual[:width] != row.meta[:width] or \
                    baseline._metadata(path)[:width] != row.meta[:width]: _fail('unsafe_directory')
    def _alias_check(self): self._now(self._anchor_deadline)
    def _alias_fd(self, row):
        if not any(row is original for original in self._ledger.rows) or row.unknown or row.closed or \
                row.meta is None:
            _fail('unsafe_directory')
        actual = baseline._metadata(self._io.fstat(row.fd))
        width = 5 if self._ledger._alias_identity(row, actual) is not None else 6
        if actual[:width] != row.meta[:width]: _fail('unsafe_directory')
        return row.fd
    def _register_alias_directory(self, row, parent, name):
        helper = self._tmp_alias
        if type(helper) is not tmp_alias.FixedTmpAnchor or not self._anchor_chain: _fail('unsafe_directory')
        root = self._anchor_chain[0][2]
        prefix = helper.prefix_tickets
        allowed = parent is None and name == '/' and row is root or \
            parent is root and name == 'var' and not prefix or \
            len(prefix) == 1 and parent is prefix[0] and name == 'volatile' or \
            len(prefix) == 2 and parent is helper.tmp_parent and name == 'tmp'
        if not allowed or len(self._ledger._alias_rows) >= 4 or any(row is item[0] for item in self._ledger._alias_rows) or \
                not any(row is item for item in self._ledger.rows) or row.unknown or row.closed or row.meta is None or \
                not stat.S_ISDIR(row.meta[2]) or row.meta[3:5] != (0, 0) or row.meta[5] < 1: _fail('unsafe_directory')
        self._ledger._alias_rows.append((row, row.meta[:5]))
        self._ledger._alias_identity(row, baseline._metadata(self._io.fstat(row.fd)))
    def _alias_open(self, parent, name):
        if self._tmp_alias is None or not (parent is self._anchor_chain[0][2] and name == 'var' or
                self._tmp_alias.prefix_tickets and parent is self._tmp_alias.prefix_tickets[0] and name == 'volatile'):
            _fail('unsafe_directory')
        self._alias_fd(parent)
        row = self._ledger.open_at(parent, name, ARM_DIR)
        self._register_alias_directory(row, parent, name)
        return row
    def _prepare_config(self, deadline):
        if self._config is not None or self._owned is None: _fail('config_unknown')
        self._anchors(deadline)
        payload = b'ctrl_interface=' + self.manifest.ctrl_dir.encode('ascii') + b'\n' + core.CLIENT_CONFIG
        try: row = self._ledger.open_at(self._run_anchor, 'client.conf', ARM_READ | 1 | 0x40 | 0x80, 0o600)
        except OSError as e:
            if e.errno == errno.EEXIST: _fail('config_exists')
            raise
        self._config = row
        if not stat.S_ISREG(row.meta[2]) or row.meta[3] != 0 or row.meta[5] != 1 or stat.S_IMODE(row.meta[2]) != 0o600:
            _fail('config_unknown')
        if self._io.write(row.fd, payload) != len(payload) or self._io.fsync(row.fd) is not None: _fail('config_unknown')
        # Exact readback uses a separate original read FD, never reuses write-only.
        readback = self._ledger.open_at(self._run_anchor, 'client.conf', ARM_READ)
        if self._io.read(readback.fd, len(payload) + 1) != payload or self._io.read(readback.fd, 1) != b'': _fail('config_unknown')
        if baseline._metadata(self._io.fstat(readback.fd))[:7] != baseline._metadata(self._io.fstat(row.fd))[:7]:
            _fail('config_unknown')
        row.meta = baseline._metadata(self._io.fstat(row.fd)); readback.meta = baseline._metadata(self._io.fstat(readback.fd))
        read_ok = self._ledger.close(readback); write_ok = self._ledger.close(row)
        if not read_ok or not write_ok: _fail('close_unknown')
        if self._io.fsync(self._run_anchor.fd) is not None: _fail('config_unknown')
        self._verify_anchors(deadline)
    def register_interface(self, identity, baseline_value, deadline):
        self._begin(deadline, True)
        if self._intent is not None or identity.key() != self.manifest.identity.key() or baseline_value.boot != self._boot:
            _fail('wrong_owner')
        rows = self._kernel.interfaces(deadline)
        if any(r.name == self.manifest.ifname for r in rows) or \
                tuple(sorted(r.key() for r in rows)) != tuple(sorted(r.key() for r in baseline_value.interfaces)):
            _fail('baseline_changed')
        seq = self._kernel.reserve()
        self._intent = core.InterfaceTicket(self._boot, baseline_value.station.phy, self.manifest.ifname, seq, self._kernel.port)
        return self._intent
    def create_client(self, ticket, deadline):
        self._begin(deadline, True)
        if ticket is not self._intent or self._create_requested: _fail('wrong_owner')
        self._create_requested = True
        attrs = _attr(1, struct.pack('<I', ticket.phy)) + _attr(5, struct.pack('<I', 8)) + _attr(4, ticket.name.encode('ascii') + b'\0')
        rows = self._kernel.request(self._kernel.family, 7, attrs, 4 | 8 | 0x600, deadline, ticket.sequence)
        if len(rows) != 1 or rows[0][0] != 7: _fail('ambiguous_create')
        owned = _origin(rows[0][1]); self._owned = owned  # Save before postchecks.
        if (owned.name, owned.phy, owned.iftype) != (ticket.name, ticket.phy, 8) or any(
                owned.name == r.name or owned.ifindex == r.ifindex or owned.wdev == r.wdev for r in self._baseline_record.interfaces):
            _fail('ambiguous_create')
        if not self._origin_exact(owned, deadline): _fail('origin_changed')
        return owned
    def _origin_exact(self, owned, deadline):
        if type(owned) is not core.Origin or owned is not self._owned or owned.iftype != 8: _fail('wrong_owner')
        rows = tuple(r for r in self._kernel.interfaces(deadline) if
            r.name == owned.name or r.ifindex == owned.ifindex or r.wdev == owned.wdev)
        return len(rows) == 1 and rows[0].key() == owned.key()
    def origin_up(self, owned, deadline):
        self._begin(deadline)
        if not self._origin_exact(owned, deadline): return False
        row = self._ledger.open('/sys/class/net/' + owned.name + '/flags', ARM_READ)
        try:
            raw = self._io.read(row.fd, 32)
            if type(raw) is not bytes or re.fullmatch(br'0x[0-9a-f]+\n', raw) is None: _fail('origin_changed')
            return bool(int(raw, 16) & 1)
        finally:
            if not self._ledger.close(row): _fail('close_unknown')
    def live_actor(self, handle, deadline):
        self._begin(deadline); self._handle(handle)
        return self._observe(handle.actor.pid, handle.actor).actor
    def _handle(self, handle):
        if type(handle) is not core.Handle or handle.ticket is not self._tickets.get(handle.ticket.role) or \
                not any(c is handle.resource for c in self._owner._tickets) or handle.resource.postexec is None or \
                handle.resource.postexec.key() != handle.actor.key(): _fail('wrong_owner')
        self._owner._exact(handle.resource); return handle.resource
    def status(self, handle=None, owned=None, deadline=None):
        if handle is None:
            return {'provider_implemented': True, 'attempted': self._started, 'mutation_sealed': self._sealed,
                'resource_pending': self._proc_history_pending_v24() or
                    self._unknown or self._ledger.pending or any(r['unknown'] for r in
                    self._proc_calls + self._collectors + self._caps_readers + self._kernel_readers +
                    self._proc_readers_v24), 'reason': self._reason,
                'orphan_recovery': False, 'send_available': False, 'receive_available': False}
        self._begin(deadline); child = self._handle(handle)
        if child.spec.role != 'controller' or not self._origin_exact(owned, deadline): _fail('ctrl_unknown')
        self.live_actor(handle, deadline)
        return self._control(handle, owned, deadline)
    def _control(self, handle, owned, deadline):
        if self._ctrl_failed: _fail('ctrl_unknown')
        self._verify_anchors(deadline)
        if not self._ctrl_setup:
            self._ctrl_setup = True
            try:
                self._ctrl = self._ledger.sock(self._io.new_ctrl)
                raw = self._ctrl.value; raw.set_inheritable(False)
                if raw.get_inheritable() is not False: _fail('ctrl_unknown')
                raw.setsockopt(1, 16, 1)
                if raw.getsockopt(1, 16) != 1: _fail('ctrl_unknown')
                local = b'\0p011-client-' + self.manifest.run_token.encode('ascii')
                raw.bind(local)
                if raw.getsockname() != local: _fail('ctrl_unknown')
                endpoint = self.manifest.ctrl_dir + '/' + owned.name
                before = baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, owned.name))
                # Fixed 2.12 ctrl_iface_unix.c chmods interface sockets 0770.
                # This exception is ONLY root:root under the exact 0700 chain.
                if not stat.S_ISSOCK(before[2]) or before[3:5] != (0, 0) or \
                        stat.S_IMODE(before[2]) != 0o770 or before[5] != 1: _fail('ctrl_unknown')
                raw.connect(endpoint)
                if raw.getpeername() != endpoint: _fail('ctrl_unknown')
                self._ctrl_endpoint = (endpoint, before, local)
            except BaseException:
                self._ctrl_failed = True; raise
        raw = self._ctrl.value
        endpoint, before, local = self._ctrl_endpoint
        try:
            if baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, owned.name)) != before or \
                    raw.getpeername() != endpoint or raw.getsockname() != local: _fail('ctrl_unknown')
            remaining = min(2, self._now(deadline)); raw.settimeout(remaining)
            actual = raw.gettimeout()
            if type(actual) not in (int, float) or not 0 < actual <= remaining + 1e-9: _fail('ctrl_unknown')
            if raw.send(b'STATUS') != 6: _fail('ctrl_unknown')
            self._ctrl_receive_unknown = True
            value = raw.recvmsg(2049, self._io.cmsg_space(_CRED.size) + self._io.cmsg_space(16 * 4), 0x40000000)
            self._ctrl_incoming.append(value)  # Before unpack/flags/FD interpretation.
            if type(value) is not tuple or len(value) != 4: _fail('ctrl_unknown')
            packet, ancillary, flags, address = value
            credential = self._ctrl_controls(ancillary)
            self._now(deadline)
            if type(flags) is not int or flags & (8 | 32) or flags not in (0, 0x40000000):
                self._ctrl_receive_unknown = True; _fail('ctrl_unknown')
            if type(packet) is not bytes or not 1 <= len(packet) <= 2048 or \
                    credential != (handle.actor.pid, 0, 0) or address not in (endpoint, endpoint.encode('ascii')):
                _fail('ctrl_unknown')
            self._verify_anchors(deadline)
            if baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, owned.name)) != before or \
                    raw.getpeername() != endpoint or raw.getsockname() != local: _fail('ctrl_unknown')
            self.live_actor(handle, deadline); core.parse_init_status(packet)
            return packet
        except BaseException:
            self._ctrl_failed = True; raise
        finally:
            # Rights are rejected, but known installed originals still close.
            for row in self._ctrl_rights:
                self._ledger.close(row)
    def _ctrl_controls(self, controls):
        if type(controls) not in (tuple, list) or len(controls) > 16: _fail('ctrl_unknown')
        credentials, invalid, rights = [], False, False
        for item in controls:
            if type(item) is not tuple or len(item) != 3 or type(item[0]) is not int or \
                    type(item[1]) is not int or type(item[2]) is not bytes:
                invalid = True; continue
            level, kind, data = item
            if (level, kind) == (1, 1):
                rights = True
                if not data or len(data) % 4 or len(data) > 64: invalid = True
                for at in range(0, min(len(data), 64) - len(data) % 4, 4):
                    row = self._ledger.new('file'); self._ctrl_rights.append(row)
                    try: self._ledger.adopt(row, struct.unpack_from('=i', data, at)[0])
                    except BaseException: invalid = True
            elif (level, kind) == (1, 2) and len(data) == _CRED.size:
                credentials.append(_CRED.unpack(data))
            else: invalid = True
        if invalid:
            self._ledger.pending = True; _fail('ctrl_unknown')
        self._ctrl_receive_unknown = False
        if rights or len(credentials) != 1: _fail('ctrl_unknown')
        return credentials[0]
    def _capture_kernel(self, row):
        # Only the exact new reader can issue historical immediate-EBADF
        # receipts. Current numeric reuse still needs our existing live owner.
        try:
            reader, operation = row['reader'], row['operation']
            expected_until = operation.deadline
            peer_owner = row['peer_owner']
            if peer_owner is not None:
                import mta_client_peer as peer
                if (type(peer_owner) is not peer.ClientPeerReader or peer_owner is not self._client_peer_owner_v29 or
                        peer_owner.provider is not self or peer_owner.operation is not operation or not peer_owner._active):
                    return False
                expected_until = peer.ClientPeerReader._io_until_for_provider(peer_owner, self, operation.deadline)
            transfer_owner = row['transfer_owner']
            if transfer_owner is not None:
                import mta_client_transfer as transfer
                if (type(transfer_owner) is not transfer.ClientTransferOwner or
                        transfer_owner is not self._client_transfer_owner_v30 or transfer_owner.provider is not self or
                        transfer_owner.operation is not operation or not transfer_owner._running or transfer_owner._scope is None):
                    return False
                expected_until = transfer.ClientTransferOwner._io_until_for_provider(transfer_owner, self, expected_until)
            if (type(reader) is not kernel_proof.ClientKernelReader or reader._owner is not operation or
                    reader._epoch != operation._operation_epoch or reader._origin is not operation.owned or
                    reader._boot != self._boot or reader._cancel_callback is not operation._cancel_checkpoint or
                    row['effective_until'] != expected_until or reader._external_deadline != expected_until): return False
            row['resources'], row['proc_rows'], row['receipts'] = (
                reader.original_resources, reader.proc_readers, reader.closed_receipts)
            state = reader.status()
            if (state.get('finished') is not True or state.get('resources_closed') is not True or
                    state.get('resource_pending') is not False or reader._receipt_unknown is not False or
                    any(type(v) is not tuple for v in (row['resources'], row['proc_rows'], row['receipts']))): return False
            expected = []
            for resource in row['resources']:
                if (type(resource) is not dict or resource['unknown'] is not False or resource['closed'] is not True or
                        resource['attempted'] is not True or not _int(resource['fd'], 0, 0x7fffffff)): return False
                if resource['kind'] == 'socket' and resource['value'].fileno() != -1: return False
                expected.append((reader._io, resource['fd'], resource))
            for item in row['proc_rows']:
                observer = item['reader']
                if (type(observer) is not proc.ProcReader or item['unknown'] is not False or item['closed'] is not True or
                        observer._pending or observer._active or observer._open_attempt is not None or
                        observer._files != observer._closed or len(observer._fd_refs) != observer._files): return False
                if not self._remember_proc_history_v24(observer): return False
                expected.extend((fs, fd, observer) for fs, fd in observer._fd_refs)
            def same(a, b): return type(a) is tuple and len(a) == 3 and type(a[1]) is int and a[0] is b[0] and a[1] == b[1] and a[2] is b[2]
            # A sequential ProcReader may reopen the lowest FD many times.
            # Preserve the source inventory multiplicity, not numeric uniqueness.
            if len(expected) != len(row['receipts']) or any(sum(same(r, e) for r in row['receipts']) !=
                    sum(same(r, e) for r in expected) for e in expected): return False
            for io, fd, original in expected:
                if type(original) is proc.ProcReader:
                    if not self._proc_history_closed_v24(original): return False
                    continue  # Kernel receipts remain exact; Provider uses each creation ticket.
                if not any(i is io and n == fd and o is original for i, n, o in self._fd_receipts):
                    if len(self._fd_receipts) >= MAX_FD_RECEIPTS: return False
                    self._append_fd_receipt_v23(io, fd, original)
                if not self._closed_fd(io, fd, original): return False
            return True
        except BaseException:
            return False
    def _kernel_closed_facts(self, row):
        # Resource outcome is separate from successful role/association fields.
        if row['unknown'] or type(row['reader']) is not kernel_proof.ClientKernelReader: return [(False, False)]
        reader, result = row['reader'], []
        for original in row['resources']:
            closed = original['closed'] is True and original['unknown'] is False and \
                self._closed_fd(reader._io, original['fd'], original)
            if original['kind'] == 'socket': closed = closed and original['value'].fileno() == -1
            result.append((original['attempted'] is True, closed))
        for item in row['proc_rows']:
            observer = item['reader']
            result.append((observer._files > 0 and observer._files == observer._closed,
                item['closed'] is True and item['unknown'] is False and not observer._pending and not observer._active and
                self._proc_history_closed_v24(observer)))
        return result
    def _connection_kernel(self, operation, deadline):
        self._connection_context(operation, deadline)
        if len(self._kernel_readers) >= MAX_KERNEL_READERS: connection._fail('kernel_unverified')
        peer_owner = self._client_peer_owner_v29
        if peer_owner is not None and not peer_owner._active: peer_owner = None
        transfer_owner = self._client_transfer_owner_v30
        if transfer_owner is not None and transfer_owner._scope is None: transfer_owner = None
        row = {'operation': operation, 'reader': None, 'value': None, 'unknown': True,
            'peer_owner': peer_owner, 'transfer_owner': transfer_owner, 'effective_until': self._peer_io_until_v29(deadline),
            'resources': (), 'proc_rows': (), 'receipts': ()}
        self._kernel_readers.append(row)  # Before constructor or read side effects.
        try:
            reader = self._kernel_factory(operation.owned, self._boot, operation, operation._operation_epoch,
                timeout=min(5, self._now(deadline)), _clock=self._clock,
                _checkpoint=operation._cancel_checkpoint, _deadline=row['effective_until'],
                _proc_factory=self._new_proc_v24)
            row['reader'] = reader  # Exact returned object before type/read/auth.
            if type(reader) is not kernel_proof.ClientKernelReader: connection._fail('kernel_unverified')
            value = reader.read(); row['value'] = value
        except kernel_proof.KernelReadError as error:
            if error.code == 'cancelled':
                operation.failed, operation.reason = True, 'cancelled'; self.cancelled.set()
                connection._fail('cancelled')
            connection._fail('kernel_unverified')
        finally:
            row['unknown'] = not self._capture_kernel(row)
        self._connection_context(operation, deadline)
        if row['unknown'] or type(value) is not kernel_proof.KernelObservation: connection._fail('kernel_unverified')
        reader.authenticate(operation, operation._operation_epoch, value)
        return value
    def _connection_caps(self, operation, snapshot, kernel, deadline):
        self._connection_context(operation, deadline)
        if type(snapshot) is not core.Snapshot or type(kernel) is not kernel_proof.KernelObservation or len(self._caps_readers) >= MAX_CAPS_READERS:
            connection._fail('channel_unverified')
        row = {'reader': None, 'value': None, 'unknown': True, 'socket': None}; self._caps_readers.append(row)
        def creator(family, kind, protocol):
            if (family, kind, protocol) != (16, 3, 16) or row['socket'] is not None: _fail('interface_unknown')
            claimed = self._ledger.sock(self._io.new_genl); row['socket'] = claimed
            return claimed.value
        reader = self._caps_factory(operation.owned.phy, timeout=min(5, self._now(deadline)),
            clock=self._clock, socket_factory=creator)
        row['reader'] = reader
        try:
            value = reader.read(); row['value'] = value
        finally:
            if row['socket'] is not None:
                self._ledger.component_closed(row['socket'], reader._finished and reader._created)
                if row['socket'].closed:
                    row['unknown'] = not self._remember(self._io, row['socket'].fd, row['socket'])
        state = reader.status()
        if (type(value) is not caps_transport.caps.DecodedCaps or state.get('read_success') is not True or
                state.get('socket_closed') is not True or state.get('resource_pending') is not False or
                row['unknown']): connection._fail('channel_unverified')
        self._connection_context(operation, deadline)
        mapped = _caps_core(value)  # Existing lossless/known-policy validation, unchanged.
        phy = mapped['phys'][0]
        current = tuple(r for r in snapshot.interfaces if r.phy == operation.owned.phy)
        fields = kernel.private_fields(); role, frequency = fields['channel']
        if (phy['index'] != operation.owned.phy or phy['software_iftypes'] or 2 not in phy['iftypes'] or 8 not in phy['iftypes'] or
                len(current) != 2 or sorted(r.iftype for r in current) != [2, 8] or
                not any(r.key() == operation.owned.key() for r in current) or
                not any(r.key() == snapshot.station.key() for r in current) or role != 8 or
                not _int(frequency, 1, 100000) or not _int(snapshot.station_frequency, 1, 100000)):
            connection._fail('channel_unverified')
        counts = {2: 1, 8: 1}; channel_count = len({snapshot.station_frequency, frequency})
        for combo in phy['combinations']:
            if (combo['radar_widths'] or combo['radar_regions'] or combo['beacon_match'] or
                    channel_count > combo['num_channels'] or sum(counts.values()) > combo['max_interfaces']): continue
            covered = set(t for limit in combo['limits'] for t in limit['types'])
            if set(counts) <= covered and all(sum(counts.get(t, 0) for t in limit['types']) <= limit['max'] for limit in combo['limits']):
                return value  # Actual raw DecodedCaps issuer original; not an init-only bool.
        connection._fail('channel_unverified')
    def _connection_context(self, operation, deadline):
        # Same F, original device OFD, exact current handoff, actual private child.
        self._begin(deadline, True)
        lease = self._lease
        if type(operation) is not connection._Connection or operation is not self._connection or \
                operation.provider is not self or operation.lease is not lease or \
                type(lease) is not LinuxClientInitLease or lease.provider is not self or \
                lease.store is not self._store or lease.sealed or lease.cleanup_complete or \
                lease.locks is not self._store._current_locks or lease._restore_held is not True:
            _fail('wrong_owner')
        binding = self._connect_binding
        if (type(binding) is not control_frame.ControlBinding or operation.binding is not binding or
                type(self._connection_creation) is not dict or self._connection_creation['operation'] is not operation or
                self._connection_creation['unknown'] is not False or operation.request is not self._connection_creation['request'] or
                type(operation.request) is not control_frame.ConnectRequest or operation.request.binding is not binding or
                operation.request._decoder._binding is not binding or operation.request._decoder._claimed_request is not operation.request or
                operation.request.cancelled or
                binding._wire != self._connect_wire or operation.binding_wire != self._connect_wire or
                control_frame.ControlBinding(binding.private_metadata())._wire != self._connect_wire or
                binding.private_metadata()['run_token'] != self.manifest.run_token or
                binding.private_metadata()['candidate_sha'] != self.manifest.candidate_sha or
                operation._operation_epoch != binding.private_metadata()['operation_epoch']): _fail('wrong_owner')
        operation._checkpoint()
        if self.cancelled.is_set(): connection._fail('cancelled')
        lease._budget(deadline)
        if deadline != operation.deadline or deadline != lease.record.deadline: _fail('wrong_owner')
        actual = lease._fresh()
        if actual.stage != 'client_init_ready' or actual.ready is not True or actual.owned is None or \
                actual.owned.key() != operation.owned.key() or lease.handles.get('controller') is not operation.handle:
            _fail('wrong_owner')
        association = actual.association
        if association is not None and (type(association) is not core.ClientAssociationRecord or
                association.binding != binding.private_metadata() or
                association.executor.key() != self._self.key() or not association.executor.live() or
                association.phase == 'invalidated' and not operation.disconnect_requested):
            connection._fail('association_unverified')
        proof = lease._executor(deadline, inherited=lease.locks)
        if proof.role != 'owner' or self._self is None or proof.actor.key() != self._self.key(): _fail('wrong_owner')
        if self._handle(operation.handle).spec.role != 'controller' or not self._origin_exact(operation.owned, deadline):
            _fail('origin_changed')
        controller = self.live_actor(operation.handle, deadline)
        operation._checkpoint()
        # Registered only after every original fresh gate. The issuer consumes
        # this producer-original once, within the same synchronous transaction.
        self._connection_last_context = {'operation': operation, 'transaction': operation._receipt_transaction,
            'current': actual, 'canonical': self._store._canonical, 'locks': lease.locks,
            'device': lease.locks._device, 'store_epoch': self._store._epoch,
            'journal_epoch': self._store._journal_epoch, 'marker': self._store._marker,
            'marker_binding': self._store._binding, 'binding': binding,
            'executor': proof, 'controller': controller, 'consumed': False}
        self._connection_issued_context = self._connection_last_context
    def _issue_association_receipt(self, operation, observation):
        context = self._connection_last_context
        registered = context is not None and context is self._connection_issued_context
        self._connection_last_context = None  # One attempt, including validation failure.
        self._connection_issued_context = None
        if not registered or type(context) is not dict or context['consumed'] is not False: connection._fail('association_unverified')
        context['consumed'] = True
        operation._checkpoint(); operation.lease._budget(operation.deadline)
        if (operation.failed or operation.disconnected or operation.receipt_invalidated or
                type(observation) is not connection.ConnectionObservation or observation is not operation.result or
                observation._operation is not operation or not any(value is observation for value in operation.observations) or
                len(self._association_receipts) >= MAX_ASSOCIATION_RECEIPTS): connection._fail('association_unverified')
        record, store = operation.lease.record, self._store
        if (context['operation'] is not operation or context['transaction'] is None or
                context['transaction'] is not operation._receipt_transaction or operation.lease.sealed or
                context['locks'] is not operation.lease.locks or context['locks'] is not store._current_locks or
                context['device'] is not context['locks']._device or context['store_epoch'] is not store._epoch or
                context['journal_epoch'] is not store._journal_epoch or context['marker'] is not store._marker or
                context['marker_binding'] is not store._binding or context['binding'] is not self._connect_binding or
                operation.binding is not context['binding'] or operation.binding_wire != self._connect_wire or
                context['canonical'] is not store._canonical or not core._same_journal(context['current'], record) or
                not any(value is context['current'] for value in store._records) or
                type(context['executor']) is not core.ExecutorProof or context['executor'].role != 'owner' or
                context['executor'].actor.key() != self._self.key() or not context['executor'].actor.live() or
                type(context['controller']) is not core.Actor or not context['controller'].live() or
                context['controller'].key() != operation.handle.actor.key()): connection._fail('association_unverified')
        association = record.association
        fields = observation._kernels[0].private_fields()
        if (type(association) is not core.ClientAssociationRecord or association.phase != 'confirmed' or
                (association.local_mac, association.bssid, association.frequency) !=
                (fields['local_mac'], fields['stations'][0][0], fields['channel'][1]) or
                association.binding != operation.binding.private_metadata() or
                association.executor.key() != self._self.key() or record.deadline != operation.deadline or
                store._journal_epoch is not store._marker._binding_ticket.journal_epoch):
            connection._fail('association_unverified')
        canonical = store._canonical
        store._canonical_valid(canonical, record)
        ticket = {'operation': operation, 'observation': observation, 'canonical': canonical,
            'context': context, 'generation': len(self._association_receipts) + 1, 'receipt': None, 'unknown': True}
        self._association_receipts.append(ticket)  # Before construction; original return retained immediately.
        value = connection.AssociationReceipt(self, operation, observation, canonical, ticket['generation'])
        ticket['receipt'] = value
        if type(value) is not connection.AssociationReceipt: connection._fail('association_unverified')
        operation._checkpoint(); operation.lease._budget(operation.deadline)
        self._active_association_receipt = value; ticket['unknown'] = False
        return value
    def _association_receipt_current(self, value):
        operation, store = self._connection, self._store
        if (type(value) is not connection.AssociationReceipt or value is not self._active_association_receipt or
                operation is None or value is not operation.receipt or operation.failed or operation.receipt_invalidated or
                operation.disconnected or operation.disconnect_requested or value._provider is not self or
                value._operation is not operation or value._binding is not self._connect_binding or
                value._observation is not operation.result or value._locks is not operation.lease.locks or
                value._store_epoch is not store._epoch or value._journal_epoch is not store._journal_epoch or
                not any(row['receipt'] is value and not row['unknown'] and row['operation'] is operation and
                    row['observation'] is value._observation and row['canonical'] is value._canonical and
                    type(value._generation) is int and row['generation'] == value._generation
                    for row in self._association_receipts)):
            connection._fail('receipt_stale')
        # Passive exact-issued/current-object check only. The caller's ensuing
        # readback retains every original fresh context/status/kernel gate.
        operation._checkpoint(); operation.lease._budget(operation.deadline)
        record, canonical = operation.lease.record, store._canonical
        store._canonical_valid(value._canonical, value._record)
        store._canonical_valid(canonical, record)
        if (not core._same_journal(record, value._record) or type(record.association) is not core.ClientAssociationRecord or
                record.association.phase != 'confirmed' or
                canonical._generation != value._canonical._generation or
                canonical.metadata != value._canonical.metadata or canonical.data != value._canonical.data or
                hashlib.sha256(canonical.data).hexdigest() != value.receipt_id): connection._fail('receipt_stale')
        return None
    def _connection_open(self, operation, deadline, event=False):
        self._connection_context(operation, deadline)
        self._verify_anchors(deadline)
        # Init owns the command socket; never borrow another provider's channel.
        if self._ctrl is None or self._ctrl_failed or not self._ctrl_setup:
            _fail('ctrl_unknown')
        if not event: return self._ctrl
        if self._connection_event_requested:
            if self._connection_event is None: _fail('ctrl_unknown')
            return self._connection_event
        self._connection_event_requested = True
        self._connection_event = self._ledger.sock(self._io.new_ctrl)
        raw = self._connection_event.value
        raw.set_inheritable(False)
        if raw.get_inheritable() is not False: _fail('ctrl_unknown')
        raw.setsockopt(1, 16, 1)
        if raw.getsockopt(1, 16) != 1: _fail('ctrl_unknown')
        local = b'\0p011-client-event-' + self.manifest.run_token.encode('ascii')
        raw.bind(local)
        if raw.getsockname() != local: _fail('ctrl_unknown')
        endpoint, before, unused = self._ctrl_endpoint
        if baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, operation.owned.name)) != before:
            _fail('ctrl_unknown')
        raw.connect(endpoint)
        if raw.getpeername() != endpoint: _fail('ctrl_unknown')
        self._connection_event_endpoint = (endpoint, before, local)
        return self._connection_event
    def _connection_channel_gate(self, operation, deadline, event):
        self._connection_context(operation, deadline)
        self._verify_anchors(deadline)
        row = self._connection_event if event else self._ctrl
        endpoint = self._connection_event_endpoint if event else self._ctrl_endpoint
        if row is None or endpoint is None or row.unknown or row.closed or row.attempted or \
                row.fd != row.value.fileno() or baseline._metadata(self._io.fstat(row.fd))[:6] != row.meta[:6]:
            _fail('ctrl_unknown')
        peer, before, local = endpoint
        if baseline._metadata(self._io.stat_at(self._ctrl_anchor.fd, operation.owned.name)) != before or \
                row.value.getpeername() != peer or row.value.getsockname() != local or \
                row.value.getsockopt(1, 16) != 1 or row.value.get_inheritable() is not False:
            _fail('ctrl_unknown')
        return row, peer
    def _connection_exchange(self, operation, wire, deadline, event=False):
        if wire is not operation._command or event is not operation._command_event or type(wire) is not bytes:
            _fail('wrong_owner')
        allowed = (b'ATTACH',) if event else (b'ADD_NETWORK', b'STATUS', b'DISCONNECT')
        if not event and operation.network_id is not None:
            allowed += tuple(c.private_bytes() for c in connection.ctrl.network_commands(operation.network_id, operation.credentials))
            allowed += (connection.ctrl.group_add_command(operation.network_id).private_bytes(),)
        if wire not in allowed or wire == b'DISCONNECT' and not operation.disconnect_requested:
            _fail('wrong_owner')
        if operation.lease.record.association is not None and operation.lease.record.association.phase == 'invalidated' and \
                (event or wire not in (b'DISCONNECT', b'STATUS')): _fail('wrong_owner')
        row, peer = self._connection_channel_gate(operation, deadline, event)
        self._connection_timeout(row.value, deadline, False)
        operation._checkpoint()
        if row.value.send(wire) != len(wire): _fail('ctrl_unknown')
        value = self._connection_receive(operation, deadline, command_event=event, reply=True)
        operation._checkpoint()
        return value
    def _connection_timeout(self, raw, deadline, poll):
        remaining = 0.0 if poll else min(.2, self._now(deadline))
        raw.settimeout(remaining)
        actual = raw.gettimeout()
        if type(actual) not in (int, float) or (actual != 0 if poll else not 0 < actual <= remaining + 1e-9):
            _fail('ctrl_unknown')
    def _connection_receive(self, operation, deadline, poll=False, command_event=False, reply=False):
        event = command_event if reply else True
        row, peer = self._connection_channel_gate(operation, deadline, event)
        self._connection_timeout(row.value, deadline, poll)
        if len(operation._packets) >= connection.MAX_PACKETS: _fail('ctrl_unknown')
        operation._checkpoint()
        self._ctrl_receive_unknown = True
        try:
            value = row.value.recvmsg(4097, self._io.cmsg_space(_CRED.size) + self._io.cmsg_space(16 * 4), 0x40000000)
        except socket.timeout:
            self._ctrl_receive_unknown = False
            operation._checkpoint()
            raise
        except OSError as error:
            if poll and type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                self._ctrl_receive_unknown = False
                operation._checkpoint()
                return None
            raise
        operation._packets.append(value); self._ctrl_incoming.append(value)
        if type(value) is not tuple or len(value) != 4: _fail('ctrl_unknown')
        packet, ancillary, flags, address = value
        credential = self._ctrl_controls(ancillary)
        if type(flags) is not int or flags & (8 | 32) or flags not in (0, 0x40000000):
            self._ctrl_receive_unknown = True; _fail('ctrl_unknown')
        if type(packet) is not bytes or not 1 <= len(packet) <= (4096 if reply else 1024) or \
                credential != (operation.handle.actor.pid, 0, 0) or address not in (peer, peer.encode('ascii')):
            _fail('ctrl_unknown')
        operation._checkpoint()
        self._connection_channel_gate(operation, deadline, event)
        return packet
    def request_child_stop(self, child, deadline):
        self._begin(deadline)
        self._owner._exact(child)
        if child not in tuple(op.child for op in self._bridge._operations) or child.unknown or child.postexec is None:
            core._fail('provider_unavailable')
        if child.waited:
            if child.exit_verified is not True: _fail('child_stop_unknown')
            return None
        try: self._observe(child.pid, child.postexec)
        except (proc.ProcReadError, LinuxProviderError):
            # A naturally exited direct child may be a zombie/non-live Actor.
            # Only actual owner wait/reap + fresh entire-task absence permits it.
            if self._owner.wait_reap(child, min(.1, self._now(deadline))) is not True or \
                    self._owner.fresh_exit(child) is not True: _fail('child_stop_unknown')
            return None
        # An unreaped direct child cannot have its PID reassigned. No global kill.
        if self._io.kill(child.pid) is not None: _fail('child_stop_unknown')
        if self._owner.wait_reap(child, min(2, self._now(deadline))) is not True: _fail('child_stop_unknown')
        if self._owner.fresh_exit(child) is not True: _fail('child_stop_unknown')
        return None
    def delete_client(self, owned, deadline):
        self._begin(deadline, True)
        if self._delete_requested or not self.cleanup_origin_ready(owned, deadline):
            _fail('origin_changed')
        self._delete_requested = True
        self._kernel.request(self._kernel.family, 8, _attr(153, struct.pack('<Q', owned.wdev)), 4, deadline)
        return self.origin_absent(owned, deadline)
    def cleanup_origin_ready(self, owned, deadline):
        self._begin(deadline)
        if not self._origin_exact(owned, deadline) or not self._bridge.verify_closed(): return False
        for child in self._owner._tickets:
            if child.fork_requested and not child.fork_negative:
                if child.waited is not True or child.exit_verified is not True or child.postexec is None:
                    return False
                actual = self._observe(child.pid, child.postexec, True)
                if actual.kind != 'absence' or actual.pid_path_absent is not True or actual.remaining_tasks != ():
                    return False
        current = self.snapshot(deadline)
        if current.key(owned) != self._baseline_record.key(): return False
        return self._observe_ctrl_deinit(deadline)
    def _observe_ctrl_deinit(self, deadline):
        # Called ONLY after every exact child actual wait+absence, closed bridge
        # and unchanged full original network. Fixed 2.12 unlinks endpoint then
        # rmdirs ctrl; open original directory FDs may validly have nlink=0.
        if self._ctrl_anchor is None: return True
        self._now(deadline)
        ctrl, run = self._ctrl_anchor, self._run_anchor
        cm, rm = baseline._metadata(self._io.fstat(ctrl.fd)), baseline._metadata(self._io.fstat(run.fd))
        if cm[:5] != ctrl.meta[:5] or rm[:5] != run.meta[:5]: return False
        try: current = baseline._metadata(self._io.stat_at(run.fd, 'ctrl'))
        except OSError as e:
            if type(e.errno) is not int or e.errno != errno.ENOENT: return False
            current = None
        if current is not None:
            return current[:6] == cm[:6] == ctrl.meta[:6] and rm[:6] == run.meta[:6]
        controllers = [c for c in self._owner._tickets if c.spec.role == 'controller' and
            c.spec.exe == self.manifest.wpa_exe and c.spec.sha == self.manifest.wpa_sha]
        if len(controllers) != 1 or controllers[0].postexec is None or controllers[0].waited is not True or \
                controllers[0].exit_verified is not True: return False
        if ctrl.meta[5] != 2 or cm[5] != 0 or run.meta[5] < 3 or rm[5] != run.meta[5] - 1:
            return False
        try: self._io.stat_at(ctrl.fd, self.manifest.ifname)
        except OSError as e:
            if type(e.errno) is not int or e.errno != errno.ENOENT: return False
        else: return False
        if self._ctrl_deinit_observation is not None and self._ctrl_deinit_observation != (cm[:6], rm[:6]): return False
        self._ctrl_deinit_observation = (cm[:6], rm[:6])
        ctrl.close_meta, run.close_meta = cm[:6], rm[:6]
        return True
    def origin_absent(self, owned, deadline):
        self._begin(deadline)
        if owned is not self._owned: _fail('wrong_owner')
        return not any(r.name == owned.name or r.ifindex == owned.ifindex or r.wdev == owned.wdev
            for r in self._kernel.interfaces(deadline))
    def _reserve_v23(self, kind, maximum=0):
        if self._store is None or getattr(self, '_resource_budget_v23', None) is not self._store._resource_budget_v23:
            _fail('wrong_owner')
        return self._resource_budget_v23.reserve(self._store._resource_lane_v23, kind, maximum)
    def _append_fd_receipt_v23(self, io, fd, original):
        credit = self._reserve_v23('FD_RECEIPT')
        budget = self._resource_budget_v23; budget.started(credit)
        receipt = (io, fd, original)
        self._fd_receipts.append(receipt)  # Original evidence, never an FD-close request.
        budget.returned(credit, receipt); budget.settle(credit)
    def _remember(self, io, fd, owner):
        # Capture actual immediate EBADF before a later registered open can
        # legitimately reuse this number. This is NOT a current close request.
        if not _int(fd, 0, 0x7fffffff) or not self._fd_absent(io, fd): return False
        if not any(i is io and n == fd and o is owner for i, n, o in self._fd_receipts):
            if len(self._fd_receipts) >= MAX_FD_RECEIPTS: _fail('close_unknown')
            self._append_fd_receipt_v23(io, fd, owner)
        return True
    def _remember_proc(self, reader, value):
        return len(reader._fd_refs) == value.file_count and self._remember_proc_history_v24(reader)
    def _proc_registered_v24(self, reader):
        budget = getattr(self, '_resource_budget_v23', None)
        return (type(reader) is proc.ProcReader and self._store is not None and
            budget is self._store._resource_budget_v23 and reader._resource_budget_v24 is budget and
            reader._bound_budget_v24 is budget and
            any(r is reader for r in budget._readers))
    def _proc_namespace_registered_v24(self):
        store, owner, original = self._store, self._owner, self._owner_proc_reader_v24
        return (type(store) is stores.DurableClientInitStore and
            type(owner) is processes.DirectChildOwner and owner._reader is original and
            self._proc_registered_v24(original) and
            store._proc_reader is store._proc_reader_original_v24 and
            self._proc_registered_v24(store._proc_reader) and
            (store._marker is None or store._marker._reader is store._proc_reader))
    def _proc_history_pending_v24(self):
        # Memory-only pending projection. Active/unknown histories cannot look
        # quiescent just because a Provider call row was never needed.
        if self._store is None: return False
        if not self._proc_namespace_registered_v24(): return True
        budget = self._store._resource_budget_v23
        return any(not self._proc_registered_v24(reader) or not reader.history_closed()
            for reader in budget._readers)
    def _capture_proc_open_v24(self, ticket):
        if (type(ticket) is not proc.ProcOpenTicket or not self._proc_registered_v24(ticket.reader) or
                not ticket.reader.owns_open_ticket(ticket) or
                not ticket.reader.closed_open_ticket(ticket)): return False
        # A failed POSIX open has no returned FD. The exact failed original is
        # retained in its generation, not fabricated as an EBADF receipt.
        if ticket.failed_without_fd: return ticket.descriptor is None and ticket.returned is False
        # PROC_OPEN already precharged and retained this exact original and
        # its immediate EBADF. Do not manufacture a second late receipt or
        # collapse sequential numeric reuse into one old reader/FD entry.
        return self._closed_fd(ticket.fs, ticket.descriptor, ticket)
    def _remember_proc_history_v24(self, reader):
        if not self._proc_registered_v24(reader) or not reader.history_closed(): return False
        for generation in reader.operation_history:
            if not reader.owns_generation(generation): return False
            for ticket in generation.tickets:
                if not self._capture_proc_open_v24(ticket): return False
        return True
    def _proc_history_closed_v24(self, reader):
        if not self._proc_registered_v24(reader) or not reader.history_closed(): return False
        for generation in reader.operation_history:
            if not reader.owns_generation(generation): return False
            for ticket in generation.tickets:
                if not reader.closed_open_ticket(ticket): return False
                if not ticket.failed_without_fd and not self._closed_fd(ticket.fs, ticket.descriptor, ticket): return False
        return True
    def _remember_collector(self, reader):
        value = reader._reader
        if len(value._fd_refs) < value._files or value._pending or value._closed != value._files: return False
        good = self._remember_proc_history_v24(value)
        for row in reader._tickets:
            if row['fd'] is not None:
                good = row['attempted'] and row['closed'] and not row['unknown'] and \
                    self._remember(reader._io, row['fd'], row) and good
        for row in reader.status_readers:
            r, source = row.get('reader'), row.get('source')
            if row['unknown'] or r is None or source is None: return False
            if r._socket_fd is not None:
                good = r._socket_attempted and r._socket_closed and self._remember(r._io, r._socket_fd, r) and good
            for item in r._rights:
                good = item['attempted'] and item['closed'] and not item['unknown'] and \
                    self._remember(r._io, item['fd'], item) and good
            for group in source._files:
                for item in group._tickets:
                    if item['fd'] is not None:
                        good = item['attempted'] and item['closed'] and not item['unknown'] and \
                            self._remember(group._io, item['fd'], item) and good
            for call in source._actor_calls:
                observer = call['reader']
                if call['unknown'] or observer is None or observer._pending or observer._files != observer._closed: return False
                good = self._remember_proc_history_v24(observer) and good
        return good
    def _known_live_fd(self, fd, actual):
        """Only exact *current* registered B/Owner/Provider originals can reuse.

        A matching inode without a live issued owner never suffices. Unknown,
        closed and stale journal tickets are not admitted and are never closed.
        """
        claims = []
        for row in self._ledger.rows:
            if row.fd == fd and not row.closed and not row.unknown and row.meta is not None:
                try: alias_identity = self._ledger._alias_identity(row, actual)
                except BaseException: return False
                claims.append((self._io, alias_identity if alias_identity is not None else
                    (row.meta[:6] if row.close_meta is None else row.close_meta)))
        store = self._store
        if type(store) is stores.DurableClientInitStore:
            c, jf = store._coordination, store._files
            if type(c) is coordination.ClientCoordination:
                for ticket, parent, name, identity, private, temporary in c._anchors:
                    if ticket.fd == fd and not ticket.closed and not ticket.opening_unknown:
                        claims.append((ticket.io, identity))
                locks = store._current_locks
                if locks is not None:
                    for ticket in (locks._device, locks._journal):
                        if ticket.fd == fd and any(t is ticket for t in c._inventory) and not ticket.closed and \
                                not ticket.opening_unknown and ticket.flock_state == 'held' and ticket.identity is not None:
                            claims.append((ticket.io, ticket.identity))
            if type(jf) is files.ClientJournalFiles:
                for ticket, parent, name, identity, private, temporary in jf._anchors:
                    if ticket.fd == fd and not ticket.closed and not ticket.opening_unknown:
                        claims.append((ticket.io, identity))
            marker = store._marker
            if type(marker) is pending.ClientPendingMarker and marker._ticket is not None:
                ticket = marker._ticket
                if ticket.fd == fd and not ticket.closed and not ticket.opening_unknown and marker._durable and marker._metadata is not None:
                    claims.append((ticket.io, marker._metadata[:5]))
        if type(self._owner) is processes.DirectChildOwner:
            for child in self._owner._tickets:
                for ticket in child.fds:
                    if ticket.fd == fd and ticket.returned and not ticket.closed and not ticket.unknown and ticket.metadata is not None:
                        claims.append((self._owner._os, ticket.metadata[:6]))
        # Multiple claimed live originals at one FD would be inconsistent.
        if len(claims) != 1: return False
        io, expected = claims[0]
        try:
            current = baseline._metadata(io.fstat(fd))
            return current == actual and current[:len(expected)] == expected
        except BaseException: return False
    def _closed_fd(self, io, fd, owner):
        issued_proc = (type(owner) is proc.ProcOpenTicket and owner.fs is io and owner.descriptor == fd and
            self._proc_registered_v24(owner.reader) and owner.reader.owns_open_ticket(owner) and
            owner.reader.closed_open_ticket(owner))
        issued_dora = False
        if self._dora_v26_creation is not None:
            import mta_client_dora as dora
            value, known = self._dora_root_v26()
            issued_dora = (known and type(owner) is dora._SocketTicket and io is self._io and
                owner.descriptor == fd and value.owns_socket_ticket_v26(owner) and value.closed_socket_ticket_v26(owner))
        if not issued_proc and not issued_dora and not any(i is io and n == fd and o is owner for i, n, o in self._fd_receipts): return False
        try: actual = baseline._metadata(io.fstat(fd))
        except OSError as e: return type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: return False
        return self._known_live_fd(fd, actual)
    def _capture_issued_closed(self, io, fd, original):
        # Called ONLY by the exact new bridge for old pinned close producers.
        # Those original rows are closed solely after close-once + EBADF in
        # the frozen producer. No user bool/number is accepted as that source.
        bridge = self._bridge
        if type(bridge) is not LinuxDirectChildLaunchBridge or bridge.provider is not self or self._owner is not bridge.owner:
            return False
        issued = type(original) is processes._FD and io is bridge.owner._os and any(
            any(r is original for r in c.fds) and c.owner is bridge.owner for c in bridge.owner._tickets) and \
            original.returned and original.closed and original.attempted and not original.unknown and original.metadata is not None
        issued = issued or type(original) is launches._Fd and original.io is io and any(
            r is original for r in bridge.registry._inventory) and original.closed and original.attempted and \
            not original.opening_unknown and original.metadata is not None
        if not issued or not _int(fd, 0, 0x7fffffff): return False
        if any(i is io and n == fd and o is original for i, n, o in self._fd_receipts):
            return self._closed_fd(io, fd, original)
        if self._remember(io, fd, original): return True
        try: actual = baseline._metadata(io.fstat(fd))
        except BaseException: return False
        if not self._known_live_fd(fd, actual) or len(self._fd_receipts) >= MAX_FD_RECEIPTS: return False
        self._append_fd_receipt_v23(io, fd, original); return True
    def _closed_objects(self):
        result, proc_attempted, proc_closed = [], [], []
        collector_facts, caps_facts, kernel_facts = [], [], []
        for row in self._proc_calls:
            reader = row['reader']; value = row['value']
            proc_attempted.append(reader is not None and type(value) is proc.ProcObservation and
                value.file_count > 0 and value.file_count == len(reader._fd_refs) and value.closed_count == value.file_count)
            proc_closed.append(not row['unknown'] and reader is not None and type(value) is proc.ProcObservation and
                not value.resource_pending and self._proc_history_closed_v24(reader))
        # The logical handle here is the exact retained ProcReader inventory.
        # Every actual FD inside it is read back; count is not physical FD count.
        if proc_closed: result.append((all(proc_attempted), all(proc_closed)))
        for row in self._collectors:
            reader = row['reader']; state = reader.status() if reader is not None else {}
            ok = not row['unknown'] and state.get('resource_pending') is False and \
                state.get('closed_count') == state.get('resource_count')
            if ok:
                ok = all(r['closed'] and not r['unknown'] and
                    (r['fd'] is None or self._closed_fd(reader._io, r['fd'], r)) for r in reader._tickets)
                ok = ok and all(self._authenticated_closed(s) for s in reader.status_readers)
                observer = reader._reader
                ok = ok and not observer._pending and observer._files == observer._closed and \
                    self._proc_history_closed_v24(observer)
            attempted = reader is not None and reader._ended and all(r['fd'] is None or r['attempted']
                for r in reader._tickets) and all(s.get('reader') is not None and s['reader']._socket_attempted
                    for s in reader.status_readers)
            collector_facts.append((attempted, ok))
        for row in self._caps_readers:
            reader = row['reader']; state = reader.status() if reader is not None else {}
            raw = row.get('socket')
            attempted = raw is not None and raw.attempted
            closed = raw is not None and raw.closed and not raw.unknown and raw.value.fileno() == -1 and \
                self._closed_fd(self._io, raw.fd, raw)
            caps_facts.append((attempted, not row['unknown'] and state.get('resource_pending') is False and
                state.get('socket_closed') is True and closed))
        for row in self._kernel_readers: kernel_facts.extend(self._kernel_closed_facts(row))
        # Logical roots only. Every original per-FD predicate above still runs.
        for group in (collector_facts, caps_facts, kernel_facts):
            if group: result.append((all(a for a, c in group), all(c for a, c in group)))
        # The budget registry contains only successfully bound readers. A
        # no-return/malformed/borrowed factory original stays a separate root;
        # allow_pending cleanup must never silently omit it from CloseProof.
        if self._proc_readers_v24:
            factory_known = tuple(row['returned'] and not row['unknown'] and
                self._proc_registered_v24(row['reader']) for row in self._proc_readers_v24)
            result.append((all(factory_known), all(known and
                self._proc_history_closed_v24(row['reader'])
                for known, row in zip(factory_known, self._proc_readers_v24))))
        # Include Store marker and direct-child readers, not only Provider's
        # latest _proc_calls. All exact generations remain registered.
        budget = getattr(self, '_resource_budget_v23', None)
        if budget is not None:
            histories = tuple(budget._readers)
            namespace_known = self._proc_namespace_registered_v24()
            result.append((bool(histories) and namespace_known,
                namespace_known and all(self._proc_history_closed_v24(r) for r in histories)))
        return result
    def _authenticated_closed(self, row):
        reader, source = row.get('reader'), row.get('source')
        if row['unknown'] or reader is None or source is None or source._pending or \
                reader.status()['resource_pending'] is not False or reader.status()['socket_closed'] is not True:
            return False
        if reader._socket is not None and (reader._socket.fileno() != -1 or
                not self._closed_fd(reader._io, reader._socket_fd, reader)): return False
        for group in source._files:
            if group._pending or any(not r['closed'] or r['unknown'] or r['fd'] is not None and
                    not self._closed_fd(group._io, r['fd'], r) for r in group._tickets): return False
        for call in source._actor_calls:
            if call['unknown'] or call['reader'] is None or not self._proc_history_closed_v24(call['reader']): return False
        return all(r['closed'] and not r['unknown'] and self._closed_fd(reader._io, r['fd'], r)
                   for r in reader._rights)
    @staticmethod
    def _fd_absent(io, fd):
        try: io.fstat(fd)
        except OSError as e: return type(e.errno) is int and e.errno == errno.EBADF
        except BaseException: pass
        return False
    def _proof(self):
        # CloseProof counts retained owner handles, NOT fabricated physical FDs.
        # Every concrete FD inside each composite owner is checked separately.
        self._now(self._deadline)
        self._close_dora_v26()  # Recovery cannot leave a live network producer outside the original graph.
        facts = self._closed_objects()
        facts.extend(self._dora_facts_v26())
        if self._client_ip_owner_v28 is not None:
            facts.extend(self._client_ip_facts_v28())
        if self._client_peer_owner_v29 is not None:
            facts.extend(self._client_peer_facts_v29())
        if self._client_transfer_owner_v30 is not None:
            facts.extend(self._client_transfer_facts_v30())
        returned = [r for r in self._ledger.rows if r.returned]
        if returned or self._ledger.pending:
            facts.append((bool(returned) and all(r.attempted for r in returned),
                not self._ledger.pending and not self._ctrl_receive_unknown and all(r.closed and not r.unknown and
                    self._closed_fd(self._io, r.fd, r) for r in returned)))
        if self._bridge is not None:
            facts.extend((op.inventory_close_requested and self._bridge._registry_close_requested,
                self._bridge.verify_closed(_absolute_deadline=self._store._recovery_deadline or self._deadline))
                for op in self._bridge._operations)
        if len(facts) > 128: _fail('close_unknown')
        self._now(self._deadline)
        return core.CloseProof(len(facts), tuple(a for a, c in facts), tuple(c for a, c in facts))

    def _client_transfer_facts_v30(self):
        value = self._client_transfer_owner_v30
        if value is None: return []
        import mta_client_transfer as transfer
        if (type(value) is not transfer.ClientTransferOwner or value.provider is not self or
                value.store is not self._store or value.lease is not self._lease):
            return [(False, False)]
        facts = transfer.ClientTransferOwner.closed_facts(value)
        if (type(facts) is not tuple or not 1 <= len(facts) <= 16 or
                any(type(r) is not tuple or len(r) != 2 or any(type(v) is not bool for v in r) for r in facts)):
            return [(False, False)]
        return list(facts)
    def _close_transfer_v30(self, deadline):
        value = self._client_transfer_owner_v30
        if value is None: return True  # Exact no-transfer/no-factory inventory.
        import mta_client_transfer as transfer
        if (type(value) is not transfer.ClientTransferOwner or value.provider is not self or
                value.store is not self._store or value.lease is not self._lease or value._running or value._scope is not None):
            return False
        transfer.ClientTransferOwner.close(value, deadline)
        return all(a and c for a, c in self._client_transfer_facts_v30())

    def _client_peer_facts_v29(self):
        value = self._client_peer_owner_v29
        if value is None: return []
        import mta_client_peer as peer
        if (type(value) is not peer.ClientPeerReader or value.provider is not self or
                value.store is not self._store or value.lease is not self._lease):
            return [(False, False)]
        facts = peer.ClientPeerReader.closed_facts(value)
        if (type(facts) is not tuple or not 1 <= len(facts) <= 8 or
                any(type(r) is not tuple or len(r) != 2 or any(type(v) is not bool for v in r) for r in facts)):
            return [(False, False)]
        return list(facts)
    def _close_peer_v29(self, deadline):
        value = self._client_peer_owner_v29
        if value is None: return True  # Exact no-reader/no-factory inventory.
        import mta_client_peer as peer
        if (type(value) is not peer.ClientPeerReader or value.provider is not self or
                value.store is not self._store or value.lease is not self._lease or value._active):
            return False
        peer.ClientPeerReader.close(value, deadline)
        return all(attempted and closed for attempted, closed in self._client_peer_facts_v29())

    def _client_ip_facts_v28(self):
        import mta_client_dynamic_ip as dynamic_ip
        value = self._client_ip_owner_v28
        if value is None: return []
        if (type(value) is not dynamic_ip.ClientDynamicIp or value.provider is not self or
                value.store is not self._store or value.lease is not self._lease): return [(False, False)]
        facts = value.closed_facts()
        if (type(facts) is not tuple or not 1 <= len(facts) <= 8 or
                any(type(r) is not tuple or len(r) != 2 or
                    any(type(v) is not bool for v in r) for r in facts)): return [(False, False)]
        return list(facts)
    def _client_ip_closed_v28(self):
        return all(attempted and closed for attempted, closed in self._client_ip_facts_v28())

    def _dora_root_v26(self):
        creation = self._dora_v26_creation
        if creation is None:
            return None, (self._dora_v21_registration is None and
                getattr(self._connection, '_dora_v21_registration', None) is None)
        import mta_client_dora as dora
        if type(creation) is not dict: return None, False
        value = creation.get('issued')
        if type(value) is not dora.PrivateClientDora: return None, False
        registered = (creation.get('creator') is dora.PrivateClientDora and creation.get('returned') is value and
            creation.get('unknown') is False and value.provider is self and value.store is self._store and
            value.lease is self._lease and value._operation is self._connection and
            value._registration is self._dora_v21_registration and
            value._registration is getattr(self._connection, '_dora_v21_registration', None) and
            value._registration.get('issuer') is value and value._registration.get('provider') is self and
            value._registration.get('store') is self._store and value._registration.get('lease') is self._lease)
        return value, bool(registered)

    def _close_dora_v26(self):
        value, known = self._dora_root_v26()
        if self._dora_v26_creation is None: return known
        if value is None: return False
        try: closed = value.close()
        except BaseException as error:
            self._dora_v26_creation['close_error'] = error
            self._dora_v26_creation['unknown'] = True
            return False
        return known and closed is True

    def _dora_facts_v26(self):
        value, known = self._dora_root_v26()
        if self._dora_v26_creation is None and known: return ()  # No invented unused socket/false FD.
        if not known or value is None: return ((True, False),)
        try: return value.closure_facts_v26(self)
        except BaseException as error:
            self._dora_v26_creation['facts_error'] = error
            self._dora_v26_creation['unknown'] = True
            return ((True, False),)
    def close_resources(self, handles, deadline):
        self._begin(deadline, allow_pending=True)
        if type(handles) is not tuple or any(type(h) is not core.Handle for h in handles): _fail('wrong_owner')
        if self._close_requested: _fail('close_unknown')
        if self._close_transfer_v30(deadline) is not True: _fail('close_unknown')
        if self._close_peer_v29(deadline) is not True: _fail('close_unknown')
        self._close_requested = self._sealed = True
        self._ledger.close_all()
        for row in self._ledger.rows:
            if row.returned and row.closed and not row.unknown: self._remember(self._io, row.fd, row)
        return self._proof()
    def closed_resources(self, handles, deadline):
        self._begin(deadline); return self._proof()
    def private_inventory_counts(self):
        """Counts of original descriptor receipts, NOT public descriptor values.

        FD numbers can be reused; counts are issuance records, not distinct
        simultaneous kernel FD slots. This passive method signs no closure.
        """
        return {'observer_fd_receipts': len(self._fd_receipts),
            'provider_fd_receipts': sum(r.returned and r.fd is not None for r in self._ledger.rows),
            'child_fd_receipts': sum(f.returned and f.fd is not None for c in
                (() if self._owner is None else self._owner._tickets) for f in c.fds),
            'registration_fd_receipts': sum(f.fd is not None for f in
                (() if self._bridge is None else self._bridge.registry._inventory))}
    def read_prior(self, store, locks, value, deadline):
        self._begin(deadline)
        if store is not self._store or locks is not store._current_locks or store._marker is not None or \
                store._coordination.read_pending(locks).get('entry_absent_observed') is not True: _fail('prior_blocked')
        # Prior history is not taken over. Unknown or any prior run blocks.
        names = self._io.listdir('/tmp/' + coordination.BASE)
        if type(names) is not list or sorted(names) != [coordination.RUN_PREFIX + self.manifest.run_token]: _fail('prior_blocked')
        current = self.snapshot(deadline)
        if current.key() != value.key(): _fail('baseline_changed')
        self._prior.append((store, locks, value, current)); return current
    def authenticate_prior(self, store, locks, value, actual, deadline):
        self._begin(deadline)
        if not any(s is store and l is locks and v is value and a is actual for s, l, v, a in self._prior):
            _fail('prior_blocked')
        return None
    def read_restore(self, store, locks, record, deadline):
        self._begin(deadline)
        if store is not self._store or locks is not store._current_locks or type(record) is not core.Journal or \
                record.identity.key() != self.manifest.identity.key() or record.ready or \
                record.stage not in ('cleanup_verified', 'reconciled') or not self._sealed or \
                self._owned is not None and self._delete_requested is not True:
            _fail('restore_unknown')
        current = self.snapshot(deadline); proof = self._proof()
        if self._owned is not None and any(r.name == self._owned.name or r.ifindex == self._owned.ifindex or
                r.wdev == self._owned.wdev for r in current.interfaces): _fail('restore_unknown')
        if current.key() != record.baseline.key() or not proof.complete(): _fail('restore_unknown')
        value = (current, proof); self._restores.append((store, locks, record, value)); return value
    def authenticate_restore(self, store, locks, record, value, deadline):
        self._begin(deadline)
        if not any(s is store and l is locks and r is record and v is value for s, l, r, v in self._restores):
            _fail('restore_unknown')
        if not self._proof().complete(): _fail('restore_unknown')
        return None
    def request_stop(self):
        self.cancelled.set()
        if self._connection is not None: self._connection.invalidate_receipt()
        self._close_dora_v26()
    def poll_transfer_requests_v30(self, actual_transfer):
        """Actual cancellation pipe reads only; no RF/restore authority or Proc scan."""
        import mta_client_transfer as transfer
        if (type(actual_transfer) is not transfer.ClientTransferOwner or
                actual_transfer is not self._client_transfer_owner_v30 or actual_transfer.provider is not self or
                actual_transfer.store is not self._store or actual_transfer.lease is not self._lease or
                not actual_transfer._running or type(self._owner) is not processes.DirectChildOwner):
            _fail('wrong_owner')
        until = min(actual_transfer.deadline, self._lease.record.deadline)
        transfer.ClientTransferOwner._quick(actual_transfer, until)
        records = tuple(t for t in self._owner._tickets if t.spec.role == 'watchdog')
        if (len(records) != 1 or records[0] not in tuple(op.child for op in self._bridge._operations) or
                records[0].deadline != self._lease.record.deadline or
                records[0].parent is None or self._self is None or records[0].parent.key() != self._self.key()):
            _fail('wrong_owner')
        value = processes.DirectChildOwner.read_requests_passive_v30(self._owner, records[0], until)
        if type(value) is not bool: _fail('wrong_owner')
        if value: self.cancelled.set()
        return value  # Stop request only; cannot authorize a network mutation or restore.

    def poll_executor_stop_v32(self, actual_executor, original_until):
        """Original F/watchdog stop notification only, never phase authority.

        No Proc traversal, RF operation, lock mutation or close is performed.
        The native passive reader still freshly checks the original worker,
        PID, nonblocking notify FD and metadata under its fixed <=0.2s cap.
        """
        import mta_client_executor as executor
        if (type(self) is not LinuxClientInitProvider or
                type(actual_executor) is not executor.ClientExecutor or
                type(actual_executor.deployment) is not executor.LoadedDeployment or
                type(actual_executor.deployment.modules) is not dict or
                actual_executor.deployment.modules.get('mta_client_executor') is not executor or
                getattr(actual_executor.deployment.modules.get('mta_client_linux_provider'), '__dict__', None) is not globals() or
                actual_executor.deployment.manifest is not self.manifest or
                type(actual_executor.assembly) is not tuple or len(actual_executor.assembly) != 5 or
                actual_executor.assembly[0] is not self or actual_executor.assembly[1] is not self._store or
                actual_executor.assembly[2] is not self._owner or actual_executor.assembly[3] is not self._bridge or
                actual_executor.assembly[4] is not self._lease or
                type(actual_executor.assembly_ticket) is not dict or
                actual_executor.assembly_ticket.get('returned') is not actual_executor.assembly or
                actual_executor.assembly_ticket.get('unknown') is not False or
                not actual_executor.start_call_started or not actual_executor.init_ready or
                not actual_executor.connect_attempted or
                threading.current_thread() is not actual_executor._stop_worker_v32 or
                type(self._owner) is not processes.DirectChildOwner or
                type(self._bridge) is not LinuxDirectChildLaunchBridge or
                self._bridge.owner is not self._owner or self._bridge.store is not self._store or
                self._bridge.provider is not self or
                type(self._store) is not stores.DurableClientInitStore or
                type(self._lease) is not LinuxClientInitLease or
                self._lease.provider is not self or self._lease.store is not self._store or
                self._lease.bridge is not self._bridge):
            _fail('wrong_owner')
        control, facts = actual_executor.input, actual_executor._stop_input_facts_v32
        if (type(control) is not executor._StdinControl or control is not actual_executor._stop_input_v32 or
                type(facts) is not tuple or len(facts) != 5 or
                control.decoder is not facts[0] or control.codec is not facts[1] or
                control.binding is not facts[2] or control.io is not facts[3] or control.metadata != facts[4] or
                control.io is not actual_executor.io or
                control.codec is not control_frame or type(control.decoder) is not control_frame.ControlFrameDecoder or
                control.decoder._binding is not control.binding or
                type(control.binding) is not control_frame.ControlBinding or
                control.binding is not self._connect_binding or
                actual_executor.deployment.connect_binding is not control.binding or
                control.binding._wire != self._connect_wire):
            _fail('wrong_owner')
        record, store = self._lease.record, self._store
        if (type(record) is not core.Journal or type(original_until) not in (int, float) or
                original_until != record.deadline or
                record.stage != 'client_init_ready' or not record.ready or
                store.session_issued_v28(record, store._session_profile, original_until) is not True):
            _fail('wrong_owner')
        self._now(original_until)
        until = self._peer_io_until_v29(original_until)  # Tighten only; never renew the Journal.
        records = tuple(t for t in self._owner._tickets if t.spec.role == 'watchdog')
        if (len(records) != 1 or not any(op.child is records[0] for op in self._bridge._operations) or
                not records[0].released or records[0].waited or records[0].unknown or
                records[0].deadline != original_until or type(records[0].parent) is not core.Actor or
                type(self._self) is not core.Actor or records[0].parent.key() != self._self.key()):
            _fail('wrong_owner')
        value = processes.DirectChildOwner.read_requests_passive_v30(self._owner, records[0], until)
        if type(value) is not bool: _fail('wrong_owner')
        if value: self.cancelled.set()
        return value  # False is not an owner/link/Proc permission or restoration proof.

    def poll_requests(self):
        if self._owner is None: return False
        found = False
        for child in self._owner._tickets:
            if child.spec.role == 'watchdog' and not child.waited:
                if self._lease is None or type(self._lease.record) is not core.Journal: _fail('wrong_owner')
                cap = self._peer_io_until_v29(self._lease.record.deadline)
                if self._owner.read_requests(child, _absolute_deadline=cap): self.cancelled.set(); found = True
        return found


class LinuxDirectChildLaunchBridge(phases.DirectChildLaunchBridge):
    """Only verification understands *authenticated* current FD reuse.

    All launch, C persistence, gate, once-close and wait actions stay inherited.
    Issued original close producers require exact registry/class and their
    actual close+EBADF branch. Current generation always fresh typed-owner IO.
    """
    def __init__(self, store, owner, specs, provider):
        super(LinuxDirectChildLaunchBridge, self).__init__(store, owner, specs)
        if type(provider) is not LinuxClientInitProvider: core._fail('invalid_provider')
        self.provider, self._generation_unknown = provider, False
        self._cleanup_deadline_v26 = None
        self._session_bound_v28 = False
    def bind_session(self, record):
        with self._mutex:
            if self._session_bound_v28 or self._operations or self.owner._tickets:
                core._fail('current_blocked')
            specs = self.provider.session_specs(record)
            self.specs = dict((s.role, s) for s in specs)
            self._session_bound_v28 = True
            return True
    def _capture_closed(self):
        good = True
        for child in self.owner._tickets:
            for row in child.fds:
                if row.closed and row.fd is not None:
                    good = self.provider._capture_issued_closed(self.owner._os, row.fd, row) and good
        for row in self.registry._inventory:
            if row.closed and row.fd is not None:
                good = self.provider._capture_issued_closed(row.io, row.fd, row) and good
        reader = self.owner._reader
        if type(reader) is proc.ProcReader:
            good = self.provider._remember_proc_history_v24(reader) and good
        else: good = False
        if not good: self._generation_unknown = True
        return good
    def _after(self):
        try: self._capture_closed()
        except BaseException: self._generation_unknown = True
    def prepare(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).prepare(op)
        finally: self._after()
    def launch(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).launch(op)
        finally: self._after()
    def release(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).release(op)
        finally: self._after()
    def resolve(self, op):
        try: return super(LinuxDirectChildLaunchBridge, self).resolve(op)
        finally: self._after()
    def _close_child_inventory(self, op):
        try:
            if not op.inventory_close_requested:
                op.inventory_close_requested = True
                try: op.inventory_closed = self.owner.close_inventory(op.child,
                    _absolute_deadline=self._cleanup_deadline_v26) is True
                except BaseException: self._pending = True
            return op.inventory_closed
        finally: self._after()
    def _close_pregate(self, op, deadline):
        try:
            child = op.child
            if (child.unknown or child.released or child.release_requested or self.owner._active or
                    not child.fork_returned or child.fork_negative or type(child.pid) is not int or child.pid <= 0):
                return False
            rows = [row for row in child.fds if row.role == 'gate_write']
            if len(rows) != 1: return False
            if op.gate is None: op.gate = rows[0]
            if op.gate is not rows[0]: return False
            gate = op.gate
            if op.gate_close_requested:
                return op.gate_closed and self._closed_fd(gate, self.owner._os, 'unknown')
            if (gate.unknown or gate.attempted or gate.closed or gate.returned is not True or
                    type(gate.fd) is not int or gate.metadata is None): return False
            self.owner._single(child, deadline=deadline, _absolute_deadline=deadline)
            op.gate_close_requested = True
            op.gate_closed = self.owner._close_fd(child, gate) is True
            return op.gate_closed
        finally: self._after()
    def _cleanup_child(self, op, provider, deadline):
        self._exact(op)
        child = op.child
        if op.prepare_unknown or type(child) is not processes.ChildTicket or child.unknown or self.owner._active:
            return False
        self.owner._exact(child)
        if not child.fork_requested or child.fork_negative:
            return self._close_child_inventory(op)
        if not child.fork_returned or child.preexec is None: return False
        if not child.released:
            if not self._close_pregate(op, deadline): return False
        elif not child.waited and not op.stop_requested:
            op.stop_requested = True
            try:
                returned = provider.request_child_stop(child, deadline)
                if returned is not None: op.stop_unknown = True
                else: op.stop_returned = True
            except core.ClientInitError as error:
                if error.code != 'provider_unavailable': op.stop_unknown = True
            except BaseException: op.stop_unknown = True
        if op.stop_unknown: return False
        remaining = deadline - self.owner._now()
        if remaining <= 0: return False
        try:
            if self.owner.wait_reap(child, min(.1, remaining), _absolute_deadline=deadline) is not True: return False
            if self.owner.fresh_exit(child, _absolute_deadline=deadline) is not True: return False
            op.exit_observations.append(child.exit_observation)
        except BaseException: return False
        return self._close_child_inventory(op)
    def cleanup(self, provider, deadline):
        with self._mutex:
            previous = self._cleanup_deadline_v26
            self._cleanup_deadline_v26 = deadline
            try:
                good = True
                for op in reversed(self._operations):
                    try: good = self._cleanup_child(op, provider, deadline) and good
                    except BaseException: good = False
                if not self._registry_close_requested:
                    self._registry_close_requested = True
                    try: self.registry.close()
                    except BaseException: self._pending = True
                return good and self.verify_closed(_absolute_deadline=deadline)
            finally:
                self._cleanup_deadline_v26 = previous
                self._after()
    def verify_closed(self, _absolute_deadline=None):
        with self._mutex:
            cap = _absolute_deadline if _absolute_deadline is not None else self.store._recovery_deadline
            if cap is not None:
                try: self.owner._now(cap)
                except BaseException: return False
            if self._generation_unknown: return False
            children = [o.child for o in self._operations if o.child is not None]
            if (self._pending or self.owner._active or self.registry._pending or
                    len(children) != len(self._operations) or len(children) != len(self.owner._tickets) or
                    any(not any(t is child for child in children) for t in self.owner._tickets) or
                    not self._registry_close_requested): return False
            for op in self._operations:
                child = op.child
                if op.prepare_unknown or op.stop_unknown or child.unknown or not op.inventory_closed: return False
                if child.fork_requested and not child.fork_negative:
                    if child.waited is not True or child.exit_verified is not True: return False
                    try:
                        if self.owner.fresh_exit(child, _absolute_deadline=cap) is not True: return False
                    except BaseException: return False
                for row in child.fds:
                    if row.unknown or row.closed is not True: return False
                    if row.fd is None:
                        if row.attempted: return False
                    elif not row.attempted or not self.provider._closed_fd(self.owner._os, row.fd, row): return False
            self._after()
            if self._generation_unknown: return False
            for row in self.registry._inventory:
                if row.opening_unknown or row.closed is not True: return False
                if row.fd is None:
                    if row.attempted: return False
                elif not row.attempted or not self.provider._closed_fd(row.io, row.fd, row): return False
            reader = self.owner._reader
            if type(reader) is proc.ProcReader:
                if reader._pending or not self.provider._proc_history_closed_v24(reader): return False
            else: return False
            if cap is not None:
                try: self.owner._now(cap)
                except BaseException: return False
            return True
    def status(self):
        value = super(LinuxDirectChildLaunchBridge, self).status()
        value['resource_pending'] = value['resource_pending'] or self._generation_unknown
        value['generation_unassessed'] = self._generation_unknown
        return value


class LinuxClientInitLease(phases.TwoPhaseClientInitLease):
    """Only teardown origin gate differs: safe owned DOWN is not reported UP."""
    def __init__(self, provider, store, identity, clock, bridge=None):
        core.ClientInitLease.__init__(self, provider, store, identity, clock)
        if type(provider) is not LinuxClientInitProvider or type(store) is not stores.DurableClientInitStore or (bridge is not None and
                (type(bridge) is not LinuxDirectChildLaunchBridge or bridge.store is not store or bridge.provider is not provider)):
            core._fail('invalid_store')
        self.bridge, self.launches, self.returned_handles = bridge, [], []
        self._start_attempted = self._restore_held = False
        self._provider_close_requested = self._provider_close_unknown = False
        self._provider_close = None
        self._diagnostic_restore = dict((key, 'not_recorded') for key in
            ('site', 'stage', 'error_group', 'error_code', 'result'))

    def connect_p2p(self, request, _checkpoint=None):
        """Trusted internal BLE caller only; not a Parent/HTTP/State endpoint."""
        with self.store._mutex:
            if self.provider._connection is not None or self.provider._connection_creation is not None or self.sealed or type(self.record) is not core.Journal:
                connection._fail('already_attempted')
            self.provider._connection_creation = {'request': request, 'operation': None, 'unknown': True}
            operation = connection._Connection(self.provider, self, request, _checkpoint)
            self.provider._connection_creation['operation'] = operation
            self.provider._connection = operation  # Before handoff/resources/callbacks.
            self.provider._connection_creation['unknown'] = False
            return operation.run()
    def read_connection(self, observation):
        operation = self.provider._connection
        if operation is None: connection._fail('not_connected')
        return operation.readback(observation)
    def disconnect_p2p(self):
        operation = self.provider._connection
        if operation is None: connection._fail('not_connected')
        return operation.disconnect()
    def read_association_receipt(self, receipt):
        with self.store._mutex:
            # A foreign/stale input cannot revoke a valid newer issuance.
            if type(receipt) is not connection.AssociationReceipt or receipt is not self.provider._active_association_receipt:
                connection._fail('receipt_stale')
            operation = self.provider._connection
            try:
                self.provider._association_receipt_current(receipt)
                operation.readback(receipt._observation)
                returned = operation.receipt  # Retain new producer original before postcheck.
                self.provider._association_receipt_current(returned)
                return returned
            except BaseException:
                if operation is not None: operation.invalidate_receipt(); operation.failed = True
                raise
    def create_private_dora(self, receipt):
        """Trusted F only: construct once from the currently issued original."""
        import mta_client_dora as dora
        with self.store._mutex:
            if (self.provider._lease is not self or self.provider._store is not self.store or
                    self.provider._dora_v26_creation is not None): connection._fail('already_attempted')
            self.provider._association_receipt_current(receipt)
            row = {'creator': dora.PrivateClientDora, 'receipt': receipt, 'issued': None,
                'returned': None, 'unknown': True}
            self.provider._dora_v26_creation = row  # Before constructor and every resource/callback.
            try:
                value = row['creator'](self, receipt)
                row['returned'] = value  # Before producer-origin postchecks.
                if (type(value) is not dora.PrivateClientDora or row['issued'] is not value or
                        value.lease is not self or value.provider is not self.provider or value.store is not self.store or
                        value._registration is not self.provider._dora_v21_registration): connection._fail('receipt_stale')
                row['unknown'] = False
                return value
            except BaseException as error:
                row['creation_error'] = error
                self.pending = self.resource_pending = True; self.cleanup_complete = False
                self.provider._close_dora_v26()
                raise
    def commit_client_ip(self, ip_record):
        """Trusted native IP owner only; persistence is not boolean authority."""
        import mta_client_dynamic_ip as dynamic_ip
        with self.store._mutex:
            ip_owner = self.provider._client_ip_owner_v28
            if (type(ip_owner) is not dynamic_ip.ClientDynamicIp or
                    ip_owner.lease is not self or ip_owner.store is not self.store or
                    type(ip_record) is not dynamic_ip.DynamicIpRecord or self.sealed or
                    self.locks is not self.store._current_locks): core._fail('invalid_record')
            rows, producer = ip_owner.commits, ip_owner.commit
            if (type(rows) is not list or not rows or type(rows[-1]) is not dict or
                    rows[-1].get('producer') is not producer or
                    rows[-1].get('proposed') is not ip_record or
                    rows[-1].get('returned') is not None or rows[-1].get('unknown') is not True or
                    ip_owner._active is not True or
                    getattr(producer, '__self__', None) is not self or
                    getattr(producer, '__func__', None) is not LinuxClientInitLease.commit_client_ip or
                    type(rows[-1].get('before')) is not core.Journal): core._fail('invalid_record')
            before = rows[-1]['before']
            self._fresh()
            if not core._same_journal(before, self.record): core._fail('current_blocked')
            self._save(self.record.replace(client_ip=ip_record))
            return self.record
    def _note_restore_diagnostic(self, site, result, error=None):
        """Only already-read stage and fixed first failure; never retain error."""
        try:
            if self._diagnostic_restore['result'] == 'raised' or site not in _DIAGNOSTIC_RESTORE_SITES or result not in ('raised', 'returned'):
                return
            record = self.record
            stage = 'none' if record is None else record.stage if type(record) is core.Journal and type(record.stage) is str and record.stage in core._STAGES else 'other'
            group, code = _diagnostic_error(error)
            self._diagnostic_restore = {'site': site, 'stage': stage,
                'error_group': group, 'error_code': code, 'result': result}
        except BaseException:
            pass

    def _restore_slice(self, deadline, seconds=20):
        now = self._now()
        if not 0 < deadline - now <= 60: core._fail('expired')
        return min(deadline, now + seconds)

    def restore(self, timeout=60, inherited=None, _absolute_deadline=None):
        core._finite(timeout, 'invalid_budget')
        if not 0 < timeout <= 60: core._fail('invalid_budget')
        now = self._now()
        deadline = now + timeout
        if _absolute_deadline is not None:
            core._finite(_absolute_deadline, 'invalid_budget')
            if not 0 < _absolute_deadline - now <= 60: core._fail('invalid_budget')
            deadline = min(deadline, _absolute_deadline)
        if self.sealed: return self._sealed_status(self._restore_slice(deadline))
        if self.bridge is None: self.reason = 'provider_unavailable'; return self.status()
        with self.store._mutex:
            self.store._resource_lane_v23 = resources.CLEANUP
            self.store._resource_budget_v23.cancel()  # Cannot renew network or borrow recovery reserve.
            if self.provider._connection is not None: self.provider._connection.invalidate_receipt()
            # The original current/_save/commit paths keep all CAS predicates.
            # Their default short budget is now also beneath this total. This
            # private field is not a caller-provided RF or restoration proof.
            previous_budget = self.store._recovery_deadline
            if previous_budget is not None: core._fail('current_blocked')
            self.store._recovery_deadline = deadline
            diagnostic_site = 'known_locks'
            try:
                self._known_locks_before_acquire(self._restore_slice(deadline))
                diagnostic_site = 'executor'
                proof = self._executor(self._restore_slice(deadline), inherited=self.locks if inherited is None else inherited)
                diagnostic_site = 'executor_role'
                if proof.role != 'owner': core._fail('executor_role_forbidden')
                diagnostic_site = 'self_actor'
                for op in self.launches:
                    for actual in (op.child.preexec, op.child.postexec) if op.child is not None else ():
                        if actual is not None and (proof.actor.pid, proof.actor.start) == (actual.pid, actual.start):
                            core._fail('self_actor_recovery')
                if not self._restore_held:
                    diagnostic_site = 'acquire'
                    self.locks = self.store.acquire(self.identity, self._restore_slice(deadline), self.locks if inherited is None else inherited)
                    self._restore_held = True
                diagnostic_site = 'current'
                self.record = self.store.current(self.locks)
                diagnostic_site = 'current_admission'
                if type(self.record) is not core.Journal or not self._pending_admission(self.record): core._fail('current_blocked')
                diagnostic_site = 'save_cleanup_intent'
                if self.record.stage != 'cleanup_intent': self._save(self.record.replace(stage='cleanup_intent', ready=False,
                    association=None if self.record.association is None else self.record.association.invalidated()))
                diagnostic_site = 'close_transfer_before_ip'
                if self.provider._close_transfer_v30(deadline) is not True:
                    core._fail('resource_close_unknown')
                diagnostic_site = 'close_peer_before_ip'
                if self.provider._close_peer_v29(deadline) is not True:
                    core._fail('resource_close_unknown')
                ip_owner = self.provider._client_ip_owner_v28
                if ip_owner is None and self.record.client_ip is not None:
                    core._fail('resource_close_unknown')
                if ip_owner is not None:
                    import mta_client_dynamic_ip as dynamic_ip
                    if (type(ip_owner) is not dynamic_ip.ClientDynamicIp or
                            ip_owner.provider is not self.provider or ip_owner.store is not self.store or
                            ip_owner.lease is not self or ip_owner.cleanup(deadline) is not True or
                            self.provider._client_ip_closed_v28() is not True):
                        core._fail('resource_close_unknown')
                # Retain the marker/children/owned interface while a DORA
                # producer remains unknown or live. A close request is not proof.
                diagnostic_site = 'close_resources'
                if self.provider._close_dora_v26() is not True or any(not c for a, c in self.provider._dora_facts_v26()):
                    core._fail('resource_close_unknown')
                diagnostic_site = 'baseline_before_children'
                self._baseline(self._restore_slice(deadline, 5), self.record.owned)
                diagnostic_site = 'bridge_cleanup'
                if self.bridge.cleanup(self.provider, self._restore_slice(deadline, 8)) is not True: core._fail('resource_close_unknown')
                diagnostic_site = 'baseline_after_children'
                self._baseline(self._restore_slice(deadline, 5), self.record.owned)
                diagnostic_site = 'owned_identity'
                owned = self.record.owned
                if owned is not None:
                    # Durable readback is a value object, not the CREATE owner.
                    issued = self.provider._owned
                    if type(issued) is not core.Origin or type(owned) is not core.Origin or issued.key() != owned.key():
                        core._fail('origin_changed')
                    owned = issued
                if owned is not None:
                    diagnostic_site = 'origin_ready_delete'
                    if self.provider.cleanup_origin_ready(owned, self._restore_slice(deadline, 5)) is not True or self.provider.delete_client(owned, self._restore_slice(deadline, 5)) is not True:
                        core._fail('origin_changed')
                    diagnostic_site = 'origin_absent'
                    if self.provider.origin_absent(owned, self._restore_slice(deadline)) is not True: core._fail('origin_changed')
                diagnostic_site = 'baseline_after_delete'
                self._baseline(self._restore_slice(deadline, 5))
                if not self._provider_close_requested:
                    self._provider_close_requested = True
                    diagnostic_site = 'close_resources'
                    try: self._provider_close = self.provider.close_resources(tuple(self.handles.values()), self._restore_slice(deadline))
                    except BaseException: self._provider_close_unknown = True; raise
                    diagnostic_site = 'close_proof'
                    if type(self._provider_close) is not core.CloseProof or not self._provider_close.complete():
                        self._provider_close_unknown = True
                diagnostic_site = 'close_proof'
                if self._provider_close_unknown or type(self._provider_close) is not core.CloseProof or \
                        self._provider_close.expected < len(self.launches) or not self.bridge.verify_closed(_absolute_deadline=deadline):
                    core._fail('resource_close_unknown')
                diagnostic_site = 'restore_reader'
                if self.store._restore_reader is None: core._fail('store_unavailable')
                diagnostic_site = 'baseline_terminal'
                self._baseline(self._restore_slice(deadline, 5))
                diagnostic_site = 'save_cleanup_verified'
                self._save(self.record.replace(stage='cleanup_verified', ready=False))
                diagnostic_site = 'finish_receipt'
                self._finish_receipt(self.record, True, deadline)
                if self.cleanup_complete: self.reason = 'not_recorded'
            except BaseException as error:
                self._note_restore_diagnostic(diagnostic_site, 'raised', error)
                self.pending = True; self.cleanup_complete = False
                self.reason = error.code if type(error) is core.ClientInitError else 'unexpected_provider_error'
                if not isinstance(error, Exception): raise
            finally:
                self.store._recovery_deadline = previous_budget
        self._note_restore_diagnostic('complete', 'returned')
        return self.status()
    def status(self):
        value = super(LinuxClientInitLease, self).status()
        value.update({'evidence': 'LINUX_CLIENT_PROVIDER_UNVERIFIED', 'provider_implemented': True,
            'rf_init_possible': self.provider.manifest is not None and not self.provider._sealed,
            'production_provider': False, 'target_verified': False})
        return value


def assemble(manifest, _connect_binding=None):
    """Pure assembly, not deployment, source verification or an RF admission."""
    provider = LinuxClientInitProvider(manifest, _connect_binding=_connect_binding)
    store = stores.DurableClientInitStore(manifest.run_token, manifest.identity,
        _clock=provider._clock, _restore_reader=provider, _prior_reader=provider,
        _session_profile=core.FORMAL_SESSION_PROFILE)
    owner = processes.DirectChildOwner(_clock=provider._clock)
    bridge = LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
    lease = LinuxClientInitLease(provider, store, manifest.identity, provider._clock, bridge)
    provider.attach(store, owner, bridge, lease)
    return provider, store, owner, bridge, lease

# V23 private tracked producer roots. These are accounting, not RF permissions.
# Typed raw projection is a PAYLOAD SUBSET; nested status/owner/marker and heap
# have not yet been proven globally covered. This SOURCE candidate is not staged.
def _payload_subset_v23(rows):
    payloads, seen, pending = [], set(), []
    for row in rows:
        reader = row.get('reader')
        value = row.get('value')
        if type(value) is proc.ProcObservation: pending.append(value.raw)
        if reader is not None:
            for attr in ('_raw', '_wiphy_raw', '_requests', '_observations'):
                pending.append(getattr(reader, attr, ()))
            observer = getattr(reader, '_reader', None)
            if type(observer) is proc.ProcReader: pending.append(observer._raw)
            for item in getattr(reader, '_readers', ()):
                if type(item) is dict and type(item.get('reader')) is proc.ProcReader:
                    pending.append(item['reader']._raw)
    visited = 0
    while pending:
        value = pending.pop(); visited += 1
        if visited > 131072: resources._fail('invalid_payload')
        if id(value) in seen: continue
        seen.add(id(value))
        if type(value) is bytes: payloads.append(value)
        elif type(value) in (tuple, list): pending.extend(value)
        elif type(value) is dict: pending.extend(value.values())
        elif type(value) is proc.RawRecord: pending.append(value.data)
        elif type(value) is proc.ProcObservation: pending.append(value.raw)
        elif type(value) is caps_transport.RawDatagram:
            pending.extend((value.data, value.ancillary))
    return tuple(payloads)


def _tracked_v23(kind, inventory, maximum):
    def decorate(method):
        def call(self, *args, **kwargs):
            budget = getattr(self, '_resource_budget_v23', None)
            if type(budget) is not resources.ResourceBudget or self._store is not budget._store:
                _fail('wrong_owner')
            if not budget._mutex.acquire(timeout=0.2): resources._fail('invalid_state')
            try:
                credit = self._reserve_v23(kind, maximum)
                prior = len(getattr(self, inventory)); budget.started(credit)
                producer_failed = False
                try: return method(self, *args, **kwargs)
                except BaseException:
                    producer_failed = True
                    raise
                finally:
                    originals = tuple(getattr(self, inventory)[prior:])
                    accounting_error = None
                    try:
                        payloads = _payload_subset_v23(originals)
                    except BaseException as error:
                        accounting_error = error
                        payloads = ()
                    try:
                        budget.returned(credit, originals, payloads)
                    except BaseException as error:
                        if accounting_error is None: accounting_error = error
                    finally:
                        try:
                            if accounting_error is not None or any(row.get('unknown') is not False for row in originals):
                                budget.mark_unknown(credit)
                        except BaseException as error:
                            if accounting_error is None: accounting_error = error
                        finally:
                            try: budget.settle(credit)
                            except BaseException as error:
                                if accounting_error is None: accounting_error = error
                    if accounting_error is not None and not producer_failed: raise accounting_error
            finally: budget._mutex.release()
        call.__name__ = method.__name__
        return call
    return decorate


LinuxClientInitProvider._observe = _tracked_v23('PROC_CALL', '_proc_calls', proc.MAX_TOTAL)(LinuxClientInitProvider._observe)
LinuxClientInitProvider.snapshot = _tracked_v23('COLLECTOR', '_collectors', 16 * 1024 * 1024)(LinuxClientInitProvider.snapshot)
LinuxClientInitProvider.caps = _tracked_v23('CAPS_READER', '_caps_readers', 4 * 1024 * 1024)(LinuxClientInitProvider.caps)
LinuxClientInitProvider._connection_caps = _tracked_v23('CAPS_READER', '_caps_readers', 4 * 1024 * 1024)(LinuxClientInitProvider._connection_caps)
LinuxClientInitProvider._connection_kernel = _tracked_v23('KERNEL_READER', '_kernel_readers', 8 * 1024 * 1024)(LinuxClientInitProvider._connection_kernel)
