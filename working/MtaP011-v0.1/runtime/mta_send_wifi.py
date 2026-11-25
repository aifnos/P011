# -*- coding: utf-8 -*-
"""Experimental owned P2P GO lease. Does not start radios on import.

Stage one only: create a private P2P netdev + private wpa, no DHCP/BLE/files.
Never controls wlan0 or the stock manager. RF writes require allow_rf=True.
Credentials are private return values, never journal/log data.
Python 3.5 / bundled JSON compatible. A host mock is NOT hardware evidence.
"""
import errno
import ctypes
import hashlib
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import time
try:
    import json
except ImportError:
    import p011_json as json

WPA_SHA256 = 'e069aef76a089215367f502015266e9ce59cf4ebb7d7246974815ff60d67f301'
IFNAME = re.compile(r'^mta[0-9a-f]{8}\Z')
DEVICE_LOCK = '/tmp/p011-mta-p2p-device.lock'
DEVICE_PENDING = '/tmp/p011-mta-p2p-device.pending'
# Verified by compiling mta-wifi-caps --ids against Linux UAPI headers.
CMD_GET_INTERFACE, CMD_NEW_INTERFACE, CMD_DEL_INTERFACE = 5, 7, 8
A_WIPHY, A_IFINDEX, A_IFNAME, A_IFTYPE, A_WDEV = 1, 3, 4, 5, 153
P2P_CLIENT, P2P_GO, P2P_DEVICE = 8, 9, 10
TRACKED = frozenset(('Z03', 'control_engine', 'weston', 'connmand', 'wpa_supplicant', 'bluetoothd'))
STOCK_PINS = {
    '/usr/bin/Z03': 'cb8d6a78617d50f64c6adc8056427dd963bc83979cbb04e349275dd8e8ffb62a',
    '/usr/bin/control_engine': '364b0bf820799070e89d9362000de4a3796a0e6a2d5f4d657464c6385b8dbd6d',
    '/usr/bin/zyb_z03_launch.sh': '7bce5379e3cc78e5bd8c04ceb603c88814f24c3a7efd28105ecc3c5849d6a42b'}

class LeaseError(RuntimeError):
    """Safe symbolic failure only; never include raw wpa/netlink messages."""

def _libc():
    library = ctypes.CDLL(None, use_errno=True)
    library.flock.argtypes = [ctypes.c_int, ctypes.c_int]; library.flock.restype = ctypes.c_int
    return library

def _disable_core():
    # This stripped P011 Python omits resource/fcntl; use the Linux libc ABI.
    class Limit(ctypes.Structure):
        _fields_ = [('soft', ctypes.c_ulong), ('hard', ctypes.c_ulong)]
    library = _libc()
    library.setrlimit.argtypes = [ctypes.c_int, ctypes.POINTER(Limit)]; library.setrlimit.restype = ctypes.c_int
    if library.setrlimit(4, ctypes.byref(Limit(0, 0))) != 0:
        raise LeaseError('cannot_disable_private_core_dump')
    library.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    library.prctl.restype = ctypes.c_int
    if library.prctl(4, 0, 0, 0, 0) != 0:
        raise LeaseError('cannot_disable_private_dumpability')

class JournalLock:
    def __init__(self, path): self.path = path; self.fd = None
    def __enter__(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise LeaseError('unsafe_journal_lock')
            library = _libc(); deadline = time.monotonic() + 10
            while library.flock(fd, 2 | 4) != 0:  # LOCK_EX | LOCK_NB
                if ctypes.get_errno() not in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR):
                    raise LeaseError('journal_lock_failed')
                if time.monotonic() >= deadline: raise LeaseError('journal_lock_timeout')
                time.sleep(.01)
            self.fd = fd; return self
        except BaseException:
            os.close(fd); raise
    def __exit__(self, kind, value, traceback):
        os.close(self.fd); self.fd = None

def _read_private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size > 65536:
            raise LeaseError('unsafe_private_json')
        with os.fdopen(fd, 'r') as handle:
            fd = None; value = json.loads(handle.read(65537))
        if not isinstance(value, dict): raise LeaseError('invalid_private_json')
        return value
    finally:
        if fd is not None: os.close(fd)

class DeviceGuard:
    """Fixed device-level flock + durable pending admission, no random-run bypass.

    A watchdog inherits the SAME open-file-description lock; it must retain that
    FD while reopening its netlink socket. Pending survives ordinary exceptions
    and blocks the next run until independently verified cleanup clears it.
    """
    def __init__(self, lock_path=DEVICE_LOCK, pending_path=DEVICE_PENDING):
        self.lock_path = lock_path; self.pending_path = pending_path; self.fd = None

    def acquire(self):
        if self.fd is not None: return
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise LeaseError('unsafe_device_lock')
            if _libc().flock(fd, 2 | 4) != 0:
                raise LeaseError('device_p2p_busy')
            os.set_inheritable(fd, False); self.fd = fd
        except BaseException:
            os.close(fd); raise

    def prepare(self, journal, boot_id, recovering=False):
        self.acquire()
        expected = {'version': 2, 'journal': os.path.abspath(journal), 'boot_id': boot_id,
                    'candidate_sha256': WPA_SHA256}
        if os.path.lexists(self.pending_path):
            current = _read_private_json(self.pending_path)
            if not recovering or current != expected:
                raise LeaseError('device_pending_requires_reconciliation')
            return
        # Initial creation is exclusive; a partial record blocks rather than
        # implying permission to create another RF interface.
        fd = os.open(self.pending_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps(expected, sort_keys=True)); handle.flush(); os.fsync(handle.fileno())
        self._sync_directory()

    def clear(self, journal, boot_id):
        if self.fd is None: raise LeaseError('device_lock_not_held')
        expected = {'version': 2, 'journal': os.path.abspath(journal), 'boot_id': boot_id,
                    'candidate_sha256': WPA_SHA256}
        if not os.path.lexists(self.pending_path): return
        if _read_private_json(self.pending_path) != expected:
            raise LeaseError('pending_record_identity_changed')
        os.unlink(self.pending_path); self._sync_directory()

    def _sync_directory(self):
        fd = os.open(os.path.dirname(self.pending_path), os.O_RDONLY)
        try:
            try: os.fsync(fd)
            except OSError as error:
                if error.errno not in (errno.EINVAL, errno.EBADF): raise
        finally: os.close(fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None

DIAGNOSTIC_STAGES = {1: 'init_enter', 2: 'capability', 3: 'early_param', 4: 'initial_type_gate',
                     5: 'initial_mode', 6: 'interface_up', 7: 'driver_finish', 8: 'driver_failed',
                     9: 'driver_deinit', 10: 'go_deinit_preserved', 11: 'client_deinit_preserved',
                     12: 'driver_init_result', 13: 'wps_init', 14: 'eapol_init',
                     15: 'control_init', 16: 'p2p_init'}

class PrivateDiagnostics:
    """Only numeric allowlisted frames enter memory/results; raw bytes never log."""
    def __init__(self):
        self.fd = None; self.buffer = b''; self.events = []; self.total = 0; self.invalid = False

    def feed(self, blob):
        if not isinstance(blob, bytes):
            self.invalid = True; return
        self.total += len(blob)
        if self.total > 4096:
            self.invalid = True; self.buffer = b''; return
        self.buffer += blob
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            match = re.match(br'^MTA_P2P_DIAG stage=([0-9]{1,2}) code=(-?[0-9]{1,4})\Z', line)
            if not match or len(self.events) >= 64:
                self.invalid = True; continue
            stage, code = int(match.group(1)), int(match.group(2))
            if stage not in DIAGNOSTIC_STAGES or not -4095 <= code <= 4095:
                self.invalid = True; continue
            self.events.append({'stage': DIAGNOSTIC_STAGES[stage], 'code': code})
        if len(self.buffer) > 64:
            self.invalid = True; self.buffer = b''

    def attach(self, fd):
        self.fd = fd
        library = _libc(); library.fcntl.restype = ctypes.c_int
        flags = library.fcntl(fd, 3)
        if flags < 0 or library.fcntl(fd, 4, flags | os.O_NONBLOCK) < 0:
            raise LeaseError('private_diagnostic_nonblocking_failed')

    def drain(self):
        if self.fd is None: return
        for _ in range(16):
            try: blob = os.read(self.fd, 512)
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK): return
                if error.errno == errno.EINTR: continue
                self.invalid = True; return
            if not blob: return
            self.feed(blob)

    def report(self):
        self.drain()
        return {'events': list(self.events), 'diagnostic_invalid': self.invalid or bool(self.buffer),
                'raw_diagnostics_not_logged': True}

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None
        self.buffer = b''

def _digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for blob in iter(lambda: handle.read(65536), b''):
            h.update(blob)
    return h.hexdigest()

def _proc_identity(pid):
    try:
        with open('/proc/%d/stat' % pid) as handle:
            tail = handle.read().rsplit(')', 1)[1].split()
        return {'pid': int(pid), 'starttime': int(tail[19]),
                'exe': os.readlink('/proc/%d/exe' % pid)}
    except (OSError, IndexError, ValueError):
        return None

def _original_route_digest(path, exclude_name=None):
    with open(path, 'rb') as handle: lines = handle.read(1048577).splitlines(True)
    if sum(len(line) for line in lines) > 1048576: raise LeaseError('route_snapshot_limit')
    if exclude_name:
        token = exclude_name.encode('ascii')
        lines = [line for line in lines if not line.split() or line.split()[-1] != token]
    return hashlib.sha256(b''.join(lines)).hexdigest()

def _origin_match(owned, row):
    return all(row.get(k) == owned.get(k) for k in ('name', 'ifindex', 'wdev', 'phy'))

def _address_dump(ifindex):
    """Read-only bounded RTM_GETADDR, returns only this exact ifindex's addresses."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    try:
        sock.set_inheritable(False); sock.bind((0, 0)); sock.settimeout(2)
        body = struct.pack('BBBBI', 0, 0, 0, 0, 0)
        sock.sendto(struct.pack('IHHII', 16 + len(body), 22, 1 | 0x300, 1, 0) + body, (0, 0))
        out = []; total = 0; end = time.monotonic() + 3
        while time.monotonic() < end:
            packet, _, trunc, sender = sock.recvmsg(262144); total += len(packet)
            if sender[0] or trunc & socket.MSG_TRUNC or total > 1048576:
                raise LeaseError('address_dump_limit')
            at = 0
            while at < len(packet):
                if len(packet) - at < 16: raise LeaseError('address_dump_truncated')
                length, kind, bits, seq, _ = struct.unpack_from('IHHII', packet, at)
                step = (length + 3) & ~3
                if length < 16 or step > len(packet) - at or seq != 1 or bits & 16:
                    raise LeaseError('address_dump_invalid')
                data = packet[at + 16:at + length]; at += step
                if kind == 3:
                    if data and (len(data) < 4 or struct.unpack_from('i', data)[0]):
                        raise LeaseError('address_dump_done_error')
                    return out
                if kind == 2: raise LeaseError('address_dump_error')
                if kind != 20 or len(data) < 8: raise LeaseError('address_dump_wrong_type')
                family, prefix, _, scope, index = struct.unpack_from('BBBBI', data)
                if index != ifindex: continue
                values = [v for k, v in _attrs(data[8:]) if k in (1, 2)]
                if not values: raise LeaseError('address_dump_identity_missing')
                for value in values:
                    if family == socket.AF_INET and len(value) == 4:
                        out.append({'family': 4, 'prefix': prefix, 'scope': scope, 'address': value})
                    elif family == socket.AF_INET6 and len(value) == 16:
                        out.append({'family': 6, 'prefix': prefix, 'scope': scope, 'address': value})
                    else: raise LeaseError('address_dump_family_invalid')
        raise LeaseError('address_dump_timeout')
    finally: sock.close()

def _only_link_local(addresses):
    return all(r['family'] == 6 and r['prefix'] == 64 and r['scope'] == 253 and
               len(r['address']) == 16 and r['address'][0] == 0xfe and r['address'][1] & 0xc0 == 0x80
               for r in addresses)

def _owned_routes_safe(name):
    with open('/proc/net/route') as handle:
        if any(line.split() and line.split()[0] == name for line in handle): return False
    with open('/proc/net/ipv6_route') as handle:
        for line in handle:
            parts = line.split()
            if not parts or parts[-1] != name: continue
            if len(parts) != 10: return False
            try:
                destination, prefix = int(parts[0], 16), int(parts[1], 16)
                if (not 10 <= prefix <= 64 or destination >> 118 != 0x3fa or
                        int(parts[2], 16) or int(parts[3], 16) or int(parts[4], 16)):
                    return False
            except ValueError: return False
    return True

def _attrs(blob):
    out = []; at = 0
    while at < len(blob):
        if len(blob) - at < 4:
            raise LeaseError('malformed_netlink_attribute')
        n, kind = struct.unpack_from('HH', blob, at); step = (n + 3) & ~3
        if n < 4 or step > len(blob) - at:
            raise LeaseError('malformed_netlink_attribute')
        out.append((kind & 0x3fff, blob[at + 4:at + n])); at += step
    return out

def _attr(kind, value):
    n = len(value) + 4
    return struct.pack('HH', n, kind) + value + b'\0' * ((-n) & 3)

def _interface(body):
    out = {}
    for kind, value in _attrs(body):
        if kind in (A_WIPHY, A_IFINDEX, A_IFTYPE):
            if len(value) != 4:
                raise LeaseError('invalid_interface_number')
            out[{A_WIPHY: 'phy', A_IFINDEX: 'ifindex', A_IFTYPE: 'iftype'}[kind]] = struct.unpack('I', value)[0]
        elif kind == A_WDEV:
            if len(value) != 8:
                raise LeaseError('invalid_wdev')
            out['wdev'] = struct.unpack('Q', value)[0]
        elif kind == A_IFNAME:
            if not value.endswith(b'\0') or len(value) > 16:
                raise LeaseError('invalid_interface_name')
            out['name'] = value[:-1].decode('ascii', 'strict')
    # A non-netdev P2P_DEVICE has no ifindex. It still blocks another private lease.
    if 'phy' not in out or 'wdev' not in out or 'iftype' not in out:
        raise LeaseError('incomplete_interface_identity')
    return out

class ReadWriteNetlink:
    """Private unicast socket; no subscription or arbitrary command API."""
    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16)
        self.sock.set_inheritable(False); self.sock.bind((0, 0)); self.sequence = 0
        rows = self._request(16, 3, _attr(2, b'nl80211\0'), 0)
        family = [struct.unpack('H', v)[0] for _, _, body in rows for k, v in _attrs(body) if k == 1 and len(v) == 2]
        if len(family) != 1:
            raise LeaseError('nl80211_family_missing')
        self.family = family[0]

    def close(self):
        self.sock.close()

    def _request(self, family, cmd, blob, flags):
        self.sequence += 1; seq = self.sequence
        self.sock.sendto(struct.pack('IHHII', 20 + len(blob), family, 1 | flags, seq, 0) +
                         struct.pack('BBH', cmd, 1, 0) + blob, (0, 0))
        deadline = time.monotonic() + 5; out = []; total = 0; count = 0
        while time.monotonic() < deadline:
            self.sock.settimeout(max(.01, deadline - time.monotonic()))
            packet, _, trunc, sender = self.sock.recvmsg(262144)
            total += len(packet); count += 1
            if trunc & socket.MSG_TRUNC or sender[0] or total > 1048576 or count > 256:
                raise LeaseError('netlink_receive_limit')
            at = 0
            while at < len(packet):
                if len(packet) - at < 16:
                    raise LeaseError('short_netlink_reply')
                n, kind, bits, q, _ = struct.unpack_from('IHHII', packet, at); step = (n + 3) & ~3
                if n < 16 or step > len(packet) - at or q != seq or bits & 16:
                    raise LeaseError('invalid_netlink_reply')
                body = packet[at + 16:at + n]; at += step
                if kind in (2, 3):
                    if kind == 2 and len(body) < 4:
                        raise LeaseError('short_netlink_error')
                    code = struct.unpack_from('i', body)[0] if len(body) >= 4 else 0
                    if code:
                        raise OSError(abs(code), 'private_nl80211_request_failed')
                    return out
                if kind != family or len(body) < 4:
                    raise LeaseError('wrong_netlink_family')
                out.append((kind, body[0], body[4:]))
                if not flags:
                    return out
        raise LeaseError('netlink_reply_timeout')

    def interfaces(self):
        return [_interface(body) for _, cmd, body in self._request(self.family, CMD_GET_INTERFACE, b'', 0x300)
                if cmd == CMD_NEW_INTERFACE]

    def create(self, name, phy):
        if not IFNAME.match(name) or not isinstance(phy, int) or phy < 0:
            raise LeaseError('invalid_owned_interface_request')
        if any(row.get('name') == name for row in self.interfaces()):
            raise LeaseError('interface_name_in_use')
        blob = (_attr(A_WIPHY, struct.pack('I', phy)) + _attr(A_IFTYPE, struct.pack('I', P2P_CLIENT)) +
                _attr(A_IFNAME, name.encode('ascii') + b'\0'))
        rows = self._request(self.family, CMD_NEW_INTERFACE, blob, 4 | 0x600)
        created = [_interface(body) for _, cmd, body in rows if cmd == CMD_NEW_INTERFACE]
        if len(created) != 1 or created[0].get('name') != name or created[0]['phy'] != phy or created[0]['iftype'] != P2P_CLIENT:
            # Never infer ownership from a post-hoc name lookup after an ambiguous create.
            raise LeaseError('create_reply_ownership_not_proven')
        return created[0]

    def delete(self, owned, allow_station=False):
        rows = [r for r in self.interfaces() if r.get('name') == owned['name']]
        if not rows:
            return True
        if (len(rows) != 1 or not _origin_match(owned, rows[0]) or
                rows[0].get('iftype') not in ((2, P2P_CLIENT, P2P_GO) if allow_station else (P2P_CLIENT, P2P_GO))):
            return False
        # Prefer WDEV identity: deleting by a reused interface name is never allowed.
        self._request(self.family, CMD_DEL_INTERFACE, _attr(A_WDEV, struct.pack('Q', owned['wdev'])), 4)
        return not any(r.get('wdev') == owned['wdev'] for r in self.interfaces())

def _owned_match(owned, row):
    return all(row.get(k) == owned.get(k) for k in ('name', 'ifindex', 'wdev', 'phy')) and row.get('iftype') in (P2P_CLIENT, P2P_GO)

class PrivateControl:
    def __init__(self, directory, peer):
        if not IFNAME.match(os.path.basename(peer)) or os.path.dirname(peer) != directory:
            raise LeaseError('invalid_private_ctrl_path')
        self.path = os.path.join(directory, 'cli-' + os.urandom(4).hex())
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.set_inheritable(False); self.sock.bind(self.path); os.chmod(self.path, 0o600)
        self.sock.connect(peer); self.sock.settimeout(2)

    def close(self):
        self.sock.close()
        try: os.unlink(self.path)
        except OSError: pass

    def request(self, command):
        # Constructed internally. No UI/network caller can submit a raw ctrl command.
        if command not in ('PING', 'ATTACH', 'DETACH', 'TERMINATE') and not re.match(r'^P2P_GROUP_ADD freq=[0-9]{4}$', command) and not re.match(r'^P2P_GROUP_REMOVE mta[0-9a-f]{8}$', command):
            raise LeaseError('ctrl_command_not_allowed')
        self.sock.send(command.encode('ascii'))
        return self.sock.recv(8192)

    def group_event(self, name, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.sock.settimeout(max(.01, deadline - time.monotonic()))
            event = self.sock.recv(8192)
            if len(event) >= 8192:
                raise LeaseError('wpa_event_limit')
            text = event.decode('utf-8', 'strict')
            if 'P2P-GROUP-STARTED ' not in text:
                continue
            match = re.search(r'P2P-GROUP-STARTED (mta[0-9a-f]{8}) GO ssid="([^"\r\n]*)" freq=([0-9]+) (?:psk=([0-9a-f]{64})|passphrase="([^"\r\n]*)") go_dev_addr=([0-9a-fA-F:]{17})(?: |$)', text.strip())
            if not match or match.group(1) != name:
                raise LeaseError('unexpected_private_group_event')
            ssid, freq, psk, password, address = match.group(2, 3, 4, 5, 6)
            if not 1 <= len(ssid.encode('utf-8')) <= 32 or (password is not None and not 8 <= len(password) <= 63):
                raise LeaseError('invalid_group_credentials')
            if not re.match(r'^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', address):
                raise LeaseError('invalid_group_address')
            # Private in-memory values, never printed or persisted by this module.
            return {'ssid': ssid, 'passphrase': password, 'psk': psk, 'frequency': int(freq), 'go_address': address}
        raise LeaseError('group_start_timeout')

class LinuxBackend:
    def __init__(self, binary, caps_probe, directory, allow_rf=False, inherited_guard=None):
        self.binary = os.path.abspath(binary); self.probe = os.path.abspath(caps_probe)
        self.directory = os.path.abspath(directory); self.allow_rf = allow_rf
        self.nl = ReadWriteNetlink(); self.command = None; self.monitor = None; self.boot_id = self._boot_id()
        self.guard = inherited_guard if inherited_guard is not None else DeviceGuard()
        self.diagnostics = PrivateDiagnostics()
        if inherited_guard is not None and inherited_guard.fd is None:
            raise LeaseError('inherited_device_lock_missing')
        if allow_rf and (os.geteuid() != 0 or os.uname()[4] != 'armv7l'):
            raise LeaseError('rf_target_or_stock_identity_mismatch')
        if allow_rf:
            _disable_core()
        for path in (self.binary, self.probe):
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
                raise LeaseError('unsafe_project_binary')
        if _digest(self.binary) != WPA_SHA256:
            raise LeaseError('private_wpa_hash_mismatch')
        st = os.lstat(self.directory)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise LeaseError('unsafe_private_run_directory')

    def _boot_id(self):
        with open('/proc/sys/kernel/random/boot_id') as handle: return handle.read().strip()

    def capabilities(self):
        process = subprocess.Popen([self.probe, '--capabilities'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = process.communicate(timeout=7)
        if process.returncode or len(out) > 32768:
            raise LeaseError('capability_probe_failed')
        caps = json.loads(out.decode('ascii'))
        if caps.get('event') != 'wifi_caps' or caps.get('read_only') is not True:
            raise LeaseError('capability_probe_invalid')
        return caps

    def acquire_device_lock(self):
        if not self.allow_rf: raise LeaseError('rf_write_not_armed')
        self.guard.acquire()

    def begin_lease(self, journal): self.guard.prepare(journal, self.boot_id)
    def recover_lease(self, journal): self.guard.prepare(journal, self.boot_id, recovering=True)
    def complete_lease(self, journal): self.guard.clear(journal, self.boot_id)

    def snapshot(self, exclude_owned=None):
        identities = []
        for token in os.listdir('/proc'):
            if not token.isdigit(): continue
            try:
                with open('/proc/' + token + '/comm') as handle: name = handle.read().strip()
                if name in TRACKED:
                    identity = _proc_identity(int(token))
                    if identity:
                        identity['cmdline_digest'] = _digest('/proc/' + token + '/cmdline')
                        identities.append(identity)
            except OSError: pass
        process = subprocess.Popen(['/usr/sbin/wpa_cli', '-i', 'wlan0', 'status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = process.communicate(timeout=5)
        fields = dict(line.split('=', 1) for line in out.decode('utf-8', 'replace').splitlines() if '=' in line)
        if process.returncode or fields.get('wpa_state') != 'COMPLETED':
            raise LeaseError('original_station_not_connected')
        try: frequency = int(fields.get('freq', '0'))
        except ValueError: frequency = 0
        if frequency not in range(2412, 2473, 5):
            raise LeaseError('same_channel_2ghz_frequency_unavailable')
        interfaces = self.nl.interfaces()
        wlan = [r for r in interfaces if r.get('name') == 'wlan0']
        if len(wlan) != 1 or wlan[0]['iftype'] != 2:
            raise LeaseError('original_station_identity_invalid')
        original_interfaces = [r for r in interfaces if exclude_owned is None or not _origin_match(exclude_owned, r)]
        exclude_name = exclude_owned['name'] if exclude_owned else None
        return {'boot_id': self.boot_id, 'processes': sorted(identities, key=lambda x: x['pid']),
                'station': wlan[0], 'interfaces': sorted(original_interfaces, key=lambda x: x['wdev']),
                'frequency': frequency, 'route_digest': _digest('/proc/net/route'),
                'ipv6_route_digest': _original_route_digest('/proc/net/ipv6_route', exclude_name),
                'ipv6_address_digest': _original_route_digest('/proc/net/if_inet6', exclude_name)}

    def create(self, name, phy):
        if not self.allow_rf: raise LeaseError('rf_write_not_armed')
        if any(_digest(p) != value for p, value in STOCK_PINS.items()):
            raise LeaseError('stock_identity_mismatch_before_create')
        return self.nl.create(name, phy)

    def interfaces(self): return self.nl.interfaces()

    def spawn_private(self, name, save_process):
        if not self.allow_rf or not IFNAME.match(name): raise LeaseError('rf_write_not_armed')
        ctrl = os.path.join(self.directory, 'ctrl'); os.mkdir(ctrl, 0o700)
        conf = os.path.join(self.directory, 'private.conf')
        fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write('ctrl_interface=' + ctrl + '\nupdate_config=0\np2p_no_group_iface=1\nap_scan=2\n'
                         'device_name=P011\ndevice_type=1-0050F204-1\n'
                         'driver_param=mta_p2p_initial=1 control_port=0\n')
        # Gate child before exec: durable PID/starttime ownership precedes RF init.
        readfd, writefd = os.pipe(); diagnostic_read, diagnostic_write = os.pipe(); pid = os.fork()
        if pid == 0:
            try:
                os.close(diagnostic_read)
                os.close(writefd); os.setsid()
                token = os.read(readfd, 1); os.close(readfd)
                if token != b'1': os._exit(125)
                devnull = os.open('/dev/null', os.O_RDWR)
                for stream in (0, 1, 2): os.dup2(devnull, stream)
                if devnull > 2: os.close(devnull)
                os.dup2(diagnostic_write, 3); os.set_inheritable(3, True)
                if diagnostic_write != 3: os.close(diagnostic_write)
                os.execve(self.binary, [self.binary, '-Dnl80211', '-i' + name, '-c' + conf, '-q'],
                          {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'MTA_PRIVATE_P2P': '1'})
            except BaseException: os._exit(126)
        os.close(diagnostic_write); os.close(readfd)
        try:
            self.diagnostics.attach(diagnostic_read)
            record = _proc_identity(pid)
            if not record: raise LeaseError('private_child_identity_missing')
            record['exe'] = self.binary
            save_process(record)
            os.write(writefd, b'1')
        finally: os.close(writefd)
        peer = os.path.join(ctrl, name); deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            self.diagnostics.drain()
            identity = _proc_identity(pid)
            if not identity or identity['starttime'] != record['starttime']:
                raise LeaseError('private_wpa_exit')
            if os.path.exists(peer):
                st = os.lstat(peer)
                if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.getuid():
                    raise LeaseError('private_ctrl_not_owned')
                self.command = PrivateControl(ctrl, peer); self.monitor = PrivateControl(ctrl, peer)
                if self.command.request('PING') != b'PONG\n' or self.monitor.request('ATTACH') != b'OK\n':
                    raise LeaseError('private_ctrl_not_ready')
                self.diagnostics.drain()
                required = {'initial_type_gate', 'initial_mode', 'interface_up', 'driver_finish', 'driver_init_result', 'p2p_init'}
                seen = {event['stage'] for event in self.diagnostics.events if event['code'] == 0}
                if self.diagnostics.invalid or not required.issubset(seen):
                    raise LeaseError('private_init_diagnostics_not_confirmed')
                return
            time.sleep(.05)
        raise LeaseError('private_wpa_ready_timeout')

    def group_add(self, name, frequency):
        self.diagnostics.drain()
        if self.diagnostics.invalid: raise LeaseError('private_diagnostics_invalid_before_go')
        if not self.allow_rf or self.command.request('P2P_GROUP_ADD freq=%d' % frequency) != b'OK\n':
            raise LeaseError('private_group_add_failed')
        result = self.monitor.group_event(name, 6)
        self.diagnostics.drain(); return result

    def stop_process(self, record):
        if not record: return True
        current = _proc_identity(record['pid'])
        if current is None: return True
        if current != record: return False
        if not self.allow_rf: return False
        os.kill(record['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try: os.waitpid(record['pid'], os.WNOHANG)
            except (ChildProcessError, OSError): pass
            current = _proc_identity(record['pid'])
            if current is None: return True
            if current != record: return False
            time.sleep(.05)
        # Exact PID/starttime/exe still checked before bounded forced termination.
        if _proc_identity(record['pid']) != record: return False
        os.kill(record['pid'], signal.SIGKILL)
        time.sleep(.1)
        try: os.waitpid(record['pid'], os.WNOHANG)
        except (ChildProcessError, OSError): pass
        return _proc_identity(record['pid']) is None

    def process_gone(self, record):
        return record is None or _proc_identity(record['pid']) is None

    def station_cleanup_ready(self, owned):
        if not IFNAME.match(owned['name']): return False
        root = '/sys/class/net/' + owned['name']
        try:
            with open(root + '/flags') as handle: flags = int(handle.read().strip(), 16)
            with open(root + '/operstate') as handle: operstate = handle.read().strip()
            with open(root + '/dormant') as handle: dormant = handle.read().strip()
            tokens = (owned['name'].encode('ascii'), ('-i' + owned['name']).encode('ascii'))
            for pid in os.listdir('/proc'):
                if not pid.isdigit(): continue
                try:
                    with open('/proc/' + pid + '/cmdline', 'rb') as handle:
                        blob = handle.read(65537)
                    if len(blob) > 65536: return False
                    args = blob.split(b'\0')
                    if any(token in args for token in tokens): return False
                except OSError: pass
            quiescent = not flags & 1 or operstate == 'dormant' or dormant == '1'
            return bool(quiescent and _only_link_local(_address_dump(owned['ifindex'])) and _owned_routes_safe(owned['name']))
        except (OSError, ValueError, LeaseError): return False

    def remove(self, owned, allow_station=False):
        if not self.allow_rf: return False
        return self.nl.delete(owned, allow_station=allow_station)

    def diagnostic_report(self): return self.diagnostics.report()

    def close(self, release_guard=True):
        for ctrl in (self.monitor, self.command):
            if ctrl: ctrl.close()
        self.diagnostics.close()
        self.nl.close()
        if release_guard: self.guard.close()

class GoLease:
    """Explicit lifecycle, durable secret-free journal, fail-closed ownership."""
    def __init__(self, backend, journal, clock=time.monotonic):
        self.backend = backend; self.journal = journal; self.clock = clock
        self.state = None; self.credentials = None

    def _lock(self):
        return JournalLock(self.journal + '.lock')

    def _save(self, locked=False):
        if not locked:
            with self._lock(): return self._save(locked=True)
        # Parent directory must already be 0700; never follow a replaced journal.
        directory = os.path.dirname(os.path.abspath(self.journal)); st = os.lstat(directory)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise LeaseError('journal_directory_not_private')
        current = _read_private_json(self.journal) if os.path.lexists(self.journal) else None
        if current is not None and self.state['stage'] not in ('cleanup_intent', 'reconciled', 'recovery_required'):
            if current.get('stage') in ('cleanup_intent', 'reconciled', 'recovery_required'):
                raise LeaseError('lease_already_entered_cleanup')
        path = self.journal + '.new'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'w') as handle:
                handle.write(json.dumps(self.state, sort_keys=True)); handle.flush(); os.fsync(handle.fileno())
            os.replace(path, self.journal)
            dirfd = os.open(directory, os.O_RDONLY)
            try: os.fsync(dirfd)
            except OSError as e:
                if e.errno not in (errno.EINVAL, errno.EBADF): raise
            finally: os.close(dirfd)
        finally:
            if os.path.lexists(path): os.unlink(path)

    def start(self, ttl=20, watchdog=None):
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 20:
            raise LeaseError('trial_ttl_invalid')
        if self.state is not None or os.path.lexists(self.journal):
            raise LeaseError('existing_lease_requires_reconciliation')
        if watchdog is None:
            raise LeaseError('independent_watchdog_required')
        self.backend.acquire_device_lock()
        baseline = self.backend.snapshot(); caps = self.backend.capabilities()
        phys = [p for p in caps.get('phys', []) if p.get('index') == baseline['station']['phy']]
        if len(phys) != 1 or not {'station', 'p2p_client', 'p2p_go'}.issubset(set(phys[0].get('iftypes', []))) or not any(c.get('station_plus_go_same_channel') is True for c in phys[0].get('combinations', [])):
            raise LeaseError('driver_concurrency_not_proven')
        if any(r['iftype'] in (P2P_CLIENT, P2P_GO, P2P_DEVICE) for r in self.backend.interfaces()):
            raise LeaseError('external_p2p_present')
        name = 'mta' + os.urandom(4).hex()
        self.backend.begin_lease(self.journal)
        self.state = {'version': 2, 'stage': 'create_intent', 'name': name, 'baseline': baseline,
                      'deadline': self.clock() + ttl, 'owned': None, 'process': None}
        self._save()
        try:
            watchdog(self.journal, self.state['deadline'])
            # Serialize the create intent against the inherited watchdog's
            # cleanup intent. Never start RF after deadline/reconciliation.
            with self._lock():
                if self.clock() >= self.state['deadline']: raise LeaseError('lease_expired_before_create')
                current = _read_private_json(self.journal)
                if current.get('stage') != 'create_intent': raise LeaseError('lease_already_entered_cleanup')
                self.state['owned'] = self.backend.create(name, baseline['station']['phy'])
                self.state['stage'] = 'interface_created'; self._save(locked=True)
            if self.clock() >= self.state['deadline']: raise LeaseError('lease_expired_before_spawn')
            def save_process(record):
                self.state['process'] = record; self.state['stage'] = 'private_process_pre_exec'; self._save()
                if self.clock() >= self.state['deadline']: raise LeaseError('lease_expired_before_exec')
            self.backend.spawn_private(name, save_process)
            if self.clock() >= self.state['deadline']: raise LeaseError('lease_expired_before_go')
            self.state['stage'] = 'group_add_intent'; self._save()
            self.credentials = self.backend.group_add(name, baseline['frequency'])
            if self.credentials.get('frequency') != baseline['frequency']:
                raise LeaseError('private_go_not_on_requested_channel')
            current = [r for r in self.backend.interfaces() if r.get('name') == name]
            if len(current) != 1 or not _owned_match(self.state['owned'], current[0]) or current[0]['iftype'] != P2P_GO:
                raise LeaseError('go_interface_identity_not_confirmed')
            if self.clock() >= self.state['deadline']: raise LeaseError('lease_expired_during_go')
            self.state['stage'] = 'go_ready'; self._save()
            return {'event': 'private_go_ready', 'ttl': ttl, 'credentials_not_logged': True}
        except BaseException:
            self.stop(); raise

    def expired(self): return self.state is not None and self.clock() >= self.state['deadline']

    def stop(self):
        if self.state is None: return {'event': 'no_owned_lease'}
        with self._lock(): return self._stop_locked()

    def _stop_locked(self):
        if os.path.exists(self.journal):
            current = _read_private_json(self.journal)
            if current.get('stage') == 'reconciled' and current.get('owned') == self.state.get('owned') and current.get('process') == self.state.get('process'):
                self.state = current; self.credentials = None
                # Cached PASS is not current restoration evidence.
                gone = self.backend.process_gone(self.state.get('process'))
                interfaces = self.backend.interfaces()
                owned = self.state.get('owned')
                absent = not any(r.get('name') == self.state['name'] or owned is not None and r.get('wdev') == owned['wdev']
                                 for r in interfaces)
                try: baseline = self.backend.snapshot() == self.state['baseline']
                except Exception: baseline = False
                if gone and absent and baseline:
                    self.backend.complete_lease(self.journal)
                    return {'event': 'private_go_cleanup', 'owned_process_removed': True,
                            'owned_interface_removed': True, 'stock_baseline_equal': True,
                            'complete': True, 'independent_readback': True}
                self.state['stage'] = 'recovery_required'
                self.backend.recover_lease(self.journal)
                report = {'event': 'private_go_cleanup', 'owned_process_removed': gone,
                          'owned_interface_removed': absent, 'stock_baseline_equal': baseline,
                          'complete': False, 'independent_readback': True}
                self.state['cleanup_result'] = report; self._save(locked=True)
                return report
        self.credentials = None
        self.state['stage'] = 'cleanup_intent'; self._save(locked=True)
        process_ok = self.backend.stop_process(self.state.get('process'))
        process_ok = bool(process_ok and self.backend.process_gone(self.state.get('process')))
        owned = self.state.get('owned')
        try: pre_baseline_ok = self.backend.snapshot(exclude_owned=owned) == self.state['baseline']
        except Exception: pre_baseline_ok = False
        # A still-alive mismatched process may control a changed interface. Never delete it.
        if process_ok and owned:
            current = [r for r in self.backend.interfaces() if r.get('name') == owned['name']]
            station_allowed = (len(current) == 1 and _origin_match(owned, current[0]) and
                               current[0].get('iftype') == 2 and pre_baseline_ok and
                               self.backend.station_cleanup_ready(owned))
            interface_ok = self.backend.remove(owned, allow_station=station_allowed)
        else:
            interface_ok = process_ok and not any(r.get('name') == self.state['name'] for r in self.backend.interfaces())
        try: baseline_ok = self.backend.snapshot() == self.state['baseline']
        except Exception: baseline_ok = False
        complete = bool(process_ok and interface_ok and baseline_ok)
        self.state['stage'] = 'reconciled' if complete else 'recovery_required'
        report = {'event': 'private_go_cleanup', 'owned_process_removed': bool(process_ok),
                'owned_interface_removed': bool(interface_ok), 'stock_baseline_equal': baseline_ok,
                'complete': complete}
        self.state['cleanup_result'] = report; self._save(locked=True)
        if complete: self.backend.complete_lease(self.journal)
        return report

    def recover(self):
        st = os.lstat(self.journal)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size > 65536:
            raise LeaseError('unsafe_recovery_journal')
        state = _read_private_json(self.journal)
        if state.get('version') != 2 or not IFNAME.match(state.get('name', '')) or state.get('baseline', {}).get('boot_id') != self.backend.boot_id:
            raise LeaseError('recovery_identity_invalid')
        if not isinstance(state.get('baseline', {}).get('interfaces'), list) or any(
                not isinstance(state['baseline'].get(k), str) or not re.match(r'^[0-9a-f]{64}\Z', state['baseline'][k])
                for k in ('ipv6_route_digest', 'ipv6_address_digest', 'route_digest')):
            raise LeaseError('recovery_original_baseline_incomplete')
        owned = state.get('owned'); process = state.get('process')
        if owned and (owned.get('name') != state['name'] or owned.get('iftype') != P2P_CLIENT or any(not isinstance(owned.get(k), int) or isinstance(owned[k], bool) or owned[k] < 0 for k in ('phy', 'ifindex', 'wdev'))):
            raise LeaseError('recovery_interface_invalid')
        if process and (process.get('exe') != self.backend.binary or any(not isinstance(process.get(k), int) or isinstance(process[k], bool) or process[k] <= 0 for k in ('pid', 'starttime'))):
            raise LeaseError('recovery_process_invalid')
        self.backend.acquire_device_lock(); self.backend.recover_lease(self.journal)
        self.state = state
        return self.stop()

def start_watchdog(backend, journal, deadline):
    """Independent child. It only restores an identity-checked private journal."""
    if not backend.allow_rf:
        raise LeaseError('rf_write_not_armed')
    parent = _proc_identity(os.getpid())
    pid = os.fork()
    if pid:
        return pid
    try:
        os.setsid(); backend.close(release_guard=False)
        null = os.open('/dev/null', os.O_RDWR)
        for stream in (0, 1, 2): os.dup2(null, stream)
        if null > 2: os.close(null)
        _disable_core()
        while time.monotonic() < deadline and _proc_identity(parent['pid']) == parent:
            try:
                with open(journal) as handle: current = json.loads(handle.read())
                if current.get('stage') == 'reconciled': break
            except (OSError, ValueError): pass
            time.sleep(.1)
        recovery = LinuxBackend(backend.binary, backend.probe, backend.directory, allow_rf=True,
                                inherited_guard=backend.guard)
        try: report = GoLease(recovery, journal).recover()
        finally: recovery.close()
        code = 0 if report.get('complete') else 2
    except BaseException:
        report = {'event': 'watchdog_failed', 'complete': False}; code = 3
    try:
        fd = os.open(journal + '.watchdog-result', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps(report)); handle.flush(); os.fsync(handle.fileno())
    except BaseException: pass
    os._exit(code)

class SenderGoContext:
    """Private GO context. No IP/DHCP support is advertised at this stage."""
    def __init__(self, lease):
        self.lease = lease; self.interface = lease.state['name']; self.local_ip = None
        self.ssid = lease.credentials['ssid']; self.psk = lease.credentials.get('passphrase') or lease.credentials.get('psk')
        self.mac = lease.credentials['go_address']

    def restore(self):
        self.ssid = self.psk = self.mac = None
        return self.lease.stop().get('complete', False)

    def status(self):
        return {'stage': self.lease.state['stage'], 'ip_ready': False, 'dhcp_ready': False,
                'expired': self.lease.expired()}

class SendWifiBackend:
    """Root integration adapter; never confuses GO-only with send-ready."""
    def __init__(self, helper_path, supplicant_path, run_dir, allow_rf=False):
        self.backend = LinuxBackend(supplicant_path, helper_path, run_dir, allow_rf)
        self.lease = GoLease(self.backend, os.path.join(run_dir, 'p2p-lease.json')); self.context = None

    def capabilities(self):
        raw = self.backend.capabilities()
        declared = any({'p2p_client', 'p2p_go'}.issubset(set(p.get('iftypes', []))) and
                       any(c.get('station_plus_go_same_channel') is True for c in p.get('combinations', []))
                       for p in raw.get('phys', []))
        return {'send': {'available': False, 'p2pDeclared': declared, 'p2pVerified': False,
                         'reason': 'private_go_and_dhcp_and_phone_transfer_not_verified'}, 'read_only': True}

    def create_group(self, cancelled=None, timeout=20):
        # Experimental admission only; production's 180-second lease is not proven.
        if cancelled is not None and cancelled(): raise LeaseError('cancelled_before_rf')
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 20:
            raise LeaseError('experimental_group_timeout_must_not_exceed_20')
        self.lease.start(ttl=timeout, watchdog=lambda path, end: start_watchdog(self.backend, path, end))
        if cancelled is not None and cancelled():
            self.lease.stop(); raise LeaseError('cancelled_after_group_create')
        self.context = SenderGoContext(self.lease)
        return self.context

    def restore(self):
        return self.context.restore() if self.context else self.lease.stop().get('complete', False)

    def status(self):
        return self.context.status() if self.context else {'stage': 'idle', 'send_available': False}

    def close(self):
        self.backend.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Explicit private P011 GO stage-one trial; no DHCP/BLE/files')
    parser.add_argument('--trial', action='store_true'); parser.add_argument('--recover', action='store_true')
    parser.add_argument('--run-dir', required=True); parser.add_argument('--binary', required=True)
    parser.add_argument('--caps-probe', required=True); parser.add_argument('--ttl', type=int, default=20)
    args = parser.parse_args()
    if args.trial == args.recover:
        parser.error('Select exactly one explicit --trial / --recover action')
    backend = LinuxBackend(args.binary, args.caps_probe, args.run_dir, allow_rf=True)
    lease = GoLease(backend, os.path.join(args.run_dir, 'p2p-lease.json')); result = None
    def stop_signal(signum, frame): raise LeaseError('trial_interrupted')
    for token in (signal.SIGTERM, signal.SIGINT): signal.signal(token, stop_signal)
    try:
        if args.recover:
            result = lease.recover()
        else:
            ready = lease.start(ttl=args.ttl, watchdog=lambda path, end: start_watchdog(backend, path, end))
            print(json.dumps(ready)); __import__('sys').stdout.flush()
            while not lease.expired(): time.sleep(.1)
            result = lease.stop()
    except BaseException as error:
        reason = error.args[0] if isinstance(error, LeaseError) and error.args else type(error).__name__
        try: cleanup = lease.stop() if lease.state is not None else {'complete': True, 'no_radio_mutation': True}
        except BaseException: cleanup = {'complete': False, 'event': 'cleanup_failed'}
        result = {'event': 'private_go_trial_failed', 'reason': reason, 'cleanup': cleanup, 'complete': False}
    finally:
        diagnostics = backend.diagnostic_report()
        backend.close()
    result['diagnostics'] = diagnostics
    print(json.dumps(result)); return 0 if result.get('complete') else 1

if __name__ == '__main__':
    raise SystemExit(main())
