"""Native same-owner GO bootstrap mechanics, Linux 4.14/ARM, SOURCE only.

This module does not import a CLIENT lease/provider/Ready/caps grant. Neutral
Snapshot/Actor/Origin and the actual route dump decoder are facts only. Every
mutation needs this original GO Store's durable intent, original creator and
same worker/period. Constructor/status do no IO. There is no arbitrary command,
scan, guessed peer/channel, default route/DNS, send or public raw logging.

The fixed WPA 2.12 source uses p2p_no_group_iface=1: GROUP_ADD applies
SET_INTERFACE to the original private type 8 netdev, then starts type 9 AP.
Fresh kernel/event/STATUS must prove that SAME tuple; extra interfaces are
pending, never adopted by name. See the pinned archive's p2p_supplicant.c
6200/8115/8182, ap.c 1044/1068 and driver_nl80211.c 7216/8215. These are source
mechanics, not a claim that P011 firmware/driver or a phone has passed them.

Private event/STATUS/packets can contain SSID/PSK and remain strong in-memory
originals only. No repr/status/export reveals them. HOST _io seams are explicit
OS models, not permission or evidence of a device executable.

r4 retains incomplete CREATE ECHO as side-effect evidence only, separates
original raw close from a first pathname unlink, and passively waits for the
original controller endpoint under the unchanged stage deadline.

r5 stop-only cleanup authenticates the once original owner period and existing
bound cleanup accounting. An unknown GO publication never authorizes group
commands, netdev deletion, pending removal or a restoration-success claim.

v46 treats absent GET_INTERFACE frequency only as unavailable corroboration.
Actual stock STATUS, associated BSS/caps and received GO event/AP STATUS remain
mandatory channel facts; request text never supplies an observed frequency.

v49 reuses only the digest retained from each exact same pin-file read.
Independent pathname/process image reads, freshness gates and original caps
remain unchanged; no digest survives as a cache or grants a later read.

v52 skips only an initial enumerated comm open that actually returned ENOENT
without any descriptor. Exact original request/error and known-absence ticket
remain retained; later read/metadata/Proc/image/close failures still refuse.

v55 keeps at most two private snapshot timing rows with five original-clock
samples each. This observer adds small clock/formatting overhead only: no
source read, gate, cap, resource, closure or admission is removed or renewed.

v56 coalesces adjacent source authentication only after a local pure shape,
original-identity and fixed-method guard. Unknown shapes retain the full old
wrappers. The guard adds work; neither a speedup nor arbitrary in-process
monkeypatch equivalence is claimed. The Store PID boundary still reauthenticates.

v56-r2 additionally checks the original Entry/Store wrapper bound functions;
instance replacements fall back to the complete old wrapper path.

v60 retains only the first rejected actual Proc observation and original Reader.
No predicate, read, clock or closure is repeated for this private diagnostic.

v62 active consumers take one new full snapshot against the original baseline.
Initial issuance and cleanup/delete/restore retain the original double reads.
This removes the active boundary's second temporal sample, not a claim of
semantic equivalence, atomicity, completed device flow or measured speedup.

v72 carries only typed IP/DHCP producers from v54 into this current v62
source. Original ACK/creator/readback, durable phase, UDP inventory and once
cleanup gates remain mandatory. Owner coalescing, private diagnostics and the
four active fresh-boundary call sites above are preserved; no transfer receipt,
provider, readiness, quota increase, renewed period or device proof is added.

v74 separates synchronous DHCP setup from one later service issuance. Only
three real IP/group/baseline boundaries authorize first UDP creation, post-bind
observation and first service. Intermediate setup facts are once consumed by
an exact transient Store consumer, not cached freshness or a packet grant.
This deliberately changes intermediate temporal sampling; no semantic-equivalence
or measured-performance claim is made. Original session/cleanup/quotas remain.

v75 issues a private GO send basis only from original serving DHCP and fresh
IP/group/AP STATUS. One owned TCP socket may be bound, never listened/accepted
or authorized here. The original service cap is not renewed. TCP must be known
closed before DHCP/IP/group deletion; an unknown factory/FD remains pending.
"""
import errno
import hashlib
import hmac
import math
import os
import re
import select
import signal
import socket
import stat
import struct
import sys
import threading
import types

import mta_client_resource_budget as _budget_v56
import mta_client_proc as _proc_v56
import mta_go_executor as _entry_v56
import mta_go_bootstrap_store as _store_v56
import mta_ip as ip
import mta_ip_lease as ip_lease
import mta_go_bootstrap_store as stores
import mta_p2p_client_init as core
import mta_go_deployment as sources

# Pure definition-time originals from earlier modules in this exact graph.
# Function/class continuity references only, never permission or cached ready.
_COALESCE_CLASSES_V56 = (_budget_v56.ResourceBudget, _proc_v56.ProcReader)
_COALESCE_FUNCTIONS_V56 = (_budget_v56.ResourceBudget._context, _proc_v56.ProcReader.owns_generation,
    _entry_v56.GoEntrySource._context, _store_v56.GoBootstrapStore._owner)

_NL, _GH, _NA, _CRED = struct.Struct('<IHHII'), struct.Struct('<BBH'), struct.Struct('<HH'), struct.Struct('<iii')
_MAX_PACKET, _MAX_RAW, _MAX_FDS, _MAX_ROWS = 262144, 16777216, 8192, 4096
_READ, _CLOEXEC, _NOFOLLOW = 0, 0x80000, 0x8000
_TRACKED = ('Z03', 'control_engine', 'weston', 'connmand', 'wpa_supplicant', 'bluetoothd')
_BOOT = '/proc/sys/kernel/random/boot_id'
_PRIVATE = frozenset((b'ATTACH', b'STATUS'))


def _fail(code): raise sources.GoSourceError(code) from None
def _int(v, lo=0, hi=0xffffffff): return type(v) is int and lo <= v <= hi
def _meta(v):
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
    row = tuple(getattr(v, n, None) for n in names)
    if any(not sources._uint(x) for x in row): _fail('native_metadata_unknown')
    return row
def _attr(kind, raw):
    if not _int(kind, 1, 16383) or type(raw) is not bytes or len(raw) > 65531: _fail('native_attr_invalid')
    n = 4 + len(raw)
    return _NA.pack(n, kind) + raw + b'\0' * ((-n) & 3)
def _attrs(raw):
    if type(raw) is not bytes or len(raw) > _MAX_PACKET: _fail('native_attr_invalid')
    at, rows = 0, []
    while at < len(raw):
        if len(raw) - at < 4: _fail('native_attr_invalid')
        n, kind = _NA.unpack_from(raw, at); end = at + ((n + 3) & ~3)
        if n < 4 or end > len(raw) or any(raw[at + n:end]) or kind & 0x4000: _fail('native_attr_invalid')
        rows.append((kind & 0x3fff, kind & 0xc000, raw[at + 4:at + n])); at = end
        if len(rows) > _MAX_ROWS: _fail('native_attr_limit')
    return tuple(rows)
def _fields(raw):
    result = {}
    for kind, flags, value in _attrs(raw):
        if kind in result: _fail('native_attr_duplicate')
        result[kind] = (flags, value)
    return result
def _u(row, width=4):
    if type(row) is not tuple or len(row) != 2 or row[0] or len(row[1]) != width: _fail('native_scalar_invalid')
    return struct.unpack('<Q' if width == 8 else '<I' if width == 4 else '<H', row[1])[0]
def _flag(row):
    if row != (0, b''): _fail('native_flag_invalid')
    return True
def _nested(row):
    if row[0] not in (0, 0x8000): _fail('native_nested_invalid')
    return _attrs(row[1])
def _text(row, limit=256):
    flags, raw = row
    if flags or not 2 <= len(raw) <= limit or raw[-1:] != b'\0' or b'\0' in raw[:-1]: _fail('native_text_invalid')
    try: value = raw[:-1].decode('ascii')
    except UnicodeError: _fail('native_text_invalid')
    if any(ord(x) < 32 or ord(x) > 126 for x in value): _fail('native_text_invalid')
    return value
def _origin(raw):
    f = _fields(raw)
    if not {1, 3, 4, 5, 153} <= set(f): _fail('native_interface_invalid')
    value = core.Origin(_u(f[1]), _u(f[153], 8), _u(f[3]), _text(f[4], 16), _u(f[5]))
    frequency = _u(f[38]) if 38 in f else None
    mac = f[6][1] if 6 in f and not f[6][0] else None
    if mac is not None and (len(mac) != 6 or not any(mac) or mac[0] & 1): _fail('native_interface_invalid')
    return value, frequency, mac
def _status(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 8192 or b'\0' in raw: _fail('native_status_invalid')
    result = {}
    for line in raw.splitlines():
        if b'=' not in line: _fail('native_status_invalid')
        name, value = line.split(b'=', 1)
        if re.fullmatch(b'[a-zA-Z0-9_]{1,64}', name) is None or name in result: _fail('native_status_invalid')
        result[name] = value
    return result


_SSID_ESCAPES_V75 = {34:b'\\"',92:b'\\\\',27:b'\\e',10:b'\\n',13:b'\\r',9:b'\\t'}
_SSID_UNESCAPE_V75 = {34:34,92:92,101:27,110:10,114:13,116:9}

def _go_ssid_v75(text):
    """Pure exact vendor printf_encode bytes; never source authority."""
    if type(text) is not bytes or not 1<=len(text)<=128:
        _fail('native_send_credentials_invalid')
    result=[];at=0
    while at<len(text):
        octet=text[at]
        if octet==92:
            if at+1>=len(text): _fail('native_send_credentials_invalid')
            escape=text[at+1]
            if escape in _SSID_UNESCAPE_V75:
                result.append(_SSID_UNESCAPE_V75[escape]);at+=2
            elif escape==120 and at+3<len(text) and re.fullmatch(b'[0-9a-f]{2}',text[at+2:at+4]) is not None:
                result.append(int(text[at+2:at+4],16));at+=4
            else: _fail('native_send_credentials_invalid')
        elif 32<=octet<=126 and octet!=34:
            result.append(octet);at+=1
        else: _fail('native_send_credentials_invalid')
        if len(result)>32: _fail('native_send_credentials_invalid')
    raw=bytes(result)
    canonical=b''.join(_SSID_ESCAPES_V75[o] if o in _SSID_ESCAPES_V75 else
        bytes((o,)) if 32<=o<=126 else ('\\x%02x'%o).encode('ascii') for o in raw)
    if canonical!=text or not raw or b'\0' in raw:
        _fail('native_send_credentials_invalid')
    try: decoded=raw.decode('utf-8')
    except UnicodeError: _fail('native_send_credentials_invalid')
    return decoded,raw

class _GoCredentialsV75(object):
    __slots__=('ssid','ssid_bytes','psk','go_dev_addr')
    def __init__(self,ssid,ssid_bytes,psk,go_dev_addr):
        for name,value in zip(self.__slots__,(ssid,ssid_bytes,psk,go_dev_addr)):
            object.__setattr__(self,name,value)
    def __setattr__(self,*unused): raise AttributeError('immutable private GO credentials')
    def __repr__(self): return '<private GO credential data; not authority>'

def _go_credentials_v75(raw,owned_name,frequency):
    """Strict real GO event grammar. Both reported keys must agree by PBKDF2."""
    if type(raw) is not bytes or not 1<=len(raw)<=8192 or b'\0' in raw or \
            type(owned_name) is not str or re.fullmatch(r'mta[0-9a-f]{8}',owned_name) is None or \
            type(frequency) is not int:
        _fail('native_send_credentials_invalid')
    line=raw[:-2] if raw.endswith(b'\r\n') else raw[:-1] if raw.endswith(b'\n') else raw
    if any(o<32 or o>126 for o in line): _fail('native_send_credentials_invalid')
    line=re.sub(b'^<[0-4]>',b'',line)
    parts=line.split(b' ',3)
    if len(parts)!=4 or parts[:3]!=[b'P2P-GROUP-STARTED',owned_name.encode('ascii'),b'GO']:
        _fail('native_send_credentials_invalid')
    text=parts[3];fields={};persistent=False;at=0
    while at<len(text):
        if text[at:at+12]==b'[PERSISTENT]':
            if persistent: _fail('native_send_credentials_invalid')
            persistent=True;at+=12
        else:
            split=text.find(b'=',at)
            if split<0 or b' ' in text[at:split]: _fail('native_send_credentials_invalid')
            key=text[at:split]
            if key not in (b'ssid',b'freq',b'psk',b'passphrase',b'go_dev_addr') or key in fields:
                _fail('native_send_credentials_invalid')
            at=split+1
            if key in (b'ssid',b'passphrase'):
                if text[at:at+1]!=b'"': _fail('native_send_credentials_invalid')
                begin=at=at+1
                while at<len(text) and text[at]!=34:
                    if key==b'ssid' and text[at]==92: at+=1
                    at+=1
                if at>=len(text): _fail('native_send_credentials_invalid')
                value=text[begin:at];at+=1
            else:
                end=text.find(b' ',at)
                if end<0: end=len(text)
                value=text[at:end];at=end
            if not value: _fail('native_send_credentials_invalid')
            fields[key]=value
        if at<len(text):
            if text[at:at+1]!=b' ' or at+1==len(text): _fail('native_send_credentials_invalid')
            at+=1
    if not {b'ssid',b'freq',b'go_dev_addr'}<=set(fields) or \
            not (b'psk' in fields or b'passphrase' in fields) or \
            re.fullmatch(b'[1-9][0-9]{3}',fields[b'freq']) is None or int(fields[b'freq'])!=frequency:
        _fail('native_send_credentials_invalid')
    ssid,ssid_bytes=_go_ssid_v75(fields[b'ssid'])
    mac_text=fields[b'go_dev_addr']
    if re.fullmatch(b'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',mac_text) is None:
        _fail('native_send_credentials_invalid')
    mac=bytes(int(part,16) for part in mac_text.split(b':'))
    if not any(mac) or mac[0]&1: _fail('native_send_credentials_invalid')
    psk=fields.get(b'psk');phrase=fields.get(b'passphrase')
    if psk is not None and re.fullmatch(b'[0-9a-fA-F]{64}',psk) is None:
        _fail('native_send_credentials_invalid')
    if phrase is not None and (not 8<=len(phrase)<=63 or any(o<32 or o>126 for o in phrase)):
        _fail('native_send_credentials_invalid')
    if phrase is not None and psk is not None:
        function=getattr(hashlib,'pbkdf2_hmac',None)
        if not callable(function): _fail('native_send_kdf_unavailable')
        try: derived=function('sha1',phrase,ssid_bytes,4096,32)
        except (ValueError,TypeError,OverflowError,NotImplementedError): _fail('native_send_kdf_unavailable')
        expected=bytes(int(psk[at:at+2],16) for at in range(0,64,2))
        if type(derived) is not bytes or len(derived)!=32 or not hmac.compare_digest(derived,expected):
            _fail('native_send_credentials_invalid')
    chosen=phrase.decode('ascii') if phrase is not None else psk.decode('ascii').lower()
    return _GoCredentialsV75(ssid,ssid_bytes,chosen,mac)


class _LinuxIo(object):
    def validate(self): sources._LinuxIo().validate()
    def open(self, path, flags): return os.open(path, flags)
    def read(self, fd, n): return os.read(fd, n)
    def close(self, fd): return os.close(fd)
    def fstat(self, fd): return os.fstat(fd)
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def readlink(self, path): return os.readlink(path)
    def listdir(self, path): return os.listdir(path)
    def realpath(self, path): return os.path.realpath(path)
    def unlink(self, path): return os.unlink(path)
    def socket(self, protocol): return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
    def unix(self): return socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    def udp(self): return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    def tcp(self): return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    def kill_term(self, pid): return os.kill(pid, signal.SIGTERM)
    def pause(self, seconds): return select.select((), (), (), seconds)


class _Resource(object):
    """Exact original native return retained before validation/first syscall."""
    def __init__(self, native, kind, cleanup_until):
        self.native, self.kind, self.cleanup_until = native, kind, cleanup_until
        self._cleanup_until_original = cleanup_until
        self.value = self.fd = self.metadata = self.port = None
        self.returned = self.unknown = self.attempted = self.closed = False
        self.path = self.path_meta = self.peer = self.peer_meta = self.actor = None
        self.bound = self.unlink_called = False
        self.endpoint_closed = True
        self.failure = self.close_failure = self.endpoint_failure = None
        self._open_requested_path_v52 = self._open_requested_flags_v52 = None
        self._open_error_original_v52 = None
        self._tcp_bind_called_v75 = False
        self._tcp_endpoint_v75 = None
        self._tcp_factory_called_v75 = False
    def __repr__(self): return '<private original GO native resource>'


class _Observation(object):
    def __init__(self, native):
        for name,value in (('native',native),('owner',native.owner),('until',native.until)):
            object.__setattr__(self,name,value)
    def __setattr__(self,*unused): raise AttributeError('immutable original GO observation')
    def __repr__(self): return '<private GO native observation; not readiness>'


class GoBaselineObservation(_Observation):
    def __init__(self, native, snapshot): _Observation.__init__(self, native); object.__setattr__(self,'snapshot',snapshot)
class GoChannelObservation(_Observation):
    def __init__(self, native, frequency, caps_raw, channel_raw, beacon_interval, go_beacon_interval):
        _Observation.__init__(self, native)
        for name,value in (('frequency',frequency),('caps_raw',caps_raw),('channel_raw',channel_raw),
                ('beacon_interval',beacon_interval),('go_beacon_interval',go_beacon_interval),
                ('caps_sha256',hashlib.sha256(b''.join(caps_raw)).hexdigest()),
                ('channel_sha256',hashlib.sha256(channel_raw).hexdigest())):
            object.__setattr__(self,name,value)
class GoGroupSource(_Observation):
    def __init__(self, native, channel):
        _Observation.__init__(self, native)
        for name,value in (('channel',channel),('frequency',channel.frequency),
                ('channel_sha256',channel.channel_sha256),('caps_sha256',channel.caps_sha256)):
            object.__setattr__(self,name,value)
class GoGroupObservation(_Observation):
    def __init__(self, native, event_raw, status_raw, frequency, observed_origin):
        _Observation.__init__(self, native)
        for name,value in (('event_raw',event_raw),('status_raw',status_raw),('frequency',frequency),('observed_origin',observed_origin)):
            object.__setattr__(self,name,value)
class GoNativeRestoreObservation(_Observation):
    def __init__(self, native, snapshot): _Observation.__init__(self, native); object.__setattr__(self,'snapshot',snapshot)


class GoIpObservation(_Observation):
    def __init__(self,native,facts,snapshot=None):
        _Observation.__init__(self,native)
        object.__setattr__(self,'facts',facts);object.__setattr__(self,'snapshot',snapshot)
class GoIpRestoreObservation(GoIpObservation): pass
class GoDhcpObservation(_Observation):
    def __init__(self,native,facts):
        _Observation.__init__(self,native);object.__setattr__(self,'facts',facts)

class _DhcpSetupToken(object):
    """Once synchronous publication facts, never kernel freshness or IO authority."""
    def __init__(self,native,binding,server,observation,canonical,history,row):
        for name,value in (('native',native),('owner',native.owner),('store',native.store),
                ('deployment',native.deployment),('worker',native.worker),('mutex',native.mutex),
                ('clock',native.clock),('until',native.until),
                ('setup_until',native._dhcp_setup_until_original),
                ('originals',native._dhcp_setup_originals),('binding',binding),('server',server),
                ('constructor',native.owner._dhcp_ticket_original),('ip',native.ip_receipt),
                ('ack',native._ip_ack_original),('observation',observation),
                ('canonical',canonical),('history',history),('issuer',native.store.issuer),
                ('row',row),('raw',None if row is None else row.value),
                ('fd',None if row is None else row.fd),
                ('metadata',None if row is None else row.metadata),('nonce',object())):
            object.__setattr__(self,name,value)
    def __setattr__(self,*unused): raise AttributeError('immutable original DHCP setup facts')
    def __repr__(self): return '<private once DHCP setup facts; not readiness>'


class GoDhcpBinding(object):
    """Actual native issuance, never serialized or constructed as a grant."""
    def __init__(self,native,original_ip):
        for k,v in (('native',native),('owner',native.owner),('store',native.store),
                ('deployment',native.deployment),('worker',native.worker),('mutex',native.mutex),
                ('clock',native.clock),('until',native.until),('setup_until',native._dhcp_setup_until_original),
                ('origin',original_ip.facts.origin),
                ('server_ip',original_ip.facts.spec.address),('client_ip',original_ip.facts.spec.address+1),
                ('subnet_mask',0xffffff00),('_ip',original_ip)):
            object.__setattr__(self,k,v)
    def __setattr__(self,*unused): raise AttributeError('immutable original GO DHCP binding')
    def check(self,server): return NativeGoResources._dhcp_gate(self.native,self,server)
    def active_until(self,server):
        NativeGoResources._dhcp_gate(self.native,self,server)
        original=self.native._dhcp_service_original
        if original is None or self.native._dhcp_service_returned is not True:
            _fail('native_dhcp_service_not_issued')
        return original[1]
    def cancelled(self,server):
        NativeGoResources._dhcp_owner(self.native,self,server)
        return self.owner._cancelled(self.until)
    def admit_station(self,server,mac_bytes,client_ip):
        return NativeGoResources._admit_station(self.native,self,server,mac_bytes,client_ip)
    def open_socket(self,server): return NativeGoResources._dhcp_socket(self.native,self,server)
    def close_socket(self,server,sock): return NativeGoResources._dhcp_close_socket(self.native,self,server,sock)
    def socket_current(self,server,sock):
        NativeGoResources._dhcp_owner(self.native,self,server)
        row=self.native.dhcp_row
        if row is None or row.value is not sock: _fail('native_dhcp_socket_changed')
        self.native._fd_current(row);return True

class GoSendBasis(object):
    """Private immutable native issuance, not a NetworkReceipt or peer grant."""
    __slots__=('native','owner','store','deployment','entry','worker','mutex','clock','until','end',
        'group','event_raw','current_status_raw','origin','ip','ack','canonical','history','issuer',
        'service_tuple','binding','server','dhcp_row','dhcp_raw','dhcp_fd','dhcp_metadata',
        'ssid','ssid_bytes','psk','go_dev_addr')
    def __init__(self,native,end,credentials,status_raw):
        values=(native,native.owner,native.store,native.deployment,native.entry,native.worker,
            native.mutex,native.clock,native.until,end,native.group,native.group.event_raw,status_raw,
            native.group.observed_origin,native.ip_receipt,native._ip_ack_original,native.store.current,
            native.store._canonical_history,native.store.issuer,native._dhcp_service_original,
            native.dhcp_binding,native.owner.dhcp,native.dhcp_row,native.dhcp_row.value,
            native.dhcp_row.fd,native.dhcp_row.metadata,credentials.ssid,credentials.ssid_bytes,
            credentials.psk,credentials.go_dev_addr)
        for name,value in zip(self.__slots__,values): object.__setattr__(self,name,value)
    def __setattr__(self,*unused): raise AttributeError('immutable private GO send basis')
    def __repr__(self): return '<private original GO send basis; no peer or send readiness>'

class GoSendListener(object):
    """Original bound TCP only. No listen, accept, TLS, wire or peer authority."""
    __slots__=('native','basis','row','raw','fd','metadata','port','end','endpoint')
    def __init__(self,native,basis,row,end):
        values=(native,basis,row,row.value,row.fd,row.metadata,row.port,end,row._tcp_endpoint_v75)
        for name,value in zip(self.__slots__,values): object.__setattr__(self,name,value)
    def __setattr__(self,*unused): raise AttributeError('immutable private GO bound TCP')
    def __repr__(self): return '<private original bound TCP; not listening or peer authority>'

class NativeGoResources(object):
    """Real socket/file/kernel/control producers under the exact original GO F.

    Default Linux IO; seams may model OS only. Pure ctor retains Store/entry/
    fixed source originals. Each method receives a narrowing absolute period,
    never remaining TTL. Resource observations and physical closure uncertainty
    are separate; parsing/timeout does not erase an actual close+typed EBADF.
    """
    def __init__(self, owner, _io=None):
        self.owner, self.store, self.deployment = owner, owner.store, owner.deployment
        self.until, self.worker, self.mutex, self.clock = self.store.until, self.store.worker, self.store.mutex, self.store.clock
        self.entry, self.io = owner.entry, _io if _io is not None else _LinuxIo()
        self._originals = (owner, self.store, self.deployment, self.until, self.worker, self.mutex, self.clock, self.entry, self.io)
        self.rows, self.raw, self.observations, self.proc_observations = [], [], [], []
        self._rows_original, self._history = self.rows, ()
        self._raw_bytes, self._packets, self._sequence, self._endpoint_sequence = 0, 0, 0, 0
        self._scope, self._scope_cleanup, self.last, self.failure = None, False, None, None
        self.baseline = self.channel = self.group_source = self.group = self.restored = None
        self.interface_ticket = self.create_row = self.create_request = self.owned = None
        self._create_echo_original = None  # An ECHO alone is NOT confirmed ownership.
        self.command_row = self.event_row = self._ctrl_actor = None
        self._create_called = self._delete_called = self._group_submit_called = self._group_remove_called = False
        self._termination = {}; self._config_raw = self._config_meta = self._config_anchors = None
        self._stop_only_calls,self._stop_only_observations,self._stop_only_failures=set(),[],[]
        self._ancillary_unknown = False; self._server_unlink_called = self._server_absent = False
        self._server_original = None
        self._go_beacon_interval = None
        self.ip_intent=self.ip_receipt=self.ip_cleanup_intent=self.ip_restored=None
        self.ip_row=self.ip_request=self.ip_ack=None
        self._ip_route_original=None
        self._ip_ack_original=None
        self._ip_create_called=self._ip_delete_called=False
        self.dhcp_binding=self.dhcp_row=self.dhcp_intent=self.dhcp_observed=self.dhcp_closed=None
        self._dhcp_row_original=None
        self._dhcp_open_called=self._dhcp_close_called=False
        self._station_wire=None
        self._dhcp_service_original=self._dhcp_service_issued_original=None
        self._dhcp_service_attempted=self._dhcp_service_returned=False
        self._dhcp_setup_until_original=self._dhcp_setup_originals=None
        self._dhcp_setup_originals_issued=None
        self._dhcp_setup_tokens=self._dhcp_setup_token_history=()
        self._dhcp_setup_c0=self._dhcp_setup_h0=None
        self._dhcp_setup_c1=self._dhcp_setup_h1=None
        self._dhcp_setup_c2=self._dhcp_setup_h2=None
        self._dhcp_intent_token_original=self._dhcp_listening_token_original=None
        self._dhcp_intent_consumed=self._dhcp_listening_consumed=False
        self._snapshot_timing_v55 = []  # Diagnostic data only; never authority.
        self.last_proc_failure_v60 = None  # First retained (value, reader), data only.
        self._send_basis_attempted = self._send_basis_returned = False
        self._send_basis_original = self._send_basis_issued_original = self._send_basis_end_original = None
        self._send_status_raw_v75 = None
        self._send_credentials_original_v75 = None
        self._send_listener_attempted = self._send_listener_returned = False
        self._send_listener_original = None
        self._send_tcp_rows_v75 = self._send_tcp_history_v75 = ()
        self._send_close_attempted_v75 = False
    def __repr__(self): return '<private original native GO resources; no IP/send readiness>'
    def _owner(self):
        self.deployment.loader.authenticate(self.deployment)
        # Local optimization choice only, not an input/grant or cached proof.
        # Exact shapes/identities are checked before any bound method is read;
        # the guard never invokes a foreign method, IO operation or clock.
        coalesce = False
        try:
            modules = self.deployment.modules
            if type(self) is NativeGoResources and type(self.deployment) is sources.LoadedGoDeployment and \
                    type(self.owner) is modules['mta_go_bootstrap'].GoBootstrap and \
                    type(self.entry) is modules['mta_go_executor'].GoEntrySource and \
                    type(self.store) is modules['mta_go_bootstrap_store'].GoBootstrapStore and \
                    type(self._originals) is tuple and len(self._originals) == 9 and \
                    type(self.rows) is list and type(self._history) is tuple and \
                    len(self.rows) == len(self._history) and \
                    all(a is b for a,b in zip(self.rows,self._history)) and \
                    type(self.until) is float and type(self.entry.until) is float and \
                    all(a is b for a,b in zip((self.owner,self.store,self.deployment,self.until,
                        self.worker,self.mutex,self.clock,self.entry,self.io),self._originals)) and \
                    type(self.entry.accounting) is modules['mta_client_store'].DurableClientInitStore and \
                    type(self.entry.accounting_ticket) is dict and \
                    type(self.entry.accounting_ticket['unknown']) is bool and \
                    type(self.entry.accounting._attempted) is bool and type(self.entry.accounting._opened) is bool and \
                    type(self.entry.budget) is _COALESCE_CLASSES_V56[0] and \
                    _COALESCE_CLASSES_V56[0] is modules['mta_client_resource_budget'].ResourceBudget and \
                    type(self.entry.reader) is _COALESCE_CLASSES_V56[1] and \
                    _COALESCE_CLASSES_V56[1] is modules['mta_client_proc'].ProcReader and \
                    type(self.entry.budget._readers) is list and len(self.entry.budget._readers) == 1 and \
                    self.entry.budget._readers[0] is self.entry.reader and self.entry.budget._provider is None and \
                    type(self.entry.observations) is list and type(self.entry.reader._history) is list and \
                    all(type(g) is modules['mta_client_proc'].ProcGeneration for g in self.entry.reader._history) and \
                    ((self.entry.actor is None and self.entry.boot is None) or \
                        (type(self.entry.actor) is core.Actor and type(self.entry.boot) is str and \
                         len(self.entry.observations) > 0 and \
                         type(self.entry.observations[-1]) is modules['mta_client_proc'].ProcObservation and \
                         type(self.entry.observations[-1].boot) is str)):
                budget_context = self.entry.budget._context
                reader_owns = self.entry.reader.owns_generation
                entry_context = self.entry._context
                store_owner = self.store._owner
                coalesce = (type(budget_context) is types.MethodType and
                    budget_context.__self__ is self.entry.budget and
                    budget_context.__func__ is _COALESCE_FUNCTIONS_V56[0] and
                    type(reader_owns) is types.MethodType and
                    reader_owns.__self__ is self.entry.reader and
                    reader_owns.__func__ is _COALESCE_FUNCTIONS_V56[1] and
                    type(entry_context) is types.MethodType and
                    entry_context.__self__ is self.entry and
                    entry_context.__func__ is _COALESCE_FUNCTIONS_V56[2] and
                    type(store_owner) is types.MethodType and
                    store_owner.__self__ is self.store and
                    store_owner.__func__ is _COALESCE_FUNCTIONS_V56[3])
        except BaseException:
            coalesce = False  # Unknown guard shape falls back, never succeeds.
        module = self.deployment.modules['mta_go_bootstrap']
        if type(self.owner) is not module.GoBootstrap or self.owner.native is not self or \
                self.store._native_original is not self or self.store.owner is not self.owner or \
                self.deployment.loader.runtime is not self.owner or threading.current_thread() is not self.worker or threading.active_count()!=1 or \
                self.rows is not self._rows_original or tuple(self.rows) != self._history or \
                (self.owner, self.store, self.deployment, self.until, self.worker, self.mutex, self.clock, self.entry, self.io) != self._originals or \
                self.entry is not self.owner.entry or self.entry.clock is not self.clock or self.entry.until != self.until:
            _fail('native_owner_changed')
        if coalesce:
            # Adjacent fixed original predicates; the Store retains post-PID D.
            self.deployment.modules['mta_go_executor'].GoEntrySource._context_after_source_v56(self.entry)
            self.deployment.modules['mta_go_bootstrap_store'].GoBootstrapStore._owner_after_source_v56(self.store)
        else:
            self.entry._context(); self.store._owner()
    def _now(self, end=None):
        self._owner(); value = sources._time(self.clock())
        if self.last is not None and value < self.last: _fail('clock_regressed')
        self.last = value
        if end is not None and value >= end: _fail('deadline')
        return value
    def _begin(self, end, cleanup=False):
        self._owner(); end = sources._time(end)
        limit = self.store.restore_until if cleanup else self.until
        if limit is None or end > limit or cleanup and not self.store.restore_attempted: _fail('native_scope_invalid')
        self._scope, self._scope_cleanup = end, cleanup
        self._now(end)
        # This is the existing process accounting cap, not CLIENT authority.
        self.entry.accounting._io_deadline = end
        return end
    def _check(self):
        value=self._now(self._scope)
        if not self._scope_cleanup:
            module=self.deployment.modules['mta_go_bootstrap']
            if module.GoBootstrap._cancelled(self.owner,self._scope): _fail('stop_requested')
        return value
    def _record(self, kind, lifecycle=False):
        self._check()
        if len(self.rows) >= _MAX_FDS: _fail('native_fd_limit')
        # Independent one descriptor-close cap fixed BEFORE its native factory;
        # does not permit more network activity or renew the session/restore.
        cap = min(self.store.restore_until, self._scope + 5) if self._scope_cleanup else self.until+60 if lifecycle else self._scope+5
        row = _Resource(self, kind, cap); self.rows.append(row); self._history += (row,)
        return row
    def _retain(self, value):
        self.raw.append(value)
        size = sum(len(x) for x in value if type(x) is bytes) if type(value) is tuple else len(value) if type(value) is bytes else 0
        self._raw_bytes += size
        if self._raw_bytes > _MAX_RAW: _fail('native_raw_limit')
    def _adopt(self, row, value, fd):
        row.value, row.fd, row.returned = value, fd, True
        if not _int(fd, 0, 0x7fffffff) or any(r is not row and r.returned and not r.closed and r.fd == fd for r in self.rows):
            row.unknown = True; _fail('native_fd_unknown')
        row.metadata = _meta(self.io.fstat(fd)); row.unknown = False
    def _fd_current(self, row, close=False):
        if type(row) is not _Resource or row.native is not self or not any(r is row for r in self._history) or \
                not row.returned or row.unknown or row.closed or not close and row.attempted or \
                _meta(self.io.fstat(row.fd)) != row.metadata or row.kind != 'file' and row.value.fileno() != row.fd:
            _fail('native_fd_changed')
    def _unlink_endpoint(self, row, cap):
        """First unlink only for an actually closed original bound pathname.

        An expired precheck has not called unlink and may be considered again
        under the SAME fixed cap. An attempted uncertain unlink is never retried.
        This method does not fstat/close a historical numeric descriptor.
        """
        self._owner()
        if row.native is not self or not any(row is r for r in self._history) or \
                not row.returned or not row.attempted or not row.closed or row.unknown:
            _fail('native_endpoint_close_pending')
        cap=sources._time(cap)
        if row.cleanup_until!=row._cleanup_until_original or cap>row._cleanup_until_original:
            _fail('native_endpoint_cleanup_cap_changed')
        if self.owner.restore_attempted:
            module=self.deployment.modules['mta_go_bootstrap']
            original=module.GoBootstrap._cleanup_period_current(self.owner,self)
            if cap>original: _fail('native_endpoint_cleanup_cap_changed')
        if self.store.restore_until is not None and (self.store.restore_until!=self.store._restore_until_original or
                cap>self.store.restore_until): _fail('native_endpoint_cleanup_cap_changed')
        if self._scope_cleanup and (self._scope is None or cap>self._scope): _fail('native_endpoint_cleanup_cap_changed')
        self._now(cap)
        if not row.bound or row.endpoint_closed: return
        if row.unlink_called: _fail('native_endpoint_close_pending')
        try:
            self._now(cap)
            if row.path is None or row.path_meta is None or self._path_metadata(row.path) != row.path_meta:
                _fail('native_endpoint_changed')
            self._now(cap)
            row.unlink_called = True  # Before actual unlink; uncertain return is not retried.
            if self.io.unlink(row.path) is not None: _fail('native_endpoint_close_pending')
            try: self.io.stat(row.path)
            except OSError as error:
                row.endpoint_closed = type(error.errno) is int and error.errno == errno.ENOENT
            if not row.endpoint_closed: _fail('native_endpoint_close_pending')
            self._now(cap)  # Retain actual absence even if this postcheck is late.
        except BaseException as error:
            row.endpoint_failure = error
            raise
    def _close(self, row, _absolute_deadline=None):
        cap=min(row.cleanup_until,self.store.restore_until) if self.store.restore_attempted and self.store.restore_until is not None else row.cleanup_until
        if self._scope_cleanup and self._scope is not None: cap=min(cap,self._scope)
        if _absolute_deadline is not None: cap=min(cap,sources._time(_absolute_deadline))
        if row.closed:
            if row.bound and not row.endpoint_closed: self._unlink_endpoint(row, cap)
            return
        if row.attempted or not row.returned or row.unknown: _fail('native_close_pending')
        original_error = None
        try:
            self._now(cap); self._fd_current(row, True)
            row.attempted = True
            result = self.io.close(row.fd) if row.kind == 'file' else row.value.close()
            try: self.io.fstat(row.fd)
            except OSError as error:
                row.closed = result is None and type(error.errno) is int and error.errno == errno.EBADF
            if not row.closed: row.unknown = True; _fail('native_close_pending')
            # Keep actual closure before a late postcheck; never repeat close.
            self._now(cap)
        except BaseException as error:
            original_error = error
            row.close_failure = error
            raise
        finally:
            if row.closed and row.bound and not row.endpoint_closed and not row.unlink_called:
                try:
                    self._unlink_endpoint(row, cap)
                except BaseException:
                    if original_error is None: raise
    def _socket(self, protocol, lifecycle=False):
        row = self._record('netlink', lifecycle)
        try: value = self.io.socket(protocol)
        except OSError:
            row.attempted = row.closed = True
            raise
        row.value, row.returned = value, True  # Before fileno or any socket IO.
        self._adopt(row, value, value.fileno())
        if not stat.S_ISSOCK(row.metadata[2]): _fail('native_socket_invalid')
        value.set_inheritable(False)
        if value.get_inheritable() is not False: _fail('native_socket_invalid')
        value.bind((0, 0)); endpoint = value.getsockname()
        if type(endpoint) is not tuple or len(endpoint) != 2 or not _int(endpoint[0], 1) or endpoint[1] != 0: _fail('native_socket_invalid')
        row.port = endpoint[0]; self._check()
        return row
    def _timeout(self, row, poll=False):
        self._fd_current(row); remaining = 0.0 if poll else self._scope - self._check()
        row.value.settimeout(remaining)
        actual = row.value.gettimeout()
        if type(actual) not in (int, float) or (actual != 0 if poll else not 0 < actual <= remaining + 1e-9): _fail('native_timeout_invalid')
    def _send(self, row, request):
        self._timeout(row); self._retain(('request', request))
        returned = row.value.sendto(request, (0, 0))
        self._retain(('send_return', returned)); self._check()
        if type(returned) is not int or returned != len(request): _fail('native_short_write')
    def _recv(self, row):
        self._timeout(row)
        returned = row.value.recvmsg(_MAX_PACKET + 1, 256, 0)
        self._retain(('kernel_return', returned))  # Original retained before unpack/postcheck.
        if type(returned) is not tuple or len(returned) != 4: _fail('native_kernel_invalid')
        raw, ancillary, flags, peer = returned
        self._retain(('kernel_raw', raw)); self._packets += 1
        if self._packets > 1024 or type(raw) is not bytes or not 16 <= len(raw) <= _MAX_PACKET or ancillary or flags or peer != (0, 0):
            _fail('native_kernel_invalid')
        self._check(); return raw
    def _next(self):
        if self._sequence >= 0xffffffff: _fail('native_sequence_limit')
        self._sequence += 1; return self._sequence
    def _request(self, row, family, command, attrs=b'', flags=0, sequence=None):
        if sequence is None: sequence=self._next()
        elif row is not self.create_row or command!=7 or self.interface_ticket is None or \
                sequence!=self.interface_ticket.sequence or row.port!=self.interface_ticket.port_id:
            _fail('native_request_not_original')
        version = 2 if family == 16 else 1
        request = _NL.pack(20 + len(attrs), family, 1 | flags, sequence, row.port) + _GH.pack(command, version, 0) + attrs
        self._send(row, request); records, ack, done = [], False, False
        for unused in range(64):
            raw = self._recv(row); at = 0
            while at < len(raw):
                if done or len(raw) - at < 16: _fail('native_kernel_invalid')
                n, kind, bits, seq, port = _NL.unpack_from(raw, at); end = at + ((n + 3) & ~3)
                if n < 16 or end > len(raw) or any(raw[at+n:end]) or seq != sequence or port != row.port or bits & (16 | 32):
                    _fail('native_kernel_invalid')
                body = raw[at+16:at+n]; at = end
                if kind == 2:
                    if ack or not flags & 4 or bits not in (0, 0x100) or len(body) < 20 or body[4:20] != request[:16]:
                        _fail('native_ack_invalid')
                    code = struct.unpack_from('<i', body)[0]
                    if not -4095 <= code <= 0 or (len(body) != 20 if code == 0 or bits & 0x100 else body[4:] != request):
                        _fail('native_ack_invalid')
                    if code: _fail('native_kernel_error')
                    ack = True
                elif kind == 3:
                    if not flags & 0x300 or bits not in (0, 2) or body not in (b'', b'\0'*4): _fail('native_done_invalid')
                    done = True
                else:
                    if kind != family or bits != (2 if flags & 0x300 else 0) or len(body) < 4 or body[1:4] != bytes((version,0,0)):
                        _fail('native_kernel_invalid')
                    records.append((body[0], body[4:]))
                    if row is self.create_row and command == 7 and flags & 8:
                        self._retain_create_echo(row, request, sequence, body[0], body[4:])
                    if len(records) > 256: _fail('native_kernel_limit')
            if flags & 0x300:
                if done: return tuple(records), request
            elif flags & 8:
                if len(records) > 1: _fail('native_create_ambiguous')
                if ack and len(records) == 1: return tuple(records), request
            elif flags & 4:
                if records: _fail('native_ack_invalid')
                if ack: return (), request
            elif len(records) == 1: return tuple(records), request
        _fail('native_kernel_limit')
    def _retain_create_echo(self, row, request, sequence, command, raw):
        """Keep actual correlated ECHO before waiting for ACK, without a grant."""
        ticket = self.interface_ticket
        if row is not self.create_row or type(ticket) is not core.InterfaceTicket or \
                not self._create_called or sequence != ticket.sequence or row.port != ticket.port_id or \
                command != 7 or self._create_echo_original is not None:
            _fail('native_create_echo_invalid')
        origin, frequency, mac = _origin(raw)
        # Retain parsed actual origin even when the following constraints fail.
        # No caller can use this observation as owned or ACK-confirmed source.
        self._create_echo_original = (request, ticket, origin, raw)
        self._retain(('create_echo_observed', raw))
        if origin.iftype != 8 or origin.phy != ticket.phy or origin.name != ticket.name or self.baseline is None or \
                any(r.wdev == origin.wdev or r.ifindex == origin.ifindex or r.name == origin.name
                    for r in self.baseline.snapshot.interfaces):
            _fail('native_create_origin_changed')
        return None
    def _family(self, row):
        records, request = self._request(row, 16, 3, _attr(2, b'nl80211\0'))
        if len(records) != 1 or records[0][0] != 1: _fail('native_family_invalid')
        f = _fields(records[0][1])
        if not {1, 2, 3, 4, 5} <= set(f) or _text(f[2]) != 'nl80211' or _u(f[3]) != 1 or _u(f[4]) != 0 or _u(f[5]) < 174:
            _fail('native_family_invalid')
        value = _u(f[1], 2)
        if not 19 <= value <= 1023: _fail('native_family_invalid')
        return value
    def _interfaces(self):
        row = self._socket(16)
        try:
            family = self._family(row); records, request = self._request(row, family, 5, flags=0x300)
            if not 1 <= len(records) <= 32 or any(cmd != 7 for cmd, data in records): _fail('native_interface_invalid')
            result = tuple(_origin(data) for cmd, data in records)
            if any(len(set(getattr(x[0], field) for x in result)) != len(result) for field in ('wdev','ifindex','name')):
                _fail('native_interface_ambiguous')
            return result
        finally: self._close(row)
    def _path_metadata(self, path): return sources._meta(self.io.stat(path))
    def _anchors(self, path):
        if type(path) is not str or not path.startswith('/') or any(p in ('','..','.') for p in path[1:].split('/')):
            _fail('native_path_invalid')
        resolved = self.io.realpath(path)
        if type(resolved) is not str or not resolved.startswith('/') or any(p in ('','..','.') for p in resolved[1:].split('/')):
            _fail('native_path_invalid')
        result = []
        for i in range(len(resolved.split('/')) - 1):
            name = '/' if i == 0 else '/' + '/'.join(resolved.split('/')[1:i+1])
            self._check(); m = self._path_metadata(name)
            temporary = name in ('/var/volatile','/var/volatile/tmp')
            if not stat.S_ISDIR(m[2]) or m[3:5] != (0,0) or not temporary and m[2] & 0o002 or \
                    name.startswith(sources.ROOT) and stat.S_IMODE(m[2]) != 0o700:
                _fail('native_path_unowned')
            result.append((name, m[:6]))
        # Symlink resolution itself must remain unchanged, not just final inode.
        if self.io.realpath(path) != resolved: _fail('native_path_changed')
        return resolved, tuple(result)
    def _file(self, path, maximum=1048576, image=False, _same_read_digest=False):
        self._check(); parts, total = [], 0
        # Only the original 64 MiB pin-read call sites may request this private
        # third value. It is this read's retained digest, never a path cache.
        if type(_same_read_digest) is not bool: _fail('native_pin_digest_invalid')
        if _same_read_digest and (type(path) is not str or type(maximum) is not int or maximum != 67108864 or
                not (image is False and any(path == p for p, unused in self.deployment.manifest.baseline_manifest) or
                     image is True and re.fullmatch('/proc/[1-9][0-9]{0,9}/exe', path) is not None)):
            _fail('native_pin_digest_invalid')
        if not image: anchors = None if path.startswith('/proc/') else self._anchors(path)
        else: anchors = None  # Exact fresh Proc actor's exe magiclink only.
        row = self._record('file')  # Immediately before factory, not before passive path refusal.
        flags = _CLOEXEC | (0 if image else _NOFOLLOW)
        row._open_requested_path_v52, row._open_requested_flags_v52 = path, flags
        try:
            try: returned = self.io.open(path, flags)
            except OSError as caught:
                row._open_error_original_v52 = caught
                row.attempted = row.closed = True
                raise
            self._adopt(row, returned, returned)
            before = sources._meta(self.io.fstat(row.fd))
            if not stat.S_ISREG(before[2]) or before[3:5] != (0,0): _fail('native_file_unowned')
            if not path.startswith('/proc/') and (before[2] & 0o022 or before[5] != 1): _fail('native_file_unowned')
            while True:
                self._check(); n = min(65536, maximum + 1 - total); chunk = self.io.read(row.fd,n)
                if type(chunk) is not bytes or len(chunk) > n: _fail('native_file_invalid')
                parts.append(chunk); total += len(chunk)
                if total > maximum: _fail('native_file_limit')
                if not chunk: break
            raw = b''.join(parts)
            digest = None if maximum <= 1048576 else hashlib.sha256(raw).digest()
            self._retain(('file', path, raw if maximum <= 1048576 else digest))
            if sources._meta(self.io.fstat(row.fd)) != before or not image and self._path_metadata(path) != before or \
                    anchors is not None and self._anchors(path) != anchors: _fail('native_file_changed')
            self._check()
            return (raw, before, digest) if _same_read_digest else (raw, before)
        finally: self._close(row)
    def _proc(self, pid, expected=None):
        self._check(); value = self.entry.reader.read_actor(pid, expected, _absolute_deadline=self._scope)
        self.proc_observations.append(value); self._check()
        proc = self.deployment.modules['mta_client_proc']
        if type(value) is not proc.ProcObservation or value.kind != 'live_actor' or type(value.actor) is not core.Actor or \
                value.same_boot is not True or type(value.passes) is not int or value.passes != 2 or value.resource_pending is not False or \
                value.boot != self.entry.boot or not any(r.observation is value and self.entry.reader.owns_generation(r)
                    for r in self.entry.reader._history) or not self.entry.reader.history_closed():
            try:
                if self.last_proc_failure_v60 is None:
                    self.last_proc_failure_v60 = (value, self.entry.reader)
            except BaseException:
                pass  # Diagnostic allocation never replaces the original refusal.
            _fail('native_actor_unknown')
        return value
    def _actors(self):
        self._check(); names = self.io.listdir('/proc')
        if type(names) not in (list,tuple) or len(names) > _MAX_ROWS or any(type(n) is not str for n in names): _fail('native_proc_limit')
        launcher, excluded = self.owner.launcher, {}
        if launcher is not None:
            for ticket in launcher._tickets:
                if ticket.pid is not None and not ticket.waited:
                    actor = ticket.postexec or ticket.preexec
                    if actor is None or ticket.unknown: _fail('native_private_actor_unknown')
                    fresh = self._proc(ticket.pid, actor)
                    if fresh.actor.key() != actor.key() or not fresh.actor.live(): _fail('native_private_actor_changed')
                    excluded[ticket.pid] = actor
        result, found = [], {}
        for name in sorted(names):
            if re.fullmatch('[1-9][0-9]{0,9}',name) is None: continue
            number = int(name)
            if not _int(number,1,0x7fffffff): _fail('native_proc_limit')
            if number in excluded: continue
            path = '/proc/'+name+'/comm'
            rows, history = self.rows, self._history
            before = len(rows)
            try: comm = self._file(path,128)[0].strip().decode('ascii')
            except OSError as caught:
                # Only the original open failure before any FD was returned.
                # No post-open/read/path/Proc/image/close error may be skipped.
                if type(caught.errno) is not int or caught.errno != errno.ENOENT or \
                        self.rows is not rows or type(rows) is not list or type(history) is not tuple or \
                        type(self._history) is not tuple or before != len(history) or \
                        len(rows) != before+1 or len(self._history) != before+1 or \
                        any(old is not new for old,new in zip(history,self._history[:before])) or \
                        any(rows[i] is not self._history[i] for i in range(before+1)):
                    raise
                row = rows[-1]
                if type(row) is not _Resource or row.native is not self or row.kind != 'file' or \
                        row._open_requested_path_v52 != path or \
                        row._open_requested_flags_v52 != (_CLOEXEC | _NOFOLLOW) or \
                        row._open_error_original_v52 is not caught or row.returned is not False or \
                        row.value is not None or row.fd is not None or row.metadata is not None or \
                        row.unknown is not False or row.attempted is not True or row.closed is not True:
                    raise
                self._check()  # Original owner/cancel/cap; never renew or clear inventory.
                continue
            except UnicodeError: _fail('native_actor_unknown')
            if comm not in _TRACKED: continue
            actor = self._proc(number).actor
            if actor.exe.rsplit('/',1)[-1] != comm or not actor.live(): _fail('native_actor_unknown')
            if comm in ('Z03','control_engine') and actor.exe != '/usr/bin/'+comm: _fail('native_actor_unknown')
            result.append(actor); found[comm] = found.get(comm,0)+1
        if any(found.get(n) != 1 for n in ('Z03','control_engine','weston','wpa_supplicant')) or len(result)>32:
            _fail('native_actor_unknown')
        return tuple(result)
    def _pins(self, actors):
        manifest = self.deployment.manifest.baseline_manifest
        if len(manifest) != 4 or tuple(sorted(r for r in manifest if r[0] != '/usr/sbin/wpa_cli')) != tuple(sorted(core.STOCK_PINS)) or \
                sum(r[0] == '/usr/sbin/wpa_cli' for r in manifest) != 1: _fail('native_baseline_manifest_invalid')
        result, metadata = [], {}
        for path, expected in manifest:
            raw, m, digest = self._file(path,67108864,_same_read_digest=True)
            if digest.hex() != expected: _fail('native_stock_pin_changed')
            metadata[path] = m
            if path != '/usr/sbin/wpa_cli': result.append((path,expected))
        for actor in actors:
            if actor.exe not in ('/usr/bin/Z03','/usr/bin/control_engine'): continue
            raw, m, digest = self._file('/proc/'+str(actor.pid)+'/exe',67108864,True,_same_read_digest=True)
            if m != metadata[actor.exe] or digest.hex() != dict(manifest)[actor.exe] or \
                    self._proc(actor.pid,actor).actor.key() != actor.key(): _fail('native_stock_image_changed')
        return tuple(result)
    def _unix_owner(self, path, actor):
        fresh = self._proc(actor.pid,actor)
        if fresh.actor.key() != actor.key() or not fresh.actor.live(): _fail('native_ctrl_actor_changed')
        raw = self._file('/proc/net/unix')[0]
        try: lines = raw.decode('ascii').splitlines()
        except UnicodeError: _fail('native_unix_table_invalid')
        rows = []
        for line in lines[1:]:
            fields = line.split()
            if len(fields) not in (7,8): _fail('native_unix_table_invalid')
            if len(fields)==8 and fields[7]==path:
                if fields[4]!='0002' or fields[5]!='01' or not fields[6].isdigit(): _fail('native_ctrl_unowned')
                rows.append(int(fields[6]))
        if len(rows)!=1: _fail('native_ctrl_unowned')
        names = self.io.listdir('/proc/'+str(actor.pid)+'/fd')
        if type(names) not in (list,tuple) or len(names)>4096: _fail('native_proc_limit')
        matched = []
        for name in names:
            if type(name) is not str or re.fullmatch('[0-9]{1,10}',name) is None: _fail('native_proc_limit')
            if self.io.readlink('/proc/'+str(actor.pid)+'/fd/'+name)=='socket:[%d]' % rows[0]: matched.append(name)
            self._check()
        if len(matched)!=1 or self._proc(actor.pid,actor).actor.key()!=actor.key(): _fail('native_ctrl_unowned')
        return rows[0]
    def _stock_endpoint(self, actor):
        raw = self._file('/proc/net/unix')[0]
        try: lines = raw.decode('ascii').splitlines()
        except UnicodeError: _fail('native_unix_table_invalid')
        candidates = []
        for line in lines[1:]:
            f = line.split()
            if len(f)==8 and f[7].startswith('/') and f[7].rsplit('/',1)[-1]=='wlan0' and f[4]=='0002': candidates.append(f[7])
        if len(candidates)!=1: _fail('native_stock_ctrl_ambiguous')
        self._unix_owner(candidates[0],actor)
        return candidates[0]
    def _unix(self, peer, actor, lifecycle=False):
        self._check(); self._anchors(peer); before = self._path_metadata(peer)
        if not stat.S_ISSOCK(before[2]) or before[3:5]!=(0,0) or before[5]!=1: _fail('native_ctrl_unowned')
        self._unix_owner(peer,actor)
        row = self._record('unix',lifecycle)
        try: raw = self.io.unix()
        except OSError:
            row.attempted=row.closed=True
            raise
        row.value,row.returned=raw,True; self._adopt(row,raw,raw.fileno())
        raw.set_inheritable(False); raw.setsockopt(1,16,1)
        if raw.get_inheritable() is not False or raw.getsockopt(1,16)!=1: _fail('native_ctrl_unknown')
        self._endpoint_sequence += 1
        local = self.deployment.manifest.run+'/go-read-%04d' % self._endpoint_sequence
        self._anchors(local)
        try: self.io.stat(local)
        except OSError as error:
            if type(error.errno) is not int or error.errno!=errno.ENOENT: raise
        else: _fail('native_endpoint_present')
        row.path=local; row.endpoint_closed=False
        try: raw.bind(local)
        except OSError:
            # Native bind negative: this creator did not create the pathname.
            # Do not delete a preexisting/foreign endpoint to make it pass.
            row.endpoint_closed=True
            raise
        row.bound=True
        row.path_meta=self._path_metadata(local)
        if not stat.S_ISSOCK(row.path_meta[2]) or row.path_meta[3:5]!=(0,0) or row.path_meta[5]!=1: _fail('native_endpoint_unowned')
        raw.connect(peer); row.peer,row.peer_meta,row.actor=peer,before,actor
        self._unix_gate(row)
        return row
    def _unix_gate(self,row):
        self._check(); self._fd_current(row)
        if row.actor is None or row.peer is None or self._path_metadata(row.peer)!=row.peer_meta or \
                self._path_metadata(row.path)!=row.path_meta or row.value.getpeername()!=row.peer or row.value.getsockname()!=row.path or \
                row.value.get_inheritable() is not False or row.value.getsockopt(1,16)!=1: _fail('native_ctrl_changed')
    def _ctrl_recv(self,row,poll=False):
        self._unix_gate(row); self._timeout(row,poll)
        try: returned=row.value.recvmsg(8193,socket.CMSG_SPACE(_CRED.size)+socket.CMSG_SPACE(64),0x40000000)
        except OSError as error:
            if poll and type(error.errno) is int and error.errno in (errno.EAGAIN,errno.EWOULDBLOCK): return None
            raise
        self._retain(('private_ctrl_return',returned))
        if type(returned) is not tuple or len(returned)!=4: _fail('native_ctrl_invalid')
        packet,ancillary,flags,address=returned
        credentials=[]
        if type(ancillary) not in (list,tuple): _fail('native_ctrl_invalid')
        for item in ancillary:
            if type(item) is not tuple or len(item)!=3 or item[:2]!=(1,2) or type(item[2]) is not bytes or len(item[2])!=_CRED.size:
                # SCM_RIGHTS is never requested/accepted; MSG_CMSG_CLOEXEC makes
                # any unexpected received descriptor noninheritable, but such
                # an unknown resource is pending, not dropped as successful.
                self._unexpected_ancillary(ancillary,row.cleanup_until)
                _fail('native_ctrl_ancillary_unknown')
            credentials.append(_CRED.unpack(item[2]))
        if type(flags) is int and flags&8: self._ancillary_unknown=True
        if credentials!=[(row.actor.pid,0,0)] or type(packet) is not bytes or not 1<=len(packet)<=8192 or \
                flags not in (0,0x40000000) or address not in (row.peer,row.peer.encode('ascii')): _fail('native_ctrl_unowned')
        self._retain(('private_ctrl_raw',packet)); self._unix_gate(row)
        return packet
    def _unexpected_ancillary(self,ancillary,cap):
        """Actual received rights are resources; known raw FD stays known."""
        for item in ancillary:
            if type(item) is not tuple or len(item)!=3: self._ancillary_unknown=True;continue
            if item[:2]!=(1,1): continue
            raw=item[2]
            if type(raw) is not bytes or not raw or len(raw)%4 or len(raw)>64:
                self._ancillary_unknown=True;continue
            for fd in struct.unpack('<%di' % (len(raw)//4),raw):
                if len(self.rows)>=_MAX_FDS: self._ancillary_unknown=True;continue
                received=_Resource(self,'file',cap);self.rows.append(received);self._history+=(received,)
                received.value=received.fd=fd;received.returned=True
                try:
                    self._adopt(received,fd,fd);self._close(received)
                except BaseException as error: received.close_failure=error
    def _exchange(self,row,wire):
        if type(wire) is not bytes: _fail('native_control_command_invalid')
        if row is self.event_row:
            if wire!=b'ATTACH' or self._scope_cleanup: _fail('native_control_command_invalid')
        elif row is self.command_row:
            if wire!=b'STATUS':
                record=self.store.current.record
                add=b'P2P_GROUP_ADD freq=%d' % self.group_source.frequency if self.group_source is not None else None
                remove=b'P2P_GROUP_REMOVE '+self.owned.name.encode('ascii') if self.owned is not None else None
                if wire==add:
                    facts=None if record.group_add is None else dict(record.group_add)
                    if self._scope_cleanup or not self._group_submit_called or record.phase!='group_add_intent' or facts is None or \
                            facts['command_sha256']!=hashlib.sha256(wire).hexdigest(): _fail('native_control_command_invalid')
                elif wire==remove:
                    if not self._scope_cleanup or not self._group_remove_called or record.phase!='ip_restored':
                        _fail('native_control_command_invalid')
                elif wire is self._station_wire:
                    if self._scope_cleanup or self.dhcp_binding is None or record.phase not in ('dhcp_intent','dhcp_listening'):
                        _fail('native_control_command_invalid')
                else: _fail('native_control_command_invalid')
        elif wire!=b'STATUS': _fail('native_stock_command_forbidden')
        self._unix_gate(row); self._timeout(row); self._retain(('private_ctrl_request',wire))
        n=row.value.send(wire); self._retain(('private_ctrl_send_return',n)); self._check()
        if type(n) is not int or n!=len(wire): _fail('native_short_write')
        return self._ctrl_recv(row)
    def _stock_status(self,actors):
        actor=next(a for a in actors if a.exe.rsplit('/',1)[-1]=='wpa_supplicant')
        row=self._unix(self._stock_endpoint(actor),actor)
        try:
            raw=self._exchange(row,b'STATUS'); f=_status(raw)
            if f.get(b'wpa_state')!=b'COMPLETED' or re.fullmatch(b'[0-9]{4}',f.get(b'freq',b'')) is None:
                _fail('native_station_unavailable')
            frequency=int(f[b'freq'])
            if frequency not in range(2412,2473,5): _fail('native_station_channel_unavailable')
            return raw,f,frequency
        finally: self._close(row)
    def _ipv4(self):
        row=self._socket(0); dumps=[]
        try:
            for kind in ('addresses','routes','rules'):
                collector=ip.DumpCollector(kind,self._next(),row.port); self._send(row,collector.request)
                while not collector.complete: collector.feed(self._recv(row))
                dumps.append(collector)
            return ip.snapshot_from_dumps(*dumps)
        finally: self._close(row)
    def _ipv6(self,path,widths):
        raw=self._file(path)[0]
        try: rows=tuple(tuple(line.split()) for line in raw.decode('ascii').splitlines())
        except UnicodeError: _fail('native_ipv6_invalid')
        if len(rows)>_MAX_ROWS or path!='/proc/net/ipv6_route' and len(set(rows))!=len(rows): _fail('native_ipv6_invalid')
        for row in rows:
            if len(row)!=len(widths)+1 or any(re.fullmatch('[0-9a-f]{%d}' % width,row[i]) is None for i,width in enumerate(widths)) or \
                    re.fullmatch('[A-Za-z0-9_.-]{1,15}',row[-1]) is None: _fail('native_ipv6_invalid')
        return rows
    def _timing_begin_v55(self):
        # All diagnostic bookkeeping is best effort. It must not turn a clock
        # observer failure into a different business exception or move last.
        try:
            if type(self._snapshot_timing_v55) is not list or len(self._snapshot_timing_v55) >= 2:
                return None
            row = [self._scope, self.until, 'boot', None, [None] * 5]
            self._snapshot_timing_v55.append(row)
            self._timing_mark_v55(row, 0)
            return row
        except BaseException:
            return None
    def _timing_mark_v55(self, row, index, component=None, failed=False):
        try:
            if row is None: return
            if component is not None: row[2] = component
            if failed: row[3] = row[2]
            if index is None: return
            # Exactly this native creator's original clock; not _now/_check,
            # no deadline/last update and no additional source/FD operations.
            value = sources._time(self._originals[6]())
            previous = tuple(v for v in row[4][:index] if v is not None)
            if previous and value < previous[-1]: return
            row[4][index] = value
        except BaseException:
            pass
    def _snapshot_once(self):
        timing = self._timing_begin_v55()
        try:
            self.io.validate(); boot=self._file(_BOOT,128)[0]
            try: boot=boot.strip().decode('ascii')
            except UnicodeError: _fail('native_boot_invalid')
            if boot!=self.entry.boot: _fail('native_boot_changed')
            self._timing_mark_v55(timing, 1, 'actors')
            actors=self._actors()
            self._timing_mark_v55(timing, 2, 'pins')
            pins=self._pins(actors)
            self._timing_mark_v55(timing, 3, 'rest')
            interfaces=self._interfaces()
            station=tuple(r for r,f,m in interfaces if r.name=='wlan0' and r.iftype==2)
            if len(station)!=1: _fail('native_station_unavailable')
            status,fields,frequency=self._stock_status(actors)
            kernel_frequency=next(f for r,f,m in interfaces if r is station[0])
            if kernel_frequency is None:
                # Absence is not a positive channel match. Read the associated BSS
                # under THIS unchanged scope before issuing even baseline facts.
                row=self._socket(16)
                try:
                    family=self._family(row)
                    self._scan_bss(row,family,station[0],frequency,fields.get(b'bssid',b''))
                finally: self._close(row)
            elif kernel_frequency!=frequency: _fail('native_station_channel_changed')
            return core.Snapshot(boot,pins,actors,station[0],hashlib.sha256(status).hexdigest(),frequency,
                tuple(r for r,f,m in interfaces),self._ipv4(),
                self._ipv6('/proc/net/if_inet6',(32,2,2,2,2)),
                self._ipv6('/proc/net/ipv6_route',(32,2,32,2,32,8,8,8,8)),True)
        except BaseException:
            self._timing_mark_v55(timing, None, failed=True)
            raise  # Keep the exact original business exception and traceback.
        finally:
            # Includes callee finally/close time; rest is the combined tail.
            self._timing_mark_v55(timing, 4)
    def _stable_snapshot(self):
        first=self._snapshot_once(); second=self._snapshot_once()
        self.observations.extend((first,second))
        if first.key()!=second.key(): _fail('native_baseline_unstable')
        self._check(); return second
    def _fresh_boundary_snapshot_v62(self):
        if self._scope_cleanup is not False: return self._stable_snapshot()
        value=self._snapshot_once()
        self.observations.append(value)
        self._check(); return value
    def _outside_key(self,snapshot,current):
        if self.baseline is None or self.owned is None or current.key()[:4]!=self.owned.key()[:4] or current.iftype not in (8,9):
            _fail('native_origin_changed')
        matching=tuple(r for r in snapshot.interfaces if r.wdev==current.wdev or r.ifindex==current.ifindex or r.name==current.name)
        if len(matching)!=1 or matching[0].key()!=current.key(): _fail('native_origin_changed')
        ipv4=snapshot.ipv4
        present=any(a.ifindex==current.ifindex for a in ipv4.addresses) or any(r.oif==current.ifindex for r in ipv4.routes)
        if present:
            original=self.ip_receipt
            record=None if self.store.current is None else self.store.current.record
            if current.iftype!=9 or type(original) is not GoIpObservation or original is not self.ip_receipt or \
                    original not in self.observations or original.facts.origin.key()!=current.key() or \
                    type(self.ip_ack) is not ip.AckResult or self.ip_ack is not self._ip_ack_original or \
                    self.ip_ack.command!=ip.RTM_NEWADDR or self.ip_ack.success is not True or record is None or record.ip is None or \
                    record.ip.source_key()!=original.facts.source_key() or self.ip_restored is not None:
                _fail('native_unexpected_l3')
            ipv4=ip_lease.without_owned(ipv4,original.facts.legacy(),
                {k:getattr(current,k) for k in ('name','ifindex','wdev','phy')})
        if any(a.ifindex==current.ifindex for a in ipv4.addresses) or any(r.oif==current.ifindex for r in ipv4.routes):
            _fail('native_unexpected_l3')
        # Reuse the neutral mechanical IPv6 shape validation, not key(owned8).
        core._owned_ipv6(snapshot.ipv6_addresses,snapshot.ipv6_routes,current)
        return (snapshot.boot,snapshot.stock_hashes,tuple(sorted(a.key() for a in snapshot.stock_actors)),
            snapshot.station.key(),snapshot.station_state_sha,snapshot.station_frequency,
            tuple(sorted(r.key() for r in snapshot.interfaces if r.key()[:4]!=current.key()[:4])),
            tuple(sorted(ipv4.addresses,key=lambda r:repr(tuple(r)))),
            tuple(sorted(ipv4.routes,key=lambda r:repr(tuple(r)))),tuple(sorted(ipv4.rules)),
            tuple(sorted(r for r in snapshot.ipv6_addresses if r[-1]!=current.name)),
            tuple(sorted(r for r in snapshot.ipv6_routes if r[-1]!=current.name)))
    def observe_baseline(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.baseline is not None or self._create_called: _fail('native_baseline_already_issued')
            value=GoBaselineObservation(self,self._stable_snapshot()); self.baseline=value
            self.observations.append(value); return value
    def baseline_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoBaselineObservation or original is not self.baseline: _fail('native_baseline_not_original')
        if self._fresh_boundary_snapshot_v62().key()!=original.snapshot.key(): _fail('native_baseline_changed')
        return original
    def _config(self):
        path=self.deployment.manifest.cfg; raw,metadata=self._file(path,4096)
        if stat.S_IMODE(metadata[2])!=0o400 or metadata[5]!=1: _fail('native_config_unowned')
        expected=(b'ctrl_interface='+self.deployment.manifest.ctrl.encode('ascii')+b'\n'+
            b'p2p_no_group_iface=1\nap_scan=2\ndevice_name=P011\ndevice_type=1-0050F204-1\n'+
            b'driver_param=mta_p2p_initial=1 control_port=0\n')
        if raw==expected: bi=100  # Pinned src/ap/ap_config.c fallback via ap.c; not measured BI.
        elif raw.startswith(expected) and re.fullmatch(b'beacon_int=[1-9][0-9]{0,4}\n',raw[len(expected):]):
            bi=int(raw[len(expected)+11:-1])
            if not 15<=bi<=65535: _fail('native_config_invalid')
        else: _fail('native_config_invalid')
        anchors=self._anchors(path)
        if self._config_raw is not None and (raw!=self._config_raw or metadata!=self._config_meta or anchors!=self._config_anchors):
            _fail('native_config_changed')
        self._config_raw,self._config_meta,self._config_anchors,self._go_beacon_interval=raw,metadata,anchors,bi
        ctrl=self.deployment.manifest.ctrl; self._anchors(ctrl+'/unused')
        m=self._path_metadata(ctrl)
        if not stat.S_ISDIR(m[2]) or m[3:5]!=(0,0) or stat.S_IMODE(m[2])!=0o700: _fail('native_ctrl_directory_unowned')
        return bi
    def validate_config(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline); self._config(); return None
    def _durable(self,phase,cleanup=False):
        self._owner()
        canonical=self.store.current
        if canonical is None or not self.store._canonical_history or self.store._canonical_history[-1] is not canonical or \
                canonical.issuer is not self.store.issuer or canonical.record.phase!=phase or self.store.publication_unknown or \
                not cleanup and (self.store.restore_attempted or self.store.failure is not None): _fail('native_durable_intent_missing')
        self.store._set_scope(self._scope,cleanup); self.store._fresh(); self._check()
        # Full stage boundary checks the actual SAME F task set through the
        # original bound ProcReader. IO midway uses only original/clock/pipe
        # gates, not recursive full-baseline/Proc per packet or file chunk.
        observed=self._proc(self.entry.actor.pid,self.entry.actor)
        if observed.actor.key()!=self.entry.actor.key() or not observed.actor.live() or len(observed.actor.tasks)!=1:
            _fail('native_f_identity_changed')
        if self.store.current is not canonical: _fail('native_canonical_changed')
        return canonical
    def _scan_bss(self,row,family,station,frequency,bssid):
        if re.fullmatch(b'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',bssid) is None: _fail('native_station_bssid_unavailable')
        mac=bytes(int(v,16) for v in bssid.split(b':'))
        records,request=self._request(row,family,32,_attr(3,struct.pack('<I',station.ifindex)),0x300)
        candidates=[]
        for cmd,raw in records:
            if cmd!=34: _fail('native_bss_invalid')  # NEW_SCAN_RESULTS, not TRIGGER_SCAN.
            f=_fields(raw)
            if 3 not in f or _u(f[3])!=station.ifindex or 47 not in f: _fail('native_bss_invalid')
            b=_fields(f[47][1])
            if f[47][0] not in (0,0x8000): _fail('native_bss_invalid')
            if b.get(1)!=(0,mac): continue
            if not {2,4,9}<=set(b) or _u(b[2])!=frequency or _u(b[9])!=1: continue
            bi=_u(b[4],2)
            if not 15<=bi<=65535: _fail('native_bss_invalid')
            candidates.append((bi,raw))
        if len(candidates)!=1: _fail('native_station_beacon_unavailable')
        return candidates[0]
    def _caps(self,row,family,phy):
        features,request=self._request(row,family,95)
        if len(features)!=1 or features[0][0]!=95: _fail('native_caps_invalid')
        f=_fields(features[0][1])
        if 173 not in f: _fail('native_caps_invalid')
        bits=_u(f[173])
        attrs=_attr(1,struct.pack('<I',phy))+(_attr(174,b'') if bits&1 else b'')
        rows,request=self._request(row,family,1,attrs,0x300)
        scalars,frequencies,generations={}, {},set()
        fragments=[]
        for command,raw in rows:
            if command!=3: _fail('native_caps_invalid')
            f=_fields(raw)
            if 1 not in f or _u(f[1])!=phy: _fail('native_caps_phy_changed')
            fragments.append(raw)
            if 46 in f: generations.add(_u(f[46]))
            for key in (32,50,120,121):
                if key in f:
                    if key in scalars and scalars[key]!=f[key]: _fail('native_caps_inconsistent')
                    scalars[key]=f[key]
            if 22 in f:
                for band,bflags,braw in _nested(f[22]):
                    bf=_fields(braw)
                    if bflags not in (0,0x8000): _fail('native_caps_invalid')
                    if 1 not in bf: continue
                    for index,flags,fraw in _nested(bf[1]):
                        if flags not in (0,0x8000): _fail('native_caps_invalid')
                        ff=_fields(fraw)
                        if 1 not in ff: _fail('native_caps_invalid')
                        freq=_u(ff[1])
                        if freq in frequencies and frequencies[freq]!=ff: _fail('native_caps_inconsistent')
                        frequencies[freq]=ff
        if not fragments or len(generations)>1 or not {32,50,120}<=set(scalars): _fail('native_caps_incomplete')
        types=[]
        for kind,flags,raw in _nested(scalars[32]):
            if not 1<=kind<=12: _fail('native_caps_iftype_unknown')
            _flag((flags,raw)); types.append(kind)
        if len(set(types))!=len(types) or not {2,8,9}<=set(types): _fail('native_caps_go_unsupported')
        software=[]
        # Linux emits software-iftypes only if nonempty. Complete split dump
        # omission is an empty set, not a fabricated supported-iftype grant.
        if 121 in scalars:
            for kind,flags,raw in _nested(scalars[121]):
                if not 1<=kind<=12: _fail('native_caps_iftype_unknown')
                _flag((flags,raw)); software.append(kind)
        if len(set(software))!=len(software): _fail('native_caps_invalid')
        commands=[]
        for index,flags,raw in _nested(scalars[50]): commands.append(_u((flags,raw)))
        if len(set(commands))!=len(commands) or not {6,7,8,15,16}<=set(commands): _fail('native_caps_command_unsupported')
        combinations=[]
        for index,flags,raw in _nested(scalars[120]):
            if flags not in (0,0x8000): _fail('native_caps_invalid')
            f=_fields(raw)
            if not {1,2,4}<=set(f) or set(f)-set(range(1,8)): _fail('native_caps_constraint_unknown')
            maximum,channels=_u(f[2]),_u(f[4])
            if not 1<=maximum<=32 or not 1<=channels<=32: _fail('native_caps_invalid')
            limits=[];seen=set()
            for li,lf,lr in _nested(f[1]):
                if lf not in (0,0x8000): _fail('native_caps_invalid')
                fields=_fields(lr)
                if set(fields)!={1,2}: _fail('native_caps_constraint_unknown')
                n=_u(fields[1]);ts=[]
                for kind,kf,kv in _nested(fields[2]):
                    if not 1<=kind<=12 or kind in seen: _fail('native_caps_invalid')
                    _flag((kf,kv));ts.append(kind);seen.add(kind)
                if not 1<=n<=32 or not ts: _fail('native_caps_invalid')
                limits.append((n,tuple(ts)))
            if not limits or len(limits)>16: _fail('native_caps_invalid')
            match=_flag(f[3]) if 3 in f else False
            gcd=_u(f[7]) if 7 in f else None
            if gcd is not None and not 1<=gcd<=65535: _fail('native_caps_invalid')
            # No radar operation is requested. Omission of optional UAPI radar
            # masks is normal v4.14; nonzero masks remain facts, not permission.
            for k in (5,6):
                if k in f: _u(f[k])
            combinations.append((maximum,channels,tuple(limits),match,gcd))
        if not combinations or len(combinations)>16: _fail('native_caps_go_unsupported')
        return tuple(fragments),frequencies,tuple(software),tuple(combinations)
    def _combo(self,interfaces,phy,role,software,combinations,station_bi,go_bi):
        rows=[r for r,f,m in interfaces if r.phy==phy and r.iftype not in software]
        if self.owned is not None:
            rows=[r for r in rows if r.key()[:4]!=self.owned.key()[:4]]
        counts={}
        for row in rows: counts[row.iftype]=counts.get(row.iftype,0)+1
        if role not in software: counts[role]=counts.get(role,0)+1
        # More than the one already-associated stock STA on the measured phy
        # needs a genuine measured channel source, not a guessed one-channel
        # assertion. This first slice therefore refuses that unknown topology.
        if any(r.iftype!=2 or r.name!='wlan0' for r in rows): _fail('native_caps_topology_unassessed')
        for maximum,channels,limits,match,gcd in combinations:
            covered=set(t for n,ts in limits for t in ts)
            if sum(counts.values())>maximum or channels<1 or set(counts)-covered: continue
            if any(sum(counts.get(t,0) for t in ts)>n for n,ts in limits): continue
            if match and station_bi!=go_bi: continue
            if gcd is not None:
                a,b=station_bi,go_bi
                while b: a,b=b,a%b
                if a<gcd: continue
            return
        _fail('native_caps_go_combo_unavailable')
    def _channel_read(self):
        bi=self._config()
        interfaces=self._interfaces();station=tuple((r,f,m) for r,f,m in interfaces if r.name=='wlan0' and r.iftype==2)
        if len(station)!=1: _fail('native_station_unavailable')
        r,kernel_frequency,mac=station[0]
        actors=self._actors();status,fields,frequency=self._stock_status(actors)
        if (kernel_frequency is not None and kernel_frequency!=frequency) or self.baseline is None or \
                frequency!=self.baseline.snapshot.station_frequency or r.key()!=self.baseline.snapshot.station.key():
            _fail('native_station_channel_changed')
        row=self._socket(16)
        try:
            family=self._family(row);station_bi,bss_raw=self._scan_bss(row,family,r,frequency,fields.get(b'bssid',b''))
            raw,freqs,software,combinations=self._caps(row,family,r.phy)
            f=freqs.get(frequency)
            if f is None or any(k in f for k in (2,3,5,14,16)) or set(f)-set(range(1,18)):
                _fail('native_channel_ir_unavailable')
            # 2.4GHz only; measured station/BSS frequency, never the requested
            # GROUP_ADD frequency as evidence of the operating channel.
            if frequency not in range(2412,2473,5): _fail('native_channel_unavailable')
            self._combo(interfaces,r.phy,8,software,combinations,station_bi,bi)
            self._combo(interfaces,r.phy,9,software,combinations,station_bi,bi)
            # Assessed facts exclude BSS age/TSF; full actual BSS is retained
            # separately in the original private kernel datagram inventory.
            channel_raw=struct.pack('<IHH',frequency,station_bi,bi)+fields[b'bssid']+b''.join(_attr(k,v) for k,(flags,v) in sorted(f.items()))
            return GoChannelObservation(self,frequency,raw,channel_raw,station_bi,bi)
        finally: self._close(row)
    def observe_channel(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.channel is not None or self.baseline is None: _fail('native_channel_already_issued')
            self._durable('watchdog_live');self.baseline_current(self.baseline,_absolute_deadline)
            first=self._channel_read();second=self._channel_read();self.observations.extend((first,second))
            if (first.frequency,first.channel_sha256,first.caps_sha256)!=(second.frequency,second.channel_sha256,second.caps_sha256):
                _fail('native_channel_unstable')
            self.channel=second;return second
    def channel_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoChannelObservation or original is not self.channel: _fail('native_channel_not_original')
        current=self._channel_read();self.observations.append(current)
        if (current.frequency,current.channel_sha256,current.caps_sha256)!=(original.frequency,original.channel_sha256,original.caps_sha256):
            _fail('native_channel_changed')
        return original
    def reserve_interface(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.interface_ticket is not None or self.create_row is not None: _fail('native_interface_already_issued')
            self._durable('watchdog_live')
            row=self._socket(16);self.create_row=row
            try:
                family=self._family(row);sequence=self._next()
                ticket=core.InterfaceTicket(self.entry.boot,self.baseline.snapshot.station.phy,self.deployment.manifest.ifname,sequence,row.port)
                self.interface_ticket=ticket;self._create_family=family;self._create_until=self._scope;self._create_sequence=sequence
                return ticket
            except BaseException:
                self._close(row);raise
    def interface_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not core.InterfaceTicket or original is not self.interface_ticket or self._create_called or \
                self.create_row is None or original.port_id!=self.create_row.port or original.sequence!=self._create_sequence:
            _fail('native_interface_not_original')
        self._fd_current(self.create_row)
        if original.boot!=self.entry.boot or original.phy!=self.baseline.snapshot.station.phy or original.name!=self.deployment.manifest.ifname:
            _fail('native_interface_not_original')
        if self._fresh_boundary_snapshot_v62().key()!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
        return original
    def create_interface(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self._create_called or self.interface_ticket is None or self.create_row is None: _fail('native_create_unavailable')
            canonical=self._durable('interface_intent');ticket=self.interface_ticket
            if canonical.record.interface_intent.key()!=ticket.key() or self._scope>self._create_until: _fail('native_create_intent_changed')
            self._fd_current(self.create_row)
            attrs=_attr(1,struct.pack('<I',ticket.phy))+_attr(4,ticket.name.encode('ascii')+b'\0')+_attr(5,struct.pack('<I',8))
            self._create_called=True
            try:
                records,request=self._request(self.create_row,self._create_family,7,attrs,4|8,ticket.sequence)
                self.create_request=request
                if len(records)!=1 or records[0][0]!=7: _fail('native_create_echo_missing')
                echo=self._create_echo_original
                if echo is None or echo[0] != request or echo[1] is not ticket or echo[3] != records[0][1]:
                    _fail('native_create_echo_missing')
                owned=echo[2];self.owned=owned  # Publish ONLY after actual complete ACK+ECHO.
                if owned.iftype!=8 or owned.phy!=ticket.phy or owned.name!=ticket.name or \
                        any(r.wdev==owned.wdev or r.ifindex==owned.ifindex or r.name==owned.name for r in self.baseline.snapshot.interfaces):
                    _fail('native_create_origin_changed')
                self.origin_current(owned,_absolute_deadline)
                return owned
            finally: self._close(self.create_row)
    def origin_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not core.Origin or original is not self.owned or original.iftype!=8 or not self._create_called or self.create_request is None:
            _fail('native_origin_not_original')
        current=self._fresh_boundary_snapshot_v62()
        if self._outside_key(current,original)!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
        return original
    def observe_group_source(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.group_source is not None or self.owned is None: _fail('native_group_source_unavailable')
            self._durable('controller_live');self.origin_current(self.owned,_absolute_deadline)
            channel=self._channel_read();self.observations.append(channel)
            value=GoGroupSource(self,channel);self.group_source=value;self.observations.append(value)
            return value
    def group_source_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoGroupSource or original is not self.group_source or original.channel not in self.observations:
            _fail('native_group_source_not_original')
        current=self._channel_read();self.observations.append(current)
        if (current.frequency,current.channel_sha256,current.caps_sha256)!=(original.frequency,original.channel_sha256,original.caps_sha256):
            _fail('native_group_source_changed')
        return original
    def _controller(self):
        launcher=self.owner.launcher;ticket=self.owner.controller
        launch=self.deployment.modules['mta_go_process_owner']
        if type(launcher) is not launch.GoDirectChildOwner or launcher is not self.store._launcher_original or \
                type(ticket) is not launch.ChildTicket or ticket is not self.owner.controller or ticket.spec is not self.deployment.controller_spec:
            _fail('native_controller_not_original')
        launch.GoDirectChildOwner._exact(launcher,ticket)
        if ticket.unknown or not ticket.released or ticket.postexec is None or ticket.waited: _fail('native_controller_unavailable')
        observed=self._proc(ticket.pid,ticket.postexec)
        if observed.actor.key()!=ticket.postexec.key() or not observed.actor.live(): _fail('native_controller_changed')
        facts=self.store.current.record.controller
        if facts is None or facts.phase!='live' or facts.actor.key()!=ticket.postexec.key(): _fail('native_controller_not_durable')
        return ticket.postexec
    def open_control(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self.command_row is not None or self.event_row is not None: _fail('native_control_already_open')
            self._durable('controller_live');self._config();actor=self._controller()
            peer=self.deployment.manifest.ctrl+'/'+self.owned.name
            anchors=self._anchors(peer);metadata=inode=None
            for unused in range(2048):
                self._check()
                if self._anchors(peer)!=anchors: _fail('native_ctrl_directory_changed')
                try: metadata=self._path_metadata(peer)
                except OSError as error:
                    if type(error.errno) is not int or error.errno!=errno.ENOENT: raise
                    self._retain(('controller_endpoint_absent', error))
                    self.io.pause(min(.01,self._scope-self._check()))
                    self._check();continue
                if not stat.S_ISSOCK(metadata[2]) or metadata[3:5]!=(0,0) or metadata[5]!=1: _fail('native_ctrl_unowned')
                if self._controller() is not actor: _fail('native_controller_changed')
                inode=self._unix_owner(peer,actor)
                if self._path_metadata(peer)!=metadata or self._anchors(peer)!=anchors: _fail('native_ctrl_changed')
                self._check();break
            if inode is None: _fail('native_controller_endpoint_unavailable')
            self._server_original=(peer,metadata,actor,inode)  # Before either channel factory.
            # Two real native datagram channels, original controller path/
            # socket inode/Proc PID source and credential-authenticated replies.
            self.command_row=self._unix(peer,actor,True)
            self.event_row=self._unix(peer,actor,True)
            self._ctrl_actor=actor
            if self.command_row.peer_meta!=self.event_row.peer_meta: _fail('native_control_changed')
            if self._exchange(self.event_row,b'ATTACH')!=b'OK\n': _fail('native_attach_failed')
            return None
    def _group_event_frequency(self,raw):
        # Parse only the real received event or the immutable original retained
        # by wait_group. Requested GROUP_ADD frequency is never a substitute.
        if type(raw) is not bytes or not 1<=len(raw)<=8192 or b'\0' in raw:
            _fail('native_group_event_mismatch')
        eventraw=raw[:-2] if raw.endswith(b'\r\n') else raw[:-1] if raw.endswith(b'\n') else raw
        if b'\r' in eventraw or b'\n' in eventraw: _fail('native_group_event_mismatch')
        eventraw=re.sub(b'^<[0-4]>',b'',eventraw)
        match=re.match(b'^P2P-GROUP-STARTED (mta[0-9a-f]{8}) GO ssid="(?:\\\\.|[^"\\\\])*" freq=([0-9]{4})(?: |$)',eventraw)
        if self.owned is None or self.group_source is None or match is None or \
                match.group(1)!=self.owned.name.encode('ascii'):
            _fail('native_group_event_mismatch')
        frequency=int(match.group(2))
        if frequency!=self.group_source.frequency: _fail('native_group_event_mismatch')
        return frequency
    def _group_status(self,event_frequency):
        if type(event_frequency) is not int: _fail('native_group_event_mismatch')
        self._controller();raw=self._exchange(self.command_row,b'STATUS');f=_status(raw)
        if f.get(b'wpa_state')!=b'COMPLETED' or f.get(b'mode')!=b'AP' or \
                re.fullmatch(b'[0-9]{4}',f.get(b'freq',b'')) is None: _fail('native_go_status_unavailable')
        frequency=int(f[b'freq'])
        interfaces=self._interfaces();rows=tuple((r,k,m) for r,k,m in interfaces if r.key()[:4]==self.owned.key()[:4])
        if len(rows)!=1 or rows[0][0].iftype!=9 or (rows[0][1] is not None and rows[0][1]!=frequency) or \
                frequency!=event_frequency or frequency!=self.group_source.frequency:
            _fail('native_go_origin_changed')
        origin,kfreq,mac=rows[0]
        if mac is None or f.get(b'bssid',b'').lower()!=b':'.join(('%02x' % x).encode('ascii') for x in mac):
            _fail('native_go_bssid_changed')
        current=self._fresh_boundary_snapshot_v62()
        if self._outside_key(current,origin)!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
        return raw,frequency,origin
    def submit_group_add(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if self._group_submit_called or self.group_source is None or self.command_row is None or self.event_row is None:
                _fail('native_group_submit_unavailable')
            canonical=self._durable('group_add_intent');facts=None if canonical.record.group_add is None else dict(canonical.record.group_add)
            self.group_source_current(self.group_source,_absolute_deadline);self.origin_current(self.owned,_absolute_deadline)
            self._controller();wire=('P2P_GROUP_ADD freq=%d' % self.group_source.frequency).encode('ascii')
            if facts is None or facts['frequency']!=self.group_source.frequency or facts['command_sha256']!=hashlib.sha256(wire).hexdigest() or \
                    facts['channel_sha256']!=self.group_source.channel_sha256 or facts['caps_sha256']!=self.group_source.caps_sha256:
                _fail('native_group_intent_changed')
            self._group_submit_called=True  # Before actual native send, no retry.
            if self._exchange(self.command_row,wire)!=b'OK\n': _fail('native_group_submit_failed')
            return None
    def wait_group(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline)
            if not self._group_submit_called or self.group is not None: _fail('native_group_event_unavailable')
            self._durable('group_add_intent');event=event_frequency=None
            for unused in range(64):
                raw=self._ctrl_recv(self.event_row)
                eventraw=re.sub(b'^<[0-4]>',b'',raw)
                if eventraw.startswith((b'P2P-GROUP-REMOVED ',b'P2P-GROUP-FORMATION-FAILURE',b'CTRL-EVENT-TERMINATING')):
                    _fail('native_group_event_failed')
                if not eventraw.startswith(b'P2P-GROUP-STARTED '): continue
                event_frequency=self._group_event_frequency(raw)
                event=raw;break
            if event is None: _fail('native_group_event_limit')
            first,freq,origin=self._group_status(event_frequency);second,sfreq,sorigin=self._group_status(event_frequency)
            if (freq,origin.key())!=(sfreq,sorigin.key()): _fail('native_group_unstable')
            value=GoGroupObservation(self,event,second,sfreq,sorigin);self.group=value;self.observations.append(value)
            self._check();return value
    def group_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if type(original) is not GoGroupObservation or original is not self.group or original not in self.observations or \
                not self._group_submit_called or original.observed_origin.key()[:4]!=self.owned.key()[:4] or original.observed_origin.iftype!=9:
            _fail('native_group_not_original')
        event_frequency=self._group_event_frequency(original.event_raw)
        if event_frequency!=original.frequency: _fail('native_group_changed')
        raw,freq,origin=self._group_status(event_frequency)
        if freq!=original.frequency or origin.key()!=original.observed_origin.key(): _fail('native_group_changed')
        return original
    def _ip_original(self):
        original=self.ip_intent
        if type(original) is not GoIpObservation or original.native is not self or original not in self.observations or \
                self.group is None or original.facts.origin is not self.group.observed_origin or \
                self.ip_row is None or self.ip_request != ip.encode_new_address(original.facts.spec,
                    dict(original.facts.request)['sequence'],dict(original.facts.request)['port_id']):
            _fail('native_ip_source_changed')
        row=self.ip_row
        if self._ip_route_original!=(row,row.value,row.fd,row.metadata,row.port,self.ip_request,original) or \
                row.port!=dict(original.facts.request)['port_id']:
            _fail('native_ip_route_changed')
        self._fd_current(row);self._check()
        if row.value.getsockname()!=(row.port,0): _fail('native_ip_route_changed')
        self._check()
        return original
    def prepare_ip(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline);self._durable('group_started')
            if self.ip_intent is not None or self._ip_create_called: _fail('native_ip_already_attempted')
            self.group_current(self.group,_absolute_deadline)
            before=self._stable_snapshot()
            if self._outside_key(before,self.group.observed_origin)!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
            choice=ip.select_subnet(before.ipv4,ip_lease.CANDIDATES)
            spec=ip.AddressSpec(self.group.observed_origin.ifindex,ip.ipv4_text(choice.network+1),24)
            row=self._socket(0,True);self.ip_row=row
            sequence=self._next();request=ip.encode_new_address(spec,sequence,row.port)
            self.ip_request=request
            value=stores.GoIpFacts({'phase':'intent','origin':self.group.observed_origin,'spec':list(spec),
                'request':{'header':request[:16].hex(),'sequence':sequence,'port_id':row.port},'address':None})
            observation=GoIpObservation(self,value,before);self.ip_intent=observation
            self._ip_route_original=(row,row.value,row.fd,row.metadata,row.port,request,observation)
            self.observations.append(observation);self._check();return observation
    def ip_intent_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        if original is not self._ip_original() or self._ip_create_called: _fail('native_ip_intent_changed')
        self._fd_current(self.ip_row);self.group_current(self.group,_absolute_deadline)
        if self._outside_key(self._stable_snapshot(),original.facts.origin)!=self.baseline.snapshot.key():
            _fail('native_baseline_changed')
        return original
    def create_ip(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline);canonical=self._durable('ip_intent')
            original=self._ip_original()
            if self._ip_create_called or canonical.record.ip.key()!=original.facts.key(): _fail('native_ip_intent_changed')
            self.ip_intent_current(original,_absolute_deadline)
            self._ip_create_called=True  # Before send; neither timeout nor parse failure permits retry.
            self._send(self.ip_row,self.ip_request)
            ack=ip.decode_ack(self._recv(self.ip_row),self.ip_request)
            self.ip_ack=self._ip_ack_original=ack;self._retain(('ip_create_ack',ack))
            if ack.success is not True: _fail('native_ip_kernel_rejected')
            after=self._stable_snapshot()
            address=ip_lease._new_address(after.ipv4,original.facts.spec,
                {k:getattr(original.facts.origin,k) for k in ('name','ifindex','wdev','phy')})
            data=original.facts.data()
            data.update(phase='receipt_recorded',address=ip_lease.snapshot_data(ip.IpSnapshot(
                (address,),(),(ip.RuleRecord(0,255),ip.RuleRecord(32766,254),ip.RuleRecord(32767,253))))['addresses'][0])
            observation=GoIpObservation(self,stores.GoIpFacts(data),after)
            self.ip_receipt=observation;self.observations.append(observation)
            if self._outside_key(after,original.facts.origin)!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
            self._check();return observation
    def _ip_retained_current(self,original):
        """Original ACK/receipt/canonical/FD facts only, not a fresh IP snapshot."""
        intent=self._ip_original()
        if type(original) is not GoIpObservation or original is not self.ip_receipt or original not in self.observations or \
                type(self.ip_ack) is not ip.AckResult or self.ip_ack is not self._ip_ack_original or \
                self.ip_ack.command!=ip.RTM_NEWADDR or self.ip_ack.success is not True or not self._ip_create_called or \
                original.facts.source_key()!=intent.facts.source_key() or self.ip_restored is not None:
            _fail('native_ip_not_original')
        canonical=self.store.current
        if canonical is None or canonical.record.ip is None or canonical.record.ip.source_key()!=original.facts.source_key():
            _fail('native_ip_canonical_changed')
        self._fd_current(self.ip_row)
        return original
    def ip_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline)
        self._ip_retained_current(original)
        self.group_current(self.group,_absolute_deadline)
        snapshot=self._stable_snapshot()
        if not any(a==original.facts.address for a in snapshot.ipv4.addresses) or \
                self._outside_key(snapshot,original.facts.origin)!=self.baseline.snapshot.key():
            _fail('native_ip_changed')
        return original
    def _cleanup_ip_snapshot(self):
        snapshot=self._stable_snapshot()
        if self.owned is None:
            if snapshot.key()!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
            return snapshot
        origins=tuple(r for r in snapshot.interfaces if r.key()[:4]==self.owned.key()[:4])
        if len(origins)!=1 or origins[0].iftype not in (8,9) or \
                self._outside_key(snapshot,origins[0])!=self.baseline.snapshot.key():
            _fail('native_baseline_changed')
        return snapshot
    def prepare_ip_cleanup(self,_absolute_deadline):
        with self.mutex:
            self._send_closed_v75()
            self._begin(_absolute_deadline,True);canonical=self._durable('dhcp_closed',True)
            if self.ip_cleanup_intent is not None: _fail('native_ip_cleanup_already_attempted')
            snapshot=self._cleanup_ip_snapshot()
            value=canonical.record.ip
            if value is not None:
                if self.ip_intent is None or value.source_key()!=self._ip_original().facts.source_key():
                    _fail('native_ip_source_changed')
                present=any(a.ifindex==value.origin.ifindex for a in snapshot.ipv4.addresses) or any(
                    r.oif==value.origin.ifindex for r in snapshot.ipv4.routes)
                if present and (value.phase!='confirmed' or self.ip_receipt is None or
                        value.address!=self.ip_receipt.facts.address): _fail('native_ip_unconfirmed_delta')
                data=value.data();data['phase']='delete_intent';value=stores.GoIpFacts(data)
            observation=GoIpRestoreObservation(self,value,snapshot)
            self.ip_cleanup_intent=observation;self.observations.append(observation);return observation
    def ip_restore_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline,True)
        if type(original) is not GoIpRestoreObservation or original not in self.observations or (
                original is not self.ip_cleanup_intent and original is not self.ip_restored):
            _fail('native_ip_restore_not_original')
        snapshot=self._cleanup_ip_snapshot()
        if original is self.ip_restored:
            if self.ip_row is not None and (not self.ip_row.closed or self.ip_row.unknown):
                _fail('native_ip_resource_pending')
            index=None if original.facts is None else original.facts.origin.ifindex
            if index is not None and (any(a.ifindex==index for a in snapshot.ipv4.addresses) or any(
                    r.oif==index for r in snapshot.ipv4.routes)): _fail('native_ip_not_restored')
        return original
    def restore_ip(self,_absolute_deadline):
        with self.mutex:
            self._send_closed_v75()
            self._begin(_absolute_deadline,True);canonical=self._durable('ip_delete_intent',True)
            if self.ip_restored is not None or self._ip_delete_called: _fail('native_ip_restore_already_attempted')
            original=self.ip_cleanup_intent
            self.ip_restore_current(original,_absolute_deadline)
            value=canonical.record.ip
            if (None if value is None else value.key())!=(None if original.facts is None else original.facts.key()):
                _fail('native_ip_cleanup_intent_changed')
            snapshot=self._cleanup_ip_snapshot()
            present=value is not None and (any(a.ifindex==value.origin.ifindex for a in snapshot.ipv4.addresses) or
                any(r.oif==value.origin.ifindex for r in snapshot.ipv4.routes))
            if present:
                if self.ip_receipt is None or value.address is None or self.ip_ack is None or self.ip_ack.success is not True:
                    _fail('native_ip_unconfirmed_delta')
                self._fd_current(self.ip_row)
                request=ip.encode_del_address(value.spec,self._next(),self.ip_row.port)
                self._ip_delete_called=True
                self._send(self.ip_row,request)
                ack=ip.decode_ack(self._recv(self.ip_row),request);self._retain(('ip_delete_ack',ack))
                if ack.success is not True: _fail('native_ip_delete_rejected')
            after=self._cleanup_ip_snapshot()
            if value is not None and (any(a.ifindex==value.origin.ifindex for a in after.ipv4.addresses) or any(
                    r.oif==value.origin.ifindex for r in after.ipv4.routes)): _fail('native_ip_not_restored')
            if self.ip_row is not None and not self.ip_row.closed: self._close(self.ip_row,_absolute_deadline)
            if value is not None:
                data=value.data();data['phase']='restored';value=stores.GoIpFacts(data)
            observation=GoIpRestoreObservation(self,value,after)
            self.ip_restored=observation;self.observations.append(observation);self._check();return observation

    def _dhcp_setup_parent(self):
        """Pure original parent facts; usable for known close after active expiry."""
        self._owner()
        original=self._dhcp_setup_originals
        actual=(self,self.owner,self.store,self.deployment,self.worker,self.mutex,self.clock,
            self.until,self._dhcp_setup_until_original,self.ip_intent,self.ip_receipt,self.ip_ack,
            self._ip_ack_original,self.ip_row,self._ip_route_original,self.baseline,self.group,
            self.group_source,self.store.issuer)
        if original is not self._dhcp_setup_originals_issued or \
                type(original) is not tuple or len(original)!=len(actual) or any(
                x is not y for x,y in zip(actual,original)) or \
                type(self._dhcp_setup_until_original) is not float or \
                self.owner.setup_until is not self._dhcp_setup_until_original or \
                self.owner._setup_until_original is not self._dhcp_setup_until_original or \
                threading.current_thread() is not self.worker or \
                getattr(self.mutex,'_is_owned',lambda:False)() is not True:
            _fail('native_dhcp_setup_original_changed')
        return self._dhcp_setup_until_original
    def _dhcp_setup_begin(self,end):
        cap=self._dhcp_setup_parent()
        end=sources._time(end)
        self._begin(min(end,cap))
        return self._scope
    def _dhcp_setup_ip(self):
        self._ip_retained_current(self.ip_receipt)
        value=self.store.current.record.ip
        if value.phase!='confirmed' or value.address!=self.ip_receipt.facts.address:
            _fail('native_dhcp_ip_changed')
        return self.ip_receipt
    def _dhcp_next_canonical(self,current,previous,history,observation,phase):
        """Only the immediately next actual publication; no equal-facts rebasing."""
        store=self.store
        if type(history) is not tuple or not history or history[-1] is not previous or \
                type(store._canonical_history) is not tuple or len(store._canonical_history)!=len(history)+1 or \
                any(x is not y for x,y in zip(store._canonical_history[:-1],history)) or \
                current is not store.current or current is not store._canonical_history[-1] or \
                type(current) is not stores.GoCanonical or current.issuer is not store.issuer or \
                current.record.phase!=phase or current.record.generation!=previous.record.generation+1 or \
                current.record.facts_key()!=previous.record.facts_key() or \
                type(observation) is not GoDhcpObservation or observation.native is not self or \
                current.record.dhcp is None or current.record.dhcp.key()!=observation.facts.key() or \
                any(stores._field_key(current.record,name)!=stores._field_key(previous.record,name)
                    for name in stores._KEYS-{'phase','generation','dhcp'}):
            _fail('native_dhcp_publication_changed')
        return current
    def _dhcp_setup_canonical(self):
        """Check fixed C0 -> pending/readback C1 -> pending/readback C2 only."""
        self._dhcp_setup_parent()
        store=self.store;current=store.current
        if type(current) is not stores.GoCanonical or current.issuer is not store.issuer or \
                type(store._canonical_history) is not tuple or not store._canonical_history or \
                current is not store._canonical_history[-1]:
            _fail('native_dhcp_canonical_changed')
        phase=current.record.phase
        if phase=='ip_confirmed':
            if current is not self._dhcp_setup_c0 or store._canonical_history is not self._dhcp_setup_h0:
                _fail('native_dhcp_publication_changed')
        elif phase=='dhcp_intent':
            if self._dhcp_intent_consumed is not True:
                _fail('native_dhcp_setup_not_consumed')
            self._dhcp_next_canonical(current,self._dhcp_setup_c0,self._dhcp_setup_h0,
                self.dhcp_intent,'dhcp_intent')
            if self._dhcp_setup_c1 is not None and (current is not self._dhcp_setup_c1 or
                    store._canonical_history is not self._dhcp_setup_h1):
                _fail('native_dhcp_publication_changed')
        elif phase=='dhcp_listening':
            if self._dhcp_listening_consumed is not True or self._dhcp_setup_c1 is None:
                _fail('native_dhcp_setup_not_consumed')
            self._dhcp_next_canonical(current,self._dhcp_setup_c1,self._dhcp_setup_h1,
                self.dhcp_observed,'dhcp_listening')
            if self._dhcp_setup_c2 is not None and (current is not self._dhcp_setup_c2 or
                    store._canonical_history is not self._dhcp_setup_h2):
                _fail('native_dhcp_publication_changed')
        else:
            _fail('native_dhcp_phase_changed')
        return current
    def _dhcp_setup_consume(self,original,consumer):
        store=self.store
        mode='intent' if original is self.dhcp_intent else 'listening'
        token=self._dhcp_intent_token_original if mode=='intent' else self._dhcp_listening_token_original
        phase='ip_confirmed' if mode=='intent' else 'dhcp_intent'
        call='dhcp_intent' if mode=='intent' else 'dhcp_listening'
        consumed=self._dhcp_intent_consumed if mode=='intent' else self._dhcp_listening_consumed
        if type(consumer) is not tuple or len(consumer)!=10 or \
                consumer is not store._dhcp_setup_consumer_original or \
                any(x is not y for x,y in zip(consumer[:6],
                    (store,self,self.owner,store.current,store.issuer,original))) or \
                type(consumer[6]) is not str or consumer[6]!='dhcp' or \
                consumer[7] is not store.scope_until or consumer[7] is not store._scope_original or \
                consumer[8] is not self.worker or consumer[9] is not self.mutex or \
                store._cleanup_scope is not False or store._scope_open_start is not None or call not in store._calls or \
                type(token) is not _DhcpSetupToken or consumed is not False or \
                type(self._dhcp_setup_tokens) is not tuple or \
                self._dhcp_setup_tokens is not self._dhcp_setup_token_history or \
                len(self._dhcp_setup_tokens)!=(1 if mode=='intent' else 2) or \
                token is not self._dhcp_setup_tokens[0 if mode=='intent' else 1] or \
                token.observation is not original or token.canonical is not store.current or \
                token.history is not store._canonical_history or token.canonical.record.phase!=phase or \
                token.originals is not self._dhcp_setup_originals or token.issuer is not store.issuer or \
                any(x is not y for x,y in zip((token.native,token.owner,token.store,token.deployment,
                    token.worker,token.mutex,token.clock,token.until,token.setup_until,token.binding,
                    token.server,token.constructor,token.ip,token.ack),
                    (self,self.owner,store,self.deployment,self.worker,self.mutex,self.clock,self.until,
                    self._dhcp_setup_until_original,self.dhcp_binding,self.owner.dhcp,
                    self.owner._dhcp_ticket_original,self.ip_receipt,self._ip_ack_original))) or \
                self._dhcp_service_attempted or self._dhcp_service_original is not None:
            _fail('native_dhcp_setup_consumer_changed')
        # Claim before a fresh FD check/callback can fail. No retry or poll grant.
        if mode=='intent': self._dhcp_intent_consumed=True
        else: self._dhcp_listening_consumed=True
        self._dhcp_setup_ip()
        if mode=='listening':
            row=self.dhcp_row
            if row is not token.row or row.value is not token.raw or row.fd is not token.fd or \
                    row.metadata is not token.metadata or row.value is not self.owner.dhcp.socket:
                _fail('native_dhcp_socket_changed')
            self._fd_current(row)
        elif token.row is not None or self.dhcp_row is not None or self._dhcp_open_called:
            _fail('native_dhcp_setup_stage_changed')
        self._check();self._dhcp_owner(self.dhcp_binding,self.owner.dhcp);self._dhcp_setup_canonical()
        retained=self._dhcp_intent_token_original if mode=='intent' else self._dhcp_listening_token_original
        actual=self.dhcp_intent if mode=='intent' else self.dhcp_observed
        claimed=self._dhcp_intent_consumed if mode=='intent' else self._dhcp_listening_consumed
        if claimed is not True or retained is not token or actual is not original or \
                type(self._dhcp_setup_tokens) is not tuple or \
                self._dhcp_setup_tokens is not self._dhcp_setup_token_history or \
                len(self._dhcp_setup_tokens)!=(1 if mode=='intent' else 2) or \
                self._dhcp_setup_tokens[0 if mode=='intent' else 1] is not token or \
                consumer is not store._dhcp_setup_consumer_original or \
                store.current is not token.canonical or store._canonical_history is not token.history:
            _fail('native_dhcp_setup_consumer_changed')
        return original
    def issue_dhcp_binding(self,_absolute_deadline):
        with self.mutex:
            if self._dhcp_setup_until_original is not None or self.dhcp_binding is not None:
                _fail('native_dhcp_binding_unavailable')
            cap=self.owner.setup_until
            if type(cap) is not float or cap is not self.owner._setup_until_original or \
                    _absolute_deadline is not cap or not 0<=cap<=self.until:
                _fail('native_dhcp_setup_original_changed')
            # The existing owner-issued cap is retained before this setup's IO.
            self._dhcp_setup_until_original=cap
            self._dhcp_setup_originals=(self,self.owner,self.store,self.deployment,self.worker,self.mutex,
                self.clock,self.until,cap,self.ip_intent,self.ip_receipt,self.ip_ack,self._ip_ack_original,
                self.ip_row,self._ip_route_original,self.baseline,self.group,self.group_source,self.store.issuer)
            self._dhcp_setup_originals_issued=self._dhcp_setup_originals
            self._dhcp_setup_begin(cap);canonical=self._durable('ip_confirmed')
            if canonical.record.ip is None or canonical.record.ip.phase!='confirmed':
                _fail('native_dhcp_binding_unavailable')
            self._dhcp_setup_ip()
            self._dhcp_setup_parent()
            if self.store.current is not canonical or not self.store._canonical_history or \
                    self.store._canonical_history[-1] is not canonical or self.store.publication_unknown or \
                    self.store.failure is not None or self.store.restore_attempted:
                _fail('native_dhcp_canonical_changed')
            self._dhcp_setup_c0,self._dhcp_setup_h0=canonical,self.store._canonical_history
            value=GoDhcpBinding(self,self.ip_receipt);self.dhcp_binding=value;return value
    def _dhcp_owner(self,binding,server):
        self._dhcp_setup_parent()
        module=self.deployment.modules['mta_go_dhcp'];ticket=self.owner.dhcp_ticket
        bootstrap=self.deployment.modules['mta_go_bootstrap']
        if type(binding) is not GoDhcpBinding or binding is not self.dhcp_binding or type(server) is not module.GoDhcpServer or \
                server is not self.owner.dhcp or type(ticket) is not bootstrap._DhcpConstructor or \
                ticket is not self.owner._dhcp_ticket_original or ticket.creator is not module.GoDhcpServer or \
                ticket.returned is not server or ticket.unknown or ticket.owner is not self.owner or ticket.binding is not binding or \
                server.binding is not binding or binding.native is not self or binding._ip is not self.ip_receipt or \
                binding.owner is not self.owner or binding.store is not self.store or binding.deployment is not self.deployment or \
                binding.until is not self.until or binding.setup_until is not self._dhcp_setup_until_original or \
                binding.worker is not self.worker or binding.mutex is not self.mutex or \
                binding.clock is not self.clock or binding.origin is not self.ip_receipt.facts.origin or \
                binding.server_ip!=self.ip_receipt.facts.spec.address or binding.client_ip!=binding.server_ip+1 or \
                binding.subnet_mask!=0xffffff00:
            _fail('native_dhcp_owner_changed')
        if self.dhcp_row is not self._dhcp_row_original or server.socket is not server._socket_original:
            _fail('native_dhcp_socket_changed')
        # Close retains original facts even after scope expiry/restore transition.
        current=self.store.current
        if type(current) is not stores.GoCanonical or current.issuer is not self.store.issuer or \
                not self.store._canonical_history or current is not self.store._canonical_history[-1] or \
                current.record.ip is None or current.record.ip.source_key()!=binding._ip.facts.source_key() or \
                current.record.dhcp is not None and current.record.dhcp.source_key()!=(
                    binding.origin.key(),binding.server_ip,binding.client_ip,24,self.until):
            _fail('native_dhcp_canonical_changed')
        return server
    def _dhcp_gate(self,binding,server):
        self._dhcp_owner(binding,server)
        if self._scope_cleanup is not False or self.store.publication_unknown or self.store.restore_attempted or \
                self.store.failure is not None:
            _fail('native_dhcp_canonical_changed')
        original=self._dhcp_service_original
        if original is None:
            self._dhcp_setup_begin(self._scope);self._dhcp_setup_canonical()
        else:
            if type(original) is not tuple or len(original)!=6 or \
                    original is not self._dhcp_service_issued_original or self._dhcp_service_returned is not True or \
                    any(x is not y for x,y in zip((self.store.current,self._scope,binding,server,self.dhcp_row,
                        self._dhcp_setup_until_original),original)) or \
                    self.owner.service_until is not original[1] or self.owner._service_until_original is not original[1] or \
                    self.store.current is not self._dhcp_setup_c2 or self.store._canonical_history is not self._dhcp_setup_h2:
                _fail('native_dhcp_service_changed')
            self._begin(original[1])
        record=self.store.current.record
        if record.phase not in ('ip_confirmed','dhcp_intent','dhcp_listening') or record.ip is None or record.ip.phase!='confirmed':
            _fail('native_dhcp_phase_changed')
        if record.ip.source_key()!=binding._ip.facts.source_key() or record.ip.address!=binding._ip.facts.address or \
                self.ip_restored is not None or type(self.ip_ack) is not ip.AckResult or \
                self.ip_ack is not self._ip_ack_original or self.ip_ack.command!=ip.RTM_NEWADDR or self.ip_ack.success is not True:
            _fail('native_dhcp_ip_changed')
        return self._check()
    def prepare_dhcp(self,binding,server,_absolute_deadline):
        with self.mutex:
            self._dhcp_setup_begin(_absolute_deadline);self._dhcp_gate(binding,server)
            if self.dhcp_intent is not None: _fail('native_dhcp_already_attempted')
            canonical=self._durable('ip_confirmed');self._dhcp_setup_canonical();self._dhcp_setup_ip()
            value=stores.GoDhcpFacts({'phase':'intent','origin':binding.origin,'server_ip':binding.server_ip,
                'client_ip':binding.client_ip,'prefix':24,'until':self.until})
            observation=GoDhcpObservation(self,value);self.dhcp_intent=observation
            self.observations.append(observation)
            self._dhcp_intent_token_original=_DhcpSetupToken(self,binding,server,observation,canonical,
                self.store._canonical_history,None)
            self._dhcp_setup_tokens+=(self._dhcp_intent_token_original,)
            self._dhcp_setup_token_history=self._dhcp_setup_tokens
            self._check();return observation
    def _dhcp_socket(self,binding,server):
        self._dhcp_gate(binding,server);canonical=self._durable('dhcp_intent')
        self._dhcp_setup_canonical()
        if self._dhcp_setup_c1 is not None: _fail('native_dhcp_socket_already_attempted')
        self._dhcp_setup_c1,self._dhcp_setup_h1=canonical,self.store._canonical_history
        self.ip_current(binding._ip,self._scope)  # Actual pre-factory boundary.
        if self._dhcp_open_called or self.dhcp_row is not None: _fail('native_dhcp_socket_already_attempted')
        self._dhcp_open_called=True;row=self._record('udp',True);self.dhcp_row=self._dhcp_row_original=row
        try: value=self.io.udp()
        except OSError:
            row.attempted=row.closed=True;raise
        row.value,row.returned=value,True
        self._adopt(row,value,value.fileno())
        if not stat.S_ISSOCK(row.metadata[2]): _fail('native_dhcp_socket_invalid')
        self._check();return value
    def _dhcp_setup_server_ready(self,server,row):
        self._dhcp_owner(self.dhcp_binding,server)
        if row is not self.dhcp_row or row is None or row.value is not server.socket or \
                server._open_returned is not True or server._opening is not False or server._active is not False or \
                server._close_called or server._failure is not None or server._stage!='listening' or \
                server._service_called is not False or server._active_until is not None or \
                server._active_until_original is not None or server._core is not None:
            _fail('native_dhcp_socket_changed')
        return row
    def _dhcp_udp_readback(self,server):
        row=self._dhcp_setup_server_ready(server,self.dhcp_row)
        self._fd_current(row);raw=row.value;module=self.deployment.modules['mta_go_dhcp']
        self._check();actual=raw.getsockname();self._check()
        if actual!=('0.0.0.0',67): _fail('native_dhcp_endpoint_changed')
        self._check();device=raw.getsockopt(socket.SOL_SOCKET,module.SO_BINDTODEVICE,16);self._check()
        if type(device) is not bytes or device!=self.dhcp_binding.origin.name.encode('ascii')+b'\0':
            _fail('native_dhcp_endpoint_changed')
        for level,option,expected in ((socket.SOL_SOCKET,socket.SO_TYPE,socket.SOCK_DGRAM),
                (socket.SOL_SOCKET,socket.SO_REUSEADDR,0),(socket.SOL_SOCKET,module.SO_REUSEPORT,0),
                (socket.SOL_SOCKET,socket.SO_BROADCAST,1),(socket.IPPROTO_IP,module.IP_PKTINFO,1)):
            self._check();actual=raw.getsockopt(level,option);self._check()
            if type(actual) is not int or actual!=expected: _fail('native_dhcp_options_changed')
        self._check();inheritable=raw.get_inheritable();self._check()
        if inheritable is not False: _fail('native_dhcp_options_changed')
        self._fd_current(row);self._dhcp_setup_server_ready(server,row)
        return row
    def observe_dhcp(self,server,_absolute_deadline):
        with self.mutex:
            self._dhcp_setup_begin(_absolute_deadline);self._dhcp_gate(self.dhcp_binding,server)
            if self.dhcp_observed is not None: _fail('native_dhcp_observation_already_issued')
            canonical=self._durable('dhcp_intent');self._dhcp_setup_canonical()
            if canonical is not self._dhcp_setup_c1: _fail('native_dhcp_publication_changed')
            self.ip_current(self.ip_receipt,self._scope)  # Actual post-bind boundary.
            row=self._dhcp_udp_readback(server)
            data=self.dhcp_intent.facts.data();data['phase']='listening'
            observation=GoDhcpObservation(self,stores.GoDhcpFacts(data))
            self.dhcp_observed=observation;self.observations.append(observation)
            self._dhcp_listening_token_original=_DhcpSetupToken(self,self.dhcp_binding,server,observation,
                canonical,self.store._canonical_history,row)
            self._dhcp_setup_tokens+=(self._dhcp_listening_token_original,)
            self._dhcp_setup_token_history=self._dhcp_setup_tokens
            self._check();return observation
    def dhcp_current(self,original,_absolute_deadline,_setup_consumer=None):
        if self._dhcp_service_original is None: self._dhcp_setup_begin(_absolute_deadline)
        else: self._begin(_absolute_deadline)
        if type(original) is not GoDhcpObservation or original not in self.observations or (
                original is not self.dhcp_intent and original is not self.dhcp_observed):
            _fail('native_dhcp_not_original')
        self._dhcp_gate(self.dhcp_binding,self.owner.dhcp)
        if original is self.dhcp_observed:
            if self.dhcp_row is None or self.dhcp_row.value is not self.owner.dhcp.socket: _fail('native_dhcp_socket_changed')
            self._fd_current(self.dhcp_row)
        if _setup_consumer is not None:
            return self._dhcp_setup_consume(original,_setup_consumer)
        # No token: preserve the original generic real group + double IP read.
        self.ip_current(self.ip_receipt,self._scope)
        return original
    def begin_dhcp_service(self,server,_absolute_deadline):
        with self.mutex:
            if _absolute_deadline is not self._dhcp_setup_until_original:
                _fail('native_dhcp_setup_original_changed')
            self._dhcp_setup_begin(_absolute_deadline);self._dhcp_gate(self.dhcp_binding,server)
            if self._dhcp_service_attempted or self._dhcp_service_original is not None or self.dhcp_observed is None:
                _fail('native_dhcp_service_already_attempted')
            self._dhcp_service_attempted=True  # Before the final IO; never retry.
            canonical=self._durable('dhcp_listening');self._dhcp_setup_canonical()
            if self._dhcp_setup_c2 is not None: _fail('native_dhcp_service_already_attempted')
            self._dhcp_setup_c2,self._dhcp_setup_h2=canonical,self.store._canonical_history
            self.ip_current(self.ip_receipt,self._scope)  # Final actual setup boundary.
            row=self._dhcp_udp_readback(server)
            self._dhcp_setup_canonical();self._dhcp_setup_server_ready(server,row)
            now=self._check()
            end=min(self.until,now+20.0)  # First service issuance, not setup renewal.
            if not now<end<=self.until: _fail('native_dhcp_service_scope_invalid')
            original=(canonical,end,self.dhcp_binding,server,row,self._dhcp_setup_until_original)
            self._dhcp_service_original=self._dhcp_service_issued_original=original
            self._begin(end);self._check()
            self._dhcp_service_returned=True
            return original[1]
    def _dhcp_close_socket(self,binding,server,sock):
        self._dhcp_owner(binding,server)
        row=self.dhcp_row
        if sock is None:
            if server.socket is not None: _fail('native_dhcp_socket_changed')
            if row is None: return self._dhcp_open_called is False
            if type(row) is not _Resource or row.native is not self or not any(row is r for r in self._history):
                _fail('native_dhcp_socket_changed')
            # Native factory/adopt may have completed but not returned to the
            # Server. Only its already recorded actual closure is consumed.
            return row.closed and row.attempted and not row.unknown
        if row is None or row.value is not sock: _fail('native_dhcp_socket_changed')
        # Stop-only original resource close, no continuing AP/UDP authority.
        self._close(row);return row.closed and not row.unknown
    def close_dhcp(self,_absolute_deadline):
        with self.mutex:
            self._send_closed_v75()
            self._begin(_absolute_deadline,True);canonical=self._durable('restore_intent',True)
            if self._dhcp_close_called or self.dhcp_closed is not None: _fail('native_dhcp_close_already_attempted')
            self._dhcp_close_called=True
            server=self.owner.dhcp
            if server is not None:
                self._dhcp_owner(self.dhcp_binding,server)
                # Native may have returned/adopted the raw socket before its
                # last postcheck failed, so Server never received that return.
                # Close ONLY this exact native inventoried known original;
                # None on Server is not a proof that the factory had no FD.
                row=self.dhcp_row
                if row is not None and server.socket is None:
                    if row.unknown or not row.returned and not row.closed:
                        _fail('native_dhcp_resource_pending')
                    if not row.closed: self._close(row,_absolute_deadline)
                module=self.deployment.modules['mta_go_dhcp']
                if module.GoDhcpServer.close(server) is not True: _fail('native_dhcp_server_pending')
            elif self.owner.dhcp_ticket is not None: _fail('native_dhcp_constructor_pending')
            if self.dhcp_row is not None and (not self.dhcp_row.closed or self.dhcp_row.unknown):
                _fail('native_dhcp_resource_pending')
            value=canonical.record.dhcp
            if value is not None:
                if self.dhcp_intent is None or value.source_key()!=self.dhcp_intent.facts.source_key():
                    _fail('native_dhcp_source_changed')
                data=value.data();data['phase']='closed';value=stores.GoDhcpFacts(data)
            observation=GoDhcpObservation(self,value)
            self.dhcp_closed=observation;self.observations.append(observation);return observation
    def dhcp_closed_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline,True)
        if type(original) is not GoDhcpObservation or original is not self.dhcp_closed or original not in self.observations or \
                self.dhcp_row is not None and (not self.dhcp_row.closed or self.dhcp_row.unknown):
            _fail('native_dhcp_close_not_original')
        if self.owner.dhcp_ticket is not None and (self.owner.dhcp is None or self.owner.dhcp_ticket.unknown):
            _fail('native_dhcp_constructor_pending')
        if self.owner.dhcp is not None: self._dhcp_owner(self.dhcp_binding,self.owner.dhcp)
        return original
    def _send_dhcp_v75(self,end):
        """Original serving C2 under a narrowing cap, never _dhcp_gate renewal."""
        end=sources._time(end);self._begin(end)
        original=self._dhcp_service_original;server=self.owner.dhcp
        if type(original) is not tuple or len(original)!=6 or \
                original is not self._dhcp_service_issued_original or self._dhcp_service_returned is not True or \
                type(original[1]) is not float or not end<=original[1] or \
                self._scope_cleanup is not False or self.store.restore_attempted or self.store.publication_unknown or \
                self.store.failure is not None or self._send_close_attempted_v75 or \
                self.store.current is not original[0] or self.store.current is not self._dhcp_setup_c2 or \
                self.store._canonical_history is not self._dhcp_setup_h2 or \
                original[2] is not self.dhcp_binding or original[3] is not server or \
                original[4] is not self.dhcp_row or original[5] is not self._dhcp_setup_until_original or \
                self.owner.service_until is not original[1] or self.owner._service_until_original is not original[1] or \
                threading.current_thread() is not self.worker or getattr(self.mutex,'_is_owned',lambda:False)() is not True:
            _fail('native_send_service_changed')
        self._dhcp_owner(self.dhcp_binding,server)
        module=self.deployment.modules['mta_go_dhcp'];module.GoDhcpServer._context(server)
        if server._stage!='serving' or server._service_called is not True or server._open_returned is not True or \
                server._opening is not False or server._active is not False or server._close_called is not False or \
                server._failure is not None or server._active_until is not original[1] or \
                server._active_until_original is not original[1] or type(server._core) is not module.wire.SingleClientServer:
            _fail('native_send_service_changed')
        canonical=self.store.current
        if type(canonical) is not stores.GoCanonical or canonical.issuer is not self.store.issuer or \
                type(self.store._canonical_history) is not tuple or not self.store._canonical_history or \
                self.store._canonical_history[-1] is not canonical or canonical.record.phase!='dhcp_listening' or \
                canonical.record.ip is None or canonical.record.ip.phase!='confirmed' or \
                canonical.record.dhcp is None or canonical.record.dhcp.phase!='listening' or \
                canonical.record.ip.source_key()!=self.ip_receipt.facts.source_key() or \
                canonical.record.ip.address!=self.ip_receipt.facts.address or self.ip_restored is not None:
            _fail('native_send_canonical_changed')
        self._ip_retained_current(self.ip_receipt)
        self._fd_current(self.dhcp_row);self._check();return end
    def _send_udp_current_v75(self):
        """Actual serving UDP FD/options readback; not a fresh IP replacement."""
        row=self.dhcp_row;server=self.owner.dhcp;module=self.deployment.modules['mta_go_dhcp']
        self._fd_current(row);raw=row.value
        if raw is not server.socket or raw is not server._socket_original:
            _fail('native_send_udp_changed')
        self._check();endpoint=raw.getsockname();self._check()
        if endpoint!=('0.0.0.0',67): _fail('native_send_udp_changed')
        self._check();device=raw.getsockopt(socket.SOL_SOCKET,module.SO_BINDTODEVICE,16);self._check()
        if type(device) is not bytes or device!=self.dhcp_binding.origin.name.encode('ascii')+b'\0':
            _fail('native_send_udp_changed')
        for level,option,expected in ((socket.SOL_SOCKET,socket.SO_TYPE,socket.SOCK_DGRAM),
                (socket.SOL_SOCKET,socket.SO_REUSEADDR,0),(socket.SOL_SOCKET,module.SO_REUSEPORT,0),
                (socket.SOL_SOCKET,socket.SO_BROADCAST,1),(socket.IPPROTO_IP,module.IP_PKTINFO,1)):
            self._check();value=raw.getsockopt(level,option);self._check()
            if type(value) is not int or value!=expected: _fail('native_send_udp_changed')
        self._check();inheritable=raw.get_inheritable();self._check()
        if inheritable is not False: _fail('native_send_udp_changed')
        self._fd_current(row);return row
    def _send_basis_gate_v75(self,basis,end):
        if type(basis) is not GoSendBasis or basis is not self._send_basis_original or \
                basis is not self._send_basis_issued_original or self._send_basis_returned is not True or \
                basis.end is not self._send_basis_end_original or sources._time(end)>basis.end:
            _fail('native_send_basis_not_original')
        self._send_dhcp_v75(end)
        actual=(self,self.owner,self.store,self.deployment,self.entry,self.worker,self.mutex,self.clock,self.until,
            self.group,self.group.event_raw,self._send_status_raw_v75,self.group.observed_origin,
            self.ip_receipt,self._ip_ack_original,self.store.current,self.store._canonical_history,self.store.issuer,
            self._dhcp_service_original,self.dhcp_binding,self.owner.dhcp,self.dhcp_row,self.dhcp_row.value,
            self.dhcp_row.fd,self.dhcp_row.metadata)
        names=('native','owner','store','deployment','entry','worker','mutex','clock','until','group','event_raw',
            'current_status_raw','origin','ip','ack','canonical','history','issuer','service_tuple','binding','server',
            'dhcp_row','dhcp_raw','dhcp_fd','dhcp_metadata')
        if any(getattr(basis,name) is not value for name,value in zip(names,actual)) or \
                type(self._send_credentials_original_v75) is not _GoCredentialsV75 or \
                (basis.ssid,basis.ssid_bytes,basis.psk,basis.go_dev_addr)!=(
                    self._send_credentials_original_v75.ssid,self._send_credentials_original_v75.ssid_bytes,
                    self._send_credentials_original_v75.psk,self._send_credentials_original_v75.go_dev_addr):
            _fail('native_send_basis_changed')
        self._check();return basis
    def issue_send_basis(self,_absolute_deadline):
        with self.mutex:
            if self._send_basis_attempted: _fail('native_send_basis_already_attempted')
            end=self._send_dhcp_v75(_absolute_deadline)
            self._send_basis_attempted=True  # Before fresh reads/codec; no retry.
            self.ip_current(self.ip_receipt,end)  # Includes actual group/STATUS/kernel + double IP.
            self._send_dhcp_v75(end);self._send_udp_current_v75()
            credentials=_go_credentials_v75(self.group.event_raw,self.owned.name,self.group.frequency)
            self._controller();self._check();raw=self._exchange(self.command_row,b'STATUS')
            self._send_status_raw_v75=raw;self._retain(('send_status_v75',raw))
            values=_status(raw)
            if values.get(b'wpa_state')!=b'COMPLETED' or values.get(b'mode')!=b'AP' or \
                    values.get(b'freq')!=str(self.group.frequency).encode('ascii') or b'ssid' not in values or \
                    _go_ssid_v75(values[b'ssid'])[1]!=credentials.ssid_bytes:
                _fail('native_send_ssid_changed')
            self._send_dhcp_v75(end);self._check()
            self._send_credentials_original_v75=credentials;self._send_basis_end_original=end
            basis=GoSendBasis(self,end,credentials,raw)
            self._send_basis_original=self._send_basis_issued_original=basis
            self._send_dhcp_v75(end);self._check();self._send_basis_returned=True
            return basis
    def _send_tcp_current_v75(self,row,basis):
        self._fd_current(row);raw=row.value
        if type(row) is not _Resource or row.native is not self or row.kind!='tcp' or \
                not any(row is r for r in self._send_tcp_history_v75) or row.bound:
            _fail('native_send_tcp_changed')
        for option,expected in ((39,socket.AF_INET),(38,socket.IPPROTO_TCP),(socket.SO_TYPE,socket.SOCK_STREAM),
                (socket.SO_ACCEPTCONN,0),(socket.SO_REUSEADDR,0),(15,0)):
            self._check();value=raw.getsockopt(socket.SOL_SOCKET,option);self._check()
            if type(value) is not int or value!=expected: _fail('native_send_tcp_options_changed')
        self._check();device=raw.getsockopt(socket.SOL_SOCKET,25,16);self._check()
        if type(device) is not bytes or device!=basis.origin.name.encode('ascii')+b'\0':
            _fail('native_send_tcp_options_changed')
        self._check();linger=raw.getsockopt(socket.SOL_SOCKET,socket.SO_LINGER,8);self._check()
        if type(linger) is not bytes or len(linger)!=8 or struct.unpack('ii',linger)[0]!=0:
            _fail('native_send_tcp_options_changed')
        self._check();inheritable=raw.get_inheritable();self._check()
        self._check();timeout=raw.gettimeout();self._check()
        if inheritable is not False or type(timeout) not in (int,float) or timeout!=0:
            _fail('native_send_tcp_options_changed')
        self._check()
        try: raw.getpeername()
        except OSError as error:
            if type(error.errno) is not int or error.errno!=errno.ENOTCONN:
                _fail('native_send_tcp_connected')
        else: _fail('native_send_tcp_connected')
        self._check();endpoint=raw.getsockname();self._check()
        if type(endpoint) is not tuple or len(endpoint)!=2 or type(endpoint[0]) is not str or \
                endpoint[0]!=ip.ipv4_text(basis.binding.server_ip) or not _int(endpoint[1],1,65535):
            _fail('native_send_tcp_endpoint_changed')
        if row._tcp_endpoint_v75 is not None and endpoint!=row._tcp_endpoint_v75:
            _fail('native_send_tcp_endpoint_changed')
        row._tcp_endpoint_v75=endpoint;row.port=endpoint[1]
        self._fd_current(row);self._check();return row
    def open_send_listener(self,basis,_absolute_deadline):
        with self.mutex:
            if self._send_listener_attempted: _fail('native_send_listener_already_attempted')
            end=sources._time(_absolute_deadline);self._send_basis_gate_v75(basis,end)
            self._send_listener_attempted=True  # Before real read/factory; no retry.
            self.ip_current(basis.ip,end);self._send_basis_gate_v75(basis,end)
            row=self._record('tcp',True)
            self._send_tcp_rows_v75+=(row,);self._send_tcp_history_v75=self._send_tcp_rows_v75
            try:
                self._check()
                row._tcp_factory_called_v75=True  # Immediately before the sole actual factory.
                try: raw=self.io.tcp()
                except OSError as error:
                    row.failure=error
                    if type(error.errno) is int and 1<=error.errno<=4095:
                        row.attempted=row.closed=True  # Known negative factory, not a closed FD.
                    else: row.unknown=True
                    raise
                except BaseException as error:
                    row.failure=error;row.unknown=True;raise
                row.value,row.returned=raw,True  # Strong original before fileno/other raw call.
                try: self._adopt(row,raw,raw.fileno())
                except BaseException:
                    row.unknown=True;raise
                if not stat.S_ISSOCK(row.metadata[2]): _fail('native_send_tcp_invalid')
                self._send_basis_gate_v75(basis,end)
                self._check();raw.set_inheritable(False);self._check()
                self._check();raw.setsockopt(socket.SOL_SOCKET,25,basis.origin.name.encode('ascii')+b'\0');self._check()
                self._check();raw.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',0,0));self._check()
                self._check();raw.setblocking(False);self._check()
                self._check();row._tcp_bind_called_v75=True
                raw.bind((ip.ipv4_text(basis.binding.server_ip),0));self._check()
                self._send_tcp_current_v75(row,basis);self._send_udp_current_v75()
                self._send_basis_gate_v75(basis,end);self._check()
                listener=GoSendListener(self,basis,row,end);self._send_listener_original=listener
                self._check();self._send_listener_returned=True
                return listener
            except BaseException as error:
                if row._tcp_factory_called_v75 is False and row.returned is False:
                    row.attempted=row.closed=True  # Exact pre-factory refusal, no descriptor existed.
                row.failure=error  # Known late bind/options do not erase FD ownership.
                raise
    def _send_inventory_v75(self):
        rows=self._send_tcp_rows_v75
        if self.rows is not self._rows_original or type(self._history) is not tuple or \
                len(self.rows)!=len(self._history) or any(a is not b for a,b in zip(self.rows,self._history)):
            _fail('native_send_inventory_changed')
        actual=tuple(r for r in self._history if type(r) is _Resource and r.kind=='tcp')
        if type(rows) is not tuple or rows is not self._send_tcp_history_v75 or len(rows)>1 or \
                len(actual)!=len(rows) or any(a is not b for a,b in zip(actual,rows)) or \
                any(type(r) is not _Resource or r.native is not self or r.kind!='tcp' or r.bound for r in rows):
            _fail('native_send_inventory_changed')
        return rows
    def _send_closed_v75(self):
        rows=self._send_inventory_v75()
        if any(r.attempted is not True or r.closed is not True or r.unknown is not False for r in rows):
            _fail('native_send_inventory_pending')
        return tuple((r.attempted,r.closed and not r.unknown) for r in rows)
    def close_send_inventory(self,cleanupUntil):
        with self.mutex:
            rows=self._send_inventory_v75()
            if not rows: return ()  # No factory/FD; no new IO or clock is needed.
            self._begin(cleanupUntil,True);self._send_close_attempted_v75=True
            failures=[]
            for row in rows:
                if row.closed and not row.unknown: continue
                if row.unknown or row.attempted or not row.returned:
                    failures.append(sources.GoSourceError('native_send_inventory_pending'));continue
                try: self._close(row,cleanupUntil)
                except BaseException as error: failures.append(error)
            if failures: raise failures[0]
            return self._send_closed_v75()
    def _admit_station(self,binding,server,mac_bytes,client_ip):
        self._dhcp_gate(binding,server)
        if type(mac_bytes) is not bytes or len(mac_bytes)!=6 or not any(mac_bytes) or mac_bytes[0]&1 or \
                type(client_ip) is not int or client_ip!=binding.client_ip:
            return False
        text=b':'.join(('%02x'%x).encode('ascii') for x in mac_bytes);wire=b'STA '+text
        if self._station_wire is not None: _fail('native_station_nested')
        self._station_wire=wire
        try:
            # Fresh kernel origin + authenticated actual original controller;
            # no per-packet Journal publication/read or caller readiness bool.
            rows=tuple(r for r,f,m in self._interfaces() if r.key()[:4]==binding.origin.key()[:4])
            if len(rows)!=1 or rows[0].key()!=binding.origin.key(): return False
            for unused in range(2):
                self._controller();self._check();raw=self._exchange(self.command_row,wire)
                first,sep,rest=raw.partition(b'\n')
                if sep!=b'\n' or first.lower()!=text: return False
                values=_status(rest);flags=values.get(b'flags',b'')
                if not all(v in flags for v in (b'[AUTH]',b'[ASSOC]',b'[AUTHORIZED]')): return False
                self._check()
            self._dhcp_gate(binding,server);return True
        finally: self._station_wire=None

    def prepare_cleanup(self,_absolute_deadline):
        with self.mutex:
            self._send_closed_v75()
            self._begin(_absolute_deadline,True);self._durable('ip_restored',True)
            if self._group_submit_called and not self._group_remove_called and self.command_row is not None:
                self._group_remove_called=True
                try:
                    self._controller()
                    wire=b'P2P_GROUP_REMOVE '+self.owned.name.encode('ascii')
                    reply=self._exchange(self.command_row,wire)
                    if reply not in (b'OK\n',b'FAIL\n'): _fail('native_group_remove_unknown')
                except BaseException as error:
                    # Observation failure is retained. Same original process
                    # TERM/absence + exact original netdev deletion/readback are
                    # still needed; FAIL/timeout is not unmutated restoration.
                    self.failure=error
            errors=[]
            for row in (self.command_row,self.event_row,self.create_row):
                if row is not None and not row.closed:
                    try: self._close(row,_absolute_deadline)
                    except BaseException as error: errors.append(error)
            if errors: raise errors[0]
            return None
    def stop_child(self,ticket,_absolute_deadline):
        """Actual original direct-child TERM/wait/Proc absence, never killall/KILL."""
        with self.mutex:
            self._begin(_absolute_deadline,True);self._durable('ip_restored',True)
            launch=self.deployment.modules['mta_go_process_owner'];launcher=self.owner.launcher
            if type(launcher) is not launch.GoDirectChildOwner: _fail('native_child_source_changed')
            launch.GoDirectChildOwner._exact(launcher,ticket)
            if ticket.fork_negative or not ticket.fork_requested:
                launcher.close_inventory(ticket,_absolute_deadline=_absolute_deadline)
                return None
            if ticket.unknown or ticket.preexec is None or ticket.pid is None: _fail('native_child_stop_pending')
            if not ticket.waited:
                if ticket not in self._termination:
                    observed=None
                    try: observed=self._proc(ticket.pid,ticket.postexec or ticket.preexec)
                    except BaseException as error: self.failure=error
                    if observed is not None and observed.actor.live():
                        expected=ticket.postexec or ticket.preexec
                        if (observed.actor.pid,observed.actor.start)!=(expected.pid,expected.start): _fail('native_child_stop_changed')
                        row={'ticket':ticket,'actor':observed.actor,'requested':True,'returned':None,'unknown':True}
                        self._termination[ticket]=row
                        returned=self.io.kill_term(ticket.pid);row['returned']=returned;row['unknown']=returned is not None
                        self._check()
                        if row['unknown']: _fail('native_child_term_unknown')
                if launcher.wait_reap(ticket,timeout=min(2.0,self._scope-self._check()),_absolute_deadline=self._scope) is not True:
                    _fail('native_child_wait_pending')
            if launcher.fresh_exit(ticket,_absolute_deadline=self._scope) is not True: _fail('native_child_absence_pending')
            launcher.close_inventory(ticket,_absolute_deadline=self._scope)
            if any(not row.closed or row.unknown for row in ticket.fds): _fail('native_child_fd_pending')
            return None
    def stop_child_only(self,ticket):
        """Original registered direct child only, WITHOUT uncertain RF authority.

        No scalar deadline input, GO canonical, GROUP_REMOVE, netlink operation,
        marker clear or logical restore. Unknown/unverified original children
        are not signalled by PID. Each independently known local FD may still
        be closed by the original launcher once under the SAME cleanup period.
        """
        with self.mutex:
            self._owner();module=self.deployment.modules['mta_go_bootstrap']
            end=module.GoBootstrap._cleanup_period_current(self.owner,self)
            self._scope,self._scope_cleanup=end,True;self._now(end)
            self.entry.accounting._io_deadline=end
            launch=self.deployment.modules['mta_go_process_owner'];launcher=self.owner.launcher
            if type(launcher) is not launch.GoDirectChildOwner or launcher is not self.store._launcher_original:
                _fail('native_child_source_changed')
            launch.GoDirectChildOwner._exact(launcher,ticket)
            if ticket in self._stop_only_calls: _fail('native_child_stop_only_already_attempted')
            self._stop_only_calls.add(ticket);errors=[];original_error=None
            try:
                if ticket is not self.owner.controller and ticket is not self.owner.watchdog: _fail('native_child_source_changed')
                if ticket.fork_negative or not ticket.fork_requested: return None
                if ticket.unknown or ticket.preexec is None or not ticket.fork_returned or \
                        type(ticket.preexec) is not core.Actor or type(ticket.parent) is not core.Actor or \
                        ticket.parent.key()!=self.entry.actor.key() or ticket.boot!=self.entry.boot or \
                        not _int(ticket.pid,1,0x7fffffff) or ticket.pid!=ticket.preexec.pid or \
                        not ticket.preexec.live() or len(ticket.preexec.tasks)!=1 or \
                        (ticket.preexec.exe,ticket.preexec.argv_sha)!=(ticket.parent.exe,ticket.parent.argv_sha):
                    _fail('native_child_stop_only_unverified')
                proc=self.deployment.modules['mta_client_proc']
                if not any(type(g.observation) is proc.ProcObservation and g.observation.actor is ticket.preexec and
                        g.observation.boot==ticket.boot and g.observation.kind=='live_actor' and
                        g.observation.same_boot is True and g.observation.passes==2 and
                        g.observation.resource_pending is False and self.entry.reader.owns_generation(g)
                        for g in self.entry.reader._history): _fail('native_child_stop_only_unverified')
                if not ticket.waited:
                    # Current two-pass original Proc producer, no expected old
                    # preexec key which could turn a valid exec transition into
                    # a fabricated match or erase a failed observation.
                    observed=self._proc(ticket.pid)
                    self._stop_only_observations.append((ticket,observed))
                    actor=observed.actor
                    allowed=((ticket.preexec.exe,ticket.preexec.argv_sha),(ticket.spec.exe,ticket.spec.argv_sha))
                    if (actor.pid,actor.start)!=(ticket.preexec.pid,ticket.preexec.start) or \
                            (actor.exe,actor.argv_sha) not in allowed or len(actor.tasks)!=1 or \
                            ticket.postexec is not None and actor.key()!=ticket.postexec.key():
                        _fail('native_child_stop_only_changed')
                    if actor.live() and ticket not in self._termination:
                        self._check()
                        row={'ticket':ticket,'actor':actor,'requested':True,'returned':None,'unknown':True}
                        self._termination[ticket]=row  # BEFORE same original once TERM.
                        try:
                            result=self.io.kill_term(ticket.pid);row['returned']=result;row['unknown']=result is not None
                            self._check()
                            if row['unknown']: _fail('native_child_term_unknown')
                        except BaseException as error:
                            row['error']=error;errors.append(error)
                    try:
                        if launcher.wait_reap(ticket,timeout=min(2.0,end-self._check()),_absolute_deadline=end) is not True:
                            _fail('native_child_wait_pending')
                    except BaseException as error: errors.append(error)
                if ticket.waited:
                    try:
                        if launcher.fresh_exit(ticket,_absolute_deadline=end) is not True: _fail('native_child_absence_pending')
                    except BaseException as error: errors.append(error)
                if errors: raise errors[0]
            except BaseException as error:
                original_error=error
                self._stop_only_failures.append((ticket,error));raise
            finally:
                # Original FD creator/metadata/once-close path only. Do not skip
                # this local attempt because current Proc or publication failed.
                try:
                    if launcher.close_inventory(ticket,_absolute_deadline=end) is not True:
                        _fail('native_child_fd_pending')
                except BaseException as error:
                    self._stop_only_failures.append((ticket,error))
                    if original_error is None: raise
            return None
    def _close_server_endpoint(self):
        if self._server_absent: return
        controller=self.owner.controller
        if controller is None or not controller.fork_requested or controller.fork_negative:
            if self._server_original is not None: _fail('native_ctrl_server_pending')
            self._server_absent=True;return
        if not controller.waited or controller.exit_verified is not True: _fail('native_ctrl_server_pending')
        peer=self.deployment.manifest.ctrl+'/'+self.owned.name
        original=self._server_original
        if original is not None and (original[0]!=peer or original[2] is not controller.postexec): _fail('native_ctrl_server_changed')
        try: before=self._path_metadata(peer)
        except OSError as error:
            if type(error.errno) is not int or error.errno!=errno.ENOENT: raise
            self._server_absent=True;return
        # A controller which never yielded an authenticated server inode can
        # prove absence after reap, but cannot adopt/unlink a pathname by name.
        if original is None or before!=original[1] or self._server_unlink_called: _fail('native_ctrl_server_changed')
        self._server_unlink_called=True
        if self.io.unlink(peer) is not None: _fail('native_ctrl_server_pending')
        try: self.io.stat(peer)
        except OSError as error: self._server_absent=type(error.errno) is int and error.errno==errno.ENOENT
        if not self._server_absent: _fail('native_ctrl_server_pending')
        self._check()
    def delete_interface(self,_absolute_deadline):
        with self.mutex:
            self._send_closed_v75()
            self._begin(_absolute_deadline,True);self._durable('ip_restored',True)
            if self._delete_called: _fail('native_delete_already_attempted')
            controller=self.owner.controller
            if controller is not None and controller.fork_requested and not controller.fork_negative and \
                    (not controller.waited or controller.exit_verified is not True):
                _fail('native_controller_still_live')
            self._close_server_endpoint()
            if not self._create_called:
                # Durable interface-intent without submission still uses real
                # baseline/readback and inventory, not old rfFalse bypass.
                if self._stable_snapshot().key()!=self.baseline.snapshot.key(): _fail('native_baseline_changed')
                return None
            if self.owned is None or self.create_request is None: _fail('native_create_pending')
            current=self._stable_snapshot()
            match=tuple(r for r in current.interfaces if r.key()[:4]==self.owned.key()[:4])
            if len(match)!=1 or match[0].iftype not in (8,9) or self._outside_key(current,match[0])!=self.baseline.snapshot.key():
                _fail('native_delete_origin_pending')
            row=self._socket(16)
            try:
                family=self._family(row);self._delete_called=True
                self._request(row,family,8,_attr(153,struct.pack('<Q',self.owned.wdev)),4)
            finally: self._close(row)
            first=self._stable_snapshot()
            if first.key()!=self.baseline.snapshot.key(): _fail('native_delete_readback_pending')
            return None
    def observe_restore(self,_absolute_deadline):
        with self.mutex:
            self._begin(_absolute_deadline,True);self._durable('ip_restored',True)
            if self.restored is not None: _fail('native_restore_already_issued')
            snapshot=self._stable_snapshot()
            if self.baseline is None or snapshot.key()!=self.baseline.snapshot.key(): _fail('native_baseline_not_restored')
            if any(not a or not c for a,c in self.closed_facts()): _fail('native_resource_pending')
            value=GoNativeRestoreObservation(self,snapshot);self.restored=value;self.observations.append(value);return value
    def restore_current(self,original,_absolute_deadline):
        self._begin(_absolute_deadline,True)
        if type(original) is not GoNativeRestoreObservation or original is not self.restored or original not in self.observations:
            _fail('native_restore_not_original')
        if self._stable_snapshot().key()!=original.snapshot.key() or any(not a or not c for a,c in self.closed_facts()):
            _fail('native_restore_pending')
        return original
    def close_known_inventory(self,_absolute_deadline):
        with self.mutex:
            self._owner();end=sources._time(_absolute_deadline)
            if self.store.restore_until is not None and end>self.store.restore_until: _fail('native_cleanup_scope_invalid')
            failures=[]
            for row in self._history:
                needs_raw=row.returned and not row.closed and not row.attempted and not row.unknown
                needs_endpoint=row.returned and row.closed and row.bound and not row.endpoint_closed and not row.unlink_called and not row.unknown
                if needs_raw or needs_endpoint:
                    try: self._close(row,end)
                    except BaseException as error: failures.append(error)
            if failures: raise failures[0]
            return self.closed_facts()
    def closed_facts(self):
        if self.rows is not self._rows_original or tuple(self.rows)!=self._history: return ((True,False),)
        facts=tuple((r.attempted,r.closed and not r.unknown and r.endpoint_closed) for r in self._history)
        if self._ancillary_unknown: facts+=((True,False),)
        if self.owner.controller is not None: facts+=((self._server_unlink_called or self._server_absent,self._server_absent),)
        return facts
    def status(self):
        return {'interface_echo_observed':self._create_echo_original is not None,
            'interface_echo_ack':self.owned is not None and self.create_request is not None,
            'group_observed':self.group is not None,'native_closed':all(a and c for a,c in self.closed_facts()),
            'go_ready':False,'ip_ready':False,'dhcp_ready':False,'send_ready':False,
            'device_tested':False,'phone_tested':False}
