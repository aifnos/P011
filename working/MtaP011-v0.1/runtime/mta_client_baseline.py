"""Fixed read-only CLIENT baseline collector, not RF/recovery admission.

Construction is pure. The internal manifest contains the three exact stock
pins and the actual fixed wpa_cli pin; no missing pin is invented. Raw records
and exact resource tickets are private. Only explicit collect performs I/O.
"""
import errno
import hashlib
import math
import os
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import time

import mta_ip as ip
import mta_client_proc as proc
import mta_client_caps_transport as genl
import mta_p2p_client_init as core

CLI = '/usr/sbin/wpa_cli'
ARGV = (CLI, '-i', 'wlan0', 'status')
TRACKED = ('Z03', 'control_engine', 'weston', 'connmand', 'wpa_supplicant', 'bluetoothd')
MAX_FILE, MAX_PROC, MAX_ROWS = 67108864, 4096, 4096
MAX_RAW, MAX_PACKETS, MAX_TICKETS = 8388608, 1024, 8320
_NL, _GENL = struct.Struct('<IHHII'), struct.Struct('<BBH')
# Linux asm-generic/fcntl.h; HOST FakeIO must not depend on Windows constants.
_READ_FLAGS = 0x20000 | 0x80000  # O_RDONLY | O_NOFOLLOW | O_CLOEXEC
_EXEC_READ_FLAGS = 0x80000  # Exact /proc/<fresh pid>/exe magiclink only.
_CODES = frozenset(('invalid_manifest', 'invalid_budget', 'invalid_clock', 'deadline',
    'already_attempted', 'unsupported_platform', 'file_identity', 'file_budget',
    'file_pin', 'resource_unknown', 'close_unknown', 'actor_unknown', 'actor_changed',
    'proc_budget', 'kernel_peer', 'netlink_budget', 'netlink_format', 'interface_format',
    'station_missing', 'ipv6_format', 'status_format', 'status_failed', 'snapshot_changed',
    'io_error', 'interrupted'))


class BaselineError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise BaselineError(code) from None


def _integer(value, minimum=0, maximum=0x7fffffff):
    return type(value) is int and minimum <= value <= maximum


def _metadata(value):
    keys = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
            'st_size', 'st_mtime_ns', 'st_ctime_ns')
    result = tuple(getattr(value, k, None) for k in keys)
    if any(not _integer(v, 0, (1 << 64) - 1) for v in result): _fail('file_identity')
    return result


class _LinuxIo(object):
    def validate(self):
        if sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or \
                getattr(os, 'O_NOFOLLOW', None) != 0x20000 or getattr(os, 'O_CLOEXEC', None) != 0x80000:
            _fail('unsupported_platform')
    def open(self, path, flags): return os.open(path, flags)
    def read(self, fd, count): return os.read(fd, count)
    def fstat(self, fd): return os.fstat(fd)
    def stat(self, path): return os.stat(path, follow_symlinks=False)
    def close(self, fd): return os.close(fd)
    def listdir(self, path): return os.listdir(path)
    def socket(self, protocol): return socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, protocol)
    def readable(self, descriptors, timeout): return select.select(descriptors, (), (), timeout)[0]
    def spawn(self, executable_fd):
        return subprocess.Popen(ARGV, executable='/proc/self/fd/' + str(executable_fd),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=(executable_fd,), env={'LC_ALL': 'C'}, shell=False)


class BaselineCollector(object):
    """One synchronous operation owned by a single-thread F; no default manifest.

    manifest: exact tuple core.STOCK_PINS plus (CLI, actual_sha256).
    _io/_reader/_clock are trusted internal HOST seams, never UI inputs.
    Two stable observations are not atomicity, Executor or restoration proof.
    """
    def __init__(self, manifest, timeout=5.0, _io=None, _reader=None, _clock=None):
        if type(manifest) is not tuple or len(manifest) != 4 or any(
                type(row) is not tuple or len(row) != 2 or type(row[0]) is not str or
                type(row[1]) is not str or re.fullmatch('[0-9a-f]{64}', row[1]) is None
                for row in manifest) or len(set(row[0] for row in manifest)) != 4 or \
                tuple(sorted(row for row in manifest if row[0] != CLI)) != tuple(sorted(core.STOCK_PINS)) or \
                sum(row[0] == CLI for row in manifest) != 1:
            _fail('invalid_manifest')
        if type(timeout) not in (int, float) or not 0.1 <= timeout <= 10 or \
                not math.isfinite(float(timeout)) or (_clock is not None and not callable(_clock)):
            _fail('invalid_budget')
        self._manifest, self._timeout = manifest, float(timeout)
        self._io, self._clock = _io if _io is not None else _LinuxIo(), _clock or time.monotonic
        self._reader = _reader if _reader is not None else proc.ProcReader(timeout=timeout)
        self._tickets, self._raw, self._observations, self._rounds = [], [], [], []
        self._binaries, self._incoming = {}, None
        self._attempted = self._ended = self._pending = self._success = False
        self._deadline = self._last_clock = None
        self._sequence, self._raw_bytes, self._packets = 0, 0, 0
        self._reason, self._snapshot = 'not_started', None

    def __repr__(self): return '<CLIENT private baseline collector>'

    def _now(self):
        value = self._clock()
        if type(value) not in (int, float) or not 0 <= value < 1e12 or not math.isfinite(float(value)):
            _fail('invalid_clock')
        value = float(value)
        if self._last_clock is not None and value < self._last_clock: _fail('invalid_clock')
        self._last_clock = value
        if self._deadline is not None and value >= self._deadline: _fail('deadline')
        return value

    def _ticket(self, kind):
        self._now()
        if len(self._tickets) >= MAX_TICKETS: _fail('resource_unknown')
        row = {'kind': kind, 'value': None, 'fd': None, 'unknown': True,
               'attempted': False, 'closed': False, 'kill_attempted': False,
               'waited': False, 'pipes': (), 'pipe_refs_valid': True}
        self._tickets.append(row)  # before creation, including unknown return
        return row

    def _adopt_fd(self, row, descriptor):
        row['fd'] = descriptor
        if not _integer(descriptor) or any(other is not row and not other['closed'] and
                other['fd'] == descriptor for other in self._tickets):
            self._pending = True; _fail('resource_unknown')
        row['unknown'] = False

    def _open(self, path, flags=_READ_FLAGS):
        row = self._ticket('fd')
        try: descriptor = self._io.open(path, flags)
        except OSError:
            row['unknown'], row['closed'] = False, True
            raise
        except BaseException:
            self._pending = True; raise
        self._adopt_fd(row, descriptor)
        return row

    def _read_file(self, path, limit, retain=False, binary=False):
        row, data = self._open(path), b''
        try:
            parents = self._binary_parents(path) if binary else None
            before = _metadata(self._io.fstat(row['fd']))
            if not stat.S_ISREG(before[2]) or before[5] != 1 or \
                    binary and (before[3] != 0 or before[2] & 0o022 or before[6] > limit):
                _fail('file_identity')
            if _metadata(self._io.stat(path)) != before: _fail('file_identity')
            while True:
                self._now()
                count = min(65536, limit + 1 - len(data))
                chunk = self._io.read(row['fd'], count)
                if type(chunk) is not bytes or len(chunk) > count: _fail('file_budget')
                data += chunk
                if len(data) > limit: _fail('file_budget')
                if not chunk: break
            if _metadata(self._io.fstat(row['fd'])) != before or _metadata(self._io.stat(path)) != before:
                _fail('file_identity')
            if binary and self._binary_parents(path) != parents: _fail('file_identity')
            self._raw.append(('file', path, data if not binary else hashlib.sha256(data).hexdigest(), before))
            return data, row, before
        finally:
            if not retain: self._close_row(row)

    def _binary_parents(self, path):
        if path not in tuple(p for p, unused in self._manifest): _fail('file_identity')
        result, current = [], ''
        for part in ('',) + tuple(path.split('/')[1:-1]):
            current = '/' if not current else current.rstrip('/') + '/' + part
            meta = _metadata(self._io.stat(current))
            if not stat.S_ISDIR(meta[2]) or meta[3] != 0 or meta[2] & 0o022: _fail('file_identity')
            result.append(meta[:6])
        return tuple(result)

    def _proc(self, pid=None, expected=None, single=False):
        self._now()
        try: value = self._reader.read_self() if pid is None else self._reader.read_actor(pid, expected)
        except BaseException:
            self._pending = True; raise
        self._observations.append(value)
        self._now()
        if type(value) is not proc.ProcObservation or value.resource_pending is not False or \
                not _integer(value.file_count, 1) or type(value.closed_count) is not int or value.file_count != value.closed_count:
            self._pending = True
            _fail('actor_unknown')
        if value.kind != 'live_actor' or type(value.actor) is not core.Actor or not value.actor.live() or \
                value.same_boot is not True or type(value.passes) is not int or value.passes != 2 or \
                type(value.task_count) is not int or value.task_count != len(value.actor.tasks) or \
                single and value.task_count != 1: _fail('actor_unknown')
        return value

    def _actors(self):
        names = self._io.listdir('/proc')
        if type(names) not in (list, tuple) or len(names) > MAX_PROC or \
                any(type(name) is not str for name in names): _fail('proc_budget')
        actors, found = [], {}
        for name in sorted(names):
            self._now()
            if not re.fullmatch('[1-9][0-9]{0,9}', name): continue
            number = int(name)
            if not _integer(number, 1): _fail('proc_budget')
            comm = self._read_file('/proc/' + name + '/comm', 128)[0]
            try: comm = comm.strip().decode('ascii')
            except UnicodeError: _fail('actor_unknown')
            if comm not in TRACKED: continue
            observed = self._proc(number)
            actor = observed.actor
            if actor.exe.rsplit('/', 1)[-1] != comm: _fail('actor_unknown')
            if comm in ('Z03', 'control_engine') and actor.exe != '/usr/bin/' + comm:
                _fail('actor_unknown')
            if comm in ('Z03', 'control_engine'): self._actor_image(actor)
            actors.append(actor); found[comm] = found.get(comm, 0) + 1
        if any(found.get(name) != 1 for name in ('Z03', 'control_engine', 'weston')) or len(actors) > 32:
            _fail('actor_unknown')
        return tuple(actors)

    def _actor_image(self, actor):
        # A pinned pathname and cmdline SHA do not authenticate a live image.
        # Follow only this actual ProcReader-identified process's exe magiclink.
        if actor.exe not in ('/usr/bin/Z03', '/usr/bin/control_engine') or actor.exe not in self._binaries:
            _fail('actor_unknown')
        expected = dict(self._manifest)[actor.exe]
        old_meta = self._binaries[actor.exe][1]
        path = '/proc/' + str(actor.pid) + '/exe'
        row, data = self._open(path, _EXEC_READ_FLAGS), b''
        try:
            before = _metadata(self._io.fstat(row['fd']))
            if before != old_meta: _fail('file_identity')
            while True:
                self._now(); count = min(65536, MAX_FILE + 1 - len(data))
                chunk = self._io.read(row['fd'], count)
                if type(chunk) is not bytes or len(chunk) > count: _fail('file_budget')
                data += chunk
                if len(data) > MAX_FILE: _fail('file_budget')
                if not chunk: break
            digest = hashlib.sha256(data).hexdigest()
            self._raw.append(('actor_image', path, digest, before))
            if digest != expected: _fail('file_pin')
            if _metadata(self._io.fstat(row['fd'])) != before: _fail('file_identity')
            fresh = self._proc(actor.pid, actor)
            if fresh.actor.key() != actor.key() or fresh.actor.tasks != actor.tasks: _fail('actor_changed')
        finally: self._close_row(row)

    def _socket(self, protocol):
        row = self._ticket('socket')
        try: value = self._io.socket(protocol)
        except BaseException:
            self._pending = True; raise
        row['value'] = value  # immediately retain even malformed objects
        methods = ('fileno', 'close', 'bind', 'getsockname', 'set_inheritable',
                   'get_inheritable', 'settimeout', 'gettimeout', 'sendto', 'recvmsg')
        if not all(callable(getattr(value, method, None)) for method in methods):
            self._pending = True; _fail('resource_unknown')
        self._adopt_fd(row, value.fileno())
        value.set_inheritable(False)
        if value.get_inheritable() is not False: _fail('resource_unknown')
        value.bind((0, 0)); endpoint = value.getsockname()
        if type(endpoint) is not tuple or len(endpoint) != 2 or not _integer(endpoint[0], 1, 0xffffffff) or \
                type(endpoint[1]) is not int or endpoint[1] != 0: _fail('resource_unknown')
        row['port'] = endpoint[0]
        return row

    def _budget_socket(self, row):
        remaining = self._deadline - self._now()
        value = row['value']; value.settimeout(remaining)
        ns = math.ceil(remaining * 1e9); seconds, fraction = divmod(ns, 1000000000)
        expected = seconds + fraction * 1e-9
        actual = value.gettimeout()
        if type(actual) is not float or not math.isfinite(actual) or actual != expected or actual <= 0:
            _fail('resource_unknown')

    def _send(self, row, request):
        self._budget_socket(row)
        self._raw.append(('request', request))
        sent = row['value'].sendto(request, (0, 0))
        if type(sent) is not int or sent != len(request): _fail('netlink_format')

    def _receive(self, row):
        self._budget_socket(row)
        packet, ancillary, flags, peer = row['value'].recvmsg(ip.MAX_DATAGRAM_BYTES + 1, 256, 0)
        self._incoming = (packet, ancillary, flags, peer)
        self._raw.append(('netlink', packet, ancillary, flags, peer))
        if type(packet) is not bytes: _fail('netlink_format')
        self._raw_bytes += len(packet); self._packets += 1
        if self._raw_bytes > MAX_RAW or self._packets > MAX_PACKETS or not 16 <= len(packet) <= ip.MAX_DATAGRAM_BYTES:
            _fail('netlink_budget')
        if type(flags) is not int or flags != 0 or type(ancillary) not in (tuple, list) or ancillary:
            _fail('netlink_format')
        if type(peer) is not tuple or len(peer) != 2 or any(type(v) is not int for v in peer) or peer != (0, 0):
            _fail('kernel_peer')
        self._now()
        return packet

    def _next(self):
        self._sequence += 1
        return self._sequence

    def _ipv4(self, row):
        dumps = []
        for kind in ('addresses', 'routes', 'rules'):
            collector = ip.DumpCollector(kind, self._next(), row['port'])
            self._send(row, collector.request)
            while not collector.complete: collector.feed(self._receive(row))
            dumps.append(collector)
        return ip.snapshot_from_dumps(*dumps)

    def _generic(self, row, family, command, dump=False):
        seq = self._next(); attrs = genl._attr(2, b'nl80211\0') if family == 16 else b''
        request = _NL.pack(20 + len(attrs), family, 1 | (0x300 if dump else 0), seq, row['port']) + _GENL.pack(command, 1 if dump else 2, 0) + attrs
        self._send(row, request); rows, done = [], False
        while not done:
            packet = self._receive(row); at = 0
            while at < len(packet):
                if done or len(packet) - at < 16: _fail('netlink_format')
                size, kind, bits, q, port = _NL.unpack_from(packet, at); step = (size + 3) & ~3
                if size < 16 or step > len(packet) - at or any(packet[at + size:at + step]) or \
                        q != seq or port != row['port'] or bits != (2 if dump else 0): _fail('netlink_format')
                body = packet[at + 16:at + size]; at += step
                if kind == 3:
                    if not dump or body != b'\0' * 4: _fail('netlink_format')
                    done = True; continue
                if kind != family or len(body) < 4: _fail('netlink_format')
                cmd, version, reserved = _GENL.unpack_from(body)
                if cmd != (7 if dump else 1) or version != (1 if dump else 2) or reserved:
                    _fail('netlink_format')
                rows.append(body[4:])
                if len(rows) > 32: _fail('netlink_budget')
                if not dump: done = True
        if not dump and len(rows) != 1: _fail('netlink_format')
        return tuple(rows)

    def _interfaces(self, row, family):
        result = []
        for body in self._generic(row, family, 5, True):
            fields = {}
            for kind, flags, value, unused_raw in genl._attrs(body):
                if kind in fields: _fail('interface_format')
                fields[kind] = (flags, value)
            if not {1, 3, 4, 5, 153}.issubset(fields): _fail('interface_format')
            numbers = []
            for kind, width in ((1, 4), (153, 8), (3, 4), (5, 4)):
                flags, value = fields[kind]
                genl._scalar(flags, value, width)
                numbers.append(struct.unpack('<Q' if width == 8 else '<I', value)[0])
            flags, value = fields[4]
            if flags or not 2 <= len(value) <= 16 or value[-1:] != b'\0' or b'\0' in value[:-1]:
                _fail('interface_format')
            try: name = value[:-1].decode('ascii')
            except UnicodeError: _fail('interface_format')
            result.append(core.Origin(numbers[0], numbers[1], numbers[2], name, numbers[3]))
        if len(set(r.ifindex for r in result)) != len(result) or len(set(r.wdev for r in result)) != len(result) or \
                len(set(r.name for r in result)) != len(result): _fail('interface_format')
        return tuple(result)

    def _ipv6(self, path, widths):
        data = self._read_file(path, 1048576)[0]
        try: rows = tuple(tuple(line.split()) for line in data.decode('ascii').splitlines())
        except UnicodeError: _fail('ipv6_format')
        if len(rows) > MAX_ROWS or len(set(rows)) != len(rows): _fail('ipv6_format')
        for row in rows:
            if len(row) != len(widths) + 1 or any(re.fullmatch('[0-9a-f]{' + str(width) + '}', row[i]) is None
                    for i, width in enumerate(widths)) or re.fullmatch('[A-Za-z0-9_.-]{1,15}', row[-1]) is None:
                _fail('ipv6_format')
        return rows

    def _status(self, executable):
        row = self._ticket('process')
        try: value = self._io.spawn(executable['fd'])
        except BaseException:
            self._pending = True; raise
        row['value'] = value
        if not all(callable(getattr(value, n, None)) for n in ('poll', 'wait', 'kill')):
            self._pending = True; _fail('resource_unknown')
        pipes = []
        for name in ('stdout', 'stderr'):
            pipe = getattr(value, name, None)
            ticket = self._ticket('pipe'); ticket['value'], ticket['parent'], ticket['name'] = pipe, row, name
            pipes.append(ticket); row['pipes'] = tuple(pipes)
            if not all(callable(getattr(pipe, n, None)) for n in ('fileno', 'close')):
                self._pending = True; _fail('resource_unknown')
            self._adopt_fd(ticket, pipe.fileno())
        row['unknown'] = False
        chunks, active = {pipes[0]['fd']: b'', pipes[1]['fd']: b''}, list(pipes)
        row['chunks'] = chunks  # partial/error output remains private, bounded
        try:
            while active:
                ready = self._io.readable([r['fd'] for r in active], self._deadline - self._now())
                self._now()
                if type(ready) not in (tuple, list) or len(set(ready)) != len(ready) or any(
                        type(fd) is not int or fd not in [r['fd'] for r in active] for fd in ready): _fail('resource_unknown')
                for fd in ready:
                    limit = 16384 if fd == pipes[0]['fd'] else 4096
                    chunk = self._io.read(fd, min(4096, limit + 1 - len(chunks[fd])))
                    if type(chunk) is not bytes or len(chunk) > min(4096, limit + 1 - len(chunks[fd])):
                        _fail('file_budget')
                    chunks[fd] += chunk
                    if len(chunks[fd]) > limit: _fail('file_budget')
                    if not chunk: active = [r for r in active if r['fd'] != fd]
            code = value.wait(timeout=self._deadline - self._now())
            row['waited'] = type(code) is int and type(value.poll()) is int and value.poll() == code
            if not row['waited'] or code != 0: _fail('status_failed')
            raw = chunks[pipes[0]['fd']]
            self._raw.append(('status', raw, chunks[pipes[1]['fd']]))
            fields = {}
            for line in raw.splitlines():
                if b'=' not in line: _fail('status_format')
                key, data = line.split(b'=', 1)
                if key in fields or re.fullmatch(b'[a-zA-Z0-9_]{1,64}', key) is None or b'\0' in data:
                    _fail('status_format')
                fields[key] = data
            if fields.get(b'wpa_state') != b'COMPLETED' or re.fullmatch(b'[0-9]{4}', fields.get(b'freq', b'')) is None:
                _fail('status_failed')
            frequency = int(fields[b'freq'])
            if frequency not in tuple(range(2412, 2473, 5)) + (2484,): _fail('status_failed')
            return hashlib.sha256(raw).hexdigest(), frequency
        finally: self._close_row(row)

    def _close_row(self, row):
        if row['attempted'] or row['closed']: return
        if row['unknown']:
            self._pending = True; return
        row['attempted'] = True
        try:
            if row['kind'] == 'process':
                value = row['value']; code = value.poll()
                if code is None:
                    row['kill_attempted'] = True; value.kill()
                code = value.wait(timeout=0.5)
                row['waited'] = type(code) is int and type(value.poll()) is int and value.poll() == code
                row['closed'] = row['waited']
            elif row['kind'] == 'socket':
                returned = row['value'].close()
                invalidated = type(row['value'].fileno()) is int and row['value'].fileno() == -1
                try: self._io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and invalidated and type(error.errno) is int and error.errno == errno.EBADF
            elif row['kind'] == 'pipe':
                if getattr(row['parent']['value'], row['name'], None) is not row['value']:
                    row['parent']['pipe_refs_valid'] = False; _fail('resource_unknown')
                returned = row['value'].close()
                if returned is not None or getattr(row['value'], 'closed', None) is not True: _fail('close_unknown')
                try: self._io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = type(error.errno) is int and error.errno == errno.EBADF
            else:
                returned = self._io.close(row['fd'])
                try: self._io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException: self._pending = True
        finally:
            if row['kind'] == 'process':
                for pipe in row['pipes']: self._close_row(pipe)
                row['closed'] = row['closed'] and row['pipe_refs_valid'] and len(row['pipes']) == 2 and all(p['closed'] and not p['unknown'] for p in row['pipes'])
            if not row['closed']: self._pending = True

    def close(self):
        self._ended = True
        # Process first: remaining known originals must still be tried if it fails.
        for row in sorted(self._tickets, key=lambda r: r['kind'] != 'process'):
            self._close_row(row)
        return not self._pending and all(r['closed'] and not r['unknown'] for r in self._tickets)

    def status(self):
        return {'attempted': self._attempted, 'read_success': self._success,
            'closed': self._ended, 'resource_pending': self._pending,
            'resource_count': len(self._tickets), 'closed_count': sum(r['closed'] for r in self._tickets),
            'unknown_count': sum(r['unknown'] for r in self._tickets), 'round_count': len(self._rounds),
            'datagram_count': self._packets, 'observer_count': len(self._observations),
            'reason': self._reason, 'mutation_admission': False, 'restoration_verified': False}

    def collect(self, deadline):
        if self._attempted or self._ended or self._pending: _fail('already_attempted')
        if type(deadline) not in (int, float) or not 0 <= deadline < 1e12 or not math.isfinite(float(deadline)):
            _fail('invalid_budget')
        self._attempted = True; result = None; error = None
        try:
            self._deadline = min(float(deadline), self._now() + self._timeout)
            self._now(); self._io.validate()
            before = self._proc(single=True); pins, executable = [], None
            for path, expected in self._manifest:
                data, ticket, metadata = self._read_file(path, MAX_FILE, retain=path == CLI, binary=True)
                if hashlib.sha256(data).hexdigest() != expected: _fail('file_pin')
                if path == CLI:
                    if not metadata[2] & 0o111: _fail('file_identity')
                    executable = ticket
                else: pins.append((path, expected))
                self._binaries[path] = (ticket, metadata, self._binary_parents(path))
            route, wireless = self._socket(0), self._socket(16)
            family = genl._family(self._generic(wireless, 16, 3)[0])
            for unused in (1, 2):
                current = self._proc(single=True)
                if current.boot != before.boot or current.actor.key() != before.actor.key(): _fail('actor_changed')
                actors = self._actors(); interfaces = self._interfaces(wireless, family)
                stations = [row for row in interfaces if row.name == 'wlan0' and row.iftype == 2]
                if len(stations) != 1: _fail('station_missing')
                state, frequency = self._status(executable)
                ipv4 = self._ipv4(route)
                addresses = self._ipv6('/proc/net/if_inet6', (32, '2,8', 2, 2, 2))
                routes = self._ipv6('/proc/net/ipv6_route', (32, 2, 32, 2, 32, 8, 8, 8, 8))
                result = core.Snapshot(current.boot, tuple(pins), actors, stations[0], state,
                    frequency, interfaces, ipv4, addresses, routes, True)
                self._rounds.append(result)
                if any(v.boot != before.boot for v in self._observations): _fail('actor_changed')
            after = self._proc(single=True)
            if after.boot != before.boot or after.actor.key() != before.actor.key(): _fail('actor_changed')
            if self._rounds[0].key() != result.key(): _fail('snapshot_changed')
            if tuple(sorted((a.pid, a.tasks) for a in self._rounds[0].stock_actors)) != \
                    tuple(sorted((a.pid, a.tasks) for a in result.stock_actors)): _fail('snapshot_changed')
            # Rehash all originals after child/dumps, before accepting observation.
            for path, expected in self._manifest:
                raw, unused_ticket, meta = self._read_file(path, MAX_FILE, binary=True)
                old_ticket, old_meta, parents = self._binaries[path]
                if meta != old_meta or self._binary_parents(path) != parents: _fail('file_identity')
                if path == CLI and _metadata(self._io.fstat(old_ticket['fd'])) != old_meta:
                    _fail('file_identity')
                if hashlib.sha256(raw).hexdigest() != expected:
                    _fail('file_pin')
            self._now()
        except BaseException as caught:
            error = caught
            self._reason = caught.code if type(caught) is BaselineError else ('interrupted' if not isinstance(caught, Exception) else 'io_error')
        finally:
            if not self.close(): error = BaselineError('close_unknown'); self._reason = 'close_unknown'
        if error is not None: raise BaselineError(self._reason) from None
        self._success, self._snapshot, self._reason = True, result, 'read_closed'
        return result
