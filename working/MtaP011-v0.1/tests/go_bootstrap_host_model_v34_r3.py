"""Explicit HOST Linux/Proc/netlink/Unix assumptions for the new GO17 test.

No producer/grant/canonical/restoration object is supplied by this model.
Production parsers, original inventories, ACK/ECHO gates, CAS and child-owner
algorithms consume these modeled syscall bytes. There is no device, RF, native
fork/exec, physical Linux FD/OFD, or real Python/CLI identity evidence here.
The fixed WPA and stock-three byte inputs are real PC archived artifacts.
"""
import errno
import hashlib
import posixpath
import stat
import struct
import types

BOOT = '12345678-1234-1234-1234-123456789abc'
ROOT = '/var/volatile/tmp/p011-mta-go-session'
PYTHON = '/usr/bin/python3.5'
TOKEN = '6' * 32
UNTIL = 301.0
NL = struct.Struct('<IHHII')
GH = struct.Struct('<BBH')


def arm_python_fixture():
    """Modeled executable shape only; never a production Python identity."""
    raw = bytearray(52)
    raw[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<HHI', raw, 16, 2, 40, 1)
    struct.pack_into('<I', raw, 36, 0x05000400)
    struct.pack_into('<H', raw, 40, 52)
    return bytes(raw)


CLI = b'HOST_GO17_CLI_BYTES_NOT_A_DEVICE_EXECUTABLE\n'


def attr(kind, raw):
    size = 4 + len(raw)
    return struct.pack('<HH', size, kind) + raw + b'\0' * (-size % 4)


def u32(kind, value): return attr(kind, struct.pack('<I', value))
def nest(kind, raw): return attr(kind | 0x8000, raw)


def reply(request, kind, body, flags=0):
    size, family, sent, seq, port = NL.unpack_from(request)
    raw = NL.pack(16 + len(body), kind, flags, seq, port) + body
    return raw + b'\0' * (-len(raw) % 4)


def stat_bytes(pid, start, comm):
    cells = [b'0'] * 50
    cells[0], cells[1], cells[17], cells[19] = b'S', b'1', b'1', str(start).encode('ascii')
    return str(pid).encode('ascii') + b' (' + comm.encode('ascii') + b') ' + b' '.join(cells) + b'\n'


class Clock:
    def __init__(self): self.value = 1.0
    def __call__(self): return self.value


class Node:
    def __init__(self, inode, mode, data=b'', nlink=1, target=None, rdev=0):
        self.inode, self.mode, self.data = inode, mode, data
        self.nlink, self.target, self.rdev, self.revision = nlink, target, rdev, 7
    def metadata(self):
        return types.SimpleNamespace(st_dev=1, st_ino=self.inode, st_mode=self.mode,
            st_uid=0, st_gid=0, st_nlink=self.nlink, st_rdev=self.rdev,
            st_size=len(self.target.encode('ascii')) if self.target is not None else len(self.data),
            st_mtime_ns=self.revision, st_ctime_ns=self.revision)


class LinuxModel:
    """One shared modeled descriptor table and kernel/process truth source."""
    O_RDONLY, O_WRONLY, O_RDWR = 0, 1, 2
    O_CREAT, O_EXCL, O_NONBLOCK = 64, 128, 2048
    O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, WNOHANG = 0x4000, 0x8000, 0x80000, 1
    def __init__(self, source_rows, source_bytes, stock_bytes, fault=None):
        self.clock, self.fault = Clock(), fault
        self.nodes, self.live, self.calls, self.closed = {}, {}, [], []
        self.nextino, self.nextfd = 100, 1000
        self.modules, self.owner, self.run = None, None, ROOT + '/go-' + TOKEN
        self.children, self.stopped, self.reaped = {}, [], []
        self.netdev, self.iftypes, self.create_count, self.delete_count = None, [], 0, 0
        self.sockets, self.unlink_calls, self.absent_reads = [], [], 0
        self.fault_used, self.controller_ready_at, self.controller_inode = False, None, None
        self.endpoint_early_failures, self.deadfd_fstats = 0, {}
        self.supports_fd = {self.execve}
        self._dirs('/', '/var', '/usr', '/usr/bin', '/usr/sbin', '/dev', '/proc', '/proc/sys',
            '/proc/sys/kernel', '/proc/sys/kernel/random', '/proc/net', '/run', '/run/wpa_supplicant')
        self.add('/var/volatile', stat.S_IFDIR | 0o1777)
        self.add('/var/volatile/tmp', stat.S_IFDIR | 0o1777)
        self.add('/tmp', stat.S_IFLNK | 0o777, target='/var/tmp')
        self.add('/var/tmp', stat.S_IFLNK | 0o777, target='/var/volatile/tmp')
        for path in (ROOT, self.run, self.run + '/runtime', self.run + '/native', self.run + '/ctrl'):
            self.add(path, stat.S_IFDIR | 0o700)
        self.add('/dev/null', stat.S_IFCHR | 0o666, rdev=259)
        self.add(PYTHON, stat.S_IFREG | 0o755, arm_python_fixture(), nlink=2)
        self.add('/usr/sbin/wpa_cli', stat.S_IFREG | 0o755, CLI)
        for path, raw in stock_bytes.items(): self.add(path, stat.S_IFREG | 0o755, raw)
        for row in source_rows:
            self.add(self.run + '/runtime/' + row['module'] + '.py', stat.S_IFREG | 0o400,
                source_bytes[row['module']])
        self.add(self.run + '/native/mta-wpa-supplicant', stat.S_IFREG | 0o500,
            source_bytes['HOST_WPA'])
        self.add('/proc/sys/kernel/random/boot_id', stat.S_IFREG | 0o444, BOOT.encode('ascii') + b'\n')
        self.add('/proc/net/if_inet6', stat.S_IFREG | 0o444, b'')
        self.add('/proc/net/ipv6_route', stat.S_IFREG | 0o444, b'')
        self.add('/proc/net/unix', stat.S_IFREG | 0o444, b'')
        self.add('/run/wpa_supplicant/wlan0', stat.S_IFSOCK | 0o600)
        self.stock_socket_inode = self.nodes['/run/wpa_supplicant/wlan0'].inode
        self.install_actor(41, 41, '/usr/bin/Z03', b'/usr/bin/Z03\0')
        self.install_actor(42, 42, '/usr/bin/control_engine', b'/usr/bin/control_engine\0')
        self.install_actor(43, 43, '/usr/bin/weston', b'/usr/bin/weston\0')
        self.install_actor(44, 44, '/usr/sbin/wpa_supplicant', b'/usr/sbin/wpa_supplicant\0')
        self.add('/proc/44/fd', stat.S_IFDIR | 0o555)
        self.add('/proc/44/fd/7', stat.S_IFLNK | 0o777, target='socket:[%d]' % self.stock_socket_inode)
        expected = (b'ctrl_interface=' + (self.run + '/ctrl').encode('ascii') + b'\n'
            b'p2p_no_group_iface=1\nap_scan=2\ndevice_name=P011\ndevice_type=1-0050F204-1\n'
            b'driver_param=mta_p2p_initial=1 control_port=0\nbeacon_int=100\n')
        self.add(self.run + '/go.conf', stat.S_IFREG | 0o400, expected)

    def _dirs(self, *paths):
        for path in paths: self.add(path, stat.S_IFDIR | 0o755)
    def add(self, path, mode, data=b'', nlink=1, target=None, rdev=0):
        self.nextino += 1
        self.nodes[path] = Node(self.nextino, mode, data, nlink, target, rdev)
        return self.nodes[path]
    def event(self, name, *args): self.calls.append((name,) + args)
    def validate(self): self.event('validate')
    def getpid(self): return 100
    def pid(self): return self.getpid()
    def getuid(self): return 0
    def flags(self, *names):
        if len(names) == 1 and type(names[0]) is int:
            return 0 if self.live[names[0]]['block'] else self.O_NONBLOCK
        value = 0
        for name in names: value |= getattr(self, name)
        return value
    def pause(self, seconds):
        if type(seconds) not in (int, float) or not 0 < seconds <= .05:
            raise AssertionError('HOST invalid bounded pause')
        self.clock.value += seconds
        if self.controller_ready_at is not None and self.clock.value >= self.controller_ready_at:
            self._publish_controller_socket()
    sleep = pause
    def _publish_controller_socket(self):
        path = self.run + '/ctrl/mta66666666'
        if path in self.nodes: return
        node = self.add(path, stat.S_IFSOCK | 0o600)
        if self.fault == 'foreign_endpoint': node.mode = stat.S_IFREG | 0o600
        self.controller_inode = node.inode
        self.add('/proc/300/fd', stat.S_IFDIR | 0o555)
        self.add('/proc/300/fd/7', stat.S_IFLNK | 0o777, target='socket:[%d]' % node.inode)
    def install_actor(self, pid, start, exe, argv):
        root = '/proc/' + str(pid)
        for path in (root, root + '/task', root + '/task/' + str(pid)):
            if path not in self.nodes: self.add(path, stat.S_IFDIR | 0o555)
        comm = exe.rsplit('/', 1)[-1]
        for path in (root + '/stat', root + '/task/' + str(pid) + '/stat'):
            raw = stat_bytes(pid, start, comm[:15])  # Linux task comm, not pathname basename identity.
            if path in self.nodes: self.nodes[path].data = raw
            else: self.add(path, stat.S_IFREG | 0o444, raw)
        for path, raw in ((root + '/cmdline', argv), (root + '/comm', comm.encode('ascii') + b'\n')):
            if path in self.nodes: self.nodes[path].data = raw
            else: self.add(path, stat.S_IFREG | 0o444, raw)
        if root + '/exe' in self.nodes: self.nodes[root + '/exe'].target = exe
        else: self.add(root + '/exe', stat.S_IFLNK | 0o777, target=exe)
    def remove_actor(self, pid):
        root = '/proc/' + str(pid)
        for path in tuple(self.nodes):
            if path == root or path.startswith(root + '/'): del self.nodes[path]
    def realpath(self, path):
        if path == '/tmp' or path.startswith('/tmp/'): return '/var/volatile/tmp' + path[4:]
        if path == '/var/tmp' or path.startswith('/var/tmp/'): return '/var/volatile/tmp' + path[8:]
        return path
    def _node(self, path, follow=False):
        if follow: path = self.realpath(path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST modeled absence')
        node = self.nodes[path]
        return self._node(node.target, True) if follow and node.target is not None and node.target.startswith('/') else node
    def stat(self, path):
        self.event('stat', path)
        if path == self.run + '/ctrl/mta66666666' and path not in self.nodes: self.absent_reads += 1
        if path.startswith(self.run + '/go-read-') and path in self.nodes and self.fault == 'unlink_precheck' and not self.fault_used:
            matching = [s for s in self.sockets if getattr(s, 'local', None) == path and s.closed
                and getattr(s, 'peer', None) != '/run/wpa_supplicant/wlan0']
            if matching:
                self.fault_used = True; self.endpoint_early_failures += 1
                raise OSError(errno.EINTR, 'HOST passive unlink precheck refusal')
        return self._node(path).metadata()
    lstat = stat
    stat_path = stat
    def stat_root(self): return self.stat('/')
    def stat_at(self, parent, name): return self.stat(posixpath.join(self.live[parent]['path'], name))
    def readlink(self, path):
        self.event('readlink', path)
        node = self._node(path)
        if node.target is None: raise OSError(errno.EINVAL, 'HOST modeled nonlink')
        return node.target
    def listdir(self, path):
        self.event('listdir', path)
        if path == '/proc/self/fd': return ['0', '1', '2'] + [str(fd) for fd in sorted(self.live)]
        prefix = path.rstrip('/') + '/'
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST modeled absence')
        return sorted({p[len(prefix):].split('/')[0] for p in self.nodes if p.startswith(prefix)})
    def alloc(self, node, path=None, ofd=None):
        fd = self.nextfd; self.nextfd += 1
        self.live[fd] = {'node': node, 'path': path, 'pos': 0, 'inherit': False,
            'block': True, 'ofd': object() if ofd is None else ofd}
        return fd
    def open(self, path, flags=None):
        self.event('open', path, flags)
        return self.alloc(self._node(path, True), self.realpath(path))
    open_path = open
    def open_root(self, flags): return self.open('/', flags)
    def open_at(self, parent, name, flags, mode=0):
        path = posixpath.join(self.live[parent]['path'], name)
        if flags & self.O_CREAT:
            if path in self.nodes and flags & self.O_EXCL: raise OSError(errno.EEXIST, 'HOST modeled exists')
            if path not in self.nodes: self.add(path, stat.S_IFREG | mode)
        return self.open(path, flags)
    def fstat(self, fd):
        self.event('fstat', fd)
        if fd not in self.live:
            self.deadfd_fstats[fd] = self.deadfd_fstats.get(fd, 0) + 1
            raise OSError(errno.EBADF, 'HOST modeled once closed')
        return self.live[fd]['node'].metadata()
    def read(self, fd, count):
        self.event('read', fd, count)
        row = self.live[fd]; node = row['node']
        if stat.S_ISFIFO(node.mode): raise OSError(errno.EAGAIN, 'HOST live writer empty queue')
        if row['path'] == '/proc/net/unix': data = self.unix_table()
        else: data = node.data
        raw = data[row['pos']:row['pos'] + count]; row['pos'] += len(raw)
        return raw
    def write(self, fd, raw):
        self.event('write', fd, len(raw))
        row = self.live[fd]; node = row['node']
        if stat.S_ISFIFO(node.mode):
            if raw != b'1': raise AssertionError('HOST unexpected parent pipe output')
            ticket = next(t for t in self.owner._tickets if any(r.role == 'gate_write' and r.fd == fd for r in t.fds))
            argv = b''.join(v.encode('ascii') + b'\0' for v in ticket.spec.argv)
            self.install_actor(ticket.pid, ticket.preexec.start, ticket.spec.exe, argv)
            if ticket.spec.role == 'controller': self.controller_ready_at = self.clock.value + .025
        else:
            node.data += raw; node.revision += 1
        return len(raw)
    def close(self, fd):
        self.event('close', fd)
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST repeated close forbidden')
        del self.live[fd]; self.closed.append(fd)
    def fsync(self, fd): self.fstat(fd); self.event('fsync', fd)
    def flock(self, fd): self.fstat(fd); self.event('flock', fd); return (0, 0)
    def rename_at(self, parent, source, destination):
        a, b = (posixpath.join(self.live[parent]['path'], name) for name in (source, destination))
        self.event('rename_at', source, destination)
        node = self.nodes[a]
        if self.fault is not None and self.fault.startswith('publication_unknown') and not self.fault_used and (
                b'"phase": "group_add_intent"' in node.data or b'"phase":"group_add_intent"' in node.data):
            self.fault_used = True; self.nodes[b] = self.nodes.pop(a)
            # Explicit denial inputs only, after both ORIGINAL native launches.
            # They cannot be repaired/adopted by a boolean or a fabricated actor.
            ticket = self.owner._tickets[1]
            if self.fault == 'publication_unknown_ticket_unknown': ticket.unknown = True
            elif self.fault == 'publication_unknown_no_preexec': ticket.preexec = None
            elif self.fault == 'publication_unknown_changed_start':
                self.install_actor(ticket.pid, ticket.preexec.start + 1, ticket.spec.exe,
                    b''.join(v.encode('ascii') + b'\0' for v in ticket.spec.argv))
            elif self.fault == 'publication_unknown_changed_exe':
                self.install_actor(ticket.pid, ticket.preexec.start, '/private/HOST_foreign', b'/private/HOST_foreign\0')
            raise OSError(errno.EIO, 'HOST publication return unknown')
        self.nodes[b] = self.nodes.pop(a)
    def unlink_at(self, parent, name): return self.unlink(posixpath.join(self.live[parent]['path'], name))
    def unlink(self, path):
        self.event('unlink', path); self.unlink_calls.append(path)
        if path not in self.nodes: raise OSError(errno.ENOENT, 'HOST modeled absence')
        del self.nodes[path]
        matching = [s for s in self.sockets if getattr(s, 'local', None) == path
            and getattr(s, 'peer', None) != '/run/wpa_supplicant/wlan0']
        if self.fault == 'unlink_unknown' and not self.fault_used and matching:
            self.fault_used = True; raise OSError(errno.EIO, 'HOST unlink return unknown')
    def set_inheritable(self, fd, value): self.live[fd]['inherit'] = value
    def get_inheritable(self, fd): return self.live[fd]['inherit']
    def set_blocking(self, fd, value): self.live[fd]['block'] = value
    def dup(self, fd):
        row = self.live[fd]
        return self.alloc(row['node'], row['path'], row['ofd'])
    def pipe2(self, flags):
        self.nextino += 1; node = Node(self.nextino, stat.S_IFIFO | 0o600)
        return self.alloc(node), self.alloc(node)
    def fork(self):
        ticket = self.owner._tickets[-1]
        pid = 200 if ticket.spec.role == 'watchdog' else 300
        self.children[pid] = ticket
        parent_argv = self.nodes['/proc/100/cmdline'].data
        self.install_actor(pid, pid, PYTHON, parent_argv)
        self.event('fork', pid)
        return pid
    def execve(self, *unused): raise AssertionError('HOST child exec deliberately modeled')
    def _exit(self, *unused): raise AssertionError('HOST no child branch')
    def kill_term(self, pid):
        self.event('kill_term', pid)
        if self.fault == 'first_child_stop' and pid == 300 and not self.fault_used:
            self.fault_used = True; raise OSError(errno.EIO, 'HOST first stop return unknown')
        self.stopped.append(pid)
    def waitpid(self, pid, flags):
        self.event('waitpid', pid)
        if pid not in self.stopped: return (0, 0)
        self.reaped.append(pid); self.remove_actor(pid)
        return (pid, 0)
    def major(self, n): return n >> 8
    def minor(self, n): return n & 255
    def WIFEXITED(self, value): return value & 127 == 0
    def WEXITSTATUS(self, value): return value >> 8
    def WIFSIGNALED(self, value): return value & 127 not in (0, 127)
    def WTERMSIG(self, value): return value & 127
    def unix_table(self):
        rows = [b'Num RefCount Protocol Flags Type St Inode Path']
        rows.append(('00000000: 00000002 00000000 00000000 0002 01 %d /run/wpa_supplicant/wlan0' % self.stock_socket_inode).encode('ascii'))
        peer = self.run + '/ctrl/mta66666666'
        if peer in self.nodes:
            rows.append(('00000000: 00000002 00000000 00000000 0002 01 %d %s' % (self.controller_inode, peer)).encode('ascii'))
        return b'\n'.join(rows) + b'\n'
    def socket(self, protocol):
        raw = Netlink(self, protocol); self.sockets.append(raw); return raw
    def unix(self):
        raw = Unix(self); self.sockets.append(raw); return raw
    def attach(self, modules, owner): self.modules, self.owner = modules, owner


class Socket:
    def __init__(self, io):
        self.io, self.closed, self.inherit, self.timeout = io, False, True, None
        io.nextino += 1
        self.fd = io.alloc(Node(io.nextino, stat.S_IFSOCK | 0o600))
        self.queue, self.options, self.sent = [], {}, []
    def fileno(self): return self.fd
    def close(self):
        self.io.close(self.fd); self.closed = True
    def set_inheritable(self, value): self.inherit = value; self.io.set_inheritable(self.fd, value)
    def get_inheritable(self): return self.inherit
    def settimeout(self, value): self.timeout = value
    def gettimeout(self): return self.timeout
    def setsockopt(self, level, option, value): self.options[level, option] = value
    def getsockopt(self, level, option): return self.options.get((level, option), 0)


class Netlink(Socket):
    def __init__(self, io, protocol):
        Socket.__init__(self, io); self.protocol, self.port = protocol, 8000 + self.fd
    def bind(self, target):
        if target != (0, 0): raise AssertionError('HOST unlisted netlink bind')
    def getsockname(self): return (self.port, 0)
    def origin(self, owned=False):
        kind = self.io.netdev if owned else 2
        return (u32(1, 0) + attr(153, struct.pack('<Q', 99 if owned else 2)) +
            u32(3, 7 if owned else 3) + attr(4, b'mta66666666\0' if owned else b'wlan0\0') +
            u32(5, kind) + u32(38, 2412) + attr(6, b'\x02\x66\x77\x88\x99\xaa' if owned else b'\x02\x11\x22\x33\x44\x55'))
    def caps(self):
        types_raw = b''.join(attr(k, b'') for k in (2, 8, 9))
        commands = b''.join(u32(i + 1, k) for i, k in enumerate((6, 7, 8, 15, 16)))
        limits = nest(1, u32(1, 1) + nest(2, attr(2, b''))) + nest(2, u32(1, 1) + nest(2, attr(8, b'') + attr(9, b'')))
        combination = nest(1, nest(1, limits) + u32(2, 2) + attr(3, b'') + u32(4, 1) + u32(7, 100))
        frequencies = nest(22, nest(1, nest(1, nest(1, u32(1, 2412)))))
        return u32(1, 0) + u32(46, 1) + nest(32, types_raw) + nest(50, commands) + nest(120, combination) + frequencies
    def sendto(self, request, target):
        if target != (0, 0): raise AssertionError('HOST unlisted kernel endpoint')
        self.sent.append(request)
        size, family, flags, sequence, port = NL.unpack_from(request)
        if port != self.port: raise AssertionError('HOST wrong netlink port')
        rows = []
        if self.protocol == 0:
            if family == 22:
                body = struct.pack('<BBBBI', 2, 24, 128, 0, 3) + attr(1, b'\xc0\xa8\x01\x64') + attr(2, b'\xc0\xa8\x01\x64') + attr(6, struct.pack('<IIII', 0xffffffff, 0xffffffff, 0, 0))
                rows.append(reply(request, 20, body, 2))
            elif family == 26:
                body = struct.pack('<BBBBBBBBI', 2, 24, 0, 0, 254, 2, 253, 1, 0) + attr(1, b'\xc0\xa8\x01\x00') + u32(4, 3)
                rows.append(reply(request, 24, body, 2))
            elif family == 34:
                for priority, table in ((0, 255), (32766, 254), (32767, 253)):
                    body = struct.pack('<BBBBBBBBI', 2, 0, 0, 0, table, 0, 0, 1, 0) + u32(6, priority)
                    rows.append(reply(request, 32, body, 2))
            else: raise AssertionError('HOST unlisted route request')
            rows.append(reply(request, 3, b'\0' * 4, 2))
        else:
            command, version, reserved = GH.unpack_from(request, 16)
            def genl(code, body, multi=False): return reply(request, family, GH.pack(code, version, 0) + body, 2 if multi else 0)
            if family == 16:
                body = attr(1, struct.pack('<H', 19)) + attr(2, b'nl80211\0') + u32(3, 1) + u32(4, 0) + u32(5, 174)
                rows.append(genl(1, body))
            elif command == 5:
                rows.append(genl(7, self.origin(), True))
                if self.io.netdev is not None: rows.append(genl(7, self.origin(True), True))
            elif command == 32:
                bss = attr(1, b'\x02\x11\x22\x33\x44\x55') + u32(2, 2412) + attr(4, struct.pack('<H', 100)) + u32(9, 1)
                rows.append(genl(34, u32(3, 3) + nest(47, bss), True))
            elif command == 95: rows.append(genl(95, u32(173, 1)))
            elif command == 1: rows.append(genl(3, self.caps(), True))
            elif command == 7:
                self.io.create_count += 1
                if self.io.netdev is not None: raise AssertionError('HOST duplicate CREATE')
                self.io.netdev = 8; self.io.iftypes.append(8)
                rows.append(genl(7, self.origin(True)))
                if self.io.fault != 'missing_ack': rows.append(reply(request, 2, b'\0' * 4 + request[:16]))
            elif command == 8:
                if self.io.netdev is None: raise AssertionError('HOST duplicate DELETE')
                self.io.delete_count += 1; self.io.netdev = None
                rows.append(reply(request, 2, b'\0' * 4 + request[:16]))
            else: raise AssertionError('HOST unlisted generic command')
            if flags & 0x300: rows.append(reply(request, 3, b'\0' * 4, 2))
        self.queue.extend((raw, [], 0, (0, 0)) for raw in rows)
        return len(request)
    def recvmsg(self, *unused):
        if self.queue: return self.queue.pop(0)
        raise OSError(errno.ETIMEDOUT, 'HOST modeled missing kernel reply')


class Unix(Socket):
    def bind(self, path):
        self.local = path
        if path in self.io.nodes: raise OSError(errno.EADDRINUSE, 'HOST modeled occupied')
        self.io.add(path, stat.S_IFSOCK | 0o600)
    def connect(self, path): self.peer = path
    def getsockname(self): return self.local
    def getpeername(self): return self.peer
    def send(self, wire):
        self.sent.append(wire)
        if self.peer == '/run/wpa_supplicant/wlan0':
            if wire != b'STATUS': raise AssertionError('HOST stock mutation forbidden')
            value = b'wpa_state=COMPLETED\nfreq=2412\nbssid=02:11:22:33:44:55\n'
            pid = 44
        else:
            pid = 300
            if wire == b'ATTACH': value = b'OK\n'
            elif wire == b'STATUS': value = b'wpa_state=COMPLETED\nmode=AP\nfreq=2412\nbssid=02:66:77:88:99:aa\n'
            elif wire == b'P2P_GROUP_ADD freq=2412':
                value = b'OK\n'; self.io.netdev = 9; self.io.iftypes.append(9)
                event = b'<3>P2P-GROUP-STARTED mta66666666 GO ssid="HOST" freq=2412 passphrase="HOST_PRIVATE_NOT_A_CREDENTIAL"\n'
                event_sockets = [s for s in self.io.sockets if isinstance(s, Unix) and b'ATTACH' in s.sent]
                if len(event_sockets) != 1: raise AssertionError('HOST event channel not unique')
                event_sockets[0].queue.append((event, [(1, 2, struct.pack('<iii', pid, 0, 0))], 0, self.peer))
            elif wire == b'P2P_GROUP_REMOVE mta66666666': value = b'OK\n'; self.io.netdev = 8; self.io.iftypes.append(8)
            else: raise AssertionError('HOST unlisted private command')
        self.queue.append((value, [(1, 2, struct.pack('<iii', pid, 0, 0))], 0, self.peer))
        return len(wire)
    def recvmsg(self, *unused):
        if self.queue: return self.queue.pop(0)
        raise OSError(errno.EAGAIN, 'HOST modeled empty Unix queue')

