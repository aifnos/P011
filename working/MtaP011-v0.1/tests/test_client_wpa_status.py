"""HOST FakeIO only; no real /proc, socket, process, lock, ADB or RF."""
import ast
import errno
import hashlib
import math
from pathlib import Path
import socket
import stat
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import mta_client_wpa_status as wpa
import mta_client_proc as proc
import mta_p2p_client_init as core

BOOT = '00000000-0000-0000-0000-000000000001'
EXE, ENDPOINT = '/usr/sbin/wpa_supplicant', '/run/wpa_supplicant/wlan0'
IMAGE = b'HOST SYNTHETIC ELF CONTENT'
CONFIG = b'CONFIG_IKCONFIG=y\n# CONFIG_NAMESPACES is not set\n'
ME = core.Actor(123, 100, '/usr/bin/python3', 'a' * 64, ((123, 100, 'R'),))
COMMAND = b'/usr/sbin/wpa_supplicant\0-iwlan0\0'
DAEMON = core.Actor(987, 200, EXE, hashlib.sha256(COMMAND).hexdigest(), ((987, 200, 'S'),))
STATUS = b'wpa_state=COMPLETED\nfreq=2412\nmode=station\nbssid=02:00:00:00:00:01\nssid=HOST\n'


def manifest(kind='full4_present'):
    return {'daemon_exe': EXE, 'daemon_sha256': hashlib.sha256(IMAGE).hexdigest(),
        'endpoint': ENDPOINT, 'real_uid': 0, 'real_gid': 0, 'namespace_kind': kind,
        'config_sha256': hashlib.sha256(CONFIG).hexdigest() if kind != 'full4_present' else None}


def metadata(mode=stat.S_IFREG | 0o644, inode=2, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=0,
        st_gid=0, st_nlink=1, st_size=size, st_mtime_ns=10, st_ctime_ns=20)


def observed(actor):
    return proc.ProcObservation('live_actor', 'live_actor', 'observed', BOOT,
        actor, False, (), True, 2, (), 1, 1, False, len(actor.tasks))


class FakeProc:
    def __init__(self): self.self_actor, self.daemon = ME, DAEMON
    def read_self(self): return observed(self.self_actor)
    def read_actor(self, pid, expected=None):
        if pid != self.daemon.pid or expected is not None and expected.key() != self.daemon.key():
            raise OSError(errno.ESRCH, 'HOST synthetic')
        return observed(self.daemon)


class FakeSocket:
    family, type, proto = 1, 2, 0
    def __init__(self, io):
        self.io, self.fd, self.close_count, self.sent = io, 400, 0, []
        self.local, self.peer, self.timeout, self.inheritable = None, None, None, True
        self.passcred, self.flags, self.ancillary = 0, 0, None
        self.packet, self.return_peer, self.hook = STATUS, ENDPOINT, None
        self.io.live[self.fd] = metadata(stat.S_IFSOCK | 0o777, inode=400)
        self.send_count, self.factory_flags, self.close_failure = 6, None, False
    def fileno(self): return self.fd
    def close(self):
        self.close_count += 1
        if self.close_failure: raise OSError(errno.EIO, 'HOST synthetic')
        self.io.close(self.fd); self.fd = -1
    def set_inheritable(self, value): self.inheritable = value
    def get_inheritable(self): return self.inheritable
    def setsockopt(self, level, kind, value): self.passcred = value
    def getsockopt(self, level, kind): return self.passcred
    def bind(self, path): self.local = path
    def getsockname(self): return self.local
    def connect(self, path): self.peer = path
    def getpeername(self): return self.peer
    def settimeout(self, value):
        sec, fraction = divmod(math.ceil(value * 1e9), 1000000000)
        self.timeout = sec + fraction * 1e-9
    def gettimeout(self): return self.timeout
    def send(self, data): self.sent.append(data); return self.send_count
    def recvmsg(self, amount, ancillary, flags):
        self.factory_flags = (amount, ancillary, flags)
        if self.hook is not None: self.hook()
        controls = self.ancillary if self.ancillary is not None else \
            [(1, 2, struct.pack('=iII', DAEMON.pid, 0, 0))]
        return self.packet, controls, self.flags, self.return_peer


class FakeIO:
    def __init__(self, reduced=False):
        self.files, self.paths, self.live, self.positions = {}, {}, {}, {}
        self.closed, self.created, self.nextfd = [], [], 30
        self.kind = 'namespaces_disabled_cgroup_mnt' if reduced else 'full4_present'
        self.names = ('cgroup', 'mnt') if reduced else ('mnt', 'net', 'pid', 'user')
        self.links, self.calls, self.close_error = {}, [], set()
        self.factory_error, self.sock, self.proc = None, None, FakeProc()
        for path in ('/', '/usr', '/usr/sbin', '/run', '/run/wpa_supplicant'):
            self.paths[path] = metadata(stat.S_IFDIR | 0o755, inode=len(self.paths) + 1)
        self.paths[ENDPOINT] = metadata(stat.S_IFSOCK | 0o770, inode=990)
        self.file(EXE, IMAGE, metadata(stat.S_IFREG | 0o755, inode=70, size=len(IMAGE)))
        self.file('/proc/987/exe', IMAGE, self.paths[EXE])
        self.file('/proc/123/comm', b'python3\n')
        self.file('/proc/987/comm', b'wpa_supplicant\n')
        self.file('/proc/987/cmdline', COMMAND)
        self.file('/proc/987/status', b'Name:\twpa_supplicant\nUid:\t0 0 0 0\nGid:\t0 0 0 0\n')
        self.file('/proc/net/unix', b'Num RefCount Protocol Flags Type St Inode Path\n'
            b'00000001: 00000002 00000000 00000000 0002 01 991 ' + ENDPOINT.encode() + b'\n')
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        self.file('/proc/config.gz', compressor.compress(CONFIG) + compressor.flush())
        for name in self.names:
            link = name + ':[101]'
            for root in ('/proc/987/ns', '/proc/self/ns'): self.links[root + '/' + name] = link
        self.links['/proc/987/fd/6'] = 'socket:[991]'
    def file(self, path, raw, meta=None):
        self.files[path] = raw
        self.paths[path] = meta or metadata(inode=len(self.paths) + 100, size=len(raw))
    def validate(self): self.calls.append('validate')
    def open(self, path, flags):
        self.calls.append(('open', path, flags))
        if path not in self.files: raise OSError(errno.ENOENT, 'HOST synthetic')
        fd = self.nextfd; self.nextfd += 1
        self.live[fd], self.positions[fd] = self.paths[path], (path, 0)
        self.created.append(fd); return fd
    def read(self, fd, count):
        path, pos = self.positions[fd]; value = self.files[path][pos:pos + count]
        self.positions[fd] = (path, pos + len(value)); return value
    def stat(self, path):
        if path not in self.paths: raise OSError(errno.ENOENT, 'HOST synthetic')
        return self.paths[path]
    def fstat(self, fd):
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST synthetic')
        return self.live[fd]
    def close(self, fd):
        self.closed.append(fd)
        if fd in self.close_error: raise OSError(errno.EIO, 'HOST synthetic')
        if fd not in self.live: raise OSError(errno.EBADF, 'HOST synthetic')
        del self.live[fd]
    def listdir(self, path):
        if path == '/proc': return ['123', '987', 'sys', 'net']
        if path in ('/proc/987/ns', '/proc/self/ns'): return list(self.names)
        if path == '/proc/987/fd': return ['6']
        raise OSError(errno.ENOENT, 'HOST synthetic')
    def readlink(self, path): return self.links[path]
    def new_socket(self):
        self.calls.append('new_socket')
        if self.factory_error is not None: raise self.factory_error
        if self.sock is None: self.sock = FakeSocket(self)
        return self.sock
    def token(self): return b'HOSTTOKEN1234567'
    def cmsg_space(self, count): return 16 + ((count + 7) & ~7)


class ClientWpaStatusTests(unittest.TestCase):
    def setUp(self):
        self.io = FakeIO(); self.clock = lambda: 10.1234567891
        self.reader = wpa.AuthenticatedStatusReader(manifest(), _io=self.io,
            _proc_reader=self.io.proc, _clock=self.clock)
    def read(self): return self.reader.read_status(12.9)
    def reject(self, reason=None):
        with self.assertRaises(wpa.WpaStatusError) as error: self.read()
        if reason is not None: self.assertEqual(error.exception.code, reason)
        self.assertFalse(self.reader.status()['read_success'])
    def socket(self): self.io.sock = FakeSocket(self.io); return self.io.sock
    def test_constructor_is_pure_and_default_is_unavailable(self):
        with mock.patch.object(wpa.socket, 'socket', side_effect=AssertionError('actual socket prohibited')), \
                mock.patch.object(wpa.os, 'open', side_effect=AssertionError('actual file prohibited')):
            reader = wpa.AuthenticatedStatusReader(_clock=self.clock)
            with self.assertRaises(wpa.WpaStatusError) as error: reader.read_status(12)
            self.assertEqual(error.exception.code, 'unavailable')
        self.assertEqual(self.io.calls, [])
    def test_p011_arm_platform_flags_are_verified_without_actual_io(self):
        fake_os = SimpleNamespace(geteuid=lambda: 0,
            uname=lambda: ('Linux', 'HOST', '4.14.174', 'HOST', 'armv7l'),
            O_NOFOLLOW=0x8000, O_CLOEXEC=0x80000)
        fake_sys = SimpleNamespace(platform='linux', byteorder='little')
        with mock.patch.object(wpa, 'os', fake_os), mock.patch.object(wpa, 'sys', fake_sys):
            wpa._LinuxIo().validate()
            fake_os.O_NOFOLLOW = 0x20000
            with self.assertRaises(wpa.WpaStatusError) as error: wpa._LinuxIo().validate()
            self.assertEqual(error.exception.code, 'unsupported_platform')
            fake_os.O_NOFOLLOW = 0x8000
            fake_os.uname = lambda: ('Linux', 'HOST', '4.14.174', 'HOST', 'x86_64')
            with self.assertRaises(wpa.WpaStatusError): wpa._LinuxIo().validate()
    def test_source_default_file_opens_use_actual_arm_nofollow_flags(self):
        self.read()
        opens = [row for row in self.io.calls if type(row) is tuple and row[0] == 'open']
        self.assertTrue(opens)
        for unused, path, flags in opens:
            self.assertEqual(flags, 0x80000 if path == '/proc/987/exe' else 0x88000)
    def test_supported_baseline_reason_is_not_hidden_as_generic_io_error(self):
        def incompatible(): raise wpa.baseline.BaselineError('unsupported_platform')
        self.io.validate = incompatible
        self.reject('unsupported_platform')
        self.assertEqual(self.reader.status()['reason'], 'unsupported_platform')
        self.assertEqual(self.reader._source._files, [])
    def test_concrete_linux_source_composes_with_fake_files_and_proc(self):
        result = self.read()
        self.assertEqual(result['raw'], STATUS)
        self.assertEqual(result['frequency'], 2412)
        self.assertTrue(result['completed']); self.assertTrue(result['source_authenticated'])
        self.assertEqual(self.io.sock.sent, [b'STATUS'])
        self.assertEqual(self.io.sock.factory_flags[2], 0x40000000)
        self.assertEqual(self.io.sock.close_count, 1)
        self.assertEqual(len(set(self.io.closed)), len(self.io.closed))
        self.assertEqual(self.io.live, {})
        self.assertEqual(self.reader.status()['source_count'], 2)
    def test_reduced_namespace_uses_actual_plain_config_hash(self):
        io = FakeIO(True)
        reader = wpa.AuthenticatedStatusReader(manifest(io.kind), _io=io, _proc_reader=io.proc, _clock=self.clock)
        self.assertTrue(reader.read_status(12.9)['source_authenticated'])
        self.assertEqual(reader._sources[0]['namespace_profile']['config_sha256'], hashlib.sha256(CONFIG).hexdigest())
    def test_absent_config_pin_rejected_at_constructor(self):
        value = manifest('namespaces_disabled_cgroup_mnt'); value['config_sha256'] = None
        with self.assertRaises(wpa.WpaStatusError): wpa.AuthenticatedStatusReader(value)
    def test_missing_namespace_not_filled_with_false(self):
        self.io.names = ('mnt', 'user', 'pid'); self.reject('namespace_invalid')
        self.assertNotIn('new_socket', self.io.calls)
    def test_namespace_link_mismatch_has_no_socket(self):
        self.io.links['/proc/987/ns/net'] = 'net:[999]'; self.reject('namespace_invalid')
        self.assertNotIn('new_socket', self.io.calls)
    def test_actual_actor_prepost_exec_change_rejected(self):
        sock = self.socket()
        sock.hook = lambda: setattr(self.io.proc, 'daemon', core.Actor(987, 201, EXE, DAEMON.argv_sha, ((987, 201, 'S'),)))
        self.reject('source_changed'); self.assertEqual(sock.close_count, 1)
    def test_original_image_fd_hash_mismatch_before_socket(self):
        self.io.files['/proc/987/exe'] = b'FOREIGN'; self.reject('image_invalid')
        self.assertNotIn('new_socket', self.io.calls)
    def test_sockfs_inode_not_path_inode_and_must_belong_daemon(self):
        self.io.links['/proc/987/fd/6'] = 'socket:[990]'; self.reject('endpoint_invalid')
    def test_noncanonical_endpoint_rejected(self):
        value = manifest(); value['endpoint'] = '/run/../wpa_supplicant/wlan0'
        with self.assertRaises(wpa.WpaStatusError): wpa.AuthenticatedStatusReader(value)
    def test_endpoint_world_writable_rejected_before_socket(self):
        self.io.paths[ENDPOINT].st_mode |= 0o002; self.reject('source_invalid')
        self.assertNotIn('new_socket', self.io.calls)
    def test_endpoint_anchor_symlink_rejected(self):
        self.io.paths['/run'].st_mode = stat.S_IFLNK | 0o777
        self.io.links['/run'] = '/run'; self.reject('endpoint_invalid')
    def test_bounded_root_owned_endpoint_parent_symlink(self):
        for target in ('/actualrun', '/actualrun/', '/actualrun///'):
            with self.subTest(target=target):
                io = FakeIO(); io.paths['/run'] = metadata(stat.S_IFLNK | 0o777, inode=900)
                io.links['/run'] = target
                io.paths['/actualrun'] = metadata(stat.S_IFDIR | 0o755, inode=901)
                io.paths['/actualrun/wpa_supplicant'] = io.paths['/run/wpa_supplicant']
                io.paths['/actualrun/wpa_supplicant/wlan0'] = io.paths[ENDPOINT]
                reader = wpa.AuthenticatedStatusReader(manifest(), _io=io,
                    _proc_reader=io.proc, _clock=self.clock)
                result = reader.read_status(12.9); self.assertTrue(result['source_authenticated'])
                self.assertEqual(reader._sources[0]['resolved_endpoint'], '/actualrun/wpa_supplicant/wlan0')
                self.assertEqual(io.sock.peer, ENDPOINT)
    def test_final_endpoint_symlink_trailing_slashes_require_directory(self):
        for target in ('/actual/socket/', 'socket/', '/actual/socket///', 'socket///'):
            with self.subTest(target=target):
                io = FakeIO(); io.paths[ENDPOINT] = metadata(stat.S_IFLNK | 0o777, inode=900)
                io.links[ENDPOINT] = target
                io.paths['/actual'] = metadata(stat.S_IFDIR | 0o755, inode=901)
                io.paths['/actual/socket'] = metadata(stat.S_IFSOCK | 0o770, inode=902)
                io.paths['/run/wpa_supplicant/socket'] = metadata(stat.S_IFSOCK | 0o770, inode=903)
                reader = wpa.AuthenticatedStatusReader(manifest(), _io=io,
                    _proc_reader=io.proc, _clock=self.clock)
                with self.assertRaises(wpa.WpaStatusError) as error: reader.read_status(12.9)
                self.assertEqual(error.exception.code, 'endpoint_invalid')
                self.assertNotIn('new_socket', io.calls)
    def test_parent_symlink_target_mutation_during_status_is_rejected(self):
        self.io.paths['/run'] = metadata(stat.S_IFLNK | 0o777, inode=900)
        self.io.links['/run'] = '/actualrun'
        for base in ('/actualrun', '/other'):
            self.io.paths[base] = metadata(stat.S_IFDIR | 0o755, inode=901)
            self.io.paths[base + '/wpa_supplicant'] = self.io.paths['/run/wpa_supplicant']
            self.io.paths[base + '/wpa_supplicant/wlan0'] = self.io.paths[ENDPOINT]
        self.socket().hook = lambda: self.io.links.__setitem__('/run', '/other')
        self.reject('source_changed')
    def test_same_source_observation_is_not_fresh(self):
        real = self.reader._source; real_read = real.read_source; rows = []
        class Cached:
            def read_source(inner, consumer, deadline):
                if not rows: rows.append(real_read(consumer, deadline))
                return rows[0]
            def authenticate_source(inner, consumer, row, deadline): return real.authenticate_source(consumer, row, deadline)
        self.reader._source = Cached(); self.reject('source_changed')
    def test_default_proc_readers_registered_before_each_call_and_retained(self):
        reader = wpa.AuthenticatedStatusReader(manifest(), _io=self.io, _clock=self.clock)
        source, created = reader._source, []
        class RegisteredProc(FakeProc):
            def __init__(inner, timeout):
                FakeProc.__init__(inner)
                self.assertEqual(source._actor_calls[-1]['reader'], None)
                created.append(inner)
            def note(inner):
                row = source._actor_calls[-1]
                self.assertIs(row['reader'], inner)
                self.assertTrue(row['started']); self.assertFalse(row['returned'])
            def read_self(inner): inner.note(); return FakeProc.read_self(inner)
            def read_actor(inner, pid, expected=None):
                inner.note(); return FakeProc.read_actor(inner, pid, expected)
        with mock.patch.object(wpa.proc, 'ProcReader', RegisteredProc):
            self.assertTrue(reader.read_status(12.9)['source_authenticated'])
        self.assertEqual(len(created), 8); self.assertEqual(len(source._actor_calls), 8)
        self.assertEqual([sum(row['files'] is files for row in source._actor_calls)
                          for files in source._files], [4, 4])
        for row, actual in zip(source._actor_calls, created):
            self.assertIs(row['reader'], actual); self.assertTrue(row['returned'])
            self.assertFalse(row['unknown']); self.assertIsNone(row['error'])
            self.assertTrue(any(value is row['value'] for value in source._raw))
    def test_default_proc_exception_retains_original_reader_and_open_attempt(self):
        reader = wpa.AuthenticatedStatusReader(manifest(), _io=self.io, _clock=self.clock)
        source, created, failure = reader._source, [], KeyboardInterrupt('PRIVATE')
        owner, attempt = object(), {'descriptor': object(), 'unknown': True}
        class InterruptedProc:
            def __init__(inner, timeout):
                inner._fd_refs, inner._open_attempt = [(owner, 55)], attempt
                created.append(inner)
            def read_self(inner):
                self.assertIs(source._actor_calls[-1]['reader'], inner)
                raise failure
            def close(inner): raise AssertionError('borrowed proc owner must not be closed')
        with mock.patch.object(wpa.proc, 'ProcReader', InterruptedProc):
            with self.assertRaises(wpa.WpaStatusError) as error: reader.read_status(12.9)
        self.assertEqual(error.exception.code, 'close_unknown')
        row = source._actor_calls[0]
        self.assertIs(row['reader'], created[0]); self.assertIs(row['error'], failure)
        self.assertIs(row['reader']._open_attempt, attempt)
        self.assertIs(row['reader']._fd_refs[0][0], owner)
        self.assertFalse(row['returned']); self.assertTrue(row['unknown'])
        self.assertTrue(source._pending); self.assertTrue(reader.status()['resource_pending'])
        self.assertNotIn('new_socket', self.io.calls)
        with self.assertRaises(wpa.WpaStatusError): reader.read_status(12.9)
        self.assertEqual(len(created), 1); self.assertEqual(len(source._actor_calls), 1)
    def test_default_proc_pending_observation_retains_reader_and_actual_value(self):
        reader = wpa.AuthenticatedStatusReader(manifest(), _io=self.io, _clock=self.clock)
        source, created, owner = reader._source, [], object()
        value = proc.ProcObservation('live_actor', 'live_actor', 'observed', BOOT,
            ME, False, (), True, 2, (), 2, 1, True, 1)
        class PendingProc:
            def __init__(inner, timeout):
                inner._fd_refs, inner._open_attempt = [(owner, 55)], {'unknown': True}
                created.append(inner)
            def read_self(inner):
                self.assertIs(source._actor_calls[-1]['reader'], inner)
                return value
            def close(inner): raise AssertionError('borrowed proc owner must not be closed')
        with mock.patch.object(wpa.proc, 'ProcReader', PendingProc):
            with self.assertRaises(wpa.WpaStatusError) as error: reader.read_status(12.9)
        self.assertEqual(error.exception.code, 'close_unknown')
        row = source._actor_calls[0]
        self.assertIs(row['reader'], created[0]); self.assertIs(row['value'], value)
        self.assertIs(row['reader']._fd_refs[0][0], owner)
        self.assertTrue(row['returned']); self.assertTrue(row['unknown'])
        self.assertTrue(source._pending); self.assertTrue(reader.status()['resource_pending'])
        self.assertEqual(len(created), 1); self.assertNotIn('new_socket', self.io.calls)
    def test_proc_call_budget_rejects_before_default_reader_construction(self):
        source = wpa.LinuxStatusSource(manifest(), _io=self.io, _clock=self.clock)
        created = []
        def factory(timeout):
            value = FakeProc(); created.append(value); return value
        files = [wpa._ReadFiles(self.io, self.clock, 12.9, manifest()) for unused in range(3)]
        with mock.patch.object(wpa.proc, 'ProcReader', factory):
            for unused in range(4): source._actor(files[0])
            with self.assertRaises(wpa.WpaStatusError): source._actor(files[0])
            self.assertEqual(len(created), 4)
            for unused in range(4): source._actor(files[1])
            with self.assertRaises(wpa.WpaStatusError): source._actor(files[2])
        self.assertEqual(len(created), 8); self.assertEqual(len(source._actor_calls), 8)
    def test_wrong_reply_pid_or_uid_or_gid_rejected(self):
        for fields in ((988, 0, 0), (987, 1, 0), (987, 0, 1)):
            io = FakeIO(); sock = FakeSocket(io); io.sock = sock
            sock.ancillary = [(1, 2, struct.pack('=iII', *fields))]
            reader = wpa.AuthenticatedStatusReader(manifest(), _io=io, _proc_reader=io.proc, _clock=self.clock)
            with self.assertRaises(wpa.WpaStatusError) as error: reader.read_status(12.9)
            self.assertEqual(error.exception.code, 'credential_mismatch'); self.assertEqual(sock.close_count, 1)
    def test_missing_or_duplicate_credential_rejected(self):
        sock = self.socket(); sock.ancillary = []
        self.reject('receive_control'); self.assertEqual(sock.close_count, 1)
    def test_duplicate_credential_rejected(self):
        sock = self.socket(); cred = (1, 2, struct.pack('=iII', 987, 0, 0))
        sock.ancillary = [cred, cred]; self.reject('receive_control')
    def test_unknown_ancillary_never_clears_resource_uncertainty(self):
        self.socket().ancillary = [(1, 99, b'UNKNOWN')]
        self.reject('receive_control')
        self.assertTrue(self.reader.status()['resource_pending'])
        self.assertEqual(self.io.sock.close_count, 1)
    def test_source_file_inventory_over_128_uses_original_resource_chunks(self):
        old_names = self.io.listdir
        extra = [str(2000 + i) for i in range(150)]
        for name in extra: self.io.file('/proc/' + name + '/comm', b'unrelated\n')
        self.io.listdir = lambda path: old_names(path) + extra if path == '/proc' else old_names(path)
        self.read()
        for value, files in zip(self.reader._sources, self.reader._source._files):
            self.assertGreater(len(value['files_closed']), 1)
            self.assertEqual(sum(p.expected for p in value['files_closed']), len(files._tickets))
            self.assertTrue(all(p.complete() for p in value['files_closed']))
        self.assertEqual(len(self.io.closed), len(set(self.io.closed)))
    def test_closed_unrelated_proc_inventory_count_is_not_daemon_identity(self):
        old_names = self.io.listdir
        self.io.file('/proc/2000/comm', b'unrelated\n')
        self.socket().hook = lambda: setattr(self.io, 'listdir',
            lambda path: old_names(path) + ['2000'] if path == '/proc' else old_names(path))
        self.assertTrue(self.read()['source_authenticated'])
        counts = [sum(p.expected for p in value['files_closed']) for value in self.reader._sources]
        self.assertEqual(counts[1], counts[0] + 1)
    def test_wrong_reply_endpoint_rejected(self):
        self.socket().return_peer = '/run/foreign/wlan0'; self.reject('wrong_endpoint')
    def test_ctrl_event_and_fail_are_not_skipped(self):
        self.socket().packet = b'<3>CTRL-EVENT-CONNECTED\n'; self.reject('invalid_status')
        self.assertEqual(self.io.sock.sent, [b'STATUS'])
    def test_rights_in_rejected_packet_all_closed_once(self):
        sock = self.socket()
        for fd in (401, 402): self.io.live[fd] = metadata(inode=fd)
        sock.ancillary = [(1, 2, struct.pack('=iII', 987, 0, 0)), (1, 1, struct.pack('=ii', 401, 402))]
        self.reject('rights_rejected')
        self.assertEqual(self.reader.status()['rights_closed'], 2)
        self.assertFalse(self.reader.status()['resource_pending'])
        self.assertEqual(self.io.closed.count(401), 1); self.assertEqual(self.io.closed.count(402), 1)
    def test_truncated_control_retains_pending_even_after_known_closes(self):
        sock = self.socket(); sock.flags = 8
        self.reject('receive_truncated'); self.assertTrue(self.reader.status()['resource_pending'])
    def test_rights_malformed_trailing_bytes_keeps_unknown(self):
        sock = self.socket(); self.io.live[401] = metadata(inode=401)
        sock.ancillary = [(1, 1, struct.pack('=i', 401) + b'x')]
        self.reject('receive_control'); self.assertTrue(self.reader.status()['resource_pending'])
        self.assertEqual(self.io.closed.count(401), 1)
    def test_rights_close_error_does_not_skip_other_originals(self):
        sock = self.socket()
        for fd in (401, 402): self.io.live[fd] = metadata(inode=fd)
        self.io.close_error.add(401)
        sock.ancillary = [(1, 1, struct.pack('=ii', 401, 402))]
        self.reject('rights_rejected')
        self.assertEqual(sock.close_count, 1); self.assertEqual(self.io.closed.count(402), 1)
        self.assertTrue(self.reader.status()['resource_pending'])
    def test_rights_numeric_collision_with_command_fd_is_not_closed(self):
        sock = self.socket(); sock.ancillary = [(1, 1, struct.pack('=i', 400))]
        self.reject('receive_control'); self.assertEqual(self.io.closed.count(400), 1)
        self.assertTrue(self.reader._rights[0]['unknown'])
    def test_unknown_factory_retains_reference_and_cannot_retry(self):
        self.io.factory_error = RuntimeError('PRIVATE'); self.reject('io_error')
        self.assertTrue(self.reader.status()['resource_pending'])
        with self.assertRaises(wpa.WpaStatusError): self.read()
        self.assertEqual(self.io.calls.count('new_socket'), 1)
    def test_unknown_receive_stays_pending_and_closes_known_socket(self):
        sock = self.socket()
        def interrupted(*unused): raise KeyboardInterrupt('PRIVATE')
        sock.recvmsg = interrupted; self.reject('interrupted')
        self.assertTrue(self.reader.status()['resource_pending']); self.assertEqual(sock.close_count, 1)
    def test_failed_command_close_invalidates_success(self):
        self.socket().close_failure = True; self.reject('close_unknown')
        self.assertTrue(self.reader.status()['resource_pending'])
    def test_short_send_never_receives_or_retries(self):
        sock = self.socket(); sock.send_count = 5; self.reject('short_send')
        self.assertIsNone(sock.factory_flags); self.assertEqual(sock.sent, [b'STATUS'])
    def test_timeout_nanosecond_quantization(self):
        self.read(); self.assertGreater(self.io.sock.timeout, 0)
    def test_boolean_and_huge_budget_reject_without_io(self):
        for value in (True, 10 ** 1000, float('inf'), float('nan')):
            reader = wpa.AuthenticatedStatusReader(manifest(), _io=self.io, _proc_reader=self.io.proc, _clock=self.clock)
            with self.assertRaises(wpa.WpaStatusError): reader.read_status(value)
        self.assertEqual(self.io.calls, [])
    def test_public_status_has_no_path_actor_argv_or_ssid(self):
        self.read(); value = repr(self.reader.status())
        for text in ('wlan0', EXE, ENDPOINT, 'HOST', BOOT, '987', '2412'): self.assertNotIn(text, value)
        self.assertFalse(self.reader.status()['restoration_verified'])
    def test_single_thread_guard_refuses_multi_task_f(self):
        self.io.proc.self_actor = core.Actor(123, 100, ME.exe, ME.argv_sha, ((123, 100, 'R'), (124, 101, 'S')))
        self.reject('actor_unknown'); self.assertNotIn('new_socket', self.io.calls)
    def test_parse_status_strict_shape(self):
        for raw in (b'FAIL\n', b'UNKNOWN COMMAND\n', b'wpa_state=COMPLETED\n',
                b'wpa_state=INACTIVE\nwpa_state=INACTIVE\n', b'wpa_state=INACTIVE\r\n',
                b'wpa_state=INACTIVE\0\n', b'wpa_state=INACTIVE\nunknown=1\n',
                b'wpa_state=COMPLETED\nfreq=9999\n', b'wpa_state=INACTIVE', b'x' * 16385):
            with self.assertRaises(wpa.WpaStatusError): wpa.parse_status(raw)
        self.assertEqual(wpa.parse_status(b'wpa_state=INACTIVE\n')[b'wpa_state'], b'INACTIVE')
    def test_python35_ast_and_no_mutation_entrypoints(self):
        source = (Path(__file__).resolve().parents[1] / 'runtime' / 'mta_client_wpa_status.py').read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ('kill', 'unlink', 'Popen', 'spawn', 'listen', 'fork', 'waitpid'))
            if isinstance(node, ast.Constant) and type(node.value) is bytes:
                self.assertNotIn(node.value, (b'ATTACH', b'SCAN', b'PING', b'P2P_FIND', b'P2P_LISTEN'))


if __name__ == '__main__': unittest.main()
