# -*- coding: utf-8 -*-
"""Original FileRegistry handles -> private stored ZIP -> TLS 1.2 context.

Python 3.5; no socket, sending thread, radio or permission receipt. Selection
is borrowed, never reopened by path and never closed here. The prepared archive
remains this owner's original w+b handle. A caller must retain this owner before
prepare(), and finally close it with one separately supplied finite cleanup cap.

The fixed OpenSSL invocation has a <=10s slice of the original active cap.
communicate buffers that trusted tool's output, then enforces 16KiB per stream;
this is not a hard memory bound against a replaced/malicious executable. Private
0700 directory ownership is not a defence against concurrent privileged writes.
No unknown process/FD/path is retired or silently retried during cleanup.
"""
import binascii
import errno
import math
import os
import shutil
import ssl
import stat
import struct
import subprocess
import threading
import time
import zlib

import mta_files as files
from mta_protocol import validate_send_request, validate_task_id
from mta_storage import validate_member_name
from mta_transport import TransportError, Cancelled

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_FILES = 256
CHUNK_BYTES = 65536
MAX_TOOL_OUTPUT = 16384


class PreparationError(TransportError):
    pass


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise PreparationError('Invalid absolute time')
    return float(value)


def _path(value):
    if type(value) is not str or not value or '\x00' in value or not os.path.isabs(value):
        raise PreparationError('An explicit absolute path is required')
    return value


def _identity(value):
    return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode),
            value.st_uid, value.st_gid, value.st_nlink)


def _snapshot(handle):
    value = os.fstat(handle.fileno())
    if not stat.S_ISREG(value.st_mode):
        raise PreparationError('Selected input is not a regular file')
    return (_identity(value), value.st_size,
            value.st_mtime_ns if hasattr(value, 'st_mtime_ns') else value.st_mtime,
            value.st_ctime_ns if hasattr(value, 'st_ctime_ns') else value.st_ctime)


class _Fd(object):
    def __init__(self, role, handle=None):
        self.role, self.handle = role, handle
        self.fd = self.metadata = None
        self.open_called = self.wrapper_called = False
        self.close_called = self.closed = self.no_resource = self.unknown = False
        self.communicate_closed = False
        self.failure = None

    def capture(self):
        # handle/raw result is already strongly retained by the caller.
        if self.handle is not None:
            self.fd = self.handle.fileno()
        if type(self.fd) is not int or self.fd < 0:
            self.unknown = True
            raise PreparationError('Invalid original file descriptor')
        self.metadata = _identity(os.fstat(self.fd))


class PreparedSend(object):
    def __init__(self, selection, openssl_path, task_id, sender_id, absolute_until,
                 temp_root, progress=None, cancelled=None, clock=None):
        if type(selection) is not files.FileSelection:
            raise PreparationError('Use the original FileRegistry.open_selection')
        validate_task_id(task_id)
        if type(sender_id) is not str or not 1 <= len(sender_id) <= 128 or \
                any(ord(c) < 32 or ord(c) == 127 for c in sender_id):
            raise PreparationError('Invalid sender identity')
        for callback in (progress, cancelled, clock):
            if callback is not None and not callable(callback):
                raise PreparationError('Invalid preparation callback')
        self.selection = selection
        self.openssl_path, self.temp_root = _path(openssl_path), _path(temp_root)
        self.task_id, self.sender_id, self.until = task_id, sender_id, _time(absolute_until)
        self.progress, self.cancelled, self.clock = progress, cancelled or (lambda: False), clock or time.monotonic
        self.worker = threading.current_thread()
        self.archive_handle = self.tls_context = self.request_payload = None
        self.archive_size = self.file_count = self.total_bytes = 0
        self.called = self.prepared = self.close_called = self.closed = False
        self.failure = self.cleanup_failure = self.cleanup_until = None
        self._last = None
        self._selection_originals = None
        self._directory = self._directory_identity = None
        self._directory_called = self._directory_created = self._directory_unknown = False
        self._paths, self.fds = [], []
        self.process = None
        self.process_called = self.process_unknown = self.process_waited = False
        self.process_returncode = None
        self.communicate_called = self.terminate_called = False
        self.tool_stdout = self.tool_stderr = None  # Private bounded bytes only.

    def _worker(self):
        if threading.current_thread() is not self.worker:
            raise PreparationError('Preparation worker changed')

    def _now(self):
        self._worker()
        value = _time(self.clock())
        if self._last is not None and value < self._last:
            raise PreparationError('Preparation clock regressed')
        self._last = value
        return value

    def _check(self):
        if self.cancelled() is not False:
            raise Cancelled('Preparation cancelled')
        now = self._now()
        if now >= self.until or self.close_called:
            raise PreparationError('Preparation deadline exceeded or closed')
        return now

    def _cleanup_check(self):
        now = self._now()
        if now >= self.cleanup_until:
            raise PreparationError('Original cleanup cap expired')
        return now

    def _notify(self, state, count):
        if self.progress is not None:
            self.progress(state, {'sourceBytes': count, 'fileCount': self.file_count,
                                  'totalSize': self.total_bytes})
        self._check()

    def _selection_current(self, check_data=False):
        original = self._selection_originals
        if self.selection.closed is not False or self.selection._close_requested is not False:
            raise PreparationError('Original file selection was invalidated')
        if original is not None:
            registry, entries, resources, rows = original
            if (self.selection._registry is not registry or self.selection.entries is not entries or
                    self.selection._resources is not resources or len(entries) != len(rows) or
                    self.selection.total_bytes != self.total_bytes or registry._blocked is not False):
                raise PreparationError('Original file selection changed')
            for index, (entry, resource, name, size, handle, snapshot) in enumerate(rows):
                if (entries[index] is not entry or not any(r is resource for r in registry._resources) or
                        entry.get('name') != name or entry.get('size') != size or
                        entry.get('handle') is not handle or resource.handle is not handle or
                        resource.pending is not False or resource.claimed is not True or
                        resource.opening is not False or resource.transfer_unknown is not False or
                        resource.attempted is not False or resource.wrapper_closed is not False or
                        resource.fd_closed is not False or resource.raw_owned is not False or
                        resource.verified is not False or handle.closed is not False or
                        resource.fd != handle.fileno() or
                        check_data and _snapshot(handle) != snapshot):
                    raise PreparationError('Selected original handle changed')

    def _manifest(self):
        self._check(); self._selection_current()
        registry = self.selection._registry
        if type(registry) is not files.FileRegistry:
            raise PreparationError('Original FileRegistry required')
        with registry.lock:
            entries, resources = self.selection.entries, self.selection._resources
            if type(entries) is not list or not 1 <= len(entries) <= MAX_FILES or \
                    type(resources) is not tuple or len(resources) != len(entries):
                raise PreparationError('Selected file count limit')
            rows, total, seen = [], 0, []
            for index, (entry, resource) in enumerate(zip(entries, resources)):
                if type(entry) is not dict or type(resource) is not files._FileResource or resource.registry is not registry:
                    raise PreparationError('Original selected resource required')
                name, size, handle = entry['name'], entry['size'], entry['handle']
                validate_member_name(name)
                member = str(index) + '/' + name
                validate_member_name(member)
                if type(size) is not int or not 0 <= size <= 256 * 1024 * 1024 or \
                        resource.handle is not handle or resource.claimed is not True or resource.pending is not False or \
                        resource.opening is not False or resource.transfer_unknown is not False or \
                        resource.attempted is not False or resource.wrapper_closed is not False or resource.fd_closed is not False or \
                        resource.raw_owned is not False or resource.verified is not False or \
                        handle.closed is not False or resource.fd != handle.fileno() or \
                        any(handle is prior for prior in seen) or not any(resource is r for r in registry._resources):
                    raise PreparationError('Invalid selected resource')
                seen.append(handle)
                snapshot = _snapshot(handle)
                if snapshot[1] != size:
                    raise PreparationError('Selected file size changed')
                rows.append((entry, resource, name, size, handle, snapshot)); total += size
                if total > MAX_ARCHIVE - 1024 * 1024:
                    raise PreparationError('Selected total byte limit')
            if type(self.selection.total_bytes) is not int or total != self.selection.total_bytes:
                raise PreparationError('Selection byte count mismatch')
            self.file_count, self.total_bytes = len(rows), total
            self._selection_originals = (registry, entries, resources, tuple(rows))
        self._check(); self._selection_current(True)
        return rows

    def _directory_current(self):
        if not self._directory_created or self._directory_identity is None or \
                _identity(os.lstat(self._directory)) != self._directory_identity:
            raise PreparationError('Original private directory changed')

    def _make_directory(self):
        self._check()
        root = os.lstat(self.temp_root)
        if not stat.S_ISDIR(root.st_mode) or os.path.realpath(self.temp_root) != os.path.abspath(self.temp_root):
            raise PreparationError('Temporary root must be an existing real directory')
        self._check()
        name = 'p011-send-' + binascii.hexlify(os.urandom(16)).decode('ascii')
        self._directory = os.path.join(self.temp_root, name)  # Before mkdir.
        self._check(); self._directory_called = True
        try:
            os.mkdir(self._directory, 0o700)
            self._directory_created = True
            value = os.lstat(self._directory)
            self._directory_identity = _identity(value)  # Before a late check.
            if not stat.S_ISDIR(value.st_mode) or os.name != 'nt' and stat.S_IMODE(value.st_mode) != 0o700:
                raise PreparationError('Private directory mode changed')
        except BaseException:
            self._directory_unknown = self._directory_created or self._directory_identity is None
            raise
        self._check()
        if shutil.disk_usage(self._directory).free < self.total_bytes + 17 * 1024 * 1024:
            raise PreparationError('Insufficient archive temporary space')
        self._check()

    def _new_path(self, name, tool_output=False):
        row = {'path': os.path.join(self._directory, name), 'metadata': None,
               'unlink_called': False, 'unlinked': False, 'unknown': False, 'tool_output': tool_output}
        self._paths.append(row)
        return row

    def _write(self, output, data):
        self._check()
        returned = output.write(data)
        if type(returned) is not int or returned != len(data):
            raise PreparationError('Archive write was incomplete')
        self._check()

    def _archive(self, rows):
        path = self._new_path('payload.zip')
        fd = _Fd('archive'); self.fds.append(fd)
        self._check(); self._directory_current(); self._check()
        fd.open_called = True
        try:
            fd.fd = os.open(path['path'], os.O_RDWR | os.O_CREAT | os.O_EXCL |
                           getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0), 0o600)
        except OSError as error:
            fd.failure = error
            if type(error.errno) is int and 1 <= error.errno <= 4095:
                fd.no_resource = fd.closed = True
            else: fd.unknown = True
            raise
        except BaseException as error:
            fd.failure, fd.unknown = error, True; raise
        fd.capture(); path['metadata'] = fd.metadata  # Original return before cap.
        self._check(); fd.wrapper_called = True
        try:
            fd.handle = os.fdopen(fd.fd, 'w+b')
            self.archive_handle = fd.handle  # Strong original before validation.
            if fd.handle.fileno() != fd.fd or fd.handle.closed is not False or \
                    fd.handle.readable() is not True or fd.handle.writable() is not True:
                raise PreparationError('Original archive wrapper changed')
        except BaseException as error:
            fd.failure, fd.unknown = error, True; raise
        self._check()
        output, central, actual_total = fd.handle, [], 0
        for index, (entry, resource, name, size, source, snapshot) in enumerate(rows):
            self._check(); self._selection_current()
            if _snapshot(source) != snapshot:
                raise PreparationError('Selected file changed before packaging')
            member = (str(index) + '/' + name).encode('utf-8')
            if len(member) > 65535:
                raise PreparationError('ZIP member name limit')
            offset = output.tell()
            self._write(output, struct.pack('<I5H3I2H', 0x04034b50, 20, 0x0808, 0, 0, 33, 0, 0, 0, len(member), 0))
            self._write(output, member)
            source.seek(0); self._check()
            crc, actual = 0, 0
            while True:
                self._check(); self._selection_current()
                data = source.read(CHUNK_BYTES)
                self._check()
                if type(data) is not bytes or len(data) > CHUNK_BYTES:
                    raise PreparationError('Selected input read limit')
                if not data: break
                actual += len(data); actual_total += len(data)
                if actual > size or actual_total > self.total_bytes:
                    raise PreparationError('Selected file grew during packaging')
                crc = zlib.crc32(data, crc) & 0xffffffff
                self._write(output, data)
                if output.tell() > MAX_ARCHIVE:
                    raise PreparationError('Archive byte limit')
                self._notify('packaging', actual_total)
            if actual != size or _snapshot(source) != snapshot:
                raise PreparationError('Selected file changed during packaging')
            self._write(output, struct.pack('<4I', 0x08074b50, crc, actual, actual))
            central.append(struct.pack('<I6H3I5H2I', 0x02014b50, (3 << 8) | 20, 20, 0x0808,
                0, 0, 33, crc, actual, actual, len(member), 0, 0, 0, 0,
                (stat.S_IFREG | 0o600) << 16, offset) + member)
        self._check(); start = output.tell()
        for value in central:
            self._write(output, value)
        central_size = output.tell() - start
        self._write(output, struct.pack('<I4H2IH', 0x06054b50, 0, 0, len(central), len(central), central_size, start, 0))
        self._check(); output.flush(); self._check(); os.fsync(fd.fd); self._check()
        self.archive_size = os.fstat(fd.fd).st_size
        if actual_total != self.total_bytes or not 1 <= self.archive_size <= MAX_ARCHIVE:
            raise PreparationError('Archive final size mismatch')
        output.seek(0); self._check(); self._selection_current(True)

    def _settle_pipes(self):
        # communicate itself closes its original streams. Immediately retain
        # real closed + EBADF before any new file open could reuse that number.
        for row in self.fds:
            if row.role not in ('stdout', 'stderr') or row.metadata is None or row.closed:
                continue
            try:
                if row.handle.closed is True:
                    try: os.fstat(row.fd)
                    except OSError as error:
                        if type(error.errno) is int and error.errno == errno.EBADF:
                            row.closed, row.communicate_closed = True, True
                            continue
                    row.unknown = True
            except BaseException as error:
                row.failure, row.unknown = error, True  # Never replace the primary exception.

    def _terminate(self):
        if self.process is not None and not self.process_waited and not self.terminate_called:
            self.terminate_called = True
            self.process.terminate()  # Only this original Popen; no global PID/name.

    def _certificate(self):
        key, cert = self._new_path('server-key.pem', True), self._new_path('server-cert.pem', True)
        argv = [self.openssl_path, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', key['path'], '-out', cert['path'], '-days', '1', '-subj', '/CN=P011-MTA']
        self._check(); self._directory_current(); self._check()
        self.process_called = True
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, shell=False, close_fds=True)
        except BaseException:
            self.process_unknown = True; raise
        # Retain ALL original streams before the first per-stream readback.
        pipe_rows = [_Fd('stdout', self.process.stdout), _Fd('stderr', self.process.stderr)]
        self.fds.extend(pipe_rows)
        for row in pipe_rows:
            try: row.capture()
            except BaseException as error:
                row.failure, row.unknown = error, True; raise
        remaining = self.until - self._check()
        self.communicate_called = True
        try:
            stdout, stderr = self.process.communicate(timeout=min(10.0, remaining))
        except subprocess.TimeoutExpired:
            # Stop-only own child; close() supplies the original bounded wait.
            try: self._terminate()
            except BaseException as error: self.cleanup_failure = error
            raise
        finally:
            self._settle_pipes()
        self.process_returncode = self.process.returncode
        self.process_waited = type(self.process_returncode) is int
        self._check()
        if type(stdout) is not bytes or type(stderr) is not bytes:
            raise PreparationError('Invalid certificate output')
        self.tool_stdout, self.tool_stderr = stdout[:MAX_TOOL_OUTPUT], stderr[:MAX_TOOL_OUTPUT]
        if len(stdout) > MAX_TOOL_OUTPUT or len(stderr) > MAX_TOOL_OUTPUT or self.process_returncode != 0:
            raise PreparationError('Certificate tool failed or exceeded output limit')
        for row in (key, cert):
            self._check(); self._directory_current()
            value = os.lstat(row['path'])
            if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
                raise PreparationError('Certificate output is not a private regular file')
            row['metadata'] = _identity(value)
            self._check(); os.chmod(row['path'], 0o600); self._check()
            if _identity(os.lstat(row['path'])) != row['metadata']:
                raise PreparationError('Certificate output changed')
        self._check()
        self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.tls_context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5:!RC4')
        self._check(); self.tls_context.load_cert_chain(cert['path'], key['path']); self._check()

    def prepare(self):
        self._worker()
        if self.called: raise PreparationError('Preparation cannot be retried')
        self.called = True
        try:
            rows = self._manifest()
            self._make_directory(); self._archive(rows); self._certificate()
            self._check(); self._selection_current(True)
            self.request_payload = {'taskId': self.task_id, 'id': self.task_id, 'senderId': self.sender_id,
                'senderName': 'P011', 'fileName': rows[0][2], 'mimeType': 'application/octet-stream',
                'fileCount': self.file_count, 'totalSize': self.total_bytes}
            validate_send_request(self.request_payload)
            self.prepared = True; self._notify('prepared', self.total_bytes)
            self._selection_current(True)
            self._check()
            return self
        except BaseException as error:
            self.failure = error; self.prepared = False
            raise

    def _close_fd(self, row):
        if row.closed: return
        if row.close_called or row.unknown or row.metadata is None:
            raise PreparationError('Original descriptor closure is unknown')
        self._cleanup_check()
        if _identity(os.fstat(row.fd)) != row.metadata:
            row.unknown = True
            raise PreparationError('Original descriptor changed before close')
        self._cleanup_check()
        row.close_called = True
        try:
            returned = row.handle.close() if row.handle is not None else os.close(row.fd)
            wrapper_closed = row.handle is None or row.handle.closed is True
            try: os.fstat(row.fd)
            except OSError as error:
                row.closed = returned is None and wrapper_closed and type(error.errno) is int and error.errno == errno.EBADF
            if not row.closed: row.unknown = True
        except BaseException as error:
            row.failure, row.unknown = error, True; raise
        self._cleanup_check()
        if not row.closed: raise PreparationError('Original descriptor close pending')

    def _remove_paths(self):
        if not self._directory_created:
            if self._directory_called: raise PreparationError('Private directory creation unknown')
            return
        if self._directory_unknown: raise PreparationError('Private directory identity unknown')
        self._cleanup_check(); self._directory_current()
        expected = set(os.path.basename(r['path']) for r in self._paths)
        if set(os.listdir(self._directory)) - expected:
            raise PreparationError('Unexpected private directory entry')
        for row in self._paths:
            if row['unlinked']: continue
            if row['unlink_called'] or row['unknown']:
                raise PreparationError('Original unlink is pending')
            self._cleanup_check(); self._directory_current()
            try: value = os.lstat(row['path'])
            except OSError as error:
                if type(error.errno) is int and error.errno == errno.ENOENT and row['metadata'] is None:
                    row['unlinked'] = True; continue
                raise
            observed = _identity(value)
            if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or
                    observed[3:5] != self._directory_identity[3:5] or
                    row['metadata'] is not None and observed != row['metadata'] or
                    row['metadata'] is None and not (row['tool_output'] and self.process_waited)):
                row['unknown'] = True
                raise PreparationError('Private output identity changed')
            # Failed fixed-tool output may have been created before exit. Only
            # after the original process/pipes are closed can it be adopted.
            row['metadata'] = observed
            self._cleanup_check(); row['unlink_called'] = True
            try:
                os.unlink(row['path'])
                try: os.lstat(row['path'])
                except OSError as error:
                    row['unlinked'] = type(error.errno) is int and error.errno == errno.ENOENT
                if not row['unlinked']: row['unknown'] = True
            except BaseException:
                row['unknown'] = True; raise
            self._cleanup_check()
        self._cleanup_check(); self._directory_current()
        if os.listdir(self._directory): raise PreparationError('Private directory is not empty')
        self._cleanup_check()
        os.rmdir(self._directory)
        try: os.lstat(self._directory)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self._directory_created = False
            else: raise
        self._cleanup_check()
        if self._directory_created: raise PreparationError('Private directory removal pending')

    def close(self, cleanup_until):
        self._worker()
        cap = _time(cleanup_until)
        if self.close_called:
            if cap != self.cleanup_until: raise PreparationError('Cleanup cap cannot be replaced')
            return self.closed
        now = self._now()
        if cap > min(now + 60.0, self.until + 60.0):
            raise PreparationError('Cleanup cap exceeds the original bounded allowance')
        self.cleanup_until, self.close_called = cap, True
        try:
            if self.process_unknown: raise PreparationError('Original certificate process is unknown')
            if self.process is not None and not self.process_waited:
                self._cleanup_check()
                if self.process.poll() is None:
                    self._cleanup_check(); self._terminate()
                remaining = cap - self._cleanup_check()
                self.process_returncode = self.process.wait(timeout=min(3.0, remaining))
                self.process_waited = type(self.process_returncode) is int
                self._cleanup_check()
            if self.process_called and not self.process_waited:
                raise PreparationError('Original certificate process has not been reaped')
        except BaseException as error:
            self.cleanup_failure = error
        # Independent original FD attempts continue even when another fails.
        for row in reversed(self.fds):
            try: self._close_fd(row)
            except BaseException as error:
                if self.cleanup_failure is None: self.cleanup_failure = error
        if not self.process_unknown and (not self.process_called or self.process_waited) and all(r.closed and not r.unknown for r in self.fds):
            try: self._remove_paths()
            except BaseException as error:
                if self.cleanup_failure is None: self.cleanup_failure = error
        self.closed = (self.cleanup_failure is None and not self.process_unknown and
            (not self.process_called or self.process_waited) and
            all(r.closed and not r.unknown for r in self.fds) and
            not self._directory_created and not self._directory_unknown)
        return self.closed

    def status(self):
        return {'prepared': self.prepared, 'failed': self.failure is not None,
                'fileCount': self.file_count, 'totalSize': self.total_bytes, 'archiveSize': self.archive_size,
                'owned_fd_count': len(self.fds), 'closed_fd_count': sum(r.closed for r in self.fds),
                'process_waited': self.process_waited, 'close_called': self.close_called,
                'private_directory_removed': self._directory_called and not self._directory_created and not self._directory_unknown,
                'resource_pending': not self.closed, 'closure_verified': self.closed,
                'selection_borrowed': True, 'selection_closed_by_preparation': False}
