# -*- coding: utf-8 -*-
"""Private parent/F send IPC, Python 3.5; explicit calls only.

The parent keeps FileSelection, PreparedSend and ECDH private key originals.
Only its held archive/certificate/key descriptors and bounded task DATA cross
exec. No Python lease, GATT receipt, NetworkReceipt or readiness is serialized.
The fixed GO F owns native GO/DHCP/STA/TCP/TLS on its single original worker.
This module does not stage a deployment, enable State admission or start RF at
import/constructor time. Its State branch and sealed deployment must be supplied
by their actual producers, not arbitrary paths/commands from a browser.

All stdout frames below are PRIVATE pipes, never a public log. A parsed child
restore field is only a report, not an independently verified native receipt.
Popen failures/late returns and partial FD wrappers remain strongly retained.
No signal/recovery/delete command is issued by this parent bridge.
"""
import base64
import errno
import hashlib
import math
import os
import re
import select
import ssl
import stat
import subprocess
import threading
import time

import p011_json as json

MAX_FRAME = 8192
MAX_PRIVATE_ERROR = 16384
_INVENTORY = []
_BIND_KEYS = frozenset(('run', 'manifest', 'task', 'nonce', 'native_epoch',
                       'operation_epoch', 'until', 'parent_pid'))


class SendBridgeError(RuntimeError):
    pass


def _fail(code): raise SendBridgeError(code)
def _number(value):
    if type(value) not in (int, float) or not 0 < value < 1e12 or not math.isfinite(value):
        _fail('invalid_absolute_until')
    return float(value)
def _uint(value, low=0, high=2 ** 53): return type(value) is int and low <= value <= high
def _hex(value, size): return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None
def _metadata(fd):
    value = os.fstat(fd)
    row = tuple(getattr(value, name, None) for name in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    if any(not _uint(v, 0, 2 ** 64 - 1) for v in row): _fail('descriptor_metadata_unknown')
    return row
def _pipe_identity(fd): return _metadata(fd)[:6]
def _file_identity(metadata): return metadata[:2] + (stat.S_IFMT(metadata[2]),) + metadata[3:6]
def _wire(value):
    if type(value) is not dict: _fail('frame_not_object')
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
    if len(raw) > MAX_FRAME: _fail('frame_limit')
    return raw
def _decode(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_FRAME or not raw.endswith(b'\n'):
        _fail('frame_limit')
    try: value = json.loads(raw[:-1].decode('ascii'))
    except (ValueError, UnicodeError): _fail('frame_format')
    if type(value) is not dict or _wire(value) != raw: _fail('noncanonical_frame')
    return value
def _binding(value):
    if (type(value) is not dict or set(value) != _BIND_KEYS or not _hex(value['run'], 32) or
        not _hex(value['manifest'], 64) or not _hex(value['nonce'], 32) or
        type(value['task']) is not str or re.fullmatch('[A-Za-z0-9_-]{1,96}', value['task']) is None or
        not _uint(value['native_epoch'], 1) or not _uint(value['operation_epoch'], 1) or
        not _uint(value['parent_pid'], 1, 0x7fffffff) or type(value['until']) is not str or
        repr(_number(float(value['until']))) != value['until']):
        _fail('invalid_binding')
    return value


class _Fd(object):
    def __init__(self, role):
        self.role, self.fd, self.value, self.metadata = role, None, None, None
        self.called = self.returned = self.close_called = self.closed = self.unknown = False
        self.failure = None
    def capture(self, fd, value=None, pipe=False):
        self.fd, self.value, self.returned = fd, value, True  # Before fstat/late check.
        if not _uint(fd, 0, 0x7fffffff): self.unknown = True; _fail('invalid_descriptor')
        self.metadata = _pipe_identity(fd) if pipe else _metadata(fd)
    def current(self, pipe=False):
        if self.closed or self.unknown or self.metadata is None or (
                _pipe_identity(self.fd) if pipe else _metadata(self.fd)) != self.metadata:
            _fail('original_descriptor_changed')
    def close(self):
        if self.closed: return True
        if self.close_called or self.unknown or self.metadata is None: return False
        self.close_called = True
        try:
            self.current(pipe=stat.S_ISFIFO(self.metadata[2]))
            result = self.value.close() if self.value is not None else os.close(self.fd)
            try: os.fstat(self.fd)
            except OSError as error:
                self.closed = result is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException as error: self.failure = error
        if not self.closed: self.unknown = True
        return self.closed


class SendTaskChannel(object):
    """F-owned inherited pipe/FD inventory. START once, SELECTED once, stop-only.

    Actual GoSendLaunch in the canonical F validates this retained START against
    its original entry/deployment and verifies the original parent Proc actor.
    Constructor never treats these DATA as a native network/GATT permission.
    """
    def __init__(self, entry):
        self.entry, self.worker, self.clock, self.until = entry, entry.worker, entry.clock, entry.until
        self.rows, self.input, self.output, self.start = [], None, None, None
        self.buffer, self.raw, self.selected, self.stop = b'', [], None, False
        self.read_seq, self.write_seq = 0, 0
        self.archive_handle = self.context = None
        self.failure = self.cleanup_until = None
        self.close_called = self.closed = False
    def _check(self):
        if threading.current_thread() is not self.worker or self.close_called: _fail('channel_owner_changed')
        now = _number(self.clock())
        if now >= self.until or self.stop: _fail('send_stopped')
        return now
    def _adopt(self, role, fd, expected=None, pipe=False):
        row = _Fd(role); self.rows.append(row); row.called = True
        row.capture(fd, pipe=pipe)
        if any(r is not row and r.fd == fd for r in self.rows): _fail('inherited_fd_alias')
        if (pipe and (not stat.S_ISFIFO(row.metadata[2]) or row.metadata[3:5] != (0, 0)) or
            not pipe and (not stat.S_ISREG(row.metadata[2]) or row.metadata[3:5] != (0, 0) or
                          row.metadata[5] not in ((1, 2) if role == 'python' else (1,)) or
                          row.metadata[2] & 0o022) or
            expected is not None and list(row.metadata) != expected):
            _fail('inherited_fd_identity')
        return row
    def open(self):
        self._check()
        if self.input is not None: _fail('channel_already_open')
        self.input = self._adopt('stdin', 0, pipe=True)
        self.output = self._adopt('stdout', 1, pipe=True)
        os.set_blocking(0, False); os.set_blocking(1, False)
        while self.start is None:
            self.poll()
            if self.start is None:
                now = self._check(); select.select([0], [], [], min(.05, self.until - now))
        data = self.start['data']
        if type(data) is not dict or set(data) != {'archive', 'cert', 'key', 'python', 'size', 'count', 'total', 'request'}:
            _fail('start_data_invalid')
        if not _uint(data['size'], 1, 512 * 1024 * 1024) or not _uint(data['count'], 1, 256) or not _uint(data['total'], 0, 512 * 1024 * 1024):
            _fail('archive_count_invalid')
        adopted = []
        for name in ('archive', 'cert', 'key', 'python'):
            item = data[name]
            if type(item) is not dict or set(item) != {'fd', 'metadata'} or not _uint(item['fd'], 3, 0x7fffffff):
                _fail('archive_descriptor_invalid')
            row = self._adopt(name, item['fd'], item['metadata']); adopted.append(row)
        archive, cert, key, executable = adopted
        digest, count = hashlib.sha256(), 0
        while True:
            self._check(); chunk = os.read(executable.fd, min(65536, 67108865 - count))
            digest.update(chunk); count += len(chunk)
            if count > 67108864: _fail('inherited_python_size')
            if not chunk: break
        if digest.hexdigest() != self.entry.deployment.manifest.python_sha or count != executable.metadata[6]:
            _fail('inherited_python_pin')
        executable.current(); self._check()
        if archive.metadata[6] != data['size']: _fail('archive_size_changed')
        archive.called = True  # fdopen transfer is retained before the native wrapper.
        try:
            archive.value = os.fdopen(archive.fd, 'rb', 0)
            if archive.value.fileno() != archive.fd: _fail('archive_wrapper_changed')
        except BaseException: archive.unknown = True; raise
        self.archive_handle = archive.value
        self.archive_handle.seek(0)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5:!RC4')
        self._check()
        self.context.load_cert_chain('/proc/self/fd/' + str(cert.fd), '/proc/self/fd/' + str(key.fd))
        self._check()
        for row in adopted: row.current()
        return self
    def poll(self):
        if self.stop: return True
        self._check(); self.input.current(pipe=True)
        ready = select.select([self.input.fd], [], [], 0)[0]
        if ready:
            try: chunk = os.read(self.input.fd, MAX_FRAME + 1)
            except OSError as error:
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK): return False
                raise
            self.raw.append(chunk)
            if not chunk: self.stop = True; return True
            self.buffer += chunk
            if len(self.buffer) > 2 * MAX_FRAME: _fail('input_buffer_limit')
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1); line += b'\n'
            if line == b'CANCEL\n': self.stop = True; return True
            frame = _decode(line)
            if set(frame) != {'kind', 'seq', 'binding', 'data'} or not _uint(frame['seq'], 1, 2) or frame['seq'] != self.read_seq + 1:
                _fail('input_sequence')
            binding = _binding(frame['binding'])
            if self.start is None:
                if frame['kind'] != 'START' or frame['seq'] != 1: _fail('start_required')
                self.start = frame
            else:
                if binding != self.start['binding'] or frame['kind'] != 'SELECTED' or self.selected is not None:
                    _fail('selection_replay_or_binding')
                self.selected = frame
            self.read_seq += 1
        if len(self.buffer) > MAX_FRAME: _fail('input_frame_limit')
        self._check(); return self.stop
    def emit(self, kind, data):
        self._check(); self.output.current(pipe=True)
        self.write_seq += 1
        raw = _wire({'kind': kind, 'seq': self.write_seq, 'binding': self.start['binding'], 'data': data})
        now = self._check()
        if not select.select([], [1], [], min(.2, self.until - now))[1]: _fail('output_not_ready')
        self._check()
        written = os.write(1, raw)  # One attempt. A short write is unknown, never retransmit.
        if type(written) is not int or written != len(raw): _fail('output_short_write')
        self._check()
    def emit_terminal(self, data, cleanup_until):
        # Cleanup-only stdout report, including failure after active expiry.
        # Never performs RF, starts work or issues a renewed network period.
        cap = _number(cleanup_until)
        if threading.current_thread() is not self.worker or self.close_called or cap > self.until + 60:
            _fail('terminal_cleanup_owner')
        self.output.current(pipe=True); self.write_seq += 1
        raw = _wire({'kind': 'RESULT', 'seq': self.write_seq, 'binding': self.start['binding'], 'data': data})
        now = _number(self.clock())
        if now >= cap or not select.select([], [1], [], min(.2, cap - now))[1]: _fail('terminal_output_expired')
        if _number(self.clock()) >= cap: _fail('terminal_output_expired')
        count = os.write(1, raw)
        if type(count) is not int or count != len(raw) or _number(self.clock()) >= cap: _fail('terminal_output_unknown')
    def close(self, cleanup_until):
        if threading.current_thread() is not self.worker: _fail('channel_worker_changed')
        if self.close_called: return self.closed
        cap, now = _number(cleanup_until), _number(self.clock())
        if not now < cap <= min(now + 60, self.until + 60): _fail('channel_cleanup_cap')
        self.cleanup_until, self.close_called = cap, True
        for row in reversed(self.rows):
            if _number(self.clock()) >= cap: break
            row.close()
        self.closed = all(r.closed and not r.unknown for r in self.rows)
        return self.closed


class GoSendBridge(object):
    """Same-State worker parent. start GO/listen BEFORE begin_scan/read/write.

    The caller retains this object before start, and finally calls close once.
    It must create its deployment and PreparedSend on the SAME original task
    cap/worker. Existing State32 does not call this branch or enable admission.
    """
    def __init__(self, state, operation, prepared, deployment):
        # Parent imports are intentionally lazy: F private graph has no State.
        import mta_service as service
        from mta_send_preparation import PreparedSend
        if type(state) is not service.State or type(operation) is not service.Operation or type(prepared) is not PreparedSend:
            _fail('original_parent_types_required')
        sources = deployment.modules.get('mta_go_deployment')
        if sources is None or type(deployment) is not sources.LoadedGoDeployment or deployment.launch_kind != 'parent_files':
            _fail('original_parent_file_deployment_required')
        self.state, self.operation, self.prepared, self.deployment = state, operation, prepared, deployment
        self.sources, self.worker, self.clock = sources, threading.current_thread(), time.monotonic
        self.until = deployment.loader.original_until
        self.file_ids = getattr(operation, 'send_file_ids', None)
        if type(self.file_ids) is not tuple or not 1 <= len(self.file_ids) <= 256 or any(
                type(v) is not str or not 1 <= len(v) <= 128 for v in self.file_ids) or len(set(self.file_ids)) != len(self.file_ids):
            _fail('original_prepared_file_ids_required')
        self.nonce = None  # Issued once in start, not in the pure constructor.
        self.binding = {'run': deployment.manifest.run_token, 'manifest': deployment.manifest_sha,
            'task': prepared.task_id, 'nonce': self.nonce, 'native_epoch': state.native_epoch,
            'operation_epoch': operation.epoch, 'until': deployment.loader.original_until_text, 'parent_pid': os.getpid()}
        self.rows, self.raw_frames, self.frame_history, self.private_stderr = [], [], [], b''
        self.stdout_raw, self.output_eof, self.error_eof = b'', False, False
        self.process = self.input = self.output = self.error_pipe = None
        self._process_original = self._process_pid = None
        self.called = self.process_called = self.process_unknown = self.process_reaped = False
        self.close_called = self.closed = self.cancel_sent = False
        self.failure = self.cleanup_until = self.returncode = self.result = None
        self.listening = self.scan = self.intent = self.peer_info = self.key = self.crypto = None
        self._native_phase, self._native_queue, self._native_failure = None, [], None
        self._read_started = self._gatt_until = None
        self._condition = threading.Condition()
        self._buffer, self._read_seq, self._write_seq = b'', 0, 0
        self._terminal_until = None
        self._originals = (state, operation, prepared, deployment, deployment.loader, self.worker, self.binding)
        _INVENTORY.append(self)
    def _check(self):
        if (threading.current_thread() is not self.worker or self._originals !=
            (self.state, self.operation, self.prepared, self.deployment, self.deployment.loader, self.worker, self.binding) or
            self.state.operation is not self.operation or self.state.session is not self.operation.session or
            getattr(self.operation, 'send_bridge', None) is not self or
            getattr(self.operation, 'send_file_ids', None) is not self.file_ids or
            self.operation.epoch != self.state.native_epoch or self.operation.cancelled.is_set() or
            self.binding['run'] != self.deployment.manifest.run_token or self.binding['manifest'] != self.deployment.manifest_sha or
            self.binding['native_epoch'] != self.operation.epoch or self.binding['operation_epoch'] != self.operation.epoch or
            self.binding['until'] != self.deployment.loader.original_until_text or self.binding['parent_pid'] != os.getpid() or
            self.prepared.until != self.until or self.prepared.closed or not self.prepared.prepared or
            self.deployment.manifest.task_id != self.prepared.task_id or self.binding['task'] != self.prepared.task_id or
            self.binding['nonce'] != self.nonce): _fail('send_parent_changed')
        self.deployment.loader.authenticate(self.deployment)
        self._process_current()
        now = _number(self.clock())
        if now >= self.until: _fail('send_deadline')
        return now
    def _process_current(self):
        if self.process is None:
            if self._process_original is not None: _fail('process_original_changed')
        elif self.process is not self._process_original or type(self.process.pid) is not int or self.process.pid != self._process_pid:
            _fail('process_original_changed')
    def _open(self, role, path, pin=None, maximum=67108864):
        row = _Fd(role); self.rows.append(row); self._check(); row.called = True
        try: row.capture(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
        except BaseException: row.unknown = True; raise
        if not stat.S_ISREG(row.metadata[2]) or row.metadata[3:5] != (0, 0) or row.metadata[2] & 0o022:
            _fail('private_file_identity')
        if not 1 <= row.metadata[6] <= maximum: _fail('private_file_size')
        if pin is not None:
            digest, size = hashlib.sha256(), 0
            while True:
                self._check(); chunk = os.read(row.fd, min(65536, maximum + 1 - size))
                if type(chunk) is not bytes: _fail('executable_read')
                digest.update(chunk); size += len(chunk)
                if size > maximum: _fail('executable_size')
                if not chunk: break
            if digest.hexdigest() != pin or size != row.metadata[6]: _fail('python_pin_changed')
            os.lseek(row.fd, 0, os.SEEK_SET)
        row.current(); self._check(); return row
    def _send(self, kind, data):
        self._check(); self.input.current(pipe=True); self._write_seq += 1
        raw = _wire({'kind': kind, 'seq': self._write_seq, 'binding': self.binding, 'data': data})
        now = self._check()
        if not select.select([], [self.input.fd], [], min(.2, self.until - now))[1]: _fail('input_not_ready')
        self._check()
        count = os.write(self.input.fd, raw)
        if type(count) is not int or count != len(raw): _fail('input_short_write')
        self._check()
    def start(self):
        self._check()
        if self.called: _fail('send_launch_once')
        self.called = True
        try:
            self.nonce = os.urandom(16).hex(); self.binding['nonce'] = self.nonce; _binding(self.binding)
            from mta_send_preparation import PreparedSend
            PreparedSend._selection_current(self.prepared, True)
            if len(self.file_ids) != self.prepared.file_count or len(self.prepared.selection.entries) != len(self.file_ids):
                _fail('prepared_file_count_changed')
            certs = dict((os.path.basename(r['path']), r) for r in self.prepared._paths)
            cert = self._open('cert', certs['server-cert.pem']['path'], maximum=16384)
            key = self._open('key', certs['server-key.pem']['path'], maximum=16384)
            if _file_identity(cert.metadata) != certs['server-cert.pem']['metadata'] or _file_identity(key.metadata) != certs['server-key.pem']['metadata']:
                _fail('prepared_certificate_changed')
            archive_fd = self.prepared.archive_handle.fileno()
            archive_meta = _metadata(archive_fd)
            if not stat.S_ISREG(archive_meta[2]) or archive_meta[6] != self.prepared.archive_size: _fail('prepared_archive_changed')
            executable = self._open('python', self.sources.PYTHON, self.deployment.manifest.python_sha)
            argv = (self.sources.PYTHON, '-B', self.deployment.manifest.executor, '--go-bootstrap',
                '--run-token', self.binding['run'], '--manifest-sha256', self.binding['manifest'], '--until', self.binding['until'])
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'P011_GO_SEND': '1'}
            self._check(); self.process_called = True
            try:
                self.process = subprocess.Popen(argv, executable='/proc/self/fd/' + str(executable.fd),
                    env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    close_fds=True, pass_fds=(archive_fd, cert.fd, key.fd, executable.fd), bufsize=0)
            except BaseException: self.process_unknown = True; raise
            self._process_original = self.process
            self._process_pid = self.process.pid
            if not _uint(self._process_pid, 1, 0x7fffffff): self.process_unknown = True; _fail('process_pid_unknown')
            # All returned pipe originals are retained before metadata/late checks.
            for role, value in (('stdin', self.process.stdin), ('stdout', self.process.stdout), ('stderr', self.process.stderr)):
                row = _Fd(role); row.value = value; self.rows.append(row)
                setattr(self, {'stdin': 'input', 'stdout': 'output', 'stderr': 'error_pipe'}[role], row)
            for row in (self.input, self.output, self.error_pipe):
                row.capture(row.value.fileno(), row.value, pipe=True); os.set_blocking(row.fd, False)
            self._check()
            self._send('START', {'archive': {'fd': archive_fd, 'metadata': list(archive_meta)},
                'cert': {'fd': cert.fd, 'metadata': list(cert.metadata)}, 'key': {'fd': key.fd, 'metadata': list(key.metadata)},
                'python': {'fd': executable.fd, 'metadata': list(executable.metadata)},
                'size': self.prepared.archive_size, 'count': self.prepared.file_count,
                'total': self.prepared.total_bytes, 'request': self.prepared.request_payload})
            self.listening = self._wait_frame('LISTENING')
            from mta_protocol import P2pInfo
            value = self.listening['data']
            if type(value) is not dict or set(value) != {'ssid', 'psk', 'mac', 'port'}: _fail('listening_frame_invalid')
            P2pInfo(value['ssid'], value['psk'], value['mac'], value['port'])
            return self
        except BaseException as error: self.failure = error; raise
    def _read_frames(self, wait=.05, cleanup_cap=None):
        check = self._read_check if cleanup_cap is None else lambda: self._drain_check(cleanup_cap)
        check()
        for row in (self.output, self.error_pipe): row.current(pipe=True)
        descriptors = ([] if self.output_eof else [self.output.fd]) + ([] if self.error_eof else [self.error_pipe.fd])
        ready = select.select(descriptors, [], [], wait)[0]
        for fd in ready:
            check()
            try: raw = os.read(fd, MAX_FRAME + 1)
            except OSError as error:
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK): continue
                raise
            if fd == self.error_pipe.fd:
                if not raw: self.error_eof = True
                self.private_stderr += raw
                if len(self.private_stderr) > MAX_PRIVATE_ERROR: _fail('private_error_limit')
            else:
                if not raw: self.output_eof = True
                self.stdout_raw += raw
                if len(self.stdout_raw) > 4 * MAX_FRAME: _fail('private_stdout_limit')
                self._buffer += raw
                if len(self._buffer) > 2 * MAX_FRAME: _fail('output_buffer_limit')
        while b'\n' in self._buffer:
            line, self._buffer = self._buffer.split(b'\n', 1); frame = _decode(line + b'\n')
            if (set(frame) != {'kind', 'seq', 'binding', 'data'} or frame['binding'] != self.binding or
                not _uint(frame['seq'], 1, 4) or frame['seq'] != self._read_seq + 1): _fail('output_binding_or_sequence')
            self._read_seq += 1; self.raw_frames.append(frame); self.frame_history.append(frame)
        check()
        return bool(ready)
    def _drain_check(self, cap):
        # Already-reaped original child only; no active work or fresh Proc read.
        if (threading.current_thread() is not self.worker or not self.process_reaped or
                cap > self.until + 60): _fail('reaped_drain_owner')
        self._process_current()
        now = _number(self.clock())
        if now >= cap: _fail('reaped_drain_expired')
        return now
    def _drain_reaped(self, cap):
        self._drain_check(cap)
        # Zero wait; total retained bytes remain under the existing stdout and
        # stderr limits. EOF is observed, never assumed from process.wait alone.
        while not (self.output_eof and self.error_eof):
            if not self._read_frames(0, cap): break
    def _read_check(self):
        if self._terminal_until is None: return self._check()
        if threading.current_thread() is not self.worker or self.state.operation is not self.operation or self._terminal_until != self.until + 60:
            _fail('terminal_parent_changed')
        self._process_current()
        if self.operation.cancelled.is_set() and not self.process_reaped:
            if self.failure is None: self.failure = SendBridgeError('task_cancelled')
            self.cancel()  # Stop-only once; still read the original cleanup tail.
        now = _number(self.clock())
        if now >= self._terminal_until: _fail('terminal_read_expired')
        return now
    def _wait_frame(self, kind):
        while True:
            self._read_frames()
            if self.raw_frames:
                frame = self.raw_frames.pop(0)
                if frame['kind'] != kind: _fail('unexpected_f_phase')
                return frame
            if self.process.poll() is not None:
                self._process_current()
                self.returncode = self.process.wait(timeout=0)
                self.process_reaped = type(self.returncode) is int
                self._drain_reaped(self.until if self._terminal_until is None else self._terminal_until)
                if self.raw_frames:
                    frame = self.raw_frames.pop(0)
                    if frame['kind'] != kind: _fail('unexpected_f_phase')
                    return frame
                _fail('f_exited_without_frame')
            if self.output_eof: _fail('f_output_eof')
    def begin_scan(self):
        self._check()
        if self.listening is None or self.scan is not None or self.operation.helper is not None: _fail('scan_start_order')
        from mta_scan_handoff import ScanSession
        helper = self.state.new_helper(self.operation)  # State retains before native start.
        now = self._check()
        self.scan = ScanSession(helper, self.operation.epoch, self.operation.epoch, now, ttl=30,
                                cancelled=self.operation.cancelled)
        self.operation.scan = self.scan
        helper.send({'cmd': 'scan', 'adapter': 'hci0', 'ttl': 30})
        self._check(); return self.scan
    def native_event(self, event, helper, native_epoch, operation_epoch):
        # Reader-thread capture only, never IO/crypto or native GO calls.
        with self._condition:
            if (helper is not self.operation.helper or native_epoch != self.binding['native_epoch'] or
                operation_epoch != self.binding['operation_epoch'] or type(native_epoch) is not int or
                type(operation_epoch) is not int or self.operation.cancelled.is_set()): return False
            if type(event) is not dict: self._native_failure = 'native_event_invalid'
            elif event.get('event') in ('closed', 'error', 'stop', 'client'): self._native_failure = 'native_failed'
            elif self._native_phase == 'read' and event.get('event') in ('client_status', 'client_read') or self._native_phase == 'write' and event.get('event') == 'client_write':
                self._native_queue.append(dict(event))
                if len(self._native_queue) > 2: self._native_failure = 'native_queue_limit'
            else: return False
            self._condition.notify_all(); return self._native_failure is None
    def _exchange(self, command, phase, seconds):
        with self._condition:
            if self._native_phase is not None or self._native_queue: _fail('native_exchange_overlap')
            self._native_phase = phase
        try:
            if phase == 'read':
                self._read_started = self._check()
                self._gatt_until = min(self.until, self._read_started + 30)  # Conservative pre-send bound, not helper lease renewal.
            self.operation.helper.send(command)
            end = min(self.until, self._check() + seconds)
            while True:
                now = self._check()
                with self._condition:
                    if self._native_failure is not None: _fail(self._native_failure)
                    if self._native_queue: return self._native_queue.pop(0)
                    if now >= end: _fail('native_exchange_timeout')
                    self._condition.wait(min(.05, end - now))
        finally:
            with self._condition: self._native_phase = None
    def run_selected(self, intent):
        self._check()
        from mta_scan_handoff import SendIntent
        from mta_protocol import DeviceInfo, P2pInfo, decode_json
        from mta_crypto import OpenSslCrypto
        if (type(intent) is not SendIntent or intent is not self.operation.send_intent or self.scan is not self.operation.scan or
            self.intent is not None or intent.handoff.helper is not self.operation.helper or
            intent.handoff.native_epoch != self.binding['native_epoch'] or intent.handoff.operation_epoch != self.binding['operation_epoch'] or
            intent.handoff.task_id != self.prepared.task_id):
            _fail('original_selection_required')
        if self.file_ids != intent.file_ids:
            _fail('prepared_selection_changed')
        from mta_send_preparation import PreparedSend
        PreparedSend._selection_current(self.prepared, True)
        for entry, ident in zip(self.prepared.selection.entries, self.file_ids):
            original = self.state.registry.catalog.get(ident)
            if type(original) is not dict or original['relative'] != entry['name'] or original['size'] != entry['size']:
                _fail('prepared_registry_selection_changed')
        self.intent = intent
        try:
            event = self._exchange({'cmd': 'client_read', 'peer': intent.handoff.peer}, 'read', 15)
            if set(event) != {'event', 'peer', 'payload_b64'} or event['event'] != 'client_status' or event['peer'] != intent.handoff.peer:
                _fail('actual_client_status_required')
            text = event['payload_b64']
            if type(text) is not str or len(text) > 684: _fail('device_info_limit')
            raw = base64.b64decode(text.encode('ascii'), validate=True)
            if not 1 <= len(raw) <= 512 or base64.b64encode(raw).decode('ascii') != text: _fail('device_info_canonical')
            data = decode_json(raw, 512)
            if type(data) is not dict or not {'state', 'mac', 'key'} <= set(data) or not set(data) <= {'state', 'mac', 'key', 'catShare'}:
                _fail('device_info_fields')
            self.peer_info = DeviceInfo.from_dict(data)
            if self.peer_info.state != 0 or self.peer_info.key is None: _fail('peer_busy_or_unencrypted')
            gatt_until = self._gatt_until
            self.crypto = OpenSslCrypto(self.state.openssl)
            self.key = self.crypto.generate_keypair()
            self.crypto.derive_shared(self.key, self.peer_info.key)  # Real curve/ECDH validation.
            self._check()
            plain = self.listening['data']
            packet = self.crypto.encrypt_credentials(P2pInfo(plain['ssid'], plain['psk'], plain['mac'], plain['port'],
                sender_id=self.prepared.task_id), self.key, self.peer_info.key).to_bytes()
            if self._check() >= gatt_until: _fail('gatt_lease_expired')
            event = self._exchange({'cmd': 'client_write', 'peer': intent.handoff.peer,
                'payload_b64': base64.b64encode(packet).decode('ascii')}, 'write', min(10, gatt_until - self._check()))
            if self._check() >= gatt_until or event != {'event': 'client_write', 'code': 'accepted_by_bluez_not_file_transfer_complete'}:
                _fail('actual_client_write_required')
            self._send('SELECTED', {'device_info': self.peer_info.to_dict(), 'helper_peer': intent.handoff.peer})
            self._terminal_until = self.until + 60  # Fixed read-only tail; no renewed task/GO/GATT cap.
            self.result = self._wait_frame('RESULT')['data']
            if (type(self.result) is not dict or set(self.result) != {'bytes', 'peer_completed', 'restored'} or
                self.result['bytes'] != self.prepared.archive_size or self.result['peer_completed'] is not True or
                type(self.result['restored']) is not bool): _fail('peer_completion_missing')
            remaining = self._terminal_until - self._read_check()
            if remaining <= 0: _fail('f_reap_expired')
            self.returncode = self.process.wait(timeout=remaining)
            self.process_reaped = type(self.returncode) is int
            if self.returncode != 0: _fail('f_failed_after_completion')
            self._drain_reaped(self._terminal_until)
            if self.raw_frames or self._buffer: _fail('unexpected_f_tail')
            self._read_check()
            if self.failure is not None: raise self.failure
            return dict(self.result)  # Child report DATA, not a native restore receipt.
        except BaseException as error: self.failure = error; raise
    def cancel(self):
        self.operation.cancelled.set()
        if self.cancel_sent or self.input is None: return
        self.cancel_sent = True
        try:
            self.input.current(pipe=True)
            if os.write(self.input.fd, b'CANCEL\n') != 7: _fail('cancel_short_write')
        except BaseException as error:
            if self.failure is None: self.failure = error
    def close(self, cleanup_until):
        if threading.current_thread() is not self.worker: _fail('parent_cleanup_worker')
        if self.close_called: return self.closed
        now, cap = _number(self.clock()), _number(cleanup_until)
        if not now < cap <= min(now + 60, self.until + 60): _fail('parent_cleanup_cap')
        self.close_called, self.cleanup_until = True, cap
        if not self.process_reaped: self.cancel()
        if self.process is not None and not self.process_unknown:
            try:
                self._process_current()
                remaining = cap - _number(self.clock())
                if remaining <= 0: _fail('parent_cleanup_expired')
                self.returncode = self.process.wait(timeout=remaining)
                self.process_reaped = type(self.returncode) is int
            except BaseException as error:
                if self.failure is None: self.failure = error
        if self.process_reaped and self.output is not None and self.error_pipe is not None:
            try: self._drain_reaped(cap)
            except BaseException as error:
                if self.failure is None: self.failure = error
        for row in reversed(self.rows):
            if _number(self.clock()) >= cap: break
            # Reaped child owns no live peer of a parent pipe. Independently
            # known certificate/python parent FDs can close even if spawn is
            # unknown; this never claims the missing child is gone/restored.
            if row.role not in ('stdin', 'stdout', 'stderr') or self.process_reaped:
                row.close()
        if self.key is not None:
            try: self.key.close()
            except BaseException as error:
                if self.failure is None: self.failure = error
        self.closed = (not self.process_unknown and (not self.process_called or self.process_reaped) and
                       all(r.closed and not r.unknown for r in self.rows))
        return self.closed
    def status(self):
        return {'started': self.called, 'listener_reported': self.listening is not None,
            'selected': self.intent is not None, 'child_reaped': self.process_reaped,
            'resource_pending': not self.closed, 'failed': self.failure is not None,
            'peer_completion_reported': type(self.result) is dict and self.result.get('peer_completed') is True and self.result.get('bytes') == self.prepared.archive_size,
            'native_restore_verified': False, 'production_admitted': False}
