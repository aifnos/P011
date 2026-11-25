# -*- coding: utf-8 -*-
"""SOURCE v86: passive original-F84 finish DATA after owned child EOF/reap.
Frozen Bridge79 is preserved. Reports never verify network restoration or clear
State/pending; existing PRIMARY/key/close failures and all budgets remain intact.

SOURCE v79: original private-key generation and once-close inventory.
Frozen Bridge77 is preserved; no execution, admission or RF success is claimed.
KeyPair.closed is not a free-return proof: an actual release exception stays
unknown even if the original KeyPair set closed before EC_KEY_free returned.

Private parent/F send IPC, Python 3.5; explicit calls only.

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
import types

import p011_json as json

MAX_FRAME = 8192
MAX_PRIVATE_ERROR = 16384
MAX_FINISH_DATA_V86 = 4096
MAX_OUTPUT_FRAMES = 642
MAX_OUTPUT_BYTES = 512 * 1024
MAX_PROGRESS_FRAMES = 640
MAX_PROGRESS_FRAME = 4096
_PROGRESS_KEYS = frozenset(('state', 'accepted', 'archiveBytesSent', 'archiveSize',
    'download_complete', 'peer_completion_verified', 'connection_attempts',
    'socket_cleanup_pending', 'fileCount', 'totalSize'))
_PROGRESS_STATES = frozenset(('waiting', 'negotiating', 'awaiting_confirmation',
    'accepted', 'transferring', 'awaiting_result', 'completed', 'cancelled', 'failed'))
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

def _progress_data(value, size, count, total):
    # Only passive bounded Pump DATA; never a completion/restore receipt.
    if (type(value) is not dict or set(value) != _PROGRESS_KEYS or
        type(value['state']) is not str or value['state'] not in _PROGRESS_STATES or
        not _uint(value['archiveBytesSent'], 0, size) or
        not _uint(value['archiveSize'], 1, 512 * 1024 * 1024) or value['archiveSize'] != size or
        not _uint(value['fileCount'], 1, 256) or value['fileCount'] != count or
        not _uint(value['totalSize'], 0, 512 * 1024 * 1024) or value['totalSize'] != total or
        not _uint(value['connection_attempts'], 0, 2) or any(type(value[n]) is not bool for n in
            ('accepted', 'download_complete', 'peer_completion_verified', 'socket_cleanup_pending')) or
        value['download_complete'] and value['archiveBytesSent'] != size or
        value['peer_completion_verified'] and (not value['download_complete'] or not value['accepted'] or
                                              value['state'] != 'completed')):
        _fail('progress_data_invalid')
    return value


_FINISH_KEYS_V86 = frozenset(('schema', 'provenance', 'binding', 'journal',
    'cleanup_until', 'finished_at', 'device_lock_metadata', 'f_actor', 'children',
    'inventory_counts', 'business_failed_at_capture', 'native_full_inventory_export',
    'independent_restore_verified', 'production_admitted'))
_FINISH_BIND_KEYS_V86 = frozenset(('run', 'manifest', 'task', 'nonce',
    'native_epoch', 'operation_epoch', 'until'))
_FINISH_JOURNAL_KEYS_V86 = frozenset(('schema', 'phase', 'generation', 'sha256',
    'bytes', 'metadata', 'facts_key'))


def _finish_number_v86(value):
    return type(value) is float and 0 <= value < 1e12 and math.isfinite(value)


def _finish_metadata_v86(value):
    return (type(value) is list and len(value) == 9 and
        all(_uint(item, 0, (1 << 64) - 1) for item in value))


def _finish_wire_v86(value):
    return ('GOFINISH84=' + json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')


def _finish_decode_v86(raw, binding, candidate_sha, child_pid, store_schema):
    # DATA-only validation. No core/Canonical/receipt/lease is reconstructed.
    if (type(raw) is not bytes or not 1 <= len(raw) <= MAX_FINISH_DATA_V86 or
            not raw.startswith(b'GOFINISH84=') or not raw.endswith(b'\n')):
        _fail('finish_data_format')
    try: value = json.loads(raw[len(b'GOFINISH84='):-1].decode('ascii'))
    except (ValueError, UnicodeError): _fail('finish_data_format')
    if type(value) is not dict or set(value) != _FINISH_KEYS_V86 or _finish_wire_v86(value) != raw:
        _fail('finish_data_noncanonical')
    data_binding, journal = value['binding'], value['journal']
    if (value['schema'] != 'p011-go-finish-data-v84' or value['provenance'] != 'returned_restore' or
        type(data_binding) is not dict or set(data_binding) != _FINISH_BIND_KEYS_V86 or
        any(type(data_binding[n]) is not type(binding[n]) or data_binding[n] != binding[n]
            for n in _FINISH_BIND_KEYS_V86) or
        type(journal) is not dict or set(journal) != _FINISH_JOURNAL_KEYS_V86 or
        journal['schema'] != store_schema or journal['phase'] != 'reconciled' or
        not _uint(journal['generation'], 1, 25) or not _hex(journal['sha256'], 64) or
        not _uint(journal['bytes'], 1, 131072) or not _finish_metadata_v86(journal['metadata'])):
        _fail('finish_data_binding')
    metadata, facts = journal['metadata'], journal['facts_key']
    if (not stat.S_ISREG(metadata[2]) or stat.S_IMODE(metadata[2]) != 0o600 or
        metadata[3:6] != [0, 0, 1] or metadata[6] != journal['bytes'] or
        type(facts) is not list or len(facts) != 7 or
        facts[:4] != [store_schema, binding['run'], candidate_sha, binding['task']] or
        type(facts[4]) is not str or re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', facts[4]) is None or
        not _finish_number_v86(facts[5]) or not _finish_number_v86(facts[6]) or
        facts[6] != float(binding['until']) or not 0 < facts[6] - facts[5] <= 300 or
        not _finish_number_v86(value['cleanup_until']) or not _finish_number_v86(value['finished_at']) or
        value['finished_at'] >= value['cleanup_until']):
        _fail('finish_data_journal')
    lock, actor, children, counts = (value[n] for n in
        ('device_lock_metadata', 'f_actor', 'children', 'inventory_counts'))
    if (not _finish_metadata_v86(lock) or not stat.S_ISREG(lock[2]) or
        stat.S_IMODE(lock[2]) != 0o600 or lock[3:6] != [0, 0, 1] or
        type(actor) is not list or len(actor) != 3 or
        not _uint(actor[0], 1, 0x7fffffff) or actor[0] != child_pid or
        not _uint(actor[1], 1, (1 << 64) - 1) or not _hex(actor[2], 64) or
        type(children) is not list or len(children) > 2 or
        type(counts) is not list or len(counts) != 2 or
        not _uint(counts[0], 8, 256) or not _uint(counts[1], 0, 8192) or
        type(value['business_failed_at_capture']) is not bool or any(value[n] is not False for n in
            ('native_full_inventory_export', 'independent_restore_verified', 'production_admitted'))):
        _fail('finish_data_inventory')
    roles = []
    for row in children:
        if (type(row) is not list or len(row) != 3 or type(row[0]) is not str or
            row[0] not in ('controller', 'watchdog') or row[0] in roles or
            not (row[1] is None and row[2] is None or
                 _uint(row[1], 1, 0x7fffffff) and _uint(row[2], 1, (1 << 64) - 1))):
            _fail('finish_data_children')
        roles.append(row[0])
    return value


class _FinishReportV86(object):
    """Private original pipe DATA; NOT independent restoration/permission."""
    __slots__ = ('raw', 'data', 'originals', 'reap', 'stdout_eof', 'stderr_eof')
    def __init__(self, raw, data, originals, reap, stdout_eof, stderr_eof):
        for name, value in (('raw', raw), ('data', data), ('originals', originals),
            ('reap', reap), ('stdout_eof', stdout_eof), ('stderr_eof', stderr_eof)):
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('immutable private F finish DATA')
    def __repr__(self): return '<private F finish report; network restore unverified>'


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
        self._output_bytes = 0
        self._progress_pump = self._progress_originals = self._progress_failure = None
        self._progress_creator = self._progress_status = self._progress_protocol = None
        self._progress_atomic_cap = self._progress_atomic_original = None
        self._progress_request_wire = None
        self._terminal_attempted = False
        self._progress_count = 0
        self._progress_last_now = self._progress_emitted_at = self._progress_state = None
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
        # Actual atomic pipe capacity, read ONCE on this adopted original pipe.
        self._progress_atomic_cap = os.fpathconf(self.output.fd, 'PC_PIPE_BUF')
        if not _uint(self._progress_atomic_cap, 1, 0x7fffffff) or os.get_blocking(self.output.fd) is not False:
            _fail('progress_pipe_not_atomic_nonblocking')
        self._progress_atomic_original = (self.output, self.output.fd, self._progress_atomic_cap)
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
        if kind != 'LISTENING' or self.write_seq != 0: _fail('listening_output_order')
        seq = self.write_seq + 1
        raw = _wire({'kind': kind, 'seq': seq, 'binding': self.start['binding'], 'data': data})
        if self._output_bytes + len(raw) > MAX_OUTPUT_BYTES: _fail('output_byte_limit')
        now = self._check()
        if not select.select([], [self.output.fd], [], min(.2, self.until - now))[1]: _fail('output_not_ready')
        self._check()
        written = os.write(self.output.fd, raw)  # One attempt; never retransmit.
        if type(written) is not int or written != len(raw):
            self.output.unknown = True; _fail('output_short_write')
        self.write_seq, self._output_bytes = seq, self._output_bytes + len(raw)
        self._check()
    def _progress_current(self, pump):
        # Exact fixed module/creator/launch originals. No Native/RF IO or grant.
        entry, deployment = self.entry, self.entry.deployment
        modules = deployment.modules
        if type(modules) is not dict or any(type(modules[n]) is not types.ModuleType for n in
                ('mta_go_executor', 'mta_sender_pump', 'mta_protocol', 'mta_go_native')):
            _fail('progress_source_changed')
        executor, pumps, protocol, native = (modules[n] for n in
            ('mta_go_executor', 'mta_sender_pump', 'mta_protocol', 'mta_go_native'))
        if type(entry) is not executor.GoEntrySource or type(pump) is not pumps.SenderPump:
            _fail('progress_pump_not_original')
        if self._progress_pump is None: self._progress_pump = pump  # First actual object before later validation/IO.
        elif pump is not self._progress_pump: _fail('progress_pump_replaced')
        launch = entry.send_launch
        if type(launch) is not executor.GoSendLaunch or entry._send_launch_original is not launch:
            _fail('progress_launch_changed')
        data = self.start['data']
        if (type(data) is not dict or type(data['request']) is not dict or
            launch.entry is not entry or launch.deployment is not deployment or launch.channel is not self or
            launch.start is not self.start or self.archive_handle is not launch.archive_handle or
            self.context is not launch.tls_context or self.worker is not entry.worker or self.clock is not entry.clock or
            self.until is not entry.until or threading.current_thread() is not self.worker or
            pump.worker is not self.worker or pump.clock is not self.clock or pump.archive is not self.archive_handle or
            pump.context is not self.context or type(pump.owner) is not native.GoSendPumpOwner or
            pump.owner.native.entry is not entry or pump.owner.end != pump.until or
            type(pump.until) is not float or not 0 < pump.until <= self.until or
            pump.started is not True or pump.archive_size != data['size'] or
            pump.file_count != data['count'] or pump.total_bytes != data['total'] or
            pump.task_id != self.start['binding']['task'] or pump.task_id != launch.task_id or
            self.output is None or self.output.unknown or not _uint(self._progress_atomic_cap, 1, 0x7fffffff) or
            type(self._progress_atomic_original) is not tuple or len(self._progress_atomic_original) != 3 or
            self._progress_atomic_original[0] is not self.output or self._progress_atomic_original[1] != self.output.fd or
            self._progress_atomic_original[2] is not self._progress_atomic_cap or
            os.get_blocking(self.output.fd) is not False):
            _fail('progress_original_changed')
        checked = protocol.validate_send_request(data['request'])
        if (checked['taskId'] != pump.task_id or checked['fileCount'] != pump.file_count or
                checked['totalSize'] != pump.total_bytes or pump.payload != data['request']):
            _fail('progress_request_changed')
        request_wire = _wire({'request': data['request']})
        archive_rows = [r for r in self.rows if r.role == 'archive']
        if len(archive_rows) != 1 or archive_rows[0].value is not self.archive_handle:
            _fail('progress_archive_changed')
        archive_rows[0].current()
        values = (pump, entry, deployment, modules, executor, pumps, protocol, native,
            launch, self.start, data, data['request'], self.archive_handle, self.context,
            self.worker, self.clock, pump.owner, pump.until, pump.archive_size,
            pump.file_count, pump.total_bytes, pump.task_id, self.output, self._progress_atomic_cap)
        if self._progress_originals is None:
            self._progress_originals = values
            self._progress_creator, self._progress_status = pumps.SenderPump, pumps.SenderPump.status
            self._progress_protocol = protocol.validate_send_request
            self._progress_request_wire = request_wire
        elif (pump is not self._progress_pump or type(self._progress_originals) is not tuple or
              len(values) != len(self._progress_originals) or
              any(a is not c for a, c in zip(values, self._progress_originals)) or
              pumps.SenderPump is not self._progress_creator or pumps.SenderPump.status is not self._progress_status or
              protocol.validate_send_request is not self._progress_protocol or
              request_wire != self._progress_request_wire):
            _fail('progress_original_replaced')
        return pumps
    def emit_progress(self, pump):
        # Best-effort observation only: no waiting, no partial retry/seq gap.
        if self._progress_failure is not None: raise self._progress_failure
        try:
            if threading.current_thread() is not self.worker or self.close_called: _fail('channel_owner_changed')
            now = _number(self.clock())
            if now >= self.until or self.stop: return False  # No new active output in the tail.
            pumps = self._progress_current(pump)
            now = self._check()
            if self._progress_last_now is not None and now < self._progress_last_now:
                _fail('progress_clock_regressed')
            self._progress_last_now = now
            if now >= pump.until or pump.failure is not None or self._progress_count >= MAX_PROGRESS_FRAMES: return False
            value = pumps.SenderPump.status(pump)  # Actual fixed-class passive method.
            if type(value) is not dict: _fail('progress_status_invalid')
            value = dict(value); value['fileCount'] = pump.file_count; value['totalSize'] = pump.total_bytes
            _progress_data(value, pump.archive_size, pump.file_count, pump.total_bytes)
            if (value['state'] == self._progress_state and self._progress_emitted_at is not None and
                    now - self._progress_emitted_at < .5): return False
            seq = self.write_seq + 1
            if not _uint(seq, 2, MAX_OUTPUT_FRAMES - 1): _fail('progress_output_order')
            raw = _wire({'kind': 'PROGRESS', 'seq': seq, 'binding': self.start['binding'], 'data': value})
            if len(raw) > min(MAX_PROGRESS_FRAME, self._progress_atomic_cap): _fail('progress_atomic_frame_limit')
            # Reserve one maximum terminal frame; truncating progress never grants RESULT.
            if self._output_bytes + len(raw) + MAX_FRAME > MAX_OUTPUT_BYTES: return False
            self.output.current(pipe=True)
            if not select.select([], [self.output.fd], [], 0)[1]: return False
            now = self._check()
            if now >= pump.until: return False
            try: count = os.write(self.output.fd, raw)  # Exactly one nonblocking atomic attempt.
            except OSError as error:
                if type(error.errno) is int and error.errno in (errno.EAGAIN, errno.EWOULDBLOCK): return False
                self.failure = error; self.output.unknown = True; raise
            if type(count) is not int or count != len(raw):
                self.output.unknown = True
                self.failure = SendBridgeError('progress_output_unknown')
                raise self.failure
            self.write_seq, self._output_bytes = seq, self._output_bytes + len(raw)
            self._progress_count += 1
            self._progress_emitted_at, self._progress_state = now, value['state']
            self._check()
            return True
        except BaseException as error:
            if self._progress_failure is None: self._progress_failure = error
            raise
    def emit_terminal(self, data, cleanup_until):
        # Cleanup-only stdout report, including failure after active expiry.
        # Never performs RF, starts work or issues a renewed network period.
        cap = _number(cleanup_until)
        if (threading.current_thread() is not self.worker or self.close_called or cap > self.until + 60 or
                self._terminal_attempted):
            _fail('terminal_cleanup_owner')
        self._terminal_attempted = True
        self.output.current(pipe=True)
        seq = self.write_seq + 1
        if not _uint(seq, 2, MAX_OUTPUT_FRAMES): _fail('terminal_output_order')
        raw = _wire({'kind': 'RESULT', 'seq': seq, 'binding': self.start['binding'], 'data': data})
        if self._output_bytes + len(raw) > MAX_OUTPUT_BYTES: _fail('output_byte_limit')
        now = _number(self.clock())
        if now >= cap or not select.select([], [self.output.fd], [], min(.2, cap - now))[1]: _fail('terminal_output_expired')
        if _number(self.clock()) >= cap: _fail('terminal_output_expired')
        count = os.write(self.output.fd, raw)
        if type(count) is not int or count != len(raw):
            self.output.unknown = True; _fail('terminal_output_unknown')
        self.write_seq, self._output_bytes = seq, self._output_bytes + len(raw)
        if _number(self.clock()) >= cap: _fail('terminal_output_unknown')
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
        self._key_generation = {'called': False, 'returned': False, 'value': None, 'originals': None,
            'native_key': None, 'error': None, 'unknown': False}
        self._key_release = {'called': False, 'returned': False, 'value': None,
            'error': None, 'unknown': False, 'verified': False}
        self._key_generation_original, self._key_release_original = self._key_generation, self._key_release
        self._native_phase, self._native_queue, self._native_failure = None, [], None
        self._read_started = self._gatt_until = None
        self._condition = threading.Condition()
        self._buffer, self._read_seq, self._write_seq = b'', 0, 0
        self._terminal_until = None
        self._listening_seen = self._result_seen = False
        self._progress_received = self._progress_bytes_seen = 0
        self._progress_task_original = (prepared, prepared.archive_handle, prepared.archive_size,
            prepared.file_count, prepared.total_bytes, prepared.task_id)
        self._latest_progress = None
        self._progress_first, self._progress_last = [], []
        self._consumed_gatt_original = None
        self._consumed_intent_type = self._consumed_handoff_type = None
        self._finish_source_originals_v86 = self._finish_reap_v86 = None
        self._finish_stdout_eof_v86 = self._finish_stderr_eof_v86 = None
        self._finish_attempted_v86 = False
        self._finish_raw_v86 = self._finish_report_v86 = self._finish_failure_v86 = None
        self._finish_unavailable_v86 = None
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
            self._finish_source_originals_v86 = (self, self.binding, tuple(sorted(self.binding.items())),
                self.deployment, self.deployment.loader, self._process_original, self._process_pid,
                self.input, self.output, self.error_pipe)
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
                if not raw:
                    self._finish_stderr_eof_v86 = (self.error_pipe, fd, self.error_pipe.value, self.error_pipe.metadata, raw)
                    self.error_eof = True
                self.private_stderr += raw
                if len(self.private_stderr) > MAX_PRIVATE_ERROR: _fail('private_error_limit')
            else:
                if not raw:
                    self._finish_stdout_eof_v86 = (self.output, fd, self.output.value, self.output.metadata, raw)
                    self.output_eof = True
                self.stdout_raw += raw
                if len(self.stdout_raw) > MAX_OUTPUT_BYTES: _fail('private_stdout_limit')
                self._buffer += raw
                if len(self._buffer) > 2 * MAX_FRAME: _fail('output_buffer_limit')
        while b'\n' in self._buffer:
            line, self._buffer = self._buffer.split(b'\n', 1); frame = _decode(line + b'\n')
            if (set(frame) != {'kind', 'seq', 'binding', 'data'} or frame['binding'] != self.binding or
                not _uint(frame['seq'], 1, MAX_OUTPUT_FRAMES) or frame['seq'] != self._read_seq + 1): _fail('output_binding_or_sequence')
            if frame['kind'] == 'LISTENING':
                if self._listening_seen or frame['seq'] != 1 or self._result_seen: _fail('listening_output_order')
                self._listening_seen = True
                self.frame_history.append(frame)
            elif frame['kind'] == 'PROGRESS':
                if (not self._listening_seen or self._result_seen or self.intent is None or
                        self._consumed_gatt_original is None or self._progress_received >= MAX_PROGRESS_FRAMES):
                    _fail('progress_output_order')
                original = self._progress_task_original
                if (len(line) + 1 > MAX_PROGRESS_FRAME or type(original) is not tuple or len(original) != 6 or
                        original[0] is not self.prepared or original[1] is not self.prepared.archive_handle or
                        original[2:] != (self.prepared.archive_size, self.prepared.file_count,
                                         self.prepared.total_bytes, self.prepared.task_id)):
                    _fail('progress_task_changed')
                value = _progress_data(frame['data'], original[2], original[3], original[4])
                if value['archiveBytesSent'] < self._progress_bytes_seen: _fail('progress_bytes_regressed')
                self._progress_bytes_seen = value['archiveBytesSent']; self._progress_received += 1
            elif frame['kind'] == 'RESULT':
                if not self._listening_seen or self._result_seen: _fail('terminal_output_order')
                self._result_seen = True
                self.frame_history.append(frame)
            else: _fail('unexpected_f_phase')
            self._read_seq += 1; self.raw_frames.append(frame)
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
        GoSendBridge._capture_finish_report_v86(self)  # Pure retained tail; no further IO/clock/wait.
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
            while self.raw_frames:
                frame = self.raw_frames.pop(0)
                if frame['kind'] == 'PROGRESS':
                    self._record_progress(frame); continue
                if frame['kind'] != kind: _fail('unexpected_f_phase')
                return frame
            if self.process.poll() is not None:
                self._process_current()
                self.returncode = self.process.wait(timeout=0)
                self.process_reaped = type(self.returncode) is int
                GoSendBridge._retain_finish_reap_v86(self)
                self._drain_reaped(self.until if self._terminal_until is None else self._terminal_until)
                while self.raw_frames:
                    frame = self.raw_frames.pop(0)
                    if frame['kind'] == 'PROGRESS':
                        self._record_progress(frame); continue
                    if frame['kind'] != kind: _fail('unexpected_f_phase')
                    return frame
                _fail('f_exited_without_frame')
            if self.output_eof: _fail('f_output_eof')
    def _record_progress(self, frame):
        # Already canonical/validated pipe DATA. Retain only first2/last2 plus latest.
        with self._condition:
            self._latest_progress = frame
            if len(self._progress_first) < 2: self._progress_first.append(frame)
            self._progress_last.append(frame)
            if len(self._progress_last) > 2: del self._progress_last[0]
    def latest_progress(self):
        # Passive cross-thread projection; no IO/clock/callback or completion grant.
        with self._condition:
            frame = self._latest_progress
            return None if frame is None else dict(frame['data'])
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
    def _consumed_gatt_current(self):
        # Original accepted write fact only, not GATT readiness or peer completion.
        facts = self._consumed_gatt_original
        if type(facts) is not tuple or len(facts) != 12: return False
        bridge, accepted, helper, intent, handoff, scan, ne, oe, operation, state, binding, snapshot = facts
        return (bridge is self and operation is self.operation and state is self.state and
            state.operation is operation and state.session is operation.session and
            binding is self.binding and helper is operation.helper and intent is self.intent and
            intent is operation.send_intent and type(intent) is self._consumed_intent_type and
            type(handoff) is self._consumed_handoff_type and intent.handoff is handoff and
            handoff.helper is helper and handoff.native_epoch == ne and handoff.operation_epoch == oe and
            handoff.task_id == self.prepared.task_id and scan is self.scan and scan is operation.scan and
            type(ne) is int and type(oe) is int and type(state.native_epoch) is int and type(operation.epoch) is int and
            state.native_epoch == ne and operation.epoch == oe and
            binding['native_epoch'] == ne and binding['operation_epoch'] == oe and
            type(accepted) is dict and set(accepted) == {'event', 'code'} and
            type(accepted['event']) is str and type(accepted['code']) is str and accepted == {'event': 'client_write', 'code': 'accepted_by_bluez_not_file_transfer_complete'} and
            snapshot == tuple(sorted(accepted.items())) and not self.close_called and not self.cancel_sent and
            self._native_failure is None and not operation.cancelled.is_set())
    def consumed_gatt_event(self, event, helper, native_epoch, operation_epoch):
        # Exactly the two known client lifecycle reports AFTER the original write.
        if (type(event) is not dict or set(event) != {'event', 'code'} or event['event'] != 'client' or
            type(event['code']) is not str or event['code'] not in
                ('lease_or_services_timeout', 'own_connection_disconnect_requested') or
            type(native_epoch) is not int or type(operation_epoch) is not int or
            not GoSendBridge._consumed_gatt_current(self)):
            return False
        facts = self._consumed_gatt_original
        return helper is facts[2] and native_epoch == facts[6] and operation_epoch == facts[7]
    def native_event(self, event, helper, native_epoch, operation_epoch):
        # Reader-thread capture only, never IO/crypto or native GO calls.
        with self._condition:
            if (helper is not self.operation.helper or native_epoch != self.binding['native_epoch'] or
                operation_epoch != self.binding['operation_epoch'] or type(native_epoch) is not int or
                type(operation_epoch) is not int or self.operation.cancelled.is_set()): return False
            if GoSendBridge.consumed_gatt_event(self, event, helper, native_epoch, operation_epoch): return True
            if type(event) is not dict: self._native_failure = 'native_event_invalid'
            elif event.get('event') in ('closed', 'error', 'stop', 'client'): self._native_failure = 'native_failed'
            elif self._native_phase == 'read' and event.get('event') in ('client_status', 'client_read') or self._native_phase == 'write' and event.get('event') == 'client_write':
                self._native_queue.append(event)  # Original reader object, not a reconstructed accepted fact.
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
    def _generate_key_original(self, crypto_type, key_type):
        row = self._key_generation_original
        if (self._key_generation is not row or row['called'] or self.key is not None or
                type(self.crypto) is not crypto_type): _fail('key_generation_original_changed')
        self._check()
        generator, closer = crypto_type.generate_keypair, key_type.close
        if (type(generator) is not types.FunctionType or type(closer) is not types.FunctionType or
                closer.__globals__ is not generator.__globals__ or
                generator.__globals__.get('OpenSslCrypto') is not crypto_type or
                generator.__globals__.get('KeyPair') is not key_type): _fail('key_source_original_changed')
        bound = self.crypto.generate_keypair
        if (type(bound) is not types.MethodType or bound.__self__ is not self.crypto or
                bound.__func__ is not generator): _fail('key_generator_original_changed')
        library = self.crypto._lib
        row['originals'] = (crypto_type, key_type, generator, closer, generator.__globals__,
                            self.crypto, library, library.EC_KEY_free)
        row['called'] = True  # Before actual generation, including unreturned allocations.
        try:
            value = generator(self.crypto)
        except BaseException as error:
            row['error'], row['unknown'] = error, True
            raise
        row['value'], self.key, row['returned'] = value, value, True  # Before any returned-object inspection.
        try:
            if type(value) is not key_type: _fail('key_return_original_changed')
            row['native_key'] = value._native_key
            self._key_current_original(False)
        except BaseException as error:
            row['error'], row['unknown'] = error, True
            raise
        # A late valid return is still retained for original cleanup, not a new
        # generation permission or a missing-key/zero-resource observation.
        self._check()
        return value

    def _key_current_original(self, released):
        row, close = self._key_generation_original, self._key_release_original
        if (self._key_generation is not row or self._key_release is not close or row['called'] is not True or
                row['returned'] is not True or row['unknown'] is not False or row['error'] is not None or
                type(row['originals']) is not tuple or len(row['originals']) != 8): _fail('key_inventory_original_changed')
        crypto_type, key_type, generator, closer, namespace, crypto, library, freer = row['originals']
        key = row['value']
        if (self.crypto is not crypto or type(crypto) is not crypto_type or self.key is not key or type(key) is not key_type or
                crypto_type.generate_keypair is not generator or key_type.close is not closer or
                generator.__globals__ is not namespace or closer.__globals__ is not namespace or
                namespace.get('OpenSslCrypto') is not crypto_type or namespace.get('KeyPair') is not key_type or
                crypto._lib is not library or key._owner is not library or library.EC_KEY_free is not freer or
                type(row['native_key']) is not int or row['native_key'] <= 0): _fail('key_owner_original_changed')
        bound_generate, bound_close = crypto.generate_keypair, key.close
        if (type(bound_generate) is not types.MethodType or bound_generate.__self__ is not crypto or
                bound_generate.__func__ is not generator or type(bound_close) is not types.MethodType or
                bound_close.__self__ is not key or bound_close.__func__ is not closer): _fail('key_function_original_changed')
        if released:
            if key.closed is not True or key._native_key is not None: _fail('key_free_return_unverified')
        elif key.closed is not False or key._native_key is not row['native_key']:
            _fail('key_native_original_changed')
        return key, closer

    def _close_key_original(self):
        row, close = self._key_generation_original, self._key_release_original
        if close['called'] or close['unknown']: return self._key_closed_original()
        try:
            if threading.current_thread() is not self.worker: _fail('key_cleanup_worker')
            if _number(self.clock()) >= self.cleanup_until: _fail('key_cleanup_expired')
            if self._key_generation is not row or self._key_release is not close:
                _fail('key_inventory_original_changed')
            if row['called'] is False:
                if (row['returned'] is not False or row['value'] is not None or row['originals'] is not None or
                        row['native_key'] is not None or row['error'] is not None or row['unknown'] is not False or
                        self.key is not None): _fail('key_zero_inventory_unverified')
                close['verified'] = True  # Actual generation never called; no free is claimed.
                return True
            key, closer = self._key_current_original(False)
            if _number(self.clock()) >= self.cleanup_until: _fail('key_cleanup_expired')
            close['called'] = True  # Before the one original free; never retry an uncertain return.
            value = closer(key)
            close['value'], close['returned'] = value, True
            if value is not None: _fail('key_close_return_unverified')
            self._key_current_original(True)
            if _number(self.clock()) >= self.cleanup_until: _fail('key_cleanup_expired')
            close['verified'] = True
            return True
        except BaseException as error:
            close['error'], close['unknown'] = error, True
            if self.failure is None: self.failure = error
            return False

    def _key_closed_original(self):
        row, close = self._key_generation_original, self._key_release_original
        known = (self._key_generation is row and self._key_release is close and
                row['unknown'] is False and row['error'] is None and
                close['verified'] is True and close['unknown'] is False and close['error'] is None)
        if not known: return False
        if row['called'] is False:
            return (row['returned'] is False and row['value'] is None and row['originals'] is None and
                    row['native_key'] is None and self.key is None and close['called'] is False and
                    close['returned'] is False and close['value'] is None)
        originals, key = row['originals'], row['value']
        return (row['called'] is True and row['returned'] is True and type(originals) is tuple and len(originals) == 8 and
                self.key is key and type(key) is originals[1] and self.crypto is originals[5] and
                type(self.crypto) is originals[0] and key._owner is originals[6] and
                key.closed is True and key._native_key is None and
                close['called'] is True and close['returned'] is True and close['value'] is None)

    def run_selected(self, intent):
        self._check()
        from mta_scan_handoff import SendIntent
        from mta_protocol import DeviceInfo, P2pInfo, decode_json
        from mta_crypto import OpenSslCrypto, KeyPair
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
            self._generate_key_original(OpenSslCrypto, KeyPair)
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
            with self._condition:
                if self._native_failure is not None or self._consumed_gatt_original is not None:
                    _fail('consumed_gatt_original_changed')
                self._consumed_intent_type, self._consumed_handoff_type = SendIntent, type(intent.handoff)
                self._consumed_gatt_original = (self, event, self.operation.helper, intent,
                    intent.handoff, self.scan, self.binding['native_epoch'], self.binding['operation_epoch'],
                    self.operation, self.state, self.binding, tuple(sorted(event.items())))
                if not GoSendBridge._consumed_gatt_current(self): _fail('consumed_gatt_original_changed')
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
            GoSendBridge._retain_finish_reap_v86(self)
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
        if self.close_called: return self.closed and self._key_closed_original()
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
                GoSendBridge._retain_finish_reap_v86(self)
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
        key_closed = self._close_key_original()
        self.closed = (not self.process_unknown and (not self.process_called or self.process_reaped) and
                        all(r.closed and not r.unknown for r in self.rows) and key_closed and self._key_closed_original())
        return self.closed
    def _retain_finish_reap_v86(self):
        # Installed only immediately after the original process.wait returned.
        try:
            value = (self.process, self._process_pid, self.returncode)
            if self._finish_reap_v86 is None: self._finish_reap_v86 = value
            elif self._finish_reap_v86 != value:
                _fail('finish_reap_changed')
        except BaseException as error:
            if self._finish_failure_v86 is None: self._finish_failure_v86 = error

    def _finish_originals_current_v86(self):
        original = self._finish_source_originals_v86
        if (type(original) is not tuple or len(original) != 10 or original[0] is not self or
            original[1] is not self.binding or type(self.binding) is not dict or
            original[2] != tuple(sorted(_binding(self.binding).items())) or
            original[3] is not self.deployment or original[4] is not self.deployment.loader or
            original[5] is not self.process or self.process is not self._process_original or
            original[6] != self._process_pid or type(self.process.pid) is not int or
            self.process.pid != self._process_pid or
            original[7] is not self.input or original[8] is not self.output or original[9] is not self.error_pipe or
            self.process_called is not True or self.process_unknown is not False or self.process_reaped is not True or
            type(self._finish_reap_v86) is not tuple or len(self._finish_reap_v86) != 3 or
            self._finish_reap_v86[0] is not self.process or self._finish_reap_v86[1] != self._process_pid or
            type(self.returncode) is not int or self._finish_reap_v86[2] != self.returncode or
            self.output_eof is not True or self.error_eof is not True or
            type(self.private_stderr) is not bytes or len(self.private_stderr) > MAX_PRIVATE_ERROR or
            type(self.stdout_raw) is not bytes or len(self.stdout_raw) > MAX_OUTPUT_BYTES or self._buffer != b''):
            _fail('finish_original_child_tail')
        for row, eof in ((self.output, self._finish_stdout_eof_v86), (self.error_pipe, self._finish_stderr_eof_v86)):
            if (type(row) is not _Fd or not any(item is row for item in self.rows) or
                row.returned is not True or row.unknown is not False or
                type(eof) is not tuple or len(eof) != 5 or eof[0] is not row or
                eof[1] != row.fd or eof[2] is not row.value or eof[3] is not row.metadata or eof[4] != b''):
                _fail('finish_original_eof')
        if (self.binding['run'] != self.deployment.manifest.run_token or
            self.binding['manifest'] != self.deployment.manifest_sha or
            self.binding['task'] != self.prepared.task_id or self.binding['nonce'] != self.nonce or
            self.binding['until'] != self.deployment.loader.original_until_text):
            _fail('finish_original_binding')
        return original

    def _capture_finish_report_v86(self):
        # No extra read, authenticate, clock, wait, key-free or native/State call.
        if self._finish_attempted_v86 or not (self.process_reaped and self.output_eof and self.error_eof): return None
        self._finish_attempted_v86 = True
        try:
            original = GoSendBridge._finish_originals_current_v86(self)
            line, separator, tail = self.private_stderr.partition(b'\n')
            raw = line + separator
            self._finish_raw_v86 = raw  # Exact original first line before any parse/refusal.
            if not separator or len(raw) > MAX_FINISH_DATA_V86 or b'\nGOFINISH84=' in tail or tail.startswith(b'GOFINISH84='):
                _fail('finish_data_first_line')
            if raw in (b'GOFINISH84=unavailable provenance=default_run\n',
                       b'GOFINISH84=unavailable provenance=returned_restore\n'):
                self._finish_unavailable_v86 = raw
                return None  # Explicit missing DATA is never a successful report.
            stores = self.deployment.modules.get('mta_go_bootstrap_store')
            if type(stores) is not types.ModuleType or stores.SCHEMA != 'p011-go-typed-live-v72':
                _fail('finish_data_source')
            data = _finish_decode_v86(raw, self.binding, self.deployment.manifest.candidate_sha,
                                     self._process_pid, stores.SCHEMA)
            self._finish_report_v86 = _FinishReportV86(raw, data, original, self._finish_reap_v86,
                self._finish_stdout_eof_v86, self._finish_stderr_eof_v86)
            return self._finish_report_v86
        except BaseException as error:
            if self._finish_failure_v86 is None: self._finish_failure_v86 = error
            return None  # Never overwrite PRIMARY/key/close or retry the tail.

    def finish_report(self):
        # Passive PRIVATE DATA access. No success/admission/restoration state changes.
        report = self._finish_report_v86
        if type(report) is not _FinishReportV86 or self._finish_failure_v86 is not None: return None
        try:
            if (report.originals is not GoSendBridge._finish_originals_current_v86(self) or
                report.reap is not self._finish_reap_v86 or report.stdout_eof is not self._finish_stdout_eof_v86 or
                report.stderr_eof is not self._finish_stderr_eof_v86 or report.raw is not self._finish_raw_v86 or
                _finish_wire_v86(report.data) != report.raw):
                return None
            return report
        except BaseException: return None

    def status(self):
        return {'started': self.called, 'listener_reported': self.listening is not None,
            'selected': self.intent is not None, 'child_reaped': self.process_reaped,
            'resource_pending': not self.closed or not self._key_closed_original(), 'failed': self.failure is not None,
            'key_generation_called': self._key_generation_original['called'],
            'key_close_called': self._key_release_original['called'], 'key_resource_closed': self._key_closed_original(),
            'peer_completion_reported': type(self.result) is dict and self.result.get('peer_completed') is True and self.result.get('bytes') == self.prepared.archive_size,
            'gatt_credentials_consumed': GoSendBridge._consumed_gatt_current(self),
            'latest_progress': GoSendBridge.latest_progress(self),
            'finish_data_reported': GoSendBridge.finish_report(self) is not None,
            'finish_data_failed': self._finish_failure_v86 is not None,
            'finish_data_unavailable': self._finish_unavailable_v86 is not None,
            'native_restore_verified': False, 'production_admitted': False}
