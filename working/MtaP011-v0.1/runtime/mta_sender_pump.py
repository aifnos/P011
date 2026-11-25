# -*- coding: utf-8 -*-
"""Single-worker, bounded nonblocking MTA TLS sender (Python 3.5).

The caller supplies a prepared regular archive handle, SSLContext and an
already-owned listener. This module creates no archive, certificate, thread,
socket, radio group or permission receipt. ``owner`` implements:

 check(until)                         raise if original ownership is not live
 listen(listener, backlog, until)     listen + nonblocking, retain failures
 accept(listener, until)              (owned raw, peer tuple), or None for EAGAIN
 wrap(raw, context, until)            owned TLS, no automatic handshake
 close_connection(raw, tls, until)    exact True only for original closure facts
 close_listener(listener, until)      exact True only for original closure facts

The owner must inventory accept/wrap BEFORE their native calls, retain partial
and late returns, and never interpret detached raw.fileno()==-1 as closure.
Pump inventory complements, never replaces, that native owner inventory.
check is an owner checkpoint, not a caller boolean or a new ScopeProof. A
future Native integration must implement these actual methods; this component
alone neither enables send_available nor proves phone interoperability.
"""
import base64
import errno
import hashlib
import math
import os
import re
import select
import socket
import ssl
import stat
import struct
import threading
import time
from urllib.parse import parse_qs, urlsplit

from mta_protocol import (WsMessage, get_task_id, validate_send_request,
                          validate_task_id)
from mta_transport import TransportError, Cancelled, WS_GUID

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MESSAGE = 65536
CHUNK_BYTES = 65536
MAX_HEADER = 16384
MAX_INPUT = MAX_MESSAGE + MAX_HEADER
MAX_OUTPUT = 2 * MAX_MESSAGE + MAX_HEADER
MAX_STEPS = 1000000
MAX_ACCEPT_CALLS = 8192


class PumpError(TransportError):
    pass


def _deadline(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise PumpError('Invalid absolute deadline')
    return float(value)


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise PumpError('Invalid transfer count')
    return value


def _archive_identity(handle):
    value = os.fstat(handle.fileno())
    if not stat.S_ISREG(value.st_mode):
        raise PumpError('Archive is not a regular file')
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns if hasattr(value, 'st_mtime_ns') else value.st_mtime,
            value.st_ctime_ns if hasattr(value, 'st_ctime_ns') else value.st_ctime)


def _frame(opcode, payload):
    if type(payload) is not bytes or len(payload) > MAX_MESSAGE:
        raise PumpError('WebSocket output limit')
    if opcode >= 8 and len(payload) > 125:
        raise PumpError('WebSocket control limit')
    if len(payload) < 126:
        head = bytes(bytearray((0x80 | opcode, len(payload))))
    elif len(payload) < 65536:
        head = bytes(bytearray((0x80 | opcode, 126))) + struct.pack('!H', len(payload))
    else:
        head = bytes(bytearray((0x80 | opcode, 127))) + struct.pack('!Q', len(payload))
    return head + payload


def _message(message):
    return _frame(1, message.serialize().encode('utf-8'))


def _http_request(raw):
    lines = raw.split(b'\r\n')
    if len(lines) < 3 or lines[-2:] != [b'', b''] or len(lines) > 83 or len(lines[0]) > 4096:
        raise PumpError('HTTP header count limit')
    match = re.match(br'^GET ([!-~]{1,4096}) HTTP/1\.[01]\Z', lines[0])
    if match is None:
        raise PumpError('Only bounded GET requests are supported')
    headers = {}
    for line in lines[1:-2]:
        if len(line) > 4096 or b':' not in line or line[:1] in (b' ', b'\t'):
            raise PumpError('Invalid HTTP header')
        key, value = line.split(b':', 1)
        if re.match(br'^[A-Za-z0-9-]+\Z', key) is None:
            raise PumpError('Invalid HTTP header name')
        try:
            key, value = key.decode('ascii').lower(), value.strip().decode('ascii')
        except UnicodeError:
            raise PumpError('Invalid HTTP header encoding')
        if key in headers or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise PumpError('Ambiguous HTTP header')
        headers[key] = value
    if 'transfer-encoding' in headers or headers.get('content-length', '0') != '0':
        raise PumpError('Request bodies are not supported')
    target = urlsplit(match.group(1).decode('ascii'))
    if target.scheme or target.netloc or target.fragment or not target.path.startswith('/'):
        raise PumpError('Invalid request target')
    return target, headers


def _upgrade(headers):
    if (headers.get('upgrade', '').lower() != 'websocket' or
            'upgrade' not in [v.strip().lower() for v in headers.get('connection', '').split(',')] or
            headers.get('sec-websocket-version') != '13' or
            'sec-websocket-extensions' in headers):
        raise PumpError('Unsupported WebSocket handshake')
    key = headers.get('sec-websocket-key', '')
    try:
        decoded = base64.b64decode(key.encode('ascii'), validate=True)
    except (ValueError, UnicodeError):
        raise PumpError('Invalid WebSocket key')
    if len(decoded) != 16:
        raise PumpError('Invalid WebSocket key')
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode('ascii')).digest()).decode('ascii')
    return ('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
            'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n').encode('ascii')


class _Connection(object):
    def __init__(self):
        # Register this exact attempt before accept and retain returned raw/TLS
        # before type/fileno/readback. Unknown/failed attempts remain here.
        self.raw = None
        self.tls = None
        self.peer = None
        self.fd = None
        self.accept_called = False
        self.accept_returned = False
        self.accept_value = None
        self.no_resource = False
        self.wrap_called = False
        self.wrap_returned = False
        self.failure = None
        self.close_called = False
        self.close_return = None
        self.close_error = None
        self.closed = False
        self.phase = 'accept'
        self.handshake_want = 'read'
        self.read_want = 'read'
        self.write_want = 'write'
        self.rx = b''
        self.tx = b''
        self.tx_offset = 0
        self.tx_body = False
        self.send_data = None
        self.after_flush = None
        self.flush_at = None
        self.ws_stage = None
        self.fragment = bytearray()
        self.fragment_started = False
        self.frame_count = 0
        self.message_count = 0


class SenderPump(object):
    """No own thread; start/step/run/close stay on the constructing worker.

    archive_handle is borrowed, strong-retained and never reopened or closed by
    this pump. Its owner must keep it stable/exclusive until pump termination.
    Request payload is validated and copied through the actual wire codec.
    close returns socket-inventory closure, not network or file restoration.
    run requires a caller-owned cleanup_until; it never issues a new TTL.
    """
    def __init__(self, listener, archive_handle, archive_size, file_count,
                 total_bytes, request_payload, tls_context, owner,
                 absolute_until, cancelled=None, progress=None, clock=None):
        self.until = _deadline(absolute_until)
        self.archive_size = _integer(archive_size, 1, MAX_ARCHIVE)
        self.file_count = _integer(file_count, 1, 256)
        self.total_bytes = _integer(total_bytes, 0, MAX_ARCHIVE)
        checked = validate_send_request(request_payload)
        if checked['fileCount'] != file_count or checked['totalSize'] != total_bytes:
            raise PumpError('Request count mismatch')
        self.payload = WsMessage.parse(WsMessage('action', 1, 'sendRequest', request_payload).serialize()).payload
        self.task_id = checked['taskId']
        if not isinstance(tls_context, ssl.SSLContext) or not isinstance(listener, socket.socket):
            raise PumpError('Actual TLS context and owned listener required')
        if isinstance(listener, ssl.SSLSocket):
            raise PumpError('Raw listener required')
        for name in ('check', 'listen', 'accept', 'wrap', 'close_connection', 'close_listener'):
            if not callable(getattr(owner, name, None)):
                raise PumpError('Incomplete socket owner')
        for callback in (cancelled, progress, clock):
            if callback is not None and not callable(callback):
                raise PumpError('Invalid pump callback')
        if not callable(getattr(archive_handle, 'read', None)) or not callable(getattr(archive_handle, 'seek', None)):
            raise PumpError('Borrowed binary archive handle required')
        self.listener = listener
        self.archive = archive_handle
        self.context = tls_context
        self.owner = owner
        self.cancelled = cancelled or (lambda: False)
        self.progress = progress
        self.clock = clock or time.monotonic
        self.worker = threading.current_thread()
        self.started = False
        self.start_called = False
        self.failure = None
        self.state = 'idle'
        self.result = None
        self.history = []
        self.connections = []
        self.listener_close_called = False
        self.listener_close_return = None
        self.listener_close_error = None
        self.listener_closed = False
        self.cleanup_until = None
        self._last_now = None
        self._steps = 0
        self._accept_calls = 0
        self._ws = None
        self._download = None
        self._peer = None
        self._accepted = False
        self._archive_original = None
        self._archive_read = 0
        self._downloaded = 0
        self._download_complete = False
        self._terminal_pending = None

    def _worker(self):
        if threading.current_thread() is not self.worker:
            raise PumpError('Pump worker changed')

    def _now(self):
        value = self.clock()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise PumpError('Invalid pump clock')
        if self._last_now is not None and value < self._last_now:
            raise PumpError('Pump clock regressed')
        self._last_now = value
        if value >= self.until:
            raise PumpError('Transfer deadline exceeded')
        return value

    def _check(self):
        self._worker()
        if self.cancelled() is not False:
            raise Cancelled('Transfer cancelled')
        self._now()
        self.owner.check(self.until)
        # Owner checkpoints may themselves use native reads. Their late return
        # must not admit a subsequent send/accept/wrap under an expired cap.
        if self.cancelled() is not False:
            raise Cancelled('Transfer cancelled')
        return self._now()

    def _notify(self, state):
        self.state = state
        if self.progress is not None:
            self.progress(state, {'archiveBytesSent': self._downloaded,
                                  'archiveSize': self.archive_size,
                                  'fileCount': self.file_count,
                                  'totalSize': self.total_bytes})
        self._check()

    def _fail(self, error):
        if self.failure is None:
            self.failure = error
        self.result = None
        self.state = 'cancelled' if isinstance(self.failure, Cancelled) else 'failed'

    def start(self):
        self._worker()
        if self.start_called:
            raise PumpError('Pump cannot start twice')
        self.start_called = True
        try:
            self._check()
            self._archive_original = _archive_identity(self.archive)
            if self._archive_original[2] != self.archive_size:
                raise PumpError('Archive size mismatch')
            self._check()
            self.archive.seek(0)
            self._check()
            self.owner.listen(self.listener, 2, self.until)
            self._check()
            if self.listener.gettimeout() != 0.0:
                raise PumpError('Listener is not nonblocking')
            self._check()
            self.started = True
            self._notify('waiting')
        except BaseException as error:
            self._fail(error)
            raise
        return self

    def _queue(self, row, data, after=None, body=False):
        if type(data) is not bytes or len(row.tx) - row.tx_offset + len(data) > MAX_OUTPUT:
            raise PumpError('Output buffer limit')
        if body and (row.tx or row.after_flush is not None):
            raise PumpError('Overlapping archive write')
        if row.tx_offset:
            if row.flush_at is not None:
                row.flush_at -= row.tx_offset
            row.tx = row.tx[row.tx_offset:]
            row.tx_offset = 0
        row.tx += data
        row.tx_body = body
        if after is not None:
            if row.after_flush is not None:
                raise PumpError('Overlapping output transition')
            row.after_flush = after
            row.flush_at = len(row.tx)

    def _accept_one(self):
        if len(self.connections) >= 2:
            return
        self._accept_calls += 1
        if self._accept_calls > MAX_ACCEPT_CALLS:
            raise PumpError('Accept poll limit')
        row = _Connection()
        self.history.append(row)
        try:
            self._check()
            row.accept_called = True
            value = self.owner.accept(self.listener, self.until)
            row.accept_value = value
            row.accept_returned = True
            if value is None:
                row.no_resource = True
                row.closed = True  # Explicit owner EAGAIN/no-return contract.
                self._check()
                return
            if type(value) is not tuple or len(value) != 2:
                row.failure = PumpError('Invalid owned accept return')
                raise row.failure
            row.raw, row.peer = value  # Strong references before any readback.
            self.connections.append(row)
            self._check()
            if (not isinstance(row.raw, socket.socket) or isinstance(row.raw, ssl.SSLSocket) or
                    type(row.peer) is not tuple or len(row.peer) < 2 or
                    type(row.peer[0]) is not str):
                raise PumpError('Invalid accepted socket')
            if self._peer is not None and row.peer[0] != self._peer:
                raise PumpError('Transfer peer changed')
            if row.raw.gettimeout() != 0.0:
                raise PumpError('Accepted socket is not nonblocking')
            self._check()
            row.wrap_called = True
            row.tls = self.owner.wrap(row.raw, self.context, self.until)
            row.wrap_returned = True
            self._check()
            if not isinstance(row.tls, ssl.SSLSocket) or row.tls is row.raw:
                raise PumpError('Invalid owned TLS return')
            row.fd = row.tls.fileno()
            if type(row.fd) is not int or row.fd < 0 or row.tls.gettimeout() != 0.0:
                raise PumpError('TLS is not nonblocking')
            row.phase = 'handshake'
            self._check()
        except BaseException as error:
            row.failure = error
            if not row.accept_called:
                row.no_resource, row.closed = True, True
            raise

    def _socket(self, row):
        if row.closed or row.tls is None or row.tls.fileno() != row.fd:
            raise PumpError('Owned TLS descriptor changed')
        return row.tls

    def _handshake(self, row):
        self._check()
        try:
            self._socket(row).do_handshake()
        except ssl.SSLWantReadError:
            row.handshake_want = 'read'
            self._check()
            return
        except ssl.SSLWantWriteError:
            row.handshake_want = 'write'
            self._check()
            return
        self._check()
        row.phase = 'http'

    def _http(self, row):
        end = row.rx.find(b'\r\n\r\n')
        if end < 0:
            if len(row.rx) >= MAX_HEADER:
                raise PumpError('HTTP header limit')
            return
        end += 4
        if end > MAX_HEADER:
            raise PumpError('HTTP header limit')
        target, headers = _http_request(row.rx[:end])
        row.rx = row.rx[end:]
        if target.path == '/websocket' and not target.query:
            if self._ws is not None:
                raise PumpError('Duplicate WebSocket')
            self._ws, self._peer = row, row.peer[0]
            row.phase, row.ws_stage = 'ws', 'version_sending'
            self._queue(row, _upgrade(headers) + _message(WsMessage(
                'action', 0, 'versionNegotiation', {'version': 1, 'versions': [1]})), 'version_ack')
            self._notify('negotiating')
        elif target.path == '/download':
            if row.rx:
                raise PumpError('Unexpected download request body')
            self._download_request(row, target.query)
        else:
            raise PumpError('Unsupported sender route')

    def _download_request(self, row, query):
        if len(query) > 512:
            raise PumpError('Download query limit')
        values = parse_qs(query, keep_blank_values=True, strict_parsing=True)
        if set(values) - {'taskId', 'startByte', 'endByte'} or any(len(v) != 1 for v in values.values()):
            raise PumpError('Ambiguous download query')
        task = validate_task_id(values.get('taskId', [None])[0])
        if values.get('startByte', ['0'])[0] != '0' or values.get('endByte', ['-1'])[0] != '-1':
            raise PumpError('Partial download unsupported')
        if task != self.task_id or self._peer != row.peer[0]:
            raise PumpError('Download task or peer mismatch')
        if not self._accepted or self._download is not None:
            raise PumpError('Download was not accepted or already started')
        self._download = row
        row.phase = 'download'
        self._queue(row, ('HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: ' +
                         str(self.archive_size) + '\r\nConnection: close\r\n\r\n').encode('ascii'))
        self._notify('transferring')

    def _ws_message(self, row, message):
        row.message_count += 1
        if row.message_count > 34:
            raise PumpError('WebSocket message count limit')
        if row.ws_stage == 'version_ack':
            if (message.msg_type != 'ack' or message.id != 0 or message.name != 'versionNegotiation' or
                    message.payload is None or type(message.payload.get('version')) is not int or
                    message.payload.get('version') != 1):
                raise PumpError('Version ACK mismatch')
            row.ws_stage = 'request_sending'
            self._queue(row, _message(WsMessage('action', 1, 'sendRequest', self.payload)), 'request_ack')
            self._notify('awaiting_confirmation')
            return
        if row.ws_stage == 'request_ack' and message.msg_type == 'ack':
            if message.id != 1 or message.name != 'sendRequest':
                raise PumpError('Send-request ACK mismatch')
            row.ws_stage = 'status'
            self._accepted = True
            self._notify('accepted')
            return
        if row.ws_stage not in ('request_ack', 'status') or message.msg_type != 'action' or message.name not in ('status', 'cancel'):
            raise PumpError('Unexpected transfer action')
        if get_task_id(message.payload) != self.task_id:
            raise PumpError('Status task mismatch')
        if message.name == 'cancel':
            terminal = ('cancelled', Cancelled('Peer cancelled transfer'), None)
        else:
            kind = message.payload.get('type')
            if type(kind) is not int or kind not in (1, 2, 3):
                raise PumpError('Invalid transfer status')
            if kind == 1:
                if not self._accepted or not self._download_complete or self._downloaded != self.archive_size:
                    raise PumpError('Completion before full archive transfer')
                terminal = ('completed', None, {'fileCount': self.file_count,
                            'totalSize': self.total_bytes, 'archiveBytesSent': self._downloaded,
                            'peer_completion_verified': True})
            elif kind == 3:
                terminal = ('cancelled', Cancelled('Peer refused transfer'), None)
            else:
                terminal = ('failed', PumpError('Peer reported transfer failure'), None)
        if self._terminal_pending is not None:
            raise PumpError('Duplicate terminal action')
        self._terminal_pending = terminal
        row.ws_stage = 'terminal_sending'
        self._queue(row, _message(message.make_ack()), 'terminal')

    def _parse_ws(self, row):
        # At most eight complete frames per step; fragmentation/control counts
        # remain bounded across all steps. Incomplete frames wait for select.
        for unused in range(8):
            if self._terminal_pending is not None or len(row.rx) < 2:
                return
            head = row.rx[:2]
            final, opcode = bool(head[0] & 128), head[0] & 15
            if head[0] & 112 or not head[1] & 128:
                raise PumpError('Invalid masked WebSocket frame')
            size, offset = head[1] & 127, 2
            if size == 126:
                if len(row.rx) < 4:
                    return
                size, offset = struct.unpack('!H', row.rx[2:4])[0], 4
                if size < 126:
                    raise PumpError('Noncanonical WebSocket length')
            elif size == 127:
                if len(row.rx) < 10:
                    return
                size, offset = struct.unpack('!Q', row.rx[2:10])[0], 10
                if size < 65536:
                    raise PumpError('Noncanonical WebSocket length')
            if size > MAX_MESSAGE or opcode >= 8 and (not final or size > 125):
                raise PumpError('WebSocket frame limit')
            if len(row.rx) < offset + 4 + size:
                return
            mask = row.rx[offset:offset + 4]
            encoded = row.rx[offset + 4:offset + 4 + size]
            row.rx = row.rx[offset + 4 + size:]
            payload = bytes(bytearray(v ^ mask[i % 4] for i, v in enumerate(encoded)))
            row.frame_count += 1
            if row.frame_count > 256:
                raise PumpError('WebSocket frame count limit')
            if opcode == 8:
                raise PumpError('Peer closed control channel')
            if opcode == 9:
                self._queue(row, _frame(10, payload))
                continue
            if opcode == 10:
                continue
            if opcode == 1 and not row.fragment_started:
                row.fragment_started = True
            elif opcode != 0 or not row.fragment_started:
                raise PumpError('Unexpected WebSocket opcode')
            row.fragment.extend(payload)
            if len(row.fragment) > MAX_MESSAGE:
                raise PumpError('WebSocket message limit')
            if final:
                text = bytes(row.fragment)
                row.fragment = bytearray()
                row.fragment_started = False
                self._ws_message(row, WsMessage.parse(text))

    def _read(self, row):
        self._check()
        try:
            data = self._socket(row).recv(4096)
        except ssl.SSLWantReadError:
            row.read_want = 'read'
            self._check()
            return
        except ssl.SSLWantWriteError:
            row.read_want = 'write'
            self._check()
            return
        self._check()
        row.read_want = 'read'
        if not data:
            raise PumpError('Unexpected TLS end of stream')
        row.rx += data
        if len(row.rx) > MAX_INPUT:
            raise PumpError('Input buffer limit')
        if row.phase == 'http':
            self._http(row)
        if row.phase == 'ws':
            self._parse_ws(row)

    def _fill_download(self, row):
        if row.tx or self._terminal_pending is not None:
            return
        self._check()
        if _archive_identity(self.archive) != self._archive_original:
            raise PumpError('Archive identity changed')
        self._check()
        maximum = min(CHUNK_BYTES, self.archive_size - self._archive_read)
        data = self.archive.read(maximum)
        self._check()
        if type(data) is not bytes or not data or len(data) > maximum:
            raise PumpError('Archive ended before expected size')
        self._archive_read += len(data)
        self._queue(row, data, body=True)

    def _finish_download(self, row):
        self._check()
        extra = self.archive.read(1)
        self._check()
        if extra != b'' or _archive_identity(self.archive) != self._archive_original:
            raise PumpError('Archive grew or changed')
        self._check()
        if not self._close_connection(row, self.until):
            raise PumpError('Download socket closure pending')
        self._check()
        self._download_complete = True
        self._notify('awaiting_result')

    def _write(self, row):
        if not row.tx:
            return
        self._check()
        if row.send_data is None:
            row.send_data = row.tx[row.tx_offset:row.tx_offset + CHUNK_BYTES]
        try:
            # SSLWantRead/Write retries must use the identical byte segment;
            # a later ping/ACK may append output but cannot change that segment.
            sent = self._socket(row).send(row.send_data)
        except ssl.SSLWantReadError:
            row.write_want = 'read'
            self._check()
            return
        except ssl.SSLWantWriteError:
            row.write_want = 'write'
            self._check()
            return
        if type(sent) is not int or not 1 <= sent <= len(row.send_data):
            raise PumpError('Invalid TLS send result')
        row.send_data = None
        # Preserve actual successful-send counters BEFORE a late postcheck.
        row.tx_offset += sent
        if row.tx_body:
            self._downloaded += sent
        self._check()
        row.write_want = 'write'
        # A subsequent pong may have been appended after the negotiation
        # frame. Consume its transition at that original frame boundary, not
        # after unrelated later output. Terminal ACK is the terminal boundary.
        if row.flush_at is not None and row.tx_offset >= row.flush_at:
            after = row.after_flush
            row.after_flush, row.flush_at = None, None
            if after == 'terminal':
                self._check()
                state, error, result = self._terminal_pending
                self.state, self.failure, self.result = state, error, result
            else:
                row.ws_stage = after
        if row.tx_offset == len(row.tx):
            body = row.tx_body
            row.tx, row.tx_offset, row.tx_body = b'', 0, False
            if body:
                if self._downloaded == self.archive_size:
                    self._finish_download(row)
                else:
                    self._notify('transferring')

    def step(self, max_wait=0.05):
        if type(max_wait) not in (int, float) or not math.isfinite(max_wait) or not 0 <= max_wait <= 0.2:
            raise PumpError('Invalid pump poll interval')
        self._worker()
        if not self.started or self.listener_close_called:
            raise PumpError('Pump is not active')
        if self.state in ('completed', 'cancelled', 'failed'):
            return self.status()
        try:
            now = self._check()
            self._steps += 1
            if self._steps > MAX_STEPS:
                raise PumpError('Pump iteration limit')
            read, write = [], []
            if len(self.connections) < 2 and self._terminal_pending is None:
                read.append(self.listener)
            for row in self.connections:
                if row.closed:
                    continue
                sock = self._socket(row)
                if row.phase == 'handshake':
                    (read if row.handshake_want == 'read' else write).append(sock)
                else:
                    if row.phase == 'download' and self._terminal_pending is None:
                        self._fill_download(row)
                    if row.tx:
                        (read if row.write_want == 'read' else write).append(sock)
                    if row.phase in ('http', 'ws') and self._terminal_pending is None:
                        (read if row.read_want == 'read' else write).append(sock)
            # TLS plaintext already buffered must not sleep awaiting kernel FD.
            buffered = [row for row in self.connections if not row.closed and
                        row.phase in ('http', 'ws') and row.tls.pending() > 0]
            wait = 0.0 if buffered else min(float(max_wait), max(0.0, self.until - now))
            ready_read, ready_write, unused = select.select(read, write, [], wait)
            self._check()
            if self.listener in ready_read:
                self._accept_one()
            for row in self.connections:
                if row.closed or row.phase == 'accept':
                    continue
                sock = self._socket(row)
                readable, writable = sock in ready_read, sock in ready_write
                if row.phase == 'handshake':
                    if readable or writable:
                        self._handshake(row)
                    continue
                if row.tx and ((row.write_want == 'read' and readable) or
                               (row.write_want == 'write' and writable)):
                    self._write(row)
                if row.closed or self.state in ('completed', 'cancelled', 'failed'):
                    continue
                if row.phase in ('http', 'ws') and self._terminal_pending is None:
                    if (row in buffered or (row.read_want == 'read' and readable) or
                            (row.read_want == 'write' and writable)):
                        self._read(row)
                    elif row.phase == 'ws' and row.rx:
                        self._parse_ws(row)
            return self.status()
        except BaseException as error:
            self._fail(error)
            raise

    def _close_connection(self, row, until):
        if row.closed:
            return True
        if row.close_called:
            return False
        row.close_called = True
        try:
            row.close_return = self.owner.close_connection(row.raw, row.tls, until)
            row.closed = row.close_return is True
        except BaseException as error:
            row.close_error = error
        return row.closed

    def close(self, cleanup_until):
        self._worker()
        until = _deadline(cleanup_until)
        if self.cleanup_until is None:
            self.cleanup_until = until
        elif until != self.cleanup_until:
            raise PumpError('Cleanup deadline cannot be replaced')
        # No active/cancel gate prevents closing an exact already-known resource.
        # The owner validates its original cleanup cap and actual FD identities.
        if self.state not in ('completed', 'cancelled', 'failed'):
            self._fail(Cancelled('Pump closed before completion'))
        for row in self.history:
            if not row.no_resource:
                self._close_connection(row, self.cleanup_until)
        if not self.listener_close_called:
            self.listener_close_called = True
            try:
                self.listener_close_return = self.owner.close_listener(self.listener, self.cleanup_until)
                self.listener_closed = self.listener_close_return is True
            except BaseException as error:
                self.listener_close_error = error
        closed = self.listener_closed and all(row.closed for row in self.history)
        if not closed:
            self._fail(PumpError('Owned socket cleanup pending'))
        return closed

    def run(self, cleanup_until):
        cleanup_until = _deadline(cleanup_until)
        try:
            if not self.started:
                self.start()
            while self.state not in ('completed', 'cancelled', 'failed'):
                self.step()
        finally:
            self.close(cleanup_until)
        if self.failure is not None:
            raise self.failure
        if self.state != 'completed' or self.result is None:
            raise PumpError('Pump ended without verified peer completion')
        return dict(self.result)

    def status(self):
        # Passive numeric/finite state projection; never taskId, peer/path/key.
        return {'state': self.state, 'accepted': self._accepted,
                'archiveBytesSent': self._downloaded, 'archiveSize': self.archive_size,
                'download_complete': self._download_complete,
                'peer_completion_verified': self.result is not None,
                'connection_attempts': len(self.connections),
                'socket_cleanup_pending': not (self.listener_closed and
                                              all(row.closed for row in self.history))}
