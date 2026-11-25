# -*- coding: utf-8 -*-
"""Bounded MTA TLS sender, independently written, Python 3.5 compatible.

This is a transport, not a Wi-Fi-group manager. It must be given an already
verified private interface address and a FileRegistry FileSelection. It never
accepts QML paths, reopens source paths, changes radios, or logs file names.
The self-signed certificate encrypts transport but is not CA authentication.
Phone interoperability and P011 AP/P2P support require separate verification.
The listener initially denies every peer unless a verified address was supplied.
The platform may authorize exactly one actual association/DHCP peer after start;
starting the listener and publishing its port never authorizes a guessed IP.
"""
import base64
import binascii
import errno
import hashlib
import os
import re
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from urllib.parse import parse_qs, urlsplit

from mta_files import FileSelection
from mta_protocol import WsMessage, ProtocolError, get_task_id, validate_send_request, validate_task_id
from mta_storage import validate_member_name
from mta_transport import Stream, WebSocket, TransportError, Cancelled, WS_GUID, private_ipv4, read_headers, SocketLifecycle

MAX_ARCHIVE = 512 * 1024 * 1024
MAX_FILES = 256
CHUNK_BYTES = 65536


class SenderError(TransportError):
    pass


def _snapshot(handle):
    value = os.fstat(handle.fileno())
    if not stat.S_ISREG(value.st_mode):
        raise SenderError("Selected input is not a regular file")
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns if hasattr(value, "st_mtime_ns") else value.st_mtime)


def _bind_address(host, allow_loopback):
    if allow_loopback and host == "127.0.0.1":
        return host
    return private_ipv4(host)


def _request(stream):
    first, headers = read_headers(stream)
    match = re.match(br"^GET ([!-~]{1,4096}) HTTP/1\.[01]\Z", first)
    if match is None:
        raise SenderError("Only bounded GET requests are supported")
    if "transfer-encoding" in headers or headers.get("content-length", "0") != "0":
        raise SenderError("Request bodies are not supported")
    target = match.group(1).decode("ascii")
    value = urlsplit(target)
    if value.scheme or value.netloc or value.fragment or not value.path.startswith("/"):
        raise SenderError("Invalid request target")
    return value, headers


def _websocket_server(stream, headers):
    if (headers.get("upgrade", "").lower() != "websocket" or
            "upgrade" not in [value.strip().lower() for value in headers.get("connection", "").split(",")] or
            headers.get("sec-websocket-version") != "13" or
            "sec-websocket-extensions" in headers):
        raise SenderError("Unsupported WebSocket handshake")
    key = headers.get("sec-websocket-key", "")
    try:
        decoded = base64.b64decode(key.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise SenderError("Invalid WebSocket key")
    if len(decoded) != 16:
        raise SenderError("Invalid WebSocket key")
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
    stream.send(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n").encode("ascii"))
    return WebSocket(stream, client=False)


class SenderTransport(object):
    def __init__(self, host, port, selection, openssl_path, sender_name="P011",
                 sender_id=None, task_id=None, cancelled=None, timeout=300,
                 allow_loopback=False, state_callback=None, allowed_peer_ip=None,
                 temp_root=None, listener_factory=None):
        if not isinstance(allow_loopback, bool):
            raise SenderError("Invalid test-mode switch")
        self.host = _bind_address(host, allow_loopback)
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
            raise SenderError("Invalid transfer port")
        if not isinstance(selection, FileSelection) or selection.closed:
            raise SenderError("An active FileRegistry selection is required")
        if not isinstance(openssl_path, str) or not os.path.isabs(openssl_path) or not os.path.isfile(openssl_path):
            raise SenderError("An existing absolute OpenSSL executable is required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.2 <= timeout <= 600:
            raise SenderError("Invalid sender deadline")
        if state_callback is not None and not callable(state_callback):
            raise SenderError("Invalid sender callback")
        if listener_factory is not None and not callable(listener_factory):
            raise SenderError("Invalid scoped listener factory")
        if temp_root is not None and (not isinstance(temp_root, str) or not os.path.isabs(temp_root) or not os.path.isdir(temp_root)):
            raise SenderError("Invalid private temporary root")
        self.port = port
        self.selection = selection
        self.openssl_path = openssl_path
        self.task_id = validate_task_id(task_id or binascii.hexlify(os.urandom(16)).decode("ascii"))
        self.sender_id = validate_task_id(sender_id or binascii.hexlify(os.urandom(2)).decode("ascii"))
        self.sender_name = sender_name
        self.external_cancelled = cancelled or (lambda: False)
        self.deadline = time.monotonic() + timeout
        self.callback = state_callback
        self._allow_loopback = allow_loopback
        self._allowed_peer_ip = _bind_address(allowed_peer_ip, allow_loopback) if allowed_peer_ip is not None else None
        self.temp_root = temp_root
        # Internal owned-lease hook, never a QML action. The platform proves
        # the interface and applies SO_BINDTODEVICE before returning a socket.
        self.listener_factory = listener_factory
        self.state = "idle"
        self.result = None
        self.error = None
        self._cancelled = threading.Event()
        self._finished = threading.Event()
        self._lock = threading.RLock()
        self._life = SocketLifecycle()
        self._listener = None
        self._listener_thread = None
        self._workers = []
        self._connections = set()
        self._private_directory = None
        self._private_identity = None
        self._archive_path = None
        self._archive_size = 0
        self._actual_bytes = 0
        self._file_count = 0
        self._request_payload = None
        self._context = None
        self._peer_ip = None
        self._ws_claimed = False
        self._accepted = False
        self._download_started = False
        self._download_complete = False
        self._downloaded_bytes = 0
        self._last_write_pending = False
        self._last_write_done = threading.Event()
        self._closed = False
        self._start_claimed = False

    def _check(self):
        if self._closed or self._cancelled.is_set() or self.external_cancelled():
            raise Cancelled("Transfer cancelled")
        if time.monotonic() >= self.deadline:
            raise SenderError("Transfer deadline exceeded")

    def _stream_cancelled(self):
        return self._cancelled.is_set() or self._finished.is_set() or self.external_cancelled()

    def _notify(self, state, details=None):
        with self._lock:
            if self._finished.is_set():
                return
            self.state = state
        if self.callback is not None:
            # Never pass source names, passwords, private paths, peer addresses,
            # taskId, or cryptographic material to progress/result logs.
            self.callback(state, details or {})

    def _fail(self, error):
        with self._lock:
            if self._finished.is_set():
                return
            self.error = error
            self.state = "cancelled" if isinstance(error, Cancelled) else "failed"
            self._finished.set()
        if self.callback is not None:
            self.callback(self.state, {})

    def _certificate(self):
        key_path = os.path.join(self._private_directory, "server-key.pem")
        certificate = os.path.join(self._private_directory, "server-cert.pem")
        arguments = [self.openssl_path, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", key_path, "-out", certificate, "-days", "1", "-subj", "/CN=P011-MTA"]
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._life.adopt_process(process)
        try:
            output, ignored_error = process.communicate(timeout=min(10, max(0.2, self.deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise SenderError("TLS certificate generation timed out")
        if process.returncode != 0 or len(output) > 1024:
            raise SenderError("TLS certificate generation failed")
        os.chmod(key_path, 0o600)
        os.chmod(certificate, 0o600)
        self._check()
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self._context.set_ciphers("HIGH:!aNULL:!eNULL:!MD5:!RC4")
        self._context.load_cert_chain(certificate, key_path)

    def _prepare_archive(self):
        if self.selection.closed:
            raise SenderError("FileRegistry selection was closed")
        entries = self.selection.entries
        if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_FILES:
            raise SenderError("Selected file count limit")
        expected_total = 0
        manifest = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or not all(key in entry for key in ("name", "size", "handle")):
                raise SenderError("Invalid FileRegistry entry")
            size = entry["size"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > 256 * 1024 * 1024:
                raise SenderError("Selected file size limit")
            validate_member_name(entry["name"])
            member = str(index) + "/" + entry["name"]
            validate_member_name(member)
            snapshot = _snapshot(entry["handle"])
            if snapshot[2] != size:
                raise SenderError("Selected file size changed")
            expected_total += size
            if expected_total > MAX_ARCHIVE - 1024 * 1024:
                raise SenderError("Selected total byte limit")
            manifest.append((member.encode("utf-8"), entry["handle"], snapshot))
        if expected_total != self.selection.total_bytes:
            raise SenderError("Selection byte count mismatch")
        if shutil.disk_usage(self._private_directory).free < expected_total + 17 * 1024 * 1024:
            raise SenderError("Insufficient archive temporary space")
        path = os.path.join(self._private_directory, "payload.zip")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        central = []
        actual_total = 0
        with os.fdopen(fd, "wb") as output:
            for name, source, snapshot in manifest:
                self._check()
                offset = output.tell()
                # Stored ZIP + data descriptors permits true bounded streaming
                # on Python 3.5, whose ZipFile.open has no write mode.
                flags = 0x0808
                output.write(struct.pack("<I5H3I2H", 0x04034b50, 20, flags, 0, 0, 33, 0, 0, 0, len(name), 0))
                output.write(name)
                source.seek(0)
                crc = 0
                actual = 0
                while True:
                    self._check()
                    data = source.read(CHUNK_BYTES)
                    if not data:
                        break
                    if not isinstance(data, bytes):
                        raise SenderError("Selected file is not binary")
                    actual += len(data)
                    actual_total += len(data)
                    if actual > snapshot[2] or actual_total > expected_total:
                        raise SenderError("Selected file grew during packaging")
                    crc = zlib.crc32(data, crc) & 0xffffffff
                    output.write(data)
                    if output.tell() > MAX_ARCHIVE:
                        raise SenderError("Archive byte limit")
                if actual != snapshot[2] or _snapshot(source) != snapshot:
                    raise SenderError("Selected file changed during packaging")
                output.write(struct.pack("<4I", 0x08074b50, crc, actual, actual))
                central.append(struct.pack("<I6H3I5H2I", 0x02014b50, (3 << 8) | 20, 20,
                                           flags, 0, 0, 33, crc, actual, actual, len(name), 0, 0, 0, 0,
                                           (stat.S_IFREG | 0o600) << 16, offset) + name)
            start = output.tell()
            for record in central:
                output.write(record)
            central_size = output.tell() - start
            output.write(struct.pack("<I4H2IH", 0x06054b50, 0, 0, len(central), len(central), central_size, start, 0))
            if output.tell() > MAX_ARCHIVE:
                raise SenderError("Archive byte limit")
            output.flush()
            os.fsync(output.fileno())
        if actual_total != expected_total:
            raise SenderError("Archive byte count mismatch")
        self._archive_path = path
        self._archive_size = os.path.getsize(path)
        self._actual_bytes = actual_total
        self._file_count = len(manifest)
        self._request_payload = {"taskId": self.task_id, "id": self.task_id, "senderId": self.sender_id,
                                 "senderName": self.sender_name, "fileName": entries[0]["name"],
                                 "mimeType": "application/octet-stream", "fileCount": self._file_count,
                                 "totalSize": self._actual_bytes}
        validate_send_request(self._request_payload)

    def start(self):
        with self._lock:
            if self._closed or self._start_claimed:
                raise SenderError("Sender cannot be started twice")
            self._check()
            self._start_claimed = True
            actor = self._life.begin('sender_start')
        try:
            parent = os.path.realpath(self.temp_root or tempfile.gettempdir())
            self._private_directory = tempfile.mkdtemp(prefix="mta-send-", dir=self.temp_root)
            current = os.lstat(self._private_directory)
            if (not stat.S_ISDIR(current.st_mode) or os.path.islink(self._private_directory) or
                    os.path.realpath(os.path.dirname(self._private_directory)) != parent):
                raise SenderError("Private temporary directory identity failed")
            self._private_identity = (current.st_dev,current.st_ino,parent,os.path.realpath(self._private_directory))
            os.chmod(self._private_directory, 0o700)
            self._notify("preparing")
            self._prepare_archive()
            self._certificate()
            if self.listener_factory is None:
                self._adopt_listener(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._listener.bind((self.host, self.port))
            else:
                raw = self.listener_factory(self.host, self.port)
                self._adopt_listener(raw)  # Retain even invalid/late factory resources.
                if not isinstance(raw, socket.socket):
                    raise SenderError("Scoped listener did not return a socket")
                if (isinstance(raw, ssl.SSLSocket) or raw.family != socket.AF_INET or
                        raw.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or
                        raw.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
                    raise SenderError("Scoped listener must be bound raw IPv4 TCP")
                address, port = raw.getsockname()
                if address != self.host or not 1 <= port <= 65535 or self.port and port != self.port:
                    raise SenderError("Scoped listener address readback mismatch")
                # A connected client is not a bound listener. Never promote it.
                try: raw.getpeername()
                except OSError as error:
                    if error.errno not in (errno.ENOTCONN, 10057):
                        raise SenderError("Scoped listener connection readback failed")
                else: raise SenderError("Scoped listener is already connected")
            self._check()
            self.port = self._listener.getsockname()[1]
            self._listener.listen(4)
            self._listener.settimeout(0.2)
            self._notify("waiting", {"fileCount": self._file_count, "totalSize": self._actual_bytes})
            self._listener_thread = threading.Thread(target=self._accept_loop, name="mta-sender-listener")
            self._listener_thread.daemon = True
            self._life.start_thread(self._listener_thread)
            return self.port
        except BaseException:
            self.close(0)
            raise
        finally:
            self._life.end(actor)
            if self._life.closing:self._cleanup_private(threading.current_thread())

    def _adopt_listener(self, raw):
        # Register exact ownership BEFORE checking a late factory return.
        if not self._life.adopt_returned(raw):
            raise SenderError("Listener returned an unverified resource")
        with self._lock:
            try:
                self._check()
            except BaseException:
                self._life.close_socket(raw)
                raise
            self._listener = raw

    @property
    def allowed_peer_ip(self):
        with self._lock:
            return self._allowed_peer_ip

    def authorize_peer(self, peer_ip):
        """Bind one actual verified peer; caller owns association/DHCP proof.

        This internal platform API accepts neither a QML action nor a peer claim.
        None is deny-all, never a wildcard. Repeating the same binding is safe;
        replacing it requires a new transport and a new owned network lease.
        """
        address = _bind_address(peer_ip, self._allow_loopback)
        with self._lock:
            self._check()
            if self._closed or self._finished.is_set() or self._listener_thread is None:
                raise SenderError("Sender is not awaiting an authorized peer")
            if self._allowed_peer_ip is not None and self._allowed_peer_ip != address:
                raise SenderError("Sender peer cannot be replaced")
            self._allowed_peer_ip = address
        return True

    def _accept_loop(self):
        requests = 0
        actor = None
        try:
            actor = self._life.begin('sender_accept')
            while not self._finished.is_set():
                self._check()
                try:
                    raw, address = self._listener.accept()
                except socket.timeout:
                    continue
                self._life.adopt(raw)
                with self._lock:
                    valid_peer = not self._closed and self._allowed_peer_ip is not None and address[0] == self._allowed_peer_ip
                    if self._peer_ip is not None and address[0] != self._peer_ip:
                        valid_peer = False
                    if not valid_peer or len(self._connections) >= 3:
                        if not self._life.close_socket(raw):
                            self.close(0)
                            raise SenderError("Sender peer cleanup pending")
                        continue
                    # Denied clients never allocate TLS workers, claim the WS,
                    # or exhaust the admitted-peer attempt allowance.
                    requests += 1
                    if requests > 16:
                        self._life.close_socket(raw)
                        raise SenderError("Connection attempt limit")
                    self._connections.add(raw)
                    worker = threading.Thread(target=self._handle_connection, args=(raw, address[0]), name="mta-sender-peer")
                    worker.daemon = True
                    self._workers.append(worker)
                    self._life.start_thread(worker)
        except (TransportError, ProtocolError) as error:
            self._fail(error)
        except (OSError, ValueError, RuntimeError):
            if not self._closed:
                self._fail(SenderError("Sender listener failed"))
        finally:
            if actor is not None:self._life.end(actor)
            if self._life.closing:self._cleanup_private(threading.current_thread())

    def _handle_connection(self, raw, peer_ip):
        sock = None
        claimed = False
        actor = None
        try:
            actor = self._life.begin('sender_peer')
            raw.settimeout(0.2)
            self._life.begin_wrap(raw)
            try:sock = self._context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
            except BaseException:
                self._life.failed_wrap(raw)
                raise
            self._life.finish_wrap(raw, sock)
            self._life.check()
            with self._lock:
                self._connections.discard(raw)
                self._connections.add(sock)
            handshake_deadline = min(self.deadline, time.monotonic() + 5)
            while True:
                self._check()
                if time.monotonic() >= handshake_deadline:
                    raise SenderError("TLS handshake deadline exceeded")
                try:
                    sock.do_handshake()
                    break
                except (socket.timeout, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
            stream = Stream(sock, self._stream_cancelled, self.deadline)
            target, headers = _request(stream)
            if target.path == "/websocket" and not target.query:
                with self._lock:
                    if self._ws_claimed:
                        self._http_error(stream, 409)
                        return
                    self._ws_claimed = True
                    self._peer_ip = peer_ip
                    claimed = True
                self._handle_ws(_websocket_server(stream, headers))
            elif target.path == "/download":
                claimed = self._handle_download(stream, target.query, peer_ip)
            else:
                self._http_error(stream, 404)
        except (TransportError, ProtocolError) as error:
            if claimed:
                self._fail(error)
        except (OSError, ValueError, RuntimeError):
            if claimed:
                self._fail(SenderError("Peer transport failed"))
        finally:
            closed = True
            if sock is not None:closed = self._life.close_socket(sock) and closed
            closed = self._life.close_socket(raw) and closed
            with self._lock:
                self._connections.discard(raw)
                if sock is not None:
                    self._connections.discard(sock)
            if not closed:self.close(0)
            if actor is not None:self._life.end(actor)
            if self._life.closing:self._cleanup_private(threading.current_thread())

    def _http_error(self, stream, code):
        stream.send(("HTTP/1.1 " + str(code) + " Rejected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode("ascii"))

    def _handle_ws(self, ws):
        self._notify("negotiating")
        ws.send(WsMessage("action", 0, "versionNegotiation", {"version": 1, "versions": [1]}))
        response = ws.receive()
        if response.msg_type != "ack" or response.id != 0 or response.name != "versionNegotiation":
            raise SenderError("Version ACK mismatch")
        if response.payload is None or isinstance(response.payload.get("version"), bool) or response.payload.get("version") != 1:
            raise SenderError("Unsupported MTA version")
        self._notify("awaiting_confirmation")
        ws.send(WsMessage("action", 1, "sendRequest", self._request_payload))
        response = ws.receive()
        if response.msg_type == "action" and response.name in ("status", "cancel"):
            self._status(ws, response)
            return
        if response.msg_type != "ack" or response.id != 1 or response.name != "sendRequest":
            raise SenderError("Send-request ACK mismatch")
        with self._lock:
            self._accepted = True
        self._notify("accepted")
        for _ in range(32):
            response = ws.receive()
            if response.msg_type != "action" or response.name not in ("status", "cancel"):
                raise SenderError("Unexpected transfer action")
            self._status(ws, response)
            if self._finished.is_set():
                return
        raise SenderError("Status message count limit")

    def _status(self, ws, message):
        payload = message.payload
        if get_task_id(payload) != self.task_id:
            raise SenderError("Status task mismatch")
        if message.name == "cancel":
            ws.send(message.make_ack())
            self._fail(Cancelled("Peer cancelled transfer"))
            return
        kind = payload.get("type")
        if isinstance(kind, bool) or kind not in (1, 2, 3):
            raise SenderError("Invalid transfer status")
        if kind == 1:
            # TLS send may have handed the final bytes to the peer while its
            # worker is descheduled before committing the byte counters. A
            # legitimate completion must not fail that narrow local race.
            # Never wait for an absent/partial download: only an already
            # identified final write, and still require actual completion.
            with self._lock:
                last_write_pending = self._last_write_pending
            if last_write_pending:
                while not self._last_write_done.wait(0.02):
                    self._check()
                    if self._finished.is_set():
                        raise SenderError("Download ended before completion status")
            with self._lock:
                if not self._accepted or not self._download_complete or self._downloaded_bytes != self._archive_size:
                    raise SenderError("Completion arrived before complete archive transfer")
            ws.send(message.make_ack())
            committed = False
            with self._lock:
                if not self._finished.is_set() and not self._cancelled.is_set() and not self.external_cancelled():
                    self.result = {"fileCount": self._file_count, "totalSize": self._actual_bytes,
                                   "archiveBytesSent": self._downloaded_bytes,
                                   "peer_completion_verified": True}
                    self.state = "completed"
                    self._finished.set()
                    committed = True
            # Only the winning terminal transaction may emit completion.
            # Call outside the transport lock: service callbacks may take a
            # separate state lock and must not introduce a cross-lock deadlock.
            if committed and self.callback is not None:
                self.callback("completed", {"fileCount": self._file_count, "totalSize": self._actual_bytes})
        else:
            ws.send(message.make_ack())
            self._fail(Cancelled("Peer refused transfer") if kind == 3 else SenderError("Peer reported transfer failure"))

    def _handle_download(self, stream, query, peer_ip):
        if len(query) > 512:
            self._http_error(stream, 400)
            return False
        try:
            values = parse_qs(query, keep_blank_values=True, strict_parsing=True)
            if set(values) - set(("taskId", "startByte", "endByte")) or any(len(items) != 1 for items in values.values()):
                raise SenderError("Ambiguous download query")
            task = validate_task_id(values.get("taskId", [None])[0])
            if values.get("startByte", ["0"])[0] != "0" or values.get("endByte", ["-1"])[0] != "-1":
                raise SenderError("Partial archive downloads are not supported")
        except (ValueError, ProtocolError, SenderError):
            self._http_error(stream, 400)
            return False
        with self._lock:
            if task != self.task_id or self._peer_ip != peer_ip:
                self._http_error(stream, 404)
                return False
            if not self._accepted or self._download_started:
                self._http_error(stream, 409)
                return False
            self._download_started = True
        self._notify("transferring", {"bytes": 0, "archiveSize": self._archive_size})
        try:
            stream.send(("HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: " + str(self._archive_size) +
                         "\r\nConnection: close\r\n\r\n").encode("ascii"))
            count = 0
            with open(self._archive_path, "rb") as source:
                while True:
                    data = source.read(CHUNK_BYTES)
                    if not data:
                        break
                    if count + len(data) == self._archive_size:
                        with self._lock:
                            self._last_write_pending = True
                    stream.send(data)
                    count += len(data)
                    with self._lock:
                        self._downloaded_bytes = count
                    self._notify("transferring", {"bytes": count, "archiveSize": self._archive_size})
            if count != self._archive_size:
                raise SenderError("Archive transfer size mismatch")
            with self._lock:
                self._download_complete = True
            self._last_write_done.set()
            self._notify("awaiting_result", {"archiveBytesSent": count})
            return True
        except TransportError as error:
            self._fail(error)
            raise
        except (OSError, ValueError):
            self._fail(SenderError("Archive transfer failed"))
            raise
        finally:
            # Wake any final-write status waiter even on write/reader/callback
            # failure. The waiter still checks complete + exact byte count.
            self._last_write_done.set()

    def wait(self):
        if self._listener is None:
            raise SenderError("Sender has not started")
        while not self._finished.wait(0.2):
            try:
                self._check()
            except TransportError as error:
                self._fail(error)
        if self.error is not None:
            raise self.error
        if self.result is None:
            raise SenderError("Sender ended without a verified result")
        return dict(self.result)

    def cancel(self):
        self._cancelled.set()
        self._fail(Cancelled("Transfer cancelled"))

    def _cleanup_private(self,ignore_thread=None):
        if not self._life.actors_quiet(ignore_thread):return False
        with self._lock:
            if self._private_directory is not None:
                directory = self._private_directory
                # Only the private directory created by this start invocation.
                identity = self._private_identity
                if not os.path.isabs(directory) or identity is None:
                    return False
                try:
                    device,inode,parent,canonical = identity
                    current = os.lstat(directory)
                    if (not stat.S_ISDIR(current.st_mode) or os.path.islink(directory) or
                            (current.st_dev,current.st_ino)!=(device,inode) or
                            os.path.realpath(os.path.dirname(directory)) != parent or
                            os.path.realpath(directory) != canonical):return False
                    shutil.rmtree(directory)
                    self._private_directory = None
                    self._private_identity = None
                except FileNotFoundError:
                    if os.path.lexists(directory):return False
                    self._private_directory = None
                    self._private_identity = None
                except Exception:return False
            if self._life.cleanup_ready(ignore_thread):self._context = None
            return self._private_directory is None

    def close(self,timeout=2):
        with self._lock:
            self._closed = True
        self._life.request_close()
        if not self._finished.is_set():
            try:self.cancel()
            except Exception:pass  # A callback error cannot skip owned cleanup.
        self._cancelled.set()
        self._life.close(timeout)
        self._cleanup_private()
        return self.closed()

    def lifecycle_status(self):
        result = self._life.snapshot()
        with self._lock:result['cleanup_pending'] = self._private_directory is not None
        result['close_verified'] = result['close_verified'] and not result['cleanup_pending']
        return result

    def closure_snapshot(self,raw):
        result = self._life.snapshot(raw)
        with self._lock:result['cleanup_pending'] = self._private_directory is not None
        result['close_verified'] = result['close_verified'] and not result['cleanup_pending']
        return result

    def closed(self):
        return self.lifecycle_status()['close_verified']

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
