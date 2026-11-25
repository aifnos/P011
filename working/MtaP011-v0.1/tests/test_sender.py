# -*- coding: utf-8 -*-
"""Real HOST TLS/WSS tests. This does not establish phone interoperability."""
import io
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
from mta_files import FileRegistry
from mta_protocol import WsMessage
from mta_sender import SenderError, SenderTransport
from mta_storage import SafeZipReceiver
from mta_transport import (Cancelled, Stream, TransportError, download_body,
                           read_headers, websocket_client)


def host_openssl():
    selected = os.environ.get("MTA_TEST_OPENSSL")
    candidates = [selected] if selected else []
    if os.name == "nt":
        candidates += [r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe"]
    else:
        candidates += ["/usr/bin/openssl", "/bin/openssl"]
    for value in candidates:
        if value and os.path.isfile(value):
            return value
    return None


class SenderTests(unittest.TestCase):
    def setUp(self):
        self.openssl = host_openssl()
        if self.openssl is None:
            self.skipTest("HOST OpenSSL unavailable; no device claim")
        self.base = tempfile.mkdtemp(prefix="mta-host-sender-test-")
        self.root = os.path.join(self.base, "user")
        self.temp_root = os.path.join(self.base, "private-temp")
        self.received_root = os.path.join(self.base, "received")
        os.makedirs(os.path.join(self.root, "Music"))
        os.mkdir(self.temp_root)
        os.mkdir(self.received_root)
        self.data = b"original file data\x00\xff" * 7000
        self.source = os.path.join(self.root, "Music", "private-name.bin")
        with open(self.source, "wb") as target:
            target.write(self.data)
        self.registry = FileRegistry(self.root)
        self.rows = self.registry.list_files()
        self.selection = self.registry.open_selection([row["id"] for row in self.rows])
        self.sender = None
        self.streams = []
        self.events = []

    def tearDown(self):
        for stream in self.streams:
            stream.socket.close()
        if self.sender is not None:
            self.sender.close()
        if hasattr(self, "selection"):
            self.selection.close()
        if hasattr(self, "base") and os.path.isdir(self.base):
            shutil.rmtree(self.base)

    def start(self, **options):
        values = dict(host="127.0.0.1", port=0, selection=self.selection,
                      openssl_path=self.openssl, task_id="host-test-task", sender_id="0011",
                      timeout=15, allow_loopback=True, allowed_peer_ip="127.0.0.1", temp_root=self.temp_root,
                      state_callback=lambda state, details: self.events.append((state, details)))
        values.update(options)
        self.sender = SenderTransport(**values)
        self.sender.start()
        return self.sender

    def connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", self.sender.port), 3)
        sock = context.wrap_socket(raw, server_hostname="127.0.0.1")
        stream = Stream(sock, deadline=time.monotonic() + 5)
        self.streams.append(stream)
        return stream

    def negotiate(self):
        ws = websocket_client(self.connect(), "127.0.0.1", self.sender.port)
        version = ws.receive()
        self.assertEqual((version.name, version.msg_type, version.id), ("versionNegotiation", "action", 0))
        ws.send(version.make_ack({"version": 1, "threadLimit": 1}))
        request = ws.receive()
        self.assertEqual((request.name, request.id), ("sendRequest", 1))
        self.assertEqual(request.payload["fileCount"], 1)
        self.assertEqual(request.payload["totalSize"], len(self.data))
        return ws, request

    def accept(self, ws, request):
        ws.send(request.make_ack())
        deadline = time.monotonic() + 2
        while not self.sender._accepted and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.sender._accepted)

    def download(self, query=None):
        stream = self.connect()
        query = query or "taskId=host-test-task"
        stream.send(("GET /download?" + query + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").encode("ascii"))
        first, headers = read_headers(stream)
        body = io.BytesIO()
        if first.startswith(b"HTTP/1.1 200 "):
            download_body(stream, headers, body)
        return first, body.getvalue()

    def status(self, ws, kind=1, task_id="host-test-task"):
        ws.send(WsMessage("action", 2, "status", {"taskId": task_id, "id": task_id, "type": kind, "reason": "fixture"}))

    def test_host_tls_wss_true_transfer_and_status(self):
        self.start()
        ws, request = self.negotiate()
        self.accept(ws, request)
        first, archive_data = self.download()
        self.assertTrue(first.startswith(b"HTTP/1.1 200 "))
        archive_path = os.path.join(self.base, "received.zip")
        with open(archive_path, "wb") as output:
            output.write(archive_data)
        result = SafeZipReceiver(self.received_root, reserve_bytes=0).receive(archive_path, "host-test-task", expected_files=1, expected_bytes=len(self.data))
        with open(result["files"][0], "rb") as source:
            self.assertEqual(source.read(), self.data)
        self.status(ws)
        ack = ws.receive()
        self.assertEqual((ack.msg_type, ack.name, ack.id), ("ack", "status", 2))
        sent = self.sender.wait()
        self.assertEqual(sent["totalSize"], len(self.data))
        self.assertEqual(sent["archiveBytesSent"], len(archive_data))
        self.assertTrue(sent["peer_completion_verified"])
        self.assertEqual(self.sender.state, "completed")
        self.assertNotIn("private-name", repr(self.events))
        self.sender.close()
        self.assertEqual(os.listdir(self.temp_root), [])
        self.assertFalse(any(worker.is_alive() for worker in self.sender._workers))

    def test_default_deny_then_actual_peer_authorization(self):
        self.start(allowed_peer_ip=None)
        self.assertIsNone(self.sender.allowed_peer_ip)
        for _ in range(18):
            with socket.create_connection(("127.0.0.1", self.sender.port), 2) as raw:
                raw.settimeout(2)
                self.assertEqual(raw.recv(1), b"")
        self.assertEqual(self.sender._workers, [])
        self.assertIsNone(self.sender._peer_ip)
        self.assertIsNone(self.sender.result)
        self.assertTrue(self.sender.authorize_peer("127.0.0.1"))
        self.assertTrue(self.sender.authorize_peer("127.0.0.1"))
        ws, request = self.negotiate()
        self.accept(ws, request)
        self.assertTrue(self.download()[1])
        self.status(ws)
        self.assertEqual(ws.receive().name, "status")
        self.assertTrue(self.sender.wait()["peer_completion_verified"])
        with self.assertRaises(SenderError):
            self.sender.authorize_peer("127.0.0.1")

    def test_actual_final_write_local_counter_race(self):
        self.start()
        ws, request = self.negotiate()
        self.accept(ws, request)
        with open(self.sender._archive_path, "rb") as source:
            archive = source.read()
        final = archive[-(len(archive) % 65536 or 65536):]
        written = threading.Event()
        release = threading.Event()
        original = Stream.send
        def delay_final_counter(stream, data):
            original(stream, data)
            if data == final:
                written.set()
                if not release.wait(3):
                    raise TransportError("HOST final-write fixture timed out")
        answers = []
        errors = []
        waiter = None
        def read_ack():
            try: answers.append(ws.receive())
            except Exception as error: errors.append(error)
        with mock.patch.object(Stream, "send", delay_final_counter):
            try:
                self.assertEqual(self.download()[1], archive)
                self.assertTrue(written.wait(2))
                self.assertFalse(self.sender._download_complete)
                self.status(ws)
                waiter = threading.Thread(target=read_ack)
                waiter.start()
                time.sleep(0.05)
                self.assertFalse(self.sender._finished.is_set())
            finally:
                release.set()
            if waiter is not None: waiter.join(3)
        self.assertIsNotNone(waiter)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(answers[0].name, "status")
        self.assertTrue(self.sender.wait()["peer_completion_verified"])

    def test_peer_authorization_cannot_retarget_or_accept_public_input(self):
        self.start(allowed_peer_ip=None)
        for value in (None, True, "0.0.0.0", "8.8.8.8", "example.com", "10.0.0.255"):
            with self.assertRaises(TransportError):
                self.sender.authorize_peer(value)
        self.sender.authorize_peer("192.168.49.2")
        with self.assertRaises(SenderError):
            self.sender.authorize_peer("127.0.0.1")
        with self.assertRaises(AttributeError):
            self.sender.allowed_peer_ip = "127.0.0.1"
        self.assertEqual(self.sender.allowed_peer_ip, "192.168.49.2")
        with socket.create_connection(("127.0.0.1", self.sender.port), 2) as raw:
            raw.settimeout(2)
            self.assertEqual(raw.recv(1), b"")
        self.assertEqual(self.sender._workers, [])

    def test_peer_authorization_requires_live_started_transport(self):
        self.sender = SenderTransport("127.0.0.1", 0, self.selection, self.openssl,
                                      allow_loopback=True, temp_root=self.temp_root)
        with self.assertRaises(SenderError):
            self.sender.authorize_peer("127.0.0.1")
        self.sender.close()
        with self.assertRaises(Cancelled):
            self.sender.authorize_peer("127.0.0.1")
        self.start(allowed_peer_ip=None)
        self.sender.deadline = time.monotonic() - 1
        with self.assertRaises(TransportError):
            self.sender.authorize_peer("127.0.0.1")

    def test_static_peer_authorization_cannot_retarget(self):
        self.start()
        self.assertTrue(self.sender.authorize_peer("127.0.0.1"))
        with self.assertRaises(SenderError):
            self.sender.authorize_peer("192.168.49.2")

    def test_scoped_listener_real_tls_transfer_and_actual_port(self):
        created = []
        def factory(host, port):
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.bind((host, port))
            created.append(raw)
            return raw
        self.start(listener_factory=factory, allowed_peer_ip=None)
        self.assertEqual(created[0].getsockname(), ("127.0.0.1", self.sender.port))
        self.sender.authorize_peer("127.0.0.1")
        ws, request = self.negotiate()
        self.accept(ws, request)
        self.assertTrue(self.download()[1])
        self.status(ws)
        self.assertEqual(ws.receive().name, "status")
        self.assertTrue(self.sender.wait()["peer_completion_verified"])
        self.sender.close()
        self.assertEqual(created[0].fileno(), -1)

    def test_scoped_listener_wrong_bind_closes_and_never_publishes_port(self):
        created = []
        def factory(host, port):
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.bind(("127.0.0.1", 0))
            created.append(raw)
            return raw
        with self.assertRaises(SenderError):
            self.start(host="192.168.49.1", listener_factory=factory)
        self.assertEqual(created[0].fileno(), -1)
        self.assertIsNone(self.sender._listener_thread)
        self.assertEqual(os.listdir(self.temp_root), [])

    def test_scoped_listener_udp_and_already_listening_are_rejected(self):
        for kind, listen in ((socket.SOCK_DGRAM, False), (socket.SOCK_STREAM, True)):
            created = []
            def factory(host, port):
                raw = socket.socket(socket.AF_INET, kind)
                raw.bind((host, port))
                if listen: raw.listen(1)
                created.append(raw)
                return raw
            with self.assertRaises(SenderError):
                self.start(listener_factory=factory)
            self.assertEqual(created[0].fileno(), -1)
            self.assertEqual(os.listdir(self.temp_root), [])

    def test_scoped_listener_failure_does_not_create_default_socket(self):
        def factory(host, port):
            raise OSError("HOST fixture scoped listener failed")
        with mock.patch("mta_sender.socket.socket", wraps=socket.socket) as default:
            with self.assertRaises(OSError):
                self.start(listener_factory=factory)
            default.assert_not_called()
        self.assertEqual(os.listdir(self.temp_root), [])

    def test_scoped_listener_late_return_after_close_is_closed(self):
        """HOST real raw socket + deterministic handoff; no device/RF claim."""
        entered = threading.Event()
        release = threading.Event()
        created = []
        errors = []
        def factory(host, port):
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.bind((host, port))
            created.append(raw)
            entered.set()
            if not release.wait(3):
                raw.close()
                raise SenderError("HOST bounded late-listener fixture timed out")
            return raw
        def start_pending():
            try:
                self.start(listener_factory=factory, allowed_peer_ip=None)
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=start_pending)
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.sender.close()
            release.set()
            worker.join(3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], Cancelled)
            self.assertEqual(created[0].fileno(), -1)
            self.assertIsNone(self.sender.result)
            self.assertIsNone(self.sender._listener_thread)
            self.assertEqual(os.listdir(self.temp_root), [])
        finally:
            release.set()
            worker.join(3)
            for raw in created:
                raw.close()

    def test_cancel_during_completion_ack_never_emits_completed(self):
        """HOST state fixture: tests ACK/terminal race, not archive/TLS bytes."""
        self.sender = SenderTransport("127.0.0.1", 0, self.selection, self.openssl,
            allow_loopback=True, temp_root=self.temp_root, task_id="host-terminal-race",
            state_callback=lambda state, details: self.events.append((state, details)))
        self.sender._accepted = True
        self.sender._download_complete = True
        self.sender._archive_size = 100
        self.sender._downloaded_bytes = 100
        sender = self.sender
        class CancelDuringAck(object):
            def send(self, message):
                self.asserted_ack = message.msg_type == "ack"
                sender.cancel()
        ws = CancelDuringAck()
        sender._status(ws, WsMessage("action", 2, "status",
            {"taskId": sender.task_id, "id": sender.task_id, "type": 1}))
        self.assertTrue(ws.asserted_ack)
        self.assertIsNone(sender.result)
        self.assertIsInstance(sender.error, Cancelled)
        self.assertEqual(sender.state, "cancelled")
        self.assertEqual([row[0] for row in self.events], ["cancelled"])

    def test_committed_completion_callback_does_not_hold_sender_lock(self):
        """HOST terminal fixture: callback may take a coordinator lock safely."""
        actors = []
        observed = []
        sender_holder = []
        def callback(state, details):
            observed.append(state)
            if state == "completed":
                worker = threading.Thread(target=sender_holder[0].cancel)
                actors.append(worker)
                worker.start()
                worker.join(1)
                self.assertFalse(worker.is_alive(), "Completion callback held sender lock across coordinator callback")
        self.sender = SenderTransport("127.0.0.1", 0, self.selection, self.openssl,
            allow_loopback=True, temp_root=self.temp_root, task_id="host-committed-race", state_callback=callback)
        sender_holder.append(self.sender)
        self.sender._accepted = True
        self.sender._download_complete = True
        self.sender._archive_size = 100
        self.sender._downloaded_bytes = 100
        class AckWithoutCancellation(object):
            def send(self, message):
                pass
        try:
            self.sender._status(AckWithoutCancellation(), WsMessage("action", 2, "status",
                {"taskId": self.sender.task_id, "id": self.sender.task_id, "type": 1}))
            self.assertEqual(observed, ["completed"])
            self.assertEqual(self.sender.state, "completed")
            self.assertTrue(self.sender.result["peer_completion_verified"])
            self.assertIsNone(self.sender.error)
        finally:
            for actor in actors:
                actor.join(2)

    def test_download_get_alone_cannot_succeed(self):
        self.start()
        first, body = self.download()
        self.assertTrue(first.startswith(b"HTTP/1.1 404 "))
        self.assertEqual(body, b"")
        self.assertIsNone(self.sender.result)
        self.assertFalse(self.sender._download_started)

    def test_download_bytes_without_status_cannot_succeed(self):
        self.start()
        ws, request = self.negotiate()
        self.accept(ws, request)
        first, data = self.download()
        self.assertTrue(first.startswith(b"HTTP/1.1 200 "))
        self.assertTrue(data)
        self.assertIsNone(self.sender.result)
        self.sender.cancel()
        with self.assertRaises(Cancelled):
            self.sender.wait()

    def test_early_success_rejected(self):
        self.start()
        ws, request = self.negotiate()
        self.accept(ws, request)
        self.status(ws)
        with self.assertRaises(SenderError):
            self.sender.wait()
        self.assertIsNone(self.sender.result)

    def test_wrong_task_success_rejected(self):
        self.start()
        ws, request = self.negotiate()
        self.accept(ws, request)
        self.download()
        self.status(ws, task_id="another-task")
        with self.assertRaises(SenderError):
            self.sender.wait()
        self.assertIsNone(self.sender.result)

    def test_refused_transfer_never_downloaded(self):
        self.start()
        ws, request = self.negotiate()
        self.status(ws, kind=3)
        ack = ws.receive()
        self.assertEqual(ack.name, "status")
        with self.assertRaises(Cancelled):
            self.sender.wait()
        self.assertFalse(self.sender._download_started)

    def test_cancel_before_acceptance(self):
        self.start()
        ws, request = self.negotiate()
        ws.send(WsMessage("action", 3, "cancel", {"taskId": "host-test-task"}))
        self.assertEqual(ws.receive().name, "cancel")
        with self.assertRaises(Cancelled):
            self.sender.wait()
        self.assertFalse(self.sender._download_started)

    def test_boolean_version_is_not_integer_version(self):
        self.start()
        ws = websocket_client(self.connect(), "127.0.0.1", self.sender.port)
        ws.receive()
        ws.send(WsMessage("ack", 0, "versionNegotiation", {"version": True}))
        with self.assertRaises(SenderError):
            self.sender.wait()
        self.assertIsNone(self.sender.result)

    def test_bad_queries_and_repeated_download(self):
        self.start()
        ws, request = self.negotiate()
        self.accept(ws, request)
        for query, code in (("taskId=other", 404), ("taskId=../bad", 400), ("taskId=host-test-task&taskId=host-test-task", 400), ("taskId=host-test-task&startByte=1", 400)):
            first, data = self.download(query)
            self.assertTrue(first.startswith(("HTTP/1.1 " + str(code) + " ").encode("ascii")))
            self.assertEqual(data, b"")
        self.assertTrue(self.download()[1])
        first, data = self.download()
        self.assertTrue(first.startswith(b"HTTP/1.1 409 "))
        self.assertEqual(data, b"")
        self.assertIsNone(self.sender.result)

    def test_one_websocket_peer(self):
        self.start()
        ws, request = self.negotiate()
        with self.assertRaises(TransportError):
            websocket_client(self.connect(), "127.0.0.1", self.sender.port)
        self.assertFalse(self.sender._accepted)

    def test_wrong_version_ack_and_unmasked_frame(self):
        self.start()
        ws = websocket_client(self.connect(), "127.0.0.1", self.sender.port)
        ws.receive()
        ws.send(WsMessage("ack", 1, "versionNegotiation", {"version": 1}))
        with self.assertRaises(SenderError):
            self.sender.wait()
        self.assertIsNone(self.sender.result)
        self.sender.close()
        self.start()
        ws = websocket_client(self.connect(), "127.0.0.1", self.sender.port)
        ws.receive()
        ws.client = False  # deliberately violates client mask direction
        ws.send(WsMessage("ack", 0, "versionNegotiation", {"version": 1}))
        with self.assertRaises(TransportError):
            self.sender.wait()

    def test_source_changed_after_registry_open_fails(self):
        with open(self.source, "ab") as target:
            target.write(b"changed")
        with self.assertRaises(SenderError):
            self.start()
        self.assertEqual(os.listdir(self.temp_root), [])

    def test_closed_selection_and_arbitrary_paths_rejected(self):
        base = dict(host="127.0.0.1", port=0, openssl_path=self.openssl, allow_loopback=True)
        for value in ([self.source], self.rows, {"path": self.source}):
            with self.assertRaises(SenderError):
                SenderTransport(selection=value, **base)
        self.selection.close()
        with self.assertRaises(SenderError):
            SenderTransport(selection=self.selection, **base)

    def test_production_bind_scope(self):
        base = dict(port=0, selection=self.selection, openssl_path=self.openssl)
        for address in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "example.com", "10.0.0.255", "192.168.001.2"):
            with self.assertRaises(TransportError):
                SenderTransport(host=address, **base)
        with self.assertRaises(TransportError):
            SenderTransport(host="8.8.8.8", allow_loopback=True, **base)

    def test_idle_deadline_and_private_cleanup(self):
        self.start()
        self.sender.deadline = time.monotonic() + 0.3
        with self.assertRaises(TransportError):
            self.sender.wait()
        self.sender.close()
        self.assertEqual(os.listdir(self.temp_root), [])

    def test_zero_length_and_multiple_files_zip_counts(self):
        self.selection.close()
        extra = os.path.join(self.root, "Music", "zero.txt")
        with open(extra, "wb"):
            pass
        rows = self.registry.list_files()
        self.selection = self.registry.open_selection([row["id"] for row in rows])
        self.start()
        with zipfile.ZipFile(self.sender._archive_path, "r") as archive:
            self.assertEqual(len(archive.infolist()), 2)
            self.assertEqual(sum(info.file_size for info in archive.infolist()), len(self.data))
            self.assertTrue(all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist()))
            self.assertEqual(sorted(archive.read(info) for info in archive.infolist()), [b"", self.data])


if __name__ == "__main__":
    unittest.main()
