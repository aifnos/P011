# -*- coding: utf-8 -*-
"""HOST-only real TLS/WSS receiver integration; no radio/device claims.

Receiver production rejects loopback. Tests override private_ipv4 only while
constructing a receiver, not during its network, TLS, WS or storage operations.
Malicious sender subclasses are network fixtures, not production behaviors.
"""
import os
import shutil
import socket
import ssl
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
from mta_files import FileRegistry
from mta_protocol import ProtocolError, WsMessage
from mta_sender import SenderTransport
from mta_storage import SafeZipReceiver, StorageError
from mta_transport import Cancelled, ReceiverTransport, TransportError, MAX_ARCHIVE


def host_openssl():
    selected = os.environ.get("MTA_TEST_OPENSSL")
    paths = [selected] if selected else []
    if os.name == "nt":
        paths += [r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe"]
    else:
        paths += ["/usr/bin/openssl", "/bin/openssl"]
    return next((path for path in paths if path and os.path.isfile(path)), None)


class UnknownActionSender(SenderTransport):
    def _handle_ws(self, ws):
        ws.send(WsMessage("action", 0, "unknownPeerAction", {}))
        ws.receive()


class OversizeBodySender(SenderTransport):
    def _handle_download(self, stream, query, peer_ip):
        # Claim an oversized archive without actually allocating/sending one.
        stream.send(("HTTP/1.1 200 OK\r\nContent-Length: " + str(MAX_ARCHIVE + 1) +
                     "\r\nConnection: close\r\n\r\n").encode("ascii"))
        return True


class OversizeRequestBodySender(SenderTransport):
    def _handle_download(self, stream, query, peer_ip):
        size = self._actual_bytes + 1024 * 1024 + 1
        stream.send(("HTTP/1.1 200 OK\r\nContent-Length: " + str(size) +
                     "\r\nConnection: close\r\n\r\n").encode("ascii"))
        return True


class OversizeChunkSender(SenderTransport):
    def _handle_download(self, stream, query, peer_ip):
        size = self._actual_bytes + 1024 * 1024 + 1
        stream.send(("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                     "Connection: close\r\n\r\n{:x}\r\n".format(size)).encode("ascii"))
        return True


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.openssl = host_openssl()
        if self.openssl is None:
            self.skipTest("HOST OpenSSL unavailable; no P011/phone claim")
        self.base = tempfile.mkdtemp(prefix="mta-host-receiver-test-")
        self.user = os.path.join(self.base, "user")
        self.incoming = os.path.join(self.base, "incoming")
        self.private = os.path.join(self.base, "private")
        os.makedirs(os.path.join(self.user, "Music"))
        os.mkdir(self.incoming)
        os.mkdir(self.private)
        self.data = b"actual end-to-end receiver bytes\x00\xff" * 5000
        with open(os.path.join(self.user, "Music", "test.bin"), "wb") as target:
            target.write(self.data)
        self.registry = FileRegistry(self.user)
        self.selection = self.registry.open_selection([row["id"] for row in self.registry.list_files()])
        self.servers = []
        self.cancelled = [False]
        self.storage = SafeZipReceiver(self.incoming, reserve_bytes=0)

    def tearDown(self):
        for server in self.servers:
            server.close()
        if hasattr(self, "selection"):
            self.selection.close()
        if hasattr(self, "base") and os.path.isdir(self.base):
            shutil.rmtree(self.base)

    def sender(self, sender_type=SenderTransport, port=0):
        server = sender_type("127.0.0.1", port, self.selection, self.openssl,
                             task_id="receiver-host-test", sender_id="0011", timeout=15,
                             allow_loopback=True, allowed_peer_ip="127.0.0.1", temp_root=self.private)
        self.servers.append(server)
        server.start()
        return server

    def receiver(self, port, **options):
        with mock.patch("mta_transport.private_ipv4", return_value="127.0.0.1"):
            receiver = ReceiverTransport("127.0.0.1", port, self.storage,
                                         cancelled=lambda: self.cancelled[0], timeout=15, **options)
        return receiver

    def assert_no_temporary_files(self):
        self.assertFalse(any(name.startswith(".mta-") for name in os.listdir(self.incoming)))

    def test_real_sender_receiver_storage_and_peer_ack(self):
        server = self.sender()
        receiver = self.receiver(server.port)
        requests = []
        network_progress = []
        file_progress = []
        def confirm(request):
            requests.append(request)
            return True
        result = receiver.run(confirm, progress=network_progress.append,
                              file_progress=lambda done, total: file_progress.append((done, total)))
        self.assertEqual(len(requests), 1)
        self.assertEqual(result["fileCount"], 1)
        self.assertEqual(result["totalSize"], len(self.data))
        self.assertTrue(result["peer_ack_verified"])
        with open(result["files"][0], "rb") as source:
            self.assertEqual(source.read(), self.data)
        sent = server.wait()
        self.assertTrue(sent["peer_completion_verified"])
        self.assertEqual(sent["archiveBytesSent"], network_progress[-1])
        self.assertEqual(file_progress[-1], (len(self.data), len(self.data)))
        self.assert_no_temporary_files()

    def test_scoped_connector_actual_tcp_tls_two_connections_and_hash(self):
        server = self.sender()
        calls = []
        def factory(host, port, timeout):
            raw = socket.create_connection((host, port), timeout, source_address=("127.0.0.1", 0))
            calls.append((raw.getsockname()[0], raw.getpeername(), timeout))
            return raw
        receiver = self.receiver(server.port, socket_factory=factory, source_ip="127.0.0.1")
        result = receiver.run(lambda request: True)
        self.assertTrue(result["peer_ack_verified"])
        self.assertTrue(server.wait()["peer_completion_verified"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(row[0] == "127.0.0.1" and row[1] == ("127.0.0.1", server.port)
                            and 0 < row[2] <= 3 for row in calls))
        with open(result["files"][0], "rb") as source:
            self.assertEqual(source.read(), self.data)
        self.assert_no_temporary_files()

    def test_scoped_connector_requires_pair_and_private_source(self):
        for options in ({"source_ip": "192.168.49.2"}, {"socket_factory": lambda *args: None},
                        {"socket_factory": "not callable", "source_ip": "192.168.49.2"},
                        {"socket_factory": lambda *args: None, "source_ip": "8.8.8.8"}):
            with self.assertRaises(TransportError):
                ReceiverTransport("192.168.49.1", 9443, self.storage, **options)

    def test_scoped_connector_wrong_source_or_target_closes_before_tls(self):
        server = self.sender()
        for host, expected_source in (("127.0.0.1", "192.168.49.2"),
                                      ("192.168.49.1", "127.0.0.1")):
            sockets = []
            def factory(host, port, timeout):
                raw = socket.create_connection(("127.0.0.1", server.port), timeout)
                sockets.append(raw)
                return raw
            with mock.patch("mta_transport.private_ipv4", side_effect=lambda value: value):
                receiver = ReceiverTransport(host, server.port, self.storage,
                    socket_factory=factory, source_ip=expected_source)
            with self.assertRaises(TransportError):
                receiver.connect()
            self.assertEqual(sockets[0].fileno(), -1)
            self.assertIsNone(receiver.fingerprint)
            self.assertFalse(server._ws_claimed)

    def test_scoped_connector_exception_has_no_default_route_fallback(self):
        def factory(*arguments):
            raise OSError("HOST fixture scoped connection failed")
        receiver = self.receiver(9443, socket_factory=factory, source_ip="127.0.0.1")
        with mock.patch("mta_transport.socket.create_connection") as default:
            with self.assertRaises(OSError):
                receiver.connect()
            default.assert_not_called()

    def test_scoped_connector_cancel_after_connect_closes_raw(self):
        server = self.sender()
        sockets = []
        def factory(host, port, timeout):
            raw = socket.create_connection((host, port), timeout)
            sockets.append(raw)
            self.cancelled[0] = True
            return raw
        receiver = self.receiver(server.port, socket_factory=factory, source_ip="127.0.0.1")
        with self.assertRaises(Cancelled):
            receiver.connect()
        self.assertEqual(sockets[0].fileno(), -1)
        self.assertIsNone(receiver.fingerprint)

    def test_confirmation_rejection_never_downloads(self):
        server = self.sender()
        receiver = self.receiver(server.port)
        with self.assertRaises(Cancelled):
            receiver.run(lambda request: False)
        self.assertFalse(server._download_started)
        self.assertIsNone(server.result)
        self.assertEqual(os.listdir(self.incoming), [])

    def test_cancel_before_connection(self):
        server = self.sender()
        receiver = self.receiver(server.port)
        self.cancelled[0] = True
        with self.assertRaises(Cancelled):
            receiver.run(lambda request: True)
        self.assertFalse(server._ws_claimed)
        self.assertEqual(os.listdir(self.incoming), [])

    def test_cancel_during_actual_download_cleans_partial_zip(self):
        server = self.sender()
        receiver = self.receiver(server.port)
        progress = []
        def cancel_progress(count):
            progress.append(count)
            self.cancelled[0] = True
        with self.assertRaises(Cancelled):
            receiver.run(lambda request: True, progress=cancel_progress)
        self.assertTrue(progress)
        self.assertLess(progress[-1], len(self.data))
        self.assertEqual(os.listdir(self.incoming), [])
        self.assertIsNone(server.result)

    def test_actual_same_endpoint_certificate_rotation_rejected_and_closed(self):
        first = self.sender()
        receiver = self.receiver(first.port)
        initial = receiver.connect()
        pinned = receiver.fingerprint
        self.assertTrue(pinned)
        initial.socket.close()
        port = first.port
        first.close()
        replacement = self.sender(port=port)
        self.assertEqual(replacement.port, port)
        captured = []
        actual_wrap = receiver.context.wrap_socket
        def capture(*arguments, **options):
            sock = actual_wrap(*arguments, **options)
            captured.append(sock)
            return sock
        with mock.patch.object(receiver.context, "wrap_socket", side_effect=capture):
            with self.assertRaises(TransportError):
                receiver.connect()
        self.assertEqual(receiver.fingerprint, pinned)
        self.assertTrue(captured)
        self.assertEqual(captured[0].fileno(), -1)

    def test_declared_oversized_download_rejected_without_large_write(self):
        server = self.sender(OversizeBodySender)
        receiver = self.receiver(server.port)
        with self.assertRaises(TransportError):
            receiver.run(lambda request: True)
        self.assertEqual(os.listdir(self.incoming), [])
        self.assertIsNone(server.result)

    def test_archive_limited_by_confirmed_request_not_only_global_cap(self):
        server = self.sender(OversizeRequestBodySender)
        receiver = self.receiver(server.port)
        with self.assertRaisesRegex(TransportError, "Archive byte limit"):
            receiver.run(lambda request: True)
        self.assertEqual(os.listdir(self.incoming), [])
        self.assertIsNone(server.result)

    def test_oversize_chunk_rejected_before_attempting_body_read(self):
        server = self.sender(OversizeChunkSender)
        receiver = self.receiver(server.port)
        with self.assertRaisesRegex(TransportError, "Archive byte limit"):
            receiver.run(lambda request: True)
        self.assertEqual(os.listdir(self.incoming), [])
        self.assertIsNone(server.result)

    def test_no_space_rejected_before_download_connection(self):
        server = self.sender()
        self.storage = SafeZipReceiver(self.incoming, reserve_bytes=16, free_space=lambda root: 0)
        receiver = self.receiver(server.port)
        with self.assertRaises(StorageError):
            receiver.run(lambda request: True)
        self.assertFalse(server._download_started)
        self.assertEqual(os.listdir(self.incoming), [])

    def test_unknown_action_rejected_over_actual_wss(self):
        server = self.sender(UnknownActionSender)
        receiver = self.receiver(server.port)
        called = []
        with self.assertRaises(ProtocolError):
            receiver.run(lambda request: called.append(request) or True)
        self.assertEqual(called, [])
        self.assertEqual(os.listdir(self.incoming), [])

    def test_production_receiver_still_rejects_loopback_and_public(self):
        for host in ("127.0.0.1", "0.0.0.0", "8.8.8.8", "hostname", "192.168.001.2"):
            with self.assertRaises(TransportError):
                ReceiverTransport(host, 33331, self.storage)

    def test_expired_deadline_prevents_network_connection(self):
        server = self.sender()
        receiver = self.receiver(server.port)
        receiver.deadline = time.monotonic() - 1
        with mock.patch("mta_transport.socket.create_connection", side_effect=AssertionError("Expired deadline must not open a socket")):
            with self.assertRaises(TransportError):
                receiver.connect()


if __name__ == "__main__":
    unittest.main()
