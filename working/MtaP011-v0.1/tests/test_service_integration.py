# -*- coding: utf-8 -*-
"""HOST service safety regressions, never P011 or phone acceptance.

Radio/network helpers below are explicit non-mutating fixtures. The last test
uses real HOST TLS/WSS, archive transport and SafeZipReceiver, but injects a
completion-write fault after genuine atomic file commit. It cannot establish
mobile discovery, Wi-Fi restoration, or interoperability.
"""
import base64
import http.client
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import p011_json as json
import mta_service
from mta_files import FileRegistry
from mta_protocol import P2pInfo
from mta_sender import SenderTransport
from mta_storage import SafeZipReceiver
from mta_transport import Cancelled, ReceiverTransport, TransportError, WebSocket
from mta_wifi import WifiRestoreError


BLUEZ = {"powered": True, "features": True, "connectable_advert": True,
         "bredr_enabled": True, "le_enabled": True, "global_advertising": False,
         "max_adv": 31, "max_scan": 31, "bluez_advertising_known": True,
         "bluez_advertising_active": False, "active_instances": 0}
HOST_EVENTS = []


class FakeKey(object):
    public_key = base64.b64encode(b"HOST public fixture").decode("ascii")
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True
        HOST_EVENTS.append("key_free")


class FakeCrypto(object):
    keys = []
    def __init__(self, *unused):
        pass
    def generate_keypair(self):
        HOST_EVENTS.append("key_generate")
        key = FakeKey()
        self.keys.append(key)
        return key


class FakeHelper(object):
    instances = []
    failed_command = None
    fail_close = False
    def __init__(self, path, callback):
        self.callback = callback
        self.closed = False
        self.close_calls = 0
        self.commands = []
        self.instances.append(self)
        HOST_EVENTS.append("helper_create")
    def start(self):
        # Production explicitly assigns ownership before its reader can run.
        HOST_EVENTS.append("helper_start")
    def send(self, value):
        HOST_EVENTS.append("ipc_" + str(value.get("cmd")))
        if value.get("cmd") == self.failed_command:
            raise ValueError("HOST helper command fault")
        self.commands.append(value)
        if value.get('cmd')=='listen':self.callback({'event':'listen','code':'ready'})
        elif value.get('cmd')=='advert':self.callback({'event':'advert','code':'ready'})
    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise OSError("HOST helper close failed")
        self.closed = True
        HOST_EVENTS.append("helper_close")
        return True
    def closure_verified(self):return self.closed is True


class FakeLease(object):
    gateway = "192.168.49.1"
    def __init__(self, backend):
        self.backend = backend
        self.close_calls = 0
        self.restored = False
        self.closed = False
        self.prepared = False
    def __enter__(self):
        return self
    def prepare(self):
        HOST_EVENTS.append('network_prepare')
        if self.backend.fail_prepare:raise WifiRestoreError('HOST original snapshot preparation failure')
        HOST_EVENTS.append('network_snapshot_held')
        self.prepared=True
    def connect(self,info):
        self.prepared=False;self.backend.receive_calls+=1;HOST_EVENTS.append('network_connect')
        self.backend.observations.append({'consented':self.backend.observer.operation.consent is True,
                                         'file_prompt_present':bool(self.backend.observer.request)})
        if self.backend.fail_after_mutation:
            self.backend._restore_failed=True;raise WifiRestoreError('HOST network mutation failure')
    def actors_closed(self):return self.closed is True
    def close(self):
        HOST_EVENTS.append("network_restore_begin")
        self.close_calls += 1
        self.restored = self.backend.restore_ok
        self.closed = self.restored
        self.backend._restore_failed = not self.restored
        if self.restored:
            self.backend._active_lease = None
            HOST_EVENTS.append("network_restore_confirmed")
        return self.restored
    restore = close


class FakeWifi(object):
    """Mirrors the real backend's ownership on failure before return."""
    instances = []
    restore_ok = True
    fail_after_mutation = False
    fail_prepare = False
    observations = []
    observer = None
    def __init__(self, *unused):
        self._active_lease = None
        self._restore_failed = False
        self.receive_calls = 0
        self.prepare_calls = 0
        self.instances.append(self)
    def prepare(self, cancelled=None, timeout=180):
        lease=self.begin_prepare(cancelled,timeout);lease.prepare();return lease
    def begin_prepare(self, cancelled=None, timeout=180):
        if self._restore_failed or self._active_lease is not None:
            raise WifiRestoreError("HOST pending or existing lease")
        self.prepare_calls += 1
        self._active_lease = FakeLease(self)
        return self._active_lease
    def status(self):
        return {"prepared": self._active_lease is not None,
                "restorePending": self._restore_failed,'recoveryLocked':self._restore_failed}
    def receive(self, info, cancelled=None, timeout=None, consented=False):
        if self._restore_failed:
            raise WifiRestoreError("HOST previous restoration unconfirmed")
        self.receive_calls += 1
        if self._active_lease is None:
            self._active_lease = FakeLease(self)
        HOST_EVENTS.append("network_connect")
        self.observations.append({"consented": consented,
                                  "file_prompt_present": bool(self.observer and self.observer.request)})
        if self.fail_after_mutation:
            self._restore_failed = True
            raise WifiRestoreError("HOST failure after network mutation and failed restoration")
        return self._active_lease
    def restore_active(self):
        if self._active_lease is None:
            return not self._restore_failed
        return self._active_lease.close()
    def recover_pending(self):return self.restore_active()


class FakeReceiver(object):
    mode = "success"
    owner = None
    results = []
    def __init__(self, host, port, receiver, cancelled=None, *unused, **options):
        self.receiver = receiver
        self.cancelled = cancelled
        self.closing=False;self.run_thread=None
    def close(self,timeout=2):self.closing=True;return self.closed()
    def closed(self):return self.closing is True and (self.run_thread is None or not self.run_thread.is_alive())
    def lifecycle_status(self):
        pending=int(self.run_thread is not None and self.run_thread.is_alive())
        return {'closing':self.closing,'socket_records':0,'sockets_pending':0,'actors_pending':0,
                'threads_pending':pending,'wrappers_pending':0,'unknown_wrappers':0,'unknown_resources':0,
                'processes_pending':0,'close_verified':self.closed(),'cleanup_pending':False}
    def closure_snapshot(self,raw):
        return dict(self.lifecycle_status(),recognized_raw=False,all_sockets_closed=self.closed(),all_actors_exited=self.closed())
    def run(self, confirm, progress=None, file_progress=None):
        self.run_thread=threading.current_thread()
        if self.mode == "cancel":
            self.owner.action({"action": "cancel"})
            if not self.cancelled():
                raise AssertionError("Cancellation did not reach transport")
            raise Cancelled("HOST cancelled during transfer")
        # Real storage: only the transport handshake and network are fixtures.
        fd, archive_path = tempfile.mkstemp(prefix="mta-host-source-", suffix=".zip")
        os.close(fd)
        try:
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_STORED) as archive:
                archive.writestr("Music/received.bin", b"HOST committed bytes")
            result = self.receiver.receive(archive_path, "host-service-task",
                                           self.cancelled, progress=file_progress,
                                           expected_files=1, expected_bytes=20)
            result["peer_ack_verified"] = True
            self.results.append(result)
            return result
        finally:
            os.unlink(archive_path)


class ServiceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="mta-host-service-")
        os.mkdir(os.path.join(self.root, "Music"))
        FakeHelper.instances = []
        FakeHelper.failed_command = None
        FakeHelper.fail_close = False
        FakeCrypto.keys = []
        FakeWifi.instances = []
        FakeWifi.restore_ok = True
        FakeWifi.fail_after_mutation = False
        FakeWifi.fail_prepare = False
        FakeWifi.observations = []
        FakeWifi.observer = None
        FakeReceiver.mode = "success"
        FakeReceiver.results = []
        del HOST_EVENTS[:]
        self.patches = [mock.patch("mta_service.capability", side_effect=lambda path, args, **options: dict(BLUEZ) if "hci0" in args else {"receive": True}),
                        mock.patch("mta_service.PrivateHelper", FakeHelper),
                        mock.patch("mta_service.OpenSslCrypto", FakeCrypto),
                        mock.patch("mta_service.State.start_watchdog"),
                        mock.patch("mta_service.WifiBackend", FakeWifi, create=True),
                        mock.patch("mta_wifi.WifiBackend", FakeWifi),
                        mock.patch("mta_service.ReceiverTransport", FakeReceiver)]
        for patch in self.patches:
            patch.start()
        self.state = mta_service.State(self.root, os.path.join(self.root, "bluez-host"),
                                       os.path.join(self.root, "network-host"))
        FakeWifi.observer = self.state
        FakeReceiver.owner = self.state
        self.info = P2pInfo("HOST-fixture", "12345678", "02:00:00:00:00:01", 33331)

    def tearDown(self):
        # Release only HOST-owned fixtures. Nothing in these tests touches ADB.
        FakeWifi.restore_ok = True
        FakeHelper.fail_close = False
        for backend in FakeWifi.instances:
            backend.restore_active()
        self.state.close()
        for patch in reversed(self.patches):
            patch.stop()
        shutil.rmtree(self.root)

    def attach_helper(self, scanning=False, advertising=False):
        with self.state.lock:op=self.state._new_operation_locked('cleanup')
        self.state.helper = FakeHelper("HOST", lambda event:self.state.native_event(event,op.epoch))
        op.helper=self.state.helper
        self.state.scanning = scanning
        self.state.discoverable = advertising
        self.state.state = "scanning" if scanning else "advertising"
        return self.state.helper

    def settle_operation(self):
        session=self.state.session
        if session is not None:
            if session._worker.ident is not None:session._worker.join(2)
            for row in list(session._attempts):
                if row['thread'].ident is not None:row['thread'].join(2)
        return self.state.status()

    def begin_receive(self):
        if self.state.session is not None:
            if not self.state.session.closed():
                if self.state.operation.kind=='cleanup':self.state.session.close(2)
                else:raise ValueError('HOST previous exact transfer cleanup pending')
        with mock.patch('mta_service.open',mock.mock_open(read_data='02:00:00:00:00:01\n'),create=True):
            self.state.action({'action':'discover_start'})
            deadline=time.monotonic()+2
            while not self.state.discoverable and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue(self.state.discoverable,'HOST discovery fixture did not become ready')
        return self.state.operation

    def run_receive(self):
        self.begin_receive();self.state.receive(self.info);return self.settle_operation()

    def scan_ready(self):
        self.state.action({'action':'scan'})
        deadline=time.monotonic()+2
        while not self.state.scanning and time.monotonic()<deadline:time.sleep(.005)
        self.assertTrue(self.state.scanning)

    def test_boot_is_readonly_and_send_capability_is_not_faked(self):
        status = self.state.status()
        self.assertEqual(status["state"], "idle")
        self.assertIsNone(self.state.helper)
        self.assertEqual(FakeHelper.instances, [])
        self.assertFalse(status["capabilities"]["send"]["available"])
        with self.assertRaises(ValueError):
            self.state.action({"action": "send", "deviceId": "1", "fileIds": ["opaque"]})

    def test_failure_before_lease_assignment_blocks_retry_and_close_success(self):
        FakeWifi.restore_ok = False
        FakeWifi.fail_after_mutation = True
        self.run_receive()
        self.assertFalse(self.state.close(), "Unconfirmed Wi-Fi recovery must not close successfully")
        self.assertFalse(self.state.status()["capabilities"]["receive"]["available"])

    def test_failed_connect_retry_keeps_one_backend_ownership_domain(self):
        FakeWifi.restore_ok = False
        FakeWifi.fail_after_mutation = True
        self.run_receive()
        with self.assertRaises(ValueError):self.run_receive()
        mutations = sum(backend.receive_calls for backend in FakeWifi.instances)
        self.assertEqual(mutations, 1, "A new backend must not bypass an existing failed restoration")

    def test_false_lease_close_is_not_discarded_or_reported_restored(self):
        FakeWifi.restore_ok = False
        self.run_receive()
        self.assertEqual(self.state.status()["state"], "restoring")
        self.assertTrue(self.state.transfer["localCommitVerified"],
                        "Recovery failure must not deny an already verified local file commit")
        self.assertFalse(self.state.close(), "Pending Wi-Fi lease is part of service close ownership")
        self.assertFalse(self.state.status()["capabilities"]["receive"]["available"])

    def test_pending_wifi_restoration_can_only_clear_on_real_fixture_recheck(self):
        FakeWifi.restore_ok = False
        self.run_receive()
        self.assertFalse(self.state.close())
        FakeWifi.restore_ok = True
        self.assertTrue(self.state.close())
        self.assertGreaterEqual(FakeWifi.instances[0].receive_calls, 1)
        self.assertIsNone(FakeWifi.instances[0]._active_lease)

    def test_failed_radio_check_is_not_erased_by_second_stop(self):
        self.attach_helper(scanning=True)
        changed = dict(BLUEZ, powered=False)
        with mock.patch("mta_service.capability", return_value=changed):
            self.assertFalse(self.state.stop_radio())
            self.assertFalse(self.state.close(), "No helper handle does not prove a failed radio check is resolved")

    def test_helper_close_error_preserves_ownership_and_pending_failure(self):
        helper = self.attach_helper(scanning=True)
        FakeHelper.fail_close = True
        self.assertFalse(self.state.stop_radio())
        self.assertIs(self.state.helper, helper, "Do not detach an unclosed native process owner")
        self.assertFalse(self.state.close())
        self.assertTrue(self.state.status()["restorePending"])
        FakeHelper.fail_close = False
        self.assertTrue(self.state.close())
        self.assertTrue(helper.closed)
        self.assertIs(self.state.helper,helper)
        self.assertTrue(helper.closure_verified())

    def test_cancel_during_transfer_reaches_transport_and_restores(self):
        FakeReceiver.mode = "cancel"
        self.attach_helper(advertising=True)
        self.run_receive()
        self.assertTrue(self.state.cancelled.is_set())
        self.assertEqual(FakeWifi.instances[-1].receive_calls, 1)
        self.assertTrue(self.state.close())
        self.assertNotEqual(self.state.status()['state'], "completed")
        self.assertEqual(self.state.received, [])

    def test_real_file_commit_is_exposed_after_verified_fixture_restoration(self):
        self.attach_helper(advertising=True)
        self.run_receive()
        self.assertEqual(self.state.status()['state'], "completed")
        self.assertEqual(self.state.transfer["bytes"], 20)
        self.assertTrue(self.state.transfer["localCommitVerified"])
        self.assertTrue(self.state.transfer["peerAckVerified"])
        self.assertEqual(len(self.state.received), 1)
        with open(FakeReceiver.results[-1]["files"][0], "rb") as source:
            self.assertEqual(source.read(), b"HOST committed bytes")
        self.assertTrue(self.state.close())

    def test_postcommit_catalog_error_does_not_escape_worker_cleanup(self):
        self.attach_helper(advertising=True)
        with mock.patch.object(self.state.registry, "list_files", side_effect=OSError("HOST catalog unavailable")):
            self.run_receive()
        self.assertIs(self.state.worker,self.state.session._worker)
        self.assertFalse(self.state.worker.is_alive())
        self.assertTrue(self.state.helper.closure_verified())
        self.assertTrue(FakeReceiver.results, "A committed result must remain distinguishable from no commit")
        self.assertTrue(os.path.isfile(FakeReceiver.results[-1]["files"][0]))
        self.assertTrue(self.state.transfer["localCommitVerified"])
        self.assertIn(self.state.status()['state'], ("completed", "error"))

    def test_discovery_never_promotes_native_cached_rows(self):
        self.attach_helper(scanning=True)
        self.state.native_event({"event": "discovered", "peer": 1, "cached": True,
                                 "name_b64": base64.b64encode(b"HOST cached").decode("ascii")})
        self.assertEqual(self.state.status()["devices"], [])
        self.state.native_event({"event": "discovered", "peer": 2, "cached": False,
                                 "name_b64": base64.b64encode(b"HOST live").decode("ascii")})
        rows = self.state.status()["devices"]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["available"])
        self.state.peer_seen[rows[0]["id"]] = time.monotonic() - 16
        self.assertFalse(self.state.status()["devices"][0]["available"])

    def test_bool_peer_id_is_not_an_integer_device_handle(self):
        self.scan_ready()
        FakeHelper.instances[-1].callback({"event": "discovered", "peer": True, "cached": False})
        self.assertEqual(self.state.status()["devices"], [])

    def test_native_closed_event_invalidates_live_discovery(self):
        self.scan_ready()
        helper = FakeHelper.instances[-1]
        helper.callback({"event": "discovered", "peer": 2, "cached": False})
        helper.callback({"event": "closed"})
        status = self.state.status()
        self.assertFalse(status["scanning"])
        self.assertTrue(all(not row["available"] for row in status["devices"]))

    def test_delayed_advert_ready_cannot_resurrect_stopped_session(self):
        self.scan_ready()
        helper = FakeHelper.instances[-1]
        self.state.action({"action": "cancel"})
        helper.callback({"event": "advert", "code": "ready"})
        status = self.state.status()
        self.assertFalse(status["discoverable"])
        self.assertNotEqual(status["state"], "advertising")

    def test_old_helper_callback_cannot_insert_rows_into_new_scan(self):
        self.scan_ready()
        old = FakeHelper.instances[-1]
        self.state.action({"action": "scan_stop"})
        self.scan_ready()
        current = FakeHelper.instances[-1]
        self.assertIsNot(current, old)
        old.callback({"event": "discovered", "peer": 999, "cached": False,
                      "name_b64": base64.b64encode(b"HOST stale session").decode("ascii")})
        self.assertEqual(self.state.status()["devices"], [],
                         "Native cached=false does not make an old session callback current")

    def test_listen_command_failure_closes_created_helper(self):
        FakeHelper.failed_command = "listen"
        with mock.patch("mta_service.open", mock.mock_open(read_data="02:00:00:00:00:01\n"), create=True):
            self.state.action({"action": "discover_start"});status=self.settle_operation()
        self.assertEqual(status['state'],'error');self.assertTrue(self.state.session.closed())
        self.assertTrue(FakeHelper.instances)
        self.assertTrue(FakeHelper.instances[-1].closed)
        self.assertTrue(self.state.helper.closure_verified())
        self.assertTrue(self.state.key.closed)

    def test_prepare_snapshot_precedes_discovery_and_stop_restores_ownership(self):
        with mock.patch("mta_service.open", mock.mock_open(read_data="02:00:00:00:00:01\n"), create=True):
            self.begin_receive()
        backend = FakeWifi.instances[0]
        self.assertEqual(backend.prepare_calls, 1)
        self.assertIs(self.state.lease, backend._active_lease)
        self.assertLess(HOST_EVENTS.index("network_snapshot_held"), HOST_EVENTS.index("helper_create"))
        self.assertLess(HOST_EVENTS.index("network_snapshot_held"), HOST_EVENTS.index("ipc_listen"))
        self.state.action({"action": "discover_stop"})
        self.assertIn("network_restore_confirmed", HOST_EVENTS)
        self.assertLess(HOST_EVENTS.index("helper_close"), HOST_EVENTS.index("network_restore_begin"))
        self.assertIsNone(backend._active_lease)
        self.assertTrue(self.state.lease.actors_closed())
        self.assertTrue(self.state.helper.closure_verified())
        self.assertTrue(self.state.close())

    def test_failed_prepare_never_starts_discovery_and_closes_owned_snapshot(self):
        FakeWifi.fail_prepare = True
        self.state.action({"action": "discover_start"});status=self.settle_operation()
        self.assertEqual(status['state'],'error');self.assertTrue(self.state.session.closed())
        self.assertEqual(FakeHelper.instances, [])
        self.assertNotIn("ipc_listen", HOST_EVENTS)
        self.assertIn("network_restore_confirmed", HOST_EVENTS)
        self.assertIsNone(FakeWifi.instances[0]._active_lease)
        self.assertTrue(self.state.close())

    def test_crypto_failure_after_prepare_restores_snapshot_without_discovery(self):
        with mock.patch.object(FakeCrypto, "generate_keypair", side_effect=ValueError("HOST key fixture unavailable")):
            self.state.action({"action": "discover_start"});status=self.settle_operation()
        self.assertEqual(status['state'],'error');self.assertTrue(self.state.session.closed())
        self.assertEqual(FakeHelper.instances, [])
        self.assertIn("network_snapshot_held", HOST_EVENTS)
        self.assertIn("network_restore_confirmed", HOST_EVENTS)
        self.assertIsNone(FakeWifi.instances[0]._active_lease)
        self.assertTrue(self.state.close())

    def test_scan_command_failure_closes_created_helper(self):
        FakeHelper.failed_command = "scan"
        self.state.action({"action": "scan"});status=self.settle_operation()
        self.assertEqual(status['state'],'error');self.assertTrue(self.state.session.closed())
        self.assertTrue(FakeHelper.instances[-1].closed)
        self.assertTrue(self.state.helper.closure_verified())
        self.assertFalse(self.state.status()["scanning"])

    def test_network_consent_precedes_file_prompt_explicit_ordering(self):
        # This is an ordering fact, not an assertion that a file-confirmation
        # dialog also authorizes changing the network. UI wording must explain
        # the earlier consent conveyed by discover_start.
        self.run_receive()
        self.assertTrue(FakeWifi.observations[-1]["consented"])
        self.assertFalse(FakeWifi.observations[-1]["file_prompt_present"])

    def test_wrong_request_id_cannot_accept_new_request(self):
        self.state.request = {"id": "current", "name": "HOST", "fileCount": 1, "totalBytes": 1}
        with self.assertRaises(ValueError):
            self.state.action({"action": "accept", "requestId": "old"})
        self.assertFalse(self.state.decision.is_set())

    def test_reject_confirmation_unblocks_without_transferring(self):
        answers = []
        request = {"taskId": "host-confirmation", "senderName": "HOST",
                   "fileCount": 1, "totalSize": 20}
        thread = threading.Thread(target=lambda: answers.append(self.state.confirm(request)))
        thread.start()
        deadline = time.monotonic() + 2
        while self.state.request is None and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertIsNotNone(self.state.request)
        self.state.action({"action": "reject", "requestId": request["taskId"]})
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(answers, [False])
        self.assertIsNone(self.state.request)
        self.assertNotEqual(self.state.state, "transferring")


class FileIdentityIntegrationTests(unittest.TestCase):
    def test_rescan_does_not_reauthorize_an_old_id_for_modified_content(self):
        base = tempfile.mkdtemp(prefix="mta-host-identity-")
        try:
            os.mkdir(os.path.join(base, "Music"))
            path = os.path.join(base, "Music", "item.bin")
            with open(path, "wb") as source:
                source.write(b"original")
            registry = FileRegistry(base)
            selected = registry.list_files()[0]["id"]
            self.assertEqual(registry.list_files()[0]["id"], selected)
            # Different actual size deterministically changes the signature.
            with open(path, "wb") as source:
                source.write(b"different replacement content")
            current = registry.list_files()[0]["id"]
            self.assertNotEqual(current, selected)
            with self.assertRaises(ValueError):
                registry.open_selection([selected])
            with registry.open_selection([current]) as selection:
                self.assertEqual(selection.entries[0]["handle"].read(), b"different replacement content")
        finally:
            shutil.rmtree(base)


class HttpContractIntegrationTests(unittest.TestCase):
    def test_default_header_contract_works_but_query_tokens_are_not_accepted(self):
        root = tempfile.mkdtemp(prefix="mta-host-http-contract-")
        state = mta_service.State(root, os.path.join(root, "absent-bluez"), os.path.join(root, "absent-network"))
        server = mta_service.Server(state)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            for path, headers, expected in (("/v1/status", {"X-P011-MTA-Token": state.token}, 200),
                                            ("/v1/status?token=" + state.token, {}, 403)):
                conn = http.client.HTTPConnection(*server.server_address, timeout=3)
                conn.request("GET", path, headers=headers)
                response = conn.getresponse()
                self.assertEqual(response.status, expected)
                payload = json.loads(response.read().decode("utf-8"))
                if expected == 200:
                    self.assertIn("state", payload)  # Service returns a bare status.
                conn.close()
        finally:
            server.server_close()
            thread.join(3)
            state.close()
            shutil.rmtree(root)


def host_openssl():
    paths = [os.environ.get("MTA_TEST_OPENSSL")]
    if os.name == "nt":
        paths += [r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe"]
    else:
        paths += ["/usr/bin/openssl", "/bin/openssl"]
    return next((path for path in paths if path and os.path.isfile(path)), None)


class PostCommitTlsIntegrationTests(unittest.TestCase):
    def test_tls_postcommit_status_write_failure_preserves_local_result(self):
        openssl = host_openssl()
        if openssl is None:
            self.skipTest("HOST OpenSSL unavailable; no P011 or phone claim")
        base = tempfile.mkdtemp(prefix="mta-host-postcommit-")
        selection = None
        server = None
        try:
            user = os.path.join(base, "user")
            incoming = os.path.join(base, "incoming")
            private = os.path.join(base, "private")
            os.makedirs(os.path.join(user, "Music"))
            os.mkdir(incoming)
            os.mkdir(private)
            data = b"HOST real TLS and committed file" * 1024
            with open(os.path.join(user, "Music", "item.bin"), "wb") as target:
                target.write(data)
            registry = FileRegistry(user)
            selection = registry.open_selection([registry.list_files()[0]["id"]])
            server = SenderTransport("127.0.0.1", 0, selection, openssl,
                                     task_id="host-postcommit-task", sender_id="0011",
                                     timeout=15, allow_loopback=True, allowed_peer_ip="127.0.0.1",
                                     temp_root=private)
            server.start()
            storage = SafeZipReceiver(incoming, reserve_bytes=0)
            with mock.patch("mta_transport.private_ipv4", return_value="127.0.0.1"):
                transport = ReceiverTransport("127.0.0.1", server.port, storage, timeout=15)
            actual_send = WebSocket.send
            committed = []
            actual_receive = storage.receive
            def record_commit(*arguments, **options):
                result = actual_receive(*arguments, **options)
                committed.append(result)
                return result
            def fail_final_status(ws, message):
                if ws.client and getattr(message, "name", None) == "status" and message.payload.get("type") == 1:
                    raise TransportError("HOST injected post-commit status write failure")
                return actual_send(ws, message)
            result = None
            error = None
            with mock.patch.object(storage, "receive", side_effect=record_commit), mock.patch.object(WebSocket, "send", new=fail_final_status):
                try:
                    result = transport.run(lambda request: True)
                except (TransportError, OSError) as caught:
                    error = caught
            self.assertTrue(committed, "The fault must occur after real ZIP commit, not before download")
            with open(committed[0]["files"][0], "rb") as source:
                self.assertEqual(source.read(), data)
            self.assertIsNone(error, "Post-commit peer write failure must preserve the actual local result")
            self.assertIsNotNone(result)
            self.assertFalse(result["peer_ack_verified"])
            self.assertIsNone(server.result, "Peer completion must never be invented")
            self.assertFalse(any(name.startswith(".mta-") for name in os.listdir(incoming)))
        finally:
            if server is not None:
                server.close()
            if selection is not None:
                selection.close()
            shutil.rmtree(base)


if __name__ == "__main__":
    unittest.main()
