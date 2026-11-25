# -*- coding: utf-8 -*-
"""HOST-only proposed send-worker contract and current production guards.

The explicit in-memory ContractFixture is a requirements harness, NOT an
implemented worker, TLS network test, phone result or availability evidence.
Three tests exercise current real service/GO-only adapter guards using no-I/O
helpers. Others pin ordering/failure expectations for the future worker.
"""
import base64
import binascii
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import p011_json as json
import mta_service
import mta_send_wifi
from mta_crypto import CryptoError, P256_SPKI_PREFIX, _public_der
from mta_protocol import DeviceInfo, ProtocolError, P2pInfo
from mta_transport import TransportError, private_ipv4

# Standard P-256 public generator point. Public fixture, no private key.
PUBLIC = base64.b64encode(P256_SPKI_PREFIX + binascii.unhexlify(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")).decode("ascii")


class ContractError(ValueError):
    pass


class LeaseFixture(object):
    def __init__(self):
        self.owner_retained = True
        self.restore_calls = 0
    def restore(self, verified):
        self.restore_calls += 1
        if verified:
            self.owner_retained = False
        return verified


class ListenerFixture(object):
    """No-I/O model of start()/authorize_peer(ip), not a TLS implementation."""
    def __init__(self):
        self.started = False
        self.closed = False
        self.allowed_peer_ip = None
    def start(self):
        if self.started or self.closed:
            raise ContractError("Listener cannot be started twice")
        self.started = True
        return 32109  # Explicit fixture returned port, never a protocol default.
    def authorize_peer(self, address):
        address = private_ipv4(address)
        if not self.started or self.closed:
            raise ContractError("Listener is not awaiting an authorized peer")
        if self.allowed_peer_ip is not None and self.allowed_peer_ip != address:
            raise ContractError("Listener peer cannot be replaced")
        self.allowed_peer_ip = address
        return True
    def accepts(self, address):
        return self.started and not self.closed and self.allowed_peer_ip is not None and address == self.allowed_peer_ip
    def close(self):
        self.closed = True


class ContractFixture(object):
    """Normative HOST fixture; never imports/spawns a native/TLS backend."""
    def __init__(self):
        self.epoch = 1
        self.peer = 7
        self.task = "host-contract-task"
        self.events = []
        self.lease = None
        self.listener = ListenerFixture()
        self.port = None
        self.admitted = None
        self.cancelled = False
        self.peer_completion_verified = False
        self.local_bytes_verified = False
        self.restore_pending = False
        self.listener_closed = False
        self.state = "idle"
    def peer_status(self, wire, point_validated=True):
        if not isinstance(wire, bytes) or len(wire) > 512:
            raise ContractError("Native status byte limit")
        value = json.loads(wire.decode("utf-8"))
        if not isinstance(value, dict) or set(value) - {"state", "mac", "key", "catShare"}:
            raise ContractError("DeviceInfo fields")
        info = DeviceInfo.from_dict(value)
        if info.state != 0 or not info.key:
            raise ContractError("Peer busy or missing encryption key")
        _public_der(info.key)
        # Native EC point check + ECDH are future worker prerequisites. This
        # boolean is a named fixture input, not evidence of real cryptography.
        if point_validated is not True:
            raise ContractError("Native EC point validation did not pass")
        self.events.append("peer_p256_and_point_validated_FIXTURE")
    def prepare(self, wire, network, prepare_fault=False, point_validated=True):
        if self.restore_pending or self.lease is not None:
            raise ContractError("Persistent lease blocks a new task")
        self.peer_status(wire, point_validated)
        self.events.append("selection_opened_FIXTURE")
        # Assignment precedes an exception from prepare/activation.
        self.lease = LeaseFixture()
        self.events.append("persistent_lease_held_FIXTURE")
        if prepare_fault:
            self.restore_pending = True
            raise ContractError("Failure after ownership assigned")
        if not all(network.get(name) is True for name in ("actual_interface_verified", "ip_ready", "dhcp_ready")):
            raise ContractError("GO-only is not a send network")
        private_ipv4(network["local_ip"])
        self.events.append("ip_dhcp_readback_FIXTURE")
        # Returned listener port, not a guessed protocol default. No actual
        # listener exists here; admission initially rejects EVERY fixture peer.
        self.port = self.listener.start()
        self.events.append("tls_listen_deny_all_FIXTURE")
        self.events.append("encrypted_p2p_client_write_FIXTURE")
        self.state = "awaiting_peer"
        return self.port
    def authorize_associated_peer(self, address, verified, epoch):
        # The worker checks current ownership/association/DHCP proof before
        # calling the actual transport API authorize_peer(ip). Proof is NOT a
        # user/QML field or an extra argument accepted by SenderTransport.
        if epoch != self.epoch or self.cancelled:
            return False
        if self.port is None or verified is not True:
            raise ContractError("Actual single peer binding required")
        self.listener.authorize_peer(address)
        self.admitted = self.listener.allowed_peer_ip
        self.events.append("actual_association_dhcp_peer_admitted_FIXTURE")
        return True
    def event(self, epoch, peer, event):
        if epoch != self.epoch or self.cancelled:
            return False
        if peer != self.peer or isinstance(peer, bool):
            raise ContractError("Native peer mismatch")
        if event == "accepted_by_bluez_not_file_transfer_complete":
            self.events.append("gatt_accepted_only_FIXTURE")
            return True
        raise ContractError("Unsupported native event")
    def complete(self, task, sent, expected, peer_status_received):
        if self.cancelled or self.admitted is None or task != self.task:
            raise ContractError("Current admitted task required")
        self.local_bytes_verified = sent == expected
        self.peer_completion_verified = self.local_bytes_verified and peer_status_received is True
        self.state = "restoring"
    def finish(self, network_restored, radio_restored, listener_close_ok=True):
        self.listener_closed = listener_close_ok
        self.events.append("owned_listener_close_FIXTURE")
        if listener_close_ok:
            self.listener.close()
        restored = self.lease.restore(network_restored) if self.lease else network_restored
        self.restore_pending = not (restored and radio_restored and listener_close_ok)
        self.events.append("network_radio_readback_FIXTURE")
        if not self.restore_pending:
            self.lease = None
        self.state = "restore_pending" if self.restore_pending else (
            "completed" if self.peer_completion_verified else "peer_unconfirmed")
        return not self.restore_pending
    def cancel(self):
        self.cancelled = True
        self.epoch += 1
        self.events.append("cancelled_FIXTURE")


class ReadOnlyWifiFixture(object):
    def __init__(self, *unused):
        pass
    def status(self):
        return {"restorePending": False, "recoveryLocked": False}
    def restore_active(self):
        return True


class SendContractTests(unittest.TestCase):
    def setUp(self):
        self.wire = DeviceInfo("02:00:00:00:00:11", PUBLIC).to_bytes()
        self.network = {"actual_interface_verified": True, "ip_ready": True,
                        "dhcp_ready": True, "local_ip": "192.168.91.1"}
        self.worker = ContractFixture()
    def ready(self):
        self.worker.prepare(self.wire, self.network)
        self.worker.authorize_associated_peer("192.168.91.2", True, self.worker.epoch)
    def test_current_service_send_stays_disabled_and_rejects_before_selection(self):
        with tempfile.TemporaryDirectory(prefix="mta-host-send-contract-") as user:
            with mock.patch.object(mta_service, "WifiBackend", ReadOnlyWifiFixture), \
                    mock.patch.object(mta_service, "capability", return_value={"powered": True}):
                state = mta_service.State(user, "/HOST/no-native-helper", "/HOST/no-network-helper")
                self.assertFalse(state.status()["capabilities"]["send"]["available"])
                with mock.patch.object(state.registry, "open_selection", side_effect=AssertionError("Must not open")):
                    with self.assertRaises(ValueError):
                        state.action({"action": "send", "deviceId": "7", "fileIds": ["opaque"]})
                state.close()
    def test_current_go_adapter_never_enables_send_from_declared_capabilities(self):
        linux = mock.Mock()
        linux.capabilities.return_value = {"phys": [{"iftypes": ["p2p_client", "p2p_go"],
            "combinations": [{"station_plus_go_same_channel": True}]}]}
        with mock.patch.object(mta_send_wifi, "LinuxBackend", return_value=linux):
            backend = mta_send_wifi.SendWifiBackend("HOST-helper", "HOST-wpa", "HOST-run")
            value = backend.capabilities()["send"]
            self.assertTrue(value["p2pDeclared"])
            self.assertFalse(value["available"])
            self.assertFalse(value["p2pVerified"])
            backend.close()
    def test_current_go_context_has_no_ip_or_dhcp_even_when_stage_go_ready(self):
        lease = mock.Mock()
        lease.state = {"name": "HOST-owned", "stage": "go_ready"}
        lease.credentials = {"ssid": "HOST-only", "passphrase": "HOST-only-private", "go_address": "02:00:00:00:00:22"}
        lease.expired.return_value = False
        context = mta_send_wifi.SenderGoContext(lease)
        self.assertIsNone(context.local_ip)
        self.assertFalse(context.status()["ip_ready"])
        self.assertFalse(context.status()["dhcp_ready"])
    def test_contract_order_listen_real_returned_port_before_ble_publish(self):
        port = self.worker.prepare(self.wire, self.network)
        self.assertEqual(port, self.worker.port)
        self.assertLess(self.worker.events.index("tls_listen_deny_all_FIXTURE"),
                        self.worker.events.index("encrypted_p2p_client_write_FIXTURE"))
        self.assertIsNone(self.worker.admitted)
        self.assertIsNone(self.worker.listener.allowed_peer_ip)
    def test_contract_listener_deny_all_until_actual_peer_authorized(self):
        self.worker.prepare(self.wire, self.network)
        self.assertFalse(self.worker.listener.accepts("192.168.91.2"))
        self.assertFalse(self.worker.listener.accepts("192.168.91.3"))
        self.worker.authorize_associated_peer("192.168.91.2", True, 1)
        self.assertTrue(self.worker.listener.accepts("192.168.91.2"))
        self.assertFalse(self.worker.listener.accepts("192.168.91.3"))
    def test_contract_authorize_peer_requires_live_listener(self):
        listener = ListenerFixture()
        with self.assertRaises(ContractError):listener.authorize_peer("192.168.91.2")
        listener.start(); listener.close()
        with self.assertRaises(ContractError):listener.authorize_peer("192.168.91.2")
        self.assertFalse(listener.accepts("192.168.91.2"))
    def test_contract_go_only_rejected_before_listen_or_ble_write(self):
        for missing in ("actual_interface_verified", "ip_ready", "dhcp_ready"):
            worker = ContractFixture()
            network = dict(self.network); network[missing] = False
            with self.assertRaises(ContractError):
                worker.prepare(self.wire, network)
            self.assertIsNone(worker.port)
            self.assertNotIn("encrypted_p2p_client_write_FIXTURE", worker.events)
    def test_contract_unsafe_network_address_rejected(self):
        for address in ("0.0.0.0", "127.0.0.1", "8.8.8.8"):
            worker = ContractFixture(); network = dict(self.network); network["local_ip"] = address
            with self.assertRaises(TransportError):worker.prepare(self.wire, network)
            self.assertIsNone(worker.port)
    def test_contract_busy_missing_invalid_and_unchecked_peer_key_before_lease(self):
        cases = [DeviceInfo("02:00:00:00:00:11", PUBLIC, state=1).to_bytes(),
                 DeviceInfo("02:00:00:00:00:11", None).to_bytes(),
                 DeviceInfo("02:00:00:00:00:11", base64.b64encode(b"not SPKI").decode("ascii")).to_bytes()]
        for wire in cases:
            worker = ContractFixture()
            with self.assertRaises((ContractError, ProtocolError, CryptoError)):worker.prepare(wire, self.network)
            self.assertIsNone(worker.lease)
        with self.assertRaises(ContractError):self.worker.prepare(self.wire, self.network, point_validated=False)
        self.assertIsNone(self.worker.lease)
    def test_contract_duplicate_and_unknown_status_fields_rejected(self):
        for wire in (b'{"state":0,"state":1,"mac":"02:00:00:00:00:11"}',
                     json.dumps({"state": 0, "mac": "02:00:00:00:00:11", "key": PUBLIC, "unknown": 1}).encode("utf-8")):
            with self.assertRaises(ValueError):self.worker.prepare(wire, self.network)
    def test_contract_status_over_native_byte_limit_before_lease(self):
        with self.assertRaises(ContractError):self.worker.prepare(b" " * 513, self.network)
        self.assertIsNone(self.worker.lease)
    def test_contract_prepare_failure_retains_owner_and_blocks_new_task(self):
        with self.assertRaises(ContractError):self.worker.prepare(self.wire, self.network, prepare_fault=True)
        self.assertTrue(self.worker.lease.owner_retained)
        self.assertTrue(self.worker.restore_pending)
        with self.assertRaises(ContractError):self.worker.prepare(self.wire, self.network)
    def test_contract_peer_requires_actual_readback_and_is_single(self):
        self.worker.prepare(self.wire, self.network)
        with self.assertRaises(ContractError):self.worker.authorize_associated_peer("192.168.91.2", False, 1)
        self.assertIsNone(self.worker.listener.allowed_peer_ip)
        self.assertTrue(self.worker.authorize_associated_peer("192.168.91.2", True, 1))
        self.assertTrue(self.worker.authorize_associated_peer("192.168.91.2", True, 1))
        with self.assertRaises(ContractError):self.worker.authorize_associated_peer("192.168.91.3", True, 1)
    def test_contract_gatt_accept_is_never_phone_completion(self):
        self.ready()
        self.worker.event(1, 7, "accepted_by_bluez_not_file_transfer_complete")
        self.assertFalse(self.worker.peer_completion_verified)
        self.assertFalse(self.worker.local_bytes_verified)
    def test_contract_wrong_peer_and_unknown_native_event_rejected(self):
        self.ready()
        with self.assertRaises(ContractError):self.worker.event(1, 8, "accepted_by_bluez_not_file_transfer_complete")
        with self.assertRaises(ContractError):self.worker.event(1, 7, "client_status_command_does_not_exist")
        self.assertFalse(self.worker.peer_completion_verified)
    def test_contract_old_epoch_late_callbacks_do_not_mutate_current_task(self):
        self.ready(); self.worker.cancel(); events = list(self.worker.events)
        self.assertFalse(self.worker.event(1, 7, "accepted_by_bluez_not_file_transfer_complete"))
        self.assertFalse(self.worker.authorize_associated_peer("192.168.91.3", True, 1))
        self.assertEqual(events, self.worker.events)
        self.assertFalse(self.worker.peer_completion_verified)
    def test_contract_wrong_task_and_short_bytes_never_complete(self):
        self.ready()
        with self.assertRaises(ContractError):self.worker.complete("old-task", 100, 100, True)
        self.worker.complete(self.worker.task, 99, 100, True)
        self.assertFalse(self.worker.peer_completion_verified)
    def test_contract_peer_complete_and_restore_failure_keep_separate_facts(self):
        self.ready(); self.worker.complete(self.worker.task, 100, 100, True)
        self.assertFalse(self.worker.finish(False, True))
        self.assertTrue(self.worker.peer_completion_verified)
        self.assertTrue(self.worker.local_bytes_verified)
        self.assertTrue(self.worker.restore_pending)
        self.assertTrue(self.worker.lease.owner_retained)
    def test_contract_byte_count_without_completion_ack_is_peer_unconfirmed(self):
        self.ready(); self.worker.complete(self.worker.task, 100, 100, False)
        self.assertTrue(self.worker.finish(True, True))
        self.assertTrue(self.worker.local_bytes_verified)
        self.assertFalse(self.worker.peer_completion_verified)
        self.assertEqual(self.worker.state, "peer_unconfirmed")
    def test_contract_close_failure_is_not_full_success(self):
        self.ready(); self.worker.complete(self.worker.task, 100, 100, True)
        self.assertFalse(self.worker.finish(True, True, listener_close_ok=False))
        self.assertEqual(self.worker.state, "restore_pending")
        self.assertIsNotNone(self.worker.lease)
    def test_real_protocol_plain_p2p_uses_returned_port_and_native_size_bound(self):
        port = self.worker.prepare(self.wire, self.network)
        plain = P2pInfo("HOST-only", "HOST-only-private", "02:00:00:00:00:22", port, sender_id="host-contract")
        self.assertEqual(P2pInfo.from_bytes(plain.to_bytes()).port, port)
        self.assertLessEqual(len(plain.to_bytes()), 2048)


if __name__ == "__main__":
    unittest.main()
