# -*- coding: utf-8 -*-
import base64
import os
import sys
import tempfile
import shutil
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
from mta_protocol import (ADV_SERVICE_UUID, DeviceInfo, P2pInfo, ProtocolError,
                          TransferState, WsMessage, decode_advertisement,
                          decode_json, decode_message, encode_advertisement,
                          encode_json, encode_message, get_task_id,
                          parse_ad_fields, validate_send_request, validate_task_id)


class ProtocolTests(unittest.TestCase):
    def test_wire_not_json_envelope(self):
        wire = encode_message("versionNegotiation", {"version": 1, "versions": [1]}, msg_id=0)
        self.assertTrue(wire.startswith("action:0:versionNegotiation?"))
        message = decode_message(wire)
        self.assertEqual(message.payload, {"version": 1, "versions": [1]})
        ack = decode_message(message.make_ack({"version": 1}).serialize())
        self.assertEqual((ack.msg_type, ack.id, ack.name, ack.payload), ("ack", 0, "versionNegotiation", {"version": 1}))

    def test_message_roundtrip_non_ascii_question_mark(self):
        message = WsMessage("action", 4294967295, "sendRequest", {"id": "a-123", "senderName": "笔?测试"})
        parsed = WsMessage.parse(message.serialize().encode("utf-8"))
        self.assertEqual(parsed.payload, message.payload)
        self.assertEqual(parsed.id, 4294967295)

    def test_no_payload(self):
        self.assertEqual(WsMessage.parse("ack:2:done").payload, None)

    def test_invalid_headers(self):
        for wire in ("event:1:a", "action:-1:a", "action:4294967296:a", "action:1:../x", "action:1:a\n", "action:1:a?", "action:1:a?[]", "action:1:a?null", "action:1:a?broken"):
            with self.assertRaises(ProtocolError, msg=wire):
                decode_message(wire)

    def test_message_limit_utf8(self):
        with self.assertRaises(ProtocolError):
            encode_message("status", {"reason": "字" * 22000})
        with self.assertRaises(ProtocolError):
            decode_message("x" * 65537)

    def test_duplicate_and_nested_json(self):
        with self.assertRaises(ProtocolError):
            decode_json(b'{"port":1,"port":2}')
        with self.assertRaises(ProtocolError):
            encode_json([[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]])

    def test_task_path_is_never_accepted(self):
        for value in ("", "../test", "a/b", "a\\b", "a?b", "a\n", "测试", "x" * 129, 5, None):
            with self.assertRaises(ProtocolError):
                validate_task_id(value)
        self.assertEqual(validate_task_id("1a3f_A-25"), "1a3f_A-25")

    def test_conflicting_task_alias(self):
        with self.assertRaises(ProtocolError):
            get_task_id({"taskId": "one", "id": "two"})
        self.assertEqual(get_task_id({"id": "abc"}), "abc")

    def test_device_info_exact_fields(self):
        key = base64.b64encode(b"test-public-key").decode("ascii")
        info = DeviceInfo("aa:bb:cc:dd:ee:ff", key)
        self.assertEqual(info.to_dict(), {"state": 0, "key": key, "mac": "AA:BB:CC:DD:EE:FF", "catShare": 1})
        self.assertEqual(DeviceInfo.from_bytes(info.to_bytes()).to_dict(), info.to_dict())
        self.assertEqual(DeviceInfo.from_bytes(b'{"state":1,"mac":"00:00:00:00:00:00"}').to_dict(), {"state": 1, "mac": "00:00:00:00:00:00"})

    def test_device_invalid(self):
        for wire in (b'{"mac":"aa:bb:cc:dd:ee:ff"}', b'{"state":false,"mac":"aa:bb:cc:dd:ee:ff"}', b'{"state":0,"mac":"invalid"}', b'{"state":0,"mac":"aa:bb:cc:dd:ee:ff","key":"!"}'):
            with self.assertRaises(ProtocolError):
                DeviceInfo.from_bytes(wire)

    def test_p2p_plain_and_encrypted_fields(self):
        plain = P2pInfo("DIRECT-test", "12345678", "02:00:00:00:00:01", 33331, sender_id="0011")
        self.assertEqual(P2pInfo.from_bytes(plain.to_bytes()).to_dict(), plain.to_dict())
        encoded = base64.b64encode(b"encrypted").decode("ascii")
        protected = P2pInfo(encoded, encoded, encoded, 33331, encoded)
        self.assertEqual(P2pInfo.from_bytes(protected.to_bytes()).key, encoded)
        self.assertEqual(P2pInfo("DIRECT-a", "ab" * 32, "02:00:00:00:00:01", 33331).psk, "ab" * 32)

    def test_p2p_limits(self):
        for kwargs in ({"port": 0}, {"port": True}, {"port": 65536}, {"ssid": "字" * 11}, {"psk": "short"}, {"mac": "foo"}):
            values = dict(ssid="DIRECT-a", psk="12345678", mac="02:00:00:00:00:01", port=10)
            values.update(kwargs)
            with self.assertRaises(ProtocolError):
                P2pInfo(**values)

    def test_precise_legacy_advertisement(self):
        result = encode_advertisement(b"\x12\x34", 0xff, "P011", False)
        self.assertEqual(len(result["adv_data"]), 31)
        self.assertEqual(len(result["scan_rsp"]), 31)
        self.assertEqual(result["identity"], b"\x12\x34\x00\x00\x00\x00")
        self.assertEqual(result["name_data"], b"\x00" * 8 + b"\x12\x34P011" + b"\x00" * 13)
        self.assertEqual(result["service_uuid"], ADV_SERVICE_UUID)
        self.assertEqual(result["adv_data"].hex(), "0201061107896745238100008000100000313300000916ff00123400000000")
        parsed = decode_advertisement(result["adv_data"], result["scan_rsp"])
        self.assertEqual(parsed["name"], "P011")
        self.assertEqual(parsed["brand"], 0xff)
        self.assertFalse(parsed["supports_5ghz"])

    def test_ad_name_truncation_valid_utf8(self):
        for name in ("abcdefghijklmnopqrstuvwxyz", "学习笔测试设备名字很长", "abcdefghijklmno字字"):
            encoded = encode_advertisement("12ab", 1, name, True)
            parsed = decode_advertisement(encoded["adv_data"], encoded["scan_rsp"])
            self.assertTrue(parsed["name_truncated"])
            self.assertTrue(name.startswith(parsed["name"]))
            self.assertEqual(parsed["sender_id"], "12ab")
            self.assertTrue(parsed["supports_5ghz"])

    def test_ad_malformed_and_mismatch(self):
        for raw in (b"\x02\x01", b"\x20" + b"\x00" * 30, b"\x00\x01", b"x" * 32):
            with self.assertRaises(ProtocolError):
                parse_ad_fields(raw)
        packet = encode_advertisement("0102", 1, "笔")
        altered = bytearray(packet["scan_rsp"])
        altered[12] = 8
        with self.assertRaises(ProtocolError):
            decode_advertisement(packet["adv_data"], bytes(altered))
        with self.assertRaises(ProtocolError):
            encode_advertisement("0102\n", 1, "name")

    def test_request_limits_and_task_alias(self):
        request = {"taskId": "test-1", "fileCount": 2, "totalSize": 5, "senderName": "手机", "fileName": "../display-only.zip", "mimeType": "application/zip"}
        self.assertEqual(validate_send_request(request)["fileCount"], 2)
        for field, value in (("fileCount", 0), ("fileCount", 257), ("totalSize", -1), ("totalSize", 512 * 1024 * 1024 + 1), ("taskId", "../bad")):
            broken = dict(request)
            broken[field] = value
            with self.assertRaises(ProtocolError):
                validate_send_request(broken)

    def test_state_needs_real_commit(self):
        state = TransferState("task-1", expected_files=1, expected_bytes=5)
        for stage in ("connected", "negotiated", "awaiting_confirmation", "transferring"):
            state.transition(stage)
        with self.assertRaises(ProtocolError):
            state.transition("completed")
        state.add_received(5)
        state.transition("verifying")
        with self.assertRaises(ProtocolError):
            state.complete([], 5)
        with self.assertRaises(ProtocolError):
            state.complete(["committed"], 4)
        with self.assertRaises(ProtocolError):
            state.complete(["committed"], 5)
        directory = tempfile.mkdtemp(prefix="mta-host-protocol-test-")
        try:
            path = os.path.join(directory, "actual.txt")
            with open(path, "wb") as target:
                target.write(b"hello")
            self.assertEqual(state.complete([path], 5), "completed")
        finally:
            shutil.rmtree(directory)
        with self.assertRaises(ProtocolError):
            state.transition("failed")

    def test_cancel_and_invalid_state(self):
        state = TransferState()
        with self.assertRaises(ProtocolError):
            state.transition("transferring")
        self.assertEqual(state.transition("cancelled"), "cancelled")
        with self.assertRaises(ProtocolError):
            state.add_received(0)


if __name__ == "__main__":
    unittest.main()
