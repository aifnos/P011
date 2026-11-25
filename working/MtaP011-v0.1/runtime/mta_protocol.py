# -*- coding: utf-8 -*-
"""Bounded MTA wire types. Independently written, Python 3.5 compatible.

These are protocol primitives, not proof of phone interoperability. UUIDs and
field names follow CatShare/Cattysend wire schemas, not the inconsistent prose
examples in some implementation documents. No radio operations occur here.
"""
import base64
import os
import re
import struct
import uuid

import p011_json as json

ADV_SERVICE_UUID = "00003331-0000-1000-8000-008123456789"
STANDARD_ADV_UUID = "00003331-0000-1000-8000-00805f9b34fb"
MAIN_SERVICE_UUID = "00009955-0000-1000-8000-00805f9b34fb"
STATUS_CHAR_UUID = "00009954-0000-1000-8000-00805f9b34fb"
P2P_CHAR_UUID = "00009953-0000-1000-8000-00805f9b34fb"
MAX_MESSAGE_BYTES = 65536
MAX_GATT_BYTES = 8192
_TASK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_WS = re.compile(r"^(action|ack):([0-9]{1,10}):([A-Za-z][A-Za-z0-9_]{0,63})(?:\?(.*))?\Z", re.S)


class ProtocolError(ValueError):
    pass


def _integer(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ProtocolError("invalid " + label)
    return value


def _text(value, maximum, label, empty=False):
    if not isinstance(value, str) or (not empty and not value):
        raise ProtocolError("invalid " + label)
    if len(value.encode("utf-8")) > maximum or "\x00" in value:
        raise ProtocolError("invalid " + label)
    return value


def validate_task_id(value):
    if not isinstance(value, str) or _TASK.match(value) is None:
        raise ProtocolError("invalid taskId")
    return value


def get_task_id(payload):
    if not isinstance(payload, dict):
        raise ProtocolError("request must be an object")
    task = payload.get("taskId")
    alias = payload.get("id")
    if task is not None and alias is not None and task != alias:
        raise ProtocolError("conflicting taskId aliases")
    return validate_task_id(task if task is not None else alias)


def _base64(value, maximum=512, label="public key"):
    _text(value, maximum * 2, label)
    try:
        result = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise ProtocolError("invalid " + label)
    if not result or len(result) > maximum:
        raise ProtocolError("invalid " + label)
    return result


def _bounded_tree(value, depth=0, counter=None):
    # Bound pathological nesting and object count before encoding and after
    # decoding. Do not accept floats/NaN: the current wire types need integers.
    if counter is None:
        counter = [0]
    counter[0] += 1
    if depth > 16 or counter[0] > 4096:
        raise ProtocolError("JSON structure limit")
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str):
            _text(value, MAX_MESSAGE_BYTES, "JSON string", empty=True)
        return
    if isinstance(value, list):
        for item in value:
            _bounded_tree(item, depth + 1, counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _text(key, 256, "JSON key")
            _bounded_tree(item, depth + 1, counter)
        return
    raise ProtocolError("unsupported JSON value")


def encode_json(value, maximum=MAX_GATT_BYTES):
    _bounded_tree(value)
    wire = json.dumps(value).encode("utf-8")
    if len(wire) > maximum:
        raise ProtocolError("JSON byte limit")
    return wire


def decode_json(wire, maximum=MAX_GATT_BYTES):
    if isinstance(wire, str):
        wire = wire.encode("utf-8")
    if not isinstance(wire, bytes) or len(wire) > maximum:
        raise ProtocolError("JSON byte limit")
    try:
        value = json.loads(wire.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, RuntimeError):
        raise ProtocolError("invalid JSON")
    _bounded_tree(value)
    return value


class DeviceInfo(object):
    def __init__(self, mac, key=None, state=0, cat_share=1):
        if not isinstance(mac, str) or _MAC.match(mac) is None:
            raise ProtocolError("invalid device MAC")
        self.mac = mac.upper()
        self.key = key
        self.state = _integer(state, 0, 65535, "device state")
        self.cat_share = cat_share
        if key is not None:
            _base64(key)
        if cat_share is not None:
            _integer(cat_share, 0, 65535, "catShare")

    def to_dict(self):
        result = {"state": self.state, "mac": self.mac}
        if self.key is not None:
            result["key"] = self.key
        if self.cat_share is not None:
            result["catShare"] = self.cat_share
        return result

    def to_bytes(self):
        return encode_json(self.to_dict())

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or "state" not in value or "mac" not in value:
            raise ProtocolError("invalid DeviceInfo")
        return cls(value["mac"], value.get("key"), value["state"], value.get("catShare"))

    @classmethod
    def from_bytes(cls, value):
        return cls.from_dict(decode_json(value))


class P2pInfo(object):
    def __init__(self, ssid, psk, mac, port, key=None, sender_id=None, cat_share=1):
        self.key = key
        self.ssid = ssid
        self.psk = psk
        self.mac = mac
        self.port = _integer(port, 1, 65535, "port")
        self.id = sender_id
        self.cat_share = cat_share
        if key is None:
            _text(ssid, 32, "SSID")
            _text(psk, 64, "PSK")
            if len(psk.encode("utf-8")) < 8 or (len(psk.encode("utf-8")) == 64 and re.match(r"^[0-9a-fA-F]{64}\Z", psk) is None):
                raise ProtocolError("invalid PSK")
            if not isinstance(mac, str) or _MAC.match(mac) is None:
                raise ProtocolError("invalid peer MAC")
            self.mac = mac.upper()
        else:
            _base64(key)
            for label, value in (("encrypted SSID", ssid), ("encrypted PSK", psk), ("encrypted MAC", mac)):
                _base64(value, 256, label)
        if sender_id is not None:
            validate_task_id(sender_id)
        if cat_share is not None:
            _integer(cat_share, 0, 65535, "catShare")

    def to_dict(self):
        result = {"ssid": self.ssid, "psk": self.psk, "mac": self.mac, "port": self.port}
        for field, value in (("key", self.key), ("id", self.id), ("catShare", self.cat_share)):
            if value is not None:
                result[field] = value
        return result

    def to_bytes(self):
        return encode_json(self.to_dict())

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or not all(field in value for field in ("ssid", "psk", "mac", "port")):
            raise ProtocolError("invalid P2pInfo")
        return cls(value["ssid"], value["psk"], value["mac"], value["port"], value.get("key"), value.get("id"), value.get("catShare"))

    @classmethod
    def from_bytes(cls, value):
        return cls.from_dict(decode_json(value))


class WsMessage(object):
    def __init__(self, msg_type, msg_id, name, payload=None):
        if msg_type not in ("action", "ack") or not isinstance(name, str) or _NAME.match(name) is None:
            raise ProtocolError("invalid WebSocket header")
        self.msg_type = msg_type
        self.type = msg_type
        self.id = _integer(msg_id, 0, 4294967295, "message id")
        self.name = name
        if payload is not None and not isinstance(payload, dict):
            raise ProtocolError("message payload must be an object")
        self.payload = payload
        if payload is not None and ("taskId" in payload or (name in ("sendRequest", "status", "cancel") and "id" in payload)):
            get_task_id(payload)

    def serialize(self):
        result = "{}:{}:{}".format(self.msg_type, self.id, self.name)
        if self.payload is not None:
            result += "?" + encode_json(self.payload, MAX_MESSAGE_BYTES).decode("utf-8")
        if len(result.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ProtocolError("message byte limit")
        return result

    def make_ack(self, payload=None):
        return WsMessage("ack", self.id, self.name, payload)

    @classmethod
    def parse(cls, text):
        if isinstance(text, bytes):
            try:
                text = text.decode("utf-8")
            except UnicodeError:
                raise ProtocolError("invalid message UTF-8")
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ProtocolError("message byte limit")
        match = _WS.match(text)
        if match is None:
            raise ProtocolError("invalid WebSocket message")
        payload = None
        if match.group(4) is not None:
            payload = decode_json(match.group(4), MAX_MESSAGE_BYTES)
            if not isinstance(payload, dict):
                raise ProtocolError("message payload must be an object")
        return cls(match.group(1), int(match.group(2)), match.group(3), payload)


def encode_message(name, payload=None, msg_id=0, msg_type="action", task_id=None):
    if task_id is not None:
        payload = dict(payload or {})
        payload["taskId"] = validate_task_id(task_id)
    return WsMessage(msg_type, msg_id, name, payload).serialize()


def decode_message(text):
    return WsMessage.parse(text)


def validate_send_request(payload, max_files=256, max_total_bytes=512 * 1024 * 1024):
    task_id = get_task_id(payload)
    count = _integer(payload.get("fileCount"), 1, max_files, "fileCount")
    size = _integer(payload.get("totalSize"), 0, max_total_bytes, "totalSize")
    for field, maximum in (("senderName", 256), ("fileName", 1024), ("mimeType", 256)):
        _text(payload.get(field), maximum, field)
    # The display filename is never used to construct a filesystem path.
    return {"taskId": task_id, "fileCount": count, "totalSize": size,
            "senderName": payload["senderName"], "fileName": payload["fileName"], "mimeType": payload["mimeType"]}


def _ad(kind, data):
    if len(data) > 254:
        raise ProtocolError("AD byte limit")
    return bytes(bytearray([len(data) + 1, kind])) + data


def encode_advertisement(sender_id, brand, name, supports_5ghz=False):
    if isinstance(sender_id, str):
        if re.match(r"^[0-9a-fA-F]{4}\Z", sender_id) is None:
            raise ProtocolError("sender ID must be two bytes")
        sender_id = bytes(bytearray.fromhex(sender_id))
    if not isinstance(sender_id, bytes) or len(sender_id) != 2:
        raise ProtocolError("sender ID must be two bytes")
    _integer(brand, 0, 255, "brand")
    if not isinstance(supports_5ghz, bool):
        raise ProtocolError("invalid band capability")
    _text(name, 256, "device name")
    identity = sender_id + b"\x00" * 4
    cap = brand | (0x100 if supports_5ghz else 0)
    name_bytes = name.encode("utf-8")
    if len(name_bytes) > 16:
        # Keep complete UTF-8 code points, leaving byte 25 for the CatShare
        # truncation marker. Never advertise a cut multibyte sequence.
        name_bytes = name_bytes[:15].decode("utf-8", "ignore").encode("utf-8")
        name_bytes = name_bytes.ljust(15, b"\x00") + b"\t"
    else:
        name_bytes = name_bytes.ljust(16, b"\x00")
    name_data = b"\x00" * 8 + sender_id + name_bytes + b"\x00"
    adv = (_ad(0x01, b"\x06") + _ad(0x07, uuid.UUID(ADV_SERVICE_UUID).bytes[::-1]) +
           _ad(0x16, struct.pack("<H", cap) + identity))
    scan = _ad(0x16, b"\xff\xff" + name_data)
    if len(adv) != 31 or len(scan) != 31:
        raise ProtocolError("legacy packet layout error")
    return {"adv_data": adv, "scan_rsp": scan, "identity": identity,
            "name_data": name_data, "capabilities": cap, "service_uuid": ADV_SERVICE_UUID}


def parse_ad_fields(raw):
    if not isinstance(raw, bytes) or len(raw) > 31:
        raise ProtocolError("invalid legacy advertising packet")
    result = []
    offset = 0
    while offset < len(raw):
        size = raw[offset]
        if size == 0:
            if any(raw[offset:]):
                raise ProtocolError("nonzero advertising padding")
            break
        end = offset + size + 1
        if size < 1 or end > len(raw):
            raise ProtocolError("truncated advertising field")
        result.append((raw[offset + 1], raw[offset + 2:end]))
        offset = end
    return result


def decode_service_data(capabilities, identity, name_data):
    _integer(capabilities, 0, 65535, "capabilities")
    if not isinstance(identity, bytes) or len(identity) != 6 or not isinstance(name_data, bytes) or len(name_data) != 27:
        raise ProtocolError("invalid MTA service-data lengths")
    if name_data[8:10] != identity[:2]:
        raise ProtocolError("sender ID mismatch")
    segment = name_data[10:26]
    truncated = segment[-1:] == b"\t"
    if truncated:
        segment = segment[:-1]
    segment = segment.rstrip(b"\x00")
    if b"\x00" in segment:
        raise ProtocolError("invalid name padding")
    try:
        name = segment.decode("utf-8")
    except UnicodeError:
        raise ProtocolError("invalid advertised name UTF-8")
    return {"sender_id": "{:02x}{:02x}".format(identity[0], identity[1]),
            "brand": capabilities & 255, "supports_5ghz": bool(capabilities & 0x100),
            "name": name, "name_truncated": truncated,
            "identity": identity, "name_data": name_data, "capabilities": capabilities}


def decode_advertisement(adv_data, scan_rsp):
    identity = None
    cap = None
    name_data = None
    known_uuid = False
    for kind, data in parse_ad_fields(adv_data):
        if kind in (0x06, 0x07) and len(data) % 16 == 0:
            for offset in range(0, len(data), 16):
                known_uuid = known_uuid or str(uuid.UUID(bytes=data[offset:offset + 16][::-1])) in (ADV_SERVICE_UUID, STANDARD_ADV_UUID)
        if kind == 0x16 and len(data) == 8:
            if identity is not None:
                raise ProtocolError("ambiguous identity data")
            cap = struct.unpack("<H", data[:2])[0]
            identity = data[2:]
    for kind, data in parse_ad_fields(scan_rsp):
        if kind == 0x16 and data[:2] == b"\xff\xff":
            if name_data is not None:
                raise ProtocolError("ambiguous name data")
            name_data = data[2:]
    if not known_uuid or identity is None or name_data is None:
        raise ProtocolError("not a supported MTA advertisement")
    return decode_service_data(cap, identity, name_data)


class TransferState(object):
    """A bounded session state; only actual verified commit can complete it."""
    _NEXT = {
        "idle": ("discovering", "connected"),
        "discovering": ("connected",),
        "connected": ("negotiated",),
        "negotiated": ("awaiting_confirmation",),
        "awaiting_confirmation": ("transferring", "refused"),
        "transferring": ("verifying",),
        "verifying": (),
        "completed": (), "refused": (), "cancelled": (), "failed": ()}

    def __init__(self, task_id=None, expected_files=None, expected_bytes=None):
        self.task_id = validate_task_id(task_id) if task_id is not None else None
        self.expected_files = expected_files
        self.expected_bytes = expected_bytes
        if expected_files is not None:
            _integer(expected_files, 1, 256, "expected file count")
        if expected_bytes is not None:
            _integer(expected_bytes, 0, 512 * 1024 * 1024, "expected bytes")
        self.state = "idle"
        self.received_bytes = 0
        self.history = ["idle"]

    def transition(self, state):
        terminal = ("completed", "refused", "cancelled", "failed")
        if self.state in terminal:
            raise ProtocolError("session already terminal")
        if state in ("cancelled", "failed") or state in self._NEXT.get(self.state, ()):
            self.state = state
            self.history.append(state)
            return state
        raise ProtocolError("invalid transfer transition")

    def add_received(self, count):
        if self.state != "transferring":
            raise ProtocolError("not transferring")
        _integer(count, 0, 512 * 1024 * 1024, "received bytes")
        new_count = self.received_bytes + count
        if self.expected_bytes is not None and new_count > self.expected_bytes:
            raise ProtocolError("received size exceeds request")
        self.received_bytes = new_count

    def complete(self, committed_files, actual_bytes):
        if self.state != "verifying" or not isinstance(committed_files, list) or not committed_files:
            raise ProtocolError("completion needs committed files")
        if self.expected_files is None or self.expected_bytes is None:
            raise ProtocolError("completion needs expected request")
        if len(committed_files) != self.expected_files or actual_bytes != self.expected_bytes:
            raise ProtocolError("committed result does not match request")
        if self.received_bytes != actual_bytes:
            raise ProtocolError("received result does not match request")
        unique = set()
        verified_bytes = 0
        for path in committed_files:
            if not isinstance(path, str) or not os.path.isabs(path) or os.path.islink(path) or not os.path.isfile(path):
                raise ProtocolError("completion needs actual regular files")
            resolved = os.path.realpath(path)
            if resolved in unique:
                raise ProtocolError("duplicate committed file")
            unique.add(resolved)
            verified_bytes += os.path.getsize(path)
        if verified_bytes != actual_bytes:
            raise ProtocolError("committed files differ from actual byte count")
        self.state = "completed"
        self.history.append("completed")
        return self.state
