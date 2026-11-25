"""HOST-only fake OS evidence; never opens a real netlink/socket/device."""
import ast
import importlib.util
import math
import os
import socket
import struct
import sys
import threading
import unittest
from unittest import mock

RUNTIME = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime'))
sys.path.insert(0, RUNTIME)
import mta_client_caps_transport as wire


def attr(kind, data=b'', flags=0):
    value = struct.pack('<HH', 4 + len(data), kind | flags) + data
    return value + b'\0' * ((-len(value)) & 3)


def u32(kind, value):
    return attr(kind, struct.pack('<I', value))


def nl(kind, seq, body, flags=0, port=41):
    value = struct.pack('<IHHII', 16 + len(body), kind, flags, seq, port) + body
    return value + b'\0' * ((-len(value)) & 3)


def genl(kind, seq, cmd, attrs=b'', flags=0, version=1, reserved=0, port=41):
    return nl(kind, seq, struct.pack('<BBH', cmd, version, reserved) + attrs, flags, port)


def family(extra=b''):
    return (attr(1, struct.pack('<H', 23)) + attr(2, b'nl80211\0') + u32(3, 1) +
            u32(4, 0) + u32(5, 259) + extra)


def identity(phy=0, generation=7, name=b'fixture\0'):
    return u32(1, phy) + attr(2, name) + u32(46, generation)


def combo(bi=None, extra=b''):
    limit = u32(1, 2) + attr(2, attr(2) + attr(8))
    data = attr(1, attr(1, limit)) + u32(2, 2) + u32(4, 1) + u32(5, 0) + u32(6, 0)
    if bi is not None:
        data += u32(7, bi)
    return attr(120, attr(1, data + extra))


def fixture(parts=None, ctrl=None, features=1):
    if parts is None:
        parts = (identity() + attr(32, attr(2) + attr(8)),
                 identity() + attr(50, u32(1, 7) + u32(2, 6)),
                 identity() + attr(121) + combo())
    result = [genl(16, 1, 1, family() if ctrl is None else ctrl, version=2),
              genl(23, 2, 95, u32(173, features))]
    result.extend(genl(23, 3, 3, value, flags=2) for value in parts)
    result.append(nl(3, 3, struct.pack('<i', 0), 2))
    return result


class FakeSocket(object):
    def __init__(self, packets=None):
        self.packets = list(fixture() if packets is None else packets)
        self.sent, self.timeouts = [], []
        self.timeout, self.inheritable, self.fd = None, True, 17
        self.close_count = 0
        self.bind_error = self.close_error = self.recv_error = None
        self.close_keeps_fd = False
        self.timeout_mismatch = self.inheritable_mismatch = False
        self.timeout_nanosecond_quantized = False
        self.timeout_override_set, self.timeout_override = False, None
        self.short_send = False
        self.endpoint = (41, 0)
        self.on_recv = None

    def set_inheritable(self, value):
        self.inheritable = value

    def get_inheritable(self):
        return True if self.inheritable_mismatch else self.inheritable

    def bind(self, endpoint):
        if self.bind_error:
            raise self.bind_error
        if endpoint != (0, 0):
            raise AssertionError('HOST fixture binding')

    def getsockname(self):
        return self.endpoint

    def settimeout(self, value):
        self.timeout = value
        if self.timeout_nanosecond_quantized:
            seconds, fraction = divmod(math.ceil(value * 1000000000), 1000000000)
            self.timeout = seconds + fraction * 1e-9
        self.timeouts.append(value)

    def gettimeout(self):
        if self.timeout_override_set:
            return self.timeout_override
        return 0 if self.timeout_mismatch else self.timeout

    def sendto(self, data, peer):
        self.sent.append((data, peer))
        return len(data) - 1 if self.short_send else len(data)

    def recvmsg(self, size, ancillary, flags):
        if (size, ancillary, flags) != (65537, 256, 0):
            raise AssertionError('HOST fixture buffer')
        if self.on_recv:
            self.on_recv(self)
        if self.recv_error:
            raise self.recv_error
        if not self.packets:
            raise socket.timeout('fixture timeout')
        packet = self.packets.pop(0)
        return packet if type(packet) is tuple else (packet, [], 0, (0, 0))

    def close(self):
        self.close_count += 1
        if self.close_error:
            raise self.close_error
        if not self.close_keeps_fd:
            self.fd = -1

    def fileno(self):
        return self.fd


class TransportTests(unittest.TestCase):
    def setUp(self):
        forbidden = mock.patch('socket.socket', side_effect=AssertionError('real socket forbidden'))
        forbidden.start()
        self.addCleanup(forbidden.stop)

    def reader(self, raw=None, **kwargs):
        raw = FakeSocket() if raw is None else raw
        creator = mock.Mock(return_value=raw)
        return wire.ClientCapsReader(0, socket_factory=creator, clock=lambda: 1.0, **kwargs), raw, creator

    def reject(self, packets=None, expected=None, raw=None):
        raw = FakeSocket(packets) if raw is None else raw
        reader, raw, creator = self.reader(raw)
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        if expected is not None:
            self.assertEqual(expected, caught.exception.code)
        self.assertEqual(1, raw.close_count)
        self.assertEqual(-1, raw.fileno())
        self.assertTrue(reader.status()['socket_closed'])
        self.assertFalse(reader.status()['read_success'])
        self.assertFalse(reader.status()['resource_pending'])
        self.assertEqual(1, creator.call_count)
        return reader, caught.exception

    def test_constructor_and_import_do_no_io(self):
        source_path = os.path.join(RUNTIME, 'mta_client_caps_transport.py')
        spec = importlib.util.spec_from_file_location('host_caps_reader_only', source_path)
        module = importlib.util.module_from_spec(spec)
        with mock.patch('socket.socket', side_effect=AssertionError('real socket forbidden')), \
                mock.patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            spec.loader.exec_module(module)
            instance = module.ClientCapsReader(0)
        self.assertFalse(instance.status()['attempted'])
        self.assertFalse(instance.status()['resource_pending'])

    def test_python35_ast(self):
        with open(os.path.join(RUNTIME, 'mta_client_caps_transport.py'), encoding='utf-8') as stream:
            ast.parse(stream.read(), feature_version=(3, 5))

    def test_ids_match_reviewed_v414_uapi(self):
        self.assertEqual((95, 173, 174, 1, 3, 2, 1),
            (wire.GET_PROTOCOL_FEATURES, wire.PROTOCOL_FEATURES, wire.SPLIT_WIPHY_DUMP,
             wire.GET_WIPHY, wire.NEW_WIPHY, wire.CTRL_VERSION, wire.NL_VERSION))

    def test_complete_split_returns_rich_defaults_without_admission(self):
        reader, raw, creator = self.reader()
        result = reader.read()
        self.assertEqual(1, len(result.phys))
        self.assertEqual((2, 8), result.phys[0].iftypes)
        self.assertEqual('all_beacons_identical', result.phys[0].combinations[0].bi_policy)
        self.assertFalse(result.phys[0].combinations[0].bi_min_gcd_present)
        self.assertIsNone(result.phys[0].combinations[0].bi_min_gcd)
        self.assertFalse(hasattr(result, 'complete'))
        self.assertTrue(reader.status()['read_success'])
        self.assertTrue(reader.status()['socket_closed'])
        self.assertTrue(reader.status()['has_unassessed_fields'])
        self.assertEqual(6, len(reader.raw_datagrams))
        self.assertEqual(3, len(reader.raw_wiphy_messages))
        self.assertEqual(1, raw.close_count)
        self.assertIs(reader._socket, raw)
        creator.assert_called_once_with(16, socket.SOCK_RAW, 16)

    def test_exact_three_readonly_requests_actual_port_and_no_ack(self):
        reader, raw, _ = self.reader()
        reader.read()
        self.assertEqual(3, len(raw.sent))
        headers = [struct.unpack_from('<IHHII', pair[0]) for pair in raw.sent]
        self.assertEqual((1, 2, 3), tuple(h[3] for h in headers))
        self.assertEqual((41, 41, 41), tuple(h[4] for h in headers))
        self.assertEqual((1, 1, 0x301), tuple(h[2] for h in headers))
        self.assertEqual((3, 95, 1), tuple(pair[0][16] for pair in raw.sent))
        self.assertEqual((2, 1, 1), tuple(pair[0][17] for pair in raw.sent))
        self.assertEqual(u32(1, 0) + attr(174), raw.sent[2][0][20:])
        self.assertTrue(all(peer == (0, 0) for _, peer in raw.sent))
        self.assertEqual(tuple(data for data, _ in raw.sent), reader.raw_requests)

    def test_one_attempt_even_after_failure(self):
        reader, _ = self.reject([b'x'], 'receive_budget')
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('already_attempted', caught.exception.code)

    def test_config_validation_before_factory(self):
        for phy in (True, -1, 2 ** 32, '0'):
            with self.subTest(phy_type=type(phy).__name__):
                with self.assertRaises(wire.CapsTransportError):
                    wire.ClientCapsReader(phy)
        for timeout in (True, 0, 11, float('inf'), float('nan'), 10 ** 1000, '5'):
            with self.subTest(timeout_type=type(timeout).__name__):
                with self.assertRaises(wire.CapsTransportError):
                    wire.ClientCapsReader(0, timeout=timeout)
        for field in ('socket_factory', 'clock'):
            with self.assertRaises(wire.CapsTransportError):
                wire.ClientCapsReader(0, **{field: False})

    def test_unknown_factory_pending_no_retry_or_general_clear(self):
        creator = mock.Mock(side_effect=OSError(5, 'private fixture detail'))
        reader = wire.ClientCapsReader(0, socket_factory=creator, clock=lambda: 1)
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('os_error', caught.exception.code)
        self.assertEqual(5, caught.exception.errno)
        self.assertNotIn('private', str(caught.exception))
        self.assertTrue(reader.status()['resource_pending'])
        self.assertFalse(reader.status()['socket_closed'])
        self.assertIs(reader._creator, creator)
        self.assertFalse(hasattr(reader, 'clear_pending'))

    def test_partial_bind_failure_closes_exact_socket_once(self):
        raw = FakeSocket()
        raw.bind_error = OSError(13, 'private fixture detail')
        reader, error = self.reject(raw=raw, expected='os_error')
        self.assertEqual(13, error.errno)
        self.assertIs(reader._socket, raw)
        self.assertEqual((), reader.raw_datagrams)

    def test_close_exception_keeps_exact_reference_and_no_result(self):
        raw = FakeSocket()
        raw.close_error = OSError(5, 'close fixture')
        reader, _, _ = self.reader(raw)
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('socket_close_unverified', caught.exception.code)
        self.assertEqual(1, raw.close_count)
        self.assertIs(reader._socket, raw)
        self.assertTrue(reader.status()['resource_pending'])
        self.assertFalse(reader.status()['read_success'])

    def test_close_return_without_fd_closed_is_pending(self):
        raw = FakeSocket()
        raw.close_keeps_fd = True
        reader, _, _ = self.reader(raw)
        with self.assertRaises(wire.CapsTransportError):
            reader.read()
        self.assertTrue(reader.status()['resource_pending'])
        self.assertEqual(1, raw.close_count)

    def test_base_exception_during_receive_never_false_success(self):
        for signal in (KeyboardInterrupt(), SystemExit()):
            raw = FakeSocket()
            raw.recv_error = signal
            reader, _, _ = self.reader(raw)
            with self.assertRaises(wire.CapsTransportError) as caught:
                reader.read()
            self.assertEqual('interrupted', caught.exception.code)
            self.assertFalse(reader.status()['read_success'])
            self.assertTrue(reader.status()['socket_closed'])
            self.assertEqual(1, raw.close_count)

    def test_base_exception_during_close_retains_pending_reference(self):
        raw = FakeSocket()
        raw.close_error = KeyboardInterrupt()
        reader, _, _ = self.reader(raw)
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('socket_close_unverified', caught.exception.code)
        self.assertTrue(reader.status()['resource_pending'])
        self.assertFalse(reader.status()['read_success'])
        self.assertIs(reader._socket, raw)
        self.assertEqual(1, raw.close_count)

    def test_inheritable_and_timeout_readbacks(self):
        for field, code in (('inheritable_mismatch', 'inheritable_readback'),
                            ('timeout_mismatch', 'timeout_readback')):
            raw = FakeSocket()
            setattr(raw, field, True)
            self.reject(raw=raw, expected=code)

    def test_nanosecond_quantized_decreasing_clock_completes_shared_deadline(self):
        raw = FakeSocket()
        raw.timeout_nanosecond_quantized = True
        current = [1.234567890123]
        def advancing():
            current[0] += 0.000123456789
            return current[0]
        reader = wire.ClientCapsReader(0, socket_factory=lambda *args: raw, clock=advancing)
        result = reader.read()
        self.assertEqual(1, len(result.phys))
        self.assertTrue(reader.status()['read_success'])
        self.assertTrue(reader.status()['socket_closed'])
        self.assertFalse(reader.status()['resource_pending'])
        self.assertEqual(3, len(raw.sent)); self.assertEqual(1, raw.close_count)
        self.assertLess(raw.timeouts[-1], raw.timeouts[0])
        self.assertTrue(all(0 < value < 5 for value in raw.timeouts))
        quantized = []
        for value in raw.timeouts:
            seconds, fraction = divmod(math.ceil(value * 1000000000), 1000000000)
            quantized.append(seconds + fraction * 1e-9)
        self.assertTrue(any(before != after for before, after in zip(raw.timeouts, quantized)))
        self.assertEqual(quantized[-1], raw.timeout)

    def test_nanosecond_readback_rejects_nonfloat_nonfinite_nonpositive_or_large(self):
        class FloatSubclass(float):
            pass
        for value in (None, True, False, 5, 0.0, -1.0, float('nan'), float('inf'),
                      float('-inf'), 10 ** 1000, 1e300, FloatSubclass(5.0), 4.0, 6.0):
            with self.subTest(kind=type(value).__name__):
                raw = FakeSocket(); raw.timeout_nanosecond_quantized = True
                raw.timeout_override_set, raw.timeout_override = True, value
                self.reject(raw=raw, expected='timeout_readback')
                self.assertEqual([], raw.sent)

    def test_nanosecond_readback_rejects_unquantized_and_adjacent_values(self):
        # deadline=6; the first remaining=4.99999999975 seconds rounds up to 5.
        for value in (4.99999999975, 4.999999999, 5.000000001):
            raw = FakeSocket(); raw.timeout_nanosecond_quantized = True
            raw.timeout_override_set, raw.timeout_override = True, value
            ticks = iter((1.0, 1.00000000025))
            reader = wire.ClientCapsReader(0, socket_factory=lambda *args: raw,
                                           clock=lambda: next(ticks))
            with self.assertRaises(wire.CapsTransportError) as caught:
                reader.read()
            self.assertEqual('timeout_readback', caught.exception.code)
            self.assertEqual([], raw.sent); self.assertEqual(1, raw.close_count)
            self.assertFalse(reader.status()['read_success'])
            self.assertFalse(reader.status()['resource_pending'])

    def test_nanosecond_quantized_mode_preserves_late_done_deadline(self):
        raw = FakeSocket(); raw.timeout_nanosecond_quantized = True
        current = [1.234567890123]
        def advancing():
            current[0] += 0.000123456789
            return current[0]
        def late_done(instance):
            if len(instance.packets) == 1:
                current[0] = 8.0
        raw.on_recv = late_done
        reader = wire.ClientCapsReader(0, socket_factory=lambda *args: raw, clock=advancing)
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('deadline', caught.exception.code)
        self.assertEqual(6, len(reader.raw_datagrams)); self.assertEqual(3, len(raw.sent))
        self.assertTrue(reader.status()['socket_closed'])
        self.assertFalse(reader.status()['read_success'])
        self.assertEqual(1, raw.close_count)

    def test_port_shape_zero_group_and_bool_reject(self):
        for endpoint in ((0, 0), (41, 1), (True, 0), (41, False), [41, 0], (41,)):
            raw = FakeSocket()
            raw.endpoint = endpoint
            self.reject(raw=raw, expected='bound_port')

    def test_short_send_is_not_retried(self):
        raw = FakeSocket()
        raw.short_send = True
        self.reject(raw=raw, expected='short_send')
        self.assertEqual(1, len(raw.sent))

    def test_os_timeout_and_opaque_error_sanitized(self):
        for error, code in ((socket.timeout('fixture'), 'os_error'),
                            (RuntimeError('secret fixture'), 'unexpected_read_error')):
            raw = FakeSocket()
            raw.recv_error = error
            reader, caught = self.reject(raw=raw, expected=code)
            self.assertNotIn('secret', repr(caught))
            self.assertEqual((), reader.raw_datagrams)

    def test_kernel_peer_not_header_pid(self):
        for peer in ((7, 0), (0, 1), (False, 0), [0, 0]):
            packets = fixture()
            packets[0] = (packets[0], [], 0, peer)
            self.reject(packets, 'not_kernel_peer')

    def test_header_sequence_and_actual_port_exact(self):
        for seq, port in ((0, 41), (2, 41), (1, 0), (1, 42)):
            packets = fixture()
            packets[0] = genl(16, seq, 1, family(), version=2, port=port)
            self.reject(packets, 'message_identity')

    def test_generic_family_command_version_reserved(self):
        cases = ((17, 1, 2, 0, 'wrong_family'), (16, 3, 2, 0, 'generic_header'),
                 (16, 1, 1, 0, 'generic_header'), (16, 1, 2, 1, 'generic_header'))
        for fam, cmd, version, reserved, code in cases:
            packets = fixture()
            packets[0] = genl(fam, 1, cmd, family(), version=version, reserved=reserved)
            self.reject(packets, code)

    def test_family_schema_name_abi_and_duplicates(self):
        cases = (family(u32(3, 1)), family(u32(8, 0)),
                 family().replace(b'nl80211\0', b'badname\0'),
                 attr(1, struct.pack('<H', 18)) + family()[8:],
                 attr(1, struct.pack('<H', 23)) + attr(2, b'nl80211\0') +
                    u32(3, 2) + u32(4, 0) + u32(5, 259),
                 attr(1, struct.pack('<H', 23)) + attr(2, b'nl80211\0') +
                    u32(3, 1) + u32(4, 4) + u32(5, 259))
        for ctrl in cases:
            self.reject(fixture(ctrl=ctrl))

    def test_family_nested_metadata_valid_and_unknown_reject(self):
        ops = attr(6, attr(1, u32(1, 1) + u32(2, 0x0e)))
        groups = attr(7, attr(1, attr(1, b'config\0') + u32(2, 7)))
        reader, _, _ = self.reader(FakeSocket(fixture(ctrl=family(ops + groups))))
        reader.read()
        self.reject(fixture(ctrl=family(attr(6, attr(1, u32(1, 1) + u32(2, 32))))))
        self.reject(fixture(ctrl=family(attr(6, attr(1, u32(1, 1) + u32(2, 14)) +
                                     attr(2, u32(1, 1) + u32(2, 14))))),
                    'family_nested_duplicate')

    def test_protocol_split_is_explicit_unknown_bits_reject(self):
        for features in (0, 2, 3, 0xffffffff):
            self.reject(fixture(features=features), 'split_not_supported')
        packets = fixture()
        packets[1] = genl(23, 2, 95, u32(173, 1) + u32(173, 1))
        self.reject(packets, 'protocol_features_format')

    def test_ack_even_success_cannot_finish_dump(self):
        packets = fixture()
        packets[-1] = nl(2, 3, struct.pack('<i', 0), 2)
        self.reject(packets, 'netlink_error')

    def test_done_requires_exact_zero_body_and_prior_data(self):
        for body in (b'', struct.pack('<i', -5), struct.pack('<i', 0) + b'\0' * 4):
            packets = fixture()
            packets[-1] = nl(3, 3, body, 2)
            self.reject(packets, 'invalid_done')
        packets = fixture()
        self.reject(packets[:2] + [packets[-1]], 'invalid_done')

    def test_dump_requires_done_not_first_fragment(self):
        reader, caught = self.reject(fixture()[:-1], 'os_error')
        self.assertEqual(3, len(reader.raw_wiphy_messages))
        self.assertEqual(5, len(reader.raw_datagrams))

    def test_intr_overrun_and_unknown_message_flags(self):
        for bits, kind, code in ((18, 23, 'dump_interrupted'),
                                 (2, 4, 'netlink_overrun'), (0, 23, 'message_flags'),
                                 (34, 23, 'message_flags')):
            packets = fixture()
            packets[2] = genl(kind, 3, 3, identity(), flags=bits)
            self.reject(packets, code)

    def test_datagram_trunc_ctrunc_unknown_control_preserves_raw(self):
        for flags, ancillary, code in ((32, [], 'receive_truncated'),
                (8, [], 'receive_truncated'), (1, [], 'receive_control'),
                (0, [(1, 2, b'private')], 'receive_control'), (0, None, 'receive_control')):
            packets = fixture()
            exact = packets[0]
            packets[0] = (exact, ancillary, flags, (0, 0))
            reader, _ = self.reject(packets, code)
            self.assertEqual(exact, reader.raw_datagrams[0].data)

    def test_nl_lengths_padding_and_trailing_message_after_terminal(self):
        for packet in (b'x' * 15, b'\0' * 16,
                       genl(16, 1, 1, family(), version=2) + b'x'):
            self.reject([packet])
        packets = fixture()
        packets[0] += packets[0]
        self.reject(packets, 'message_after_terminal')
        packets = fixture()
        packets[-1] += packets[-1]
        self.reject(packets, 'message_after_terminal')

    def test_unknown_top_attribute_preserves_full_unassessed_raw(self):
        parts = (identity() + attr(32, attr(2) + attr(8)),
                 identity() + attr(50, u32(1, 7)),
                 identity() + attr(121) + combo() + u32(500, 1))
        reader, _ = self.reject(fixture(parts), 'unreviewed_top_attribute')
        self.assertTrue(reader.raw_wiphy_messages[-1].endswith(u32(500, 1)))

    def test_known_bands_feature_flags_retained_not_admission(self):
        parts = (identity() + attr(32, attr(2) + attr(8)) + attr(22, attr(0, b'')),
                 identity() + attr(50, u32(1, 7)) + u32(143, 0x12345678),
                 identity() + attr(121) + combo() + attr(217, b'\xff'))
        reader, _, _ = self.reader(FakeSocket(fixture(parts)))
        reader.read()
        retained = {item.kind: item.encoded for item in reader.unprojected_attributes}
        self.assertEqual(u32(143, 0x12345678), retained[143])
        self.assertEqual(attr(217, b'\xff'), retained[217])
        self.assertTrue(reader.status()['has_unassessed_fields'])

    def test_metadata_generation_name_and_phy_match_every_fragment(self):
        for changed in (identity(generation=8), identity(phy=1), identity(name=b'other\0')):
            self.reject(fixture((identity() + attr(32, attr(2) + attr(8)),
                changed + attr(50, u32(1, 7)), identity() + attr(121) + combo())))

    def test_missing_metadata_or_caps_reject(self):
        self.reject(fixture((u32(1, 0) + attr(32, attr(2) + attr(8)),)), 'wiphy_identity')
        self.reject(fixture((identity() + attr(32, attr(2) + attr(8)),)), 'missing_caps_fields')

    def test_top_duplicates_within_and_across_fragments(self):
        self.reject(fixture((identity() + u32(1, 0),)), 'duplicate_top_attribute')
        self.reject(fixture((identity() + attr(32, attr(2)),
                            identity() + attr(32, attr(2)))), 'duplicate_top_attribute')

    def test_nested_constraint_unknown_and_duplicate_refuse_not_strip(self):
        for extra in (u32(8, 1), u32(4, 1)):
            self.reject(fixture((identity() + attr(32, attr(2) + attr(8)),
                identity() + attr(50, u32(1, 7)), identity() + attr(121) + combo(extra=extra))),
                'caps_schema')

    def test_known_shape_and_attribute_flags_reject(self):
        for extra in (attr(143, b'x'), attr(143, b'\0' * 4, 0x8000),
                      attr(22, b'xx'), attr(61, b'xx'), attr(56, b'x'),
                      attr(104, b'x'), attr(57, b'x'), attr(148, b'x'),
                      attr(176, b'x'), attr(2, b'missingnul')):
            self.reject(fixture((identity() + extra,)))

    def test_received_byte_fragment_message_budgets(self):
        self.reject([b'\0' * (wire.MAX_DATAGRAM + 1)], 'receive_budget')
        packets = fixture()[:2] + [genl(23, 3, 3, identity(), flags=2)] * 65
        self.reject(packets, 'fragment_budget')
        with mock.patch.object(wire, 'MAX_MESSAGES', 2):
            self.reject(fixture(), 'message_budget')
        with mock.patch.object(wire, 'MAX_RAW_BYTES', 20):
            self.reject(fixture(), 'receive_budget')
        with mock.patch.object(wire, 'MAX_DATAGRAMS', 1):
            self.reject(fixture(), 'receive_budget')

    def test_attribute_budget_bound(self):
        with mock.patch.object(wire, 'MAX_TOP_ATTRIBUTES', 2):
            self.reject(fixture(), 'attribute_budget')

    def test_deadline_post_receive_refuses_late_done(self):
        current = [1.0]
        raw = FakeSocket()
        def hook(instance):
            if len(instance.packets) == 1:
                current[0] = 8.0
        raw.on_recv = hook
        reader = wire.ClientCapsReader(0, socket_factory=lambda *args: raw,
                                       clock=lambda: current[0])
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('deadline', caught.exception.code)
        self.assertEqual(6, len(reader.raw_datagrams))
        self.assertTrue(reader.status()['socket_closed'])

    def test_invalid_clock_before_factory_and_huge_integer_safe(self):
        for value in (True, float('nan'), 10 ** 1000):
            creator = mock.Mock()
            reader = wire.ClientCapsReader(0, socket_factory=creator, clock=lambda: value)
            with self.assertRaises(wire.CapsTransportError) as caught:
                reader.read()
            self.assertEqual('invalid_clock_value', caught.exception.code)
            creator.assert_not_called()
            self.assertFalse(reader.status()['resource_pending'])

    def test_clock_regression_rejects_before_send(self):
        ticks = iter((1.0, 0.9))
        raw = FakeSocket()
        reader = wire.ClientCapsReader(0, socket_factory=lambda *args: raw,
                                       clock=lambda: next(ticks))
        with self.assertRaises(wire.CapsTransportError) as caught:
            reader.read()
        self.assertEqual('clock_regressed', caught.exception.code)
        self.assertEqual([], raw.sent)
        self.assertEqual(1, raw.close_count)

    def test_default_production_os_gate_no_real_socket(self):
        with mock.patch.object(wire.sys, 'platform', 'win32'), \
                mock.patch('socket.socket', side_effect=AssertionError('no real socket')) as forbidden:
            reader = wire.ClientCapsReader(0)
            with self.assertRaises(wire.CapsTransportError) as caught:
                reader.read()
            self.assertEqual('unsupported_platform', caught.exception.code)
            forbidden.assert_not_called()

    def test_public_status_contains_no_identifiers_raw_or_paths(self):
        reader, _, _ = self.reader()
        reader.read()
        public = reader.status()
        self.assertEqual({'attempted', 'finished', 'read_success', 'socket_closed',
            'resource_pending', 'has_unassessed_fields', 'datagram_count',
            'message_count', 'unassessed_count', 'reason'}, set(public))
        self.assertNotIn('fixture', repr(public))
        self.assertNotIn('41', repr(public))
        self.assertIsInstance(reader.raw_datagrams, tuple)

    def test_concurrent_second_read_cannot_create_second_socket(self):
        entered, release = threading.Event(), threading.Event()
        raw = FakeSocket()
        def wait_first(instance):
            instance.on_recv = None
            entered.set()
            if not release.wait(2):
                raise RuntimeError('HOST fixture bounded wait')
        raw.on_recv = wait_first
        reader, _, creator = self.reader(raw)
        results = []
        thread = threading.Thread(target=lambda: results.append(reader.read()))
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaises(wire.CapsTransportError) as caught:
                reader.read()
            self.assertEqual('already_attempted', caught.exception.code)
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(1, creator.call_count)
        self.assertEqual(1, len(results))
        self.assertEqual(1, raw.close_count)


if __name__ == '__main__':
    unittest.main()
