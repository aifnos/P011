"""HOST-only synthetic rtnetlink tests; never opens a network socket."""

import ast
import os
import pathlib
import random
import struct
import sys
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'runtime'))
import mta_ip as ip


def attr(kind, payload):
    length = 4 + len(payload)
    return struct.pack('<HH', length, kind) + payload + b'\0' * ((-length) % 4)


def u32(number):
    return struct.pack('<I', number)


def address(text):
    return bytes(int(part) for part in text.split('.'))


def message(kind, payload, flags=2, sequence=10, port=123):
    length = 16 + len(payload)
    return struct.pack('<IHHII', length, kind, flags, sequence, port) + payload + b'\0' * ((-length) % 4)


def address_payload(local='10.1.1.2', prefix=24, index=2, peer=None, flags=128,
                    scope=0, extra=b'', label=b'wlan0\0', cache=True):
    payload = struct.pack('<BBBBI', 2, prefix, flags & 255, scope, index)
    payload += attr(1, address(peer or local)) + attr(2, address(local))
    if label is not None:
        payload += attr(3, label)
    if cache:
        payload += attr(6, struct.pack('<IIII', 0xffffffff, 0xffffffff, 5, 8))
    payload += attr(8, u32(flags))
    return payload + extra


def route_payload(network='10.1.1.0', prefix=24, table=254, oif=2, gateway=None,
                  prefsrc=None, priority=None, extra=b'', kind=1, flags=0,
                  scope=253, source_prefix=0, tos=0):
    payload = struct.pack('<BBBBBBBBI', 2, prefix, source_prefix, tos,
                          table if table < 256 else 252, 2, scope, kind, flags)
    payload += attr(15, u32(table))
    if prefix:
        payload += attr(1, address(network))
    if oif is not None:
        payload += attr(4, u32(oif))
    for key, value in ((5, gateway), (7, prefsrc)):
        if value is not None:
            payload += attr(key, address(value))
    if priority is not None:
        payload += attr(6, u32(priority))
    return payload + extra


def rule_payload(priority, table, extra=b'', suppress=0xffffffff,
                 flags=0, action=1, src_len=0):
    payload = struct.pack('<BBBBBBBBI', 2, 0, src_len, 0,
                          table if table < 256 else 0, 0, 0, action, flags)
    payload += attr(15, u32(table))
    if suppress is not None:
        payload += attr(14, u32(suppress))
    if priority:
        payload += attr(6, u32(priority))
    return payload + extra


def done(sequence=10, port=123, status=0, flags=2):
    return message(3, struct.pack('<i', status), flags, sequence, port)


def collector(kind, payloads=(), sequence=10, port=123):
    c = ip.DumpCollector(kind, sequence, port)
    msgtype = {'addresses': 20, 'routes': 24, 'rules': 32}[kind]
    c.feed(b''.join(message(msgtype, p, sequence=sequence, port=port) for p in payloads) + done(sequence, port))
    return c


DEFAULT_RULES = ((0, 255), (32766, 254), (32767, 253))


def snapshot(addresses=(), routes=(), rules=DEFAULT_RULES):
    return ip.snapshot_from_dumps(collector('addresses', addresses, 10),
                                  collector('routes', routes, 11),
                                  collector('rules', [rule_payload(*r) for r in rules], 12))


def ack(request, errno=0, flags=0, echo=None, sequence=None, port=None):
    unused_len, unused_type, unused_flags, seq, pid = struct.unpack_from('<IHHII', request)
    echoed = request[:16] if errno == 0 or flags & 0x100 else request
    payload = struct.pack('<i', -errno) + (echo if echo is not None else echoed)
    return message(2, payload, flags, seq if sequence is None else sequence,
                   pid if port is None else port)


class CoreCase(unittest.TestCase):
    def assertCode(self, code, action):
        with self.assertRaises(ip.IpCoreError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        return caught.exception


class DumpTests(CoreCase):
    def test_requests_unfiltered_family_all_tables(self):
        for kind, command, bodylen in (('addresses', 22, 8), ('routes', 26, 12), ('rules', 34, 12)):
            raw = ip.encode_dump(kind, 37, 123)
            self.assertEqual(struct.unpack_from('<IHHII', raw), (16 + bodylen, command, 0x301, 37, 123))
            self.assertEqual(raw[16], 2)
            self.assertEqual(raw[17:], b'\0' * (bodylen - 1))

    def test_invalid_request_inputs(self):
        self.assertCode('invalid_dump_kind', lambda: ip.encode_dump('links', 1, 2))
        self.assertCode('invalid_dump_kind', lambda: ip.encode_dump([], 1, 2))
        for seq, port in ((0, 2), (True, 2), (-1, 2), (1, 0), (1, True), (1, 2 ** 32)):
            self.assertCode('invalid_integer', lambda: ip.encode_dump('addresses', seq, port))

    def test_multipart_and_complete_records(self):
        c = ip.DumpCollector('addresses', 10, 123)
        self.assertCode('incomplete_dump', c.records)
        c.feed(message(20, address_payload()))
        self.assertFalse(c.complete)
        c.feed(done())
        self.assertTrue(c.complete)
        row = c.records()[0]
        self.assertEqual((row.ifindex, row.prefixlen, row.flags, row.scope), (2, 24, 128, 0))
        self.assertEqual(row.local, ip.ipv4_number('10.1.1.2'))
        self.assertNotIn('10.', repr(row))

    def test_empty_complete_dump(self):
        self.assertEqual(collector('routes').records(), ())

    def test_poison_on_wrong_sequence_or_port(self):
        for seq, port in ((11, 123), (10, 999)):
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode('dump_identity_mismatch', lambda: c.feed(done(seq, port)))
            self.assertTrue(c.failed)
            self.assertCode('dump_failed', lambda: c.feed(done()))
            self.assertCode('incomplete_dump', c.records)

    def test_dump_interruption_and_filtered_fail_closed(self):
        for flags in (18, 34, 50):
            c = ip.DumpCollector('routes', 10, 123)
            self.assertCode('inconsistent_dump', lambda: c.feed(done(flags=flags)))

    def test_overrun_rejected(self):
        c = ip.DumpCollector('rules', 10, 123)
        self.assertCode('dump_overrun', lambda: c.feed(message(4, b'')))

    def test_nonmultipart_data_wrong_type_and_noop_rejected(self):
        for raw in (message(20, address_payload(), flags=0), message(24, route_payload()), message(1, b'')):
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode('unexpected_dump_message', lambda: c.feed(raw))

    def test_done_shape_and_error(self):
        for payload, flags in ((b'', 2), (b'\0' * 8, 2), (u32(0), 1)):
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode('invalid_dump_done', lambda: c.feed(message(3, payload, flags)))
        c = ip.DumpCollector('addresses', 10, 123)
        error = self.assertCode('kernel_error', lambda: c.feed(done(status=-12)))
        self.assertEqual(error.errno, 12)
        for status in (1, -4096):
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode('invalid_kernel_errno', lambda: c.feed(done(status=status)))

    def test_message_after_done_and_feed_after_complete(self):
        c = ip.DumpCollector('addresses', 10, 123)
        self.assertCode('message_after_done', lambda: c.feed(done() + done()))
        c = collector('addresses')
        self.assertCode('dump_already_complete', lambda: c.feed(done()))
        self.assertCode('incomplete_dump', c.records)

    def test_malformed_header_and_alignment(self):
        malformed = ((b'\0' * 15, 'truncated_header'),
                     (struct.pack('<IHHII', 15, 20, 2, 10, 123), 'invalid_message_length'),
                     (struct.pack('<IHHII', 40, 20, 2, 10, 123), 'invalid_message_length'),
                     (struct.pack('<IHHII', 17, 20, 2, 10, 123) + b'\0', 'invalid_message_length'),
                     (struct.pack('<IHHII', 17, 20, 2, 10, 123) + b'\0\1\0\0', 'invalid_padding'))
        for raw, code in malformed:
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode(code, lambda: c.feed(raw))

    def test_invalid_data_type_size(self):
        for raw in ('no', bytearray(done()), b'', b'\0' * (ip.MAX_DATAGRAM_BYTES + 1)):
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode('invalid_datagram', lambda: c.feed(raw))

    def test_datagram_and_byte_limits(self):
        c = ip.DumpCollector('addresses', 10, 123)
        c._datagrams = ip.MAX_DUMP_DATAGRAMS
        self.assertCode('dump_limit', lambda: c.feed(done()))
        c = ip.DumpCollector('addresses', 10, 123)
        c._bytes = ip.MAX_DUMP_BYTES
        self.assertCode('dump_limit', lambda: c.feed(done()))

    def test_record_limit(self):
        c = ip.DumpCollector('addresses', 10, 123)
        c._records = [None] * ip.MAX_DUMP_RECORDS
        self.assertCode('record_limit', lambda: c.feed(message(20, address_payload())))

    def test_datagram_validation_is_transactional(self):
        c = ip.DumpCollector('addresses', 10, 123)
        raw = message(20, address_payload()) + message(20, address_payload(extra=attr(99, b'bad')))
        self.assertCode('unknown_attribute', lambda: c.feed(raw))
        self.assertEqual(c._records, [])

    def test_exact_and_identity_duplicates_fail(self):
        for second in (address_payload(), address_payload(flags=1)):
            c = ip.DumpCollector('addresses', 10, 123)
            self.assertCode('duplicate_record', lambda: c.feed(message(20, address_payload()) + message(20, second)))

    def test_dump_error_ack(self):
        c = ip.DumpCollector('addresses', 10, 123)
        error = self.assertCode('kernel_error', lambda: c.feed(ack(c.request, 5)))
        self.assertEqual(error.errno, 5)
        c = ip.DumpCollector('addresses', 10, 123)
        self.assertCode('unexpected_dump_ack', lambda: c.feed(ack(c.request)))

    def test_random_bounded_bytes_never_escape_fixed_parser_errors(self):
        rng = random.Random(20261001)
        for kind in ('addresses', 'routes', 'rules'):
            for unused in range(200):
                raw = bytes(rng.randrange(256) for unused_byte in range(rng.randrange(1, 128)))
                c = ip.DumpCollector(kind, 10, 123)
                with self.assertRaises(ip.IpCoreError):
                    c.feed(raw)
                self.assertTrue(c.failed)

    def test_every_nonboundary_truncation_is_rejected(self):
        raw = message(20, address_payload()) + done()
        boundary = len(message(20, address_payload()))
        for length in range(1, len(raw)):
            if length == boundary:
                continue  # A complete data datagram without DONE is valid but incomplete.
            c = ip.DumpCollector('addresses', 10, 123)
            with self.assertRaises(ip.IpCoreError):
                c.feed(raw[:length])

    def test_duplicate_routes_and_rules_rejected(self):
        for kind, payload in (('routes', route_payload()), ('rules', rule_payload(0, 255))):
            self.assertCode('duplicate_record', lambda: collector(kind, [payload, payload]))


class AddressDecodeTests(CoreCase):
    def test_point_to_point_local_and_peer_retained(self):
        row = collector('addresses', [address_payload(local='10.9.1.2', peer='10.11.1.7', prefix=32)]).records()[0]
        self.assertNotEqual(row.local, row.address)
        self.assertEqual(row.prefixlen, 32)

    def test_missing_local_uses_address(self):
        p = struct.pack('<BBBBI', 2, 24, 128, 0, 2) + attr(1, address('10.1.1.2'))
        row = collector('addresses', [p]).records()[0]
        self.assertEqual(row.local, row.address)

    def test_u32_flags_supersede_header(self):
        p = struct.pack('<BBBBI', 2, 24, 0, 0, 2) + attr(1, address('10.1.1.2')) + attr(8, u32(128))
        self.assertEqual(collector('addresses', [p]).records()[0].flags, 128)

    def test_unknown_attributes_flags_duplicates(self):
        cases = ((attr(99, u32(0)), 'unknown_attribute'),
                 (attr(2, address('10.1.1.3')), 'duplicate_attribute'),
                 (attr(0x4004, address('10.1.1.255')), 'unsupported_attribute_flags'),
                 (attr(0x8004, address('10.1.1.255')), 'unsupported_attribute_flags'))
        for extra, code in cases:
            self.assertCode(code, lambda: collector('addresses', [address_payload(extra=extra)]))

    def test_bad_attr_size_length_padding(self):
        for extra, code in ((attr(4, b'\0'), 'invalid_attribute_size'),
                            (b'\0', 'truncated_attribute'),
                            (struct.pack('<HH', 3, 4), 'invalid_attribute_length'),
                            (struct.pack('<HH', 20, 4), 'invalid_attribute_length'),
                            (struct.pack('<HH', 5, 4) + b'\0\1\0\0', 'invalid_padding')):
            self.assertCode(code, lambda: collector('addresses', [address_payload(extra=extra)]))

    def test_bad_header_missing_address_unknown_scope_flags(self):
        for p, code in ((b'\0' * 7, 'truncated_address'),
                        (struct.pack('<BBBBI', 10, 24, 0, 0, 2), 'invalid_address_header'),
                        (address_payload(prefix=33), 'invalid_address_header'),
                        (address_payload(index=0), 'invalid_address_header'),
                        (address_payload(scope=50), 'unsupported_address_scope'),
                        (address_payload(flags=0x1000), 'unknown_address_flags'),
                        (struct.pack('<BBBBI', 2, 24, 0, 0, 2), 'missing_address')):
            self.assertCode(code, lambda: collector('addresses', [p]))

    def test_bad_label_and_cache(self):
        for label in (b'', b'no-null', b'x\0x\0', b'x' * 16 + b'\0'):
            self.assertCode('invalid_address_label', lambda: collector('addresses', [address_payload(label=label)]))
        for cache, code in ((b'\0' * 12, 'invalid_attribute_size'),
                            (struct.pack('<IIII', 20, 10, 0, 0), 'invalid_address_lifetime')):
            self.assertCode(code, lambda: collector('addresses', [address_payload(cache=False, extra=attr(6, cache))]))


class RouteDecodeTests(CoreCase):
    def test_all_table_and_default_retained(self):
        rows = collector('routes', [route_payload(table=700), route_payload(prefix=0, gateway='10.1.1.1', scope=0)]).records()
        self.assertEqual(rows[0].table, 700)
        self.assertEqual((rows[1].network, rows[1].prefixlen), (0, 0))
        self.assertNotIn('10.', repr(rows[0]))

    def test_metrics_known_u32_nested_and_plain(self):
        for key in (8, 0x8008):
            p = route_payload(extra=attr(key, attr(2, u32(1500)) + attr(8, u32(1400))))
            self.assertEqual(collector('routes', [p]).records()[0].metrics, ((2, 1500), (8, 1400)))

    def test_complex_unknown_routes_fail_closed(self):
        for extra, code in ((attr(9, b'\0' * 8), 'unknown_attribute'),
                            (attr(16, u32(42)), 'unknown_attribute'),
                            (attr(8, attr(16, b'cubic\0')), 'unknown_attribute'),
                            (attr(8, attr(2, u32(1)) + attr(2, u32(2))), 'duplicate_attribute')):
            self.assertCode(code, lambda: collector('routes', [route_payload(extra=extra)]))

    def test_route_strategy_and_canonical_prefix(self):
        for p, code in ((route_payload(source_prefix=8), 'unsupported_route'),
                        (route_payload(tos=4), 'unsupported_route'),
                        (route_payload(kind=6), 'unsupported_route'),
                        (route_payload(flags=0x100), 'unsupported_route'),
                        (route_payload(scope=50), 'unsupported_route'),
                        (route_payload(network='10.1.1.7'), 'noncanonical_route'),
                        (route_payload(oif=0), 'invalid_route_interface')):
            self.assertCode(code, lambda: collector('routes', [p]))

    def test_route_header_destination_table(self):
        p = route_payload()
        for bad, code in ((b'\0' * 11, 'truncated_route'),
                          (bytes([10]) + p[1:], 'invalid_route_header'),
                          (p[:1] + bytes([33]) + p[2:], 'invalid_route_header'),
                          (p[:12] + attr(15, u32(254)), 'missing_route_destination'),
                          (p[:4] + b'\xff' + p[5:], 'invalid_route_table'),
                          (route_payload(table=0), 'invalid_route_table')):
            self.assertCode(code, lambda: collector('routes', [bad]))


class RuleAndSnapshotTests(CoreCase):
    def test_exact_three_default_rules(self):
        snap = snapshot()
        ip.require_default_rules(snap)
        self.assertEqual(snap.rules, tuple(ip.RuleRecord(*r) for r in DEFAULT_RULES))
        self.assertNotIn('10.', repr(snap))
        with self.assertRaises(AttributeError):
            snap.rules = ()

    def test_nondefault_count_priority_table_rejected(self):
        for rules in ((), DEFAULT_RULES[:2], DEFAULT_RULES + ((40, 700),),
                      ((0, 255), (32765, 254), (32767, 253)),
                      ((0, 255), (32766, 200), (32767, 253))):
            self.assertCode('nondefault_policy', lambda: ip.select_subnet(snapshot(rules=rules), ['10.20.1.0/24']))

    def test_disabled_suppress_attributes_supported(self):
        p = rule_payload(0, 255, extra=attr(13, u32(0xffffffff)))
        self.assertEqual(collector('rules', [p]).records(), (ip.RuleRecord(0, 255),))

    def test_policy_selectors_and_unknown_attrs_rejected(self):
        for p, code in ((rule_payload(0, 255, flags=1), 'unsupported_policy'),
                        (rule_payload(0, 255, action=2), 'unsupported_policy'),
                        (rule_payload(0, 255, src_len=8), 'unsupported_policy'),
                        (rule_payload(0, 255, suppress=0), 'unsupported_policy'),
                        (rule_payload(0, 255, extra=attr(13, u32(0))), 'unsupported_policy'),
                        (rule_payload(0, 255, extra=attr(10, u32(1))), 'unknown_attribute'),
                        (rule_payload(0, 255, extra=attr(21, b'\x02')), 'unknown_attribute')):
            self.assertCode(code, lambda: collector('rules', [p]))

    def test_rule_header_reserved_and_sizes(self):
        p = rule_payload(0, 255)
        for bad, code in ((b'\0' * 11, 'truncated_rule'),
                          (p[:5] + b'\1' + p[6:], 'unsupported_policy'),
                          (p[:4] + b'\1' + p[5:], 'invalid_rule_table'),
                          (p + attr(6, b'\0'), 'invalid_attribute_size')):
            self.assertCode(code, lambda: collector('rules', [bad]))

    def test_snapshot_requires_complete_order_and_port(self):
        a, r, u = collector('addresses', sequence=10), collector('routes', sequence=11), collector('rules', sequence=12)
        self.assertCode('invalid_snapshot', lambda: ip.snapshot_from_dumps(r, a, u))
        self.assertCode('invalid_snapshot', lambda: ip.snapshot_from_dumps(None, r, u))
        self.assertCode('snapshot_dump_identity', lambda: ip.snapshot_from_dumps(a, r, collector('rules', sequence=12, port=999)))
        self.assertCode('incomplete_dump', lambda: ip.snapshot_from_dumps(ip.DumpCollector('addresses', 10, 123), r, u))

    def test_completed_sequential_dumps_can_reuse_sequence(self):
        snap = ip.snapshot_from_dumps(collector('addresses', sequence=10),
                                      collector('routes', sequence=10),
                                      collector('rules', [rule_payload(*r) for r in DEFAULT_RULES], sequence=10))
        ip.require_default_rules(snap)

    def test_structural_key_preserves_fields_ignores_cache_clock(self):
        p = address_payload(cache=False)
        one = snapshot(addresses=[p + attr(6, struct.pack('<IIII', 30, 60, 1, 2))])
        two = snapshot(addresses=[p + attr(6, struct.pack('<IIII', 20, 50, 1, 9))])
        self.assertEqual(one.structural_key(), two.structural_key())
        self.assertNotEqual(one.addresses, two.addresses)
        self.assertNotEqual(snapshot(addresses=[address_payload(flags=1)]).structural_key(), one.structural_key())

    def test_dump_record_order_does_not_change_structural_key(self):
        addr = [address_payload(index=2), address_payload(local='10.2.1.2', index=3)]
        routes = [route_payload(), route_payload(network='10.2.1.0', oif=3)]
        one = snapshot(addr, routes, DEFAULT_RULES)
        two = snapshot(list(reversed(addr)), list(reversed(routes)), tuple(reversed(DEFAULT_RULES)))
        self.assertEqual(one.structural_key(), two.structural_key())


class ConflictTests(CoreCase):
    def test_default_route_does_not_block_all_private_candidates(self):
        snap = snapshot(addresses=[address_payload()], routes=[route_payload(prefix=0, gateway='10.1.1.1', scope=0)])
        choice = ip.select_subnet(snap, ['10.20.1.0/24'])
        self.assertEqual(choice, (ip.ipv4_number('10.20.1.0'), 24))
        self.assertFalse(hasattr(choice, 'gateway'))
        self.assertFalse(hasattr(choice, 'local_ip'))
        self.assertNotIn('10.', repr(choice))

    def test_existing_address_subnet_overlap(self):
        snap = snapshot(addresses=[address_payload(local='10.20.7.8', prefix=16)])
        choice = ip.select_subnet(snap, ['10.20.1.0/24', '10.21.1.0/24'])
        self.assertEqual(choice.network, ip.ipv4_number('10.21.1.0'))

    def test_specific_routes_in_inactive_tables_block(self):
        snap = snapshot(routes=[route_payload(network='10.20.0.0', prefix=16, table=700)])
        choice = ip.select_subnet(snap, ['10.20.1.0/24', '10.21.1.0/24'])
        self.assertEqual(choice.network, ip.ipv4_number('10.21.1.0'))

    def test_local_host_route_blocks_enclosing_candidate(self):
        snap = snapshot(routes=[route_payload(network='10.20.1.7', prefix=32, table=255, kind=2, scope=254)])
        self.assertCode('no_available_subnet', lambda: ip.select_subnet(snap, ['10.20.1.0/24']))

    def test_point_to_point_peer_also_blocks(self):
        snap = snapshot(addresses=[address_payload(local='10.1.1.2', prefix=32, peer='10.20.1.7')])
        self.assertCode('no_available_subnet', lambda: ip.select_subnet(snap, ['10.20.1.0/24']))

    def test_gateway_and_prefsrc_endpoints_block_even_on_default_route(self):
        for gateway, prefsrc in (('10.20.1.7', None), (None, '10.20.1.8')):
            snap = snapshot(routes=[route_payload(prefix=0, gateway=gateway, prefsrc=prefsrc, scope=0)])
            self.assertCode('no_available_subnet', lambda: ip.select_subnet(snap, ['10.20.1.0/24']))

    def test_boundary_adjacent_subnets_do_not_overlap(self):
        snap = snapshot(routes=[route_payload(network='192.168.10.0')])
        choice = ip.select_subnet(snap, ['192.168.11.0/24'])
        self.assertEqual(choice.network, ip.ipv4_number('192.168.11.0'))

    def test_candidate_validation_and_limits(self):
        for candidates in ((), '10.20.1.0/24', ['10.20.1.0/24'] * 33):
            self.assertCode('invalid_candidates', lambda: ip.select_subnet(snapshot(), candidates))
        for candidate in ('10.20.1.7/24', '10.20.0.0/16', '10.20.1.0/024', '8.8.8.0/24',
                          '172.32.1.0/24', '169.254.1.0/24', '10.20.1.0', '10.20.1.0/24/24'):
            self.assertCode('invalid_candidate', lambda: ip.select_subnet(snapshot(), [candidate]))
        self.assertCode('invalid_candidate', lambda: ip.select_subnet(snapshot(), ['10.20.1.0/24'] * 2))

    def test_rfc1918_edges_and_all_candidates_exhausted(self):
        for candidate in ('10.0.0.0/24', '172.16.0.0/24', '172.31.255.0/24', '192.168.0.0/24'):
            self.assertEqual(ip.select_subnet(snapshot(), [candidate]).prefixlen, 24)
        snap = snapshot(routes=[route_payload(network='10.20.0.0', prefix=16)])
        self.assertCode('no_available_subnet', lambda: ip.select_subnet(snap, ['10.20.1.0/24', '10.20.2.0/24']))


class AddressEncodeAndAckTests(CoreCase):
    def setUp(self):
        self.spec = ip.AddressSpec(7, '10.20.1.8', 24)

    def test_explicit_address_new_create_excl_and_exact_delete(self):
        new = ip.encode_new_address(self.spec, 30, 123)
        delete = ip.encode_del_address(self.spec, 31, 123)
        self.assertEqual(struct.unpack_from('<IHHII', new), (48, 20, 0x605, 30, 123))
        self.assertEqual(struct.unpack_from('<IHHII', delete), (48, 21, 5, 31, 123))
        self.assertEqual(new[16:], delete[16:])
        self.assertEqual(new[16:24], struct.pack('<BBBBI', 2, 24, 128, 0, 7))
        self.assertEqual(new[24:], attr(1, address('10.20.1.8')) + attr(2, address('10.20.1.8')) + attr(4, address('10.20.1.255')))
        self.assertNotIn('10.', repr(self.spec))

    def test_address_spec_is_private_explicit_host(self):
        for index, text, prefix in ((0, '10.20.1.8', 24), (True, '10.20.1.8', 24),
                                    (7, '8.8.8.8', 24), (7, '10.20.1.0', 24), (7, '10.20.1.255', 24),
                                    (7, '10.20.1.8', 32), (7, '10.20.1.8', True)):
            with self.assertRaises(ip.IpCoreError):
                ip.AddressSpec(index, text, prefix)
        self.assertCode('invalid_address_spec', lambda: ip.encode_new_address((7, 1, 24), 30, 123))
        forged = ip.AddressSpec._make((7, ip.ipv4_number('8.8.8.8'), 24))
        self.assertCode('invalid_address_spec', lambda: ip.encode_new_address(forged, 30, 123))

    def test_canonical_ipv4_only(self):
        for text in ('01.2.3.4', '1.2.3', '1.2.3.256', ' 1.2.3.4', '1.2.3.4\n', '1.2.-1.4', '１.2.3.4', 123):
            self.assertCode('invalid_ipv4', lambda: ip.ipv4_number(text))
        for text in ('0.0.0.0', '255.255.255.255', '192.168.1.2'):
            self.assertEqual(ip.ipv4_text(ip.ipv4_number(text)), text)

    def test_success_ack_and_numeric_error_full_or_capped(self):
        request = ip.encode_new_address(self.spec, 30, 123)
        for flags in (0, 0x100):
            self.assertTrue(ip.decode_ack(ack(request, flags=flags), request).success)
            result = ip.decode_ack(ack(request, 17, flags), request)
            self.assertEqual((result.errno, result.command, result.success), (17, 20, False))

    def test_wrong_ack_sequence_port_kind_count(self):
        request = ip.encode_new_address(self.spec, 30, 123)
        for raw, code in ((ack(request, sequence=31), 'ack_identity_mismatch'),
                          (ack(request, port=456), 'ack_identity_mismatch'),
                          (done(sequence=30), 'ack_identity_mismatch'),
                          (ack(request) + ack(request), 'ack_message_count')):
            self.assertCode(code, lambda: ip.decode_ack(raw, request))

    def test_embedded_header_and_body_must_match_exactly(self):
        request = ip.encode_new_address(self.spec, 30, 123)
        changed_header = request[:4] + b'\x15' + request[5:16]
        self.assertCode('ack_request_mismatch', lambda: ip.decode_ack(ack(request, echo=changed_header), request))
        changed_body = request[:-1] + b'\1'
        self.assertCode('ack_request_mismatch', lambda: ip.decode_ack(ack(request, 5, echo=changed_body), request))

    def test_truncated_ack_unexpected_tlvs_or_extra_body(self):
        request = ip.encode_new_address(self.spec, 30, 123)
        for raw, code in ((message(2, b'\0' * 19, flags=0, sequence=30), 'truncated_ack'),
                          (ack(request, flags=0x200), 'unsupported_ack_flags'),
                          (ack(request, echo=request[:16] + b'\0' * 4), 'invalid_ack_length')):
            self.assertCode(code, lambda: ip.decode_ack(raw, request))

    def test_invalid_errno_and_request_flags(self):
        request = ip.encode_new_address(self.spec, 30, 123)
        for errno in (-1, 4096):
            self.assertCode('invalid_kernel_errno', lambda: ip.decode_ack(ack(request, errno), request))
        wrong = request[:6] + b'\x05\x01' + request[8:]
        self.assertCode('invalid_request', lambda: ip.decode_ack(ack(wrong), wrong))

    def test_no_socket_or_execution_or_journal_api(self):
        tree = ast.parse((PROJECT / 'runtime' / 'mta_ip.py').read_text(encoding='utf-8'), feature_version=(3, 5))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertEqual(imported, {'struct', 'collections'})
        self.assertFalse(hasattr(ip, 'available'))
        self.assertFalse(hasattr(ip, 'socket'))


class ExistingPrivateFixtureTests(CoreCase):
    def test_saved_p011_readonly_dumps_offline_only(self):
        # Do not package this private fixture or print records, labels or IPs.
        # This tests a historical byte sample, not current device state.
        override = os.environ.get('MTA_IP_PRIVATE_FIXTURE')
        path = pathlib.Path(override) if override else PROJECT.parents[1] / 'logs' / \
            'MtaP011-IpDumpReadOnly-20261001-032317-adba0ac0' / 'private-raw' / \
            '02-ipv4-dumps-readonly.stdout.raw'
        if not path.is_file():
            self.skipTest('historical private fixture not present')
        text = path.read_text(encoding='utf-8')
        self.assertLessEqual(len(text), 1024 * 1024)
        rows = [line for line in text.splitlines() if line.startswith('RESULT={')]
        self.assertEqual(len(rows), 1)
        data = ast.literal_eval(rows[0][7:])
        self.assertTrue(data['collections_imported'])
        self.assertFalse(data['network_configuration'])
        dumps = {}
        names = {22: 'addresses', 26: 'routes', 34: 'rules'}
        for item in data['raw_dump_records']:
            request = item['request']
            unused_len, command, unused_flags, sequence, unused_port = struct.unpack_from('<IHHII', request)
            self.assertEqual(command, item['kind'])
            # A fixture header can supply correlation IDs, not kernel authority.
            port = struct.unpack_from('<IHHII', item['packets'][0])[4]
            c = ip.DumpCollector(names[command], sequence, port)
            for packet in item['packets']:
                c.feed(packet)
            self.assertTrue(c.complete)
            dumps[names[command]] = c
        snap = ip.snapshot_from_dumps(dumps['addresses'], dumps['routes'], dumps['rules'])
        ip.require_default_rules(snap)
        self.assertEqual((len(snap.addresses), len(snap.routes), len(snap.rules)), (2, 9, 3))
        self.assertNotIn('label', repr(snap))


if __name__ == '__main__':
    unittest.main()
