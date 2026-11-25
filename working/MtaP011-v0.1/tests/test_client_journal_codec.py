"""Synthetic private records only; no Store/disk/network/OS ownership proof."""
import ast
import builtins
import copy
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
import mta_client_journal_codec as codec
import mta_p2p_client_init as core
import mta_ip as ip
import p011_json as json

BOOT = '12345678-1234-1234-1234-123456789abc'
IDENTITY = core.Identity('a' * 64)
STATION = core.Origin(0, 1, 22, 'wlan0', 2)
OWNED = core.Origin(0, (1 << 63) + 2, 23, 'mta1234abcd', 8)
RULES = (ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254), ip.RuleRecord(32767, 253))


def actor(pid, exe, digest, tasks=None):
    return core.Actor(pid, 100, exe, digest, tasks or ((pid, 100, 'S'),))


def baseline(ipv4=None, ipv6_addresses=None):
    actors = (actor(11, '/usr/bin/Z03', 'b' * 64, ((11, 100, 'R'), (111, 101, 'D'))),
        actor(12, '/usr/bin/control_engine', 'c' * 64), actor(13, '/usr/bin/weston', 'd' * 64),
        actor(14, '/private/学习/café/😀', 'e' * 64, ((14, 100, 'I'),)))
    if ipv4 is None:
        ipv4 = ip.IpSnapshot((ip.AddressRecord(22, 0xc0a80102, 0xc0a80102, 24, 0x80, 0,
            b'wlan0\x00', 0xc0a801ff, (0xffffffff, 0xffffffff, 123, 456)),
            ip.AddressRecord(1, 0x7f000001, 0x7f000001, 8, 0x80, 254, None, None,
                (0xffffffff, 0xffffffff, 1, 2))),
            (ip.RouteRecord(0, 0, 254, 3, 0, 1, 0, 22, 0xc0a80101, 600, 0xc0a80102, ((2, 1500), (3, 0))),
             ip.RouteRecord(0xc0a80102, 32, 255, 2, 254, 2, 0, 22, None, None, None, ())), RULES)
    if ipv6_addresses is None:
        ipv6_addresses = (('fe80' + '0' * 28, '16', '40', '20', '80', 'wlan0'),)
    routes = (('ff' + '0' * 30, '08', '0' * 32, '00', '0' * 32,
        '00000100', '00000001', '00000000', '00000001', 'wlan0'),)
    return core.Snapshot(BOOT, core.STOCK_PINS, actors, STATION, 'f' * 64, 2412,
        (STATION, core.Origin(1, 0xffffffffffffffff, 31, 'aux0', 10)), ipv4, ipv6_addresses, routes, True)


def record(stage='client_init_ready', snapshot=None):
    base = snapshot or baseline()
    if stage in ('new', 'prepared'):
        return core.Journal(IDENTITY, stage, base, 30.25)
    watchdog_ticket = core.Ticket('1' * 32, 'watchdog', BOOT, '/usr/bin/python3.5', 'b' * 64)
    watchdog = actor(201, watchdog_ticket.exe, watchdog_ticket.argv_sha, ((201, 100, 'T'), (211, 102, 't')))
    interface_ticket = core.InterfaceTicket(BOOT, 0, OWNED.name, 0xffffffff, 0xffffffff)
    controller_ticket = core.Ticket('2' * 32, 'controller', BOOT, '/private/client-wpa', 'c' * 64)
    controller = actor(202, controller_ticket.exe, controller_ticket.argv_sha, ((202, 100, 'S'), (212, 103, 'Z')))
    return core.Journal(IDENTITY, stage, base, 30.25, OWNED, controller_ticket,
        controller, watchdog_ticket, watchdog, stage == 'client_init_ready', interface_ticket)


def wire(document):
    return json.dumps(document, ensure_ascii=True, sort_keys=True).encode('ascii')


def descend(document, path):
    for key in path: document = document[key]
    return document


class JournalCodecTests(unittest.TestCase):
    def setUp(self):
        self.record = record(); self.data = codec.encode_journal(self.record)
        self.document = json.loads(self.data.decode('ascii'))

    def reject(self, data, code=None):
        with self.assertRaises(codec.JournalCodecError) as caught: codec.decode_journal(data)
        error = caught.exception
        self.assertIn(error.code, codec._CODES); self.assertEqual(str(error), error.code)
        if code is not None: self.assertEqual(error.code, code)
        for private in (BOOT, 'wlan0', 'mta1234abcd', '/private/', 'c0a8', 'argv_sha', '学习'):
            self.assertNotIn(private, repr(error))

    def changed(self, path, key, value):
        document = copy.deepcopy(self.document); descend(document, path)[key] = value
        return wire(document)

    def test_complete_record_roundtrip_all_types_and_full_private_values(self):
        rebuilt = codec.decode_journal(self.data)
        self.assertIs(type(rebuilt), core.Journal); self.assertIs(type(rebuilt.identity), core.Identity)
        self.assertIs(type(rebuilt.baseline), core.Snapshot); self.assertIs(type(rebuilt.owned), core.Origin)
        self.assertIs(type(rebuilt.interface_ticket), core.InterfaceTicket)
        self.assertIs(type(rebuilt.controller_ticket), core.Ticket); self.assertIs(type(rebuilt.controller), core.Actor)
        self.assertIs(type(rebuilt.baseline.ipv4), ip.IpSnapshot)
        self.assertEqual(rebuilt.controller.tasks, self.record.controller.tasks) # Includes Z, not only Actor.key().
        self.assertEqual(rebuilt.watchdog.tasks, self.record.watchdog.tasks)
        self.assertEqual(rebuilt.baseline.stock_actors[0].tasks, self.record.baseline.stock_actors[0].tasks)
        self.assertEqual(rebuilt.baseline.ipv4, self.record.baseline.ipv4)
        self.assertIs(type(rebuilt.baseline.ipv4.addresses[0]), ip.AddressRecord)
        self.assertIs(type(rebuilt.baseline.ipv4.routes[0]), ip.RouteRecord)
        self.assertIs(type(rebuilt.baseline.ipv4.rules[0]), ip.RuleRecord)
        self.assertIs(type(rebuilt.baseline.ipv4.addresses[0].label), bytes)
        self.assertIs(type(rebuilt.baseline.ipv4.addresses[0].cacheinfo), tuple)
        self.assertEqual(rebuilt.baseline.ipv6_addresses, self.record.baseline.ipv6_addresses)
        self.assertEqual(rebuilt.baseline.ipv6_routes, self.record.baseline.ipv6_routes)
        self.assertEqual(rebuilt.deadline, self.record.deadline); self.assertIs(type(rebuilt.deadline), float)
        self.assertEqual(codec.encode_journal(rebuilt), self.data)
        self.assertTrue(all(byte < 128 for byte in self.data)); self.assertLess(len(self.data), codec.MAX_BYTES)
        self.assertEqual('<CLIENT RF-init private record>', repr(rebuilt))

    def test_null_fields_and_array_order_survive_without_defaults(self):
        for stage in ('new', 'prepared'):
            value = codec.decode_journal(codec.encode_journal(record(stage)))
            self.assertFalse(value.ready)
            for key in ('owned', 'interface_ticket', 'controller_ticket', 'controller', 'watchdog_ticket', 'watchdog'):
                self.assertIsNone(getattr(value, key))
        value = codec.decode_journal(self.data).baseline.ipv4
        self.assertIsNone(value.addresses[1].label); self.assertIsNone(value.addresses[1].broadcast)
        self.assertIsNone(value.routes[1].gateway); self.assertIsNone(value.routes[1].priority)
        self.assertIsNone(value.routes[1].prefsrc); self.assertEqual(value.rules, RULES)

    def test_all_schema_maps_reject_each_missing_or_extra_field(self):
        paths = ((), ('journal',), ('journal', 'identity'), ('journal', 'owned'), ('journal', 'interface_ticket'),
            ('journal', 'controller_ticket'), ('journal', 'controller'), ('journal', 'baseline'),
            ('journal', 'baseline', 'stock_hashes', 0), ('journal', 'baseline', 'stock_actors', 0),
            ('journal', 'baseline', 'station'), ('journal', 'baseline', 'ipv4'),
            ('journal', 'baseline', 'ipv4', 'addresses', 0), ('journal', 'baseline', 'ipv4', 'routes', 0),
            ('journal', 'baseline', 'ipv4', 'rules', 0))
        for path in paths:
            for key in tuple(descend(self.document, path)):
                with self.subTest(path=path, key=key):
                    value = copy.deepcopy(self.document); del descend(value, path)[key]
                    self.reject(wire(value), 'invalid_schema')
            value = copy.deepcopy(self.document); descend(value, path)['future'] = None
            self.reject(wire(value), 'invalid_schema')

    def test_envelope_fixed_version_kind_marker_no_go_migration(self):
        for key, value in (('version', 3), ('version', True), ('kind', 'go_ip_only'),
                ('marker', 'p011-go-ip-v1'), ('version', 4.0)):
            self.reject(self.changed((), key, value), 'unsupported_envelope')
        self.reject(wire({'version': 3, 'kind': 'go_ip_only', 'receipt': {}}), 'invalid_schema')
        for key in ('wpa_sha', 'ctrl_sha'):
            self.reject(self.changed(('journal', 'identity'), key, '0' * 64), 'unsupported_envelope')

    def test_no_class_tags_complete_or_dynamic_object_forms(self):
        for key in ('__class__', '__module__', 'complete', 'pickle', 'restore_authorized'):
            value = copy.deepcopy(self.document); value['journal'][key] = 'os.system'
            self.reject(wire(value), 'invalid_schema')
        self.reject(self.changed((), 'journal', ['core.Journal', self.document['journal']]), 'invalid_schema')

    def test_duplicate_keys_nested_or_envelope_rejected_by_bundled_parser(self):
        self.reject(self.data.replace(b'"version": 4', b'"version": 4, "version": 4', 1), 'invalid_json')
        self.reject(self.data.replace(b'"ready": true', b'"ready": true, "ready": true', 1), 'invalid_json')
        self.reject(self.data.replace(b'"candidate_sha": ', b'"candidate_sha": null, "candidate_sha": ', 1), 'invalid_json')

    def test_noncanonical_whitespace_order_escape_and_number_rejected(self):
        variants = (self.data + b'\n', b' ' + self.data, self.data.replace(b': ', b':'),
            self.data.replace(b'30.25', b'3.025e1'), self.data.replace(b'/usr/', b'\\/usr/', 1),
            self.data.replace(b'"priority": 0', b'"priority": -0', 1),
            json.dumps(self.document, ensure_ascii=False, sort_keys=True).encode('utf-8'),
            json.dumps(dict((key, self.document[key]) for key in reversed(sorted(self.document))), sort_keys=False).encode('ascii'))
        for value in variants:
            with self.subTest(size=len(value)): self.reject(value, 'noncanonical')

    def test_invalid_utf8_bom_trailing_garbage_and_json_extensions(self):
        for value in (b'\xff' + self.data, b'\xef\xbb\xbf' + self.data, self.data + b'null', b'{', b'[]', b'null', b'"x"'):
            self.reject(value)
        for value in (b'NaN', b'Infinity', b'-Infinity', b'1e999'):
            self.reject(self.data.replace(b'30.25', value), 'invalid_json')
        self.reject(self.data.replace(b'"stage": "client_init_ready"', b'"stage": "\\ud800"'), 'invalid_json')

    def test_input_type_and_size_no_subclass_or_mutable_buffer(self):
        class ByteSubclass(bytes): pass
        for value in (None, '', self.data.decode('ascii'), bytearray(self.data), memoryview(self.data), ByteSubclass(self.data), b''):
            self.reject(value, 'invalid_input')
        self.reject(b'x' * (codec.MAX_BYTES + 1), 'byte_budget')
        with self.assertRaises(codec.JournalCodecError): codec.encode_journal(object())

    def test_integer_types_and_bounds_at_all_numeric_families(self):
        fields = ((('journal', 'owned'), 'wdev', (True, 0, -1, 1 << 64, 1.0)),
            (('journal', 'owned'), 'ifindex', (True, 0, 1 << 31)),
            (('journal', 'owned'), 'iftype', (0, 13, True)),
            (('journal', 'controller'), 'pid', (0, True, 1 << 31)),
            (('journal', 'controller'), 'start', (0, True, 1 << 64)),
            (('journal', 'interface_ticket'), 'sequence', (0, True, 1 << 32)),
            (('journal', 'interface_ticket'), 'port_id', (0, True, 1 << 32)),
            (('journal', 'baseline'), 'station_frequency', (True, 2411, 2485)),
            (('journal', 'baseline', 'ipv4', 'addresses', 0), 'prefixlen', (True, -1, 33)),
            (('journal', 'baseline', 'ipv4', 'addresses', 0), 'local', (True, 1 << 32)),
            (('journal', 'baseline', 'ipv4', 'routes', 0), 'table', (0, True, 1 << 32)),
            (('journal', 'baseline', 'ipv4', 'routes', 0), 'protocol', (True, 256)),
            (('journal', 'baseline', 'ipv4', 'routes', 0), 'oif', (0, True, 1 << 31)),
            (('journal', 'baseline', 'ipv4', 'rules', 0), 'priority', (True, 1 << 32)))
        for path, key, values in fields:
            for value in values:
                with self.subTest(path=path, key=key, value=value): self.reject(self.changed(path, key, value))

    def test_float_deadline_bool_ready_and_completed_are_strict(self):
        for value in (30, True, -1.0, 1e12, None, '30.25'):
            self.reject(self.changed(('journal',), 'deadline', value))
        for path, key in ((('journal',), 'ready'), (('journal', 'baseline'), 'station_completed')):
            for value in (1, 0, 'true', None): self.reject(self.changed(path, key, value))
        self.reject(self.changed(('journal', 'baseline'), 'station_completed', False))

    def test_hash_path_boot_role_and_ticket_core_revalidation(self):
        for path, key, value in ((('journal', 'identity'), 'candidate_sha', 'A' * 64),
                (('journal', 'controller'), 'argv_sha', 'secret'),
                (('journal', 'controller'), 'exe', '/private/../client'),
                (('journal', 'controller_ticket'), 'role', 'sender'),
                (('journal', 'controller_ticket'), 'token', '1' * 31),
                (('journal', 'interface_ticket'), 'boot', '0' * 36),
                (('journal', 'interface_ticket'), 'name', 'wlan0'),
                (('journal', 'owned'), 'iftype', 9),
                (('journal', 'watchdog'), 'argv_sha', 'd' * 64)):
            self.reject(self.changed(path, key, value))

    def test_label_lowercase_hex_nullable_and_core_byte_invariants(self):
        path = ('journal', 'baseline', 'ipv4', 'addresses', 0)
        self.assertEqual('776c616e3000', descend(self.document, path)['label_hex'])
        for value in ('776C616e3000', '', '0', 'xx', '61006200', '6162', 'aa' * 17, 123, {'hex': '6100'}):
            self.reject(self.changed(path, 'label_hex', value))
        valid = codec.decode_journal(self.changed(path, 'label_hex', None))
        self.assertIsNone(valid.baseline.ipv4.addresses[0].label)

    def test_ip_cache_metrics_and_rules_preserve_types_and_reject_bad_rows(self):
        paths = (('journal', 'baseline', 'ipv4', 'addresses', 0), ('journal', 'baseline', 'ipv4', 'routes', 0))
        for value in ([], [0xffffffff] * 3, [0xffffffff, 0xffffffff, True, 1], [1, 0xffffffff, 1, 2]):
            self.reject(self.changed(paths[0], 'cacheinfo', value))
        for value in ([[2, True]], [[2]], [[0, 1]], [[2, 1], [2, 1]], [[16, 1]], None):
            self.reject(self.changed(paths[1], 'metrics', value))
        for key, value in (('scope', 1), ('flags', 0), ('label_hex', '776c616e30')):
            self.reject(self.changed(paths[0], key, value))
        self.reject(self.changed(('journal', 'baseline', 'ipv4'), 'rules', []))

    def test_actor_tasks_full_state_and_duplicate_identity_validation(self):
        path = ('journal', 'controller'); original = descend(self.document, path)['tasks']
        for value in ([], [original[0], original[0]], [[202, 100]], [[202, True, 'S']], [[202, 100, 'Q']], [[999, 100, 'S']]):
            self.reject(self.changed(path, 'tasks', value))
        for state in ('R', 'S', 'D', 'T', 't', 'Z', 'X', 'I'):
            tasks = [[202, 100, state], [212, 103, 'Z']]
            value = codec.decode_journal(self.changed(path, 'tasks', tasks))
            self.assertEqual(tuple(tuple(row) for row in tasks), value.controller.tasks)

    def test_stage_and_record_cross_reference_checks_not_just_json_shape(self):
        for key, value in (('stage', 'go_ready'), ('stage', 'prepared'), ('ready', False), ('controller', None), ('watchdog', None)):
            self.reject(self.changed(('journal',), key, value))
        self.reject(self.changed(('journal', 'controller_ticket'), 'boot', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'))
        self.reject(self.changed(('journal', 'owned'), 'name', 'mta00000000'))

    def test_collection_limits_and_nested_depth_budget(self):
        for path, key, value in ((('journal', 'controller'), 'tasks', [[202, 100, 'S']] * 129),
                (('journal', 'baseline'), 'interfaces', [self.document['journal']['owned']] * 33),
                (('journal', 'baseline'), 'stock_actors', [self.document['journal']['controller']] * 33),
                (('journal', 'baseline'), 'stock_hashes', self.document['journal']['baseline']['stock_hashes'] * 6),
                (('journal', 'baseline', 'ipv4'), 'addresses', [0] * 4097)):
            self.reject(self.changed(path, key, value))
        self.reject(b'[' * 26 + b'0' + b']' * 26, 'invalid_json')

    def test_global_encode_node_and_escaped_byte_budget_are_prechecked(self):
        rows = tuple((str(n), '16', '40', '20', '80', 'wlan0') for n in range(2000))
        with self.assertRaises(codec.JournalCodecError) as caught:
            codec.encode_journal(record('prepared', baseline(ipv6_addresses=rows)))
        self.assertEqual('structure_budget', caught.exception.code)
        rows = tuple((str(n), '😀' * 256, '40', '20', '80', 'wlan0') for n in range(100))
        with self.assertRaises(codec.JournalCodecError) as caught:
            codec.encode_journal(record('prepared', baseline(ipv6_addresses=rows)))
        self.assertEqual('byte_budget', caught.exception.code)

    def test_noncanonical_normalized_stock_pin_order_rejected(self):
        value = copy.deepcopy(self.document); value['journal']['baseline']['stock_hashes'].reverse()
        self.reject(wire(value), 'noncanonical')

    def test_exact_core_class_required_and_object_corruption_cannot_escape(self):
        class Derived(core.Journal): pass
        with self.assertRaises(codec.JournalCodecError): codec.encode_journal(Derived(IDENTITY, 'prepared', baseline(), 30))
        value = record('prepared'); object.__setattr__(value, 'deadline', True)
        with self.assertRaises(codec.JournalCodecError): codec.encode_journal(value)
        value = record(); object.__setattr__(value.controller, 'exe', 'SECRET\ud800PATH')
        with self.assertRaises(codec.JournalCodecError) as caught: codec.encode_journal(value)
        self.assertNotIn('SECRET', repr(caught.exception))

    def test_decode_fresh_immutable_objects_not_shared_state_or_provider(self):
        first = codec.decode_journal(self.data); second = codec.decode_journal(self.data)
        self.assertIsNot(first, second); self.assertIsNot(first.baseline, second.baseline)
        self.assertIsNot(first.controller, second.controller)
        with self.assertRaises(AttributeError): first.stage = 'reconciled'
        self.assertEqual(self.data, codec.encode_journal(second))
        self.assertNotIn(b'"complete":', self.data); self.assertNotIn(b'"store":', self.data)

    def test_public_failure_suppresses_private_parser_or_core_exception_chain(self):
        for value in (b'\xffSECRET_PRIVATE_PATH', self.changed(('journal', 'controller'), 'exe', '/SECRET/../PRIVATE'),
                self.data.replace(b'"version": 4', b'"version": 4, "version": 4', 1)):
            with self.assertRaises(codec.JournalCodecError) as caught: codec.decode_journal(value)
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertIsNone(caught.exception.__cause__)
            self.assertNotIn('SECRET', repr(caught.exception)); self.assertEqual((caught.exception.code,), caught.exception.args)

    def test_python35_ast_pure_import_encode_decode_no_io_or_dynamic_calls(self):
        path = BASE / 'runtime/mta_client_journal_codec.py'; source = path.read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5)); compiled = compile(tree, str(path), 'exec')
        imports = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        self.assertEqual(['p011_json', 'mta_p2p_client_init', 'mta_ip'], imports)
        forbidden = {'eval', 'exec', 'open', 'pickle', '__import__', 'Popen', 'socket', 'flock', 'fsync'}
        calls = [node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ''
            for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(set(calls) & forbidden)
        with mock.patch.object(builtins, 'open', side_effect=AssertionError('HOST_IO')), \
                mock.patch.object(socket, 'socket', side_effect=AssertionError('HOST_SOCKET')), \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('HOST_POPEN')):
            namespace = {'__name__': 'HOST_PRIVATE_CODEC'}; exec(compiled, namespace)
            self.assertEqual(self.data, namespace['encode_journal'](namespace['decode_journal'](self.data)))


if __name__ == '__main__': unittest.main()
