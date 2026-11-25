"""One new HOST85 method: fixed Snapshot DATA codec, never a native receipt.

The complete pinned p011_json, IPv4 core, RO33 core and Snapshot codec execute
in a test-private definition/import domain. Fixtures construct actual pure
Actor/Origin/IpSnapshot/Snapshot DATA; their numbers are not device samples.
No prior TestCase/helper is imported. No Loader, Proc, native owner, lock,
Journal, RF, service, restoration, phone or production admission is exercised.
Each of eight affected domains forbids platform IO/clock/thread operations.
The checker, its isolated child and any one-click entry are ROOT's separate
work; this SOURCE was not executed by its author.
"""
import builtins
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import threading
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE_INPUTS = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 'runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'candidate/client-parent-cap-v33/runtime/mta_p2p_client_init.py', 71315,
     'd3b51493d3ae778aeb72c1304dc50e5a6221428f7775bc7a28d15a3f19abeaaa'),
    ('mta_snapshot_data', 'candidate/go-send-observer-v85/runtime/mta_snapshot_data.py', 17217,
     'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
)
MARKER = 'HOST85_SNAPSHOT_DATA new_methods=1 old_methods=0 cases=8 device=false phone=false\n'


def _definitions():
    # HOST input IO precedes the pure-case tripwires. These are actual complete
    # source bytes, not extracted methods or substituted codec/core classes.
    modules = {}
    ordinary = {'re': re, 'struct': struct, 'hashlib': hashlib,
                'collections': __import__('collections')}
    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name not in modules and name not in ordinary:
            raise AssertionError('unexpected pure definition import')
        return modules[name] if name in modules else ordinary[name]
    for name, path, size, pin in SOURCE_INPUTS:
        raw = (ROOT / path).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
            raise AssertionError('fixed HOST85 input changed: ' + path)
        module = types.ModuleType(name)
        module.__file__ = str(ROOT / path)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=fixed_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


@contextmanager
def _pure_domain():
    calls = []
    def forbidden(*unused, **ignored):
        calls.append('platform')
        raise AssertionError('HOST85 pure codec attempted platform IO')
    targets = ((builtins, 'open'), (os, 'open'), (os, 'read'), (os, 'write'),
        (os, 'close'), (os, 'stat'), (os, 'lstat'), (os, 'fstat'),
        (os, 'listdir'), (os, 'mkdir'), (os, 'getpid'), (os, 'urandom'),
        (socket, 'socket'), (subprocess, 'Popen'), (threading.Thread, 'start'),
        (time, 'monotonic'), (time, 'time'))
    with ExitStack() as stack:
        for owner, name in targets:
            stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
        yield calls
    if calls:
        raise AssertionError('HOST85 platform tripwire count was not zero')


def _snapshot(modules, state='S', reverse=False, addresses=None,
              v6_addresses=None, cache_tail=17):
    core, ip = modules['mta_p2p_client_init'], modules['mta_ip']
    actors = tuple(core.Actor(pid, start, exe, digit * 64,
        ((pid, start, state), (pid + 100, start + 100, state)))
        for pid, start, exe, digit in ((101, 1001, '/usr/bin/Z03', 'a'),
            (202, 2002, '/usr/bin/control_engine', 'b'),
            (303, 3003, '/usr/bin/weston', 'c')))
    station = core.Origin(0, 0x101, 3, 'wlan0', 2)
    other = core.Origin(0, 0x102, 5, 'eth0', 2)
    if addresses is None:
        labels = (b"a'b\x00", b'a"b\x00', b'\\x\x00', b'\t\r\n\xff\x00')
        addresses = tuple(ip.AddressRecord(3, local, local, 24, 0x80, 0,
            label, 0xc0a832ff, (0xffffffff, 0xffffffff, cache_tail, 19))
            for local, label in zip((9, 10, 11, 12), labels))
    routes = tuple(ip.RouteRecord(0, 0, 254, 2, 0, 1, 0, 3,
        0xc0a83201, priority, 0xc0a83209, ((2, 1500), (1, 64)))
        for priority in (9, 10))
    rules = (ip.RuleRecord(32767, 253), ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254))
    if v6_addresses is None:
        v6_addresses = tuple(('fe80000000000000000000000000000' + suffix,
            '03', '40', '20', '80', 'wlan0') for suffix in ('2', '1'))
    ra = ('0' * 32, '00', '0' * 32, '00', '0' * 32,
          '00000001', '00000000', '00000000', '00000001', 'wlan0')
    rb = ('fe80' + '0' * 28, '40', '0' * 32, '00', '0' * 32,
          '00000002', '00000000', '00000000', '00000001', 'wlan0')
    v6_routes = (ra, ra, rb)  # Actual core permits repeated IPv6 route rows.
    interfaces = (other, station)
    if reverse:
        actors, interfaces = actors[::-1], interfaces[::-1]
        addresses, routes, rules = addresses[::-1], routes[::-1], rules[::-1]
        v6_addresses, v6_routes = v6_addresses[::-1], v6_routes[::-1]
    return core.Snapshot('01234567-89ab-cdef-0123-456789abcdef',
        tuple(sorted(core.STOCK_PINS)), actors, station, 'd' * 64, 2412,
        interfaces, ip.IpSnapshot(addresses, routes, rules),
        v6_addresses, v6_routes, True)


def _fields(snapshot):
    # Independent explicit fixture expectation, not codec._fields/_stable_key.
    actors = tuple((a.pid, a.start, a.exe, a.argv_sha, a.tasks) for a in snapshot.stock_actors)
    origin = lambda o: (o.phy, o.wdev, o.ifindex, o.name, o.iftype)
    return (snapshot.boot, snapshot.stock_hashes, actors, origin(snapshot.station),
        snapshot.station_state_sha, snapshot.station_frequency,
        tuple(origin(o) for o in snapshot.interfaces),
        (tuple(tuple(r) for r in snapshot.ipv4.addresses),
         tuple(tuple(r) for r in snapshot.ipv4.routes), tuple(tuple(r) for r in snapshot.ipv4.rules)),
        snapshot.ipv6_addresses, snapshot.ipv6_routes, snapshot.station_completed)


def _key(snapshot):
    value = snapshot.key()  # The actual unchanged RO33 standard.
    return value[:7] + tuple(tuple(tuple(row) for row in rows) for rows in value[7:10]) + value[10:]


def _tag(value):
    # Pure test-wire builder, not a codec success, proof or constructor hook.
    if type(value) is tuple: return ['tuple', [_tag(item) for item in value]]
    if type(value) is bytes: return ['bytes', value.hex()]
    if value is None or type(value) in (bool, int, str): return value
    raise AssertionError('test wire builder accepts primitives only')


def _wire(modules, fields, key):
    return (modules['p011_json'].dumps(['p011-snapshot-data-v85', _tag(fields), _tag(key)],
        ensure_ascii=True) + '\n').encode('ascii')


def _nodes(tree):
    pending, count = [(tree, 0)], 0
    maximum = 0
    while pending:
        value, depth = pending.pop()
        count += 1; maximum = max(maximum, depth)
        if type(value) is list: pending.extend((item, depth + 1) for item in value)
    return count, maximum


def _replace(fields, index, value):
    return fields[:index] + (value,) + fields[index + 1:]


class GoSnapshotData85Test(unittest.TestCase):
    def test_roundtrip_stable_key_and_complete_package_refusals(self):
        modules = _definitions()
        codec, json, ip, core = (modules[name] for name in
            ('mta_snapshot_data', 'p011_json', 'mta_ip', 'mta_p2p_client_init'))
        def refuses(call, reason):
            with self.assertRaises(codec.SnapshotDataError) as seen: call()
            self.assertEqual(str(seen.exception), reason)

        with self.subTest(domain='complete_roundtrip'), _pure_domain():
            snapshot = _snapshot(modules)
            raw = codec.encode_snapshot(snapshot)
            data = codec.decode_snapshot(raw)
            self.assertIs(type(data), codec.SnapshotData)
            self.assertNotIsInstance(data, core.Snapshot)
            self.assertEqual(data.fields, _fields(snapshot))
            self.assertEqual(data.stable_key, _key(snapshot))
            self.assertIs(data.private_ascii(), raw)
            self.assertEqual(data.private_key_ascii(), codec.key_ascii(snapshot))
            self.assertEqual(data.data_sha, hashlib.sha256(raw).hexdigest())
            self.assertEqual(data.key_sha, codec.key_digest(snapshot))
            self.assertEqual(raw, _wire(modules, _fields(snapshot), _key(snapshot)))
            self.assertEqual(len(data.fields), 11)
            self.assertEqual(data.fields[7][0][0][-1], (0xffffffff, 0xffffffff, 17, 19))
            self.assertEqual(data.fields[9].count(data.fields[9][0]), 2)
            self.assertEqual(repr(data), '<private Snapshot DATA; not sampling, restore or admission>')

        with self.subTest(domain='actor_R_S'), _pure_domain():
            sleeping, running = _snapshot(modules, 'S'), _snapshot(modules, 'R')
            self.assertEqual(sleeping.key(), running.key())
            self.assertNotEqual(codec.encode_snapshot(sleeping), codec.encode_snapshot(running))
            self.assertNotEqual(codec.decode_snapshot(codec.encode_snapshot(sleeping)).data_sha,
                codec.decode_snapshot(codec.encode_snapshot(running)).data_sha)
            self.assertEqual(codec.key_ascii(sleeping), codec.key_ascii(running))
            self.assertEqual(codec.key_digest(sleeping), codec.key_digest(running))
            self.assertEqual(codec.decode_snapshot(codec.encode_snapshot(running)).fields[2][0][4][0][2], 'R')

        with self.subTest(domain='original_record_sort'), _pure_domain():
            original, reordered = _snapshot(modules), _snapshot(modules, reverse=True)
            self.assertEqual(_key(original), _key(reordered))
            self.assertEqual(codec.key_ascii(original), codec.key_ascii(reordered))
            self.assertNotEqual(codec.encode_snapshot(original), codec.encode_snapshot(reordered))
            decoded = codec.decode_snapshot(codec.encode_snapshot(reordered))
            self.assertEqual(decoded.fields, _fields(reordered))
            self.assertEqual(decoded.stable_key, _key(original))
            self.assertEqual(tuple(row[1] for row in decoded.stable_key[7]), (10, 11, 12, 9))
            self.assertEqual(tuple(row[9] for row in decoded.stable_key[8]), (10, 9))
            # Same first six address fields force exact bytes-literal ordering,
            # including both quote styles, backslash, controls and non-ASCII.
            labels = (b"a'b\x00", b'a"b\x00', b'\\x\x00', b'\t\r\n\xff\x00')
            same = tuple(ip.AddressRecord(3, 9, 9, 24, 0x80, 0, label,
                None, (0xffffffff, 0xffffffff, 0, 0)) for label in labels)
            quoted = _snapshot(modules, addresses=same)
            self.assertEqual(codec.decode_snapshot(codec.encode_snapshot(quoted)).stable_key, _key(quoted))

        with self.subTest(domain='complete_key_fields'), _pure_domain():
            before, changed = _snapshot(modules), _snapshot(modules, cache_tail=18)
            self.assertNotEqual(codec.key_digest(before), codec.key_digest(changed))
            self.assertNotEqual(_key(before), _key(changed))
            fields, key = _fields(before), _key(before)
            bad_key = _replace(key, 5, 2437)
            refuses(lambda: codec.decode_snapshot(_wire(modules, fields, bad_key)), 'stable_key_mismatch')

        with self.subTest(domain='complete_package_budgets'), _pure_domain():
            self.assertEqual((codec.MAX_ASCII_BYTES, codec.MAX_JSON_NODES, codec.MAX_JSON_DEPTH),
                (131072, 8192, 24))
            # Every record is accepted by the actual Snapshot constructor.
            # Each tagged half fits, but the COMPLETE full+key package does not.
            addresses = tuple(ip.AddressRecord(3, n, n, 24, 0x80, 0,
                None, None, (0xffffffff, 0xffffffff, 0, 0)) for n in range(1, 241))
            crowded = _snapshot(modules, addresses=addresses)
            fields, key = _fields(crowded), _key(crowded)
            halves = (_tag(fields), _tag(key))
            self.assertTrue(all(_nodes(half)[0] <= 8192 for half in halves))
            tree = [codec.DATA_SCHEMA, halves[0], halves[1]]
            self.assertGreater(_nodes(tree)[0], 8192)
            wire = _wire(modules, fields, key)
            self.assertLess(len(wire), 131072)
            with self.assertRaises(ValueError): json.loads(wire.decode('ascii'))
            refuses(lambda: codec.encode_snapshot(crowded), 'json_structure_limit')
            # Large valid core IPv6 text rows exceed ASCII before node quota.
            v6 = tuple((('%03d' % n) + 'a' * 253,) + ('b' * 256,) * 5 for n in range(45))
            large = _snapshot(modules, v6_addresses=v6)
            fields, key = _fields(large), _key(large)
            self.assertLess(_nodes([codec.DATA_SCHEMA, _tag(fields), _tag(key)])[0], 8192)
            self.assertGreater(len(_wire(modules, fields, key)), 131072)
            refuses(lambda: codec.encode_snapshot(large), 'ascii_limit')
            refuses(lambda: codec.decode_snapshot(b' ' * 131073), 'ascii_limit')
            # Actual encoder and actual stripped-json parser use the same limits.
            edge = codec._canonical(['x' * (131072 - 5)])
            self.assertEqual(len(edge), 131072)
            self.assertEqual(len(json.loads(edge.decode('ascii'))[0]), 131072 - 5)
            refuses(lambda: codec._canonical(['x' * (131072 - 4)]), 'ascii_limit')
            self.assertEqual(len(json.loads(codec._canonical([0] * 8191).decode('ascii'))), 8191)
            refuses(lambda: codec._canonical([0] * 8192), 'json_structure_limit')
            with self.assertRaises(ValueError): json.loads(json.dumps([0] * 8192))
            shallow, deep = 0, 0
            for unused in range(24): shallow = [shallow]
            for unused in range(25): deep = [deep]
            self.assertEqual(json.loads(codec._canonical(shallow).decode('ascii')), shallow)
            refuses(lambda: codec._canonical(deep), 'json_structure_limit')
            with self.assertRaises(ValueError): json.loads(json.dumps(deep))
            tagged = 0
            for unused in range(12): tagged = (tagged,)
            self.assertEqual(codec._unpack(codec._pack(tagged)), tagged)
            refuses(lambda: codec._pack((tagged,)), 'tag_depth')

        with self.subTest(domain='field_and_tag_refusals'), _pure_domain():
            snapshot = _snapshot(modules)
            fields, key = _fields(snapshot), _key(snapshot)
            bad_cases = (
                (_replace(fields, 5, True), 'integer_shape'),
                (_replace(fields, 10, False), 'stock_shape'),
                (_replace(fields, 0, 'x' * 36), 'boot_shape'),
                (_replace(fields, 2, (fields[2][0],)), 'stock_actors_shape'),
                (_replace(fields, 6, (fields[3], fields[3])), 'interfaces_shape'),
                (_replace(fields, 8, (fields[8][0], fields[8][0])), 'ipv6_duplicate'),
            )
            for malformed, reason in bad_cases:
                refuses(lambda malformed=malformed: codec.decode_snapshot(_wire(modules, malformed, key)), reason)
            address = fields[7][0][0]
            for replacement, reason in ((None, 'tuple_shape'), ((1, 1, 17, 19), 'address_cache_shape')):
                row = address[:8] + (replacement,)
                malformed = _replace(fields, 7, ((row,) + fields[7][0][1:], fields[7][1], fields[7][2]))
                refuses(lambda malformed=malformed: codec.decode_snapshot(_wire(modules, malformed, key)), reason)
            row = address[:6] + (b'a\x00b\x00',) + address[7:]
            malformed = _replace(fields, 7, ((row,) + fields[7][0][1:], fields[7][1], fields[7][2]))
            refuses(lambda: codec.decode_snapshot(_wire(modules, malformed, key)), 'address_label_shape')
            malformed = _replace(fields, 7, (fields[7][0] + (address,), fields[7][1], fields[7][2]))
            refuses(lambda: codec.decode_snapshot(_wire(modules, malformed, key)), 'ipv4_duplicate')
            malformed = _replace(fields, 7, (fields[7][0], fields[7][1], fields[7][2][:-1]))
            refuses(lambda: codec.decode_snapshot(_wire(modules, malformed, key)), 'default_rules_shape')
            refuses(lambda: codec._unpack(['bytes', 'FF']), 'bytes_shape')
            refuses(lambda: codec._unpack(['bytes', 'f']), 'bytes_shape')
            refuses(lambda: codec._unpack(['other', []]), 'tag_shape')
            refuses(lambda: codec._unpack({'tuple': []}), 'tag_shape')
            refuses(lambda: codec.decode_snapshot(b'\xff\n'), 'json_invalid')

        with self.subTest(domain='exact_domain_and_immutable_DATA'), _pure_domain():
            foreign_calls = []
            class Foreign(object):
                def __repr__(self): foreign_calls.append('repr'); raise AssertionError('foreign repr')
                def __bool__(self): foreign_calls.append('bool'); raise AssertionError('foreign bool')
            refuses(lambda: codec.encode_snapshot(Foreign()), 'snapshot_type')
            class DerivedSnapshot(core.Snapshot): pass
            base = _snapshot(modules)
            derived = DerivedSnapshot(*tuple(getattr(base, name) for name in core.Snapshot.__slots__))
            refuses(lambda: codec.encode_snapshot(derived), 'snapshot_type')
            def altered_key(*unused): foreign_calls.append('key'); raise AssertionError('foreign key')
            with mock.patch.object(core.Actor, 'key', altered_key):
                refuses(lambda: codec.encode_snapshot(base), 'fixed_domain_changed')
            self.assertEqual(foreign_calls, [])
            raw = codec.encode_snapshot(base)
            data = codec.decode_snapshot(raw)
            with self.assertRaises(AttributeError): data.fields = ()
            with self.assertRaises(AttributeError): del data.stable_key
            refuses(lambda: codec.SnapshotData(data.fields, data.stable_key, raw,
                data.private_key_ascii()), 'data_constructor')

        with self.subTest(domain='canonical_envelope_refusals'), _pure_domain():
            raw = codec.encode_snapshot(_snapshot(modules))
            refuses(lambda: codec.decode_snapshot(raw[:-1]), 'noncanonical_data')
            refuses(lambda: codec.decode_snapshot(b' ' + raw), 'noncanonical_data')
            tree = json.loads(raw.decode('ascii')); tree[0] = codec.KEY_SCHEMA
            refuses(lambda: codec.decode_snapshot((json.dumps(tree) + '\n').encode('ascii')), 'data_schema')
            refuses(lambda: codec.decode_snapshot(bytearray(raw)), 'ascii_limit')
            refuses(lambda: codec.decode_snapshot(b''), 'ascii_limit')
            refuses(lambda: codec.decode_snapshot(raw + b'null'), 'json_invalid')

        print(MARKER, end='')


if __name__ == '__main__':
    unittest.main()
