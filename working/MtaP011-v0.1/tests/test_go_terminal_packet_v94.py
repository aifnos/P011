"""HOST94: two NEW terminal Packet DATA domains, not a terminal observer.

Five complete pinned definitions execute in a private import namespace:
p011_json, actual IPv4/core28, Snapshot DATA85, and appended Packet94. No old
TestCase/helper is imported; no preflight87 API or prior test is dispatched.
Finish/Journal/stock Snapshot/absence numbers, metadata, task/epoch and all
closure claims are explicitly synthetic DATA. Native constructors, platform
IO, clocks, callbacks and the old public preflight API are per-fixture
tripwires. Packet validity, private raw retention and stream finish are not
sampling, EOF, reap, FD closure, native restoration, admission or RF evidence.

Exactly 26 independent fixtures in 2 domains: request12 (1 valid/11 refusal),
response14 (2 valid/12 refusal). Valid cleanup runs after synthetic task expiry
and uses DISTINCT original F and Parent cleanup caps. Every mutation has its
own fresh fixture and exact expected constant reason; byte lengths, hashes,
canonical encodings and complete multi-segment retention use the actual new
algorithms. ROOT alone executes/AST-checks this SOURCE, if authorized.
"""
import builtins
import collections
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import math
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
INPUTS = (
    ('p011_json', 'runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_ip', 'runtime/mta_ip.py', 22049,
     '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    ('mta_p2p_client_init', 'candidate/client-session-v28/runtime/mta_p2p_client_init.py', 69966,
     '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b'),
    ('mta_snapshot_data', 'candidate/go-send-observer-v85/runtime/mta_snapshot_data.py', 17217,
     'cb5e8f16c78cc4c879a8986dd9c2ab8ed5e6c055f105baad3ce60eb9a10d2a26'),
    ('mta_observer_packet', 'candidate/go-send-terminal-channel-v94/runtime/mta_observer_packet.py', 48253,
     '004ff5616924a4529ce3a3f710ac83a8d2dedbd55ae2edb790998a68f68fe40f'),
)
METHOD = 'GoTerminalPacket94Test.test_cleanup_request_and_complete_terminal_packet'
MARKER = 'HOST94_TERMINAL_PACKET new_methods=1 old_methods=0 domains=2 fixtures=26 pure_codec=true device=false phone=false\n'
SOURCE_MANIFEST = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
FALSE_KEYS = ('rf_requested', 'native_restore_verified', 'restoration_verified',
              'independent_restore_verified', 'production_admitted')


def _definitions():
    modules = {}
    ordinary = dict(re=re, struct=struct, hashlib=hashlib, math=math, collections=collections)
    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name not in modules and name not in ordinary:
            raise AssertionError('unexpected HOST94 pure definition import')
        return modules[name] if name in modules else ordinary[name]
    for name, path, size, pin in INPUTS:
        raw = (ROOT / path).read_bytes()
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin:
            raise AssertionError('fixed HOST94 input changed')
        module = types.ModuleType(name)
        module.__file__ = str(ROOT / path)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=fixed_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


@contextmanager
def _pure(modules):
    calls = []
    def forbidden(*unused, **ignored):
        calls.append('forbidden')
        raise AssertionError('HOST94 platform/native/old-preflight tripwire')
    targets = ((builtins, 'open'), (os, 'open'), (os, 'read'), (os, 'write'),
        (os, 'close'), (os, 'fstat'), (os, 'stat'), (os, 'lstat'), (os, 'getpid'),
        (os, 'listdir'), (os, 'mkdir'), (os, 'urandom'), (socket, 'socket'),
        (subprocess, 'Popen'), (threading.Thread, 'start'), (time, 'time'),
        (time, 'monotonic'))
    codec, core, ip = (modules[k] for k in ('mta_observer_packet', 'mta_p2p_client_init', 'mta_ip'))
    with ExitStack() as stack:
        for owner, name in targets:
            stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
        for cls in (core.Actor, core.Origin, core.Snapshot, ip.IpSnapshot,
                    ip.AddressRecord, ip.RouteRecord, ip.RuleRecord):
            stack.enter_context(mock.patch.object(cls, '__init__', side_effect=forbidden))
        for owner, name in ((codec, 'encode_result'), (codec, 'decode_packet'),
                (codec.ObserverPacketReader, 'feed'), (codec.ObserverPacketReader, 'finish')):
            stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
        yield calls
    if calls: raise AssertionError('HOST94 tripwire count not zero')


def _tag(value):
    # Independent primitive wire builder, not a native DATA constructor.
    if type(value) is tuple: return ['tuple', [_tag(item) for item in value]]
    if type(value) is bytes: return ['bytes', value.hex()]
    if value is None or type(value) in (str, bool, int): return value
    raise AssertionError('fixture tag accepts primitives only')


def _snapshot(modules):
    core, json = modules['mta_p2p_client_init'], modules['p011_json']
    boot = '01234567-89ab-cdef-0123-456789abcdef'
    hashes = tuple(sorted(core.STOCK_PINS))
    actors = (
        (101, 1001, '/usr/bin/Z03', 'a' * 64, ((101, 1001, 'S'),)),
        (202, 2002, '/usr/bin/control_engine', 'b' * 64, ((202, 2002, 'S'),)),
        (303, 3003, '/usr/bin/weston', 'c' * 64, ((303, 3003, 'S'),)),
    )
    station = (0, 257, 3, 'wlan0', 2)
    rules = ((0, 255), (32766, 254), (32767, 253))
    fields = (boot, hashes, actors, station, 'd' * 64, 2412, (station,),
              ((), (), rules), (), (), True)
    actors_key = tuple((a[0], a[1], a[2], a[3], tuple(t[:2] for t in a[4])) for a in actors)
    key = (boot, hashes, actors_key, station, 'd' * 64, 2412, (station,), (), (), rules, (), ())
    raw = (json.dumps(['p011-snapshot-data-v85', _tag(fields), _tag(key)],
                      ensure_ascii=True) + '\n').encode('ascii')
    key_raw = (json.dumps(['p011-snapshot-key-v85', _tag(key)], ensure_ascii=True) + '\n').encode('ascii')
    def origin(row): return dict(zip(('phy', 'wdev', 'ifindex', 'name', 'iftype'), row))
    def actor(row):
        return dict(pid=row[0], start=row[1], exe=row[2], argv_sha=row[3],
                    tasks=[list(t) for t in row[4]])
    tree = dict(boot=boot, stock_hashes=[dict(path=p, sha256=s) for p, s in hashes],
        stock_actors=[actor(a) for a in actors], station=origin(station),
        station_state_sha='d' * 64, station_frequency=2412, interfaces=[origin(station)],
        ipv4=dict(addresses=[], routes=[], rules=[dict(priority=a, table=b) for a, b in rules]),
        ipv6_addresses=[], ipv6_routes=[], station_completed=True)
    return raw, hashlib.sha256(key_raw).hexdigest(), tree


def _refresh(modules, fixture):
    # SHA/size DATA is recomputed only from THIS synthetic Journal raw, not
    # substituted into the production codec or presented as an IO receipt.
    json, value, journal, finish = (modules['p011_json'], fixture['value'],
                                    fixture['journal'], fixture['finish'])
    raw = json.dumps(journal, ensure_ascii=True, sort_keys=True).encode('ascii')
    metadata = (91, 92, 0o100600, 0, 0, 1, len(raw), 93, 94)
    finish['journal'] = dict(schema='p011-go-typed-live-v72', phase='reconciled',
        generation=journal['generation'], sha256=hashlib.sha256(raw).hexdigest(),
        bytes=len(raw), metadata=list(metadata),
        facts_key=[journal[k] for k in ('schema', 'run_token', 'candidate_sha',
                   'task_id', 'boot_id', 'issued_at', 'until')])
    finish_raw = ('GOFINISH84=' + json.dumps(finish, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
    value.update(finish_raw=finish_raw, finish_sha256=hashlib.sha256(finish_raw).hexdigest(),
        journal_raw=raw, journal_sha256=hashlib.sha256(raw).hexdigest(), journal_metadata=metadata)
    return fixture


def _fixture(modules, child=False):
    snapshot_raw, key_sha, tree = _snapshot(modules)
    binding = dict(nonce='9' * 32, task_id='3' * 32, native_epoch=7,
                   operation_epoch=7, until=140.0, cleanup_until=145.0)
    launch = dict(run='1' * 32, manifest='4' * 64, task='3' * 32, nonce='2' * 32,
        native_epoch=7, operation_epoch=7, until='100.0', candidate_sha='5' * 64, child_pid=42)
    limits = dict(task_until=100.0, service_until=120.0, go_cleanup_until=155.0,
                  service_cleanup_until=180.0)
    device, journal_lock = (71, 72, 0o100600, 0, 0, 1, 0, 73, 74), (81, 82, 0o100600, 0, 0, 1, 0, 83, 84)
    journal = dict(schema='p011-go-typed-live-v72', run_token=launch['run'],
        candidate_sha=launch['candidate_sha'], task_id=launch['task'], boot_id=tree['boot'],
        issued_at=1.0, until=100.0, phase='reconciled', generation=20,
        baseline=copy.deepcopy(tree), restored=copy.deepcopy(tree),
        interface_intent=None, owned=None, watchdog=None, controller=None,
        group_add=None, group_observed=None, cleanup_until=150.0, ip=None, dhcp=None)
    f_actor = dict(pid=42, start=4200, exe='/usr/bin/python3.5', argv_sha='6' * 64,
                   tasks=[[42, 4200, 'S'], [43, 4300, 'R']])
    finish = dict(schema='p011-go-finish-data-v93', provenance='returned_restore',
        binding=dict((k, launch[k]) for k in ('run', 'manifest', 'task', 'nonce',
                      'native_epoch', 'operation_epoch', 'until')), journal=None,
        cleanup_until=150.0, finished_at=130.0, device_lock_metadata=list(device),
        f_actor=[42, 4200, '6' * 64], f_actor_data=f_actor, children=[],
        children_outcomes=[], inventory_counts=[8, 12], business_failed_at_capture=True,
        native_full_inventory_export=False, independent_restore_verified=False, production_admitted=False)
    absences = [('f', 42, 4200, 2, 10, 10)]
    if child:
        actor = dict(pid=411, start=4110, exe='/fixed/controller', argv_sha='8' * 64,
                     tasks=[[411, 4110, 'S'], [412, 4120, 'R']])
        journal['controller'] = dict(phase='live', spec_sha='7' * 64, argv_sha='8' * 64,
                                     until=100.0, actor=actor)
        journal['interface_intent'] = dict(boot=tree['boot'], phy=0, name='mta01234567', sequence=1, port_id=2)
        journal['owned'] = dict(phy=0, wdev=258, ifindex=9, name='mta01234567', iftype=8)
        finish['children'] = [['controller', 411, 4110]]
        finish['children_outcomes'] = [dict(role='controller', fork_requested=True,
            fork_negative=False, waited=True, exit_verified=True, actor_present=True)]
        absences.append(('controller', 411, 4110, 2, 12, 12))
    value = dict(schema='p011-go-terminal-data-v94',
        binding=tuple(sorted(binding.items())), launch_binding=tuple(sorted(launch.items())),
        cleanup_limits=tuple(sorted(limits.items())), finish_raw=None, finish_sha256=None,
        journal_raw=None, journal_sha256=None, journal_metadata=None,
        device_lock_metadata=device, journal_lock_metadata=journal_lock,
        snapshot_raw=snapshot_raw, stable_key_sha256=key_sha, snapshot_round_count=2,
        absence_facts=tuple(absences), source_manifest_sha256=SOURCE_MANIFEST, source_count=38,
        active_until=140.0, cleanup_until=145.0)
    for key in FALSE_KEYS: value[key] = False
    return _refresh(modules, dict(binding=binding, launch=launch, limits=limits,
        journal=journal, finish=finish, value=value))


def _request(modules, fixture):
    value = fixture['value']
    return modules['mta_observer_packet'].encode_terminal_request(
        fixture['binding'], fixture['launch'], value['finish_raw'], fixture['limits'])


def _wire(modules, value, header_change=None, header_raw_change=None):
    # Independent framing fixture. It never invokes or patches the new gates.
    header = dict((k, v) for k, v in value.items() if k not in
                  ('schema', 'binding', 'launch_binding', 'cleanup_limits', 'finish_raw', 'snapshot_raw', 'journal_raw'))
    header.update(schema='p011-go-terminal-packet-v94', binding=dict(value['binding']),
        launch_binding=dict(value['launch_binding']), cleanup_limits=dict(value['cleanup_limits']),
        finish_ascii=value['finish_raw'].decode('ascii'), snapshot_bytes=len(value['snapshot_raw']),
        snapshot_sha256=hashlib.sha256(value['snapshot_raw']).hexdigest(), journal_bytes=len(value['journal_raw']))
    if header_change is not None: header_change(header)
    raw = (modules['p011_json'].dumps(header, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
    if header_raw_change is not None: raw = header_raw_change(raw)
    return b'P011TERM94\x00' + struct.pack('!III', len(raw), len(value['snapshot_raw']),
        len(value['journal_raw'])) + raw + value['snapshot_raw'] + value['journal_raw']


class GoTerminalPacket94Test(unittest.TestCase):
    def test_cleanup_request_and_complete_terminal_packet(self):
        modules = _definitions()
        codec = modules['mta_observer_packet']
        totals = dict(request=0, response=0, valid=0, refused=0)
        def refusal(domain, name, invoke, reason):
            with self.subTest(domain=domain, fixture=name), _pure(modules) as calls:
                with self.assertRaises(codec.ObserverPacketError) as caught: invoke()
                self.assertEqual(str(caught.exception), reason)
                self.assertEqual(calls, [])
            totals[domain] += 1; totals['refused'] += 1

        with self.subTest(domain='request', fixture='task_expired_cleanup'), _pure(modules) as calls:
            fixture = _fixture(modules)
            raw = _request(modules, fixture)
            data = codec.decode_terminal_request(raw)
            self.assertIs(type(data), codec.TerminalRequestData)
            self.assertGreater(dict(data.binding)['until'], dict(data.cleanup_limits)['task_until'])
            self.assertNotEqual(fixture['finish']['cleanup_until'], fixture['limits']['go_cleanup_until'])
            self.assertEqual(data.private_finish_ascii(), fixture['value']['finish_raw'])
            self.assertIs(data.private_request_ascii(), raw)
            self.assertEqual(data.binding, tuple(sorted(fixture['binding'].items())))
            self.assertEqual(data.launch_binding, tuple(sorted(fixture['launch'].items())))
            self.assertEqual(data.cleanup_limits, tuple(sorted(fixture['limits'].items())))
            self.assertEqual(data.finish_sha256, hashlib.sha256(fixture['value']['finish_raw']).hexdigest())
            self.assertEqual(raw, (modules['p011_json'].dumps(dict(schema='p011-go-terminal-request-v94',
                binding=fixture['binding'], launch_binding=fixture['launch'],
                finish_ascii=fixture['value']['finish_raw'].decode('ascii'),
                cleanup_limits=fixture['limits']), ensure_ascii=True, sort_keys=True) + '\n').encode('ascii'))
            with self.assertRaises(AttributeError): data.binding = ()
            self.assertEqual(calls, [])
        totals['request'] += 1; totals['valid'] += 1

        def request_changed(name):
            fixture = _fixture(modules)
            if name == 'past_F_cleanup': fixture['binding'].update(until=149.0, cleanup_until=151.0)
            elif name == 'past_Parent_cleanup':
                fixture['finish']['cleanup_until'] = fixture['journal']['cleanup_until'] = 170.0
                fixture['binding'].update(until=154.0, cleanup_until=156.0); _refresh(modules, fixture)
            elif name == 'service_cleanup_changed': fixture['limits']['service_cleanup_until'] = 181.0
            elif name == 'GO_cleanup_extension': fixture['limits']['go_cleanup_until'] = 161.0
            elif name == 'task_changed': fixture['limits']['task_until'] = 101.0
            elif name == 'epoch_changed': fixture['binding']['operation_epoch'] = 8
            elif name == 'same_F_nonce': fixture['binding']['nonce'] = fixture['launch']['nonce']
            elif name == 'full_actor_mismatch':
                fixture['finish']['f_actor_data']['start'] = 4201
                fixture['finish']['f_actor_data']['tasks'][0][1] = 4201; _refresh(modules, fixture)
            elif name == 'finish_whole_limit':
                fixture['value']['finish_raw'] = b'GOFINISH84=' + b'x' * 4096
            return _request(modules, fixture)
        for name, reason in (
                ('past_F_cleanup', 'terminal_cleanup_limits'),
                ('past_Parent_cleanup', 'terminal_cleanup_limits'),
                ('service_cleanup_changed', 'terminal_cleanup_limits'),
                ('GO_cleanup_extension', 'terminal_cleanup_limits'),
                ('task_changed', 'terminal_cleanup_limits'),
                ('epoch_changed', 'packet_binding'),
                ('same_F_nonce', 'terminal_ownership'),
                ('full_actor_mismatch', 'terminal_finish_actor'),
                ('finish_whole_limit', 'terminal_finish_ascii')):
            refusal('request', name, lambda n=name: request_changed(n), reason)
        refusal('request', 'request_noncanonical',
            lambda: codec.decode_terminal_request(_request(modules, _fixture(modules))[:-1]), 'terminal_noncanonical')
        refusal('request', 'request_whole_limit',
            lambda: codec.decode_terminal_request(b'x' * 16385), 'terminal_ascii_limit')

        for child in (False, True):
            with self.subTest(domain='response', fixture='complete_child' if child else 'chunked_cleanup'), _pure(modules) as calls:
                fixture = _fixture(modules, child)
                value = fixture['value']
                raw = codec.encode_terminal_result(value)
                self.assertEqual(raw, _wire(modules, value))
                reader = codec.TerminalPacketReader()
                sizes, index, ordinal = (1, 7, 19, 83, 257, 1024), 0, 0
                while index < len(raw):
                    count = sizes[ordinal % len(sizes)]
                    self.assertIsNone(reader.feed(raw[index:index + count]))
                    index += count; ordinal += 1
                data = reader.finish()
                self.assertIs(type(data), codec.TerminalPacketData)
                self.assertEqual(data.private_snapshot_ascii(), value['snapshot_raw'])
                self.assertEqual(data.private_journal_ascii(), value['journal_raw'])
                self.assertEqual(data.private_finish_ascii(), value['finish_raw'])
                self.assertEqual(data.snapshot.private_ascii(), value['snapshot_raw'])
                self.assertEqual(data.stable_key_sha256, value['stable_key_sha256'])
                self.assertEqual(data.absence_facts, value['absence_facts'])
                self.assertEqual(data.cleanup_limits, value['cleanup_limits'])
                self.assertEqual(data.launch_binding, value['launch_binding'])
                self.assertEqual(data.snapshot_round_count, 2)
                self.assertEqual(data.packet_sha256, hashlib.sha256(raw).hexdigest())
                self.assertEqual(reader.size, len(raw)); self.assertTrue(reader.ended)
                self.assertIs(reader.value, data)
                for key in FALSE_KEYS: self.assertIs(getattr(data, key), False)
                with self.assertRaises(AttributeError): data.absence_facts = ()
                self.assertEqual(calls, [])
            totals['response'] += 1; totals['valid'] += 1

        def response_bad(name):
            fixture = _fixture(modules)
            value = fixture['value']
            if name == 'truncation': return codec.decode_terminal_packet(_wire(modules, value)[:-1])
            if name == 'declared_payload_limit':
                raw = _wire(modules, value)
                prefix = b'P011TERM94\x00'
                hsize, ssize, jsize = struct.unpack('!III', raw[len(prefix):len(prefix) + 12])
                return codec.decode_terminal_packet(prefix + struct.pack('!III', hsize, 131073, jsize) + raw[len(prefix) + 12:])
            if name == 'snapshot_hash':
                return codec.decode_terminal_packet(_wire(modules, value,
                    header_change=lambda header: header.update(snapshot_sha256='0' * 64)))
            if name == 'header_noncanonical':
                return codec.decode_terminal_packet(_wire(modules, value, header_raw_change=lambda raw: raw[:-1]))
            if name == 'whole_packet_limit': return codec.decode_terminal_packet(b'x' * 393217)
            if name == 'snapshot_key':
                value['stable_key_sha256'] = '0' * 64
            elif name == 'journal_snapshot_changed':
                fixture['journal']['restored']['station_state_sha'] = 'e' * 64
                _refresh(modules, fixture)
            elif name == 'F_leader_missing':
                fixture['finish']['f_actor_data']['tasks'] = [[43, 4300, 'R']]
                _refresh(modules, fixture)
            elif name == 'absence_actor_changed':
                value['absence_facts'] = (('f', 43, 4200, 2, 10, 10),)
            elif name == 'absence_passes_changed':
                value['absence_facts'] = (('f', 42, 4200, 1, 10, 10),)
            elif name == 'absence_closed_count_changed':
                value['absence_facts'] = (('f', 42, 4200, 2, 10, 9),)
            elif name == 'journal_noncanonical':
                raw = value['journal_raw'] + b'\n'
                meta = tuple(value['journal_metadata'][:6]) + (len(raw),) + tuple(value['journal_metadata'][7:])
                fixture['finish']['journal'].update(sha256=hashlib.sha256(raw).hexdigest(),
                    bytes=len(raw), metadata=list(meta))
                finish = ('GOFINISH84=' + modules['p011_json'].dumps(fixture['finish'],
                          ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
                value.update(journal_raw=raw, journal_sha256=hashlib.sha256(raw).hexdigest(),
                    journal_metadata=meta, finish_raw=finish, finish_sha256=hashlib.sha256(finish).hexdigest())
            return codec.encode_terminal_result(value)
        for name, reason in (
                ('truncation', 'terminal_lengths'),
                ('declared_payload_limit', 'terminal_lengths'),
                ('snapshot_hash', 'terminal_payload_changed'),
                ('header_noncanonical', 'terminal_noncanonical'),
                ('journal_noncanonical', 'terminal_noncanonical'),
                ('snapshot_key', 'terminal_snapshot_key'),
                ('journal_snapshot_changed', 'terminal_journal_snapshot'),
                ('F_leader_missing', 'terminal_actor_leader'),
                ('absence_actor_changed', 'terminal_absence_actor'),
                ('absence_passes_changed', 'terminal_absence_actor'),
                ('absence_closed_count_changed', 'terminal_absence_files'),
                ('whole_packet_limit', 'terminal_prefix')):
            refusal('response', name, lambda n=name: response_bad(n), reason)
        self.assertEqual(totals, dict(request=12, response=14, valid=3, refused=23))
        print(MARKER, end='')


if __name__ == '__main__':
    unittest.main(verbosity=0)

