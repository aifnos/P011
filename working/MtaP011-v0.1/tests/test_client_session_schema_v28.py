"""One new v28 schema method: exact definitions over private synthetic records.

No previous test methods, Store persistence, kernel/IP installation, DHCP
handoff, full lifecycle, device or phone acceptance is exercised here.
"""
import ast
import builtins
from contextlib import ExitStack
import hashlib
from pathlib import Path
import types
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
PINS = {
    'p011_json': ('runtime/p011_json.py', 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    'mta_ip': ('runtime/mta_ip.py', '1fa5e72817772285fd966f52c57af105950ff0d3b6ea49b202983aebfbab40c5'),
    'mta_p2p_client_init': ('candidate/client-session-v28/runtime/mta_p2p_client_init.py',
        '178bd8a491e9e5ec03e8da3bce780f8e8e8c1c8781bfeaca7d8c3bac59fa364b'),
    'mta_client_journal_codec': ('candidate/client-session-v28/runtime/mta_client_journal_codec.py',
        '2ffeca6b59498c9e2dfa4b9906bbe55db909d5d5e1d448fa0c795490996fe14a'),
    'mta_client_dynamic_ip': ('candidate/client-session-v28/runtime/mta_client_dynamic_ip.py',
        'c789edbc52b28bceaee33ced79d337c6944f76d6040df4a26cefd83f184bec4a'),
}


def definitions():
    # HOST input read precedes the tripwires. No target module can choose a path.
    originals = {}
    for name, pair in PINS.items():
        raw = (BASE / pair[0]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pair[1]: raise ValueError('HOST fixed input changed')
        originals[name] = raw
    return originals


def load(originals):
    modules, original_import = {}, builtins.__import__
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in originals:
            if level or name not in modules: raise AssertionError('HOST fixed definition order')
            return modules[name]
        if level or name.startswith(('mta_', 'p011_')): raise AssertionError('HOST unfixed target import')
        return original_import(name, globals, locals, fromlist, level)
    for name in ('p011_json', 'mta_ip', 'mta_p2p_client_init', 'mta_client_journal_codec', 'mta_client_dynamic_ip'):
        raw = originals[name]
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        module = types.ModuleType(name)
        module.__file__ = 'HOST-session-schema-v28/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


class SessionSchemaV28Tests(unittest.TestCase):
    def test_fixed_profiles_original_issuance_strict_v6_and_dynamic_ip_facts(self):
        originals = definitions()
        with ExitStack() as stack:
            for name in ('os.open', 'os.read', 'os.write', 'os.close', 'os.fstat',
                    'os.stat', 'os.listdir', 'os.readlink', 'os.getpid', 'os.fork',
                    'os.execve', 'os.waitpid', 'os.kill', 'os.system', 'os.urandom',
                    'socket.socket', 'socket.create_connection', 'subprocess.Popen',
                    'ctypes.CDLL', 'threading.Thread.start', 'time.sleep'):
                stack.enter_context(mock.patch(name, side_effect=AssertionError('HOST schema has no actual OS permission'), create=True))
            modules = load(originals)
            core, codec, ip, json, dynamic = (modules[name] for name in
                ('mta_p2p_client_init', 'mta_client_journal_codec', 'mta_ip', 'p011_json', 'mta_client_dynamic_ip'))
            trial, formal = core.TRIAL_SESSION_PROFILE, core.FORMAL_SESSION_PROFILE
            self.assertEqual((20.0, 300.0), (trial.max_active_seconds, formal.max_active_seconds))
            for profile in (trial, formal):
                self.assertIs(profile, core._session_profile(profile))
                self.assertIs(profile, core.session_profile_named(profile.name))
                self.assertEqual((20.0, 60.0), (profile.max_prepare_seconds, profile.max_cleanup_seconds))
                with self.assertRaises(AttributeError): profile.max_active_seconds = 900.0
            with self.assertRaises(core.ClientInitError): core.SessionProfile('trial20', 20.0)
            clone = core.SessionProfile.__new__(core.SessionProfile)
            with self.assertRaises(core.ClientInitError): core._session_profile(clone)
            for value in ('trial', 'formal', 'formal600', {}, None, True):
                with self.assertRaises(core.ClientInitError): core.session_profile_named(value)

            boot, identity = '11111111-1111-1111-1111-111111111111', core.Identity('a' * 64)
            def actor(pid, exe, digest='a'):
                return core.Actor(pid, 100 + pid, exe, digest * 64, ((pid, 100 + pid, 'S'),))
            stock = (actor(1, '/usr/bin/Z03'), actor(2, '/usr/bin/control_engine'), actor(3, '/usr/bin/weston'))
            station = core.Origin(0, 1, 2, 'wlan0', 2)
            station_local = ip.ipv4_number('192.168.8.5')
            station_address = ip.AddressRecord(2, station_local, station_local, 24,
                0x80, 0, b'wlan0\0', ip.ipv4_number('192.168.8.255'),
                (ip.UINT_MAX, ip.UINT_MAX, 10, 20))
            station_route = ip.RouteRecord(ip.ipv4_number('192.168.8.0'), 24, 254,
                2, 253, 1, 0, 2, None, None, station_local, ())
            baseline_ip = ip.IpSnapshot((station_address,), (station_route,),
                (ip.RuleRecord(0, 255), ip.RuleRecord(32766, 254), ip.RuleRecord(32767, 253)))
            baseline = core.Snapshot(boot, core.STOCK_PINS, stock, station, 'b' * 64,
                2412, (station,), baseline_ip, (), (), True)
            def journal(profile=trial, issued=100.0, deadline=120.0, **changes):
                fields = {'identity': identity, 'stage': 'prepared', 'baseline': baseline,
                    'deadline': deadline, 'session_profile': profile.name, 'issued_at': issued}
                fields.update(changes)
                return core.Journal(**fields)
            trial_record = journal()
            formal_record = journal(formal, deadline=400.0)
            self.assertEqual((trial.name, 100.0, 120.0),
                (trial_record.session_profile, trial_record.issued_at, trial_record.deadline))
            for profile, end in ((trial, 120.000001), (formal, 400.000001), (trial, 100.0), (trial, 99.0)):
                with self.assertRaises(core.ClientInitError): journal(profile, deadline=end)
            for field in ('issued_at', 'session_profile'):
                fields = {'identity': identity, 'stage': 'prepared', 'baseline': baseline,
                    'deadline': 120.0, 'session_profile': trial.name, 'issued_at': 100.0}
                del fields[field]
                with self.assertRaises(core.ClientInitError): core.Journal(**fields)
            for value in (True, None, float('nan'), float('inf'), -1.0):
                with self.assertRaises(core.ClientInitError): journal(issued=value)
            for field, changed in (('session_profile', formal.name), ('issued_at', 101.0), ('deadline', 121.0)):
                with self.assertRaises(core.ClientInitError): trial_record.replace(**{field: changed})
            retained = trial_record.replace(stage='cleanup_intent', issued_at=100.0,
                session_profile=trial.name, deadline=120.0)
            self.assertIs(trial_record.issued_at, retained.issued_at)
            self.assertIs(trial_record.deadline, retained.deadline)
            self.assertIs(trial_record.session_profile, retained.session_profile)
            later_issue = journal(issued=101.0)
            self.assertNotEqual(trial_record.key(), later_issue.key())
            self.assertFalse(core._same_journal(trial_record, later_issue))

            for record in (trial_record, formal_record):
                encoded = codec.encode_journal(record)
                rebuilt = codec.decode_journal(encoded)
                self.assertTrue(core._same_journal(record, rebuilt))
                self.assertEqual(encoded, codec.encode_journal(rebuilt))
                document = json.loads(encoded.decode('ascii'))
                self.assertEqual((6, 'p011-client-session-v28-1'), (document['version'], document['marker']))
                self.assertIsNone(document['journal']['client_ip'])
                for field in ('session_profile', 'issued_at', 'client_ip'):
                    bad = json.loads(encoded.decode('ascii')); del bad['journal'][field]
                    with self.assertRaises(codec.JournalCodecError): codec.decode_journal(json.dumps(bad, sort_keys=True).encode('ascii'))
                for field, value in (('session_profile', 'formal600'), ('issued_at', 100), ('issued_at', True),
                        ('deadline', 120), ('deadline', record.issued_at), ('extra', None)):
                    bad = json.loads(encoded.decode('ascii')); bad['journal'][field] = value
                    with self.assertRaises(codec.JournalCodecError): codec.decode_journal(json.dumps(bad, sort_keys=True).encode('ascii'))
                legacy = json.loads(encoded.decode('ascii'))
                legacy['version'], legacy['marker'] = 5, 'p011-client-durable-association-v18-1'
                for field in ('session_profile', 'issued_at', 'client_ip'): del legacy['journal'][field]
                with self.assertRaises(codec.JournalCodecError) as caught:
                    codec.decode_journal(json.dumps(legacy, sort_keys=True).encode('ascii'))
                self.assertEqual('unsupported_envelope', caught.exception.code)

            owned = core.Origin(0, 2, 5, 'mta00000000', 8)
            controller, watchdog, executor = actor(51, '/host/wpa', 'c'), actor(52, '/usr/bin/python3.5', 'd'), actor(53, '/usr/bin/python3.5')
            binding = {'version': 1, 'run_token': 'a' * 32, 'candidate_sha': identity.candidate_sha,
                'operation_id': 'HOST-v28-schema', 'native_epoch': 8, 'operation_epoch': 8,
                'gatt_session': 12, 'nonce': 'e' * 32, 'receive_consent': True}
            association = core.ClientAssociationRecord('confirmed', binding, executor,
                b'\x02\x01\x02\x03\x04\x05', b'\x02\x01\x02\x03\x04\x06', 2412, 'f' * 64)
            common = {'stage': 'client_init_ready', 'ready': True, 'owned': owned,
                'interface_ticket': core.InterfaceTicket(boot, 0, owned.name, 1, 100),
                'controller_ticket': core.Ticket('c' * 32, 'controller', boot, controller.exe, controller.argv_sha),
                'controller': controller,
                'watchdog_ticket': core.Ticket('d' * 32, 'watchdog', boot, watchdog.exe, watchdog.argv_sha),
                'watchdog': watchdog, 'association': association}
            intent = dynamic.DynamicIpRecord('intent', owned, '10.5.0.2', 24, 119.0, baseline_ip)
            active = journal(client_ip=intent, **common)
            spec = dynamic.DynamicAddressSpec(owned.ifindex, '10.5.0.2', 24)
            address = ip.AddressRecord(owned.ifindex, spec.address, spec.address, spec.prefixlen,
                ip.IFA_F_PERMANENT, 0, owned.name.encode('ascii') + b'\0',
                ip.ipv4_number('10.5.0.255'), (ip.UINT_MAX, ip.UINT_MAX, 30, 40))
            observed_ip = ip.IpSnapshot(baseline_ip.addresses + (address,),
                baseline_ip.routes + dynamic.expected_routes(spec), baseline_ip.rules)
            applied = intent.replace('applied', observed_ip)
            active_applied = active.replace(client_ip=applied)
            restored = dynamic.DynamicIpRecord('restored', owned, '10.5.0.2', 24, 119.0, baseline_ip, baseline_ip)
            cleanup = active.replace(stage='cleanup_intent', ready=False, association=association.invalidated())
            deleting = active_applied.replace(stage='cleanup_intent', ready=False,
                association=association.invalidated(), client_ip=applied.replace('delete_intent', observed_ip))
            terminal = cleanup.replace(stage='cleanup_verified', client_ip=restored)
            for record in (active, active_applied, cleanup, deleting, terminal, terminal.replace(stage='reconciled')):
                data = codec.encode_journal(record)
                rebuilt = codec.decode_journal(data)
                self.assertIs(type(rebuilt.client_ip), dynamic.DynamicIpRecord)
                self.assertEqual(record.client_ip.key(), rebuilt.client_ip.key())
                self.assertTrue(core._same_journal(record, rebuilt))
                self.assertEqual(data, codec.encode_journal(rebuilt))
            for changes in ({'client_ip': object()}, {'client_ip': restored},
                    {'association': association.invalidated()}):
                with self.assertRaises(core.ClientInitError): active.replace(**changes)
            for stage in ('cleanup_verified', 'reconciled'):
                with self.assertRaises(core.ClientInitError): cleanup.replace(stage=stage)
            late = dynamic.DynamicIpRecord('intent', owned, '10.5.0.2', 24, 121.0, baseline_ip)
            with self.assertRaises(core.ClientInitError): active.replace(client_ip=late)
            other = core.Origin(0, 3, 6, owned.name, 8)
            graft = dynamic.DynamicIpRecord('intent', other, '10.5.0.2', 24, 119.0, baseline_ip)
            with self.assertRaises(core.ClientInitError): active.replace(client_ip=graft)
            encoded = codec.encode_journal(active)
            for field, value in (('extra', None), ('local_ip', True), ('prefix', True),
                    ('allocation_until', 119), ('phase', 'invented')):
                bad = json.loads(encoded.decode('ascii')); bad['journal']['client_ip'][field] = value
                with self.assertRaises(codec.JournalCodecError): codec.decode_journal(json.dumps(bad, sort_keys=True).encode('ascii'))

            # Actual base start reaches its first actual Journal constructor,
            # then stops before persistence/registration. Only trial20 is allowed.
            class Clock:
                value = 100.0
                def __call__(self):
                    result = self.value; self.value += .125; return result
            clock, calls = Clock(), []
            class Provider(core.ClientInitProvider):
                def executor(self, deadline): return core.ExecutorProof('owner', executor, True)
                def snapshot(self, deadline): return baseline
                def original_actors(self, snapshot, deadline): return True
                def caps(self, deadline): return object()
            class Store(core.ClientInitStore):
                def acquire(self, identity, deadline, inherited=None): return object()
                def lock_valid(self, locks): return True
                def current(self, locks): return None
                def pending_clear(self, locks): return True
                def prior_clear(self, locks, baseline, deadline): return True
            class StopAfterPrepared(BaseException): pass
            def stop(record): calls.append(record); raise StopAfterPrepared()
            stack.enter_context(mock.patch.object(core, 'client_combo', return_value=None))
            lease = core.ClientInitLease(Provider(), Store(), identity, clock)
            lease._save = stop
            with self.assertRaises(StopAfterPrepared): lease.start(ttl=20)
            self.assertEqual(1, len(calls))
            self.assertEqual(('trial20', 100.0, 120.0),
                (calls[0].session_profile, calls[0].issued_at, calls[0].deadline))
            self.assertGreater(clock.value, 100.0)
            for ttl in (1, 19.0, 20.000001, 300, True):
                with self.assertRaises(core.ClientInitError): lease.start(ttl=ttl)
            print('HOST_SESSION_SCHEMA_V28_ONLY',
                [(name, hashlib.sha256(raw).hexdigest(), len(raw)) for name, raw in originals.items()])


if __name__ == '__main__': unittest.main()
