"""v18 actual schema/codec/Store over FakeIO; no OS/RF/phone admission."""
import ast
import builtins
import copy
import errno
import hashlib
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
sys.path.insert(0, str(BASE / 'runtime'))
from test_durable_client_store import StoreIo
from test_client_files import TOKEN, TARGET, PENDING, RUN
from test_client_journal_codec import baseline as old_baseline

DIRECTORY = BASE / 'candidate/client-durable-association-v18/runtime'
SOURCES = {
    'p011_json': BASE / 'runtime/p011_json.py',
    'mta_ip': BASE / 'runtime/mta_ip.py',
    'mta_client_tmp_alias': BASE / 'candidate/client-tmp-alias-v11/runtime/mta_client_tmp_alias.py',
    'mta_p2p_client_init': DIRECTORY / 'mta_p2p_client_init.py',
    'mta_client_journal_codec': DIRECTORY / 'mta_client_journal_codec.py',
    'mta_client_proc': BASE / 'runtime/mta_client_proc.py',
    'mta_client_coordination': BASE / 'candidate/client-tmp-alias-v11/runtime/mta_client_coordination.py',
    'mta_client_files': BASE / 'candidate/client-tmp-alias-v11/runtime/mta_client_files.py',
    'mta_client_pending': BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_pending.py',
    'mta_client_store': DIRECTORY / 'mta_client_store.py',
}
ORDER = tuple(SOURCES)
MODULES = {}


def scoped_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name in MODULES: return MODULES[name]
    return builtins.__import__(name, globals, locals, fromlist, level)


for _name in ORDER:
    _module = types.ModuleType(_name)
    _module.__file__ = str(SOURCES[_name])
    _module.__dict__['__builtins__'] = dict(vars(builtins), __import__=scoped_import)
    MODULES[_name] = _module
    exec(compile(SOURCES[_name].read_bytes(), str(SOURCES[_name]), 'exec'), _module.__dict__)

core = MODULES['mta_p2p_client_init']
codec = MODULES['mta_client_journal_codec']
store_module = MODULES['mta_client_store']
coord = MODULES['mta_client_coordination']
files = MODULES['mta_client_files']
pending = MODULES['mta_client_pending']
proc = MODULES['mta_client_proc']
json = MODULES['p011_json']
_baseline_scope = dict(old_baseline.__globals__, core=core, ip=MODULES['mta_ip'])
_old_actor = _baseline_scope['actor']
_baseline_scope['actor'] = types.FunctionType(_old_actor.__code__, _baseline_scope, 'actor', _old_actor.__defaults__)
_baseline_scope['STATION'] = core.Origin(0, 1, 22, 'wlan0', 2)
_baseline_scope['RULES'] = tuple(MODULES['mta_ip'].RuleRecord(*tuple(row)) for row in _baseline_scope['RULES'])
baseline = types.FunctionType(old_baseline.__code__, _baseline_scope, 'baseline', old_baseline.__defaults__)
IDENTITY = core.Identity('a' * 64)
LOCAL, BSSID = bytes.fromhex('0266778899aa'), bytes.fromhex('021122334455')


def binding(**changes):
    value = dict(version=1, run_token=TOKEN, candidate_sha=IDENTITY.candidate_sha,
        operation_id='local-operation_1', native_epoch=5, operation_epoch=6,
        gatt_session=7, nonce='2' * 32, receive_consent=True)
    value.update(changes)
    return value


class Reader(object):
    def __init__(self):
        self.actor = core.Actor(123, 300, '/usr/bin/python3', 'b' * 64, ((123, 300, 'S'),))
        self.calls = 0

    def read_self(self):
        self.calls += 1
        return proc.ProcObservation('live_actor', 'synthetic', 'observed', baseline().boot,
            self.actor, False, (), True, 2, (), 12, 12, False, 1)


class Producer(object):
    """Synthetic fresh issuance registry, never a True authorization callback."""
    def __init__(self): self.issued, self.authenticated, self.reuse = [], [], False

    def read_restore(self, store, locks, request, deadline):
        value = (baseline(), core.CloseProof(2, (True, True), (True, True)))
        if self.reuse and self.issued: value = self.issued[-1][3]
        self.issued.append((store, locks, request, value))
        return value

    def authenticate_restore(self, store, locks, request, value, deadline):
        if not any(a is store and b is locks and c is request and d is value for a, b, c, d in self.issued):
            raise ValueError('synthetic unissued')
        self.authenticated.append(value)
        return None


class AssociationTests(unittest.TestCase):
    def setUp(self):
        for cls in (coord._LinuxIo, files._LinuxIo, pending._LinuxIo):
            for name in ('validate', 'open_root', 'open_at', 'fstat', 'stat_at', 'close',
                    'read', 'write', 'fsync', 'seek_start', 'flock', 'rename_at', 'unlink_at'):
                if hasattr(cls, name):
                    patcher = mock.patch.object(cls, name, side_effect=AssertionError('actual OS forbidden'))
                    patcher.start(); self.addCleanup(patcher.stop)
        for name in ('ctypes.CDLL', 'socket.socket', 'subprocess.Popen', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(name, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        patcher = mock.patch.object(proc.ProcReader, 'read_self', side_effect=AssertionError('actual proc forbidden'))
        patcher.start(); self.addCleanup(patcher.stop)

    def make(self, restore=None):
        io, reader = StoreIo(), Reader()
        obj = store_module.DurableClientInitStore(TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock, _restore_reader=restore)
        self.addCleanup(obj.close)
        return obj, io, reader

    def ready(self, restore=None):
        obj, io, reader = self.make(restore)
        locks = obj.acquire(IDENTITY, 3.0)
        rec = obj.commit(locks, core.Journal(IDENTITY, 'prepared', baseline(), 20.0))
        wt = core.Ticket('3' * 32, 'watchdog', rec.baseline.boot, '/usr/bin/python3.5', 'c' * 64)
        wa = core.Actor(201, 100, wt.exe, wt.argv_sha, ((201, 100, 'S'),))
        it = core.InterfaceTicket(rec.baseline.boot, 0, 'mta1234abcd', 2, 33)
        owned = core.Origin(0, 2, 23, it.name, 8)
        ct = core.Ticket('4' * 32, 'controller', rec.baseline.boot, '/private/client-wpa', 'd' * 64)
        ca = core.Actor(202, 100, ct.exe, ct.argv_sha, ((202, 100, 'S'),))
        for change in (dict(stage='watchdog_intent', watchdog_ticket=wt),
                dict(stage='watchdog_saved', watchdog=wa), dict(stage='interface_intent', interface_ticket=it),
                dict(stage='interface_owned', owned=owned), dict(stage='controller_intent', controller_ticket=ct),
                dict(stage='controller_saved', controller=ca), dict(stage='client_init_ready', ready=True)):
            rec = obj.commit(locks, rec.replace(**change))
        return obj, io, reader, locks, rec

    def association(self, reader, phase='intent', **changes):
        options = dict(phase=phase, binding=binding(), executor=reader.actor)
        if phase == 'confirmed': options.update(local_mac=LOCAL, bssid=BSSID, frequency=2412, observed_digest='e' * 64)
        options.update(changes)
        return core.ClientAssociationRecord(**options)

    def intent(self, restore=None):
        obj, io, reader, locks, rec = self.ready(restore)
        rec = obj.commit(locks, rec.replace(association=self.association(reader)))
        return obj, io, reader, locks, rec

    def confirmed(self, restore=None):
        obj, io, reader, locks, rec = self.intent(restore)
        rec = obj.commit(locks, rec.replace(association=self.association(reader, 'confirmed')))
        return obj, io, reader, locks, rec

    def reject(self, action, cls, code=None):
        with self.assertRaises(cls) as caught: action()
        if code is not None: self.assertEqual(code, caught.exception.code)
        for secret in (TOKEN, RUN, 'local-operation_1', 'wlan0', 'private/client-wpa'):
            self.assertNotIn(secret, str(caught.exception))

    def store_reject(self, action, code='invalid_transition'):
        self.reject(action, store_module.DurableStoreError, code)

    def test_pure_constructor_python35_and_unchanged_publish_restore_budget_defs(self):
        obj, io, reader = self.make()
        self.assertEqual([], io.ops); self.assertEqual(0, reader.calls)
        for name in ('mta_p2p_client_init', 'mta_client_journal_codec', 'mta_client_store'):
            tree = ast.parse(SOURCES[name].read_text(encoding='utf-8'), feature_version=(3, 5))
            self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        pairs = ((SOURCES['mta_client_store'], BASE / 'candidate/client-recovery-budget-v8/runtime/mta_client_store.py',
                ('_publish', '_read_exact', '_producer_context', '_fresh_restore', '_authorize_terminal_clear', 'finish')),
            (SOURCES['mta_p2p_client_init'], BASE / 'candidate/client-caps-v7/runtime/mta_p2p_client_init.py', ('_same_journal',)))
        for new, old, names in pairs:
            nodes = lambda path: {n.name: ast.dump(n) for n in ast.walk(ast.parse(path.read_text(encoding='utf-8')))
                if isinstance(n, ast.FunctionDef)}
            left, right = nodes(new), nodes(old)
            for name in names: self.assertEqual(left[name], right[name])
        self.assertEqual((5, 'p2p_client_association'), (core.VERSION, core.KIND))
        self.assertFalse(obj.status()['send_available']); self.assertFalse(obj.status()['receive_available'])

    def test_binding_immutable_copy_and_full_executor_tasks_key(self):
        reader, data = Reader(), binding()
        item = core.ClientAssociationRecord('intent', data, reader.actor)
        data['nonce'] = 'f' * 32; item.binding['operation_id'] = 'changed'
        self.assertEqual('2' * 32, item.binding['nonce']); self.assertEqual('local-operation_1', item.binding['operation_id'])
        with self.assertRaises(AttributeError): item.phase = 'confirmed'
        other = core.Actor(reader.actor.pid, reader.actor.start, reader.actor.exe, reader.actor.argv_sha, ((123, 300, 'R'),))
        self.assertEqual(reader.actor.key(), other.key())
        self.assertNotEqual(item.key(), core.ClientAssociationRecord('intent', binding(), other).key())
        self.assertNotIn(TOKEN, repr(item))

    def test_binding_exact_primitive_schema_and_no_secret_fields(self):
        reader = Reader()
        for changes in (dict(version=True), dict(version=2), dict(run_token='F' * 32), dict(candidate_sha='a' * 63),
                dict(operation_id='bad\n'), dict(operation_id='a' * 129), dict(operation_id='_bad'),
                dict(native_epoch=True), dict(native_epoch=2 ** 53 + 1), dict(operation_epoch=0),
                dict(gatt_session='7'), dict(gatt_session=0xffffffff + 1), dict(nonce='z' * 32),
                dict(receive_consent=1), dict(ssid='not-persisted'), dict(psk='not-persisted')):
            with self.subTest(changes=changes):
                self.reject(lambda: self.association(reader, binding=binding(**changes)), core.ClientInitError, 'invalid_association')
        data = binding(); del data['nonce']
        self.reject(lambda: self.association(reader, binding=data), core.ClientInitError, 'invalid_association')

    def test_phase_mac_frequency_digest_and_invalidated_facts(self):
        reader = Reader()
        for changes in (dict(phase='ready'), dict(local_mac=LOCAL), dict(executor=object()),
                dict(executor=core.Actor(123, 300, reader.actor.exe, reader.actor.argv_sha, ((123, 300, 'Z'),)))):
            self.reject(lambda: self.association(reader, **changes), core.ClientInitError, 'invalid_association')
        for changes in (dict(local_mac=b'\0' * 6), dict(bssid=b'\1' + b'\0' * 5), dict(local_mac=b'12345'),
                dict(frequency=True), dict(frequency=2413), dict(frequency=2483), dict(frequency=5180),
                dict(observed_digest='E' * 64), dict(observed_digest=None)):
            self.reject(lambda: self.association(reader, 'confirmed', **changes), core.ClientInitError, 'invalid_association')
        for freq in (2412, 2417, 2472, 2484): self.assertEqual(freq, self.association(reader, 'confirmed', frequency=freq).frequency)
        for phase in ('intent', 'confirmed'):
            item = self.association(reader, phase); invalid = item.invalidated()
            self.assertEqual(item.key()[1:], invalid.key()[1:]); self.assertEqual('invalidated', invalid.phase)
            self.assertIs(invalid, invalid.invalidated())

    def test_codec_roundtrip_none_intent_confirmed_invalidated_full_private_facts(self):
        obj, _, reader, _, rec = self.ready()
        for item in (None, self.association(reader), self.association(reader, 'confirmed'),
                self.association(reader).invalidated(), self.association(reader, 'confirmed').invalidated()):
            journal = rec.replace(association=item)
            data = codec.encode_journal(journal); rebuilt = codec.decode_journal(data)
            self.assertTrue(core._same_journal(journal, rebuilt)); self.assertEqual(data, codec.encode_journal(rebuilt))
            self.assertLess(len(data), codec.MAX_BYTES); self.assertTrue(all(n < 128 for n in data))
            if item: self.assertEqual(item.executor.tasks, rebuilt.association.executor.tasks)
        self.assertNotIn(b'"psk":', data); self.assertNotIn(b'"ssid":', data)

    def test_codec_v4_envelope_unknown_keys_and_noncanonical_mac_rejected(self):
        _, _, reader, _, rec = self.ready()
        document = json.loads(codec.encode_journal(rec.replace(association=self.association(reader, 'confirmed'))).decode('ascii'))
        for change in (dict(version=4, kind='p2p_client_rf_init_only', marker='p011-client-rf-init-v1-1'), dict(version=True)):
            altered = copy.deepcopy(document); altered.update(change)
            self.reject(lambda: codec.decode_journal(json.dumps(altered, ensure_ascii=True, sort_keys=True).encode('ascii')),
                codec.JournalCodecError, 'unsupported_envelope')
        for location, key, value in (('association', 'ssid', 'secret'), ('binding', 'psk', 'secret'),
                ('association', 'local_mac_hex', LOCAL.hex().upper()), ('association', 'frequency', True)):
            altered = copy.deepcopy(document); row = altered['journal']['association']
            if location == 'binding': row = row['binding']
            row[key] = value
            self.reject(lambda: codec.decode_journal(json.dumps(altered, ensure_ascii=True, sort_keys=True).encode('ascii')),
                codec.JournalCodecError)
        self.assertEqual((131072, 8192, 24), (codec.MAX_BYTES, codec.MAX_NODES, codec.MAX_DEPTH))

    def test_complete_real_store_trace_association_cleanup_finish_three_fresh(self):
        producer = Producer(); obj, io, reader, locks, rec = self.confirmed(producer)
        device = locks._device
        self.assertEqual('confirmed', codec.decode_journal(obj._canonical.data).association.phase)
        invalid = rec.association.invalidated()
        rec = obj.commit(locks, rec.replace(association=invalid))
        rec = obj.commit(locks, rec.replace(stage='cleanup_intent', ready=False))
        rec = obj.commit(locks, rec.replace(stage='cleanup_verified'))
        receipt = obj.finish(locks, rec, True, 50.0)
        self.assertTrue(receipt.complete); self.assertTrue(receipt.record.association.phase == 'invalidated')
        self.assertEqual(3, len(producer.issued)); self.assertEqual(3, len(producer.authenticated))
        self.assertNotIn(PENDING, io.nodes); self.assertIn(TARGET, io.nodes)
        self.assertEqual(device.fd, io.closed[-1]); self.assertEqual(len(io.closed), len(set(io.closed)))
        self.assertFalse(io.handles); self.assertTrue(obj.authenticate_finish(locks, rec, receipt, 51.0))

    def test_store_run_candidate_and_same_f_owner_shape_not_authority(self):
        obj, io, reader, locks, rec = self.ready()
        owner_r = core.Actor(reader.actor.pid, reader.actor.start, reader.actor.exe, reader.actor.argv_sha, ((123, 300, 'R'),))
        written = obj.commit(locks, rec.replace(association=self.association(reader, executor=owner_r)))
        self.assertEqual(owner_r.tasks, written.association.executor.tasks)
        self.assertEqual(reader.actor.key(), written.association.executor.key())
        for changes in (dict(run_token='f' * 32), dict(native_epoch=True)):
            if changes.get('native_epoch') is True: continue  # Constructor matrix covers malformed shape.
            item = core.ClientAssociationRecord('intent', binding(**changes), reader.actor)
            self.store_reject(lambda: obj.commit(locks, rec.replace(association=item)))
        foreign = core.Actor(124, 300, reader.actor.exe, reader.actor.argv_sha, ((124, 300, 'S'),))
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader, executor=foreign))))
        self.reject(lambda: rec.replace(association=self.association(reader, binding=binding(candidate_sha='f' * 64))),
            core.ClientInitError, 'invalid_journal')

    def test_phase_skip_reconfirm_and_same_phase_change_are_rejected(self):
        obj, io, reader, locks, rec = self.ready()
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader, 'confirmed'))))
        rec = obj.commit(locks, rec.replace(association=self.association(reader)))
        same = obj.commit(locks, rec.replace(association=self.association(reader)))
        self.assertTrue(core._same_journal(rec, same))
        rec = obj.commit(locks, same.replace(association=self.association(reader, 'confirmed')))
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader, 'confirmed', observed_digest='f' * 64))))
        rec = obj.commit(locks, rec.replace(association=rec.association.invalidated()))
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader, 'confirmed'))))
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=None)))

    def test_cleanup_requires_invalidated_and_preserves_all_confirmed_history(self):
        obj, io, reader, locks, rec = self.confirmed()
        self.reject(lambda: rec.replace(stage='cleanup_intent', ready=False), core.ClientInitError, 'invalid_journal')
        self.store_reject(lambda: obj.commit(locks, rec.replace(stage='cleanup_intent', ready=False, association=None)))
        invalid = rec.association.invalidated()
        rec = obj.commit(locks, rec.replace(stage='cleanup_intent', ready=False, association=invalid))
        changed = core.ClientAssociationRecord('invalidated', invalid.binding, invalid.executor, LOCAL, BSSID, 2417, 'e' * 64)
        self.store_reject(lambda: obj.commit(locks, rec.replace(stage='cleanup_verified', association=changed)))
        rec = obj.commit(locks, rec.replace(stage='cleanup_verified'))
        self.assertEqual(invalid.key(), codec.decode_journal(obj._canonical.data).association.key())

    def test_persistent_raw_tasks_binding_deadline_origin_and_base_fields_never_rebased(self):
        obj, io, reader, locks, rec = self.intent()
        other = core.Actor(123, 300, reader.actor.exe, reader.actor.argv_sha, ((123, 300, 'R'),))
        for association in (self.association(reader, 'confirmed', executor=other),
                self.association(reader, 'confirmed', binding=binding(operation_id='another'))):
            self.store_reject(lambda: obj.commit(locks, rec.replace(association=association)))
        snap = rec.baseline; actors = list(snap.stock_actors); first = actors[0]
        actors[0] = core.Actor(first.pid, first.start, first.exe, first.argv_sha,
            tuple((pid, start, 'S' if state == 'R' else state) for pid, start, state in first.tasks))
        changed = core.Snapshot(snap.boot, snap.stock_hashes, tuple(actors), snap.station, snap.station_state_sha,
            snap.station_frequency, snap.interfaces, snap.ipv4, snap.ipv6_addresses, snap.ipv6_routes, True)
        for change in (dict(deadline=21.0), dict(baseline=changed),
                dict(owned=core.Origin(0, 99, 23, rec.owned.name, 8))):
            self.store_reject(lambda: obj.commit(locks, rec.replace(**change)))
        clone = codec.decode_journal(codec.encode_journal(rec))
        object.__setattr__(clone.association.executor, 'tasks', other.tasks)
        self.assertFalse(core._same_journal(rec, clone))

    def test_expired_intent_confirmation_blocked_but_exact_cleanup_revocation_does_not_renew(self):
        obj, io, reader, locks, rec = self.ready(); io.clock.value = rec.deadline
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader))), 'expired')
        obj, io, reader, locks, rec = self.intent(); io.clock.value = rec.deadline
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader, 'confirmed'))), 'expired')
        rec = obj.commit(locks, rec.replace(stage='cleanup_intent', ready=False, association=rec.association.invalidated()))
        self.assertEqual(20.0, rec.deadline); self.assertEqual('invalidated', rec.association.phase)

    def test_unknown_publication_retains_one_attempt_inventory_and_pending_no_retry(self):
        obj, io, reader, locks, rec = self.ready()
        before = len([op for op in io.ops if op[0] == 'rename'])
        def fault(fs, operation, path, count):
            if operation == 'fsync' and path == RUN: raise OSError(errno.EIO, 'synthetic private')
        io.hook = fault
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader))), 'component_error')
        after = len([op for op in io.ops if op[0] == 'rename'])
        self.assertEqual(before + 1, after); self.assertTrue(obj._unknown); self.assertIn(PENDING, io.nodes)
        inventory = tuple(obj._files._inventory); io.hook = None
        self.store_reject(lambda: obj.commit(locks, rec.replace(association=self.association(reader))), 'resource_pending')
        self.assertEqual(inventory, tuple(obj._files._inventory))
        self.assertEqual(after, len([op for op in io.ops if op[0] == 'rename']))

    def test_actual_journal_handoff_reacquire_and_current_canonical_identity_kept(self):
        obj, io, reader, locks, rec = self.intent()
        device = locks._device
        closed = obj.active_return(locks, rec); self.assertTrue(closed.complete())
        fresh_locks = obj.acquire(IDENTITY, 3.0, locks)
        self.assertIs(device, fresh_locks._device); self.assertIsNot(locks._journal, fresh_locks._journal)
        self.store_reject(lambda: obj.commit(locks, rec), 'invalid_locks')
        current = obj.current(fresh_locks)
        rec = obj.commit(fresh_locks, current.replace(association=self.association(reader, 'confirmed')))
        self.assertEqual('confirmed', rec.association.phase)
        self.assertIs(obj._canonical._issuer, obj._files._issuer)

    def test_default_producer_and_reused_authenticated_tuple_do_not_clear_marker(self):
        for producer in (None, Producer()):
            if producer is not None: producer.reuse = True
            obj, io, reader, locks, rec = self.confirmed(producer)
            rec = obj.commit(locks, rec.replace(stage='cleanup_intent', ready=False, association=rec.association.invalidated()))
            rec = obj.commit(locks, rec.replace(stage='cleanup_verified'))
            receipt = obj.finish(locks, rec, True, 50.0)
            self.assertFalse(receipt.complete); self.assertIn(PENDING, io.nodes)
            self.assertEqual('invalidated', receipt.record.association.phase)

    def test_base_restore_invalidates_before_fake_child_reap_and_retains_record(self):
        producer = Producer(); obj, io, reader, locks, rec = self.confirmed(producer)
        calls = []
        class Provider(core.ClientInitProvider):
            def __init__(self): self.owned = rec.owned
            def executor(self, deadline): return core.ExecutorProof('owner', reader.actor, True)
            def snapshot(self, deadline):
                value = baseline()
                if self.owned is None: return value
                return core.Snapshot(value.boot, value.stock_hashes, value.stock_actors, value.station,
                    value.station_state_sha, value.station_frequency, value.interfaces + (self.owned,),
                    value.ipv4, value.ipv6_addresses, value.ipv6_routes, True)
            def original_actors(self, value, deadline): return True  # Explicit synthetic Provider only.
            def resolve(self, ticket, deadline):
                calls.append(obj.current(obj._current_locks).association.phase)
                actor = rec.controller if ticket.role == 'controller' else rec.watchdog
                return core.Handle(ticket, actor, object())
            def stop_and_reap(self, handle, deadline): return core.ExitProof(handle.actor, True, (), True, 0)
            def origin_up(self, owned, deadline): return True
            def delete_client(self, owned, deadline): self.owned = None; return True
            def origin_absent(self, owned, deadline): return self.owned is None
            def close_resources(self, handles, deadline): return core.CloseProof(2, (True, True), (True, True))
        obj.active_return(locks, rec)
        lease = core.ClientInitLease(Provider(), obj, IDENTITY, io.clock)
        lease.record, lease.locks = rec, locks
        result = lease.restore()
        self.assertTrue(result['cleanup_complete']); self.assertEqual(['invalidated', 'invalidated'], calls)
        self.assertEqual('invalidated', lease.record.association.phase)
        self.assertTrue(lease.finish_receipt.complete); self.assertNotIn(PENDING, io.nodes)


if __name__ == '__main__': unittest.main()
