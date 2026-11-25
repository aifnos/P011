"""v19 only: actual private typed graph/Store/reader code over FakeIO.

Saved init actors and successful init are synthetic fixture assumptions, not
OS, RF, association, restoration or production acceptance.
"""
import ast
import builtins
import errno
import hashlib
import json
import stat
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'tests'))
import test_client_association_mac_v16 as fixtures
import test_client_journal_codec as journals
import test_client_linux_provider as observer_fixture
import test_client_pending as pending_fixture

ROOT = BASE / 'candidate/client-durable-connect-v19/runtime'
V18 = BASE / 'candidate/client-durable-association-v18/runtime'
PINS = {
    'mta_p2p_client_init': (V18 / 'mta_p2p_client_init.py', 'b255e3ac01ae5c39e19b611493da2ddd71115f6afac80732565d012fa72511b4'),
    'mta_client_journal_codec': (V18 / 'mta_client_journal_codec.py', 'a4ddb4691c78bbb1bdc8727a432ca4d6a72dcfe33e7f67ac606f0ced247a86d1'),
    'mta_client_store': (V18 / 'mta_client_store.py', '5ee1c184c3511bc3072e87409a88861713bfd249d79584df1d50fc1377964426'),
    'mta_client_kernel_proof': (BASE / 'candidate/client-association-v16/runtime/mta_client_kernel_proof.py', '4ebfedf198673e3bad2f64a4bd72c581e5d6af24cef83e589b4456d2a38f8ede')}


def graph():
    """Reject missing mta imports; never fall back to the mutable runtime."""
    rows = json.loads((BASE / 'host/client_kernel_connect_v15_source_manifest.json').read_text(encoding='utf-8'))['sources']
    result, real_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name in result: return result[name]
        if name.startswith('mta_') or name == 'p011_json': raise ImportError('unavailable private module')
        return real_import(name, *args, **kwargs)
    for row in rows:
        name = row['module']
        if name in PINS: path, digest = PINS[name]
        elif name in ('mta_client_connection', 'mta_client_linux_provider', 'mta_client_executor'):
            path, digest = ROOT / (name + '.py'), None
        else: path, digest = BASE / row['path'], row['sha256']
        raw = path.read_bytes()
        if digest is not None and hashlib.sha256(raw).hexdigest() != digest: raise ValueError('source pin mismatch')
        namespace = dict(vars(builtins)); namespace['__import__'] = private_import
        module = types.ModuleType(name); module.__file__ = str(path); module.__builtins__ = namespace
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        result[name] = module
    return result


M = graph()
p, c, f = (M[n] for n in ('mta_client_linux_provider', 'mta_client_connection', 'mta_client_executor'))
core, frame, k = (M[n] for n in ('mta_p2p_client_init', 'mta_client_control_frame', 'mta_client_kernel_proof'))
old = fixtures.old.old
clone = fixtures.fixture
LOCAL, BSSID = fixtures.LOCAL, fixtures.old.BSSID
OWNED = core.Origin(*old.OWNED.key())
IDENTITY = core.Identity('a' * 64)
ARGV = fixtures.old.ARGV
SELF = core.Actor(123, 300, '/usr/bin/python3', hashlib.sha256(ARGV).hexdigest(), ((123, 300, 'S'),))
actor = clone(journals.actor, {'core': core})
baseline = clone(journals.baseline, {'core': core, 'ip': M['mta_ip'], 'actor': actor,
    'STATION': core.Origin(*journals.STATION.key()),
    'RULES': tuple(M['mta_ip'].RuleRecord(*r) for r in journals.RULES)})
manifest = clone(fixtures.manifest, {'p': p})
info = clone(old.info, {'protocol': M['mta_protocol']})


class ClosedProc(observer_fixture.ClosedProc):
    observation = clone(observer_fixture.ClosedProc.observation, {'core': core, 'proc': M['mta_client_proc']})


class Proc(ClosedProc):
    def __init__(self, io, **kwargs): self.io = io; ClosedProc.__init__(self, io, **kwargs)
    def read_self(self): return self.observation(SELF)
    def read_actor(self, pid, expected=None):
        if pid == 300 and not self.io.actor_alive: raise OSError(errno.ESRCH, 'HOST')
        return self.observation(expected)


class Reader(pending_fixture.Reader):
    read_self = clone(pending_fixture.Reader.read_self, {'proc': M['mta_client_proc']})
    def __init__(self): pending_fixture.Reader.__init__(self); self.actor = SELF; self.boot = baseline().boot


class Collector(observer_fixture.Collector):
    def __init__(self, provider, timeout):
        self.p, self._io, self._tickets, self.status_readers = provider, provider._io, [], []
        self._reader = ClosedProc(provider._io); self._ended = False
    collect = clone(observer_fixture.Collector.collect, {'core': core})


class CtrlSock(old.CtrlSock):
    send = clone(old.CtrlSock.send, {'p': p})


class Io(old.Io):
    def new_ctrl(self):
        path = old.RUN + '/HOST-ctrl-' + str(len(self.sockets))
        self.add(path, stat.S_IFSOCK | 0o600)
        value = CtrlSock(self, self._open(path, 0, 0), 'ctrl'); self.sockets.append(value)
        return value
    def pid(self): return SELF.pid


def binding():
    return frame.ControlBinding({'version': 1, 'run_token': old.TOKEN, 'candidate_sha': 'a' * 64,
        'operation_id': 'synthetic-v19-operation', 'native_epoch': 8, 'operation_epoch': 100000001,
        'gatt_session': 12, 'nonce': '3' * 32, 'receive_consent': True})


class DurableConnectV19Tests(unittest.TestCase):
    def setUp(self):
        p._OWNERS[:] = []
        self.addCleanup(lambda: p._OWNERS.__setitem__(slice(None), []))
        for target in ('socket.socket', 'subprocess.Popen', 'ctypes.CDLL', 'os.open', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('mta_client_coordination', 'mta_client_files', 'mta_client_pending'):
            patcher = mock.patch.object(M[name]._LinuxIo, 'open_root', side_effect=AssertionError('actual root forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
    def make(self, kernel_rows=None):
        io, reader, bound = Io(), Reader(), binding()
        store = M['mta_client_store'].DurableClientInitStore(old.TOKEN, IDENTITY, _coordination_io=io,
            _files_io=io, _pending_io=io, _proc_reader=reader, _clock=io.clock)
        self.addCleanup(store.close)
        provider = p.LinuxClientInitProvider(manifest(), _io=io, _clock=io.clock,
            _proc_factory=lambda **kw: Proc(io, **kw), _collector_factory=Collector, _connect_binding=bound)
        owner = M['mta_client_process_owner'].DirectChildOwner(_clock=io.clock)
        bridge = p.LinuxDirectChildLaunchBridge(store, owner, provider.specs(), provider)
        lease = p.LinuxClientInitLease(provider, store, IDENTITY, io.clock, bridge); provider.attach(store, owner, bridge, lease)
        locks = store.acquire(IDENTITY, 3)
        base = baseline(); journal = store.commit(locks, core.Journal(IDENTITY, 'prepared', base, 10))
        tickets, actors = {}, {}
        for role, pid in (('watchdog', 200), ('controller', 300)):
            spec = bridge.specs[role]
            tickets[role] = core.Ticket(('1' if role == 'watchdog' else '2') * 32, role, base.boot, spec.exe, spec.argv_sha)
            actors[role] = core.Actor(pid, 30, spec.exe, spec.argv_sha, ((pid, 30, 'S'),))
            child = owner.register(spec, locks._device.fd, 10); child.postexec, child.pid = actors[role], pid
            lease.handles[role] = core.Handle(tickets[role], actors[role], child)
        interface = core.InterfaceTicket(base.boot, 0, OWNED.name, 1, 900)
        for change in (dict(stage='watchdog_intent', watchdog_ticket=tickets['watchdog']),
                dict(stage='watchdog_saved', watchdog=actors['watchdog']), dict(stage='interface_intent', interface_ticket=interface),
                dict(stage='interface_owned', owned=OWNED), dict(stage='controller_intent', controller_ticket=tickets['controller']),
                dict(stage='controller_saved', controller=actors['controller']), dict(stage='client_init_ready', ready=True)):
            journal = store.commit(locks, journal.replace(**change))
        provider._tickets, provider._owned = tickets, OWNED
        provider._self, provider._boot, provider._baseline_record = SELF, base.boot, base
        provider.fake_snapshot = core.Snapshot(base.boot, base.stock_hashes, base.stock_actors, base.station,
            base.station_state_sha, base.station_frequency, base.interfaces + (OWNED,), base.ipv4,
            base.ipv6_addresses, base.ipv6_routes, base.station_completed)
        provider._kernel.interfaces = lambda deadline: (() if io.changed_origin else provider.fake_snapshot.interfaces)
        provider._anchors(3)
        provider._ctrl = provider._ledger.sock(io.new_ctrl); provider._ctrl_setup = True
        raw = provider._ctrl.value; raw.setsockopt(1, 16, 1)
        local = b'\0p011-client-' + old.TOKEN.encode(); raw.bind(local)
        endpoint = provider.manifest.ctrl_dir + '/' + OWNED.name; raw.connect(endpoint)
        provider._ctrl_endpoint = (endpoint, p.baseline._metadata(io.stat(endpoint)), local)
        lease.record, lease.locks = journal, locks
        store.active_return(locks, journal); self.addCleanup(provider._ledger.close_all)
        decoder = frame.ControlFrameDecoder(bound); decoder.feed(frame.encode_connect(bound, info()))
        request = decoder.take_connect()
        kernels, rawcaps = [], []
        def kernel_factory(*args, **kwargs):
            values = kernel_rows(len(kernels)) if callable(kernel_rows) else kernel_rows
            actual_io = fixtures.old.KernelIo(fixtures.packets() if values is None else values)
            actual = k.ClientKernelReader(*args, _io=actual_io,
                _proc_factory=lambda **kw: M['mta_client_proc'].ProcReader(_fs=fixtures.old.proc_fs(), **kw), **kwargs)
            kernels.append((actual, actual_io)); return actual
        def genl():
            path = old.RUN + '/kernel-caps-' + str(len(rawcaps)); io.add(path, stat.S_IFSOCK | 0o600)
            raw = fixtures.old.CapsSocket(io, fixtures.old.caps_packets(), io._open(path, 0, 0))
            rawcaps.append(raw); return raw
        provider._kernel_factory, io.new_genl = kernel_factory, genl
        return lease, provider, store, io, request, kernels, rawcaps
    def connect(self, lease, request, checkpoint=None):
        return lease.connect_p2p(request, _checkpoint=checkpoint or (lambda: False))
    def assert_revoked(self, provider):
        self.assertIsNone(provider._active_association_receipt)
        self.assertTrue(provider._connection.receipt_invalidated)
        self.assertFalse(provider.status()['receive_available'])
    def test_intent_actual_cas_before_attach_confirmed_canonical_no_secrets(self):
        lease, provider, store, io, request, kernels, caps = self.make(); phases = []
        def command(raw, wire):
            phase = lease.record.association.phase; phases.append((wire, phase))
            self.assertIsNone(store._canonical_valid(store._canonical, lease.record))
        io.command_hook = command
        observed = self.connect(lease, request); receipt = provider._connection.receipt
        self.assertIs(type(observed), c.ConnectionObservation); self.assertIs(type(receipt), c.AssociationReceipt)
        self.assertTrue(phases); self.assertTrue(all(phase == 'intent' for wire, phase in phases))
        self.assertEqual(b'ATTACH', phases[0][0]); self.assertEqual('confirmed', lease.record.association.phase)
        self.assertIs(receipt._binding, request.binding); self.assertIs(receipt._record, lease.record)
        self.assertEqual(hashlib.sha256(store._canonical.data).hexdigest(), receipt.receipt_id)
        self.assertEqual((LOCAL, BSSID, 2412), (lease.record.association.local_mac, lease.record.association.bssid, lease.record.association.frequency))
        self.assertEqual(lease.record.association.observed_digest, c._observation_digest(observed))
        for secret in (old.SSID, b'fixture-passphrase', b'P2P-GROUP-STARTED', b'wpa_state=COMPLETED'):
            self.assertNotIn(secret, store._canonical.data)
        self.assertEqual(2, len(kernels)); self.assertEqual(2, len(caps)); self.assertFalse(receipt.public_summary()['dhcp_proof_issued'])
    def test_exact_request_and_binding_only_no_info_or_copied_binding_authority(self):
        for mode in ('info', 'dict', 'binding_copy', 'unclaimed'):
            with self.subTest(mode=mode):
                lease, provider, store, io, request, _, _ = self.make()
                value = info() if mode == 'info' else {} if mode == 'dict' else request
                if mode == 'binding_copy':
                    decoder = frame.ControlFrameDecoder(frame.ControlBinding(request.binding.private_metadata()))
                    decoder.feed(frame.encode_connect(decoder._binding, info())); value = decoder.take_connect()
                if mode == 'unclaimed': value = frame.ConnectRequest(request._decoder, request._info_wire)
                with self.assertRaises(Exception): self.connect(lease, value)
                self.assertFalse(any(raw.sent for raw in io.sockets)); self.assertEqual(1, len(io.sockets))
                self.assertIs(provider._connection_creation['request'], value)
                with self.assertRaises(c.ConnectionError): self.connect(lease, request)
                self.assertIsNone(lease.record.association)
    def test_fresh_receipt_reissues_not_confirmed_cas_old_receipt_cannot_replay(self):
        lease, provider, store, _, request, kernels, _ = self.make(); self.connect(lease, request)
        first = provider._connection.receipt; generation = store._files._generation
        second = lease.read_association_receipt(first)
        self.assertIsNot(second, first); self.assertEqual(second.receipt_id, first.receipt_id)
        self.assertEqual(generation, store._files._generation); self.assertEqual(4, len(kernels))
        self.assertIs(provider._active_association_receipt, second)
        with self.assertRaises(c.ConnectionError) as raised: lease.read_association_receipt(first)
        self.assertEqual('receipt_stale', raised.exception.code); self.assertIs(provider._active_association_receipt, second)
        self.assertFalse(provider._connection.failed)
        self.assertLessEqual(len(store._files._inventory), 256)
    def test_once_context_original_registered_and_cleared_after_sync_transaction(self):
        lease, provider, _, _, request, _, _ = self.make(); self.connect(lease, request)
        operation = provider._connection; ticket = provider._association_receipts[0]; context = ticket['context']
        self.assertTrue(context['consumed']); self.assertIs(context['operation'], operation)
        self.assertIsNone(operation._receipt_transaction); self.assertIsNone(provider._connection_last_context)
        self.assertIsNone(provider._connection_issued_context)
        for copied in (context, dict(context)):
            provider._connection_last_context = copied
            with self.assertRaises(c.ConnectionError): provider._issue_association_receipt(operation, operation.result)
            self.assertIsNone(provider._connection_last_context); self.assertIsNone(provider._connection_issued_context)
        self.assertEqual(1, len(provider._association_receipts))
        self.assertIs(provider._active_association_receipt, operation.receipt)
    def test_context_after_cancellation_cannot_reissue_and_raw_tickets_remain(self):
        lease, provider, _, _, request, _, _ = self.make(); self.connect(lease, request)
        operation = provider._connection; original = provider._association_receipts[0]
        provider.request_stop()
        self.assert_revoked(provider); self.assertIsNone(provider._connection_last_context)
        self.assertIsNone(provider._connection_issued_context)
        with self.assertRaises(c.ConnectionError): lease.read_association_receipt(original['receipt'])
        self.assertIs(provider._association_receipts[0], original)
    def test_constructed_receipt_not_registered_cannot_steal_current(self):
        lease, provider, store, _, request, _, _ = self.make(); observed = self.connect(lease, request)
        current = provider._connection.receipt
        fake = c.AssociationReceipt(provider, provider._connection, observed, store._canonical, current._generation)
        with self.assertRaises(c.ConnectionError): lease.read_association_receipt(fake)
        self.assertIs(provider._active_association_receipt, current)
        with self.assertRaises(AttributeError): current.receipt_id = '0' * 64
        self.assertNotIn(old.SSID.decode(), repr(current))
    def test_changed_journal_epoch_rejects_current_receipt_and_revokes(self):
        lease, provider, store, _, request, _, _ = self.make(); self.connect(lease, request)
        receipt = provider._connection.receipt; store._journal_epoch = object()
        with self.assertRaises(c.ConnectionError): lease.read_association_receipt(receipt)
        self.assert_revoked(provider); self.assertIs(provider._association_receipts[0]['receipt'], receipt)
    def test_changed_canonical_bytes_or_identity_never_rebased(self):
        lease, provider, store, io, request, _, _ = self.make(); self.connect(lease, request)
        receipt = provider._connection.receipt; current = store._canonical
        io.nodes[old.RUN + '/journal.json'].data += b' '
        with self.assertRaises(Exception): lease.read_association_receipt(receipt)
        self.assert_revoked(provider); self.assertIs(store._canonical, current)
        self.assertTrue(store._unknown); self.assertIn(old.RUN + '/journal.json', io.nodes)
    def test_fresh_local_mac_change_retains_new_observation_and_revokes(self):
        lease, provider, _, io, request, kernels, _ = self.make(kernel_rows=lambda n:
            fixtures.packets((LOCAL if n < 2 else fixtures.CHANGED,) * 3))
        self.connect(lease, request); receipt = provider._connection.receipt
        io.status_wire = old.CONNECTED.replace(b'address=02:66:77:88:99:aa', b'address=02:66:77:88:99:ab')
        with self.assertRaises(c.ConnectionError) as raised: lease.read_association_receipt(receipt)
        self.assertEqual('kernel_mismatch', raised.exception.code); self.assert_revoked(provider)
        self.assertEqual(2, len(provider._connection.observations)); self.assertEqual(4, len(kernels))
        self.assertEqual('confirmed', lease.record.association.phase)
    def test_disconnected_event_after_confirmed_synchronously_revokes(self):
        lease, provider, _, io, request, _, _ = self.make(); self.connect(lease, request)
        receipt = provider._connection.receipt
        io.sockets[1].queue.append((b'<3>CTRL-EVENT-DISCONNECTED bssid=02:aa:bb:cc:dd:ee reason=3 locally_generated=1',
            [(1, 2, p._CRED.pack(300, 0, 0))], 0, io.sockets[1].peer))
        with self.assertRaises(c.ConnectionError): lease.read_association_receipt(receipt)
        self.assert_revoked(provider); self.assertEqual('confirmed', lease.record.association.phase)
    def test_cancel_during_confirmed_commit_no_receipt_or_later_commands(self):
        lease, provider, store, io, request, _, _ = self.make(); cancelled = [False]
        original, calls = store.commit, []
        def commit(locks, journal):
            returned = original(locks, journal); calls.append(returned)
            if returned.association is not None and returned.association.phase == 'confirmed': cancelled[0] = True
            return returned
        store.commit = commit
        with self.assertRaises(c.ConnectionError) as raised: self.connect(lease, request, lambda: cancelled[0])
        self.assertEqual('cancelled', raised.exception.code); self.assert_revoked(provider)
        self.assertEqual('confirmed', lease.record.association.phase); self.assertIs(lease.record, calls[-1])
        self.assertFalse(provider._association_receipts); self.assertEqual(2, io.sockets[0].sent.count(b'STATUS'))
    def test_disconnect_persists_invalidated_before_actual_command_same_deadline(self):
        lease, provider, _, io, request, _, _ = self.make(); self.connect(lease, request)
        deadline, checks = lease.record.deadline, []
        def hook(raw, wire):
            if wire == b'DISCONNECT': checks.append((lease.record.association.phase, provider._active_association_receipt))
        io.command_hook = hook
        self.assertTrue(lease.disconnect_p2p()['disconnect_observed'])
        self.assertEqual([('invalidated', None)], checks); self.assertEqual(deadline, lease.record.deadline)
        self.assert_revoked(provider)
    def test_restore_intent_invalidates_even_when_original_child_cleanup_unavailable(self):
        lease, provider, _, _, request, _, _ = self.make(); self.connect(lease, request)
        receipt = provider._connection.receipt
        def unavailable(*args): raise OSError(errno.EIO, 'synthetic cleanup unavailable')
        provider._bridge.cleanup = unavailable
        restored = lease.restore(); self.assertFalse(restored['cleanup_complete']); self.assert_revoked(provider)
        self.assertEqual('cleanup_intent', lease.record.stage); self.assertEqual('invalidated', lease.record.association.phase)
        self.assertFalse(lease.cleanup_complete); self.assertIs(provider._association_receipts[0]['receipt'], receipt)
    def test_deadline_does_not_renew_and_intent_write_unknown_has_zero_commands(self):
        lease, provider, store, io, request, _, _ = self.make(); original = store.commit
        def unknown(locks, journal):
            returned = original(locks, journal)
            if returned.association is not None: raise OSError(errno.EIO, 'post durable return unknown')
            return returned
        store.commit = unknown
        with self.assertRaises(Exception): self.connect(lease, request)
        self.assertFalse(any(raw.sent for raw in io.sockets)); self.assertIsNotNone(store._canonical.journal.association)
        self.assert_revoked(provider); self.assertEqual(10, lease.record.deadline)
        lease2, provider2, _, io2, request2, _, _ = self.make(); io2.clock.value = 10
        with self.assertRaises(Exception): self.connect(lease2, request2)
        self.assertFalse(any(raw.sent for raw in io2.sockets)); self.assertEqual(10, lease2.record.deadline)
    def test_executor_passes_exact_loader_binding_and_claimed_request_source(self):
        source = (ROOT / 'mta_client_executor.py').read_text(encoding='utf-8')
        prior = (BASE / 'candidate/client-kernel-connect-v15/runtime/mta_client_executor.py').read_text(encoding='utf-8')
        replacements = (("creator(self.deployment.manifest, _connect_binding=binding)", "creator(self.deployment.manifest)"),
            ("'binding': binding, 'operation_epoch': None, 'returned': None, 'unknown': True}",
             "'info': None, 'operation_epoch': None, 'returned': None, 'unknown': True}\n                            info = request.private_info(); self.connection_ticket['info'] = info"),
            ("                            result = creator(request, _checkpoint=self._cancelled)",
             "                            result = creator(info, _checkpoint=self._cancelled,\n                                _operation_epoch=epoch)"))
        for new, old_value in replacements:
            self.assertEqual(1, source.count(new)); source = source.replace(new, old_value, 1)
        self.assertEqual(prior, source)
        self.assertEqual(24, len(M)); self.assertEqual(tuple(M), f.MODULES)
        self.assertIs(p.core, core); self.assertIs(M['mta_client_store'].core, core); self.assertIs(c.frame, frame)
        self.assertFalse(p.LinuxClientInitProvider().status()['send_available'])
    def test_ast35_restore_other_gates_and_digest_has_no_fallback(self):
        for path in (ROOT / 'mta_client_executor.py', ROOT / 'mta_client_connection.py', ROOT / 'mta_client_linux_provider.py', Path(__file__)):
            ast.parse(path.read_text(encoding='utf-8'), feature_version=(3, 5))
        original = ast.parse((BASE / 'candidate/client-kernel-connect-v15/runtime/mta_client_linux_provider.py').read_text(encoding='utf-8'))
        current = ast.parse((ROOT / 'mta_client_linux_provider.py').read_text(encoding='utf-8'))
        altered = {'__init__', '_connection_context', '_connection_exchange', 'request_stop', 'connect_p2p', 'restore'}
        for node in original.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                new = next(v for v in current.body if type(v) is type(node) and v.name == node.name)
                if isinstance(node, ast.FunctionDef) and node.name != 'assemble': self.assertEqual(ast.dump(node), ast.dump(new), node.name)
                elif isinstance(node, ast.ClassDef):
                    for method in node.body:
                        if isinstance(method, ast.FunctionDef) and method.name not in altered:
                            actual = next(v for v in new.body if isinstance(v, ast.FunctionDef) and v.name == method.name)
                            self.assertEqual(ast.dump(method), ast.dump(actual), (node.name, method.name))
        with self.assertRaises(c.ConnectionError): c._facts_tree(object())


if __name__ == '__main__': unittest.main()
