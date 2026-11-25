"""HOST fake-kernel/socket QA only; no real TCP, P011, RF, journal or IP lease."""
import ast
import errno
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime'))
import mta_scoped_sockets as scoped

LOCAL, PEER, PORT = '192.168.77.2', '192.168.77.1', 8899
IFNAME, IFINDEX = 'mta_scope_host', 91


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class FakeSocket:
    """Explicit fake syscall contract; never a platform/socket acceptance result."""
    family = socket.AF_INET

    def __init__(self, number=0):
        self.options = {(socket.SOL_SOCKET, socket.SO_TYPE): int(socket.SOCK_STREAM),
                        (socket.SOL_SOCKET, socket.SO_ACCEPTCONN): 0,
                        (socket.SOL_SOCKET, socket.SO_LINGER): b'\0' * 8,
                        (socket.SOL_SOCKET, socket.SO_REUSEADDR): 0,
                        (socket.SOL_SOCKET, scoped.SO_REUSEPORT): 0,
                        (socket.SOL_SOCKET, socket.SO_ERROR): 0}
        self.number = number
        self.inheritable = True
        self.closed = False
        self.detached = False
        self.close_fails = False
        self.timeout = None
        self.address = None
        self.peer = None
        self.requested_peer = None
        self.connect_result = 0
        self.calls = []
        self.fail_at = None
        self.hook = None
        self.overrides = {}

    def step(self, name):
        self.calls.append(name)
        if self.hook:
            self.hook(name)
        if self.fail_at == name:
            raise OSError('HOST_PRIVATE_OS_TEXT')

    def set_inheritable(self, value):
        self.step('set_inheritable')
        self.inheritable = value

    def get_inheritable(self):
        self.step('get_inheritable')
        return self.inheritable

    def setsockopt(self, level, option, value):
        self.step('setsockopt')
        self.calls.append(('setsockopt', level, option, value))
        self.options[level, option] = value

    def getsockopt(self, level, option, size=None):
        self.step('getsockopt')
        return self.overrides.get((level, option), self.options.get((level, option), 0))

    def bind(self, address):
        self.step('bind')
        self.address = (address[0], address[1] or (40000 + self.number))

    def getsockname(self):
        self.step('getsockname')
        return self.address

    def getpeername(self):
        self.step('getpeername')
        if self.peer is None:
            raise OSError(errno.ENOTCONN, 'HOST_NOT_CONNECTED')
        return self.peer

    def setblocking(self, value):
        self.step('setblocking')
        self.timeout = None if value else 0.0

    def settimeout(self, value):
        self.step('settimeout')
        self.timeout = value

    def gettimeout(self):
        self.step('gettimeout')
        return self.timeout

    def connect_ex(self, peer):
        self.step('connect_ex')
        self.requested_peer = peer
        if self.connect_result == 0:
            self.peer = peer
        return self.connect_result

    def fileno(self):
        self.calls.append('fileno')
        return -1 if self.closed or self.detached else 100 + self.number

    def close(self):
        self.step('close')
        if self.close_fails:
            raise OSError('HOST_CLOSE_UNKNOWN')
        self.closed = True


class ScopedSocketTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.index = IFINDEX
        self.cancel = False
        self.owner_lock = threading.RLock()
        self.proof_values = {}
        self.proof_hook = None
        self.proof_calls = []
        self.sockets = []
        self.factory_calls = []
        self.factory_hook = None
        self.socket_hook = None
        self.polls = []
        self.poll_hook = None
        self.capsules = []

    def tearDown(self):
        # Test teardown does not forge a transport closed proof.
        for capsule in self.capsules:
            capsule.close()

    def context(self, mode='go', **values):
        result = scoped.OwnedContext('11111111-2222-3333-4444-555555555555', 7, 4,
            1, 0x100000001, IFINDEX, IFNAME, mode, LOCAL, 24, 120.0, 'a' * 64)
        return result._replace(**values)

    def proof(self, context, purpose, budget):
        self.proof_calls.append((context, purpose, budget))
        if self.proof_hook:
            self.proof_hook(context, purpose, budget)
        client = context.mode == 'client'
        result = scoped.ScopeProof(context, 'confirmed', True, True, True, True, True,
            client, client, client, self.capsule.endpoint if client else None)
        return result._replace(**self.proof_values)

    def factory(self, *args):
        self.factory_calls.append(args)
        if self.factory_hook:
            return self.factory_hook(*args)
        raw = FakeSocket(len(self.sockets))
        raw.hook = self.socket_hook
        self.sockets.append(raw)
        return raw

    def select_ready(self, readers, writers, errors, timeout):
        self.polls.append((readers, writers, errors, timeout))
        self.clock.now += timeout
        if self.poll_hook:
            return self.poll_hook(readers, writers, errors, timeout)
        writers[0].peer = writers[0].requested_peer
        return ([], writers, [])

    def make(self, mode='go', **values):
        options = dict(context=self.context(mode), proof_callback=self.proof,
            cancelled=lambda: self.cancel, ownership_lock=self.owner_lock,
            endpoint=scoped.PeerEndpoint(PEER, PORT, 'b' * 64) if mode == 'client' else None,
            clock=self.clock, socket_factory=self.factory, raw_socket_type=FakeSocket,
            if_nametoindex=lambda name: self.index, select_ready=self.select_ready)
        options.update(values)
        self.capsule = scoped.ScopedDataSockets(**options)
        self.capsules.append(self.capsule)
        return self.capsule

    def opened(self, mode='go', port=0):
        capsule = self.make(mode)
        raw = (capsule.listener_factory(LOCAL, port) if mode == 'go' else
               capsule.socket_factory(PEER, PORT, 3))
        return capsule, raw

    def closed_proof(self, context, raw, budget):
        return scoped.TransportClosedProof(context, raw, True, True)

    def test_listener_exact_bound_unconnected_nonlistening_raw_and_no_reuse(self):
        capsule, raw = self.opened()
        self.assertIs(raw, self.sockets[0])
        self.assertEqual(raw.getsockname(), (LOCAL, 40000))
        self.assertIsNone(raw.peer)
        self.assertNotIn('connect_ex', raw.calls)
        self.assertEqual([call for call in raw.calls if isinstance(call, tuple)],
            [('setsockopt', socket.SOL_SOCKET, 25, IFNAME.encode() + b'\0')])
        self.assertEqual(self.factory_calls, [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)])
        self.assertEqual(capsule.status()['handoffs_pending'], 1)
        self.assertFalse(capsule.status()['peer_authorized'])

    def test_listener_fixed_requested_port_is_read_back(self):
        capsule, raw = self.opened(port=8888)
        self.assertEqual(raw.getsockname(), (LOCAL, 8888))
        self.assertFalse(capsule.close())

    def test_go_listener_does_not_need_station_dhcp_or_first_peer(self):
        capsule, raw = self.opened()
        self.assertTrue(self.proof_calls)
        self.assertTrue(all(purpose == 'listener' for _, purpose, _ in self.proof_calls))
        self.assertFalse(capsule.status()['peer_authorized'])
        self.assertFalse(raw.closed)

    def test_connector_exact_source_peer_and_real_ephemeral_port(self):
        capsule, raw = self.opened('client')
        self.assertEqual(raw.getsockname(), (LOCAL, 40000))
        self.assertEqual(raw.getpeername(), (PEER, PORT))
        self.assertEqual(raw.requested_peer, (PEER, PORT))
        self.assertTrue(0 < raw.timeout <= 3)
        self.assertFalse(capsule.close())
        self.assertFalse(raw.closed)

    def test_two_receiver_calls_keep_same_context_endpoint_and_binding(self):
        capsule, first = self.opened('client')
        second = capsule.socket_factory(PEER, PORT, 3)
        self.assertIsNot(first, second)
        self.assertEqual(first.getpeername(), second.getpeername())
        self.assertEqual(capsule.status()['handoffs_pending'], 2)
        self.assertTrue(all(context is capsule.context for context, _, _ in self.proof_calls))
        self.assertEqual(first.options[socket.SOL_SOCKET, 25], second.options[socket.SOL_SOCKET, 25])

    def test_pending_nonblocking_connect_polls_are_bounded(self):
        self.factory_hook = lambda *args: self.pending_socket()
        capsule = self.make('client')
        raw = capsule.socket_factory(PEER, PORT, 3)
        self.assertEqual(len(self.polls), 1)
        self.assertLessEqual(self.polls[0][3], scoped.POLL_SECONDS)
        self.assertEqual(raw.getpeername(), (PEER, PORT))

    def pending_socket(self):
        raw = FakeSocket(len(self.sockets))
        raw.connect_result = errno.EINPROGRESS
        raw.hook = self.socket_hook
        self.sockets.append(raw)
        return raw

    def test_missing_durable_receipt_or_full_readback_never_creates_socket(self):
        for field in ('receipt_fsynced', 'persistent_readback_verified', 'owner_verified',
                      'address_verified', 'route_baseline_verified'):
            for value in (False, None, 1):
                with self.subTest(field=field, value=value):
                    self.proof_values = {field: value}
                    capsule = self.make()
                    with self.assertRaisesRegex(scoped.ScopedSocketError, '^owned_scope_unverified$'):
                        capsule.listener_factory(LOCAL, 0)
                    self.assertTrue(capsule.close())
        self.assertFalse(self.factory_calls)

    def test_deleting_restored_or_recorded_receipt_is_not_data_authority(self):
        for stage in ('delete_intent', 'restored', 'receipt_recorded', 'create_intent', None):
            with self.subTest(stage=stage):
                self.proof_values = {'receipt_stage': stage}
                capsule = self.make()
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^owned_scope_unverified$'):
                    capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_generic_boolean_proof_cannot_create_socket(self):
        capsule = self.make(proof_callback=lambda *args: True)
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^owned_scope_unverified$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_equal_but_different_context_does_not_match_owner_identity(self):
        capsule = self.make()
        self.proof_values = {'context': capsule.context._replace()}
        self.assertIsNot(self.proof_values['context'], capsule.context)
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^owned_scope_unverified$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_ifindex_reuse_or_truthy_index_fails_before_create(self):
        for value in (92, True, '91'):
            with self.subTest(value=value):
                self.index = value
                capsule = self.make()
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^owned_scope_unverified$'):
                    capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_client_requires_real_association_dhcp_peer_and_exact_endpoint_proof(self):
        for field in ('client_association_verified', 'dhcp_verified', 'peer_verified'):
            with self.subTest(field=field):
                self.proof_values = {field: False}
                capsule = self.make('client')
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^client_peer_unverified$'):
                    capsule.socket_factory(PEER, PORT, 3)
        self.proof_values = {}
        capsule = self.make('client')
        self.proof_values = {'endpoint': capsule.endpoint._replace()}
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^client_peer_unverified$'):
            capsule.socket_factory(PEER, PORT, 3)
        self.assertFalse(self.factory_calls)

    def test_go_proof_cannot_be_used_to_claim_peer_authority(self):
        capsule = self.make()
        self.proof_values = {'peer_verified': True}
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^go_listener_not_peer_authority$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_owned_context_and_endpoint_are_immutable(self):
        capsule = self.make('client')
        with self.assertRaises(AttributeError):
            capsule.context.local_ip = PEER
        with self.assertRaises(AttributeError):
            capsule.context = self.context()
        with self.assertRaises(AttributeError):
            capsule.endpoint = scoped.PeerEndpoint(LOCAL, PORT, 'c' * 64)

    def test_constructor_rejects_original_iface_unowned_or_ambiguous_context(self):
        for values in ({'ifname': 'wlan0'}, {'ifname': 'lo'}, {'ifname': 'bad/name'},
                       {'ifindex': True}, {'ifindex': 0}, {'wdev': 0}, {'task_epoch': 0},
                       {'boot_id': 'unknown'}, {'local_ip': '0.0.0.0'}, {'local_ip': '127.0.0.1'},
                       {'local_ip': '192.168.077.2'}, {'local_ip': '192.168.77.0'},
                       {'local_ip': '192.168.77.255'}, {'prefix': 0}, {'prefix': True},
                       {'deadline': float('nan')}, {'deadline': 401}, {'receipt_id': 'not_hash'}):
            with self.subTest(values=values):
                with self.assertRaises(scoped.ScopedSocketError):
                    self.make(context=self.context(**values))
        self.assertFalse(self.factory_calls)

    def test_client_constructor_does_not_guess_endpoint_or_use_other_subnet(self):
        for endpoint in (None, scoped.PeerEndpoint(LOCAL, PORT, 'b' * 64),
                         scoped.PeerEndpoint('192.168.78.1', PORT, 'b' * 64),
                         scoped.PeerEndpoint('192.168.77.255', PORT, 'b' * 64),
                         scoped.PeerEndpoint(PEER, True, 'b' * 64)):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(scoped.ScopedSocketError):
                    self.make('client', endpoint=endpoint)

    def test_missing_shared_owner_lock_is_rejected(self):
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^required_owner_callbacks_missing$'):
            self.make(ownership_lock=None)

    def test_shared_owner_lock_is_held_inside_every_proof_and_final_handoff(self):
        owned = []
        self.proof_hook = lambda *args: owned.append(self.owner_lock._is_owned())
        self.opened()
        self.assertTrue(owned)
        self.assertTrue(all(owned))

    def test_owner_lock_timeout_is_no_socket_no_fallback(self):
        lock = mock.Mock()
        lock.acquire.return_value = False
        capsule = self.make(ownership_lock=lock)
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^owner_lock_timeout$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)
        lock.release.assert_not_called()

    def test_wrong_listener_or_connector_endpoint_never_creates_socket(self):
        for mode, host, port in (('go', '0.0.0.0', 0), ('go', PEER, 0), ('go', LOCAL, True),
                                ('go', LOCAL, 65536), ('client', LOCAL, PORT),
                                ('client', PEER, PORT + 1), ('client', PEER, True)):
            with self.subTest(mode=mode, host=host, port=port):
                capsule = self.make(mode)
                with self.assertRaises(scoped.ScopedSocketError):
                    if mode == 'go':
                        capsule.listener_factory(host, port)
                    else:
                        capsule.socket_factory(host, port, 3)
        self.assertFalse(self.factory_calls)

    def test_factories_cannot_swap_go_and_client_roles(self):
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^connector_endpoint_out_of_scope$'):
            capsule.socket_factory(PEER, PORT, 3)
        capsule = self.make('client')
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^listener_endpoint_out_of_scope$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_invalid_connector_budget_never_creates_socket(self):
        for timeout in (0, -1, 4, True, None, float('inf')):
            with self.subTest(timeout=timeout):
                capsule = self.make('client')
                with self.assertRaises(scoped.ScopedSocketError):
                    capsule.socket_factory(PEER, PORT, timeout)
        self.assertFalse(self.factory_calls)

    def test_cancel_expiry_and_backwards_clock_are_no_socket(self):
        for reason in ('cancelled', 'lease_or_connect_expired', 'clock_moved_backwards'):
            with self.subTest(reason=reason):
                self.clock.now = 100
                self.cancel = False
                capsule = self.make()
                if reason == 'cancelled':
                    self.cancel = True
                elif reason == 'lease_or_connect_expired':
                    self.clock.now = 120
                else:
                    self.clock.now = 99
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^' + reason + '$'):
                    capsule.listener_factory(LOCAL, 0)
                self.assertTrue(capsule.close())
        self.assertFalse(self.factory_calls)

    def test_cancel_or_expiry_inside_proof_prevents_create(self):
        for expired in (False, True):
            self.cancel = False
            self.clock.now = 100
            self.proof_hook = (lambda *args: setattr(self.clock, 'now', 120)) if expired else (
                lambda *args: setattr(self, 'cancel', True))
            capsule = self.make()
            with self.assertRaises(scoped.ScopedSocketError):
                capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_slow_or_private_exception_proof_is_failclosed(self):
        for hook, reason in ((lambda *args: setattr(self.clock, 'now', self.clock.now + .201),
                              'scope_readback_budget_exceeded'),
                             (lambda *args: (_ for _ in ()).throw(RuntimeError('HOST_PRIVATE_PROOF')),
                              'scope_readback_failed')):
            self.clock.now = 100
            self.proof_hook = hook
            capsule = self.make()
            with self.assertRaisesRegex(scoped.ScopedSocketError, '^' + reason + '$'):
                capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_actual_host_thread_blocked_proof_remains_actor_and_close_is_false(self):
        entered, finish = threading.Event(), threading.Event()
        errors = []
        def slow_proof(*args):
            entered.set()
            self.assertTrue(finish.wait(2))
        self.proof_hook = slow_proof
        capsule = self.make()
        thread = threading.Thread(target=lambda: self.record_open_error(capsule, errors))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(capsule.close())
            self.assertTrue(capsule.status()['actors_pending'])
            self.assertFalse(self.factory_calls)
        finally:
            finish.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ['capsule_closed'])
        self.assertTrue(capsule.close())

    def record_open_error(self, capsule, errors):
        try:
            capsule.listener_factory(LOCAL, 0)
        except scoped.ScopedSocketError as error:
            errors.append(str(error))

    def test_factory_error_has_one_attempt_and_no_default_fallback(self):
        self.factory_hook = lambda *args: (_ for _ in ()).throw(OSError('HOST_PRIVATE_CREATE'))
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^socket_operation_failed$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertEqual(len(self.factory_calls), 1)
        self.assertTrue(capsule.close())

    def test_actual_host_thread_late_created_socket_is_closed_not_handed(self):
        entered, finish = threading.Event(), threading.Event()
        raw = FakeSocket()
        errors = []
        def late(*args):
            entered.set()
            self.assertTrue(finish.wait(2))
            return raw
        self.factory_hook = late
        capsule = self.make()
        thread = threading.Thread(target=lambda: self.record_open_error(capsule, errors))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(capsule.close())
            self.assertTrue(capsule.status()['actors_pending'])
        finally:
            finish.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ['capsule_closed'])
        self.assertTrue(raw.closed)
        self.assertNotIn('setsockopt', raw.calls)
        self.assertTrue(capsule.close())

    def test_slow_factory_expiry_closes_created_socket(self):
        raw = FakeSocket()
        def late(*args):
            self.clock.now = 120
            return raw
        self.factory_hook = late
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^lease_or_connect_expired$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertTrue(raw.closed)
        self.assertNotIn('bind', raw.calls)

    def test_wrong_socket_family_or_tls_is_not_adopted(self):
        raw = FakeSocket()
        raw.family = socket.AF_INET6
        self.factory_hook = lambda *args: raw
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^raw_ipv4_tcp_required$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertTrue(raw.closed)
        raw = FakeSocket()
        capsule = self.make()
        with mock.patch.object(scoped.ssl, 'SSLSocket', FakeSocket):
            with self.assertRaisesRegex(scoped.ScopedSocketError, '^raw_ipv4_tcp_required$'):
                capsule.listener_factory(LOCAL, 0)
        self.assertTrue(raw.closed)

    def test_options_binding_reuse_listening_and_inheritance_fail_closed(self):
        for key, value in (((socket.SOL_SOCKET, 25), b'wlan0\0'),
                           ((socket.SOL_SOCKET, socket.SO_TYPE), int(socket.SOCK_DGRAM)),
                           ((socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1),
                           ((socket.SOL_SOCKET, socket.SO_REUSEADDR), 1),
                           ((socket.SOL_SOCKET, scoped.SO_REUSEPORT), 1),
                           ((socket.SOL_SOCKET, socket.SO_LINGER), b'\x01' + b'\0' * 7),
                           ((socket.SOL_SOCKET, socket.SO_TYPE), True)):
            with self.subTest(key=key, value=value):
                raw = FakeSocket()
                raw.overrides[key] = value
                self.factory_hook = lambda *args: raw
                capsule = self.make()
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^socket_scope_readback_failed$'):
                    capsule.listener_factory(LOCAL, 0)
                self.assertTrue(raw.closed)
                self.assertNotIn('bind', raw.calls)

    def test_backend_exception_even_same_error_class_does_not_expose_private_text(self):
        self.factory_hook = lambda *args: (_ for _ in ()).throw(scoped.ScopedSocketError('HOST_PRIVATE_VALUE'))
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^unclassified_scope_failure$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertNotIn('HOST_PRIVATE', repr(capsule.status()))

    def test_blocked_nonblocking_mode_and_kernel_error_readbacks_fail_closed(self):
        for setup in ('nonblocking', 'socket_error', 'poll_unknown'):
            with self.subTest(setup=setup):
                raw = self.pending_socket()
                self.factory_hook = lambda *args: raw
                self.poll_hook = None
                if setup == 'nonblocking':
                    raw.gettimeout = lambda: None
                elif setup == 'socket_error':
                    raw.overrides[socket.SOL_SOCKET, socket.SO_ERROR] = errno.EHOSTUNREACH
                else:
                    self.poll_hook = lambda *args: ([], [object()], [])
                capsule = self.make('client')
                with self.assertRaises(scoped.ScopedSocketError):
                    capsule.socket_factory(PEER, PORT, 3)
                self.assertTrue(raw.closed)
                self.assertTrue(capsule.close())

    def test_fresh_owner_lost_after_bind_has_no_handoff(self):
        self.socket_hook = lambda step: self.proof_values.update(owner_verified=False) if step == 'bind' else None
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^owned_scope_unverified$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertTrue(self.sockets[0].closed)
        self.assertFalse(capsule.status()['handoffs_pending'])

    def test_broken_or_truthy_cancel_callback_is_failclosed(self):
        for callback in (lambda: 1, lambda: (_ for _ in ()).throw(RuntimeError('HOST_PRIVATE_CANCEL'))):
            capsule = self.make(cancelled=callback)
            with self.assertRaises(scoped.ScopedSocketError):
                capsule.listener_factory(LOCAL, 0)
        self.assertFalse(self.factory_calls)

    def test_already_connected_socket_is_rejected_before_bind(self):
        raw = FakeSocket()
        raw.peer = (PEER, PORT)
        self.factory_hook = lambda *args: raw
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^socket_already_connected$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertTrue(raw.closed)
        self.assertNotIn('bind', raw.calls)

    def test_syscall_failures_close_only_the_new_exact_socket(self):
        for step in ('set_inheritable', 'setsockopt', 'getsockopt', 'bind', 'getsockname',
                     'setblocking', 'connect_ex', 'settimeout'):
            with self.subTest(step=step):
                raw = FakeSocket()
                raw.fail_at = step
                self.factory_hook = lambda *args: raw
                capsule = self.make('client')
                with self.assertRaises(scoped.ScopedSocketError) as caught:
                    capsule.socket_factory(PEER, PORT, 3)
                self.assertNotIn('HOST_PRIVATE', str(caught.exception))
                self.assertTrue(raw.closed)
                self.assertTrue(capsule.close())

    def test_source_wildcard_wrong_port_or_changed_after_connect_is_rejected(self):
        for value in (('0.0.0.0', 40000), (LOCAL, 0), (LOCAL, True), (LOCAL, 9999)):
            with self.subTest(value=value):
                raw = FakeSocket()
                raw.getsockname = lambda: value
                self.factory_hook = lambda *args: raw
                capsule = self.make()
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^source_binding_readback_failed$'):
                    capsule.listener_factory(LOCAL, 8888)
                self.assertTrue(raw.closed)
        self.factory_hook = None
        def change(step):
            if step == 'connect_ex':
                self.sockets[-1].address = (LOCAL, 44444)
        self.socket_hook = change
        capsule = self.make('client')
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^source_port_changed_during_connect$'):
            capsule.socket_factory(PEER, PORT, 3)

    def test_connect_error_or_wrong_precise_peer_has_no_fallback(self):
        raw = FakeSocket()
        raw.connect_result = errno.ECONNREFUSED
        self.factory_hook = lambda *args: raw
        capsule = self.make('client')
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^connect_failed$'):
            capsule.socket_factory(PEER, PORT, 3)
        self.assertTrue(raw.closed)
        self.assertEqual(len(self.factory_calls), 1)
        raw = self.pending_socket()
        self.factory_hook = lambda *args: raw
        self.poll_hook = lambda r, w, e, t: self.wrong_ready(w)
        capsule = self.make('client')
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^peer_binding_readback_failed$'):
            capsule.socket_factory(PEER, PORT, 3)
        self.assertTrue(raw.closed)

    def wrong_ready(self, writers):
        writers[0].peer = (PEER, PORT + 1)
        return ([], writers, [])

    def test_pending_connect_timeout_closes_and_never_default_connects(self):
        self.factory_hook = lambda *args: self.pending_socket()
        self.poll_hook = lambda *args: ([], [], [])
        capsule = self.make('client')
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^lease_or_connect_expired$'):
            capsule.socket_factory(PEER, PORT, .35)
        self.assertLessEqual(self.clock.now, 100.36)
        self.assertTrue(self.sockets[0].closed)
        self.assertEqual(len(self.factory_calls), 1)

    def test_revoked_peer_after_connect_or_during_poll_never_hands_off(self):
        for pending in (False, True):
            with self.subTest(pending=pending):
                self.proof_values = {}
                if pending:
                    self.factory_hook = lambda *args: self.pending_socket()
                    def revoke(r, w, e, t):
                        self.proof_values = {'client_association_verified': False}
                        return ([], w, [])
                    self.poll_hook = revoke
                else:
                    self.factory_hook = None
                    self.socket_hook = lambda step: self.proof_values.update(dhcp_verified=False) if step == 'connect_ex' else None
                capsule = self.make('client')
                with self.assertRaisesRegex(scoped.ScopedSocketError, '^client_peer_unverified$'):
                    capsule.socket_factory(PEER, PORT, 3)
                self.assertEqual(capsule.status()['handoffs_pending'], 0)
                self.assertTrue(self.sockets[-1].closed)

    def test_cancel_during_connect_closes_pre_handoff_socket(self):
        self.socket_hook = lambda step: setattr(self, 'cancel', True) if step == 'connect_ex' else None
        capsule = self.make('client')
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^cancelled$'):
            capsule.socket_factory(PEER, PORT, 3)
        self.assertTrue(self.sockets[0].closed)
        self.assertTrue(capsule.close())

    def test_close_during_bind_cannot_publish_late_socket(self):
        results = []
        def hook(step):
            if step == 'bind':
                results.append(self.capsule.close())
        self.socket_hook = hook
        capsule = self.make()
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^capsule_closed$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertEqual(results, [False])
        self.assertTrue(self.sockets[0].closed)
        self.assertEqual(capsule.status()['handoffs_pending'], 0)

    def test_duplicate_factory_object_cannot_mutate_existing_handoff(self):
        capsule, raw = self.opened()
        options_before = raw.calls.count('setsockopt')
        self.factory_hook = lambda *args: raw
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^socket_identity_already_owned$'):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(raw.closed)
        self.assertEqual(raw.calls.count('setsockopt'), options_before)
        self.assertEqual(capsule.status()['handoffs_pending'], 1)
        self.assertTrue(capsule.confirm_transport_closed(raw, self.closed_proof))
        self.assertTrue(capsule.close())

    def test_capsule_close_does_not_close_or_inspect_handed_off_raw_socket(self):
        capsule, raw = self.opened()
        calls = list(raw.calls)
        self.assertFalse(capsule.close())
        self.assertEqual(raw.calls, calls)
        self.assertFalse(raw.closed)
        self.assertEqual(capsule.status()['handoffs_pending'], 1)

    def test_tls_detach_or_raw_fd_minus_one_is_not_transport_close_proof(self):
        capsule, raw = self.opened('client')
        raw.detached = True
        self.assertEqual(raw.fileno(), -1)
        self.assertFalse(capsule.close())
        self.assertFalse(capsule.confirm_transport_closed(raw, lambda *args: True))
        self.assertFalse(capsule.status()['close_verified'])
        self.assertEqual(capsule.status()['handoffs_pending'], 1)

    def test_transport_close_proof_requires_exact_context_raw_and_all_actor_flags(self):
        capsule, raw = self.opened()
        capsule.close()
        wrong = FakeSocket(raw.number)  # Same fd is deliberately insufficient.
        for change in ({'context': capsule.context._replace()}, {'raw_socket': wrong},
                       {'all_sockets_closed': False}, {'all_actors_exited': False},
                       {'all_sockets_closed': 1}):
            with self.subTest(change=change):
                def proof(context, item, budget):
                    return self.closed_proof(context, item, budget)._replace(**change)
                self.assertFalse(capsule.confirm_transport_closed(raw, proof))
                self.assertFalse(capsule.status()['close_verified'])
        self.assertFalse(capsule.confirm_transport_closed(wrong, self.closed_proof))
        self.assertTrue(capsule.confirm_transport_closed(raw, self.closed_proof))
        self.assertTrue(capsule.close())

    def test_slow_or_throwing_transport_closed_callback_keeps_handoff(self):
        capsule, raw = self.opened()
        def slow(context, item, budget):
            self.clock.now += budget + .001
            return self.closed_proof(context, item, budget)
        self.assertFalse(capsule.confirm_transport_closed(raw, slow))
        self.assertFalse(capsule.confirm_transport_closed(raw,
            lambda *args: (_ for _ in ()).throw(RuntimeError('HOST_PRIVATE_CLOSE_PROOF'))))
        self.assertFalse(capsule.close())
        self.assertTrue(capsule.confirm_transport_closed(raw, self.closed_proof))
        self.assertTrue(capsule.close())

    def test_transport_proof_after_expiry_resolves_only_resource_not_lease(self):
        capsule, raw = self.opened()
        self.clock.now = 121
        self.cancel = True
        self.assertFalse(capsule.close())
        self.assertTrue(capsule.confirm_transport_closed(raw, self.closed_proof))
        self.assertTrue(capsule.close())
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^capsule_closed$'):
            capsule.listener_factory(LOCAL, 0)

    def test_actual_host_thread_pending_transport_proof_blocks_verified_close(self):
        capsule, raw = self.opened()
        entered, finish = threading.Event(), threading.Event()
        results = []
        def proof(context, item, budget):
            entered.set()
            self.assertTrue(finish.wait(2))
            return self.closed_proof(context, item, budget)
        thread = threading.Thread(target=lambda: results.append(capsule.confirm_transport_closed(raw, proof)))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(capsule.close())
            self.assertFalse(capsule.confirm_transport_closed(raw, self.closed_proof))
            self.assertTrue(capsule.status()['actors_pending'])
        finally:
            finish.set()
            thread.join(2)
        self.assertEqual(results, [True])
        self.assertFalse(thread.is_alive())
        self.assertTrue(capsule.close())

    def test_failed_pre_handoff_close_keeps_exact_resource_for_retry(self):
        raw = FakeSocket()
        raw.close_fails = True
        raw.overrides[socket.SOL_SOCKET, 25] = b'wlan0\0'
        self.factory_hook = lambda *args: raw
        capsule = self.make()
        with self.assertRaises(scoped.ScopedSocketError):
            capsule.listener_factory(LOCAL, 0)
        self.assertFalse(capsule.close())
        self.assertEqual(capsule.status()['pre_handoff_close_pending'], 1)
        raw.close_fails = False
        self.assertTrue(capsule.close())
        self.assertTrue(raw.closed)

    def test_actual_host_thread_pending_socket_close_actor_cannot_false_pass(self):
        entered, finish = threading.Event(), threading.Event()
        raw = FakeSocket()
        raw.overrides[socket.SOL_SOCKET, 25] = b'wlan0\0'
        original = raw.close
        def delayed():
            entered.set()
            self.assertTrue(finish.wait(2))
            original()
        raw.close = delayed
        self.factory_hook = lambda *args: raw
        capsule = self.make()
        errors = []
        thread = threading.Thread(target=lambda: self.record_open_error(capsule, errors))
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(capsule.close())
            self.assertTrue(capsule.status()['actors_pending'])
        finally:
            finish.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(raw.closed)
        self.assertTrue(capsule.close())

    def test_ongoing_revocation_keeps_transport_outstanding_for_owner_shutdown(self):
        capsule, raw = self.opened('client')
        self.proof_values = {'dhcp_verified': False}
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^client_peer_unverified$'):
            capsule.check()
        self.assertFalse(raw.closed)
        self.assertFalse(capsule.close())
        self.assertTrue(capsule.confirm_transport_closed(raw, self.closed_proof))
        self.assertTrue(capsule.close())

    def test_resource_limit_and_close_before_open_are_terminal(self):
        capsule = self.make('client')
        for _ in range(scoped.MAX_RESOURCES):
            capsule.socket_factory(PEER, PORT, 3)
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^resource_limit$'):
            capsule.socket_factory(PEER, PORT, 3)
        self.assertEqual(len(self.factory_calls), scoped.MAX_RESOURCES)
        capsule = self.make()
        self.assertTrue(capsule.close())
        self.assertTrue(capsule.close())
        with self.assertRaisesRegex(scoped.ScopedSocketError, '^capsule_closed$'):
            capsule.listener_factory(LOCAL, 0)

    def test_passive_status_has_fixed_fields_without_private_context_values(self):
        capsule, raw = self.opened()
        before = len(self.proof_calls)
        status = capsule.status()
        self.assertEqual(len(self.proof_calls), before)
        self.assertEqual(set(status), {'stage', 'reason', 'actors_pending', 'handoffs_pending',
            'pre_handoff_close_pending', 'close_verified', 'peer_authorized'})
        for private in (LOCAL, PEER, IFNAME, capsule.context.boot_id, capsule.context.receipt_id):
            self.assertNotIn(private, repr(status))
        self.assertFalse(status['peer_authorized'])

    def test_source_python35_and_no_network_mutation_or_shell_imports(self):
        source = Path(scoped.__file__).read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 5))
        imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse({'json', 'subprocess', 'mta_ip_lease', 'mta_dhcp_server'} & imports)
        self.assertNotIn('create_connection(', source)
        self.assertNotIn('getaddrinfo(', source)


if __name__ == '__main__':
    unittest.main()
