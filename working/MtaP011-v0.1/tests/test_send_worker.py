"""HOST actual worker, fake external IO only; no RF/socket/crypto/file opens."""
import ast
import base64
import errno
import io
import pathlib
import socket
import struct
import sys
import threading
import unittest

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
import mta_send_worker as core
from mta_protocol import P2pInfo, DeviceInfo
from mta_scoped_sockets import OwnedContext, ScopeProof, ScopedDataSockets
from mta_dhcp_server import DhcpSocketServer


def file_status(pending=False):
    return {'resource_count': 1, 'open_attempt_count': 1, 'close_attempted_count': 1,
        'wrapper_closed_count': 0 if pending else 1, 'fd_closed_count': 0 if pending else 1,
        'unknown_count': int(pending), 'resource_pending': pending, 'closure_verified': not pending}


class FakeSelection(core.FileSelection):
    def __init__(self):
        # Explicit fake external selection: do not call the evolving real
        # FileRegistry/FD constructor or fabricate OS EBADF evidence here.
        self.entries = [{'name': 'Text/test.txt', 'size': 3, 'handle': io.BytesIO(b'abc')}]
        self.total_bytes = 3
        self.closed = False
        self.close_count = 0
        self.pending = False

    def close(self):
        self.close_count += 1
        if not self.pending:
            for item in self.entries:
                item['handle'].close()
        self.closed = True

    def lifecycle_status(self):
        return dict(file_status(self.pending), close_requested=self.close_count > 0,
                    selection_closed=self.closed)

class FakeRegistry(core.FileRegistry):
    def __init__(self):
        self.selection = FakeSelection()
        self.calls = 0
        self.error = None
        self.pending = False

    def open_selection(self, ids):
        self.calls += 1
        if self.error is not None:
            raise self.error
        if ids != ['file-id']:
            raise ValueError('stale')
        return self.selection

    def lifecycle_status(self):
        return file_status(self.pending)


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class Raw:
    """No OS socket: exercise actual ScopedDataSockets through its HOST seam."""
    family = socket.AF_INET
    def __init__(self, *unused):
        self.source = None
        self.device = b''
        self.inheritable = True
        self.closed = False

    def set_inheritable(self, value):
        self.inheritable = value

    def get_inheritable(self):
        return self.inheritable

    def setsockopt(self, level, option, value):
        if option == 25:
            self.device = value

    def getsockopt(self, level, option, size=None):
        if option == 25:
            return self.device
        if option == socket.SO_LINGER:
            return struct.pack('=ii', 0, 0)
        if option == socket.SO_TYPE:
            return int(socket.SOCK_STREAM)
        return 0

    def getpeername(self):
        raise OSError(errno.ENOTCONN, 'fake')

    def bind(self, source):
        self.source = (source[0], source[1] or 45678)

    def getsockname(self):
        return self.source

    def close(self):
        self.closed = True

    def fileno(self):
        return -1 if self.closed else 123


class FakeDhcp(DhcpSocketServer):
    def __init__(self):
        self.closed = False
        self.pending = False
        self.mac = b'\x02\x11\x22\x33\x44\x55'
        self.ip = '192.168.88.2'
        self.expiry = 200.0
        self.ack = True
        self._ifindex = 9
        self._ifname_text = 'mta12345678'
        self._server_ip = '192.168.88.1'
        self._deadline = 280.0

    def status(self):
        return {'stage': 'closed' if self.closed else 'listening', 'client_limit': 1,
            'socket_actor_pending': self.pending, 'socket_close_verified': self.closed,
            'default_route_supplied': False, 'dns_supplied': False}

    def allocation(self):
        return {'client_ip': self.ip, 'mac': self.mac, 'usable_until': self.expiry,
                'ack_transmitted': self.ack, 'phone_configured': False}

    def close(self):
        self.closed = True


class FakeKey:
    public_key = base64.b64encode(b'local-public').decode('ascii')
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeCrypto:
    def __init__(self, *unused):
        self.key = FakeKey()
        self.reject = False

    def generate_keypair(self):
        return self.key

    def derive_shared(self, key, peer):
        if self.reject:
            raise ValueError('private secret detail must not leak')
        return b's' * 32

    def encrypt_credentials(self, plain, key, peer):
        self.plain = plain
        cipher = base64.b64encode(b'encrypted').decode('ascii')
        return P2pInfo(cipher, cipher, cipher, plain.port, key.public_key, plain.id)


class Helper:
    def __init__(self):
        self.worker = None
        self.calls = []
        self.close_count = 0
        self.closed = False
        self.status = DeviceInfo('00:AA:BB:CC:DD:EE', base64.b64encode(b'peer-public').decode('ascii')).to_bytes()
        self.write_code = 'accepted_by_bluez_not_file_transfer_complete'
        self.mutate_read = None
        self.on_send = None

    def send(self, command):
        self.calls.append(command)
        if self.on_send:
            self.on_send(command)
        if command['cmd'] == 'client_read':
            event = {'event': 'client_status', 'peer': 7,
                     'payload_b64': base64.b64encode(self.status).decode('ascii')}
            if self.mutate_read:
                self.mutate_read(event)
        else:
            event = {'event': 'client_write', 'code': self.write_code}
        self.worker.native_event(event, self, 2, 3)

    def close(self):
        self.close_count += 1
        self.closed = True
        return True

    def closure_verified(self):
        return self.closed


class Hooks:
    def __init__(self):
        self.tickets = []
        self.attached = []
        self.handed = []
        self.fail_kind = None

    def claim(self, ticket):
        self.tickets.append(ticket)
        return False if ticket.kind == self.fail_kind else ticket

    def adopt(self, ticket):
        return ticket

    def attach_transport(self, ticket, transport):
        self.attached.append(transport)
        return ticket

    def handoff(self, ticket, transport, raw):
        self.handed.append((transport, raw))
        return ticket


class Provider:
    def __init__(self, clock):
        self.clock = clock
        self.log = []
        self.lease = object()
        self.dhcp = FakeDhcp()
        self.proof_bad = False
        self.binding_bad = False
        self.activation_error = None
        self.on_activate = None
        self.extra_pending = False
        self.restore_count = 0

    def reserve(self, handoff, deadline, cancelled):
        self.log.append('reserve')
        return self.lease

    def activate(self, lease, handoff, info, deadline, cancelled):
        self.log.append('activate')
        if self.on_activate:
            self.on_activate()
        if self.activation_error:
            raise self.activation_error
        context = OwnedContext('00000000-0000-0000-0000-000000000001', 3, 2, 0, 8,
            9, 'mta12345678', 'go', '192.168.88.1', 24, deadline, 'a' * 64)
        scope = ScopedDataSockets(context, lambda c, p, b: self.scope_proof(c), cancelled.is_set,
            threading.RLock(), clock=self.clock, socket_factory=Raw,
            if_nametoindex=lambda name: 9, raw_socket_type=Raw)
        self.network = core.NetworkReceipt(lease, context, scope, self.dhcp,
                                          'HOST-FIXTURE', 'host-only-pass', '02:00:00:00:00:01')
        return self.network

    def scope_proof(self, context):
        return ScopeProof(context, 'confirmed', not self.proof_bad, True, True,
                          True, True, False, False, False, None)

    def read_network(self, network, budget):
        self.log.append('network_readback')
        return self.scope_proof(network.context)

    def wait_association(self, network, handoff, info, deadline, cancelled):
        self.log.append('association')
        return core.AssociationReceipt(network, handoff, info.mac, self.dhcp.mac,
            deadline, 'b' * 64, 'c' * 64 if not self.binding_bad else 'not-receipt')

    def read_association(self, receipt, budget):
        self.log.append('peer_readback')
        return receipt

    def close_extra(self, lease):
        self.log.append('close_extra')

    def extra_closed(self, lease):
        return core.ProviderClosed(lease, 0, 0, int(self.extra_pending), not self.extra_pending)


class FakeSender:
    def __init__(self, host, port, selection, openssl, **options):
        self.host = host
        self.options = options
        self.selection = selection
        self.allowed_peer_ip = options['allowed_peer_ip']
        self.raw = None
        self.is_closed = False
        self.error = None
        self.on_wait = None
        self.count = 0

    def start(self):
        self.options['state_callback']('preparing', {})
        self.raw = self.options['listener_factory'](self.host, 0)
        self.options['state_callback']('waiting', {'fileCount': 1, 'totalSize': 3})
        return self.raw.getsockname()[1]

    def authorize_peer(self, ip):
        self.allowed_peer_ip = ip
        return True

    def wait(self):
        if self.on_wait:
            self.on_wait()
        if self.error:
            raise self.error
        for stage in ('negotiating', 'awaiting_confirmation', 'accepted'):
            self.options['state_callback'](stage, {})
        self.options['state_callback']('transferring', {'bytes': 0, 'archiveSize': 100})
        self.options['state_callback']('transferring', {'bytes': 100, 'archiveSize': 100})
        self.options['state_callback']('awaiting_result', {'archiveBytesSent': 100})
        self.options['state_callback']('completed', {'fileCount': 1, 'totalSize': 3})
        return {'fileCount': 1, 'totalSize': 3, 'archiveBytesSent': 100, 'peer_completion_verified': True}

    def cancel(self):
        self.is_closed = True

    def close(self, timeout=2):
        self.count += 1
        if self.raw:
            self.raw.close()
        self.is_closed = True
        return True

    def closed(self):
        return self.is_closed

    def lifecycle_status(self):
        return dict({'closing': self.is_closed, 'close_verified': self.is_closed,
                     'cleanup_pending': False, 'socket_records': int(self.raw is not None)},
                    **{key: 0 for key in core._PENDING})

    def closure_snapshot(self, raw):
        return dict(self.lifecycle_status(), recognized_raw=raw is self.raw,
                    all_sockets_closed=self.is_closed, all_actors_exited=True)


class SendWorkerTests(unittest.TestCase):
    def make(self, provider=True):
        self.clock = Clock()
        self.helper = Helper()
        self.registry = FakeRegistry()
        self.provider = Provider(self.clock)
        self.crypto = FakeCrypto()
        self.hooks = Hooks()
        self.observation = None
        handoff = core.ScanHandoff(self.helper, 2, 3, 7, 100.0, 'task-1',
            lambda owned, budget: self.observation or core.ScanObservation(self.helper, 2, 3, 7, 100.0, False, True))
        self.worker = core.SendWorker(handoff, self.registry, ['file-id'],
            provider=self.provider if provider else None, clock=self.clock,
            crypto_factory=lambda path: self.crypto, transport_factory=self.sender)
        self.helper.worker = self.worker
        self.sender_instance = None
        return self.worker

    def sender(self, *args, **options):
        self.sender_instance = FakeSender(*args, **options)
        return self.sender_instance

    def run_worker(self):
        self.result = None
        self.error = None
        def body():
            try:
                self.result = self.worker.run(self.hooks)
            except BaseException as error:
                self.error = error
        thread = threading.Thread(target=body)
        thread.start()
        thread.join(2)
        self.assertFalse(thread.is_alive(), 'HOST fixture did not finish')
        return self.result

    def finish_extra(self):
        self.assertTrue(self.worker.release_scoped())
        self.assertTrue(self.worker.close_extra())

    def test_default_provider_rejects_before_any_io_and_defaults_real(self):
        self.make(False)
        self.run_worker()
        self.assertEqual(str(self.error), 'backend_unavailable')
        self.assertEqual(self.registry.calls, 0)
        self.assertEqual(self.helper.calls, [])
        self.assertEqual(self.provider.log, [])
        actual = core.SendWorker(self.worker.handoff, self.registry, ['file-id'])
        self.assertIs(actual._crypto_factory, core.OpenSslCrypto)
        self.assertIs(actual._transport_factory, core.SenderTransport)

    def test_actual_worker_happy_sequence_no_restore_no_local_commit(self):
        self.make()
        result = self.run_worker()
        self.assertIsNone(self.error)
        self.assertIs(type(result), core.SendResult)
        self.assertTrue(result.peer_completion_verified)
        self.assertEqual(result.archive_bytes_sent, 100)
        self.assertFalse(hasattr(result, 'local_commit_verified'))
        self.assertEqual([value['cmd'] for value in self.helper.calls], ['client_read', 'client_write'])
        self.assertLess(self.provider.log.index('activate'), self.provider.log.index('association'))
        self.assertEqual(self.sender_instance.allowed_peer_ip, '192.168.88.2')
        self.assertIsNone(self.sender_instance.options['allowed_peer_ip'])
        self.assertEqual(self.crypto.plain.port, 45678)
        self.assertEqual(self.crypto.plain.mac, '02:00:00:00:00:01')
        self.assertEqual(len(self.hooks.attached), 1)
        self.assertEqual(len(self.hooks.handed), 1)
        self.assertEqual(self.provider.restore_count, 0)
        self.assertFalse(self.registry.selection.closed)
        self.finish_extra()
        self.assertEqual(self.registry.selection.close_count, 1)
        self.assertTrue(self.worker.status()['network_restore_required'])
        self.assertFalse(self.worker.status()['platform_available'])

    def test_stale_scan_refused_before_file_and_gatt(self):
        self.make()
        self.clock.value = 116.0
        self.run_worker()
        self.assertEqual(str(self.error), 'scan_handoff_expired')
        self.assertEqual(self.registry.calls, 0)
        self.assertEqual(self.helper.calls, [])

    def test_exact_helper_epoch_and_cached_fresh_observation_required(self):
        for observation in (core.ScanObservation(object(), 2, 3, 7, 100.0, False, True),
                core.ScanObservation(None, 2, 3, 7, 100.0, True, True),
                core.ScanObservation(None, True, 3, 7, 100.0, False, True)):
            self.make()
            self.observation = observation
            self.run_worker()
            self.assertEqual(str(self.error), 'scan_handoff_changed')
            self.assertEqual(self.registry.calls, 0)

    def test_boolean_owner_ack_not_exact_ticket_blocks_creating(self):
        self.make()
        self.hooks.fail_kind = 'selection'
        self.run_worker()
        self.assertEqual(self.registry.calls, 0)
        self.assertGreater(self.worker.status()['unresolved_unknown'], 0)
        self.assertFalse(self.worker.release_scoped())

    def test_native_status_512_budget_and_unknown_fields(self):
        for wire in (b'x' * 513, b'{"state":0,"mac":"00:AA:BB:CC:DD:EE","key":"YQ==","extra":1}'):
            self.make()
            self.helper.status = wire
            self.run_worker()
            self.assertIn(str(self.error), ('native_event_invalid', 'peer_status_invalid'))
            self.assertNotIn('activate', self.provider.log)

    def test_busy_peer_never_activates_network(self):
        self.make()
        self.helper.status = DeviceInfo('00:AA:BB:CC:DD:EE', 'YQ==', 1).to_bytes()
        self.run_worker()
        self.assertEqual(str(self.error), 'peer_busy_or_unencrypted')
        self.assertNotIn('activate', self.provider.log)
        self.finish_extra()

    def test_crypto_point_failure_before_mutation_and_sanitized(self):
        self.make()
        self.crypto.reject = True
        self.run_worker()
        self.assertEqual(str(self.error), 'send_failed')
        self.assertNotIn('activate', self.provider.log)
        self.assertNotIn('secret', repr(self.worker.status()))
        self.finish_extra()

    def test_gatt_write_accepted_not_file_complete(self):
        self.make()
        self.provider.binding_bad = True
        self.run_worker()
        self.assertEqual(str(self.error), 'association_invalid')
        self.assertIsNone(self.sender_instance.allowed_peer_ip)
        self.assertFalse(self.worker.status()['peerCompletionVerified'])
        self.finish_extra()

    def test_lease_expiry_after_slow_activation_no_gatt_write(self):
        self.make()
        self.provider.on_activate = lambda: setattr(self.clock, 'value', 131.0)
        self.run_worker()
        self.assertEqual(str(self.error), 'native_lease_expired')
        self.assertEqual(len(self.helper.calls), 1)
        self.finish_extra()

    def test_bad_durable_scope_proof_no_sender_or_write(self):
        self.make()
        self.provider.proof_bad = True
        self.run_worker()
        self.assertEqual(str(self.error), 'network_readback_invalid')
        self.assertIsNone(self.sender_instance)
        self.assertEqual(len(self.helper.calls), 1)
        self.finish_extra()

    def test_native_failed_write_stays_deny_all_and_closes_later(self):
        self.make()
        self.helper.write_code = 'cancelled_or_late_reply'
        self.run_worker()
        self.assertEqual(str(self.error), 'native_failed')
        self.assertIsNone(self.sender_instance.allowed_peer_ip)
        self.finish_extra()

    def test_dhcp_allocation_requires_actual_mac_ack_subnet_expiry(self):
        for field, value in (('mac', b'\x02\x99\x22\x33\x44\x55'), ('ack', False),
                             ('ip', '192.168.99.2'), ('ip', '192.168.88.1'), ('expiry', 99.0)):
            self.make()
            # Association is independently mapped, not copied from this mutable allocation.
            station = self.provider.dhcp.mac
            self.provider.wait_association = lambda network, handoff, info, deadline, cancelled: core.AssociationReceipt(
                network, handoff, info.mac, station, deadline, 'b' * 64, 'c' * 64)
            setattr(self.provider.dhcp, field, value)
            self.run_worker()
            self.assertEqual(str(self.error), 'allocation_invalid')
            self.assertIsNone(self.sender_instance.allowed_peer_ip)
            self.finish_extra()

    def test_cancel_before_run_zero_file_gatt_network(self):
        self.make()
        self.worker.cancel()
        self.run_worker()
        self.assertEqual(str(self.error), 'cancelled')
        self.assertEqual(self.registry.calls, 0)
        self.assertEqual(self.helper.calls, [])
        self.assertEqual(self.provider.log, [])

    def test_cancel_after_activation_retains_exact_lease_no_restore(self):
        self.make()
        self.provider.on_activate = self.worker.cancel
        self.run_worker()
        self.assertEqual(str(self.error), 'cancelled')
        self.assertIs(self.worker.lease, self.provider.lease)
        self.assertEqual(len(self.helper.calls), 1)
        self.assertEqual(self.provider.restore_count, 0)
        self.finish_extra()

    def test_ignored_late_wrong_namespace_events_and_passive_status(self):
        self.make()
        event = {'event': 'client_write', 'code': 'accepted_by_bluez_not_file_transfer_complete'}
        self.assertFalse(self.worker.native_event(event, object(), 2, 3))
        self.assertFalse(self.worker.native_event(event, self.helper, True, 3))
        self.run_worker()
        before = list(self.provider.log), list(self.helper.calls)
        self.assertFalse(self.worker.native_event(event, self.helper, 2, 3))
        self.worker.status()
        self.assertEqual((self.provider.log, self.helper.calls), before)
        self.assertNotIn('192.168', repr(self.worker.status()))
        self.finish_extra()

    def test_native_queue_overflow_is_bounded_and_no_network(self):
        self.make()
        def fill(command):
            if command['cmd'] == 'client_read':
                event = {'event': 'client_status', 'peer': 7, 'payload_b64': 'YQ=='}
                for unused in range(12):
                    self.worker.native_event(event, self.helper, 2, 3)
        self.helper.on_send = fill
        self.run_worker()
        self.assertEqual(str(self.error), 'native_queue_overflow')
        self.assertLessEqual(len(self.worker._queue), 8)
        self.assertNotIn('activate', self.provider.log)
        self.finish_extra()

    def test_selection_failure_proved_empty_vs_sticky_unknown(self):
        for pending in (False, True):
            self.make()
            self.registry.error = ValueError('stale')
            self.registry.pending = pending
            self.run_worker()
            self.assertEqual(self.helper.calls, [])
            self.assertTrue(self.worker.release_scoped())
            self.assertEqual(self.worker.close_extra(), not pending)
            self.assertEqual(self.worker.status()['unresolved_unknown'], int(pending))

    def test_selection_closed_flag_not_fd_proof(self):
        self.make()
        self.run_worker()
        self.registry.selection.pending = True
        self.assertTrue(self.worker.release_scoped())
        self.assertFalse(self.worker.close_extra())
        self.assertTrue(self.registry.selection.closed)
        self.assertTrue(self.crypto.key.closed)
        self.assertTrue(self.helper.closed)

    def test_actual_running_worker_blocks_external_cleanup(self):
        self.make()
        entered = threading.Event()
        release = threading.Event()
        original = self.sender
        def factory(*args, **options):
            sender = original(*args, **options)
            sender.on_wait = lambda: (entered.set(), release.wait(2))
            return sender
        self.worker._transport_factory = factory
        result = []
        thread = threading.Thread(target=lambda: result.append(self.worker.run(self.hooks)))
        thread.start()
        self.assertTrue(entered.wait(1))
        self.assertFalse(self.worker.release_scoped())
        self.assertFalse(self.worker.close_extra())
        self.assertFalse(self.registry.selection.closed)
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.finish_extra()

    def test_no_fd_minus_one_shortcut_for_transport_handoff(self):
        self.make()
        self.run_worker()
        self.sender_instance.closure_snapshot = lambda raw: dict(self.sender_instance.lifecycle_status(),
            recognized_raw=True, all_sockets_closed=True, all_actors_exited=False)
        self.assertEqual(self.sender_instance.raw.fileno(), -1)
        self.assertFalse(self.worker.release_scoped())
        self.assertFalse(self.worker.close_extra())

    def test_transport_factory_unknown_and_exact_preclaim_retained(self):
        self.make()
        def bad(*args, **options):
            self.assertEqual(self.hooks.tickets[-1].kind, 'transport')
            self.assertTrue(self.hooks.tickets[-1].claimed)
            raise KeyboardInterrupt('private detail')
        self.worker._transport_factory = bad
        self.run_worker()
        self.assertEqual(str(self.error), 'send_failed')
        tickets = self.worker.private_owner_records()
        self.assertTrue(tickets[-1].unknown)
        self.assertTrue(tickets[-1].resolved)
        self.assertFalse(self.worker.release_scoped())
        self.assertFalse(self.worker.close_extra())
        self.assertIs(self.worker.lease, self.provider.lease)

    def test_late_sender_return_after_cancel_adopted_then_no_start(self):
        self.make()
        original = self.sender
        def late(*args, **options):
            sender = original(*args, **options)
            self.worker.cancel()
            return sender
        self.worker._transport_factory = late
        self.run_worker()
        self.assertEqual(str(self.error), 'cancelled')
        self.assertIs(self.worker.transport, self.sender_instance)
        self.assertEqual(self.hooks.attached, [self.sender_instance])
        self.assertIsNone(self.sender_instance.raw)
        self.assertTrue(self.sender_instance.closed())
        self.finish_extra()

    def test_missing_peer_completion_keeps_real_bytes_not_saved_or_completed(self):
        self.make()
        original = self.sender
        def factory(*args, **options):
            sender = original(*args, **options)
            def wait():
                sender.options['state_callback']('transferring', {'bytes': 100, 'archiveSize': 100})
                sender.options['state_callback']('awaiting_result', {'archiveBytesSent': 100})
                raise ValueError('missing matching task completion')
            sender.wait = wait
            return sender
        self.worker._transport_factory = factory
        self.run_worker()
        self.assertEqual(str(self.error), 'send_failed')
        self.assertTrue(self.worker.status()['localBytesVerified'])
        self.assertFalse(self.worker.status()['peerCompletionVerified'])
        self.assertEqual(self.worker.status()['archiveBytesSent'], 100)
        self.assertNotIn('localCommitVerified', self.worker.status())
        self.finish_extra()
        self.assertEqual(self.worker.status()['unresolved_unknown'], 0)

    def test_bad_sender_progress_strict_int_and_denominator(self):
        for details in ({'bytes': True, 'archiveSize': 100}, {'bytes': 101, 'archiveSize': 100}):
            self.make()
            original = self.sender
            def factory(*args, **options):
                sender = original(*args, **options)
                sender.wait = lambda: sender.options['state_callback']('transferring', details)
                return sender
            self.worker._transport_factory = factory
            self.run_worker()
            self.assertEqual(str(self.error), 'progress_invalid')
            self.assertFalse(self.worker.status()['peerCompletionVerified'])
            self.finish_extra()

    def test_native_reader_status_cancel_responsive_during_blocked_send(self):
        self.make()
        entered = threading.Event()
        release = threading.Event()
        self.helper.on_send = lambda command: (entered.set(), release.wait(2))
        errors = []
        def body():
            try:
                self.worker.run(self.hooks)
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=body)
        thread.start()
        self.assertTrue(entered.wait(1))
        self.assertEqual(self.worker.status()['stage'], 'reading_peer')
        self.assertFalse(self.worker.native_event({'event': 'client_write', 'code': 'old'}, self.helper, 2, 3))
        self.worker.cancel()
        self.assertTrue(self.worker.status()['cancel_requested'])
        self.assertFalse(self.worker.release_scoped())
        release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(str(errors[0]), 'cancelled')
        self.assertNotIn('activate', self.provider.log)
        self.finish_extra()

    def test_credentials_native_2048_budget_before_write(self):
        self.make()
        class Oversize(P2pInfo):
            def to_bytes(self):
                return b'x' * 2049
        cipher = base64.b64encode(b'encrypted').decode('ascii')
        self.crypto.encrypt_credentials = lambda plain, key, peer: Oversize(cipher, cipher, cipher, plain.port, key.public_key)
        self.run_worker()
        self.assertEqual(str(self.error), 'credential_budget')
        self.assertEqual(len(self.helper.calls), 1)
        self.assertIsNone(self.sender_instance.allowed_peer_ip)
        self.finish_extra()

    def test_sender_actual_cancel_guard_tracks_network_and_allocation_expiry(self):
        self.make()
        original = self.sender
        def factory(*args, **options):
            sender = original(*args, **options)
            def wait():
                self.assertFalse(options['cancelled']())
                self.clock.value = self.provider.dhcp.expiry
                self.assertTrue(options['cancelled']())
                raise ValueError('lease expired')
            sender.wait = wait
            return sender
        self.worker._transport_factory = factory
        self.run_worker()
        self.assertTrue(self.worker.status()['cancel_requested'])
        self.assertFalse(self.worker.status()['peerCompletionVerified'])
        self.finish_extra()

    def test_dhcp_same_owned_interface_server_address_not_just_subnet(self):
        for field, value in (('_ifindex', 10), ('_ifname_text', 'wlan0'),
                             ('_server_ip', '192.168.88.9'), ('_deadline', 999.0)):
            self.make()
            setattr(self.provider.dhcp, field, value)
            self.run_worker()
            self.assertEqual(str(self.error), 'dhcp_not_listening')
            self.assertIsNone(self.sender_instance)
            self.finish_extra()

    def test_active_owned_dhcp_receive_actor_is_not_a_closed_failure(self):
        self.make()
        original = self.provider.dhcp.status
        self.provider.dhcp.status = lambda: dict(original(), socket_actor_pending=not self.provider.dhcp.closed)
        self.run_worker()
        self.assertIsNone(self.error)
        self.finish_extra()

    def test_failed_selection_close_is_not_retried_on_next_extra_check(self):
        self.make()
        self.run_worker()
        self.registry.selection.pending = True
        self.assertTrue(self.worker.release_scoped())
        self.assertFalse(self.worker.close_extra())
        self.assertFalse(self.worker.close_extra())
        self.assertEqual(self.registry.selection.close_count, 1)

    def test_selection_lifecycle_only_production_api_no_private_fd_close(self):
        self.make()
        self.assertFalse(hasattr(self.registry.selection, 'closure_verified'))
        self.assertNotIn('closure_verified', core.FileSelection.__dict__)
        self.run_worker()
        self.assertIsNone(self.error)
        self.finish_extra()
        self.assertEqual(self.registry.selection.close_count, 1)
        self.assertTrue(self.worker.status()['extra_resources_closed'])

    def test_selection_complete_status_counts_and_original_handles_required(self):
        for field, value in (('resource_count', 0), ('open_attempt_count', True),
                             ('close_attempted_count', 0), ('wrapper_closed_count', 0),
                             ('fd_closed_count', 0), ('close_requested', 1),
                             ('selection_closed', 1), ('foreign', 'private')):
            self.make()
            self.run_worker()
            original = self.registry.selection.lifecycle_status
            self.registry.selection.lifecycle_status = lambda: dict(original(), **{field: value})
            self.assertTrue(self.worker.release_scoped())
            self.assertFalse(self.worker.close_extra())
            self.assertTrue(self.crypto.key.closed)
            self.assertTrue(self.helper.closed)
        self.make()
        self.run_worker()
        self.registry.selection.close = lambda: setattr(self.registry.selection, 'closed', True)
        original_status = self.registry.selection.lifecycle_status
        self.registry.selection.lifecycle_status = lambda: dict(original_status(), close_requested=True)
        self.assertTrue(self.worker.release_scoped())
        self.assertFalse(self.worker.close_extra())
        self.assertFalse(self.worker._selection_handles[0].closed)
        self.assertEqual(self.registry.selection.close_count, 0)

    def test_network_readback_budget_failure_retains_lease(self):
        self.make()
        original = self.provider.read_network
        def slow(*args):
            result = original(*args)
            self.clock.value += .201
            return result
        self.provider.read_network = slow
        self.run_worker()
        self.assertEqual(str(self.error), 'network_readback_invalid')
        self.assertIs(self.worker.lease, self.provider.lease)
        self.assertIsNone(self.sender_instance)
        self.finish_extra()

    def test_key_native_free_error_closed_flag_stays_unknown_without_retry(self):
        for error_type in (RuntimeError, KeyboardInterrupt):
            self.make()
            self.run_worker()
            key = self.crypto.key
            calls = []
            def fail_free():
                calls.append(key)
                key.closed = True
                raise error_type('private native free detail')
            key.close = fail_free
            self.assertTrue(self.worker.release_scoped())
            self.assertFalse(self.worker.close_extra())
            self.assertTrue(key.closed)
            self.assertTrue(self.worker._key_close_requested)
            self.assertFalse(self.worker._key_close_returned)
            self.assertTrue(self.worker._key_close_unknown)
            self.assertIs(self.worker._key_close_owner, key)
            self.assertIn(key, [ticket.resource for ticket in self.worker.private_owner_records()])
            self.assertTrue(self.registry.selection.closed)
            self.assertTrue(self.helper.closed)
            self.assertFalse(self.worker.close_extra())
            self.assertEqual(calls, [key])
            self.assertFalse(self.worker.status()['extra_resources_closed'])
            self.assertEqual(self.worker.status()['stage'], 'cleanup_pending')
            self.assertNotIn('native free detail', repr(self.worker.status()))

    def test_key_malformed_close_return_stays_unknown_without_retry(self):
        for returned in (True, False, 1, 'private return'):
            self.make()
            self.run_worker()
            key = self.crypto.key
            calls = []
            def malformed():
                calls.append(key)
                key.closed = True
                return returned
            key.close = malformed
            self.assertTrue(self.worker.release_scoped())
            self.assertFalse(self.worker.close_extra())
            self.assertFalse(self.worker.close_extra())
            self.assertEqual(calls, [key])
            self.assertTrue(self.worker._key_close_unknown)
            self.assertFalse(self.worker._key_close_returned)

    def test_clock_sampling_commits_in_same_lock_with_deterministic_interleaving(self):
        self.make()
        waiting = threading.Event()
        release = threading.Event()
        original_lock = self.worker._lock
        class Gate:
            def __enter__(self):
                if threading.current_thread().name == 'HOST-early-sampler':
                    waiting.set()
                    if not release.wait(1):
                        raise RuntimeError('HOST gate timed out')
                original_lock.acquire()
                return self
            def __exit__(self, *unused):
                original_lock.release()
        values = iter((100.0, 101.0))
        sampled = []
        def clock():
            sampled.append(threading.current_thread().name)
            return next(values)
        self.worker._lock = Gate()
        self.worker._clock = clock
        results = []
        failures = []
        def sample():
            try:
                results.append(self.worker._now())
            except BaseException as error:
                failures.append(error)
        first = threading.Thread(target=sample, name='HOST-early-sampler')
        second = threading.Thread(target=sample, name='HOST-later-sampler')
        first.start()
        try:
            self.assertTrue(waiting.wait(1))
            second.start()
            second.join(1)
            self.assertFalse(second.is_alive())
        finally:
            release.set()
            first.join(1)
        self.assertFalse(first.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(sampled, ['HOST-later-sampler', 'HOST-early-sampler'])
        self.assertEqual(results, [100.0, 101.0])
        self.assertEqual(self.worker._last_time, 101.0)

    def test_clock_real_rollback_nonfinite_and_wrong_type_still_rejected(self):
        self.make()
        self.assertEqual(self.worker._now(), 100.0)
        for value in (99.0, float('nan'), float('inf'), True, 10 ** 1000):
            self.worker._clock = lambda: value
            with self.assertRaisesRegex(core.SendWorkerError, '^clock_failed$'):
                self.worker._now()
            self.assertEqual(self.worker._last_time, 100.0)

    def test_strict_final_result_fills_missing_awaiting_result_notification(self):
        self.make()
        original = self.sender
        observed = []
        def factory(*args, **options):
            sender = original(*args, **options)
            def wait():
                options['state_callback']('transferring', {'bytes': 100, 'archiveSize': 100})
                observed.append(self.worker.status())
                return {'fileCount': 1, 'totalSize': 3, 'archiveBytesSent': 100,
                        'peer_completion_verified': True}
            sender.wait = wait
            return sender
        self.worker._transport_factory = factory
        result = self.run_worker()
        self.assertIsNone(self.error)
        self.assertFalse(observed[0]['localBytesVerified'])
        self.assertFalse(observed[0]['peerCompletionVerified'])
        self.assertEqual(observed[0]['archiveBytesSent'], 0)
        status = self.worker.status()
        self.assertTrue(status['localBytesVerified'])
        self.assertTrue(status['peerCompletionVerified'])
        self.assertEqual(status['archiveBytesSent'], 100)
        self.assertEqual(status['stage'], 'protocol_complete')
        self.assertEqual(result, core.SendResult(1, 3, 100, True, True))
        self.assertNotIn('localCommitVerified', status)
        self.assertFalse(hasattr(result, 'local_commit_verified'))
        self.finish_extra()

    def test_invalid_final_result_without_notification_never_fills_byte_proof(self):
        for field, value in (('archiveBytesSent', 99), ('archiveBytesSent', True),
                             ('fileCount', 2), ('totalSize', 4),
                             ('peer_completion_verified', False)):
            self.make()
            original = self.sender
            def factory(*args, **options):
                sender = original(*args, **options)
                def wait():
                    options['state_callback']('transferring', {'bytes': 100, 'archiveSize': 100})
                    result = {'fileCount': 1, 'totalSize': 3, 'archiveBytesSent': 100,
                              'peer_completion_verified': True}
                    result[field] = value
                    return result
                sender.wait = wait
                return sender
            self.worker._transport_factory = factory
            self.run_worker()
            self.assertEqual(str(self.error), 'sender_result_invalid')
            self.assertFalse(self.worker.status()['localBytesVerified'])
            self.assertFalse(self.worker.status()['peerCompletionVerified'])
            self.assertEqual(self.worker.status()['archiveBytesSent'], 0)
            self.assertEqual(self.worker.status()['stage'], 'failed')
            self.finish_extra()

    def test_late_progress_during_run_finally_cannot_downgrade_strict_result(self):
        self.make()
        closing = threading.Event()
        release = threading.Event()
        original = self.sender
        def factory(*args, **options):
            sender = original(*args, **options)
            def wait():
                options['state_callback']('transferring', {'bytes': 100, 'archiveSize': 100})
                return {'fileCount': 1, 'totalSize': 3, 'archiveBytesSent': 100,
                        'peer_completion_verified': True}
            original_close = sender.close
            def paused_close(timeout=2):
                closing.set()
                if not release.wait(1):
                    raise RuntimeError('HOST finally gate timed out')
                return original_close(timeout)
            sender.wait = wait
            sender.close = paused_close
            return sender
        self.worker._transport_factory = factory
        returned = []
        errors = []
        def body():
            try:
                returned.append(self.worker.run(self.hooks))
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=body, name='HOST-worker-finally')
        thread.start()
        try:
            self.assertTrue(closing.wait(1))
            before = self.worker.status()
            exact_result = self.worker._result
            self.assertFalse(before['run_returned'])
            self.assertEqual(before['stage'], 'protocol_complete')
            self.assertTrue(before['localBytesVerified'])
            self.assertTrue(before['peerCompletionVerified'])
            self.assertEqual(before['archiveBytesSent'], 100)
            self.assertEqual(exact_result, core.SendResult(1, 3, 100, True, True))
            callback = self.sender_instance.options['state_callback']
            callback('completed', {'fileCount': 1, 'totalSize': 3})
            self.assertEqual(self.worker.status(), before)
            callback('awaiting_result', {'archiveBytesSent': 100})
            self.assertEqual(self.worker.status(), before)
            self.assertIs(self.worker._result, exact_result)
        finally:
            release.set()
            thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(returned, [exact_result])
        self.assertIs(returned[0], exact_result)
        self.assertEqual(self.worker.status()['stage'], 'protocol_complete')
        self.assertNotIn('localCommitVerified', self.worker.status())
        self.finish_extra()

    def test_constructor_bounds_bool_huge_nan_duplicate_and_repr(self):
        self.make()
        for timeout in (True, float('nan'), float('inf'), 10 ** 1000, 0):
            with self.assertRaises(core.SendWorkerError):
                core.SendWorker(self.worker.handoff, self.registry, ['file-id'], timeout=timeout)
        with self.assertRaises(core.SendWorkerError):
            core.SendWorker(self.worker.handoff, self.registry, ['file-id', 'file-id'])
        self.assertEqual(repr(self.worker), '<SendWorker>')

    def test_source_python35_no_subprocess_thread_spawn_or_inline_restore(self):
        source = (BASE / 'runtime' / 'mta_send_worker.py').read_text(encoding='utf-8')
        ast.parse(source, feature_version=(3, 5))
        tree = ast.parse(source)
        names = [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)]
        self.assertNotIn('Popen', names)
        self.assertNotIn('Thread', names)
        self.assertNotIn('restore', names)
        self.assertNotIn('create_connection', names)
        self.assertNotIn('socket', names)


if __name__ == '__main__':
    unittest.main()
