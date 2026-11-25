"""New HOST batch: fake native events/clocks only, no external IO."""
import ast
import base64
import os
import pathlib
import socket
import subprocess
import sys
import threading
import unittest
from unittest import mock

BASE = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (BASE / 'runtime' / 'mta_scan_handoff.py').read_text(encoding='utf-8')
sys.path.insert(0, str(BASE / 'runtime'))
import mta_scan_handoff as core


class Helper:
    def send(self, value):
        raise AssertionError('component must not send any helper command')


class Clock:
    def __init__(self):
        self.now, self.calls = 100.0, 0
    def __call__(self):
        self.calls += 1
        return self.now


def peer(number=7, cached=False):
    return {'event': 'discovered', 'peer': number, 'cached': cached,
            'name_b64': base64.b64encode('附近互传'.encode('utf-8')).decode('ascii'),
            'service_data': [{'uuid': '00009955-0000-1000-8000-00805f9b34fb', 'payload_b64': 'YQ=='}]}


class ScanHandoffTests(unittest.TestCase):
    def setUp(self):
        self.guards = []
        for obj, names in ((os, ('open', 'mkdir', 'makedirs', 'unlink', 'remove', 'rmdir', 'rename', 'replace', 'kill')),
                           (socket, ('socket', 'create_connection')), (subprocess, ('Popen', 'run'))):
            for name in names:
                guard = mock.patch.object(obj, name, side_effect=AssertionError('actual IO forbidden'))
                guard.start()
                self.guards.append(guard)
        self.addCleanup(lambda: [guard.stop() for guard in reversed(self.guards)])
        self.clock, self.helper, self.cancelled = Clock(), Helper(), threading.Event()
        self.session = core.ScanSession(self.helper, 2, 3, 100.0, clock=self.clock, cancelled=self.cancelled)

    def event(self, value, **identity):
        return self.session.native_event(value, identity.get('helper', self.helper),
            identity.get('native_epoch', 2), identity.get('operation_epoch', 3))

    def ready(self):
        self.assertTrue(self.event({'event': 'scan', 'code': 'ready'}))
        self.assertTrue(self.event(peer()))

    def intent(self):
        self.ready()
        return self.session.claim_intent('7', ['opaque-file-id'], 'internal-task')

    def test_python35_ast_and_no_external_actions(self):
        tree = ast.parse(SOURCE, feature_version=(3, 5))
        names = [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)]
        for name in ('send', 'Popen', 'Thread', 'socket', 'open', 'restore', 'generate_keypair'):
            self.assertNotIn(name, names)

    def test_constructor_and_status_are_pure_and_nonsecret(self):
        self.assertEqual(self.clock.calls, 0)
        status = self.session.status()
        self.assertEqual(self.clock.calls, 0)
        self.assertFalse(status['platform_available'])
        self.assertNotIn('file', repr(status))
        self.assertNotIn('internal-task', repr(self.session))

    def test_only_real_ready_then_noncached_events_enable_claim(self):
        self.assertFalse(self.event(peer()))
        with self.assertRaisesRegex(core.ScanHandoffError, 'scan_not_ready'):
            self.session.claim_intent('7', ['opaque'], 'task')
        self.assertTrue(self.event({'event': 'scan', 'code': 'ready'}))
        self.assertFalse(self.event(peer(cached=True)))
        with self.assertRaisesRegex(core.ScanHandoffError, 'unknown_peer'):
            self.session.claim_intent('7', ['opaque'], 'task')
        self.assertTrue(self.event(peer()))
        self.assertIs(type(self.session.claim_intent('7', ['opaque'], 'task')), core.SendIntent)

    def test_boolean_ready_and_extra_ready_fields_fail_closed(self):
        for event in ({'event': 'scan', 'code': True}, {'event': 'scan', 'code': 'ready', 'ready': True}):
            self.session = core.ScanSession(self.helper, 2, 3, 100, clock=self.clock)
            self.assertFalse(self.event(event))
            self.assertTrue(self.session.status()['invalidated'])

    def test_duplicate_ready_does_not_restart_or_extend_scan(self):
        self.ready()
        self.assertFalse(self.event({'event': 'scan', 'code': 'ready'}))
        self.assertTrue(self.cancelled.is_set())

    def test_exact_helper_and_epochs_reject_other_namespaces_without_clock(self):
        for identity in ({'helper': Helper()}, {'native_epoch': True}, {'native_epoch': 4},
                         {'operation_epoch': True}, {'operation_epoch': 4}):
            self.assertFalse(self.event({'event': 'scan', 'code': 'ready'}, **identity))
        self.assertEqual(self.clock.calls, 0)
        self.assertFalse(self.cancelled.is_set())

    def test_canonical_device_ids_and_file_ids_no_arbitrary_paths_proof(self):
        self.ready()
        for identifier, files in (('07', ['opaque']), ('0', ['opaque']), ('65536', ['opaque']),
            (True, ['opaque']), ('7', ('opaque',)), ('7', []), ('7', ['opaque', 'opaque']),
            ('7', [True]), ('7', ['x' * 129])):
            with self.assertRaisesRegex(core.ScanHandoffError, 'invalid_input'):
                self.session.claim_intent(identifier, files, 'task')

    def test_intent_is_once_immutable_and_readback_real_same_domain(self):
        intent = self.intent()
        self.assertIs(intent.cancelled, self.cancelled)
        self.assertEqual(intent.file_ids, ('opaque-file-id',))
        self.assertIs(intent.handoff.helper, self.helper)
        self.assertFalse(self.session.status()['selectable'])
        with self.assertRaises(AttributeError):
            intent.file_ids = ('foreign',)
        with self.assertRaisesRegex(core.ScanHandoffError, 'intent_already_claimed'):
            self.session.claim_intent('7', ['other'], 'other-task')
        observation = intent.handoff.readback(intent.handoff, .2)
        self.assertIs(type(observation), core.ScanObservation)
        self.assertIs(observation.helper, self.helper)
        self.assertEqual((observation.native_epoch, observation.operation_epoch, observation.peer), (2, 3, 7))
        self.assertIs(observation.cached, False)
        self.assertIs(observation.active, True)
        self.assertEqual(repr(intent), '<private scan send intent>')

    def test_copy_equal_handoff_is_not_exact_owner(self):
        intent = self.intent()
        copy = core.ScanHandoff(*intent.handoff)
        self.assertEqual(copy, intent.handoff)
        with self.assertRaisesRegex(core.ScanHandoffError, 'handoff_changed'):
            self.session.readback(copy, .2)
        with self.assertRaisesRegex(core.ScanHandoffError, 'handoff_changed'):
            self.session.note_client_read(copy, {'cmd': 'client_read', 'peer': 7})

    def test_discovery_stale_at_exact_fifteen_seconds(self):
        self.ready()
        self.clock.now = 115
        with self.assertRaisesRegex(core.ScanHandoffError, 'peer_expired'):
            self.session.claim_intent('7', ['opaque'], 'task')

    def test_cached_update_cannot_refresh_old_discovery(self):
        self.ready()
        self.clock.now = 114
        self.assertFalse(self.event(peer(cached=True)))
        self.clock.now = 115
        with self.assertRaisesRegex(core.ScanHandoffError, 'peer_expired'):
            self.session.claim_intent('7', ['opaque'], 'task')

    def test_fresh_update_extends_peer_time_but_not_scan_ttl(self):
        self.ready()
        self.clock.now = 114
        self.assertTrue(self.event(peer()))
        intent = self.session.claim_intent('7', ['opaque'], 'task')
        self.assertEqual(intent.handoff.seen_at, 114)
        self.clock.now = 130
        with self.assertRaises(core.ScanHandoffError):
            self.session.readback(intent.handoff, .2)
        self.assertTrue(intent.cancelled.is_set())
        self.assertEqual(self.session.status()['reason'], 'scan_expired')

    def test_late_ready_cannot_renew_command_ttl(self):
        self.clock.now = 130
        self.assertFalse(self.event({'event': 'scan', 'code': 'ready'}))
        self.assertEqual(self.session.status()['reason'], 'scan_expired')
        self.assertTrue(self.cancelled.is_set())

    def test_note_is_exact_command_once_and_does_not_change_native_active(self):
        intent = self.intent()
        for command in ({'cmd': 'client_read', 'peer': True}, {'cmd': 'client_read', 'peer': 8},
            {'cmd': 'client_read', 'peer': 7, 'handoffSucceeded': True}, {'cmd': 'stop', 'peer': 7}, True):
            with self.assertRaisesRegex(core.ScanHandoffError, 'invalid_input'):
                self.session.note_client_read(intent.handoff, command)
        self.assertIs(self.session.note_client_read(intent.handoff, {'cmd': 'client_read', 'peer': 7}), intent)
        self.assertTrue(self.session.status()['native_scan_active'])
        self.assertFalse(self.cancelled.is_set())
        with self.assertRaisesRegex(core.ScanHandoffError, 'read_already_noted'):
            self.session.note_client_read(intent.handoff, {'cmd': 'client_read', 'peer': 7})

    def test_legitimate_native_stop_keeps_intent_not_fake_active(self):
        intent = self.intent()
        self.session.note_client_read(intent.handoff, {'cmd': 'client_read', 'peer': 7})
        self.assertTrue(self.event({'event': 'scan', 'code': 'own_session_stopped'}))
        self.assertTrue(self.session.status()['intent_valid'])
        self.assertFalse(self.session.status()['native_scan_active'])
        self.assertFalse(self.cancelled.is_set())
        self.assertIs(self.session.readback(intent.handoff, .2).active, False)
        self.clock.now = 131
        # The real stop reset scan_deadline; passive status/unknown events do not invent expiry.
        self.assertFalse(self.event({'event': 'client_status'}))
        self.assertFalse(self.cancelled.is_set())

    def test_unnoted_stop_invalidates_current_intent(self):
        self.intent()
        self.assertFalse(self.event({'event': 'scan', 'code': 'own_session_stopped'}))
        self.assertTrue(self.cancelled.is_set())
        self.assertFalse(self.session.status()['intent_valid'])

    def test_native_expiry_after_handoff_stop_still_cancels_intent(self):
        intent = self.intent()
        self.session.note_client_read(intent.handoff, {'cmd': 'client_read', 'peer': 7})
        self.event({'event': 'scan', 'code': 'own_session_stopped'})
        self.assertFalse(self.event({'event': 'scan', 'code': 'lease_expired'}))
        self.assertTrue(intent.cancelled.is_set())
        self.assertEqual(self.session.status()['reason'], 'scan_expired')

    def test_cleanup_closed_error_stop_read_failure_cancel_after_claim(self):
        for event in ({'event': 'cleanup', 'code': 'scan_stop_failed_owner_exit_will_release'},
                      {'event': 'closed'}, {'event': 'error', 'code': 'private detail'},
                      {'event': 'stop', 'code': 'resources_released_or_cleanup_reported'},
                      {'event': 'client_read', 'code': 'read_failed'}):
            self.cancelled = threading.Event()
            self.session = core.ScanSession(self.helper, 2, 3, 100, clock=self.clock, cancelled=self.cancelled)
            intent = self.intent()
            self.assertFalse(self.event(event))
            self.assertTrue(intent.cancelled.is_set())
            self.assertEqual(self.session.status()['reason'], 'native_failed')
            self.assertNotIn('private detail', repr(self.session.status()))

    def test_peer_id_range_and_bounded_inventory_are_distinct(self):
        self.event({'event': 'scan', 'code': 'ready'})
        for number in range(65504, 65536):
            self.assertTrue(self.event(peer(number)))
        self.assertEqual(self.session.status()['peer_records'], 32)
        self.assertTrue(self.event(peer(65535)))
        self.assertFalse(self.event(peer(7)))
        self.assertTrue(self.cancelled.is_set())

    def test_malformed_discovered_name_service_fields_fail_closed(self):
        rows = [dict(peer(), peer=True), dict(peer(), cached=0), dict(peer(), name_b64='!'),
                dict(peer(), name_b64=base64.b64encode(b'\xff').decode('ascii')),
                dict(peer(), service_data=[{'uuid': 'bad', 'payload_b64': 'YQ=='}]),
                dict(peer(), service_data=[{'uuid': '00009955-0000-1000-8000-00805f9b34fb',
                                          'payload_b64': base64.b64encode(b'a' * 32).decode('ascii')}]),
                dict(peer(), foreign=True), dict(peer(), service_data=[])]
        for event in rows[:-1]:
            self.session = core.ScanSession(self.helper, 2, 3, 100, clock=self.clock)
            self.event({'event': 'scan', 'code': 'ready'})
            self.assertFalse(self.event(event))
            self.assertEqual(self.session.status()['reason'], 'native_event_invalid')
        self.session = core.ScanSession(self.helper, 2, 3, 100, clock=self.clock)
        self.event({'event': 'scan', 'code': 'ready'})
        self.assertTrue(self.event(rows[-1]))

    def test_clock_invalid_and_backwards_are_sticky_and_reader_safe(self):
        for value in (True, float('nan'), float('inf'), -1, 99, 10 ** 1000):
            self.clock.now = 100
            self.cancelled = threading.Event()
            self.session = core.ScanSession(self.helper, 2, 3, 100, clock=self.clock, cancelled=self.cancelled)
            self.ready()
            self.clock.now = value
            self.assertFalse(self.event(peer()))
            self.assertTrue(self.cancelled.is_set())
            self.assertEqual(self.session.status()['reason'], 'clock_failed')

    def test_clock_sampling_is_serialized_across_native_threads(self):
        self.ready()
        entered, release, second = threading.Event(), threading.Event(), threading.Event()
        samples, outcomes = [], []
        def clock():
            samples.append(len(samples) + 1)
            if len(samples) == 1:
                entered.set()
                if not release.wait(1):
                    raise AssertionError('HOST clock release missed')
            else:
                second.set()
            return 100.0 + samples[-1] / 10
        self.session._clock = clock
        first = threading.Thread(target=lambda: outcomes.append(self.event(peer())))
        other = threading.Thread(target=lambda: outcomes.append(self.event(peer())))
        first.start()
        self.assertTrue(entered.wait(1))
        other.start()
        self.assertFalse(second.wait(.01))
        release.set()
        first.join(1)
        other.join(1)
        self.assertFalse(first.is_alive() or other.is_alive())
        self.assertEqual(outcomes, [True, True])
        self.assertEqual(samples, [1, 2])
        self.assertFalse(self.cancelled.is_set())

    def test_readback_budget_and_crossing_expiry_reject(self):
        intent = self.intent()
        for budget in (True, float('nan'), float('inf'), 0, .201):
            with self.assertRaises(core.ScanHandoffError):
                self.session.readback(intent.handoff, budget)
        ticks = iter((114.9, 130.0))
        self.session._clock = lambda: next(ticks)
        with self.assertRaises(core.ScanHandoffError):
            self.session.readback(intent.handoff, .2)
        self.assertTrue(self.cancelled.is_set())

    def test_shared_cancel_and_explicit_cancel_no_helper_actions(self):
        intent = self.intent()
        self.cancelled.set()
        self.assertFalse(self.session.status()['intent_valid'])
        with self.assertRaises(core.ScanHandoffError):
            self.session.readback(intent.handoff, .2)
        self.assertEqual(self.session.status()['reason'], 'cancelled')
        self.session.cancel()
        self.assertTrue(self.session.status()['cancel_requested'])

    def test_constructor_boundaries(self):
        for options in ({'native_epoch': True}, {'operation_epoch': 0}, {'started_at': float('nan')},
                        {'ttl': True}, {'ttl': 61}, {'cancelled': True}):
            args = dict(helper=self.helper, native_epoch=2, operation_epoch=3, started_at=100, clock=self.clock)
            args.update(options)
            with self.assertRaises(core.ScanHandoffError):
                core.ScanSession(**args)
        self.assertEqual(self.clock.calls, 0)


if __name__ == '__main__':
    unittest.main()
