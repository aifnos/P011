"""HOST-only original PrivateHelper drain/close contracts.

Extract the real new PrivateHelper and State classes, not substitute production
methods. Real child Popen/PIPE/Thread exercise delayed cleanup, physical EOF,
decode failure, nonzero exit and a real 18-second wait timeout. The child is a
finite HOST script, not mta-bluez-helper; no State constructor/Parent/Session
startup or native radio is used, and no receive/restore/admission is certified.
The Popen adapter only redirects the fixed fixture path to the HOST interpreter.
"""
import ast
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock


BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / 'candidate/receive-radio-lifecycle-v1/runtime/mta_service.py'
SOURCE_PIN = (105064, '2924c44e15be6f1d445906ea9c9e5b47798cc0c1bdf95bb16a3c13c44e9ddb43')
CODEC = BASE / 'runtime/p011_json.py'
CODEC_PIN = (8061, 'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
RADIO = BASE / 'runtime/mta_receive_radio_baseline.py'
RADIO_PIN = (3971, '27a1cf60be3f964862904233c600af11b8d3e9468febba61d8c622fceb29824c')
FIXTURE_PATH = '/HOST/pipe-fixture-not-native-never-RF'

CHILD = r'''
import json
import os
import sys
import time

mode = sys.argv[1]
def emit(data):
    written = os.write(1, data)
    if written != len(data):
        raise RuntimeError('HOST fixture short output')

emit(b'{"event":"helper","code":"ready_no_radio_change"}\n')
if mode == 'timeout':
    time.sleep(60)
else:
    stop_seen = False
    for line in sys.stdin.buffer:
        if json.loads(line.decode('ascii')) == {'cmd': 'stop'}:
            stop_seen = True
    # Child only emits these after the parent's original stdin physically closes.
    if not stop_seen:
        sys.exit(9)
    time.sleep(.03)
    if mode == 'invalid':
        emit(b'{not-valid-json}\n')
    else:
        emit(b'{"event":"cleanup","code":"gatt_unregistered"}\n')
        time.sleep(.03)
        emit(b'{"event":"advertisement","code":"ownership_lost"}\n')
    sys.exit(7 if mode == 'nonzero' else 0)
'''


def fixed_bytes(path, pin):
    data = path.read_bytes()
    if (len(data), hashlib.sha256(data).hexdigest()) != pin:
        raise AssertionError('HOST SOURCE changed')
    return data


def load_actual_class():
    fixed_bytes(CODEC, CODEC_PIN)
    spec = importlib.util.spec_from_file_location('_host_helper_drain_codec', str(CODEC))
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    text = fixed_bytes(SOURCE, SOURCE_PIN).decode('utf-8')
    tree = ast.parse(text, filename=str(SOURCE))
    nodes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name in ('PrivateHelper', 'State')]
    if len(nodes) != 2 or {node.name for node in nodes} != {'PrivateHelper', 'State'}:
        raise AssertionError('HOST actual helper/State definitions unavailable')
    fixed_bytes(RADIO, RADIO_PIN)
    radio_spec = importlib.util.spec_from_file_location('_host_actual_radio_baseline', str(RADIO))
    radio = importlib.util.module_from_spec(radio_spec)
    radio_spec.loader.exec_module(radio)
    namespace = {'subprocess': subprocess, 'threading': threading, 'time': time,
                 'json': codec, 'radio_baseline': radio, '__name__': '_host_actual_private_helper'}
    actual = ast.Module(body=nodes, type_ignores=[])
    ast.fix_missing_locations(actual)
    exec(compile(actual, str(SOURCE), 'exec'), namespace)
    return namespace['PrivateHelper'], namespace['State'], namespace


class HelperDrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper_type, cls.state_type, cls.owner_globals = load_actual_class()

    def setUp(self):
        self.helpers = []

    def tearDown(self):
        # Only finite original HOST fixtures, never global-name termination.
        for helper in self.helpers:
            helper.close()
            process = helper._process_original
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                helper._reader_original.join(3)
                for handle in (helper._stdin_original, helper._stdout_original):
                    if handle is not None and not handle.closed:
                        handle.close()
                self.assertFalse(helper._reader_original.is_alive())

    def start_fixture(self, mode, callback_error=False):
        observed = []
        ready = threading.Event()
        fixture_error = RuntimeError('HOST private callback failure')

        def callback(event):
            observed.append((event, threading.current_thread()))
            if event.get('event') == 'helper':
                ready.set()
            if callback_error and event.get('event') == 'cleanup':
                raise fixture_error

        helper = self.helper_type(FIXTURE_PATH, callback)
        self.helpers.append(helper)
        original_popen = subprocess.Popen

        def host_child(argv, **options):
            self.assertEqual(argv, [FIXTURE_PATH, '--serve', 'hci0'])
            self.assertIs(options['stdin'], subprocess.PIPE)
            self.assertIs(options['stdout'], subprocess.PIPE)
            self.assertIs(options['stderr'], subprocess.DEVNULL)
            return original_popen([sys.executable, '-I', '-B', '-c', CHILD, mode], **options)

        # Only the original Popen creator is redirected. Helper/read/close and
        # the returned Popen's wait/terminate/kill/PIPE methods remain actual.
        with mock.patch.object(subprocess, 'Popen', side_effect=host_child):
            helper.start()
        self.assertTrue(ready.wait(3), 'HOST fixture did not start')
        self.assertIs(helper.process, helper._process_original)
        self.assertIs(helper.thread, helper._reader_original)
        self.assertIs(helper.process.stdin, helper._stdin_original)
        self.assertIs(helper.process.stdout, helper._stdout_original)
        self.assertFalse(helper.stdout_eof)
        return helper, observed, fixture_error

    def assert_physical_end(self, helper):
        self.assertFalse(helper.thread.is_alive())
        self.assertIsNotNone(helper.process.poll())
        self.assertTrue(helper._stdin_original.closed)
        self.assertTrue(helper._stdout_original.closed)

    def test_pure_unstarted_owner_has_known_zero_inventory(self):
        helper = self.helper_type(FIXTURE_PATH, lambda event: None)
        self.helpers.append(helper)
        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('HOST no child allowed')):
            self.assertTrue(helper.closure_verified())
            self.assertTrue(helper.close())
        self.assertFalse(helper.spawn_claimed)
        self.assertFalse(helper.reader_claimed)
        self.assertFalse(helper.stdout_eof)
        self.assertIsNone(helper.returncode)
        helper.spawn_unknown = True  # Explicit negative partial-creation fixture.
        self.assertFalse(helper.closure_verified())

    def test_close_drains_all_late_cleanup_in_original_reader(self):
        helper, observed, unused = self.start_fixture('late')
        self.assertTrue(helper.close())
        self.assert_physical_end(helper)
        self.assertTrue(helper.stdout_eof)
        self.assertEqual(helper.returncode, 0)
        self.assertIsNone(helper.reader_error)
        self.assertEqual([event for event, thread in observed], [
            {'event': 'helper', 'code': 'ready_no_radio_change'},
            {'event': 'cleanup', 'code': 'gatt_unregistered'},
            {'event': 'advertisement', 'code': 'ownership_lost'},
            {'event': 'closed'}])
        self.assertTrue(all(thread is helper.thread for event, thread in observed))
        # Exactly-once cleanup: a later passive query must not issue more I/O.
        with mock.patch.object(helper.process, 'wait', side_effect=AssertionError('HOST no second wait')):
            self.assertTrue(helper.close())
        self.assertEqual(len(observed), 4)
        with self.assertRaises(ValueError):
            helper.send({'cmd': 'listen'})

    def test_closed_notification_cannot_substitute_for_physical_eof(self):
        helper, observed, unused = self.start_fixture('late')
        helper.callback({'event': 'closed'})  # Explicit synthetic-notification negative.
        self.assertFalse(helper.stdout_eof)
        self.assertFalse(helper.closure_verified())
        self.assertTrue(helper.close())
        self.assertTrue(helper.stdout_eof)
        self.assert_physical_end(helper)

    def test_malformed_late_output_retains_first_reader_error(self):
        helper, observed, unused = self.start_fixture('invalid')
        self.assertFalse(helper.close())
        self.assert_physical_end(helper)
        self.assertIsInstance(helper.reader_error, ValueError)
        primary = helper.reader_error
        self.assertFalse(helper.stdout_eof)
        self.assertEqual(helper.returncode, 0)
        self.assertIn({'event': 'error', 'code': 'native_ipc_invalid'}, [e for e, t in observed])
        self.assertFalse(helper.close())
        self.assertIs(helper.reader_error, primary)

    def test_callback_error_is_not_lost_or_upgraded_to_eof(self):
        helper, observed, fixture_error = self.start_fixture('late', callback_error=True)
        self.assertFalse(helper.close())
        self.assert_physical_end(helper)
        self.assertIs(helper.reader_error, fixture_error)
        self.assertFalse(helper.stdout_eof)
        self.assertEqual(helper.returncode, 0)
        self.assertIn({'event': 'error', 'code': 'native_ipc_invalid'}, [e for e, t in observed])

    def test_nonzero_exit_keeps_resources_closed_but_verification_false(self):
        helper, observed, unused = self.start_fixture('nonzero')
        self.assertFalse(helper.close())
        self.assert_physical_end(helper)
        self.assertTrue(helper.stdout_eof)
        self.assertEqual(helper.returncode, 7)
        self.assertIsNone(helper.reader_error)
        self.assertFalse(helper.closure_verified())

    def test_real_wait_timeout_does_not_upgrade_forced_exit(self):
        helper, observed, unused = self.start_fixture('timeout')
        original_terminate = helper.process.terminate
        with mock.patch.object(helper.process, 'terminate', wraps=original_terminate) as terminate:
            self.assertFalse(helper.close())  # Real 18-second wait expiry.
            self.assertEqual(terminate.call_count, 1)
            self.assertFalse(helper.close())
            self.assertEqual(terminate.call_count, 1)
        self.assert_physical_end(helper)
        self.assertTrue(helper._wait_timeout)
        self.assertTrue(helper.stdout_eof)
        self.assertIs(type(helper.returncode), int)
        self.assertNotEqual(helper.returncode, 0)
        self.assertFalse(helper.closure_verified())

    def test_actual_state_radio_verification_rejects_unknown_and_equal_counts(self):
        # Explicit HOST capability/Popen-actor DATA models, not live BlueZ,
        # actual State construction, native GATT, RF or restoration proof.
        baseline = {
            'event': 'capabilities', 'radio_schema': 'p011-bluez-radio-baseline-v1',
            'powered': True, 'bredr_enabled': True, 'le_enabled': True,
            'global_advertising': False, 'bluez_advertising_active': False,
            'connectable_advert': True, 'discovering': False, 'discoverable': False,
            'pairable': True, 'mgmt_info': True, 'features': True,
            'bluez_advertising_known': True, 'adapter_properties_known': True,
            'connected_devices_known': True, 'current_settings': 641,
            'bluez_owner': ':1.30', 'max_adv': 31, 'max_scan': 31,
            'max_instances': 5, 'active_instances': 0,
            'active_instance_ids': [], 'connected_devices': []}
        scenarios = [
            ('same', dict(baseline), dict(baseline), False, False, True),
            ('missing', dict(baseline), {k: v for k, v in baseline.items() if k != 'bluez_owner'}, False, False, False),
            ('unknown_owner', dict(baseline), dict(baseline, bluez_owner=None), False, False, False),
            ('changed_owner', dict(baseline), dict(baseline, bluez_owner=':1.31'), False, False, False),
            ('unknown_peers', dict(baseline), dict(baseline, connected_devices_known=False), False, False, False),
            ('same_peer_count', dict(baseline, connected_devices=['/org/bluez/hci0/dev_02_00_00_00_00_11']),
                dict(baseline, connected_devices=['/org/bluez/hci0/dev_02_00_00_00_00_22']), False, False, False),
            ('same_advert_identity', dict(baseline, active_instances=1, active_instance_ids=[2]),
                dict(baseline, active_instances=1, active_instance_ids=[2]), False, False, True),
            ('same_advert_count', dict(baseline, active_instances=1, active_instance_ids=[2]),
                dict(baseline, active_instances=1, active_instance_ids=[3]), False, False, False),
            ('post_probe_unclosed', dict(baseline), dict(baseline), False, True, False),
            ('prior_probe_unclosed', dict(baseline), dict(baseline), True, False, False)]
        for name, before, after, prior_unclosed, post_unclosed, expected in scenarios:
            with self.subTest(case=name):
                state = self.state_type.__new__(self.state_type)
                state.bluez_path = FIXTURE_PATH
                state.bluetooth_caps = before
                state.probe_actors = ([{'spawn_pending': False, 'spawn_unknown': False, 'closed': False}]
                                      if prior_unclosed else [])
                state.state = 'idle'
                state.reason = ''
                state.receive_available = False
                state.radio_restore_pending = True
                calls = []

                def capability_model(path, args, actors=None):
                    self.assertEqual(path, FIXTURE_PATH)
                    self.assertEqual(args, ['--capabilities', 'hci0'])
                    self.assertIs(actors, state.probe_actors)
                    calls.append((path, tuple(args)))
                    actors.append({'spawn_pending': False, 'spawn_unknown': False,
                                   'closed': not post_unclosed})
                    return after

                # Original State.verify_radio_restore/_probes_closed and the
                # complete actual parser are executed; only probe IO is modelled.
                with mock.patch.dict(self.owner_globals, {'capability': capability_model}):
                    self.assertIs(state.verify_radio_restore(), expected)
                self.assertEqual(len(calls), 0 if prior_unclosed else 1)
                self.assertFalse(state.receive_available)
                if not prior_unclosed:
                    self.assertIs(state.radio_restore_pending, not expected)
                    self.assertEqual(state.state, 'idle' if expected else 'error')


if __name__ == '__main__':
    unittest.main()
