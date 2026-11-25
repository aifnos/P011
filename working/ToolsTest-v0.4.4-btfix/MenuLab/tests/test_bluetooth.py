#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Host-only mocks; does not access D-Bus, the pen or its radio."""
import ast
import os
import sys
import threading
import time
import unittest

RUNTIME = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runtime'))
sys.path.insert(0, RUNTIME)
import tools_bluetooth as B


def path(number):
    return B.ADAPTER + '/dev_00_11_22_33_' + '{:02X}_{:02X}'.format(
        (number // 256) % 256, number % 256)


def device(number, name=None, alias=None):
    value = {'Address': path(number).rsplit('dev_', 1)[1].replace('_', ':')}
    if name is not None:
        value['Name'] = name
    if alias is not None:
        value['Alias'] = alias
    return value


class Clock:
    def __init__(self):
        self.value = 100.0
    def __call__(self):
        return self.value


class Backend:
    def __init__(self, callbacks, objects=None):
        self.callbacks = callbacks
        self.objects = objects or {B.ADAPTER: {B.ADAPTER_IFACE: {
            'Powered': True, 'Discovering': True}}}
        self.calls = []
        self.pending = []
        self.start_error = None
        self.stop_error = None
        self.start_hook = None
        self.stop_hook = None
        self.closed = False
        self.call_threads = []
    def mark(self, name):
        self.calls.append(name)
        self.call_threads.append(threading.current_thread().ident)
    def baseline(self):
        self.mark('baseline')
        return self.objects
    def start(self):
        self.mark('start')
        if self.start_hook:
            self.start_hook()
        if self.start_error:
            raise self.start_error
    def stop(self):
        self.mark('stop')
        if self.stop_hook:
            self.stop_hook()
        if self.stop_error:
            raise self.stop_error
    def pump(self):
        pending, self.pending = self.pending, []
        for kind, args in pending:
            self.callbacks[kind](*args)
    def close(self):
        self.mark('close')
        self.closed = True


class DBusError(Exception):
    def get_dbus_name(self):
        return 'org.bluez.Error.InProgress'


class BluetoothTests(unittest.TestCase):
    def service(self, objects=None, autostart=False):
        self.clock = Clock()
        self.logs = []
        self.backends = []
        def factory(callbacks):
            result = Backend(callbacks, objects)
            self.backends.append(result)
            return result
        self.discovery = B.BluetoothDiscovery(self.logs.append, factory,
                                              self.clock, autostart)
        return self.discovery

    def tearDown(self):
        discovery = getattr(self, 'discovery', None)
        if discovery:
            discovery.close()
            # Deterministic tests don't start a thread; emulate its finally.
            if not discovery._thread.is_alive():
                discovery._release(close=True)

    def test_schema_and_initial_baseline_is_cache(self):
        objects = {B.ADAPTER: {B.ADAPTER_IFACE: {'Powered': True, 'Discovering': True}},
                   path(1): {B.DEVICE_IFACE: device(1, 'Named', 'not used')},
                   path(2): {B.DEVICE_IFACE: device(2, alias='Alias Only')}}
        discovery = self.service(objects)
        discovery._step()
        state = discovery.snapshot()
        for key in ('available', 'powered', 'discovering', 'status', 'active',
                    'owner', 'request_id', 'generation', 'remaining_ms', 'error',
                    'epoch', 'devices', 'counts'):
            self.assertIn(key, state)
        self.assertEqual(state['counts'], dict(total=2, named=1, observed=0))
        self.assertEqual([item['source'] for item in state['devices']], ['cache', 'cache'])
        self.assertEqual(state['devices'][1]['name'], '')
        self.assertIsNone(state['devices'][0]['last_seen_age_ms'])
        self.assertNotIn('start', self.backends[0].calls)

    def test_start_idempotence_and_owned_timeout_stop(self):
        discovery = self.service()
        first = discovery.start('toolbox', 'request1')
        self.assertEqual(first['status'], 'starting')
        discovery._step()
        second = discovery.start('toolbox', 'request1')
        self.assertEqual(second['generation'], first['generation'])
        discovery._step()
        self.assertEqual(self.backends[0].calls.count('start'), 1)
        self.clock.value += 20.1
        discovery._step()
        self.assertEqual(discovery.snapshot()['status'], 'completed')
        self.assertEqual(self.backends[0].calls.count('stop'), 1)
        self.assertTrue(discovery.snapshot()['discovering'])  # Other owner's scan.
        discovery.start('toolbox', 'request1')
        discovery._step()
        self.assertEqual(self.backends[0].calls.count('start'), 1)

    def test_old_stop_cannot_stop_new_request_and_replay_cannot_start(self):
        discovery = self.service()
        discovery.start('stock', 'first')
        discovery._step()
        discovery.start('toolbox', 'second')
        discovery._step()
        backend = self.backends[0]
        self.assertEqual(backend.calls.count('stop'), 1)
        state = discovery.stop('stock', 'first')
        discovery._step()
        self.assertEqual(state['request_id'], 'second')
        self.assertTrue(state['active'])
        self.assertEqual(backend.calls.count('stop'), 1)
        discovery.start('stock', 'first')
        self.assertEqual(discovery.snapshot()['request_id'], 'second')

    def test_stop_before_start_cancels_without_dbus_stop(self):
        discovery = self.service()
        discovery.stop('stock', 'cancelled')
        discovery.start('stock', 'cancelled')
        discovery._step()
        self.assertEqual(discovery.snapshot()['status'], 'idle')
        self.assertNotIn('start', self.backends[0].calls)
        self.assertNotIn('stop', self.backends[0].calls)
        discovery.start('stock', 'queued')
        discovery.stop('stock', 'queued')
        discovery._step()
        self.assertNotIn('start', self.backends[0].calls)

    def test_stop_during_start_releases_exact_acquisition(self):
        discovery = self.service()
        discovery._step()
        backend = self.backends[0]
        backend.start_hook = lambda: discovery.stop('toolbox', 'racing')
        discovery.start('toolbox', 'racing')
        discovery._step()
        self.assertEqual(discovery.snapshot()['status'], 'stopped')
        self.assertEqual(backend.calls.count('start'), 1)
        self.assertEqual(backend.calls.count('stop'), 1)

    def test_failed_start_never_calls_stop_closes_private_bus(self):
        discovery = self.service()
        discovery._step()
        backend = self.backends[0]
        backend.start_error = DBusError('private device name/address must not leak')
        discovery.start('toolbox', 'failure')
        discovery._step()
        self.assertEqual(discovery.snapshot()['status'], 'error')
        self.assertEqual(discovery.snapshot()['error'], 'org.bluez.Error.InProgress')
        self.assertNotIn('stop', backend.calls)
        self.assertTrue(backend.closed)
        self.assertNotIn('private device', '\n'.join(self.logs))

    def test_failed_stop_closes_private_bus_once(self):
        discovery = self.service()
        discovery.start('toolbox', 'owned')
        discovery._step()
        backend = self.backends[0]
        backend.stop_error = RuntimeError('do not echo')
        discovery.stop('toolbox', 'owned')
        discovery._step()
        self.assertTrue(backend.closed)
        self.assertEqual(backend.calls.count('stop'), 1)
        discovery.stop('toolbox', 'owned')
        discovery._step()
        self.assertEqual(backend.calls.count('stop'), 1)

    def test_signal_merge_invalidations_removal_and_anonymous_logs(self):
        discovery = self.service()
        discovery.start('toolbox', 'signals')
        discovery._step()
        backend = self.backends[0]
        backend.pending.append(('added', (path(1), {B.DEVICE_IFACE: device(1, 'SECRETNAME')})))
        discovery._step()
        self.clock.value += .3
        backend.pending.append(('changed', (B.DEVICE_IFACE,
            {'Paired': True, 'Connected': True, 'Class': 1234}, [], path(1))))
        discovery._step()
        row = discovery.snapshot()['devices'][0]
        self.assertEqual(row['name'], 'SECRETNAME')
        self.assertEqual(row['source'], 'updated')
        self.assertTrue(row['seen_this_session'])
        self.assertTrue(row['paired'])
        self.assertTrue(row['connected'])
        self.assertEqual(row['class_code'], 1234)
        backend.pending.append(('changed', (B.DEVICE_IFACE, {'Alias': 'ALIAS'}, ['Name'], path(1))))
        discovery._step()
        self.assertEqual(discovery.snapshot()['devices'][0]['name'], '')
        self.assertEqual(discovery.snapshot()['counts']['named'], 0)
        backend.pending.append(('removed', (path(1), [B.DEVICE_IFACE])))
        discovery._step()
        self.assertEqual(discovery.snapshot()['counts']['total'], 0)
        self.assertNotIn('SECRETNAME', '\n'.join(self.logs))
        self.assertNotIn('00:11:22', '\n'.join(self.logs))

    def test_pre_start_notifications_not_counted_as_current_session(self):
        discovery = self.service()
        discovery._step()
        backend = self.backends[0]
        backend.pending.append(('added', (path(1), {B.DEVICE_IFACE: device(1, 'OLD')})))
        discovery.start('toolbox', 'new')
        discovery._step()
        self.assertEqual(discovery.snapshot()['counts']['observed'], 0)
        backend.pending.append(('changed', (B.DEVICE_IFACE, {'RSSI': -41}, [], path(1))))
        discovery._step()
        self.assertEqual(discovery.snapshot()['counts']['observed'], 1)
        discovery.start('stock', 'next')
        self.assertEqual(discovery.snapshot()['counts']['observed'], 0)

    def test_poweroff_clears_session_without_setting_power(self):
        discovery = self.service()
        discovery.start('toolbox', 'power')
        discovery._step()
        backend = self.backends[0]
        backend.pending.append(('added', (path(1), {B.DEVICE_IFACE: device(1, 'ONE')})))
        discovery._step()
        backend.pending.append(('changed', (B.ADAPTER_IFACE, {'Powered': False}, [], B.ADAPTER)))
        discovery._step()
        state = discovery.snapshot()
        self.assertEqual(state['status'], 'error')
        self.assertEqual(state['error'], 'PoweredOff')
        self.assertEqual(state['counts']['observed'], 0)
        self.assertFalse(state['powered'])
        self.assertTrue(backend.closed)
        self.assertEqual(backend.calls.count('stop'), 1)

    def test_daemon_restart_never_stops_new_daemon(self):
        discovery = self.service()
        discovery.start('stock', 'restart')
        discovery._step()
        backend = self.backends[0]
        backend.pending.append(('owner', ('org.bluez', ':1.4', ':1.5')))
        discovery._step()
        self.assertEqual(discovery.snapshot()['error'], 'BlueZRestarted')
        self.assertEqual(discovery.snapshot()['counts']['total'], 0)
        self.assertNotIn('stop', backend.calls)
        self.assertTrue(backend.closed)

    def test_poweroff_also_clears_completed_session_observation(self):
        discovery = self.service()
        discovery.start('toolbox', 'done')
        discovery._step()
        backend = self.backends[0]
        backend.pending.append(('added', (path(1), {B.DEVICE_IFACE: device(1, 'ONE')})))
        discovery._step()
        self.clock.value += 21
        discovery._step()
        self.assertEqual(discovery.snapshot()['counts']['observed'], 1)
        backend.pending.append(('changed', (B.ADAPTER_IFACE, {'Powered': False}, [], B.ADAPTER)))
        discovery._step()
        self.assertEqual(discovery.snapshot()['counts']['observed'], 0)
        self.assertEqual(discovery.snapshot()['devices'][0]['source'], 'cache')

    def test_old_release_notifications_dont_mark_new_session_observed(self):
        discovery = self.service()
        discovery.start('stock', 'old')
        discovery._step()
        backend = self.backends[0]
        def on_stop():
            backend.pending.append(('added', (path(1), {B.DEVICE_IFACE: device(1, 'OLD')})))
        backend.stop_hook = on_stop
        discovery.start('toolbox', 'new')
        discovery._step()
        self.assertEqual(discovery.snapshot()['counts']['observed'], 0)
        self.assertEqual(discovery.snapshot()['status'], 'scanning')

    def test_max_visible_full_counts_and_priority(self):
        objects = {B.ADAPTER: {B.ADAPTER_IFACE: {'Powered': True}}}
        for number in range(180):
            objects[path(number)] = {B.DEVICE_IFACE: device(number, 'N' if number % 2 else None)}
        discovery = self.service(objects)
        discovery.start('toolbox', 'many')
        discovery._step()
        backend = self.backends[0]
        backend.pending.append(('changed', (B.DEVICE_IFACE, {'RSSI': -40}, [], path(178))))
        discovery._step()
        state = discovery.snapshot()
        self.assertEqual(len(state['devices']), 100)
        self.assertEqual(state['counts'], dict(total=180, named=90, observed=1))
        self.assertTrue(state['devices'][0]['seen_this_session'])
        self.assertFalse(state['devices'][0]['named'])
        self.assertTrue(state['devices'][1]['named'])

    def test_storage_cap_explicit_and_observed_evicts_cache(self):
        discovery = self.service()
        discovery.start('toolbox', 'bounded')
        discovery._step()
        for number in range(B.MAX_DEVICES + 20):
            discovery._merge_device(path(number), device(number), 'cache')
        self.assertEqual(discovery.snapshot()['counts']['total'], B.MAX_DEVICES)
        self.assertTrue(discovery.snapshot()['storage_limited'])
        discovery._merge_device(path(1600), device(1600, 'NEW'), 'added')
        state = discovery.snapshot()
        self.assertEqual(state['counts']['total'], B.MAX_DEVICES)
        self.assertEqual(state['counts']['observed'], 1)
        self.assertEqual(state['devices'][0]['name'], 'NEW')

    def test_validation(self):
        discovery = self.service()
        for owner, request in [('other', 'a'), ('stock', ''), ('stock', 'a\n'),
                               ('stock', 'a-b'), ('stock', 'x' * 33), ('stock', None)]:
            with self.assertRaises(ValueError):
                discovery.start(owner, request)
            with self.assertRaises(ValueError):
                discovery.stop(owner, request)
        discovery.close()
        with self.assertRaises(RuntimeError):
            discovery.start('stock', 'closed')

    def test_real_worker_owns_bus_and_close_is_bounded(self):
        discovery = self.service(autostart=True)
        main_thread = threading.current_thread().ident
        start = time.monotonic()
        discovery.start('toolbox', 'thread')
        self.assertLess(time.monotonic() - start, .1)
        until = time.monotonic() + 2
        while discovery.snapshot()['status'] != 'scanning' and time.monotonic() < until:
            time.sleep(.01)
        self.assertEqual(discovery.snapshot()['status'], 'scanning')
        self.assertTrue(discovery.close())
        self.assertTrue(self.backends[0].closed)
        self.assertEqual(self.backends[0].calls.count('stop'), 1)
        self.assertNotIn(main_thread, self.backends[0].call_threads)
        self.assertEqual(len(set(self.backends[0].call_threads)), 1)

    def test_python35_parse_and_no_unsafe_radio_methods(self):
        with open(os.path.join(RUNTIME, 'tools_bluetooth.py'), encoding='utf-8') as source:
            text = source.read()
        try:
            ast.parse(text, feature_version=(3, 5))
        except TypeError:
            ast.parse(text)
        tree = ast.parse(text)
        forbidden = {'SetDiscoveryFilter', 'Pair', 'Connect', 'RemoveDevice', 'Set'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, forbidden)


if __name__ == '__main__':
    unittest.main(verbosity=2)
