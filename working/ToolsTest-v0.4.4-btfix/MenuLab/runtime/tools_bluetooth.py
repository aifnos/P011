# -*- coding: utf-8 -*-
"""Bounded, connection-owned BlueZ discovery; compatible with Python 3.5.

The HTTP thread only reads or changes in-memory intent.  One worker owns every
D-Bus call, GLib dispatch and bus.close.  No adapter setters, discovery filters,
pairing, connections or device removal are exposed.  Device identity is returned
only to the local UI; event callbacks contain anonymous aggregate counts.
"""
import ctypes
import re
import threading
import time
from collections import OrderedDict

ADAPTER = '/org/bluez/hci0'
ADAPTER_IFACE = 'org.bluez.Adapter1'
DEVICE_IFACE = 'org.bluez.Device1'
MAX_DEVICES = 1500
MAX_VISIBLE = 100
SCAN_SECONDS = 20.0


def error_name(exc):
    """Do not stringify D-Bus exceptions: their messages can contain identity."""
    name = type(exc).__name__
    getter = getattr(exc, 'get_dbus_name', None)
    if getter is not None:
        try:
            value = str(getter())
            if re.match(r'^[A-Za-z0-9_.]{1,128}$', value):
                name = value
        except Exception:
            pass
    return name if re.match(r'^[A-Za-z0-9_.]{1,128}$', name) else 'BackendError'


class _DBusBackend:
    """Created, used and closed exclusively by BluetoothDiscovery's worker."""
    def __init__(self, callbacks):
        import dbus
        from dbus.mainloop.glib import DBusGMainLoop, threads_init
        self.bus = None
        self.matches = []
        threads_init()
        self.glib = ctypes.CDLL('libglib-2.0.so.0')
        self.glib.g_main_context_iteration.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.glib.g_main_context_iteration.restype = ctypes.c_int
        try:
            self.bus = dbus.SystemBus(private=True,
                                      mainloop=DBusGMainLoop(set_as_default=False))
            # Subscribe before baseline, then drain queued pre-scan signals.
            self.matches.append(self.bus.add_signal_receiver(
                callbacks['added'], signal_name='InterfacesAdded',
                dbus_interface='org.freedesktop.DBus.ObjectManager',
                bus_name='org.bluez'))
            self.matches.append(self.bus.add_signal_receiver(
                callbacks['removed'], signal_name='InterfacesRemoved',
                dbus_interface='org.freedesktop.DBus.ObjectManager',
                bus_name='org.bluez'))
            self.matches.append(self.bus.add_signal_receiver(
                callbacks['changed'], signal_name='PropertiesChanged',
                dbus_interface='org.freedesktop.DBus.Properties',
                bus_name='org.bluez', path_keyword='path'))
            self.matches.append(self.bus.add_signal_receiver(
                callbacks['owner'], signal_name='NameOwnerChanged',
                dbus_interface='org.freedesktop.DBus',
                bus_name='org.freedesktop.DBus', arg0='org.bluez'))
            self.manager = dbus.Interface(self.bus.get_object(
                'org.bluez', '/', introspect=False),
                'org.freedesktop.DBus.ObjectManager')
            self.adapter = dbus.Interface(self.bus.get_object(
                'org.bluez', ADAPTER, introspect=False), ADAPTER_IFACE)
        except Exception:
            self.close()
            raise

    def baseline(self):
        return self.manager.GetManagedObjects(timeout=2.0)

    def start(self):
        self.adapter.StartDiscovery(timeout=2.0)

    def stop(self):
        self.adapter.StopDiscovery(timeout=2.0)

    def pump(self):
        # Never let a flood of signals prevent checking cancellation/deadlines.
        for unused in range(32):
            if not self.glib.g_main_context_iteration(None, False):
                break

    def close(self):
        for match in self.matches:
            try:
                match.remove()
            except Exception:
                pass
        self.matches = []
        if self.bus is not None:
            try:
                self.bus.close()
            finally:
                self.bus = None


class BluetoothDiscovery:
    def __init__(self, event, _backend_factory=None, _clock=None, _autostart=True):
        self._event = event
        self._factory = _backend_factory or _DBusBackend
        self._clock = _clock or time.monotonic
        self._lock = threading.RLock()
        self._wake = threading.Event()
        self._closing = False
        self._desired = None
        self._requests = OrderedDict()
        self._devices = {}
        self._backend = None
        self._acquired = False
        self._acquired_generation = 0
        self._observing_generation = 0
        self._deadline = 0.0
        self._abort = ''
        self._storage_limited = False
        self._last_event = 0.0
        self._state = dict(available=False, powered=False, discovering=False,
                           status='idle', active=False, owner='', request_id='',
                           generation=0, error='')
        self._thread = threading.Thread(target=self._run,
                                        name='p011-bluetooth-discovery')
        self._thread.daemon = True
        if _autostart:
            self._thread.start()

    @staticmethod
    def _key(owner, request_id):
        if owner not in ('stock', 'toolbox'):
            raise ValueError('InvalidOwner')
        if not isinstance(request_id, str) or not re.match(
                r'^[A-Za-z0-9]{1,32}\Z', request_id):
            raise ValueError('InvalidRequestId')
        return owner, request_id

    def _remember(self, key):
        self._requests[key] = True
        # A bounded replay/cancellation tombstone window, separate from devices.
        while len(self._requests) > 256:
            self._requests.popitem(last=False)

    def start(self, owner, request_id):
        key = self._key(owner, request_id)
        with self._lock:
            if self._closing:
                raise RuntimeError('Closed')
            if (self._state['owner'], self._state['request_id']) == key:
                return self._snapshot_locked()
            if key not in self._requests:
                self._remember(key)
                generation = self._state['generation'] + 1
                self._clear_observed_locked()
                self._state.update(status='starting', active=True, owner=owner,
                                   request_id=request_id, generation=generation,
                                   error='')
                self._deadline = 0.0
                self._desired = (generation, owner, request_id)
                self._wake.set()
            return self._snapshot_locked()

    def stop(self, owner, request_id):
        key = self._key(owner, request_id)
        with self._lock:
            # Cancel a not-yet-arrived start too.  An old stop cannot touch the
            # current generation belonging to a different request/owner.
            self._remember(key)
            if (self._state['owner'], self._state['request_id']) == key:
                if self._state['active']:
                    self._desired = None
                    self._state.update(status='stopped', active=False)
                    self._deadline = 0.0
                    self._wake.set()
            return self._snapshot_locked()

    def snapshot(self):
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self):
        now = self._clock()
        result = dict(self._state)
        devices = []
        for item in self._devices.values():
            current = dict(item)
            seen = current.pop('_seen_at', None)
            current['last_seen_age_ms'] = (max(0, int((now - seen) * 1000))
                                           if seen is not None else None)
            devices.append(current)
        devices.sort(key=lambda item: (not item['seen_this_session'],
                                      not item['named'],
                                      item['last_seen_age_ms'] if
                                      item['last_seen_age_ms'] is not None
                                      else 2147483647,
                                      item['address']))
        result.update(epoch=time.time(), remaining_ms=(
            max(0, int((self._deadline - now) * 1000)) if
            self._state['active'] and self._deadline else 0),
            devices=devices[:MAX_VISIBLE], counts=dict(
                total=len(devices), named=sum(1 for item in devices if item['named']),
                observed=sum(1 for item in devices if item['seen_this_session'])),
            storage_limited=self._storage_limited)
        return result

    def _clear_observed_locked(self):
        for item in self._devices.values():
            item.update(source='cache', seen_this_session=False, _seen_at=None)

    def _log(self, force=False):
        now = self._clock()
        if not force and now - self._last_event < 1.0:
            return
        self._last_event = now
        snapshot = self.snapshot()
        counts = snapshot['counts']
        # Do not log owner request IDs, addresses, names or exception messages.
        message = ('bluetooth:status={}:generation={}:total={}:named={}:observed={}'
                   ':limited={}:error={}').format(snapshot['status'],
                       snapshot['generation'], counts['total'], counts['named'],
                       counts['observed'], int(snapshot['storage_limited']),
                       snapshot['error'])
        try:
            self._event(message)
        except Exception:
            pass

    def _merge_device(self, path, properties, source, invalidated=()):
        path = str(path)
        if not path.startswith(ADAPTER + '/dev_') or len(path) > 128:
            return
        with self._lock:
            previous = self._devices.get(path)
            if previous is None and len(self._devices) >= MAX_DEVICES:
                self._storage_limited = True
                # Keep an observed record in preference to an old cached item.
                cached = [key for key, item in self._devices.items()
                          if not item['seen_this_session']]
                if source == 'cache' or not cached:
                    return
                del self._devices[sorted(cached)[0]]
            item = dict(previous or dict(address='', name='', named=False,
                        paired=False, connected=False, class_code=0,
                        source='cache', seen_this_session=False, _seen_at=None))
            values = dict(properties)
            defaults = dict(Name='', Address='', Paired=False,
                            Connected=False, Class=0)
            for key in invalidated:
                if str(key) in defaults:
                    values[str(key)] = defaults[str(key)]
            if 'Address' in values:
                address = str(values['Address']).upper()
                item['address'] = address if re.match(
                    r'^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$', address) else ''
            if not item['address']:
                address = path.rsplit('/dev_', 1)[-1].replace('_', ':').upper()
                if re.match(r'^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$', address):
                    item['address'] = address
            if 'Name' in values:
                item['name'] = re.sub(r'[\x00-\x1f\x7f]', ' ',
                                      str(values['Name']))[:128].strip()
                item['named'] = bool(item['name'])
            for field, prop in (('paired', 'Paired'), ('connected', 'Connected')):
                if prop in values:
                    item[field] = bool(values[prop])
            if 'Class' in values:
                try:
                    item['class_code'] = max(0, min(0xffffff, int(values['Class'])))
                except (ValueError, TypeError, OverflowError):
                    item['class_code'] = 0
            observing = (self._observing_generation != 0 and
                         self._observing_generation == self._state['generation']
                         and self._state['active'])
            if source != 'cache' and observing:
                # Any Device1 change is evidence of an event this session, not
                # necessarily a new radio advertisement or current proximity.
                item.update(source=source, seen_this_session=True,
                            _seen_at=self._clock())
            self._devices[path] = item

    def _adapter_properties(self, values):
        with self._lock:
            self._state['available'] = True
            if 'Powered' in values:
                self._state['powered'] = bool(values['Powered'])
                if not self._state['powered']:
                    self._clear_observed_locked()
                    if self._state['active']:
                        self._abort = 'PoweredOff'
            if 'Discovering' in values:
                self._state['discovering'] = bool(values['Discovering'])

    def _added(self, path, interfaces):
        if str(path) == ADAPTER and ADAPTER_IFACE in interfaces:
            self._adapter_properties(interfaces[ADAPTER_IFACE])
        if DEVICE_IFACE in interfaces:
            self._merge_device(path, interfaces[DEVICE_IFACE], 'added')
        self._log()

    def _removed(self, path, interfaces):
        with self._lock:
            if DEVICE_IFACE in interfaces:
                self._devices.pop(str(path), None)
            if str(path) == ADAPTER and ADAPTER_IFACE in interfaces:
                self._state.update(available=False, powered=False, discovering=False)
                self._clear_observed_locked()
                self._abort = 'AdapterRemoved'
        self._log()

    def _changed(self, interface, values, invalidated, path=None):
        if str(path) == ADAPTER and str(interface) == ADAPTER_IFACE:
            values = dict(values)
            for prop in invalidated:
                if str(prop) in ('Powered', 'Discovering'):
                    values[str(prop)] = False
            self._adapter_properties(values)
        elif str(interface) == DEVICE_IFACE:
            self._merge_device(path, values, 'updated', invalidated)
        self._log()

    def _owner_changed(self, name, old_owner, new_owner):
        if str(name) != 'org.bluez' or str(old_owner) == str(new_owner):
            return
        with self._lock:
            self._devices.clear()
            self._state.update(available=False, powered=False, discovering=False)
            self._abort = 'BlueZRestarted'
        # The old daemon has lost its sessions.  Do not send StopDiscovery to
        # an unrelated replacement daemon; dropping this bus is the fallback.
        self._acquired = False
        self._observing_generation = 0

    def _connect(self):
        callbacks = dict(added=self._added, removed=self._removed,
                         changed=self._changed, owner=self._owner_changed)
        backend = self._factory(callbacks)
        try:
            objects = backend.baseline()
            with self._lock:
                self._devices.clear()
                self._storage_limited = False
                self._state.update(available=False, powered=False, discovering=False)
            for path, interfaces in objects.items():
                if str(path) == ADAPTER and ADAPTER_IFACE in interfaces:
                    self._adapter_properties(interfaces[ADAPTER_IFACE])
                if DEVICE_IFACE in interfaces:
                    self._merge_device(path, interfaces[DEVICE_IFACE], 'cache')
            backend.pump()
            self._backend = backend
        except Exception:
            backend.close()
            raise

    def _finish_error(self, name, generation=None):
        with self._lock:
            if generation is None or generation == self._state['generation']:
                self._desired = None
                self._deadline = 0.0
                self._clear_observed_locked()
                self._state.update(status='error', active=False, error=name)
        self._log(True)

    def _release(self, close=False):
        backend = self._backend
        self._observing_generation = 0
        if self._acquired and backend is not None:
            self._acquired = False
            try:
                backend.stop()
            except Exception:
                # Closing only our private connection drops only our session,
                # including ambiguous StopDiscovery failures.
                close = True
        self._acquired_generation = 0
        if close and backend is not None:
            try:
                backend.close()
            finally:
                self._backend = None

    def _step(self):
        """One worker iteration; also a deterministic lifecycle test seam."""
        if self._backend is None:
            self._connect()
        self._backend.pump()
        if self._abort:
            reason = self._abort
            self._abort = ''
            self._finish_error(reason)
            self._release(close=True)
            return
        with self._lock:
            desired = self._desired
        if self._acquired and (desired is None or
                               desired[0] != self._acquired_generation):
            self._release()
        if desired is not None and not self._acquired:
            # StopDiscovery itself can enqueue final old-session properties.
            # Drain those with observation disabled before the new acquisition.
            if self._backend is None:
                return
            self._backend.pump()
            if self._abort:
                return
            with self._lock:
                if desired != self._desired or self._closing:
                    return
                ready = self._state['available'] and self._state['powered']
            if not ready:
                self._finish_error('AdapterNotPowered', desired[0])
                return
            # All pre-request queued notifications have been drained first.
            self._observing_generation = desired[0]
            try:
                self._backend.start()
                self._acquired = True
                self._acquired_generation = desired[0]
            except Exception as exc:
                self._finish_error(error_name(exc), desired[0])
                # Start timeout is ambiguous; only bus.close safely drops a
                # session possibly acquired after the server received the call.
                self._release(close=True)
                return
            with self._lock:
                current = desired == self._desired and not self._closing
                if current:
                    self._deadline = self._clock() + SCAN_SECONDS
                    self._state.update(status='scanning', active=True, error='')
            if not current:
                self._release()
            self._log(True)
        with self._lock:
            expired = (self._acquired and self._deadline and
                       self._clock() >= self._deadline and
                       self._acquired_generation == self._state['generation'])
            if expired:
                self._desired = None
                self._deadline = 0.0
                self._state.update(status='completed', active=False)
        if expired:
            self._release()
            self._log(True)

    def _run(self):
        try:
            while not self._closing:
                try:
                    self._step()
                except Exception as exc:
                    self._finish_error(error_name(exc))
                    self._release(close=True)
                    self._wake.wait(0.25)
                self._wake.wait(0.05)
                self._wake.clear()
        finally:
            self._release(close=True)

    def close(self):
        with self._lock:
            self._closing = True
            self._desired = None
            self._deadline = 0.0
            if self._state['active']:
                self._state.update(active=False, status='stopped')
        self._wake.set()
        if self._thread.is_alive() and self._thread is not threading.current_thread():
            # Each bus method is bounded at 2 seconds.  The worker, never the
            # HTTP thread, must close the private connection.
            self._thread.join(7.0)
        return not self._thread.is_alive()
