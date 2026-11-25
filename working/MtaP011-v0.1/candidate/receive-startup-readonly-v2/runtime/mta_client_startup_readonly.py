"""Original Owner startup-only ARM/STA observation, never receive admission.

No private graph is imported into the canonical module namespace.  The fixed
Factory supplies its already verified private modules and live profile.  One
real Store is constructed solely to bind the original ProcReader budgets;
acquire, assemble, leases, publication and RF are deliberately not called.
Actual BaselineCollector and AuthenticatedStatusReader produce the evidence.
Raw snapshots, source observations and every original resource stay private.
"""
import math
import os
import threading
import time
import types

ARM_READ = 0x80000 | 0x8000
MAX_SECONDS = 10.0
_CODES = frozenset(('startup_originals', 'startup_source_changed',
    'startup_deadline', 'startup_already_attempted', 'startup_status',
    'startup_baseline', 'startup_close_unknown', 'startup_read_failed'))


class StartupReadError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'startup_read_failed'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise StartupReadError(code) from None


def _finite(value):
    return type(value) in (int, float) and math.isfinite(float(value)) and 0 <= value < 1e12


class StartupCollection(object):
    """Retained synchronous producer; success/closure does not grant RF use."""
    def __init__(self, scope):
        # Pure construction; collect() retains this partial instance first.
        self.scope = self._scope_original = scope
        self.modules = self._modules_original = scope.private_modules
        self.profile = self._profile_original = scope.profile
        self.clock = self._clock_original = scope.clock
        self.until = self._until_original = scope.original_until
        self.store = self._store_original = None
        self.budget = self._budget_original = None
        self.collector = self._collector_original = None
        self.snapshot = None
        self.reader_rows, self.status_rows = [], []
        self.constructor_rows, self.close_failures = [], []
        self.io_started = self._io_started_original = False
        self.failure, self.close_failure = None, None
        self.attempted = self.ended = self.success = self.close_attempted = False
        self._last = self._deadline = None
        self._native_class = self._io = None
        self._module_rows = tuple(sorted(self.modules.items()))
        self._definitions = self._definitions_now()

    def __repr__(self):
        return '<private original startup collection; no receive permission>'

    def _definitions_now(self):
        m = self.modules
        names = ('mta_client_baseline', 'mta_client_proc', 'mta_client_store',
                 'mta_client_resource_budget', 'mta_client_wpa_status', 'mta_p2p_client_init')
        if type(m) is not dict or any(type(m.get(n)) is not types.ModuleType for n in names):
            _fail('startup_source_changed')
        b, p, s, r, w, c = (m[n] for n in names)
        return (b.BaselineCollector, b.BaselineCollector.collect, b.BaselineCollector.close,
            b.BaselineCollector._open, p.ProcReader, p.ProcReader.history_closed,
            s.DurableClientInitStore, r.ResourceBudget, r.ResourceBudget.bind_reader,
            w.LinuxStatusSource, w.AuthenticatedStatusReader,
            w.AuthenticatedStatusReader.read_status, w.AuthenticatedStatusReader._close,
            w._ReadFiles.close, w._LinuxIo, c.Identity, c.Snapshot,
            p.ProcReader.__init__, s.DurableClientInitStore.__init__,
            b.BaselineCollector.__init__, w.LinuxStatusSource.__init__,
            w.AuthenticatedStatusReader.__init__, w._LinuxIo.__init__)

    def _construct(self, kind, cls, initializer, args, kwargs):
        # These exact verified constructors are pure. Retain partial objects
        # and their original exception even when __init__ does not return.
        row = {'kind': kind, 'class': cls, 'initializer': initializer,
               'value': None, 'started': True, 'ended': False,
               'returned': False, 'failure': None}
        self.constructor_rows.append(row)
        try:
            value = cls.__new__(cls)
            row['value'] = value
            initializer(value, *args, **kwargs)
            row['returned'] = True
            return value
        except BaseException as error:
            row['failure'] = error
            raise
        finally:
            row['ended'] = True

    def _originals(self, active):
        scope = self.scope
        if (scope is not self._scope_original or self.modules is not self._modules_original or
                scope.private_modules is not self.modules or scope.profile is not self.profile or
                self.profile is not self._profile_original or self.clock is not self._clock_original or
                self.clock is not scope.clock or self.clock is not time.monotonic or
                self.until is not self._until_original or self.until is not scope.original_until or
                threading.current_thread() is not scope.worker or os.getpid() != scope.pid or
                tuple(sorted(self.modules.items())) != self._module_rows or
                any(a is not b for a, b in zip(self._definitions_now(), self._definitions))):
            _fail('startup_originals')
        ticket = scope.collector_ticket
        if (type(ticket) is not dict or ticket.get('creator') is not StartupCollection or
                ticket.get('returned') is not self or ticket.get('started') is not True):
            _fail('startup_originals')
        if active:
            scope.check_active()
        elif scope.close_originals_allowed() is not True:
            _fail('startup_originals')

    def _now(self):
        self._originals(True)
        value = self.clock()
        if not _finite(value) or self._last is not None and value < self._last:
            _fail('startup_deadline')
        self._last = float(value)
        if value >= self.until or self._deadline is not None and value >= self._deadline:
            _fail('startup_deadline')
        return float(value)

    def _new_reader(self, timeout):
        self._now()
        proc = self.modules['mta_client_proc']
        row = {'value': None, 'bound': False, 'failure': None}
        self.reader_rows.append(row)
        try:
            value = self._construct('proc', proc.ProcReader, self._definitions[17], (),
                                    {'timeout': timeout, '_clock': self.clock})
            row['value'] = value
            if self.budget.bind_reader(value) is not value:
                _fail('startup_originals')
            row['bound'] = True
            self._now()
            return value
        except BaseException as error:
            row['failure'] = error
            raise

    def _status(self, deadline):
        self._now()
        remaining = deadline - self.clock()
        if not _finite(deadline) or remaining < 0.1:
            _fail('startup_deadline')
        timeout = min(3.0, remaining)
        w = self.modules['mta_client_wpa_status']
        manifest = dict(self.profile['status_manifest'])
        row = {'source': None, 'reader': None, 'value': None, 'failure': None}
        self.status_rows.append(row)
        try:
            proc_reader = self._new_reader(timeout)
            source = self._construct('source', w.LinuxStatusSource, self._definitions[20],
                (manifest,), {'_io': self._io, '_proc_reader': proc_reader, '_clock': self.clock})
            row['source'] = source
            reader = self._construct('status', w.AuthenticatedStatusReader, self._definitions[21],
                (manifest, source), {'timeout': timeout, '_io': self._io, '_clock': self.clock})
            row['reader'] = reader
            value = reader.read_status(deadline)
            row['value'] = value  # retain before any postcheck
            self._now()
            facts = reader.status()
            if (type(value) is not dict or reader._result is not value or
                    value.get('source_authenticated') is not True or value.get('completed') is not True or
                    type(value.get('frequency')) is not int or
                    value['frequency'] not in tuple(range(2412, 2473, 5)) + (2484,) or
                    facts.get('read_success') is not True or facts.get('socket_closed') is not True or
                    facts.get('resource_pending') is not False):
                _fail('startup_status')
            return value['digest'], value['frequency']
        except BaseException as error:
            row['failure'] = error
            raise

    def run(self):
        if self.attempted or self.ended:
            _fail('startup_already_attempted')
        self.attempted = True
        try:
            now = self._now()
            self._deadline = min(float(self.until), now + MAX_SECONDS)
            m = self.modules
            core, stores = m['mta_p2p_client_init'], m['mta_client_store']
            baseline, status = m['mta_client_baseline'], m['mta_client_wpa_status']
            identity = core.Identity(self.scope.source_manifest_sha)
            store = self._construct('store', stores.DurableClientInitStore, self._definitions[18],
                (os.urandom(16).hex(), identity), {'timeout': MAX_SECONDS, '_clock': self.clock})
            self.store = self._store_original = store
            self.budget = self._budget_original = store._resource_budget_v23
            parent = self

            class ReadOnlyArmIo(status._LinuxIo):
                def spawn(self, unused_executable_fd):
                    # The inherited baseline wpa_cli child path is forbidden.
                    _fail('startup_originals')

            class NativeCollector(baseline.BaselineCollector):
                def _open(self, path, flags=None):
                    parent._now()
                    return baseline.BaselineCollector._open(self, path,
                        ARM_READ if flags is None else flags)
                def _status(self, unused_executable):
                    return parent._status(self._deadline)

            self._native_class = NativeCollector
            self._io_class = ReadOnlyArmIo
            self._io = self._construct('io', ReadOnlyArmIo, self._definitions[22], (), {})
            reader = self._new_reader(MAX_SECONDS)
            collector = self._construct('baseline', NativeCollector, self._definitions[19],
                (tuple(self.profile['baseline_manifest']),),
                {'timeout': MAX_SECONDS, '_io': self._io, '_reader': reader, '_clock': self.clock})
            self.collector = self._collector_original = collector
            # The only actual IO entry. No pure-constructor failure before
            # this point may be converted into a resource-leak diagnosis.
            self.io_started = self._io_started_original = True
            self.snapshot = collector.collect(self._deadline)
            self._now()
            if (type(self.snapshot) is not core.Snapshot or collector._snapshot is not self.snapshot or
                    len(collector._rounds) != 2 or collector._rounds[1] is not self.snapshot or
                    len(self.status_rows) != 2):
                _fail('startup_baseline')
            self.success = True
        except BaseException as error:
            self.failure = error
            raise
        finally:
            self.ended = True
            if not self.close_originals():
                self.success = False
                if self.failure is None:
                    _fail('startup_close_unknown')
        return self

    def close_originals(self):
        # No active clock/readback/IO permission is acquired during known close.
        if self.close_attempted:
            return self.resources_closed()
        self.close_attempted = True
        try:
            self._originals(False)
        except BaseException as error:
            self.close_failure = error
            self.close_failures.append(error)
            return False
        actions = []
        for row in self.status_rows:
            source, reader = row['source'], row['reader']
            if reader is not None and hasattr(reader, '_rights'):
                actions.append((self._definitions[12], reader))
            if source is not None:
                actions.extend((self._definitions[13], files) for files in getattr(source, '_files', ()))
        if self.collector is not None and hasattr(self.collector, '_tickets'):
            actions.append((self._definitions[2], self.collector))
        # Independent original attempts: a failed close must not strand the
        # remaining known resources. Never retry a previous physical close.
        for method, value in actions:
            try:
                method(value)
            except BaseException as error:
                self.close_failures.append(error)
                if self.close_failure is None:
                    self.close_failure = error
        return self.resources_closed()

    def _never_entered_io(self):
        if (self.io_started is not False or self._io_started_original is not False or
                self.status_rows or self.snapshot is not None or self.success):
            return False
        d = self._definitions
        expected = {'store': (d[6], d[18]), 'io': (getattr(self, '_io_class', None), d[22]),
                    'proc': (d[4], d[17]), 'baseline': (self._native_class, d[19])}
        for row in self.constructor_rows:
            pair = expected.get(row['kind'])
            if (pair is None or row['class'] is not pair[0] or row['initializer'] is not pair[1] or
                    row['started'] is not True or row['ended'] is not True or
                    row['returned'] is not True and row['failure'] is None or
                    row['returned'] is True and (type(row['value']) is not pair[0] or row['failure'] is not None)):
                return False
        # Failed pure constructors retain their partial originals above, not
        # inferred FD closure. Returned constructors must still have no IO.
        for row in self.constructor_rows:
            if not row['returned']:
                continue
            value, kind = row['value'], row['kind']
            if kind == 'proc' and (value._history or value._fd_refs or value._raw or
                    value._active or value._history_active or value._pending or
                    value._open_attempt is not None or value._current_generation is not None):
                return False
            if kind == 'baseline' and (value._tickets or value._raw or value._observations or
                    value._rounds or value._binaries or value._incoming is not None or
                    value._attempted or value._pending):
                return False
            if kind == 'store':
                budget = value._resource_budget_v23
                if (value._attempted or value._opened or value._unknown or value._marker is not None or
                        value._current_locks is not None or budget._rows or budget._provider is not None or
                        value._coordination._inventory or value._coordination._anchors or
                        value._files._inventory or value._files._anchors or
                        value._proc_reader._history or not value._proc_reader.history_closed()):
                    return False
        return True

    def resources_closed(self):
        """Passive exact original inventories, not Store.status() or RF proof."""
        try:
            self._originals(False)
            if not self.close_attempted or self.close_failure is not None or not self.ended:
                return False
            if self.io_started is False:
                return self._never_entered_io()
            if self.io_started is not True or self._io_started_original is not True:
                return False
            store, budget, collector = self.store, self.budget, self.collector
            if (store is not self._store_original or budget is not self._budget_original or
                    collector is not self._collector_original or
                    type(store) is not self._definitions[6] or
                    type(budget) is not self._definitions[7] or
                    store._resource_budget_v23 is not budget or budget._store is not store or
                    budget._provider is not None or store._attempted or store._opened or store._unknown or
                    store._marker is not None or store._current_locks is not None or
                    type(collector) is not self._native_class or collector._pending or
                    not collector._ended or any(r['unknown'] or not r['closed'] or
                        r.get('fd') is not None and not r['attempted'] for r in collector._tickets)):
                return False
            original_readers = (store._proc_reader,) + tuple(r['value'] for r in self.reader_rows)
            if (len(budget._readers) != len(original_readers) or
                    any(a is not b for a, b in zip(budget._readers, original_readers)) or
                    any(r['bound'] is not True for r in self.reader_rows) or
                    any(type(r) is not self._definitions[4] or r._bound_budget_v24 is not budget or
                        r._resource_budget_v24 is not budget or not self._definitions[5](r)
                        for r in original_readers)):
                return False
            for row in self.status_rows:
                reader, source = row['reader'], row['source']
                if (type(reader) is not self._definitions[10] or type(source) is not self._definitions[9] or
                        reader._source is not source or not reader._ended or reader._pending or
                        reader._socket_unknown or reader._source_unknown or reader._receive_unknown or
                        reader._socket is not None and (not reader._socket_closed or
                            type(reader._socket.fileno()) is not int or reader._socket.fileno() != -1) or
                        source._pending or source._consumer is not reader or
                        not any(source._reader is value for value in original_readers)):
                    return False
                if any(r['unknown'] or not r['closed'] or not r['attempted'] for r in reader._rights):
                    return False
                for files in source._files:
                    if files._pending or any(r['unknown'] or not r['closed'] or
                            r.get('fd') is not None and not r['attempted'] for r in files._tickets):
                        return False
                for call in source._actor_calls:
                    proc = call['reader']
                    if (not any(proc is value for value in original_readers) or
                            call['started'] is not True or call['returned'] is not True or call['unknown'] or
                            not proc.history_closed() or not any(proc.owns_generation(g) and
                                g.observation is call['value'] and g.ended and not g.active and
                                not g.unknown and not g.late for g in proc.operation_history)):
                        return False
            if any(r['active'] or not r['settled'] or r['unknown'] or r['sticky'] or r['late'] for r in budget._rows):
                return False
            return True
        except BaseException:
            return False

    def public_status(self):
        return {'attempted': self.attempted, 'finished': self.ended, 'read_success': self.success,
            'resources_closed': self.resources_closed(), 'status_count': len(self.status_rows),
            'proc_reader_count': len(self.reader_rows), 'receive_admission': False,
            'restoration_verified': False}


def collect(scope):
    if scope.collector_ticket is not None:
        _fail('startup_already_attempted')
    ticket = {'creator': StartupCollection, 'returned': None, 'started': True,
              'ended': False, 'failure': None}
    scope.collector_ticket = ticket
    value = StartupCollection.__new__(StartupCollection)
    ticket['returned'] = value
    try:
        StartupCollection.__init__(value, scope)
        return value.run()
    except BaseException as error:
        ticket['failure'] = error
        raise
    finally:
        ticket['ended'] = True

