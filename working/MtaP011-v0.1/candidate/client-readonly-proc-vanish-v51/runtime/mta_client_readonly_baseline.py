"""Independent actual ARM read-only baseline owner; no staging/RF admission.

The v51 35-source graph permits only exact original ENOENT for a known-unopened
numeric PID comm ticket; all other collection and private v47 receipts remain.
A real pure DurableClientInitStore
is used ONLY as the original neutral Proc accounting issuer. Its lock, FILES,
marker, Journal, Provider and network lifecycles are never opened. Identity is
fixed source provenance, not LoadedDeployment, Handoff or mutation permission.
Construction performs no target file/socket/process action. Only collect()
may perform fixed stock/status/netlink read-only operations. No HOST/ADB
entry is provided; static-preparer physical admission remains unavailable.
"""
import errno
import math
import os
import re
import sys
import threading
import time

import mta_client_baseline as baseline
import mta_client_coordination as coordination
import mta_client_proc as proc
import mta_client_resource_budget as resources
import mta_client_store as stores
import mta_p2p_client_init as core


SOURCE_MANIFEST_SHA = '8e7882aed5237eb4a2a704bee36bd8a8bdf930c079efae20a90d7dfc26a89b60'
CLI_SHA = 'e5d7e23dd0eef64dcc37fa379eedd4bba5e453a10b0b35a3c1e1efabaa34c849'
BASELINE_MANIFEST = tuple(sorted(core.STOCK_PINS + ((baseline.CLI, CLI_SHA),)))
PENDING = '/tmp/' + coordination.GLOBAL_PENDING
MAX_SECONDS = 30.0
COLLECT_SECONDS = 10.0


class ReadonlyBaselineError(ValueError):
    pass


def _fail(code):
    raise ReadonlyBaselineError(code) from None


class _ReadonlyArmIo(baseline._LinuxIo):
    """Only a fixed platform/flags adapter, not a Provider or monkeypatch.

The sole flags conversion is the original generic _READ_FLAGS to the actual
P011 ARM O_RDONLY|O_NOFOLLOW|O_CLOEXEC. Proc itself already uses actual os
flags. Original actor-image magiclink flags and all other requests are kept.
No wrapper substitutes netlink/socket/child/close return values.
"""
    def __init__(self, owner):
        self.owner = owner

    def validate(self):
        self.owner.same_worker()
        if (sys.platform != 'linux' or sys.byteorder != 'little' or os.geteuid() != 0 or
                os.uname()[4] != 'armv7l' or tuple(sys.version_info[:3]) != (3, 5, 5) or
                getattr(os, 'O_RDONLY', None) != 0 or getattr(os, 'O_NOFOLLOW', None) != 0x8000 or
                getattr(os, 'O_CLOEXEC', None) != 0x80000):
            _fail('platform')

    def open(self, path, flags):
        self.owner.same_worker()
        if type(flags) is not int:
            _fail('readonly_flags')
        actual = (os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if flags == baseline._READ_FLAGS else flags)
        return super(_ReadonlyArmIo, self).open(path, actual)

    def read(self, fd, count):
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).read(fd, count)

    def fstat(self, fd):
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).fstat(fd)

    def stat(self, path):
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).stat(path)

    def close(self, fd):
        # Original known cleanup is not skipped merely because the read cap
        # elapsed. This checks the original actor, and never retries a close.
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).close(fd)

    def listdir(self, path):
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).listdir(path)

    def socket(self, protocol):
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).socket(protocol)

    def readable(self, descriptors, timeout):
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).readable(descriptors, timeout)

    def spawn(self, executable_fd):
        # The original collector executes only the authenticated fixed
        # /usr/sbin/wpa_cli -i wlan0 status, with its original retained exec FD.
        self.owner.same_worker()
        return super(_ReadonlyArmIo, self).spawn(executable_fd)


class ReadonlyBaselineOwner(object):
    """One private same-worker read lifetime with actual native inventories.

run_token is internal provenance only; no run directory is created or read.
original_until is the once-captured readonly task cap, never now+renewed TTL.
No fake Store, direct _bound_budget assignment, external IO seam or caller
manifest is accepted. This class cannot open a State/Parent/F network gate.
"""
    def __init__(self, run_token, original_until, _clock=None):
        if (type(run_token) is not str or re.fullmatch('[0-9a-f]{32}', run_token) is None or
                type(original_until) not in (int, float) or
                not math.isfinite(float(original_until)) or not 0 <= original_until < 1e12 or
                _clock is not None and not callable(_clock)):
            _fail('readonly_config')
        self._clock = time.monotonic if _clock is None else _clock
        self.worker, self.pid = threading.current_thread(), os.getpid()
        self.until = self._original_until = float(original_until)
        self._last = None
        issued = self.now()
        if not 0 < self.until - issued <= MAX_SECONDS:
            _fail('readonly_config')
        self.issued_at, self.token = issued, run_token
        self.identity = core.Identity(SOURCE_MANIFEST_SHA)
        self.reader = proc.ProcReader(timeout=COLLECT_SECONDS, _clock=self.now)
        # This is the ACTUAL fixed Store constructor and its ACTUAL fixed
        # ResourceBudget/bind_reader. No acquire/open/prepare/claim occurs.
        self.store = stores.DurableClientInitStore(run_token, self.identity,
            timeout=COLLECT_SECONDS, _proc_reader=self.reader, _clock=self.now,
            _session_profile=core.TRIAL_SESSION_PROFILE)
        self.budget = self.store._resource_budget_v23
        self.io = _ReadonlyArmIo(self)
        self.attempted, self.ended, self.read_success = False, False, False
        self.pending_before, self.pending_after = None, None
        self.platform_before, self.platform_after = None, None
        self.collector_rows, self.observations = [], []
        self.result, self.error = None, None
        self.resource_pending = False

    def same_worker(self):
        if threading.current_thread() is not self.worker or os.getpid() != self.pid:
            _fail('readonly_worker')

    def now(self):
        self.same_worker()
        if self.until is not self._original_until:
            _fail('readonly_cap_changed')
        value = self._clock()
        if (type(value) not in (int, float) or not math.isfinite(float(value)) or
                not 0 <= value < 1e12 or self._last is not None and value < self._last):
            _fail('readonly_clock')
        value = float(value)
        self._last = value
        if value >= self.until:
            _fail('readonly_expired')
        return value

    def _neutral(self):
        self.same_worker()
        store, reader, budget = self.store, self.reader, self.budget
        if (type(store) is not stores.DurableClientInitStore or type(reader) is not proc.ProcReader or
                type(budget) is not resources.ResourceBudget or budget._store is not store or
                budget._profile is not resources.SOURCE_PROFILE or budget._provider is not None or
                budget._mutex is not store._mutex or budget._epoch is not store._epoch or
                store._identity is not self.identity or store._run_token != self.token or
                store._resource_budget_v23 is not budget or store._proc_reader is not reader or
                store._proc_reader_original_v24 is not reader or reader._bound_budget_v24 is not budget or
                reader._resource_budget_v24 is not budget or len(budget._readers) != 1 or
                budget._readers[0] is not reader or
                store._session_profile is not core.TRIAL_SESSION_PROFILE or
                store._session_profile_original_v28 is not core.TRIAL_SESSION_PROFILE or
                store._resource_lane_v23 != resources.PREPARATION_NETWORK or
                store._attempted or store._opened or store._unknown or store._current_locks is not None or
                store._canonical is not None or store._marker is not None or store._binding is not None or
                store._records or store._locksets or store._session_issued_v28 is not None or
                store._coordination._attempted or store._coordination._locks is not None or
                store._coordination._inventory or store._coordination._locksets or
                store._files._opened or store._files._inventory or store._files._publication_attempted or
                store._files._owned_marker_binding is not None):
            _fail('readonly_owner')
        budget._context()  # Pure actual original issuer check; never FILES/Proc IO.

    def _platform(self):
        self.now()
        self.io.validate()
        value = (tuple(os.uname()), tuple(sys.version_info[:3]), os.geteuid(), os.getpid())
        self.now()
        return value

    def _pending_absent(self):
        self.now()
        try:
            self.io.stat(PENDING)
        except OSError as error:
            self.now()
            if type(error.errno) is int and error.errno == errno.ENOENT:
                return True
            raise
        _fail('pending_exists')

    def _closed(self):
        self.same_worker()
        self._neutral()
        if self.reader.history_closed() is not True:
            return False
        for row in self.collector_rows:
            collector = row['collector']
            if (row['unknown'] or type(collector) is not baseline.BaselineCollector or
                    collector._io is not self.io or collector._reader is not self.reader or
                    collector._ended is not True or collector._pending is not False or
                    any(ticket['closed'] is not True or ticket['unknown'] is not False
                        for ticket in collector._tickets)):
                return False
        state = self.budget.status()
        return (state['resource_pending'] is False and state['active_producers'] == 0 and
            state['owner_changed'] is False and state['payload_overrun'] is False)

    def collect(self):
        self.now()
        if self.attempted or self.ended:
            _fail('readonly_already_attempted')
        self.attempted = True
        try:
            self._neutral()
            self.platform_before = self._platform()
            self.pending_before = self._pending_absent()
            row = {'collector': None, 'unknown': True, 'value': None, 'returned': False}
            self.collector_rows.append(row)  # Before the actual constructor.
            collector = baseline.BaselineCollector(BASELINE_MANIFEST, timeout=COLLECT_SECONDS,
                _io=self.io, _reader=self.reader, _clock=self.now)
            row['collector'] = collector
            if type(collector) is not baseline.BaselineCollector:
                _fail('readonly_collector')
            row['unknown'] = False  # Actual pure ctor returned; read failure is separate.
            value = collector.collect(self.until)
            row['value'], row['returned'] = value, True  # Original before postchecks.
            self.observations.append(value)
            if (type(value) is not core.Snapshot or collector._snapshot is not value or
                    collector._success is not True or collector._reason != 'read_closed' or
                    len(collector._rounds) != 2 or collector._rounds[-1] is not value or
                    collector._rounds[0].key() != value.key()):
                _fail('readonly_snapshot')
            self.pending_after = self._pending_absent()
            self.platform_after = self._platform()
            if self.platform_before != self.platform_after or not self._closed():
                _fail('readonly_unclosed')
            self.now()
            self.result = value  # Retain original before final closure/late checks.
        except BaseException as error:
            self.error = error
            raise
        finally:
            # Original collector collect() has already run its actual finally
            # close on errors; no historical numeric FD is retried here.
            self.ended = True
            try:
                self.resource_pending = not self._closed()
            except BaseException:
                self.resource_pending = True
        try:
            if self.resource_pending:
                _fail('readonly_unclosed')
            self.now()
        except BaseException as error:
            self.error = error
            raise
        self.read_success = True
        return self.result  # Private data only; no network or restore permission.

    def status(self):
        # Projection only. No syscall, retry, fresh proof, full Store.close(),
        # mkdir, prepare, StageOwner or RF action occurs in this method.
        return {'evidence': 'CLIENT_READONLY_PROC_VANISH_V51_ONLY',
            'attempted': self.attempted, 'ended': self.ended, 'read_success': self.read_success,
            'resource_pending': self.resource_pending,
            'neutral_store_opened': bool(self.store._attempted or self.store._opened or
                self.store._coordination._attempted or self.store._files._opened),
            'source_manifest_sha256': SOURCE_MANIFEST_SHA,
            'pending_absence_before': self.pending_before is True,
            'pending_absence_after': self.pending_after is True,
            'full_native_rounds': sum(len(row['collector']._rounds) for row in self.collector_rows
                if type(row['collector']) is baseline.BaselineCollector),
            'staging_attempted': False, 'rf_requested': False, 'restoration_verified': False,
            'source_factory_ready': False, 'send_available': False, 'receive_available': False,
            'phone_tested': False}


