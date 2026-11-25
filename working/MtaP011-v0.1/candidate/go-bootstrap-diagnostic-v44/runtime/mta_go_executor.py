"""SOURCE r3 graph: frozen r2 mechanics with isolated r3 Store/Native/Bootstrap;
no old source/manifest/result is overwritten and no execution is claimed.

Fixed single-worker GO F entry and stop-only original-until watchdog.

SOURCE sub-slice: real manifest loader, original process accounting/identity,
and native inherited descriptor/notify lifecycle. GO Store/kernel/control/
bootstrap definitions are the next slice, not fabricated READY capabilities.
No module import, constructor or status function performs RF. main invokes the
fixed reviewed graph only; no shell, signal, restore CLI or arbitrary source.
"""
import errno
import hashlib
import math
import os
import re
import select
import stat
import sys
import threading
import time
import types

import mta_go_deployment as sources

_ENTRY_INVENTORY = []


def _fail(code): raise sources.GoSourceError(code) from None
def _number(value): return sources._time(value)
def _metadata(value): return sources._meta(value)
def _descriptor_metadata(value):
    # Original FD identity is not a file-content/timestamp snapshot. Native
    # pipe writes may update mtime/ctime without replacing the open descriptor.
    names = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_rdev')
    row = tuple(getattr(value, n, None) for n in names)
    if any(not sources._uint(v) for v in row): _fail('inherited_metadata_unknown')
    return row


class _LinuxIo(object):
    def validate(self): sources._LinuxIo().validate()
    def fstat(self, fd): return os.fstat(fd)
    def write(self, fd, raw): return os.write(fd, raw)
    def close(self, fd): return os.close(fd)
    def ready(self, fds, seconds): return select.select(fds, (), (), seconds)[0]


class GoEntrySource(object):
    """Original same-F actual Proc producer, never a GO network grant.

    Its CLIENT accounting Store is PURE and never acquire()/opens a journal or
    claims CLIENT ownership. The exact Store/RLock/epoch/profile/bound reader
    must be unchanged before every actual read. Original numeric active until
    belongs to the native GO F and is never extended by a local stage budget.
    """
    def __init__(self, deployment, original_until, until_text, mode, clock, _proc_fs=None):
        if type(deployment) is not sources.LoadedGoDeployment or mode not in ('--go-bootstrap', '--go-watchdog') or \
                sources.canonical_until(until_text) != _number(original_until) or \
                original_until != deployment.loader.original_until or \
                until_text != deployment.loader.original_until_text:
            _fail('invalid_entry')
        deployment.loader.authenticate(deployment)
        self.deployment, self.until, self.until_text, self.mode = deployment, float(original_until), until_text, mode
        self.worker, self.clock = threading.current_thread(), clock
        self.accounting = self.budget = self.reader = self.accounting_ticket = None
        self.observations, self.failure, self.actor, self.boot = [], None, None, None
        self.last, self.cleanup_until = None, None
        self._proc_fs = _proc_fs
    def _context(self):
        self.deployment.loader.authenticate(self.deployment)
        modules = self.deployment.modules
        if threading.current_thread() is not self.worker or \
                not any(item is self for item in _ENTRY_INVENTORY) or \
                self.accounting_ticket is None or self.accounting_ticket['unknown'] or \
                self.accounting_ticket['creator'] is not modules['mta_client_store'].DurableClientInitStore or \
                self.accounting_ticket['returned'] is not self.accounting or \
                type(self.accounting) is not modules['mta_client_store'].DurableClientInitStore or \
                self.accounting._attempted or self.accounting._opened or self.accounting._current_locks is not None or \
                self.accounting._canonical is not None or self.accounting._marker is not None or \
                self.accounting._resource_budget_v23 is not self.budget or self.budget._store is not self.accounting or \
                self.budget._mutex is not self.accounting._mutex or self.budget._epoch is not self.accounting._epoch or \
                type(self.reader) is not modules['mta_client_proc'].ProcReader or \
                self.reader is not self.accounting._proc_reader or \
                self.reader is not self.accounting._proc_reader_original_v24 or \
                self.accounting._clock is not self.clock or \
                self.reader._bound_budget_v24 is not self.budget or self.reader._resource_budget_v24 is not self.budget or \
                not any(r is self.reader for r in self.budget._readers):
            _fail('accounting_source_changed')
        self.budget._context()
        if self.actor is not None and (not self.observations or self.observations[-1].actor is not self.actor or \
                self.observations[-1].boot != self.boot or not any(
                    g.observation is self.observations[-1] and self.reader.owns_generation(g)
                    for g in self.reader._history)):
            _fail('entry_observation_not_original')
    def prepare(self):
        if self.accounting_ticket is not None: _fail('accounting_already_created')
        modules = self.deployment.modules
        creator = modules['mta_client_store'].DurableClientInitStore
        self.accounting_ticket = {'creator': creator, 'returned': None, 'unknown': True}
        # Registry is already strong in _ENTRY_INVENTORY before any constructor.
        reader_creator = modules['mta_client_proc'].ProcReader
        reader = reader_creator(timeout=3, _fs=self._proc_fs, _clock=self.clock)
        self.reader = reader
        core = modules['mta_p2p_client_init']
        value = creator(self.deployment.manifest.run_token,
            core.Identity(self.deployment.manifest.candidate_sha), _clock=self.clock,
            _proc_reader=reader, _session_profile=core.FORMAL_SESSION_PROFILE)
        self.accounting_ticket['returned'] = value
        self.accounting, self.budget = value, value._resource_budget_v23
        self.accounting_ticket['unknown'] = False
        self._context()
        now = _number(self.clock())
        if not 0 < self.until - now <= 300: _fail('original_until_invalid')
        value._io_deadline = min(self.until, now + 10)
        return self
    def observe_self(self):
        self._context()
        now = _number(self.clock())
        end = min(self.until, now + 3)
        self.accounting._io_deadline = end
        result = self.reader.read_self(_absolute_deadline=end)
        self.observations.append(result)  # Actual original before every check.
        modules = self.deployment.modules
        core, proc = modules['mta_p2p_client_init'], modules['mta_client_proc']
        if type(result) is not proc.ProcObservation or type(result.actor) is not core.Actor or \
                result.kind != 'live_actor' or result.same_boot is not True or \
                type(result.passes) is not int or result.passes != 2 or \
                result.resource_pending is not False or result.file_count != result.closed_count or \
                not result.actor.live() or len(result.actor.tasks) != 1 or \
                not self.reader.history_closed() or threading.active_count() != 1:
            _fail('entry_identity_unknown')
        expected = (sources.PYTHON, '-B', self.deployment.manifest.executor, self.mode,
            '--run-token', self.deployment.manifest.run_token,
            '--manifest-sha256', self.deployment.manifest_sha, '--until', self.until_text)
        digest = hashlib.sha256(b''.join(v.encode('ascii') + b'\0' for v in expected)).hexdigest()
        actor = result.actor
        if actor.exe != sources.PYTHON or actor.argv_sha != digest or actor.pid != os.getpid():
            _fail('wrong_f_entry')
        if self.actor is not None and (self.actor.key() != actor.key() or self.boot != result.boot):
            _fail('entry_process_changed')
        self.actor, self.boot = actor, result.boot
        return result
    def closed_facts(self):
        if self.accounting is None or self.reader is None: return ()
        return ((self.accounting_ticket is not None and not self.accounting_ticket['unknown'],
            self.reader.history_closed() and not self.accounting._attempted and not self.accounting._opened),)


def _entry(deployment, until, until_text, mode, clock, proc_fs=None):
    value = GoEntrySource(deployment, until, until_text, mode, clock, proc_fs)
    _ENTRY_INVENTORY.append(value)  # Original owner before prepare constructor/IO.
    value.prepare(); value.observe_self()
    return value


def watchdog(deployment, original_until, until_text, _io=None, _clock=None,
             _environ=None, _proc_fs=None):
    """Native original device/notify descriptors; exactly one R, no RF/restore.

    EOF/error at the F is stop-only; this process never clears pending, acquires
    a new lock, modifies the journal, invokes WPA or signals another process.
    Only the actual parent launch ticket authenticates it as *its* watchdog.
    """
    if type(deployment) is not sources.LoadedGoDeployment: _fail('foreign_deployment')
    deployment.loader.authenticate(deployment)
    io, clock = _io or _LinuxIo(), _clock or time.monotonic
    env = os.environ if _environ is None else _environ
    io.validate()
    # Until was supplied as the original gate-bound watchdog argv; not now+TTL.
    original_until = _number(original_until)
    start = _number(clock())
    if not 0 < original_until - start <= 300: _fail('original_until_invalid')
    source = _entry(deployment, original_until, until_text, '--go-watchdog', clock, _proc_fs)
    descriptors, rows, failure, result = [], [], None, None
    # These are child-owned inherited FDs, not aliases of the parent's registry.
    for key in ('P011_CLIENT_DEVICE_FD', 'P011_CLIENT_NOTIFY_FD'):
        text = env.get(key)
        if type(text) is not str or re.fullmatch('[1-9][0-9]{0,9}', text) is None or int(text) > 0x7fffffff:
            _fail('inherited_descriptor_invalid')
        descriptors.append(int(text))
    if descriptors[0] == descriptors[1]: _fail('inherited_descriptor_alias')
    try:
        for role, number in zip(('original_device', 'original_notify'), descriptors):
            row = {'role': role, 'fd': number, 'metadata': None, 'close_called': False, 'closed': False}
            rows.append(row)  # Retain original before fstat, even unknown return.
            row['metadata'] = _descriptor_metadata(io.fstat(number))
        device, notify = (r['metadata'] for r in rows)
        if not stat.S_ISREG(device[2]) or device[3:6] != (0, 0, 1) or stat.S_IMODE(device[2]) != 0o600 or \
                not stat.S_ISFIFO(notify[2]) or notify[3:5] != (0, 0):
            _fail('inherited_source_invalid')
        last = start
        while True:
            now = _number(clock())
            if now < last: _fail('clock_regressed')
            last = now
            if now >= original_until: break
            answer = io.ready((), min(.05, original_until - now))
            if type(answer) not in (list, tuple) or answer: _fail('watchdog_wait_invalid')
        # Stop-only output is allowed at original expiry; never renew active RF.
        if any(_descriptor_metadata(io.fstat(r['fd'])) != r['metadata'] for r in rows) or \
                not source.reader.history_closed(): _fail('inherited_source_changed')
        result = io.write(rows[1]['fd'], b'R')
        if type(result) is not int or result != 1: _fail('notify_short_write')
        return 0
    except BaseException as error:
        failure = error; raise
    finally:
        # Close original known descriptors ONCE even after expiry/read failure.
        # Never fstat or close a historical numeric FD after it was closed.
        for row in reversed(rows):
            if row['metadata'] is None: continue
            row['close_called'] = True
            try:
                if _descriptor_metadata(io.fstat(row['fd'])) != row['metadata']: continue
                returned = io.close(row['fd'])
                try: io.fstat(row['fd'])
                except OSError as error:
                    row['closed'] = returned is None and type(error.errno) is int and error.errno == errno.EBADF
            except BaseException: pass  # Physical failure remains below, not success.
        _ENTRY_INVENTORY.append({'entry': source, 'watchdog_fds': rows,
            'failure': failure, 'notify_return': result})
        if not all(r['closed'] for r in rows): _fail('inherited_close_unknown')


def bootstrap(deployment, original_until, until_text, _clock=None, _proc_fs=None):
    """Exact F source handed to the concrete native GO bootstrap, not bool."""
    clock = _clock or time.monotonic
    source = _entry(deployment, original_until, until_text, '--go-bootstrap', clock, _proc_fs)
    modules = deployment.modules
    creator = modules['mta_go_bootstrap'].GoBootstrap
    ticket = {'creator': creator, 'returned': None, 'unknown': True, 'source': source}
    _ENTRY_INVENTORY.append(ticket)
    value = creator(deployment, source, clock=clock)
    ticket['returned'] = value
    if type(value) is not creator or value.entry is not source or value.deployment is not deployment:
        _fail('bootstrap_creation_unknown')
    ticket['unknown'] = False
    # GoBootstrap.run must perform durable reserve/native create/actors/ctrl,
    # exact channel/caps/GROUP_ADD/event/STATUS, and its one same-owner restore.
    # No missing stage is implemented here as a READY/True substitute.
    return value.run()


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if type(args) not in (list, tuple) or len(args) != 7 or args[0] not in ('--go-bootstrap', '--go-watchdog') or \
            args[1] != '--run-token' or args[3] != '--manifest-sha256' or args[5] != '--until' or \
            not sources._hex(args[2], 32) or not sources._hex(args[4], 64) or \
            type(args[6]) is not str:
        return 2
    try: original_until = sources.canonical_until(args[6])
    except (sources.GoSourceError, ValueError, OverflowError): return 2
    # Script entry retains this SAME module for the fixed loader. Never exec F
    # again into a duplicate class domain. Existing foreign alias is refused.
    running = sys.modules.get(__name__)
    old = sys.modules.get('mta_go_executor')
    if type(running) is not types.ModuleType or running.__dict__ is not globals() or old is not None and old is not running:
        return 2
    sys.modules['mta_go_executor'] = running
    try:
        value = sources.GoDeploymentLoader(args[2], args[4], original_until, args[6]).load()
        if args[0] == '--go-watchdog': return watchdog(value, original_until, args[6])
        result = bootstrap(value, original_until, args[6])
        return result if type(result) is int and result in (0, 1, 2) else 1
    except BaseException:
        # v44 private diagnostic only. No stdout/public trace, RF retry, grant,
        # inventory export or change to the original failure exit/restore path.
        # Standard traceback stays outside the pinned mta/p011 source namespace.
        try:
            import traceback
            raw = traceback.format_exc().encode('utf-8', 'replace')
            raw = raw[:16384].decode('utf-8', 'ignore').encode('utf-8')
            os.write(2, raw)  # Existing parent FD2 is a private captured pipe.
        except BaseException:
            pass  # Diagnostic failure never replaces the original exit1.
        return 1


if __name__ == '__main__':
    sys.exit(main())

