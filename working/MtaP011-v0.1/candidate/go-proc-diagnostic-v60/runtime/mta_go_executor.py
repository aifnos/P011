"""SOURCE r3 graph: frozen r2 mechanics with isolated r3 Store/Native/Bootstrap;
no old source/manifest/result is overwritten and no execution is claimed.

Fixed single-worker GO F entry and stop-only original-until watchdog.

SOURCE sub-slice: real manifest loader, original process accounting/identity,
and native inherited descriptor/notify lifecycle. GO Store/kernel/control/
bootstrap definitions are the next slice, not fabricated READY capabilities.
No module import, constructor or status function performs RF. main invokes the
fixed reviewed graph only; no shell, signal, restore CLI or arbitrary source.

v55 formats only retained private snapshot timing data in the existing bounded
failure head. No extra clock, source read, public field or stderr write exists.

v56 separates the original entry predicate body from its standalone source
wrapper. Only the original native-owner path coalesces adjacent authentication;
all original accounting/history predicates and standalone checks remain.

v60 formats a first retained Proc rejection in the original private FD2 head.
Only direct exact typed data is read; no sampling, clock, retry or proof is added.
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
        GoEntrySource._context_after_source_v56(self)
    def _context_after_source_v56(self):
        # Internal fixed-class body, not a caller capability or cached grant.
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


def _snapshot_timing_text_v55(value):
    # Pure private formatting, not permission or a resource/restore proof.
    # The stored original caps remain full precision; displayed numbers use
    # bounded scientific notation. No clock or source method is called here.
    try:
        native = value.native
        creator = value.deployment.modules['mta_go_native'].NativeGoResources
        if type(native) is not creator: return 'SNAP55=unavailable\n'
        rows = native._snapshot_timing_v55
        if type(rows) is not list or not 0 < len(rows) <= 2:
            return 'SNAP55=unavailable\n'
        tags = ('boot', 'actors', 'pins', 'rest')
        text = []
        def number(v):
            return type(v) in (int, float) and 0 <= v < 1e12 and math.isfinite(float(v))
        def show(v):
            return '-' if v is None else '%.6e' % v
        for index, row in enumerate(rows):
            if type(row) is not list or len(row) != 5:
                return 'SNAP55=invalid\n'
            end, until, component, failed, samples = row
            if not number(end) or not number(until) or until != native.until or \
                    type(component) is not str or component not in tags or \
                    failed is not None and (type(failed) is not str or failed != component) or \
                    type(samples) is not list or len(samples) != 5:
                return 'SNAP55=invalid\n'
            known = []
            for sample in samples:
                if sample is not None:
                    if type(sample) is not float or not number(sample) or known and sample < known[-1]:
                        return 'SNAP55=invalid\n'
                    known.append(sample)
            now = samples[4]
            elapsed = []
            for i, tag in enumerate(tags):
                start, stop = samples[i], samples[i + 1]
                partial = stop is None and failed == tag
                if partial: stop = now
                amount = None if start is None or stop is None else stop - start
                if amount is not None and (not math.isfinite(amount) or amount < 0):
                    return 'SNAP55=invalid\n'
                elapsed.append(('~' if partial and amount is not None else '') + show(amount))
            left = None if now is None else end - now
            if left is not None and not math.isfinite(left): return 'SNAP55=invalid\n'
            text.append(('SNAP55#%d end=%s until=%s now=%s left=%s at=%s fail=%s '
                         'boot=%s actors=%s pins=%s rest=%s\n') %
                        ((index + 1, show(end), show(until), show(now), show(left),
                          component, '-' if failed is None else failed) + tuple(elapsed)))
        return ''.join(text)
    except BaseException:
        return 'SNAP55=unavailable\n'


def _proc_failure_text_v60(value, deployment):
    # First rejection data only. No source/read/clock/history method is called.
    unavailable = 'PROC60=unavailable\n'
    try:
        if type(deployment) is not sources.LoadedGoDeployment: return unavailable
        modules = deployment.modules
        if type(modules) is not dict or any(type(modules[n]) is not types.ModuleType for n in
                ('mta_go_bootstrap', 'mta_go_native', 'mta_client_proc', 'mta_client_resource_budget')):
            return unavailable
        if type(value) is not modules['mta_go_bootstrap'].GoBootstrap or value.deployment is not deployment:
            return unavailable
        native, entry, proc = value.native, value.entry, modules['mta_client_proc']
        if type(native) is not modules['mta_go_native'].NativeGoResources or type(entry) is not GoEntrySource or native.entry is not entry:
            return unavailable
        pair = native.last_proc_failure_v60
        if type(pair) is not tuple or len(pair) != 2: return unavailable
        observation, reader = pair
        if type(observation) is not proc.ProcObservation or type(reader) is not proc.ProcReader or reader is not entry.reader:
            return unavailable
        def token(item):
            return type(item) is str and re.fullmatch('[a-z][a-z0-9_]{0,63}', item) is not None
        def bit(item):
            return '1' if item is True else '0' if item is False else '-'
        def error_text(error):
            if error is None: return 'none'
            if type(error) is proc.ProcReadError:
                return 'ProcReadError/' + error.code if token(error.code) else 'invalid'
            budget = modules['mta_client_resource_budget']
            if type(error) is budget.ResourceBudgetError:
                return 'ResourceBudgetError/' + error.code if token(error.code) else 'invalid'
            if any(type(error) is known for known in (OSError, FileNotFoundError, PermissionError, ProcessLookupError,
                    InterruptedError, BlockingIOError, TimeoutError, FileExistsError, IsADirectoryError,
                    NotADirectoryError, BrokenPipeError, ChildProcessError, ConnectionAbortedError,
                    ConnectionRefusedError, ConnectionResetError)):
                return 'OSError/%d' % error.errno if type(error.errno) is int and 1 <= error.errno <= 4095 else 'OSError/invalid'
            return 'other'  # Never str/repr/getattr on an unknown exception.
        if not token(observation.kind) or observation.kind not in ('live_actor', 'opaque', 'absence', 'unknown') or \
                not token(observation.reason) or not token(observation.stage) or \
                type(observation.passes) is not int or not 0 <= observation.passes <= 2:
            return unavailable
        flags = (observation.same_boot, observation.resource_pending, reader._active, reader._history_active, reader._pending)
        if any(type(flag) is not bool for flag in flags): return unavailable
        if observation.boot is None: boot_match = '-'
        elif type(observation.boot) is str and type(entry.boot) is str:
            boot_match = bit(observation.boot == entry.boot)
        else: return unavailable
        history = reader._history
        if type(history) is not list: return unavailable
        latest = 'latest=none'
        if history:
            generation = history[-1]
            if type(generation) is not proc.ProcGeneration or generation.reader is not reader or \
                    generation._issuer is not reader._issuer or type(generation.ordinal) is not int or \
                    generation.ordinal != len(history)-1:
                return unavailable
            gen_flags = (generation.active, generation.ended, generation.unknown, generation.late)
            if any(type(flag) is not bool for flag in gen_flags): return unavailable
            # A cleanup generation may now be last: match=0 is not PRIMARY causation.
            latest = 'latest=%s/%s/%s/%s match=%s latest_error=%s' % (
                tuple(bit(flag) for flag in gen_flags) +
                (bit(generation.observation is observation), error_text(generation.error)))
        text = ('PROC60 role=first_native_proc_reject kind=%s reason=%s stage=%s passes=%d '
                'same_boot=%s entry_boot=%s pending=%s reader=%s/%s/%s %s resource_error=%s\n') % (
                (observation.kind, observation.reason, observation.stage, observation.passes,
                 bit(flags[0]), boot_match, bit(flags[1]), bit(flags[2]), bit(flags[3]), bit(flags[4]),
                 latest, error_text(reader._resource_error_v24)))
        return text if len(text) <= 512 else unavailable  # Strict ASCII byte bound.
    except BaseException:
        return unavailable  # Diagnostic failure never changes the business error.


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
    result = value.run()
    if result != 0:
        # v45 private retained errors only. The phase is the final phase, not
        # an invented primary-error stage; no inventory or success is emitted.
        try:
            import traceback
            phase = value.phase if type(value.phase) is str else 'unavailable'
            head = ('FINAL_PHASE=' + phase + '\n' + _snapshot_timing_text_v55(value) +
                    _proc_failure_text_v60(value, deployment)).encode('utf-8', 'replace')
            head = head[:1024].decode('utf-8', 'ignore').encode('utf-8')
            parts = [head]
            # Keep both original roles within one aggregate 16KiB UTF8 write.
            limit = (16384 - len(head)) // 2
            for label, error in (('PRIMARY', value.failure), ('RESTORE', value.restore_failure)):
                text = 'unavailable\n' if error is None else ''.join(
                    traceback.format_exception(type(error), error, error.__traceback__))
                raw = (label + '\n' + text).encode('utf-8', 'replace')
                parts.append(raw[:limit].decode('utf-8', 'ignore').encode('utf-8'))
            os.write(2, b''.join(parts))  # Original private FD2; no public trace.
        except BaseException:
            pass  # Diagnostic failure never replaces or rethrows the result.
    return result


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
