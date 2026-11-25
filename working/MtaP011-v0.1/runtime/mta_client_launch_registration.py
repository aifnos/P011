"""Durable direct-child pre/post-exec sidecar, not RF admission or recovery.

New launch schema only, no changes to core Journal/codec/Store. The exact
DirectChildOwner release uses this instance's real persist callback. Existing
core.start still needs a separately reviewed two-phase launch contract.
"""
import errno
import math

import p011_json as json
import mta_client_files as files
import mta_client_store as store_module
import mta_client_coordination as coordination
import mta_client_process_owner as processes
import mta_p2p_client_init as core

VERSION = 1
KIND = 'direct_child_launch_registration'
MAX_BYTES, MAX_FDS = 32768, 32
NAMES = {'watchdog': 'launch-watchdog.json', 'controller': 'launch-controller.json'}
_CODES = frozenset(('invalid_config', 'invalid_ticket', 'already_attempted', 'not_registered',
    'invalid_phase', 'store_unknown', 'owner_unknown', 'actor_unknown', 'callback_unknown',
    'deadline', 'clock_unknown', 'file_unknown', 'foreign_file', 'write_unknown',
    'publish_unknown', 'close_unknown', 'resource_pending', 'component_error', 'interrupted'))


class LaunchRegistrationError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in _CODES else 'component_error'
        ValueError.__init__(self, self.code)


def _fail(code):
    raise LaunchRegistrationError(code) from None


def _uint(value, maximum=0x7fffffff):
    return type(value) is int and 0 <= value <= maximum


def _finite(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(float(value))


def _actor(value):
    if type(value) is not core.Actor or not value.live() or len(value.tasks) != 1:
        _fail('actor_unknown')
    return {'pid': value.pid, 'start': value.start, 'exe': value.exe,
        'argv_sha': value.argv_sha, 'tasks': [list(row) for row in value.tasks]}


class _Fd(object):
    def __init__(self, io, creator):
        self.io, self.creator, self.fd, self.metadata = io, creator, None, None
        self.opening_unknown, self.attempted, self.closed = True, False, False


class LaunchRegistration(object):
    """Private exact record; object/schema/filename never grants ownership."""
    def __init__(self, issuer, target, child, locks):
        self._issuer, self.target, self.child, self.locks = issuer, target, child, locks
        self.spec = child.spec
        self._borrowed = None
        self.phase, self.intent, self.data, self.metadata = 'registered', None, None, None
        self.candidate_data, self.candidate_metadata = None, None
        self.preexec, self.postexec, self.persist_receipt, self.handle = None, None, None, None
        self.final_observation = None
        self.publication_attempted, self.published_unknown, self.unknown = False, False, False
        self.callback_attempted, self.release_attempted = False, False
        self.resolve_count = 0

    def __repr__(self): return '<CLIENT private durable launch registration>'


class DurableLaunchRegistry(object):
    """Pure ctor; fixed existing Store/run only, same shared outer RLock.

    Explicit methods execute actual bounded local sidecar IO. No child launch,
    process signals, caller-supplied paths, marker clear or recovery API exists.
    Trusted _io seam is borrowed from the exact Store FILES instance.
    """
    def __init__(self, store, owner, timeout=3.0):
        if (type(store) is not store_module.DurableClientInitStore or
                type(owner) is not processes.DirectChildOwner or
                type(timeout) not in (int, float) or not 0.1 <= timeout <= 10 or
                not math.isfinite(float(timeout))): _fail('invalid_config')
        self._store, self._owner, self._mutex, self._epoch = store, owner, store._mutex, store._epoch
        self._io, self._issuer, self._timeout = store._files._io, object(), float(timeout)
        self._records, self._inventory, self._observations = [], [], []
        self._deadline, self._last, self._temp_counter = None, None, 0
        self._ended, self._pending, self._close_attempted = False, False, False
        self._reason = 'not_recorded'

    def _exact(self, record):
        if type(record) is not LaunchRegistration or record._issuer is not self._issuer or \
                not any(item is record for item in self._records): _fail('not_registered')

    def _check(self):
        try: now = self._owner._clock()
        except BaseException: _fail('clock_unknown')
        if not _finite(now) or self._last is not None and now < self._last: _fail('clock_unknown')
        self._last = float(now)
        if self._deadline is not None and now >= self._deadline: _fail('deadline')
        return float(now)

    def _begin(self, starting=False, child=None):
        self._deadline = None
        now = self._check()
        self._deadline = now + self._timeout
        if starting:
            if child is None or not _finite(child.deadline) or now >= child.deadline: _fail('deadline')
            self._deadline = min(self._deadline, child.deadline)

    def _failed(self, record, error):
        self._pending, record.unknown = True, True
        self._reason = error.code if type(error) is LaunchRegistrationError else \
            'component_error' if isinstance(error, Exception) else 'interrupted'
        if isinstance(error, Exception): _fail(self._reason)
        raise error

    def register(self, target, child):
        with self._mutex:
            if self._ended or self._pending: _fail('resource_pending')
            if (type(target) is not core.Ticket or type(child) is not processes.ChildTicket or
                    child.owner is not self._owner or not any(t is child for t in self._owner._tickets) or
                    type(child.spec) is not processes.LaunchSpec or child.started or child.unknown or
                    (target.role, target.exe, target.argv_sha) != (child.spec.role, child.spec.exe, child.spec.argv_sha) or
                    type(self._store._current_locks) is not coordination.LockSet or
                    self._store._marker is None or self._store._binding is None or
                    not self._store._files._anchors or self._store._files._io is not self._io or
                    child.original_device_fd != self._store._current_locks._device.fd): _fail('invalid_ticket')
            if len(self._records) >= 2 or any(r.target.role == target.role or r.child is child for r in self._records):
                _fail('already_attempted')
            record = LaunchRegistration(self._issuer, target, child, self._store._current_locks)
            anchor = self._store._files._anchors[-1]
            record._borrowed = (self._store._files, self._store._coordination, self._store._marker,
                self._store._binding, anchor, anchor[0], anchor[0].fd,
                record.locks._device, record.locks._device.fd)
            self._records.append(record)
            return record  # Registration only, no filesystem or launch action.

    def _guard(self, record):
        self._exact(record)
        if self._ended or self._pending or record.unknown: _fail('resource_pending')
        store, child = self._store, record.child
        self._check()
        borrowed = record._borrowed
        if (store._epoch is not self._epoch or store._mutex is not self._mutex or
                store._current_locks is not record.locks or store._binding is None or store._marker is None or
                type(borrowed) is not tuple or len(borrowed) != 9 or
                store._files is not borrowed[0] or store._files._io is not self._io or
                store._coordination is not borrowed[1] or store._marker is not borrowed[2] or
                store._binding is not borrowed[3] or not store._files._anchors or
                store._files._anchors[-1] is not borrowed[4] or
                store._files._anchors[-1][0] is not borrowed[5] or borrowed[5].fd != borrowed[6] or
                record.locks._device is not borrowed[7] or borrowed[7].fd != borrowed[8] or
                child.original_device_fd != record.locks._device.fd): _fail('store_unknown')
        if child.spec is not record.spec or child.owner is not self._owner: _fail('owner_unknown')
        store._begin_io(self._deadline)
        store._validate(record.locks)
        current = store.current(record.locks)
        self._observations.append(current)
        if (type(current) is not core.Journal or current.stage != record.target.role + '_intent' or
                getattr(current, record.target.role + '_ticket') is None or
                getattr(current, record.target.role + '_ticket').key() != record.target.key() or
                current.baseline.boot != child.boot or record.target.boot != child.boot or
                current.deadline != child.deadline): _fail('store_unknown')
        if record.intent is None: record.intent = current
        elif not core._same_journal(record.intent, current): _fail('store_unknown')
        self._owner._exact(child)
        self._owner._single(child, deadline=self._deadline)
        if (type(child.parent) is not core.Actor or store._marker._owner is None or
                child.parent.key() != store._marker._owner.key() or child.boot != store._marker._boot): _fail('owner_unknown')
        store._files._anchors_valid()
        self._check()

    def _flags(self, *names):
        result = 0
        for name in names: result |= self._io.flag(name)
        return result

    def _open(self, parent, name, flags, mode=0):
        self._check()
        if len(self._inventory) >= MAX_FDS: _fail('resource_pending')
        ticket = _Fd(self._io, self._io.open_at); self._inventory.append(ticket)
        try:
            ticket.fd = ticket.creator(parent, name, flags, mode)
            if not _uint(ticket.fd): _fail('file_unknown')
            other = self._inventory + self._store._coordination._inventory + self._store._files._inventory
            if self._store._marker._ticket is not None: other = other + [self._store._marker._ticket]
            for child in self._owner._tickets: other = other + child.fds
            if any(r is not ticket and r.fd == ticket.fd and r.closed is not True for r in other): _fail('file_unknown')
            ticket.metadata = files._file_metadata(self._io.fstat(ticket.fd))
            ticket.opening_unknown = False
            return ticket
        except OSError as error:
            if ticket.fd is None and _uint(error.errno, 4095) and error.errno > 0:
                ticket.opening_unknown, ticket.closed = False, True
            else: self._pending = True
            raise
        except BaseException: self._pending = True; raise

    def _close(self, ticket):
        if ticket.closed or ticket.attempted: return
        if ticket.opening_unknown or ticket.metadata is None or not _uint(ticket.fd): self._pending = True; return
        ticket.attempted = True
        returned = False
        try:
            if files._file_metadata(self._io.fstat(ticket.fd))[:6] != ticket.metadata[:6]: _fail('file_unknown')
            returned = self._io.close(ticket.fd) is None
        except BaseException: self._pending = True
        try: self._io.fstat(ticket.fd)
        except OSError as error:
            if returned and type(error.errno) is int and error.errno == errno.EBADF: ticket.closed = True; return
        except BaseException: pass
        self._pending = True

    def _read(self, record):
        parent, name = self._store._files._anchors[-1][0].fd, NAMES[record.target.role]
        try: metadata = files._file_metadata(self._io.stat_at(parent, name))
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT:
                if record.data is not None: _fail('foreign_file')
                return None
            raise
        if record.data is None: _fail('foreign_file')
        ticket = self._open(parent, name, self._flags('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'))
        try:
            data = b''
            while len(data) <= MAX_BYTES:
                self._check(); amount = min(4096, MAX_BYTES + 1 - len(data))
                chunk = self._io.read(ticket.fd, amount)
                if type(chunk) is not bytes or len(chunk) > amount: _fail('file_unknown')
                if not chunk: break
                data += chunk
            observed = (metadata, data)
            self._observations.append(observed)
            if (metadata != files._file_metadata(self._io.fstat(ticket.fd)) or
                    metadata != files._file_metadata(self._io.stat_at(parent, name)) or
                    metadata != record.metadata or data != record.data): _fail('foreign_file')
            return observed
        finally: self._close(ticket)

    def _tree(self, record, stage, actor):
        child, spec, target = record.child, record.child.spec, record.target
        return {'version': VERSION, 'kind': KIND, 'stage': stage,
            'identity': list(self._store._identity.key()), 'run': self._store._files._run,
            'role': target.role, 'deadline': child.deadline, 'boot': child.boot,
            'target_ticket': {'token': target.token, 'role': target.role, 'boot': target.boot,
                'exe': target.exe, 'argv_sha': target.argv_sha},
            'target': {'exe': spec.exe, 'argv_sha': spec.argv_sha, 'binary_sha': spec.sha},
            'parent': _actor(child.parent), 'preexec': _actor(record.preexec),
            'postexec': None if stage == 'pre_exec_durable' else _actor(actor)}

    def _publish(self, record, stage, actor):
        self._guard(record)
        self._read(record)
        data = json.dumps(self._tree(record, stage, actor), sort_keys=True).encode('utf-8')
        if not 0 < len(data) <= MAX_BYTES: _fail('write_unknown')
        record.candidate_data = data
        parent, name = self._store._files._anchors[-1][0].fd, NAMES[record.target.role]
        self._temp_counter += 1
        temporary = 'launch-%s.%08x.tmp' % (record.target.role, self._temp_counter)
        ticket = self._open(parent, temporary, self._flags('O_WRONLY', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_CLOEXEC'), 0o600)
        try:
            created = ticket.metadata
            if created[6] != 0: _fail('file_unknown')
            offset = 0
            while offset < len(data):
                self._check(); chunk = data[offset:offset + 4096]
                count = self._io.write(ticket.fd, chunk)
                if type(count) is not int or not 1 <= count <= len(chunk): _fail('write_unknown')
                offset += count
            if self._io.fsync(ticket.fd) is not None: _fail('write_unknown')
            written = files._file_metadata(self._io.fstat(ticket.fd))
            record.candidate_metadata = written
            if written[:6] != created[:6] or written[6] != len(data) or \
                    files._file_metadata(self._io.stat_at(parent, temporary)) != written: _fail('file_unknown')
        finally: self._close(ticket)
        if not ticket.closed or self._pending: _fail('close_unknown')
        self._guard(record); self._read(record)
        if files._file_metadata(self._io.stat_at(parent, temporary)) != written: _fail('file_unknown')
        record.publication_attempted, record.published_unknown = True, True
        if self._io.rename_at(parent, temporary, name) is not None: _fail('publish_unknown')
        # Save actual returned publication before directory fsync/postchecks.
        record.data = data
        record.metadata = files._file_metadata(self._io.stat_at(parent, name))
        if record.metadata[:7] != written[:7]: _fail('publish_unknown')
        if self._io.fsync(parent) is not None: _fail('publish_unknown')
        self._guard(record); self._read(record)
        if self._pending: _fail('close_unknown')
        record.published_unknown, record.phase = False, stage

    def _persist(self, record, child, actor):
        self._exact(record)
        if (child is not record.child or actor is not child.preexec or record.callback_attempted or
                record.phase != 'registered' or self._owner._active is not True or
                child.persist_requested is not True or child.persist_returned or child.release_requested or child.released):
            _fail('callback_unknown')
        record.callback_attempted, record.preexec = True, actor
        self._begin(True, child)
        if (type(actor) is not core.Actor or actor.pid != child.pid or not actor.live() or
                len(actor.tasks) != 1 or child.parent is None or
                (actor.exe, actor.argv_sha) != (child.parent.exe, child.parent.argv_sha)):
            _fail('actor_unknown')
        self._publish(record, 'pre_exec_durable', actor)
        self._check()
        result = processes.PersistReceipt(child, actor)
        record.persist_receipt = result
        return result

    def release(self, record):
        with self._mutex:
            self._exact(record)
            if self._ended or self._pending or record.unknown: _fail('resource_pending')
            if record.release_attempted or record.phase != 'registered': _fail('already_attempted')
            record.release_attempted = True
            try:
                result = self._owner.release(record.child, lambda child, actor: self._persist(record, child, actor))
                if (result is not True or record.persist_receipt is None or
                        record.child.persist_receipt is not record.persist_receipt or
                        record.child.released is not True or record.child.unknown): _fail('callback_unknown')
                record.phase = 'exec_gate_released'
                return record.persist_receipt
            except BaseException as error: self._failed(record, error)

    def resolve(self, record):
        with self._mutex:
            self._exact(record)
            if self._ended or self._pending or record.unknown: _fail('resource_pending')
            if record.phase != 'exec_gate_released' or record.handle is not None: _fail('invalid_phase')
            if record.resolve_count >= 16: _fail('already_attempted')
            record.resolve_count += 1
            try:
                self._begin(); self._guard(record)
                actor = self._owner.resolve(record.child)
                record.postexec = actor  # Actual returned reference before postchecks.
                if actor is None:
                    if record.child.unknown: _fail('actor_unknown')
                    return None  # Still waiting is not completion/absence/reap.
                if (type(actor) is not core.Actor or actor is not record.child.postexec or
                        not actor.live() or len(actor.tasks) != 1 or actor.pid != record.preexec.pid or
                        actor.start != record.preexec.start or record.child.boot != record.target.boot or
                        (actor.exe, actor.argv_sha) != (record.target.exe, record.target.argv_sha)):
                    _fail('actor_unknown')
                self._publish(record, 'post_exec_durable', actor)
                # Disk IO can outlive the first post-exec observation. Keep the
                # exact new reader result, never relabel the persisted Actor.
                observed = self._owner._reader.read_actor(record.child.pid, actor)
                record.final_observation = observed
                self._observations.append(observed)
                if (type(observed) is not processes.ProcObservation or observed.kind != 'live_actor' or
                        observed.boot != record.child.boot or observed.same_boot is not True or
                        type(observed.passes) is not int or observed.passes != 2 or
                        observed.resource_pending is not False or type(observed.actor) is not core.Actor or
                        not observed.actor.live() or len(observed.actor.tasks) != 1 or
                        observed.actor.key() != actor.key() or record.child.unknown or
                        any(t.closed is not True or t.opening_unknown for t in self._inventory)):
                    _fail('actor_unknown')
                self._owner._single(record.child, deadline=self._deadline)
                self._check()
                handle = core.Handle(record.target, actor, record.child)
                record.handle = handle
                return handle
            except BaseException as error: self._failed(record, error)

    def close(self):
        with self._mutex:
            self._ended = True
            if not self._close_attempted:
                self._close_attempted = True
                for ticket in self._inventory:
                    try: self._close(ticket)
                    except BaseException: self._pending = True
            return self.status()  # Only local sidecar FDs, never child/Store/OFD closure.

    def status(self):
        with self._mutex:
            return {'evidence': 'DURABLE_LAUNCH_REGISTRATION_ONLY', 'registration_count': len(self._records),
                'preexec_durable_count': sum(r.persist_receipt is not None for r in self._records),
                'postexec_durable_count': sum(r.handle is not None for r in self._records),
                'fd_count': len(self._inventory), 'fd_closed_count': sum(t.closed for t in self._inventory),
                'resource_pending': self._pending, 'unknown_count': sum(r.unknown for r in self._records),
                'close_attempted': self._close_attempted, 'reason': self._reason,
                'child_exit_verified': False, 'orphan_recovery': False, 'manifest_authenticated': False,
                'provider_ready': False, 'rf_admission': False, 'complete': False}
