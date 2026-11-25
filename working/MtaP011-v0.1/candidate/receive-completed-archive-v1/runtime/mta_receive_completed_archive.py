"""SOURCE-only preservation of ONE future, original Factory receive run.

No CLI, arbitrary path, model IO, legacy-history enumeration, cleanup, RF or
receipt constructor is provided. Call only from the original fixed Owner after
its State, task worker, all finalizers and HTTP workers have actually closed.
The F's FinishReceipt remains in F. Its bounded completion frame is DATA from
the fixed original Parent, never a transplanted FinishReceipt/Native grant.
The original passive State terminal consumer, Parent inventories and independent
network/radio observations are all mandatory before administrative IO.

Only the original _PublicationAttempt's already-created run inode can move.
Existing device/journal lock files are opened (never created) and flocked by the
same retained OFDs throughout both journal reads, marker absence and directory
CAS. ARM Linux 4.14 renameat2(382, RENAME_NOREPLACE) moves the entire directory;
there is no overwrite, unlink, rmdir, rewrite, permission repair or retry.
Historical runs are never examined or admitted. A completed-run archive is an
administrative preservation outcome, not native restoration or next-session
permission. The original once-claimed Trial is never reset.
"""
import ctypes
import errno
import hashlib
import math
import os
import stat
import sys
import threading
import time
import types

MODULE = 'mta_receive_completed_archive'
OWNER_MODULE = 'startup_readonly_private_owner'
CLIENT_NAME = 'p011-mta-client-rfinit'
ARCHIVE_NAME = 'p011-mta-client-completed'
DEVICE_LOCK = 'p011-mta-p2p-device.lock'
PENDING = 'p011-mta-p2p-device.pending'
JOURNAL = 'journal.json'
JOURNAL_LOCK = 'journal.lock'
MAX_SECONDS = 5.0
MAX_JOURNAL = 131072
MAX_ROWS = 12
REASONS = frozenset(('not_attempted', 'archived', 'not_requested',
    'source_changed', 'owner_changed', 'receive_not_completed', 'factory_unknown',
    'parent_unknown', 'terminal_unknown', 'journal_unknown', 'marker_present',
    'unsafe_path', 'path_changed', 'unsupported_platform', 'lock_busy',
    'lock_unknown', 'destination_exists', 'deadline', 'io_error',
    'rename_failed', 'rename_unknown', 'close_unknown'))
_HEX = frozenset('0123456789abcdef')


class CompletedArchiveError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in REASONS else 'io_error'
        ValueError.__init__(self, self.code)


def _fail(code): raise CompletedArchiveError(code) from None


def _meta(value):
    row = tuple(getattr(value, name, None) for name in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(v) is not int or not 0 <= v < (1 << 64) for v in row): _fail('unsafe_path')
    return row


def _directory(value, private=False, temporary=False):
    row = _meta(value)
    if not stat.S_ISDIR(row[2]) or row[3:5] != (0, 0) or row[5] < 1: _fail('unsafe_path')
    mode = stat.S_IMODE(row[2])
    if private and mode != 0o700: _fail('unsafe_path')
    if not private and mode & 0o022 and not (temporary and mode == 0o1777): _fail('unsafe_path')
    return row[:5]


def _file(value, mode, empty=False):
    row = _meta(value)
    if (not stat.S_ISREG(row[2]) or row[3:5] != (0, 0) or row[5] != 1 or
            stat.S_IMODE(row[2]) != mode or empty and row[6] != 0): _fail('unsafe_path')
    return row


class FixedCompletedReceiveArchive(object):
    """Original Owner close-window consumer and one administrative move."""
    def __init__(self, owner, op):
        # Install the complete local close inventory BEFORE reading caller state.
        self.owner, self.operation = owner, op
        self.worker, self.pid = threading.current_thread(), os.getpid()
        self.rows = self._rows_original = []
        self.observations = self._observations_original = []
        self.failure, self.close_errors = None, []
        self.reason = 'not_attempted'
        self.initialized = self._initialized_original = True
        self.accepted = self.attempted = self.ended = False
        self.close_called = self.close_complete = False
        self.rename_called = self.rename_returned = self.rename_outcome_known = False
        self.rename_result = self.rename_errno = None
        self.root_created = self.root_create_called = self.root_create_returned = False
        self.source_absent = self.same_inode_archived = self.journal_unchanged = False
        self.fsync_source = self.fsync_destination = False
        self.archive_root_parent_fsynced = False
        self.before_raw = self.before_meta = self.before_record = None
        self.after_raw = self.after_meta = self.after_record = None
        self.until = self.original_until = None
        self.libc = self.roots = self.run = self.destination = None
        self.aliases = self.originals = None
        try:
            self._capture()
            self._check_originals()
            self.accepted = True
        except BaseException as error:
            self.failure = error
            self.reason = error.code if type(error) is CompletedArchiveError else 'terminal_unknown'
            # A refused pure constructor retains everything it captured. No IO.

    def __repr__(self): return '<private original completed receive archive>'

    def _module(self, name):
        module = self.owner.loader.modules.get(name)
        if (type(module) is not types.ModuleType or sys.modules.get(name) is not module or
                module.__name__ != name or module.__file__ != self.owner_namespace['ROOT'] + '/runtime/' + name + '.py'):
            _fail('source_changed')
        return module

    def _capture(self):
        module = sys.modules.get(MODULE)
        own = sys.modules.get(OWNER_MODULE)
        if (type(module) is not types.ModuleType or module.__dict__ is not globals() or
                type(own) is not types.ModuleType or own.FixedStateServiceOwner is not type(self.owner) or
                own.FixedStateServiceOwner.__init__.__globals__ is not own.__dict__ or
                type(self.owner.io) is not own._LinuxIo or self.owner.io is not self.owner.original_io):
            _fail('source_changed')
        self.owner_module, self.owner_namespace = own, own.__dict__
        owner, op = self.owner, self.operation
        if (owner.worker is not self.worker or owner.pid != self.pid or owner.clock is not time.monotonic or
                owner.receive_archive is not self or owner._receive_archive_original is not self or
                owner.archive_completed_receives is not True or
                owner.archive_completed_receives is not owner._archive_completed_receives_original or
                owner._receive_archive_module_original is not module or
                owner._receive_archive_type_original is not FixedCompletedReceiveArchive or
                type(owner._receive_archive_ticket) is not dict or
                owner._receive_archive_ticket is not owner._receive_archive_ticket_original or
                owner._receive_archive_ticket['creator'] is not FixedCompletedReceiveArchive or
                owner._receive_archive_ticket['partial'] is not self or
                owner._receive_archive_ticket['constructor_called'] is not True or
                owner._receive_archive_ticket['constructed'] is not False): _fail('owner_changed')
        self.modules = tuple(self._module(name) for name in
            ('mta_service', 'mta_transfer_session', 'mta_client_receive_factory',
             'mta_client_state_bridge', 'mta_client_executor', 'mta_receive_network'))
        service, sessions, factories, bridges, executor, network = self.modules
        self.definitions = (service.State._receive_terminal_closed, service.State._receive_network_terminal_closed,
            service.State._probes_closed, sessions.TransferSession.closed,
            factories.FixedReceiveDeploymentFactory.closed_publication_facts.__func__,
            bridges.StateClientBridge.restoration_verified, executor._reader_closed,
            network.compare_observations, network.NetworkObserver.resources_closed)
        state = owner.state
        if (type(state) is not service.State or state is not owner._state_original or
                type(op) is not service.Operation or state.operation is not op or op.kind != 'receive' or
                owner.close_called is not True or owner.stop_called is not True or
                owner.state_close_called is not True or owner.state_close_return is not True or
                owner._http_closed() is not True or owner._startup_closed() is not True or
                state.closing is not True or
                state._trusted_receive_deployment_factory is not owner.factory): _fail('terminal_unknown')
        session = op.session
        if (type(session) is not sessions.TransferSession or state.session is not session or
                state.worker is not session._worker or session._direction != 'receive' or
                session.closed() is not True or type(session._outcome) is not sessions.Outcome or
                session._outcome.local_commit_verified is not True or
                session._outcome.peer_ack_verified is not True or session._task_failed is not False):
            _fail('receive_not_completed')
        factory, bridge, handoff = owner.factory, op.client_bridge, op.client_handoff
        if (type(factory) is not factories.FixedReceiveDeploymentFactory or
                type(bridge) is not bridges.StateClientBridge or bridge._factory is not factory or
                bridge.operation is not op or bridge.session is not session or bridge.handoff is not handoff or
                bridge.started is not True or bridge.running is not False): _fail('factory_unknown')
        facts = factories.FixedReceiveDeploymentFactory.closed_publication_facts(factory, handoff)
        if type(facts) is not tuple or len(facts) != 9: _fail('factory_unknown')
        attempt = facts[2]
        if (type(attempt) is not factories._PublicationAttempt or attempt.factory is not factory or
                attempt.operation is not op or attempt.state is not state or attempt.session is not session or
                attempt.worker is not session._worker or attempt.handoff is not handoff or
                attempt.bridge is not bridge or attempt.success is not True or attempt.failure is not None or
                attempt.closed_facts is not facts or type(attempt.writer) is not factories._Writer): _fail('factory_unknown')
        writer, deployment, parent = attempt.writer, attempt.value, bridge.parent
        if (type(deployment) is not executor.LoadedDeployment or bridge.deployment is not deployment or
                bridge.factory_ticket['returned'] is not deployment or bridge.factory_ticket['authenticated'] is not True or
                deployment.loader is not attempt.loader or deployment.manifest.run_token != attempt.token or
                type(attempt.token) is not str or len(attempt.token) != 32 or any(c not in _HEX for c in attempt.token) or
                deployment.manifest.candidate_sha != factories.SOURCE_MANIFEST_SHA or
                writer.run_name != 'client-' + attempt.token or writer.attempt is not attempt or
                type(writer.run) is not dict or writer.run['owner'] is not writer or
                writer.run['parent'] is not writer.private_root or writer.run['name'] != writer.run_name or
                writer.run['closed'] is not True or writer.run['unknown'] is not False or
                not any(row is writer.run for row in writer.rows)): _fail('factory_unknown')
        if (type(parent) is not executor.ParentExecutor or type(parent.io) is not executor._LinuxIo or
                parent._proc_fs is not None or parent.clock is not time.monotonic or
                type(parent.process) is not parent.io.process_type or bridge.parent_ticket['returned'] is not parent or
                parent.deployment is not deployment or parent.reaped is not True or parent.absent is not True or
                parent.closed is not True or parent.pending is not False or parent.exit_code != 0 or parent.failures or
                bridge.finish_ticket['started'] is not True or bridge.finish_ticket['complete'] is not True or
                parent.spawn_ticket['returned'] is not parent.process or parent.spawn_ticket['unknown'] is not False or
                parent.process.returncode != 0 or parent.eof != {1: True, 2: True} or
                parent.buffers != {1: b'', 2: b''}): _fail('parent_unknown')
        self.state, self.session, self.factory = state, session, factory
        self.bridge, self.handoff, self.attempt = bridge, handoff, attempt
        self.writer, self.deployment, self.parent = writer, deployment, parent
        self.run_name, self.run_identity = writer.run_name, writer.run['identity']
        self.private_root_identity = writer.private_root['identity']
        self.tmp_identity = writer.tmp['identity']
        self.frame = parent.frames[-1] if type(parent.frames) is list and parent.frames else None
        if (type(self.frame) is not dict or self.frame['reason'] != 'restored' or
                self.frame['done'] is not True or self.frame['resource_pending'] is not False): _fail('parent_unknown')
        # Scalar frame is only a source-bound child assertion. Require original
        # Parent reader/pipe owners and independent State terminal consumer below.
        self.frame_wire = service.json.dumps(parent.frames, sort_keys=True)
        self.parent_observations = tuple(parent.observations)
        proc = deployment.modules['mta_client_proc']
        absent = [row for row in parent.reader_rows if row['returned'] is True and
                  type(row['result']) is proc.ProcObservation and row['result'].kind == 'absence']
        if len(absent) != 1: _fail('parent_unknown')
        self.absence_row, self.absence = absent[0], absent[0]['result']
        if (self.absence not in parent.observations or self.absence.same_boot is not True or
                self.absence.boot != parent.boot or self.absence.passes != 2 or
                self.absence.pid_path_absent is not True or self.absence.remaining_tasks != () or
                self.absence.resource_pending is not False or self.absence.file_count != self.absence.closed_count):
            _fail('parent_unknown')
        for row in parent.reader_rows:
            if (row['returned'] is not True or row['creator'] is not proc.ProcReader or
                    row['budget'] is not parent.proc_budget or not executor._reader_closed(row['reader'], proc)):
                _fail('parent_unknown')
        if (len(parent.pipes) != 3 or any(row['closed'] is not True or row['unknown'] is not False or
                row['attempted'] is not True or row['pipe'].closed is not True for row in parent.pipes) or
                parent.file_owner is None or parent.file_owner.pending or
                any(row['closed'] is not True or row['unknown'] for row in parent.file_owner.rows)):
            _fail('parent_unknown')
        self.scope = owner._startup_scope_original
        self.collection = owner._startup_window_collection_original
        if (self.scope is None or self.scope is not owner._startup_window_scope_original or
                owner.startup_scope is not self.scope or owner.startup_result is not self.collection or
                self.collection is None or self.scope.collector_ticket['returned'] is not self.collection or
                self.collection.success is not True or self.collection.failure is not None or
                self.collection.snapshot is not self.collection.collector._snapshot or
                owner.startup_window_closed is not True): _fail('terminal_unknown')
        self.originals = (owner, owner.loader, owner.factory, state, op, session, session._worker,
            tuple(session._attempts), session._outcome, bridge, handoff, attempt, writer, writer.run,
            writer.private_root, writer.tmp, deployment, attempt.loader, parent, parent.spawn_ticket,
            parent.process, tuple(parent.pipes), tuple(parent.reader_rows), parent.file_owner,
            self.frame, self.absence_row, self.absence, self.scope, self.collection,
            self.collection.snapshot, state.probe_actors, state.radio_restore_probes,
                state.network_caps, state.bluetooth_caps, op.receive_network_observer,
            op.receive_network_before, op.receive_network_after, owner._network_observer_spec_original,
            owner._network_observer_asset_original, owner.assets,
            owner._received_directory_original, owner._user_directory_original, owner.original_until)
        self.codec = deployment.modules['mta_client_journal_codec']
        self.core = deployment.modules['mta_p2p_client_init']
        if (type(self.codec) is not types.ModuleType or self.codec.core is not self.core or
                self.codec.decode_journal.__globals__ is not self.codec.__dict__): _fail('source_changed')
        self.codec_definitions = (self.codec.decode_journal, self.codec.encode_journal, self.core.Journal)
        self.capability_wires = (service.json.dumps(state.network_caps, sort_keys=True),
            service.json.dumps(state.bluetooth_caps, sort_keys=True))
        self.probe_rows = tuple(state.probe_actors)
        self.radio_rows = tuple(state.radio_restore_probes)

    def _check_originals(self):
        owner, op, state = self.owner, self.operation, self.state
        if (threading.current_thread() is not self.worker or os.getpid() != self.pid or
                owner.worker is not self.worker or owner.state is not state or owner._state_original is not state or
                owner.factory is not self.factory or owner.loader is not self.originals[1] or
                owner.original_until is not self.originals[-1] or owner.until is not owner.original_until or
                owner.archive_completed_receives is not True or
                owner.archive_completed_receives is not owner._archive_completed_receives_original or
                owner.receive_archive is not self or owner._receive_archive_original is not self or
                owner.close_called is not True or owner.stop_called is not True or
                state.operation is not op or op.session is not self.session or state.session is not self.session or
                op.client_bridge is not self.bridge or op.client_handoff is not self.handoff or
                self.attempt.value is not self.deployment or self.attempt.writer is not self.writer or
                self.writer.run is not self.originals[13] or self.writer.run['identity'] != self.run_identity or
                self.bridge.parent is not self.parent or self.parent.process is not self.originals[20] or
                self.parent.spawn_ticket is not self.originals[19] or self.parent.spawn_ticket['returned'] is not self.parent.process or
                self.parent.frames[-1] is not self.frame or self.parent.observations != list(self.parent_observations) or
                state.probe_actors is not self.originals[30] or state.radio_restore_probes is not self.originals[31] or
                state.network_caps is not self.originals[32] or state.bluetooth_caps is not self.originals[33] or
                op.receive_network_observer is not self.originals[34] or
                op.receive_network_before is not self.originals[35] or op.receive_network_after is not self.originals[36] or
                owner._network_observer_spec_original is not self.originals[37] or
                owner._network_observer_asset_original is not self.originals[38] or owner.assets is not self.originals[39] or
                owner.received_directory is not self.originals[40] or owner._received_directory_original is not self.originals[40] or
                owner.user_directory is not self.originals[41] or owner._user_directory_original is not self.originals[41] or
                state._original_received_binding is not self.originals[40] or
                state._received_binding_original is not self.originals[40] or
                self.attempt.received_directory is not self.originals[40] or
                self.deployment.receive_directory_binding is not self.originals[40]):
            _fail('owner_changed')
        service, sessions, factories, bridges, executor, network = self.modules
        current = (service.State._receive_terminal_closed, service.State._receive_network_terminal_closed,
            service.State._probes_closed, sessions.TransferSession.closed,
            factories.FixedReceiveDeploymentFactory.closed_publication_facts.__func__,
            bridges.StateClientBridge.restoration_verified, executor._reader_closed,
            network.compare_observations, network.NetworkObserver.resources_closed)
        if any(a is not b for a, b in zip(current, self.definitions)): _fail('source_changed')
        for module in self.modules:
            if self._module(module.__name__) is not module: _fail('source_changed')
        if (sys.modules.get(OWNER_MODULE) is not self.owner_module or
                self.owner_module.__dict__ is not self.owner_namespace or
                sys.modules.get(MODULE).__dict__ is not globals() or
                self.codec.decode_journal is not self.codec_definitions[0] or
                self.codec.encode_journal is not self.codec_definitions[1] or
                self.core.Journal is not self.codec_definitions[2]): _fail('source_changed')
        if (self.session.closed() is not True or self.session._outcome is not self.originals[8] or
                self.session._worker is not self.originals[6] or
                len(self.session._attempts) != len(self.originals[7]) or any(
                    a is not b for a, b in zip(self.session._attempts, self.originals[7])) or
                self.session._worker.is_alive() is not False or any(
                    row['thread'].is_alive() is not False or row['claimed'] is not True or
                    row['resolved'] is not True or row['unknown_start'] is not False for row in self.session._attempts) or
                service.json.dumps(self.parent.frames, sort_keys=True) != self.frame_wire or
                (service.json.dumps(state.network_caps, sort_keys=True),
                 service.json.dumps(state.bluetooth_caps, sort_keys=True)) != self.capability_wires or
                len(state.probe_actors) != len(self.probe_rows) or any(
                    a is not b for a, b in zip(state.probe_actors, self.probe_rows)) or
                len(state.radio_restore_probes) != len(self.radio_rows) or any(
                    a is not b for a, b in zip(state.radio_restore_probes, self.radio_rows)) or
                service.State._receive_terminal_closed(state, op) is not True or
                owner._http_closed() is not True or owner._startup_closed() is not True or
                owner._receive_trial_closed() is not True): _fail('terminal_unknown')

    def _check(self):
        self._check_originals()
        value = time.monotonic()
        if (type(value) is not float or not math.isfinite(value) or self.until is not self.original_until or
                value >= self.until or self.until > self.owner.cleanup_until or
                self.owner.cleanup_until > self.owner.original_until + 60.0): _fail('deadline')
        return value

    def _open(self, parent, name, kind, private=False, temporary=False, mode=0o600, empty=False):
        self._check()
        if len(self.rows) >= MAX_ROWS: _fail('io_error')
        row = {'owner': self, 'parent': parent, 'name': name, 'kind': kind,
            'private': private, 'temporary': temporary, 'mode': mode, 'empty': empty,
            'fd': None, 'identity': None, 'open_called': False, 'open_returned': False,
            'preopen_error': None, 'open_error': None, 'close_called': False, 'close_result': None,
            'ebadf_error': None, 'close_error': None, 'closed': False, 'unknown': True,
            'lock_called': False, 'lock_returned': False, 'lock_result': None, 'lock_errno': None,
            'lock_acquired': False}
        self.rows.append(row)  # Retain before original open, including partial failures.
        try:
            parent_fd = None if parent is None else self._fd(parent)
            before = os.stat('/', follow_symlinks=False) if parent is None else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            identity = _directory(before, private, temporary) if kind == 'directory' else _file(before, mode, empty)
            self._check()
            if parent is not None and self._fd(parent) != parent_fd: _fail('path_changed')
            flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            flags |= os.O_RDONLY | os.O_DIRECTORY if kind == 'directory' else os.O_RDWR if empty else os.O_RDONLY
        except BaseException as error:
            # This row has not called open at all. Retain that actual failure,
            # distinct from an unknown/partially returned FD. It signs only this
            # local no-FD inventory, never a Native/Session restoration proof.
            row['preopen_error'] = error
            row['closed'], row['unknown'] = True, False
            raise
        row['open_called'] = True
        try:
            row['fd'] = os.open('/', flags) if parent is None else os.open(name, flags, dir_fd=parent_fd)
            row['open_returned'] = True
        except OSError as error:
            row['open_error'] = error; row['closed'], row['unknown'] = True, False
            raise
        if type(row['fd']) is not int or row['fd'] < 0: _fail('io_error')
        actual = os.fstat(row['fd'])
        # Capture raw identity before validating permissions/type, so a failed
        # policy check cannot lose an actually returned, known original FD.
        raw_identity = _meta(actual)
        row['identity'] = raw_identity[:5] if kind == 'directory' else raw_identity
        row['unknown'] = False
        after = _directory(actual, private, temporary) if kind == 'directory' else _file(actual, mode, empty)
        row['identity'] = after
        if before is None or identity != after: _fail('path_changed')
        self._fd(row); self._check()
        return row

    def _fd(self, row):
        if (self.rows is not self._rows_original or row['owner'] is not self or
                not any(value is row for value in self.rows) or type(row['fd']) is not int or
                row['closed'] or row['close_called'] or row['unknown']): _fail('path_changed')
        value = os.fstat(row['fd'])
        actual = _directory(value, row['private'], row['temporary']) if row['kind'] == 'directory' else _file(value, row['mode'], row['empty'])
        if actual != row['identity']: _fail('path_changed')
        parent = row['parent']
        value = os.stat('/', follow_symlinks=False) if parent is None else os.stat(row['name'], dir_fd=self._fd(parent), follow_symlinks=False)
        current = _directory(value, row['private'], row['temporary']) if row['kind'] == 'directory' else _file(value, row['mode'], row['empty'])
        if current != actual: _fail('path_changed')
        return row['fd']

    def _aliases_current(self):
        current = tuple((_meta(os.lstat(path)), os.readlink(path)) for path in ('/tmp', '/var/tmp'))
        if current != self.aliases: _fail('path_changed')

    def _roots(self):
        root = self._open(None, '/', 'directory')
        var = self._open(root, 'var', 'directory')
        volatile = self._open(var, 'volatile', 'directory', temporary=True)
        tmp = self._open(volatile, 'tmp', 'directory', temporary=True)
        client = self._open(tmp, CLIENT_NAME, 'directory', private=True)
        run = self._open(client, self.run_name, 'directory', private=True)
        if (client['identity'] != self.private_root_identity or run['identity'] != self.run_identity or
                tmp['identity'] != self.tmp_identity): _fail('path_changed')
        aliases = tuple((_meta(os.lstat(path)), os.readlink(path)) for path in ('/tmp', '/var/tmp'))
        for pair, target in zip(aliases, ('/var/tmp', '/var/volatile/tmp')):
            if (pair[0][2] != stat.S_IFLNK | 0o777 or pair[0][3:5] != (0, 0) or
                    pair[0][5] != 1 or pair[1] != target or pair[0][6] != len(target)): _fail('unsafe_path')
        self.aliases, self.roots, self.run = aliases, (root, var, volatile, tmp, client), run
        self._aliases_current()

    def _lock(self, parent, name):
        row = self._open(parent, name, 'file', empty=True)
        self._check(); row['lock_called'] = True; ctypes.set_errno(0)
        value = self.libc.flock(self._fd(row), 2 | 4)
        number = ctypes.get_errno()
        row['lock_result'], row['lock_errno'], row['lock_returned'] = value, number, True
        if value != 0:
            _fail('lock_busy' if number in (errno.EAGAIN, errno.EWOULDBLOCK) else 'lock_unknown')
        row['lock_acquired'] = True
        self._fd(row); self._check()
        return row

    def _marker_absent(self):
        self._check(); tmp = self._fd(self.roots[3])
        try: value = os.stat(PENDING, dir_fd=tmp, follow_symlinks=False)
        except OSError as error:
            self.observations.append(('pending_absence', error))
            if type(error.errno) is int and error.errno == errno.ENOENT:
                self._fd(self.roots[3]); self._check(); return
            raise
        self.observations.append(('pending_present', value))
        _fail('marker_present')

    def _read_journal(self, row):
        self._check(); fd = self._fd(row)
        if not 1 <= row['identity'][6] <= MAX_JOURNAL: _fail('journal_unknown')
        os.lseek(fd, 0, 0); parts, count = [], 0
        while True:
            self._check(); block = os.read(fd, min(8192, MAX_JOURNAL + 1 - count))
            if type(block) is not bytes: _fail('journal_unknown')
            parts.append(block); count += len(block)
            if count > MAX_JOURNAL: _fail('journal_unknown')
            if not block: break
        raw = b''.join(parts)
        self._fd(row); self._check()
        if len(raw) != row['identity'][6]: _fail('journal_unknown')
        record = self.codec.decode_journal(raw)  # DATA only, never reconstructed authority.
        binding = dict(record.association.binding) if record.association is not None else None
        if (type(record) is not self.core.Journal or record.stage != 'reconciled' or record.ready is not False or
                record.identity.key() != self.deployment.manifest.identity.key() or
                record.association is None or record.association.executor.key() != self.parent.actor.key() or
                binding['run_token'] != self.attempt.token or
                binding['candidate_sha'] != self.deployment.manifest.candidate_sha or
                binding['operation_id'] != self.attempt.operation_id or
                self.codec.encode_journal(record) != raw): _fail('journal_unknown')
        return raw, row['identity'], record

    def _destination(self):
        self._check(); tmp = self.roots[3]; self._fd(tmp); self._aliases_current()
        try: actual = os.stat(ARCHIVE_NAME, dir_fd=tmp['fd'], follow_symlinks=False)
        except OSError as error:
            self.observations.append(('archive_root_absence', error))
            if type(error.errno) is not int or error.errno != errno.ENOENT: raise
            self._check(); self._fd(tmp); self._aliases_current()
            self.root_create_called = True
            os.mkdir(ARCHIVE_NAME, 0o700, dir_fd=tmp['fd'])
            self.root_create_returned = self.root_created = True
            self._fd(tmp); self._aliases_current()
        else: _directory(actual, True)
        destination = self._open(tmp, ARCHIVE_NAME, 'directory', private=True)
        if destination['identity'][0] != self.run_identity[0]: _fail('unsafe_path')
        self.destination = destination
        if self.root_created:
            # The archive-parent entry itself must be durable BEFORE moving the
            # original run. The later two fsyncs cover the rename's two parents.
            os.fsync(self._fd(tmp)); self.archive_root_parent_fsynced = True
            self._fd(destination); self._aliases_current(); self._check()
        try: actual = os.stat(self.run_name, dir_fd=self._fd(destination), follow_symlinks=False)
        except OSError as error:
            self.observations.append(('archive_destination_absence', error))
            if type(error.errno) is not int or error.errno != errno.ENOENT: raise
        else:
            self.observations.append(('archive_destination_present', actual)); _fail('destination_exists')
        self._check()

    def archive(self):
        if self.attempted or self.close_called: _fail('rename_unknown')
        self.attempted = True
        try:
            if not self.accepted:
                if self.failure is not None: raise self.failure
                _fail('terminal_unknown')
            self._check_originals()
            original_end = self.owner.cleanup_until
            now = time.monotonic()
            if (type(original_end) is not float or not math.isfinite(original_end) or
                    original_end > self.owner.original_until + 60.0): _fail('deadline')
            self.until = self.original_until = min(original_end, now + MAX_SECONDS)
            if (sys.platform != 'linux' or os.geteuid() != 0 or sys.byteorder != 'little' or
                    os.uname()[4] != 'armv7l' or not os.uname()[2].startswith('4.14.') or
                    os.O_NOFOLLOW != 0x8000 or os.O_CLOEXEC != 0x80000): _fail('unsupported_platform')
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.libc.flock.argtypes, self.libc.flock.restype = (ctypes.c_int, ctypes.c_int), ctypes.c_int
            self.libc.syscall.argtypes = (ctypes.c_long, ctypes.c_int, ctypes.c_char_p,
                ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
            self.libc.syscall.restype = ctypes.c_long
            self._roots()
            self.device_lock = self._lock(self.roots[3], DEVICE_LOCK)
            self.journal_lock = self._lock(self.run, JOURNAL_LOCK)
            self._marker_absent()
            self.journal_row = self._open(self.run, JOURNAL, 'file')
            self.before_raw, self.before_meta, self.before_record = self._read_journal(self.journal_row)
            self._destination()
            self._marker_absent()
            raw, metadata, record = self._read_journal(self.journal_row)
            self.observations.append(('terminal_journal_cas', raw, metadata, record))
            if raw != self.before_raw or metadata != self.before_meta: _fail('journal_unknown')
            self._check(); self._aliases_current()
            for row in self.rows: self._fd(row)
            if self.device_lock['lock_acquired'] is not True or self.journal_lock['lock_acquired'] is not True:
                _fail('lock_unknown')
            source_parent, destination_parent = self.roots[4], self.destination
            name = self.run_name.encode('ascii')
            self.rename_called = True  # Unknown until the full post-readback, even on exception.
            ctypes.set_errno(0)
            value = self.libc.syscall(382, source_parent['fd'], name, destination_parent['fd'], name, 1)
            self.rename_result, self.rename_errno, self.rename_returned = value, ctypes.get_errno(), True
            if value != 0:
                # Do not assume error == no mutation, and never fall back/retry.
                _fail('rename_failed')
            # Rebind only this original directory row AFTER exact destination
            # identity and source absence. Its fd/identity never change.
            actual = _directory(os.stat(self.run_name, dir_fd=destination_parent['fd'], follow_symlinks=False), True)
            if actual != self.run_identity or _directory(os.fstat(self.run['fd']), True) != self.run_identity:
                _fail('rename_unknown')
            self.same_inode_archived = True
            try: actual = os.stat(self.run_name, dir_fd=source_parent['fd'], follow_symlinks=False)
            except OSError as error:
                self.observations.append(('moved_source_absence', error))
                if type(error.errno) is not int or error.errno != errno.ENOENT: raise
                self.source_absent = True
            else:
                self.observations.append(('moved_source_present', actual)); _fail('rename_unknown')
            self.run['parent'], self.run['name'] = destination_parent, self.run_name
            self._fd(self.run); self._aliases_current(); self._check()
            self.after_raw, self.after_meta, self.after_record = self._read_journal(self.journal_row)
            if self.after_raw != self.before_raw or self.after_meta != self.before_meta: _fail('journal_unknown')
            self.journal_unchanged = True
            self._marker_absent()
            os.fsync(self._fd(source_parent)); self.fsync_source = True; self._check()
            os.fsync(self._fd(destination_parent)); self.fsync_destination = True; self._check()
            self._fd(self.device_lock); self._fd(self.journal_lock); self._fd(self.journal_row)
            self._fd(self.run); self._aliases_current(); self._check()
            self.rename_outcome_known = True
            self.reason = 'archived'
        except BaseException as error:
            if self.failure is None: self.failure = error
            self.reason = error.code if type(error) is CompletedArchiveError else 'io_error'
            raise
        finally:
            self.ended = True
            self.close()  # Never let an expired activity cap skip known originals.
        if not self.resources_closed():
            if self.failure is None:
                self.failure = CompletedArchiveError('close_unknown')
                self.reason = 'close_unknown'
            raise self.failure
        return True

    def close(self):
        # No activity/Owner clock checks here: expiry cannot skip known close.
        # An unrelated HTTP/session thread cannot release this Owner's OFDs.
        if threading.current_thread() is not self.worker or os.getpid() != self.pid:
            return False
        if self.close_called: return self.resources_closed()
        self.close_called = True
        if self.rows is not self._rows_original:
            self.close_complete = False; return False
        for row in reversed(self.rows):
            if row['close_called'] or row['closed']: continue
            fd = row['fd']
            if type(fd) is not int:
                row['unknown'] = True; continue
            row['close_called'] = True
            try:
                value = _meta(os.fstat(fd))
                actual = value[:5] if row['kind'] == 'directory' else value
                if row['identity'] is not None and actual != row['identity']: _fail('path_changed')
                row['close_result'] = os.close(fd)
                try: os.fstat(fd)
                except OSError as error:
                    row['ebadf_error'] = error
                    row['closed'] = row['close_result'] is None and type(error.errno) is int and error.errno == errno.EBADF
                if row['closed'] is not True: row['unknown'] = True
            except BaseException as error:
                row['close_error'], row['unknown'] = error, True
                self.close_errors.append(error)
        self.close_complete = self.resources_closed()
        return self.close_complete

    def resources_closed(self):
        # Only original once-close inventories; no deadline/IO/re-close/restore.
        if (self.initialized is not self._initialized_original or self.initialized is not True or
                self.rows is not self._rows_original or self.close_called is not True): return False
        for row in self.rows:
            if row['owner'] is not self or row['unknown'] or row['closed'] is not True: return False
            if row['fd'] is None:
                if row['open_returned'] is not False or row['close_called'] is not False: return False
                if row['open_called'] is False:
                    if (not isinstance(row['preopen_error'], BaseException) or
                            row['open_error'] is not None): return False
                elif (row['open_called'] is not True or row['preopen_error'] is not None or
                        not isinstance(row['open_error'], OSError)): return False
            elif (row['open_returned'] is not True or row['close_called'] is not True or
                    row['close_result'] is not None or row['close_error'] is not None or
                    not isinstance(row['ebadf_error'], OSError) or row['ebadf_error'].errno != errno.EBADF):
                return False
        return True

    def public_facts(self):
        return dict(requested=True, attempted=self.attempted, terminal_originals_accepted=self.accepted,
            archived=self.rename_outcome_known and self.reason == 'archived' and self.resources_closed(),
            rename_called=self.rename_called, rename_outcome_known=self.rename_outcome_known,
            archive_outcome_unknown=self.rename_called and not self.rename_outcome_known,
            original_inode_archived=self.same_inode_archived, source_absent=self.source_absent,
            journal_unchanged=self.journal_unchanged,
            directories_fsynced=self.fsync_source and self.fsync_destination,
            archive_root_parent_fsynced=self.archive_root_parent_fsynced,
            resources_closed=self.resources_closed(), inventory_count=len(self.rows),
            fd_count=sum(type(row['fd']) is int for row in self.rows),
            closed_fd_count=sum(type(row['fd']) is int and row['closed'] is True for row in self.rows), reason=self.reason,
            archive_root_creation_unknown=self.root_create_called and not self.root_create_returned,
            native_restore_grant=False, receive_admission=False, historical_entries_examined=0)
