"""V82-r2 local preflight + task-bound sender file publication, SOURCE only.

Terminal local inventory/cap failures retain their first original exception;
this diagnosis fix does not change local DATA, closure or admission predicates.

No RF/process startup or admission at import/construction. The actual State
worker first retains PreparedSend and this publication. Only fixed sealed
assets are read; no caller source path, hash, executable, IO or ready flag.
Existing GO root is never created/repaired. Only a new random go-token child
is published with EXCL and read back. Failure/partial directories are retained;
no cleanup of another task, pending journal or system file is implemented.
load_parent() yields files-only LoadedGoDeployment; it cannot authorize Native.

The bundle seal is deliberately unset until ROOT freezes the complete sender
graph. This unexecuted SOURCE must not be presented as State/device admission.

preflight_local()/consume_local_preflight() issue/consume only this worker's
actual fixed file/readback DATA. They do not sample helper/stock/network state.
The readonly observer, its input/output channel and Boot seal are not connected;
publish() refuses that missing producer BEFORE any new run directory/write.
The original publication 20s slice is issued once at local preflight, never
renewed by consume/publish; the original absolute task cap remains unchanged.
"""
import errno
import hashlib
import os
import re
import stat
import struct
import threading
import time

import p011_json as json
import mta_go_deployment as sources

ASSET_ROOT = '/var/volatile/tmp/p011-mta-go-send-v76-assets'
BUNDLE_MANIFEST_SHA = None
MAX_ENTRIES = 4096
_ATTEMPTS = []
_LOADER_ORIGINAL = (sources, sources.GoDeploymentLoader, sources.LoadedGoDeployment)


class GoSendPublicationError(ValueError):
    pass


def _fail(code): raise GoSendPublicationError(code) from None
def _digest(raw): return hashlib.sha256(raw).hexdigest()
def _identity(meta): return meta[:2] + (stat.S_IFMT(meta[2]),) + meta[3:6]
def _hex(value, size): return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def _elf_local(raw):
    # Same pure ARM ELF shape as the actual fixed Loader; never execute bytes.
    if (type(raw) is not bytes or len(raw) < 52 or raw[:7] != b'\x7fELF\x01\x01\x01' or
        struct.unpack_from('<H', raw, 16)[0] not in (2, 3) or
        struct.unpack_from('<H', raw, 18)[0] != 40 or
        struct.unpack_from('<I', raw, 20)[0] != 1 or
        struct.unpack_from('<H', raw, 40)[0] != 52 or
        struct.unpack_from('<I', raw, 36)[0] & 0xff000600 != 0x05000400):
        _fail('publication_local_arm_elf_required')


class _LocalPreflight(object):
    """Immutable local readback references, never admission/RF/restore proof."""
    __slots__ = ('owner', 'issuer', 'binding', 'prepared_refs', 'bundle',
                 'root_fact', 'closed_rows', 'row_facts', 'until')
    def __init__(self, owner, binding, prepared_refs, bundle, root_fact, rows):
        for name, value in (
                ('owner', owner), ('issuer', owner._local_issuer),
                ('binding', binding), ('prepared_refs', prepared_refs),
                ('bundle', bundle), ('root_fact', root_fact),
                ('closed_rows', rows), ('row_facts', tuple(
                    (r['kind'], r['path'], r['fd'], r['metadata'], r['identity'],
                     r['close_called'], r['closed'], r['unknown'], r['close_result'])
                    for r in rows)), ('until', owner.prepare_until)):
            object.__setattr__(self, name, value)
    def __setattr__(self, *unused): raise AttributeError('immutable local readback DATA')
    def __repr__(self): return '<private local source readback; not admission>'


class FixedGoSendPublication(object):
    """Original State worker's file producer, not a network/restore receipt."""
    def __init__(self, state, operation, prepared):
        import mta_service as service
        from mta_send_preparation import PreparedSend
        if (type(state) is not service.State or type(operation) is not service.Operation or
            type(prepared) is not PreparedSend): _fail('publication_parent_types')
        self.state, self.operation, self.prepared = state, operation, prepared
        self.worker, self.clock = threading.current_thread(), time.monotonic
        self.until = prepared.until
        self.epoch, self.task_id = operation.epoch, prepared.task_id
        self.originals = (state, operation, prepared, self.worker, self.clock, self.until, self.epoch, self.task_id)
        self.rows, self.mutations, self.raw = [], [], []
        self.reader = self.loader = self.deployment = None
        self.token = self.root = self.run = self.runtime = self.native = self.ctrl = None
        self.called = self.close_called = self.closed = self.unknown = False
        self.failure = self.prepare_until = self.manifest_sha = None
        self.local_called = self.local_consume_called = False
        self.local_failure = self.local_facts = self._local_original = None
        self.local_close_errors = []
        self.local_consume_rows = []
        self._local_issuer, self.local_pid = object(), None
        self._local_prepared_class = PreparedSend
        self._local_selection_check = PreparedSend._selection_current
        self._local_fd_class = PreparedSend.__init__.__globals__['_Fd']
        self._local_request_validate = PreparedSend.prepare.__globals__['validate_send_request']
        self._local_binding = None
        _ATTEMPTS.append(self)
    def __repr__(self): return '<private fixed sender file publication; not RF permission>'
    def _parent(self):
        op = self.operation
        if (not any(a is self for a in _ATTEMPTS) or self.originals !=
            (self.state, op, self.prepared, self.worker, self.clock, self.until, self.epoch, self.task_id) or
            threading.current_thread() is not self.worker or self.state.operation is not op or
            self.state.session is not op.session or op.session._worker is not self.worker or
            op.epoch != self.state.native_epoch or getattr(op, 'send_publication', None) is not self or
            getattr(op, 'send_prepared', None) is not self.prepared or
            self.prepared.until != op.session._task_deadline or self.until != self.prepared.until or
            self.prepared.task_id != self.task_id or self.prepared.closed or not self.prepared.prepared or
            (sources, sources.GoDeploymentLoader, sources.LoadedGoDeployment) != _LOADER_ORIGINAL):
            _fail('publication_parent_changed')
    def _check(self):
        self._parent()
        now = sources._time(self.clock())
        if self.operation.cancelled.is_set() or now >= self.until or (
                self.prepare_until is not None and now >= self.prepare_until): _fail('publication_stopped')
        return now
    def _row(self, kind, path):
        row = dict(kind=kind, path=path, fd=None, metadata=None, identity=None,
                   unknown=True, close_called=False, closed=False, close_result=None, error=None)
        self.rows.append(row)
        return row
    def _adopt(self, row, fd):
        row['fd'] = fd  # Retain the actual return before fstat/late checks.
        if type(fd) is not int or fd < 0 or any(
            r is not row and r['fd'] == fd and not r['closed'] for r in self.rows): _fail('publication_fd_unknown')
        meta = sources._meta(os.fstat(fd))
        row['metadata'], row['identity'] = meta, _identity(meta)
        if meta[3:5] != (0, 0): _fail('publication_fd_owner')
        row['unknown'] = False
    def _close(self, row):
        # Close known originals even after cancellation/expiry; no new IO grant.
        self._parent()
        if row['closed']: return not row['unknown']
        if row['close_called'] or row['unknown'] or row['identity'] is None: return False
        row['close_called'] = True
        try:
            if _identity(sources._meta(os.fstat(row['fd']))) != row['identity']:
                _fail('publication_close_identity')
            row['close_result'] = os.close(row['fd'])
            try: os.fstat(row['fd'])
            except OSError as error:
                row['closed'] = row['close_result'] is None and type(error.errno) is int and error.errno == errno.EBADF
        except BaseException as error: row['error'] = error
        if not row['closed']: row['unknown'] = True
        return row['closed'] and not row['unknown']
    def _read(self, path, maximum, pin=None, binary=False):
        self._check()
        anchors, aliases = self.reader.anchors(path), self.reader.aliases()
        row = self._row('read', path)
        try:
            self._check()
            try: fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError as error:
                if type(error.errno) is int: row['closed'], row['unknown'] = True, False
                raise
            self._adopt(row, fd)
            before = row['metadata']
            if (not stat.S_ISREG(before[2]) or before[2] & 0o022 or
                not 1 <= before[6] <= maximum or before[5] not in ((1, 2) if path == sources.PYTHON else (1,)) or
                binary and not before[2] & 0o111 or sources._meta(os.stat(path, follow_symlinks=False)) != before):
                _fail('publication_read_identity')
            parts, length = [], 0
            while True:
                self._check(); chunk = os.read(fd, min(65536, maximum + 1 - length))
                self.raw.append(chunk)  # Actual late/malformed returns stay private.
                if type(chunk) is not bytes: _fail('publication_read_result')
                parts.append(chunk); length += len(chunk)
                if length > maximum: _fail('publication_read_limit')
                if not chunk: break
            raw = b''.join(parts)
            if (len(raw) != before[6] or sources._meta(os.fstat(fd)) != before or
                sources._meta(os.stat(path, follow_symlinks=False)) != before or
                self.reader.anchors(path) != anchors or self.reader.aliases() != aliases or
                pin is not None and _digest(raw) != pin): _fail('publication_read_changed')
            self._check()
            return raw
        finally:
            if not self._close(row): self.unknown = True
    def _directory(self, path, parent=None, name=None, create=False):
        self._check()
        if create:
            ticket = dict(parent=parent, name=name, called=True, returned=False)
            self.mutations.append(ticket)
            self._dir_current(parent)
            self._check()
            os.mkdir(name, 0o700, dir_fd=parent['fd']); ticket['returned'] = True
            self._check()
        row = self._row('directory', path)
        try:
            before = sources._meta(os.stat(path, follow_symlinks=False))
            self._check()
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            if type(error.errno) is int: row['closed'], row['unknown'] = True, False
            raise
        self._adopt(row, fd)
        if (not stat.S_ISDIR(row['metadata'][2]) or stat.S_IMODE(row['metadata'][2]) != 0o700 or
            row['identity'] != _identity(before)): _fail('publication_directory_identity')
        self._check()
        return row
    def _dir_current(self, row):
        self._check()
        if (row is None or row not in self.rows or row['unknown'] or row['closed'] or row['close_called'] or
            not stat.S_ISDIR(row['metadata'][2]) or
            _identity(sources._meta(os.fstat(row['fd']))) != row['identity'] or
            _identity(sources._meta(os.stat(row['path'], follow_symlinks=False))) != row['identity']):
            _fail('publication_directory_changed')
        self._check()
    def _pending(self):
        self._check()
        try: os.stat('/var/volatile/tmp/p011-mta-p2p-device.pending', follow_symlinks=False)
        except OSError as error:
            if type(error.errno) is int and error.errno == errno.ENOENT: return
            raise
        _fail('publication_previous_restore_pending')
    def _write(self, parent, name, raw, mode):
        self._dir_current(parent); self._pending()
        if type(raw) is not bytes or not 1 <= len(raw) <= sources.MAX_BINARY or mode not in (0o400, 0o500):
            _fail('publication_write_shape')
        row = self._row('write', parent['path'] + '/' + name)
        try:
            self._check()
            try: fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent['fd'])
            except OSError as error:
                if type(error.errno) is int: row['closed'], row['unknown'] = True, False
                raise
            self._adopt(row, fd)
            if not stat.S_ISREG(row['metadata'][2]) or row['metadata'][5] != 1 or stat.S_IMODE(row['metadata'][2]) != 0o600:
                _fail('publication_write_identity')
            offset = 0
            while offset < len(raw):
                self._dir_current(parent)
                count = os.write(fd, raw[offset:offset + 65536]); self._check()
                if type(count) is not int or not 1 <= count <= min(65536, len(raw) - offset): _fail('publication_write_result')
                offset += count
                if _identity(sources._meta(os.fstat(fd))) != row['identity']: _fail('publication_write_changed')
            self._check(); os.fsync(fd); self._check()
            os.lseek(fd, 0, os.SEEK_SET); self._check()
            parts, total = [], 0
            while total <= len(raw):
                self._check(); chunk = os.read(fd, min(65536, len(raw) + 1 - total))
                if type(chunk) is not bytes: _fail('publication_write_readback')
                parts.append(chunk); total += len(chunk)
                if not chunk: break
            if b''.join(parts) != raw: _fail('publication_write_readback')
            self._check(); os.fchmod(fd, mode); self._check()
            os.fsync(fd); self._check()
            meta = sources._meta(os.fstat(fd))
            if (_identity(meta) != row['identity'] or stat.S_IMODE(meta[2]) != mode or meta[6] != len(raw) or
                sources._meta(os.stat(name, dir_fd=parent['fd'], follow_symlinks=False)) != meta):
                _fail('publication_seal_changed')
            row['metadata'] = meta
        finally:
            if not self._close(row): self.unknown = True
    def _local_binding_current(self):
        self._parent()
        op, p = self.operation, self.prepared
        if (op.kind != 'go_send' or op.go_worker is not self.worker or
            op.go_until is not op.session._task_deadline or
            p.worker is not self.worker or p.clock is not self.clock or
            p.until != op.go_until or self.until is not p.until or
            type(self.state._service_until_original) is not float or
            self.state._original_service_until is not self.state._service_until_original or
            not 0 < self.until <= self.state._service_until_original or
            op.send_selection is not p.selection or op.go_selection_original is not p.selection or
            p.selection._registry is not self.state.registry):
            _fail('publication_local_parent_changed')
        value = (self, self.state, op, p, self.worker, self.clock, self.until,
                 op.session, op.go_until, self.state._service_until_original,
                 self.epoch, self.task_id, self.local_pid)
        if self._local_binding is not None and (
            any(a is not b for a, b in zip(value[:10], self._local_binding[:10])) or
            value[10:] != self._local_binding[10:] or os.getpid() != self.local_pid):
            _fail('publication_local_binding_changed')
        return value
    def _request_local(self, prepared):
        # Immutable bounded DATA catches in-place edits to the retained dict.
        # Exact primitive fields precede the original pure protocol validator.
        value = prepared.request_payload
        if (type(value) is not dict or set(value) != {'taskId', 'id', 'senderId', 'senderName',
                'fileName', 'mimeType', 'fileCount', 'totalSize'} or any(
                type(value[name]) is not str or not 1 <= len(value[name]) <= maximum
                for name, maximum in (('taskId', 96), ('id', 96), ('senderId', 128),
                    ('senderName', 256), ('fileName', 1024), ('mimeType', 256))) or
            type(value['fileCount']) is not int or type(value['totalSize']) is not int or
            value['taskId'] != self.task_id or value['id'] != self.task_id or
            value['senderId'] != prepared.sender_id or value['fileCount'] != prepared.file_count or
            value['totalSize'] != prepared.total_bytes):
            _fail('publication_local_request_changed')
        self._local_request_validate(value)
        raw = (json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
        if not 1 <= len(raw) <= 8192: _fail('publication_local_request_limit')
        return raw
    def _prepared_local(self):
        self._local_binding_current()
        p = self.prepared
        if (type(p) is not self._local_prepared_class or
            self._local_prepared_class._selection_current is not self._local_selection_check or
            p.prepared is not True or p.called is not True or p.close_called is not False or
            p.closed is not False or p.failure is not None or p.process_unknown is not False or
            p.process_waited is not True or type(p._selection_originals) is not tuple or
            p.cleanup_failure is not None or len(p._selection_originals) != 4 or type(p.fds) is not list or
            len(p.fds) != 3 or any(type(r) is not self._local_fd_class or r.unknown is not False or
                r.failure is not None or r.role not in ('archive', 'stdout', 'stderr') or
                r.role != 'archive' and r.closed is not True for r in p.fds)):
            _fail('publication_local_prepared_changed')
        self._check()
        self._local_selection_check(p, True) # Original borrowed handles, never reopen by path.
        rows = [r for r in p.fds if r.role == 'archive']
        if len(rows) != 1: _fail('publication_local_archive_inventory')
        row, handle = rows[0], p.archive_handle
        if (row.handle is not handle or row.open_called is not True or row.wrapper_called is not True or
            row.unknown is not False or row.close_called is not False or row.closed is not False or
            row.failure is not None or handle is None or handle.closed is not False or
            handle.fileno() != row.fd or type(row.fd) is not int or row.fd < 0):
            _fail('publication_local_archive_changed')
        meta = sources._meta(os.fstat(row.fd))
        if (not stat.S_ISREG(meta[2]) or meta[3:6] != (0, 0, 1) or
            _identity(meta) != row.metadata or meta[6] != p.archive_size or
            type(p.archive_size) is not int or not 1 <= p.archive_size <= 512 * 1024 * 1024):
            _fail('publication_local_archive_identity')
        self._check()
        return (p, p.selection, p._selection_originals, p.fds, row, handle,
                row.fd, meta, p.archive_size, p.file_count, p.total_bytes,
                p.tls_context, p.request_payload, p.until, p.task_id, p.worker, p.clock,
                p.process, p.process_returncode, tuple(p.fds), self._request_local(p))
    def _bundle_local(self):
        manifest_raw = self._read(ASSET_ROOT + '/source-manifest.json', 65536, BUNDLE_MANIFEST_SHA)
        tree = json.loads(manifest_raw.decode('ascii'))
        if (type(tree) is not dict or set(tree) != {'schema', 'sources', 'baseline_manifest'} or
            tree['schema'] != 'p011-go-send-assets-v76'):
            _fail('publication_bundle_manifest')
        rows = tree['sources']
        if (type(rows) is not list or len(rows) != len(sources.MODULES) or any(
            type(r) is not list or len(r) != 3 or r[0] != name or type(r[1]) is not int or
            not 1 <= r[1] <= sources.MAX_SOURCE or not _hex(r[2], 64)
            for name, r in zip(sources.MODULES, rows))):
            _fail('publication_bundle_graph')
        payloads = []
        for name, size, pin in rows:
            raw = self._read(ASSET_ROOT + '/runtime/' + name + '.py', sources.MAX_SOURCE, pin)
            if len(raw) != size: _fail('publication_bundle_size')
            payloads.append((name, size, pin, raw))
        pins = dict((name, pin) for name, size, pin in rows)
        baseline = tree['baseline_manifest']
        if (any(pins.get(name) != pin for name, pin in sources.NEUTRAL_PINS) or
            type(baseline) is not list or len(baseline) != 4 or any(
                type(r) is not list or len(r) != 2 or type(r[0]) is not str or not _hex(r[1], 64)
                for r in baseline) or len(set(r[0] for r in baseline)) != 4):
            _fail('publication_local_manifest_data')
        own = self._read(sources.__file__, sources.MAX_SOURCE, pins['mta_go_deployment'])
        if own != dict((name, raw) for name, size, pin, raw in payloads)['mta_go_deployment']:
            _fail('publication_running_loader_changed')
        wpa = self._read(ASSET_ROOT + '/native/mta-wpa-supplicant',
                         sources.WPA_BYTES, sources.WPA_SHA, True)
        python = self._read(sources.PYTHON, sources.MAX_BINARY, binary=True)
        if len(wpa) != sources.WPA_BYTES: _fail('publication_wpa_size')
        _elf_local(wpa); _elf_local(python)
        # Local source DATA only. The actual Loader still validates stock facts
        # against its exact private definitions after a future authorized publish.
        return (manifest_raw, tuple(payloads), wpa, python)
    def preflight_local(self):
        """One fixed local read lifetime; no helper/baseline/observer permission."""
        self._check()
        if self.local_called or self.called or self.close_called:
            _fail('publication_local_reused_or_closed')
        self.local_called = True
        root = None
        try:
            if not _hex(BUNDLE_MANIFEST_SHA, 64): _fail('publication_unsealed_or_reused')
            if sources.__file__ != ASSET_ROOT + '/runtime/mta_go_deployment.py':
                _fail('publication_fixed_loader_path')
            self.local_pid = os.getpid()
            self._local_binding = self._local_binding_current()
            self.prepare_until = min(self.until, self._check() + 20.0)
            self.reader = sources._SourceRead(sources._LinuxIo(), self._check, self.prepare_until)
            sources._LinuxIo().validate()
            prepared = self._prepared_local()
            self._pending()
            bundle = self._bundle_local()
            anchors, aliases = self.reader.anchors(sources.ROOT + '/unused'), self.reader.aliases()
            root = self._directory(sources.ROOT) # Existing only; no mkdir/O_CREAT.
            entries = os.listdir(root['fd'])
            if (type(entries) is not list or len(entries) >= MAX_ENTRIES or
                any(type(name) is not str for name in entries)):
                _fail('publication_local_root_entries')
            entries = tuple(sorted(entries))
            self._dir_current(root)
            if tuple(sorted(os.listdir(root['fd']))) != entries:
                _fail('publication_local_root_changed')
            self._pending()
            if self._prepared_local() != prepared:
                _fail('publication_local_prepared_changed')
            self._check()
            root_fact = (sources.ROOT, root['metadata'], root['identity'], entries, anchors, aliases)
        except BaseException as error:
            self.local_failure = error
            if self.failure is None: self.failure = error
            raise
        finally:
            # Do not call close(): publication's eventual once-close remains unused.
            # All actual rows are retained, including failed/unknown opens.
            for row in reversed(self.rows):
                try:
                    if not self._close(row): self.unknown = True
                except BaseException as error:
                    self.local_close_errors.append(error); self.unknown = True
        try:
            if self.unknown or not all(r['closed'] and not r['unknown'] for r in self.rows):
                _fail('publication_local_fd_inventory_pending')
            self._check()
            facts = _LocalPreflight(self, self._local_binding, prepared, bundle, root_fact, tuple(self.rows))
            self.local_facts = self._local_original = facts
            return facts
        except BaseException as error:
            if self.local_failure is None: self.local_failure = error
            if self.failure is None: self.failure = error
            raise
    def consume_local_preflight(self):
        """Consume original local DATA once, not an observer/RF admission claim."""
        self._check()
        if self.local_consume_called: _fail('publication_local_already_consumed')
        self.local_consume_called = True
        value = self.local_facts
        if (type(value) is not _LocalPreflight or value is not self._local_original or
            value.owner is not self or value.issuer is not self._local_issuer or
            value.binding is not self._local_binding or value.until is not self.prepare_until or
            self.local_failure is not None or self.unknown or self.close_called or
            len(value.closed_rows) != len(self.rows) or
            any(a is not b for a, b in zip(value.closed_rows, self.rows))):
            _fail('publication_local_facts_changed')
        for row, fact in zip(value.closed_rows, value.row_facts):
            if (row['kind'], row['path'], row['fd'], row['metadata'], row['identity'],
                row['close_called'], row['closed'], row['unknown'], row['close_result']) != fact:
                _fail('publication_local_inventory_changed')
        self._local_binding_current()
        if self._prepared_local() != value.prepared_refs:
            _fail('publication_local_prepared_changed')
        path, metadata, identity, entries, anchors, aliases = value.root_fact
        start = len(self.rows)
        root = None
        try:
            self._pending()
            if (path != sources.ROOT or sources._meta(os.stat(path, follow_symlinks=False)) != metadata or
                self.reader.anchors(path + '/unused') != anchors or self.reader.aliases() != aliases):
                _fail('publication_local_root_changed')
            root = self._directory(path) # Original FD ticket, no hidden listdir(path) open.
            if root['identity'] != identity or tuple(sorted(os.listdir(root['fd']))) != entries:
                _fail('publication_local_root_changed')
            self._dir_current(root)
            self._pending()
            self._check()
        except BaseException as error:
            self.local_failure = error
            if self.failure is None: self.failure = error
            raise
        finally:
            self.local_consume_rows = self.rows[start:]
            for row in reversed(self.local_consume_rows):
                try:
                    if not self._close(row): self.unknown = True
                except BaseException as error:
                    self.local_close_errors.append(error); self.unknown = True
        try:
            if self.unknown or not all(r['closed'] and not r['unknown'] for r in self.local_consume_rows):
                _fail('publication_local_fd_inventory_pending')
            self._check()
            return value
        except BaseException as error:
            if self.local_failure is None: self.local_failure = error
            if self.failure is None: self.failure = error
            raise
    def publish(self):
        self._check()
        if self.called or not _hex(BUNDLE_MANIFEST_SHA, 64): _fail('publication_unsealed_or_reused')
        if sources.__file__ != ASSET_ROOT + '/runtime/mta_go_deployment.py':
            _fail('publication_fixed_loader_path')
        self.consume_local_preflight()
        # A real fixed readonly observer must later bind helper/stock/network
        # DATA and its original process/pipe closure to this same local fact.
        # No placeholder bool/caller callback is accepted as that producer.
        _fail('publication_readonly_observer_unavailable')
        self.called = True
        # Original once-issued prepare_until is not renewed at publication.
        self.reader = sources._SourceRead(sources._LinuxIo(), self._check, self.prepare_until)
        try:
            sources._LinuxIo().validate()
            self._pending()
            manifest_raw = self._read(ASSET_ROOT + '/source-manifest.json', 65536, BUNDLE_MANIFEST_SHA)
            tree = json.loads(manifest_raw.decode('ascii'))
            if type(tree) is not dict or set(tree) != {'schema', 'sources', 'baseline_manifest'} or tree['schema'] != 'p011-go-send-assets-v76':
                _fail('publication_bundle_manifest')
            rows = tree['sources']
            if (type(rows) is not list or len(rows) != len(sources.MODULES) or any(
                type(r) is not list or len(r) != 3 or r[0] != name or type(r[1]) is not int or
                not 1 <= r[1] <= sources.MAX_SOURCE or not _hex(r[2], 64)
                for name, r in zip(sources.MODULES, rows))): _fail('publication_bundle_graph')
            payloads = {}
            for name, size, pin in rows:
                raw = self._read(ASSET_ROOT + '/runtime/' + name + '.py', sources.MAX_SOURCE, pin)
                if len(raw) != size: _fail('publication_bundle_size')
                payloads[name] = raw
            if payloads['mta_go_deployment'] != self._read(sources.__file__, sources.MAX_SOURCE, dict((r[0], r[2]) for r in rows)['mta_go_deployment']):
                _fail('publication_running_loader_changed')
            wpa = self._read(ASSET_ROOT + '/native/mta-wpa-supplicant', sources.WPA_BYTES, sources.WPA_SHA, True)
            if len(wpa) != sources.WPA_BYTES: _fail('publication_wpa_size')
            python = self._read(sources.PYTHON, sources.MAX_BINARY, binary=True)
            self.token = os.urandom(16).hex()
            run = sources.ROOT + '/go-' + self.token
            value = {'schema': 'p011-go-send-transport-v76', 'go': {
                'version': 1, 'run_token': self.token, 'candidate_sha': _digest(manifest_raw),
                'task_id': self.task_id, 'ifname': 'mta' + self.token[:8], 'python_sha': _digest(python),
                'sources': [[name, pin] for name, size, pin in rows], 'baseline_manifest': tree['baseline_manifest']}}
            sources.GoManifest(value['go'], self.token)  # Pure original schema, no permission.
            deployment_raw = (json.dumps(value, ensure_ascii=True, sort_keys=True) + '\n').encode('ascii')
            self.manifest_sha = _digest(deployment_raw)
            anchors = self.reader.anchors(sources.ROOT + '/unused')
            self.root = self._directory(sources.ROOT)
            entries = os.listdir(self.root['fd'])
            if len(entries) >= MAX_ENTRIES: _fail('publication_root_limit')
            self.run = self._directory(run, self.root, 'go-' + self.token, True)
            self.runtime = self._directory(run + '/runtime', self.run, 'runtime', True)
            self.native = self._directory(run + '/native', self.run, 'native', True)
            self.ctrl = self._directory(run + '/ctrl', self.run, 'ctrl', True)
            for name, size, pin in rows: self._write(self.runtime, name + '.py', payloads[name], 0o400)
            self._write(self.native, 'mta-wpa-supplicant', wpa, 0o500)
            self._write(self.run, 'deployment.json', deployment_raw, 0o400)
            config = (b'ctrl_interface=' + (run + '/ctrl').encode('ascii') + b'\n'
                b'p2p_no_group_iface=1\nap_scan=2\ndevice_name=P011\ndevice_type=1-0050F204-1\n'
                b'driver_param=mta_p2p_initial=1 control_port=0\n')
            self._write(self.run, 'go.conf', config, 0o400)
            for row in (self.runtime, self.native, self.ctrl, self.run, self.root):
                self._dir_current(row); os.fsync(row['fd']); self._check()
            if self.reader.anchors(sources.ROOT + '/unused') != anchors: _fail('publication_root_anchors_changed')
            if set(os.listdir(self.root['fd'])) != set(entries) | {'go-' + self.token}: _fail('publication_root_entries_changed')
            self._check()
        except BaseException as error:
            self.failure = error
            raise
        finally:
            if not self.close(): self.unknown = True
        if self.unknown: _fail('publication_fd_inventory_pending')
        try:
            self._check()
            self.loader = sources.GoDeploymentLoader(self.token, self.manifest_sha, self.until, repr(self.until),
                                                     _clock=self._check)
            self.deployment = self.loader.load_parent()
            if self.deployment.launch_kind != 'parent_files' or self.deployment.task_id != self.task_id:
                _fail('publication_parent_origin_changed')
            self.loader.authenticate(self.deployment)
            self._check()
            return self.deployment
        except BaseException as error:
            self.failure = error
            raise
    def close(self):
        self._parent()
        if self.close_called: return self.closed
        self.close_called = True
        for row in reversed(self.rows):
            if not self._close(row): self.unknown = True
        self.closed = not self.unknown and all(r['closed'] and not r['unknown'] for r in self.rows)
        return self.closed
    def status(self):
        return {'local_preflight_called': self.local_called, 'local_preflight_retained': self.local_facts is not None,
                'local_preflight_consumed': self.local_consume_called, 'readonly_observer_connected': False,
                'started': self.called, 'files_closed': self.closed, 'resource_pending': self.unknown or not self.closed,
                'files_only_deployment': self.deployment is not None, 'production_admitted': False,
                'native_restore_verified': False, 'failed': self.failure is not None}
