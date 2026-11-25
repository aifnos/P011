"""Explicit task-bound append-only sender publication, SOURCE only.

No RF/process startup or admission at import/construction. The actual State
worker first retains PreparedSend and this publication. Only fixed sealed
assets are read; no caller source path, hash, executable, IO or ready flag.
Existing GO root is never created/repaired. Only a new random go-token child
is published with EXCL and read back. Failure/partial directories are retained;
no cleanup of another task, pending journal or system file is implemented.
load_parent() yields files-only LoadedGoDeployment; it cannot authorize Native.

The bundle seal is deliberately unset until ROOT freezes the complete sender
graph. This unexecuted SOURCE must not be presented as State/device admission.
"""
import errno
import hashlib
import os
import re
import stat
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
    def publish(self):
        self._check()
        if self.called or not _hex(BUNDLE_MANIFEST_SHA, 64): _fail('publication_unsealed_or_reused')
        if sources.__file__ != ASSET_ROOT + '/runtime/mta_go_deployment.py':
            _fail('publication_fixed_loader_path')
        self.called = True
        self.prepare_until = min(self.until, self._check() + 20.0)
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
        return {'started': self.called, 'files_closed': self.closed, 'resource_pending': self.unknown or not self.closed,
                'files_only_deployment': self.deployment is not None, 'production_admitted': False,
                'native_restore_verified': False, 'failed': self.failure is not None}
