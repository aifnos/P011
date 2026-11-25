"""Owner-bound confined FileCenter companion. No CLI, LAN or radio actions.

Original Toolbox State/FileStore/HTTP parser/audio query engine are reused.
The public factory requires the exact retained formal Owner and same user root.
The private constructor exists for labelled HOST tests, not device authority.
"""
import errno
import math
import os
import re
import socket
import stat
import sys
import threading
import time
import types
import urllib.parse
from mta_toolbox_server import State, BoundedServer, Handler
from mta_toolbox_storage import FileStore, components, kind
from mta_filecenter_audio import FileCenterAudio
from mta_filecenter_storage import RetainedFileStore

USER_ROOT = '/mnt/data/p011-toolbox/user'
GET_ROUTES = ('/api/state', '/api/files', '/api/open', '/api/audio')
POST_ROUTES = ('/api/audio/play', '/api/audio/stop', '/api/ui/event')
MEDIA_TYPES = {'.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
    '.gif':'image/gif', '.bmp':'image/bmp', '.webp':'image/webp',
    '.mp4':'video/mp4', '.m4v':'video/mp4', '.webm':'video/webm',
    '.mkv':'video/x-matroska', '.avi':'video/x-msvideo', '.mov':'video/quicktime'}


def _cleanup_cap(cleanup_until, seconds=3.0):
    now = time.monotonic()
    if cleanup_until is not None and (type(cleanup_until) is not float or
            not math.isfinite(cleanup_until)):
        raise ValueError('original_finite_cleanup_cap_required')
    return min(now + seconds, cleanup_until) if cleanup_until is not None else now + seconds


def _cleanup_remaining(cleanup_until):
    return max(0.0, cleanup_until - time.monotonic())


class _MediaLock:
    """Wait only within the retained parent/caller cap, without renewing it."""
    def __init__(self, companion, lock, deadline=None):
        parent_until = companion.until
        if type(parent_until) is not float or not math.isfinite(parent_until):
            raise ValueError('original_finite_cap_required')
        if deadline is not None and (type(deadline) is not float or not math.isfinite(deadline)):
            raise ValueError('filecenter_finite_media_deadline_required')
        self.companion, self.lock = companion, lock
        self.deadline = parent_until if deadline is None else min(parent_until, deadline)

    def __enter__(self):
        while True:
            self.companion.check()
            remaining = self.deadline - time.monotonic()
            if remaining <= 0: raise ValueError('filecenter_media_lock_deadline')
            if self.lock.acquire(timeout=min(0.05, remaining)):
                try:
                    self.companion.check()
                    if time.monotonic() >= self.deadline:
                        raise ValueError('filecenter_media_lock_deadline')
                except BaseException:
                    self.lock.release()
                    raise
                return self

    def __exit__(self, error_type, error, traceback):
        self.lock.release()
        return False


def _owner_binding(owner, module):
    if (type(module) is not types.ModuleType or
            type(owner) is not getattr(module, 'FixedStateServiceOwner', None) or
            module.FixedStateServiceOwner is not owner._startup_owner_type_original or
            owner._startup_namespace_original is not module.__dict__ or
            module.FixedStateServiceOwner.__init__.__globals__ is not module.__dict__):
        raise ValueError('original_owner_required')
    if (owner.worker is not threading.current_thread() or owner.start_complete is not True or
            owner.state_complete is not True or owner.server_complete is not True or
            owner.state is not owner._state_original or owner.server is not owner._server_original or
            owner.user_directory is not owner._user_directory_original or
            owner.received_directory is not owner._received_directory_original or
            owner.user_directory.root != USER_ROOT or
            owner.received_directory.root != USER_ROOT+'/Received' or
            owner.state.registry.root != USER_ROOT or owner.state.received_root != USER_ROOT+'/Received' or
            owner.until is not owner.original_until or owner.clock is not time.monotonic or
            owner.stop_called or owner.close_called):
        raise ValueError('original_owner_changed')
    owner._context()
    if owner.user_directory.check() is not owner.user_directory or \
            owner.received_directory.check() is not owner.received_directory:
        raise ValueError('original_directory_changed')
    return owner.user_directory.root


def create(owner, owner_module, retain):
    root = _owner_binding(owner, owner_module)
    if not callable(retain): raise ValueError('original_companion_retainer_required')
    original_state, original_server = owner.state, owner.server
    original_directory, original_received = owner.user_directory, owner.received_directory
    original_until, original_clock = owner.original_until, owner.clock
    storage = sys.modules.get('mta_storage')
    if (type(storage) is not types.ModuleType or type(original_directory) is not storage.DirectoryBinding or
            type(original_received) is not storage.DirectoryBinding or
            storage.DirectoryBinding._current.__globals__ is not storage.__dict__ or
            original_directory.clock is not original_clock or original_received.clock is not original_clock or
            original_directory.absolute_until is not original_until or
            original_received.absolute_until is not original_until):
        raise ValueError('original_storage_required')
    directory_type, passive = storage.DirectoryBinding, storage.DirectoryBinding._current
    directory_fd, received_fd = passive(original_directory, False), passive(original_received, False)
    def guard():
        # Handler workers do not invoke worker-only Owner methods or acquire RF.
        if (owner.state is not original_state or owner.server is not original_server or
                owner.user_directory is not original_directory or
                owner.received_directory is not original_received or owner.stop_called or
                owner.close_called or owner.state.closing or owner.until is not original_until or
                owner.original_until is not original_until or owner.clock is not original_clock or
                original_clock() >= original_until or
                type(owner) is not owner_module.FixedStateServiceOwner or
                owner._startup_namespace_original is not owner_module.__dict__ or
                sys.modules.get('mta_storage') is not storage or storage.DirectoryBinding is not directory_type or
                storage.DirectoryBinding._current is not passive or
                original_directory.clock is not original_clock or original_received.clock is not original_clock or
                original_directory.absolute_until is not original_until or
                original_received.absolute_until is not original_until):
            raise ValueError('original_owner_changed')
        if passive(original_directory, False) != directory_fd or passive(original_received, False) != received_fd:
            raise ValueError('original_directory_changed')
        return True
    value = _Companion.__new__(_Companion)
    retain(value)  # Caller owns the exact object before State/HTTP/Thread can fail.
    try: _Companion.__init__(value, root, owner.original_until, guard)
    finally: value.owner = owner
    return value


class _FileCenterState(State):
    def __init__(self, root, parent_until=None):
        # Only the original Handler's permitted FileCenter/audio fields. Do
        # not run State's unrelated scores/sampler/LAN initialization.
        self.store = RetainedFileStore.__new__(RetainedFileStore)
        self.audio = None
        self.lock = threading.RLock(); self.audio_control_lock = threading.RLock()
        self.token = os.urandom(32).hex(); self.native_bootstrap_until = 0
        self.last_audio_command = -1; self.events = []; self.lan = self.lan_thread = None
        self.worker = None; self.stop_event = threading.Event(); self.preview = False
        self.state_dir = None
        RetainedFileStore.__init__(self.store, root)
        self.state_dir = os.path.join(self.store.root, '.toolbox-state')
        if os.path.lexists(self.state_dir) and (os.path.islink(self.state_dir) or not os.path.isdir(self.state_dir)):
            raise ValueError('状态目录不可用')
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        self.audio = FileCenterAudio.__new__(FileCenterAudio)
        FileCenterAudio.__init__(self.audio, self.state_dir, self.event,
                                lambda path: (_ for _ in ()).throw(ValueError('source_unbound')),
                                parent_until=parent_until)

    def close(self, cleanup_until=None):
        cleanup_until = _cleanup_cap(cleanup_until)
        self.stop_event.set()
        failure = None
        try:
            if self.audio is not None:
                acquired = self.audio_control_lock.acquire(timeout=_cleanup_remaining(cleanup_until))
                if not acquired: raise RuntimeError('filecenter_audio_control_pending')
                try: self.audio.stop_audio(cleanup_until=cleanup_until)
                finally: self.audio_control_lock.release()
        except BaseException as error: failure = error
        try:
            if getattr(self.store, 'rootfd', None) is not None: self.store.close()
        except BaseException as error:
            if failure is None: failure = error
        if failure is not None: raise failure

    def start_lan(self, address): raise ValueError('本互传会话不开放局域网网页传输')
    def arm_native_bootstrap(self, seconds=30): raise ValueError('bootstrap_disabled')
    def native_bootstrap(self): raise ValueError('bootstrap_disabled')


class _FileCenterServer(BoundedServer):
    def __init__(self, address, state):
        self._listener_close_original = self._listener_close_original_retained = None
        self.listener_close_called = False
        self.listener_close_return_none = self.listener_post_fileno_minus_one = None
        self.listener_close_error = None
        self.listener_close_seal = self._listener_close_seal_retained = None
        self.listener_close_methods = self._listener_close_methods_retained = (
            type(self)._listener_receipt, type(self).listener_closed)
        self.actor_rows = []
        self.actor_lock = threading.Lock()
        try: BoundedServer.__init__(self, address, state)
        except BaseException:
            # HTTPServer can have opened its real socket before a later
            # semaphore/thread field fails. Retain only that actual object.
            try: self._retain_listener()
            except BaseException as error: self.listener_close_error = error
            raise
        self._retain_listener()

    def _retain_listener(self):
        raw = getattr(self, 'socket', None)
        if type(raw) is not socket.socket: raise ValueError('filecenter_listener_unknown')
        fd = raw.fileno()
        original = (self, raw, fd, None)
        self._listener_close_original = self._listener_close_original_retained = original
        if type(fd) is not int or fd < 0: raise ValueError('filecenter_listener_unknown')
        metadata = _listener_metadata(os.fstat(fd))
        if not stat.S_ISSOCK(metadata[2]): raise ValueError('filecenter_listener_unknown')
        original = (self, raw, fd, metadata)
        self._listener_close_original = self._listener_close_original_retained = original

    def _listener_receipt(self):
        original = self._listener_close_original
        if (type(original) is not tuple or len(original) != 4 or
                original is not self._listener_close_original_retained or original[0] is not self or
                type(original[1]) is not socket.socket or self.socket is not original[1] or
                type(original[2]) is not int or original[2] < 0 or type(original[3]) is not tuple or
                len(original[3]) != 7 or any(type(item) is not int or item < 0 for item in original[3]) or
                not stat.S_ISSOCK(original[3][2])): return None
        return original

    def listener_closed(self):
        """Consume the original listener's sealed close without its old FD."""
        methods = self.listener_close_methods
        if (type(methods) is not tuple or methods is not self._listener_close_methods_retained or
                len(methods) != 2 or type(self)._listener_receipt is not methods[0] or
                type(self).listener_closed is not methods[1]): return False
        original = methods[0](self)
        seal = self.listener_close_seal
        if (original is None or self.listener_close_called is not True or self.listener_close_error is not None or
                self.listener_close_return_none is not True or self.listener_post_fileno_minus_one is not True or
                type(seal) is not tuple or len(seal) != 6 or seal is not self._listener_close_seal_retained or
                seal[0] is not original or seal[1] is not True or seal[2] is not True): return False
        after = original[1].fileno()
        if type(after) is not int or after != -1: return False
        if seal[3] == 'badfd':
            return seal[4] is None and type(seal[5]) is int and seal[5] == errno.EBADF
        if seal[3] == 'reused':
            post = seal[4]
            return (type(post) is tuple and len(post) == 7 and
                all(type(item) is int and item >= 0 for item in post) and seal[5] is None and
                (post[0], post[1], stat.S_IFMT(post[2])) !=
                (original[3][0], original[3][1], stat.S_IFMT(original[3][2])))
        return False

    def close_listener(self):
        if self.listener_close_called:
            if self.listener_closed(): return None
            if self.listener_close_error is not None: raise self.listener_close_error
            raise ValueError('filecenter_listener_close_unknown')
        self.listener_close_called = True
        try:
            methods = self.listener_close_methods
            if (type(methods) is not tuple or methods is not self._listener_close_methods_retained or
                    len(methods) != 2 or type(self)._listener_receipt is not methods[0] or
                    type(self).listener_closed is not methods[1]):
                raise ValueError('filecenter_listener_close_unknown')
            original = methods[0](self)
            if original is None: raise ValueError('filecenter_listener_close_unknown')
            before = original[1].fileno()
            if (type(before) is not int or before != original[2] or
                    _listener_metadata(os.fstat(original[2])) != original[3]):
                raise ValueError('filecenter_listener_close_unknown')
            returned = original[1].close()
            self.listener_close_return_none = returned is None
            after = original[1].fileno()
            self.listener_post_fileno_minus_one = type(after) is int and after == -1
            if not self.listener_close_return_none or not self.listener_post_fileno_minus_one:
                raise ValueError('filecenter_listener_close_unknown')
            post, number = None, None
            try: post = _listener_metadata(os.fstat(original[2]))
            except OSError as error:
                number = error.errno
                if type(number) is not int or number != errno.EBADF: raise
                outcome = 'badfd'
            else:
                if ((post[0], post[1], stat.S_IFMT(post[2])) ==
                        (original[3][0], original[3][1], stat.S_IFMT(original[3][2]))):
                    raise ValueError('filecenter_listener_close_unknown')
                outcome = 'reused'
            seal = (original, True, True, outcome, post, number)
            self.listener_close_seal = self._listener_close_seal_retained = seal
        except BaseException as error:
            self.listener_close_error = error
            raise

    def serve_forever(self):
        while not self.stopping.is_set():
            try: request, address = self.socket.accept()
            except socket.timeout: continue
            except OSError:
                if self.stopping.is_set(): break
                raise
            row = dict(request=request, request_original=request, thread=None,
                initialized=False, start_called=False, start_returned=False,
                entered=False, ended=False, no_slot=False, error=None)
            with self.actor_lock: self.actor_rows.append(row)
            if not self.slots.acquire(False):
                row['no_slot'] = True; request.close(); row['ended'] = True; continue
            try:
                worker = threading.Thread.__new__(threading.Thread)
                row['thread'] = row['thread_original'] = worker
                threading.Thread.__init__(worker, target=self._process_retained, args=(row,address))
                row['initialized'] = True; worker.daemon = True
                with self.worker_lock: self.workers[request] = worker
                row['start_called'] = True
                worker.start(); row['start_returned'] = True
            except BaseException as error:
                row['error'] = error
                # Unknown starts remain retained; close() cannot sign closure.
                if not row['start_called']:
                    request.close()
                    with self.worker_lock: self.workers.pop(request,None)
                    self.slots.release(); row['ended'] = True
                raise

    def _process_retained(self, row, address):
        row['entered'] = True
        try: BoundedServer.process(self, row['request_original'], address)
        finally: row['ended'] = True

    def shutdown(self, cleanup_until=None):
        deadline = _cleanup_cap(cleanup_until)
        self.stopping.set()
        self.close_listener()
        if not self.worker_lock.acquire(timeout=_cleanup_remaining(deadline)):
            raise RuntimeError('filecenter_http_worker_lock_pending')
        try: requests = tuple(self.workers)
        finally: self.worker_lock.release()
        for request in requests:
            try: request.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def server_close(self, cleanup_until=None):
        deadline = _cleanup_cap(cleanup_until)
        # The inherited server_close creates its own two-second deadline.
        # Reuse shutdown, but join the exact retained actors under this cap.
        self.shutdown(cleanup_until=deadline)
        if not self.actor_lock.acquire(timeout=_cleanup_remaining(deadline)):
            raise RuntimeError('filecenter_http_actor_lock_pending')
        try: rows = tuple(self.actor_rows)
        finally: self.actor_lock.release()
        for row in rows:
            worker = row['thread']
            if worker is not None and row['initialized'] and row['start_returned'] and worker is not threading.current_thread():
                worker.join(_cleanup_remaining(deadline))

    def actors_closed(self):
        if not self.actor_lock.acquire(False): return False
        try: rows = tuple(self.actor_rows)
        finally: self.actor_lock.release()
        for row in rows:
            if row['request'] is not row['request_original'] or row['request_original'].fileno() != -1:
                return False
            worker = row['thread']
            if worker is None:
                if not row['no_slot'] or not row['ended']: return False
            elif not row['initialized'] or worker is not row['thread_original'] or worker.is_alive():
                return False
            elif row['start_called'] and (not row['start_returned'] or not row['entered'] or not row['ended']):
                return False
        return True


class _FileCenterHandler(Handler):
    def setup(self):
        self.deadline = min(self.deadline, self.server.companion.until)
        Handler.setup(self)

    def authorized(self, path):
        if path == '/api/media':
            headers = self.headers
            if (self.command != 'GET' or self.client_address[0] != '127.0.0.1' or
                    headers.get('Host', '') != self.server.expected_host or
                    headers.get('Origin', '') not in ('', 'null', 'file://') or
                    headers.get('Transfer-Encoding') or
                    any(len(headers.get_all(k, [])) > 1 for k in ('Host', 'Origin', 'Range'))):
                return False
            return True
        if not ((self.command == 'GET' and path in GET_ROUTES) or
                (self.command == 'POST' and path in POST_ROUTES)):
            return False
        return Handler.authorized(self, path)

    def dispatch(self):
        try:
            self.server.companion.check()
            path, query = self.query()
            if not self.authorized(path): self.reply('此会话不开放该接口', 403); return
            if path == '/api/media': self.media(query); return
            if self.command == 'GET' and path == '/api/open':
                self.reply(self.server.companion.open_file(query.get('path', ''), deadline=self.deadline)); return
            if self.command == 'GET' and path == '/api/state':
                self.reply({'metrics':{}, 'history':[], 'scores':{}, 'transfer':{'enabled':False}, 'addresses':[]}); return
            Handler.dispatch(self)
        except (OSError, ValueError, RuntimeError):
            if not self.response_started: self.reply('文件不可用、格式不支持或会话已结束', 400)

    def media(self, query):
        row = self.server.companion.media_row(query, deadline=self.deadline)
        with _MediaLock(self.server.companion, row['lock'], self.deadline):
            self.server.companion.check()
            size = row['bytes']; start, end = 0, size-1
            ranged = self.headers.get('Range', '')
            if ranged:
                match = re.fullmatch(r'bytes=([0-9]*)-([0-9]*)', ranged)
                if not match or not any(match.groups()): raise ValueError('invalid_range')
                first, last = match.groups()
                if first:
                    start = int(first); end = min(size-1, int(last)) if last else size-1
                else:
                    count = int(last); start = max(0, size-count)
                    if count <= 0: raise ValueError('invalid_range')
                if not 0 <= start <= end < size: raise ValueError('invalid_range')
            self.send_response(206 if ranged else 200)
            self.send_header('Content-Type', row['mime'])
            self.send_header('Content-Length', str(end-start+1))
            self.send_header('Accept-Ranges', 'bytes')
            if ranged: self.send_header('Content-Range', 'bytes %d-%d/%d' % (start, end, size))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.end_headers()
            row['handle'].seek(start); remaining = end-start+1
            while remaining:
                self.server.companion.check()
                block = row['handle'].read(min(65536, remaining))
                if not block: raise OSError('media_changed')
                self.wfile.write(block); remaining -= len(block)


def _listener_metadata(value):
    result = tuple(getattr(value, name, None) for name in
        ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size'))
    if any(type(item) is not int or not 0 <= item < (1 << 64) for item in result):
        raise ValueError('filecenter_listener_metadata_unknown')
    return result


class _Companion:
    def __init__(self, root, until, guard):
        if type(until) is not float or not math.isfinite(until) or until <= time.monotonic():
            raise ValueError('original_finite_cap_required')
        self.root, self.until, self.guard = root, until, guard
        self.worker = threading.current_thread()
        self.owner = None
        self.state = self.server = self.thread = None
        self.state_complete = self.server_complete = self.thread_initialized = False
        self.start_called = self.start_returned = False
        self.close_called = self.close_complete = False
        self.cleanup_until = None
        self.failure = None
        self.cleanup_failures = []
        self.media = []; self.media_lock = threading.RLock()
        self.audio = self.original_audio = None
        self.rootfd = self.original_rootfd = None
        self.address = self.socket_original = None
        self.store_original = self.store_close_original = self.listener_close_original = None
        self.check()
        # Retain the original object before constructors can fail partially.
        self.state = _FileCenterState.__new__(_FileCenterState)
        try:
            _FileCenterState.__init__(self.state, root, parent_until=self.until)
            self.state_complete = True
            self.rootfd = self.original_rootfd = self.state.store.rootfd
            self.store_original = self.state.store
            self.store_close_original = self.store_original._root_close_original
            self.audio = self.original_audio = self.state.audio
            source_callback = self.audio_source_fd
            self.audio.source_fd = source_callback
            self.audio.bind_source_fd_deadline(source_callback)
            self.server = _FileCenterServer.__new__(_FileCenterServer)
            _FileCenterServer.__init__(self.server, ('127.0.0.1', 0), self.state)
            self.server_complete = True
            self.server.handler = _FileCenterHandler
            self.server.companion = self
            self.address = self.server.server_address
            self.socket_original = self.server.socket
            self.listener_close_original = self.server._listener_close_original
            self.thread = threading.Thread.__new__(threading.Thread)
            threading.Thread.__init__(self.thread, target=self.server.serve_forever)
            self.thread_initialized = True; self.thread.daemon = True
            self.start_called = True
            self.thread.start(); self.start_returned = True
        except BaseException as error:
            self.failure = error
            # The caller must retain this constructor through __new__ + __init__.
            # No false close receipt is emitted for a partial/unknown constructor.
            raise
        finally:
            store = getattr(self.state, 'store', None)
            if store is not None: self.rootfd = self.original_rootfd = getattr(store, 'rootfd', None)
            if self.store_original is None:
                self.store_original = store
                self.store_close_original = getattr(store, '_root_close_original', None)
            if self.listener_close_original is None:
                self.listener_close_original = getattr(self.server, '_listener_close_original', None)
            if self.audio is None: self.audio = getattr(self.state, 'audio', None)

    def check(self):
        if self.close_called or time.monotonic() >= self.until or self.guard() is not True:
            raise ValueError('filecenter_session_ended')
        return True

    def credentials(self):
        if threading.current_thread() is not self.worker: raise ValueError('wrong_worker')
        self.check()
        if self.state_complete is not True or self.server_complete is not True or \
                self.start_returned is not True or not self.thread.is_alive():
            raise ValueError('filecenter_not_running')
        return {'endpoint':'http://'+self.server.expected_host, 'token':self.state.token}

    def open_file(self, path, deadline=None):
        self.check(); components(path)
        category = kind(path)
        if category == 'resource': raise ValueError('此文件仅保存，尚不支持打开')
        if category == 'text':
            value = self.state.store.text(path)
            value.update(kind='text', path=path)
            # Size is obtained on its own validated handle and must be closed.
            handle, info = self.state.store.open_file(path); handle.close()
            value['bytes'] = info.st_size
            return value
        with _MediaLock(self, self.media_lock, deadline):
            for row in self.media:
                if row['path'] == path and row['valid'] and row['handle'].closed is False:
                    return self._open_result(row)
            if len(self.media) >= 32: raise ValueError('preview_limit')
            row = dict(handle=None, fd=None, bytes=None,
                path=path, kind=category, cap=None,
                mime=MEDIA_TYPES.get(os.path.splitext(path)[1].lower(), 'application/octet-stream'),
                lock=None, close_called=False, closed=False, valid=False, error=None)
            self.media.append(row)
            try:
                handle, info = self.state.store.open_file(path)
                row['handle'] = handle; row['fd'] = handle.fileno(); row['bytes'] = info.st_size
                row['cap'] = os.urandom(32).hex(); row['lock'] = threading.RLock()
                if not 0 < info.st_size <= 256*1024*1024: raise ValueError('preview_size')
                row['valid'] = True
            except BaseException as error:
                row['error'] = error
                # Failed FileStore open owns its own pre-fstat/fdopen ticket.
                if row['handle'] is None: row['closed'] = True
                raise
            return self._open_result(row)

    def _open_result(self, row):
        return dict(kind=row['kind'], path=row['path'], bytes=row['bytes'],
            url='http://'+self.server.expected_host+'/api/media?cap='+row['cap'])

    def media_row(self, query, deadline=None):
        if set(query) != {'cap'} or re.fullmatch(r'[0-9a-f]{64}', query['cap']) is None:
            raise ValueError('invalid_media_cap')
        with _MediaLock(self, self.media_lock, deadline):
            rows = [row for row in self.media if row['cap'] == query['cap']]
        if len(rows) != 1 or not rows[0]['valid'] or rows[0]['handle'].closed: raise ValueError('invalid_media_cap')
        return rows[0]

    def audio_source_fd(self, path, deadline=None):
        self.check()
        with _MediaLock(self, self.media_lock, deadline):
            rows = [row for row in self.media if row['valid'] and row['kind']=='audio' and
                os.path.join(self.root, *components(row['path'])) == path and not row['handle'].closed]
        if len(rows) != 1: raise ValueError('original_audio_fd_required')
        return rows[0]['fd']

    def close(self, cleanup_until=None):
        if threading.current_thread() is not self.worker: raise ValueError('wrong_worker')
        if self.close_called: return self.close_complete
        # One budget for listener, handlers, serving thread and audio. A
        # caller's original absolute deadline can only shorten this cap.
        self.cleanup_until = _cleanup_cap(cleanup_until)
        self.close_called = True
        def attempt(action):
            try: action()
            except BaseException as error:
                self.cleanup_failures.append(error)
                if self.failure is None: self.failure = error
        if self.server is not None:
            if self.server_complete:
                attempt(lambda:self.server.shutdown(cleanup_until=self.cleanup_until))
                attempt(lambda:self.server.server_close(cleanup_until=self.cleanup_until))
            else:
                if type(self.server) is _FileCenterServer:
                    attempt(self.server.close_listener)
        if self.thread_initialized and self.start_returned:
            attempt(lambda:self.thread.join(_cleanup_remaining(self.cleanup_until)))
        if self.state is not None and hasattr(self.state,'stop_event'):
            attempt(lambda:self.state.close(cleanup_until=self.cleanup_until))
        try:
            # Close media only after HTTP workers and audio child have ended.
            if self._workers_closed() and self.audio is not None and self.audio.actors_closed():
                for row in self.media:
                    if row['handle'] is not None:
                        row['close_called'] = True
                        attempt(row['handle'].close)
                        row['closed'] = row['handle'].closed
                attempt(self.state.store.close_known_opens)
            self.close_complete = self.closed()
        except BaseException as error:
            self.cleanup_failures.append(error)
            if self.failure is None: self.failure = error
            self.close_complete = False
        return self.close_complete

    def _workers_closed(self):
        if not self.server_complete or not self.thread_initialized: return False
        if self.start_called and not self.start_returned: return False
        if not self.server.worker_lock.acquire(False): return False
        try:
            return self.thread.is_alive() is False and not self.server.workers and self.server.actors_closed()
        finally: self.server.worker_lock.release()

    def closed(self):
        if not self.close_called or not self.state_complete or not self.server_complete:
            return False
        return (self._workers_closed() and self.socket_original.fileno() == -1 and
            self.server.socket is self.socket_original and self.server.stopping.is_set() and
            type(self.server) is _FileCenterServer and
            self.server._listener_close_original is self.listener_close_original and
            _FileCenterServer.listener_closed(self.server) is True and
            self.state.worker is None and self.state.lan is None and
            self.state.audio is self.audio and self.audio.actors_closed() and
            self.state.store is self.store_original and type(self.store_original) is RetainedFileStore and
            type(self.store_close_original) is tuple and len(self.store_close_original) == 4 and
            type(self.listener_close_original) is tuple and len(self.listener_close_original) == 4 and
            self.store_original._root_close_original is self.store_close_original and
            self.store_close_original[1] is self.original_rootfd and
            self.listener_close_original[1] is self.socket_original and
            RetainedFileStore.root_closed(self.store_original) is True and
            self.state.store.opens_closed() and not self.cleanup_failures and
            all(row['closed'] and (row['handle'] is None or row['handle'].closed) for row in self.media))

    def public(self):
        return dict(closed=self.closed(), close_called=self.close_called,
            state_constructed=self.state_complete, server_constructed=self.server_complete,
            serve_thread_started=self.start_returned, media_handles=len(self.media),
            http_actor_rows=len(self.server.actor_rows) if self.server_complete else 0,
            sampler_created=False,
            cleanup_errors=len(self.cleanup_failures),
            audio_launches=len(self.audio.tickets) if self.audio is not None else 0,
            lan_allowed=False, bootstrap_allowed=False, radio_actions=False)
