"""SOURCE-only HOST77: actual private Linux pipes, modeled send antecedents.

One new method, eighteen independent fixtures; no previous TestCase is imported.
The complete fixed definitions are loaded without invoking Loader, GoEntry,
GoSendLaunch, Native, GoSendPumpOwner, SenderPump or parent constructors that
produce authority. Their exact-class __new__ fields below are explicit HOST
antecedents. No GO/GATT/DHCP/TLS/peer-completion/restore permission is proved.

Actual77 Channel adoption/current/status/progress/terminal and parent canonical
frame/sequence/inline consumption/passive retention algorithms run unchanged.
Pipe creation, fstat, nonblocking mode, PC_PIPE_BUF, select, read, write, close
and immediate EBADF observations are actual Linux syscalls. One EAGAIN fault
is an explicitly injected real OSError; partial-write instrumentation forwards
the original os.write on a strict prefix, not a simulated write success.

Clock values and GATT accepted-write/State/Operation/Process ancestry are model
data, not elapsed-task or radio evidence. Progress alone cannot issue RESULT,
reap an actual process or prove restore. Keys, paths and failure raw stay private.
The author must not execute/import/AST-parse this SOURCE, WSL or a device.
"""
import builtins
import errno
import hashlib
import json
import os
from pathlib import Path
import ssl
import stat
import sys
import tempfile
import threading
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    'host/go_send_progress_v77_definition_manifest.json',
    '802a8cf5abb1f360f3c637c1eac312e8edec00fd3a41ac065654b76552bffb6c', 5372)
BRIDGE_SOURCE = (
    'candidate/go-send-progress-v77/runtime/mta_go_send_bridge.py',
    'b5f723c7cd259e06d3aa07322909b4d96e48ad97529cd31f7166afe1a3b0f72c', 55247)
EXECUTOR_SOURCE = (
    'candidate/go-send-progress-v77/runtime/mta_go_executor.py',
    'c6bbf1b483c1ceea8f4d4cd4a6ada5ba843a07e8a10cc490fecef34acb950c0b', 36974)
LOADER_SOURCE = (
    'candidate/go-send-transport-v76/runtime/mta_go_deployment.py',
    '3abac40ec1fc0a6d223a7238cd10eb86fd2942407ec26156484826021eb161e8', 26113)
EXTRA_SOURCES = (
    ('mta_storage', 'runtime/mta_storage.py',
     '3c5c5f65ef0c8eb9a0256a99f931faff40558484bb908e89acee1c1c0aa3b4d6', 14335),
    ('mta_files', 'runtime/mta_files.py',
     'c37a00be58487abee32abf7ded7ed857e059883aee680e049e6372d3d06681ae', 10267),
    ('mta_send_preparation', 'runtime/mta_send_preparation.py',
     '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814', 28532),
)
MARKER = ('HOST77_GO_SEND_PROGRESS new_methods=1 old_methods=0 '
          'linux_pipe=true antecedents_model=true device=false phone=false\n')


def _bytes(reference):
    if type(reference) is not tuple or len(reference) != 3:
        raise AssertionError('HOST77 final source pin unavailable')
    raw = (ROOT / reference[0]).read_bytes()
    if len(raw) != reference[2] or hashlib.sha256(raw).hexdigest() != reference[1]:
        raise AssertionError('HOST77 fixed source changed')
    return raw


def _forbidden(*args, **kwargs):
    raise AssertionError('HOST77 authority/business/transport operation forbidden')


class _Definitions(object):
    """Copied whole-definition loading shape, no old helper or method execution."""
    def __init__(self):
        value = json.loads(_bytes(MANIFEST).decode('utf-8'))
        rows = value['sources']
        if type(rows) is not list or len(rows) != 24:
            raise AssertionError('HOST77 fixed24 source inventory changed')
        for name, expected in (('mta_go_send_bridge', BRIDGE_SOURCE),
                               ('mta_go_executor', EXECUTOR_SOURCE),
                               ('mta_go_deployment', LOADER_SOURCE)):
            selected = [r for r in rows if r['module'] == name]
            if len(selected) != 1 or tuple(selected[0][n] for n in ('path', 'sha256', 'bytes')) != expected:
                raise AssertionError('HOST77 source binding changed')
        references = [(r['module'], (r['path'], r['sha256'], r['bytes'])) for r in rows]
        references += [(n, (p, h, z)) for n, p, h, z in EXTRA_SOURCES]
        names = [n for n, reference in references]
        if len(set(names)) != len(names):
            raise AssertionError('HOST77 duplicated private definition name')
        self.modules = {n: types.ModuleType(n) for n in names}
        original_import = builtins.__import__

        def private_import(name, globals=None, locals=None, fromlist=(), level=0):
            if not level and name in self.modules:
                return self.modules[name]
            if level or name.startswith(('mta_', 'p011_')):
                raise AssertionError('HOST77 undeclared private dependency')
            return original_import(name, globals, locals, fromlist, level)

        for name, reference in references:
            module = self.modules[name]
            module.__file__ = str(ROOT / reference[0])
            module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
            exec(compile(_bytes(reference), name, 'exec'), module.__dict__)
        self.bridge = self.modules['mta_go_send_bridge']
        self.executor = self.modules['mta_go_executor']
        self.pumps = self.modules['mta_sender_pump']
        self.native = self.modules['mta_go_native']
        # No authority constructor, bootstrap, pump transport or native gate runs.
        self.executor._entry = self.executor._make_send_launch = _forbidden
        self.executor.bootstrap = self.executor.watchdog = _forbidden
        self.modules['mta_go_deployment'].GoDeploymentLoader.load = _forbidden
        self.modules['mta_go_deployment'].GoDeploymentLoader.authenticate = _forbidden
        self.native.NativeGoResources._owner = self.native.NativeGoResources._check = _forbidden
        self.pumps.SenderPump.start = self.pumps.SenderPump.step = self.pumps.SenderPump.run = _forbidden


class _Clock(object):
    def __init__(self):
        self.value, self.calls = 1.0, 0

    def __call__(self):
        self.calls += 1
        return self.value


class _OsProxy(object):
    """Actual syscalls; only one selected explicit write fault is injected."""
    def __init__(self):
        self.events, self.write_fault, self.write_fd = [], None, None

    def __getattr__(self, name):
        return getattr(os, name)

    def fstat(self, fd):
        self.events.append(('fstat', fd))
        return os.fstat(fd)

    def get_blocking(self, fd):
        self.events.append(('get_blocking', fd))
        return os.get_blocking(fd)

    def read(self, fd, size):
        self.events.append(('read', fd, size))
        return os.read(fd, size)

    def write(self, fd, raw):
        self.events.append(('write', fd, len(raw)))
        if fd == self.write_fd and self.write_fault == 'eagain':
            raise BlockingIOError(errno.EAGAIN, 'HOST77 explicit no-byte write')
        if fd == self.write_fd and self.write_fault == 'partial':
            return os.write(fd, raw[:max(1, len(raw) // 2)])
        return os.write(fd, raw)


class _Process(object):
    """No real process or reap proof; wait is always a tripwire."""
    def __init__(self):
        self.pid, self.poll_calls = 314159, 0

    def poll(self):
        self.poll_calls += 1
        return None

    wait = _forbidden


class _Fixture(object):
    def __init__(self, definitions, test):
        self.d, self.test = definitions, test
        self.clock, self.until = _Clock(), 301.0
        self.fd_rows, self.cleanup_failures = [], []
        self.archive, self.archive_path, self.archive_identity = None, None, None
        self.channel, self.parent = None, None
        self.original_os = definitions.bridge.os
        self.io = _OsProxy()
        definitions.bridge.os = self.io  # Private module only, not global os.
        try:
            self._construct()
        except BaseException as primary:
            retained_traceback = primary.__traceback__
            try: self.close()
            except BaseException as cleanup: raise primary.with_traceback(retained_traceback) from cleanup
            raise

    def _pipe(self, role):
        read, write = os.pipe()
        self.fd_rows.extend({'role': role, 'fd': fd, 'handle': None, 'closed': False} for fd in (read, write))
        for fd in (read, write):
            os.set_blocking(fd, False)
            self.test.assertIs(os.get_blocking(fd), False)
            self.test.assertIs(os.get_inheritable(fd), False)
        return read, write

    def _construct(self):
        b, f = self.d.bridge, self.d.executor
        self.output_read, self.output_write = self._pipe('output')
        self.error_read, self.error_write = self._pipe('error')
        self.control_read, self.control_write = self._pipe('control')
        # A linked private regular file: actual channel archive adoption requires nlink1.
        self.archive = tempfile.NamedTemporaryFile(mode='w+b', prefix='host77-', delete=False)
        self.archive_path = self.archive.name
        archive_ticket = {'role': 'archive', 'fd': None, 'handle': self.archive, 'closed': False}
        self.fd_rows.append(archive_ticket)  # Original returned handle before fileno/metadata.
        archive_ticket['fd'] = self.archive.fileno()
        initial = os.lstat(self.archive_path)
        self.archive_identity = (initial.st_dev, initial.st_ino, stat.S_IFMT(initial.st_mode),
                                 initial.st_uid, initial.st_gid, initial.st_nlink)
        archive_bytes = b'HOST77 private archive antecedent\n' * 4
        self.archive.write(archive_bytes); self.archive.flush(); self.archive.seek(0)
        self.size, self.count, self.total = len(archive_bytes), 1, len(archive_bytes)
        self.request = {'taskId': 'HOST77_task', 'fileCount': self.count, 'totalSize': self.total,
            'senderName': 'HOST model', 'fileName': 'model.bin', 'mimeType': 'application/octet-stream'}
        self.binding = {'run': '1' * 32, 'manifest': '2' * 64, 'nonce': '3' * 32,
            'task': self.request['taskId'], 'native_epoch': 7, 'operation_epoch': 7,
            'until': repr(self.until), 'parent_pid': os.getpid()}
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Explicit __new__ ancestry; no actor, durable, kernel-network or launch grant.
        self.entry = object.__new__(f.GoEntrySource)
        self.entry.worker, self.entry.clock, self.entry.until = threading.current_thread(), self.clock, self.until
        self.entry.deployment = types.SimpleNamespace(modules=self.d.modules)
        self.channel = b.SendTaskChannel(self.entry)  # Actual pure channel constructor.
        self.channel.input = self.channel._adopt('stdin', self.control_read, pipe=True)
        self.channel.output = self.channel._adopt('stdout', self.output_write, pipe=True)
        archive_row = self.channel._adopt('archive', self.archive.fileno())
        archive_row.value = self.archive
        self.channel.archive_handle, self.channel.context = self.archive, self.context
        self.channel.start = {'kind': 'START', 'seq': 1, 'binding': self.binding,
            'data': {'size': self.size, 'count': self.count, 'total': self.total, 'request': self.request}}
        cap = os.fpathconf(self.output_write, 'PC_PIPE_BUF')
        self.test.assertIs(type(cap), int); self.test.assertGreaterEqual(cap, 512)
        self.channel._progress_atomic_cap = cap
        self.channel._progress_atomic_original = (self.channel.output, self.output_write, cap)
        self.launch = object.__new__(f.GoSendLaunch)
        for name, value in (('entry', self.entry), ('deployment', self.entry.deployment),
            ('channel', self.channel), ('start', self.channel.start), ('archive_handle', self.archive),
            ('tls_context', self.context), ('task_id', self.request['taskId'])):
            object.__setattr__(self.launch, name, value)
        self.entry.send_launch = self.entry._send_launch_original = self.launch
        self.native = object.__new__(self.d.native.NativeGoResources)
        self.native.entry = self.entry
        self.owner = object.__new__(self.d.native.GoSendPumpOwner)
        object.__setattr__(self.owner, 'native', self.native)
        object.__setattr__(self.owner, 'end', self.until)
        self.pump = object.__new__(self.d.pumps.SenderPump)
        for name, value in dict(worker=self.entry.worker, clock=self.clock, archive=self.archive,
            context=self.context, owner=self.owner, until=self.until, started=True, failure=None,
            archive_size=self.size, file_count=self.count, total_bytes=self.total,
            task_id=self.request['taskId'], payload=dict(self.request), state='waiting',
            _accepted=False, _downloaded=0, _download_complete=False, result=None,
            connections=[], listener_closed=False, history=[]).items():
            setattr(self.pump, name, value)
        self.parent = object.__new__(b.GoSendBridge)
        self.operation = types.SimpleNamespace(epoch=7, cancelled=threading.Event(), session=object())
        self.state = types.SimpleNamespace(operation=self.operation, session=self.operation.session, native_epoch=7)
        self.helper, self.scan = types.SimpleNamespace(send=_forbidden), object()
        self.handoff = types.SimpleNamespace(helper=self.helper, native_epoch=7, operation_epoch=7,
            task_id=self.request['taskId'])
        self.intent = types.SimpleNamespace(handoff=self.handoff)
        self.operation.helper, self.operation.scan, self.operation.send_intent = self.helper, self.scan, self.intent
        self.prepared = types.SimpleNamespace(archive_handle=self.archive, archive_size=self.size,
            file_count=self.count, total_bytes=self.total, task_id=self.request['taskId'])
        self.process = _Process()
        for name, value in dict(state=self.state, operation=self.operation, prepared=self.prepared,
            worker=self.entry.worker, clock=self.clock, until=self.until, binding=self.binding,
            intent=self.intent, scan=self.scan, output=None, error_pipe=None, input=None, rows=[],
            raw_frames=[], frame_history=[], private_stderr=b'', stdout_raw=b'', output_eof=False,
            error_eof=False, _buffer=b'', _read_seq=0, _write_seq=0, _terminal_until=None,
            _listening_seen=False, _result_seen=False, _progress_received=0, _progress_bytes_seen=0,
            _latest_progress=None, _progress_first=[], _progress_last=[], _consumed_gatt_original=None,
            _consumed_intent_type=type(self.intent), _consumed_handoff_type=type(self.handoff),
            _native_phase=None, _native_queue=[], _native_failure=None, _condition=threading.Condition(),
            process=self.process, _process_original=self.process, _process_pid=self.process.pid,
            process_reaped=False, returncode=None, result=None, failure=None, close_called=False,
            closed=False, cancel_sent=False, called=False, listening=None).items():
            setattr(self.parent, name, value)
        self.parent._progress_task_original = (self.prepared, self.archive, self.size,
            self.count, self.total, self.request['taskId'])
        # Old parent State/deployment source admission is an explicit antecedent seam.
        def model_parent_check():
            if threading.current_thread() is not self.parent.worker or self.operation.cancelled.is_set():
                raise b.SendBridgeError('HOST77 modeled parent stop')
            now = self.clock()
            if now >= self.until: raise b.SendBridgeError('HOST77 modeled parent deadline')
            return now
        self.parent._check = model_parent_check
        for name, fd in (('output', self.output_read), ('error_pipe', self.error_read), ('input', self.control_write)):
            row = b._Fd(name); row.called = True; row.capture(fd, pipe=True)
            self.parent.rows.append(row); setattr(self.parent, name, row)
        self.accepted = {'event': 'client_write', 'code': 'accepted_by_bluez_not_file_transfer_complete'}
        self._consume_gatt_fixture()
        self.io.write_fd = self.output_write

    def _consume_gatt_fixture(self):
        # The ORIGINAL accepted model object, not a GATT producer or caller ready bit.
        self.parent._consumed_gatt_original = (self.parent, self.accepted, self.helper, self.intent,
            self.handoff, self.scan, 7, 7, self.operation, self.state, self.binding,
            tuple(sorted(self.accepted.items())))

    def prime(self):
        self.channel.emit('LISTENING', {'ssid': 'HOST77-MODEL', 'psk': 'model-only',
            'mac': '01:02:03:04:05:06', 'port': 12345})
        frame = self.parent._wait_frame('LISTENING')
        self.test.assertEqual('LISTENING', frame['kind'])
        self.test.assertEqual(1, frame['seq'])

    def consume_progress(self):
        self.parent._read_frames(0)
        while self.parent.raw_frames:
            frame = self.parent.raw_frames.pop(0)
            self.test.assertEqual('PROGRESS', frame['kind'])
            self.parent._record_progress(frame)

    def data(self, amount=0):
        value = self.d.pumps.SenderPump.status(self.pump)
        value = dict(value); value.update(fileCount=self.count, totalSize=self.total, archiveBytesSent=amount)
        return value

    def wire(self, kind, seq, data, binding=None):
        raw = self.d.bridge._wire({'kind': kind, 'seq': seq,
            'binding': self.binding if binding is None else binding, 'data': data})
        self.test.assertEqual(len(raw), os.write(self.output_write, raw))

    def drain(self):
        data = bytearray()
        while True:
            try: value = os.read(self.output_read, 8192)
            except BlockingIOError as error:
                self.test.assertEqual(errno.EAGAIN, error.errno); break
            if not value: break
            data.extend(value)
        return bytes(data)

    def close_output(self):
        self.test.assertIs(self.channel.output.close(), True)
        for row in self.fd_rows:
            if row['fd'] == self.output_write: row['closed'] = True

    def close(self):
        # Independent actual closure, even after sticky channel/partial failures.
        # This fixture never upgrades an unknown production row to closedKnown.
        for record in reversed(self.fd_rows):
            if record['closed']: continue
            fd = record['fd']
            try:
                metadata = os.fstat(fd)
                self.test.assertTrue(stat.S_ISFIFO(metadata.st_mode) or stat.S_ISREG(metadata.st_mode))
                returned = record['handle'].close() if record['handle'] is not None else os.close(fd)
                self.test.assertIsNone(returned)
                with self.test.assertRaises(OSError) as caught: os.fstat(fd)
                self.test.assertIs(type(caught.exception.errno), int)
                self.test.assertEqual(errno.EBADF, caught.exception.errno)
                record['closed'] = True
            except BaseException as error:
                self.cleanup_failures.append((record['role'], error))
        if self.archive_path is not None:
            try:
                current = os.lstat(self.archive_path)
                self.test.assertEqual(self.archive_identity,
                    (current.st_dev, current.st_ino, stat.S_IFMT(current.st_mode),
                     current.st_uid, current.st_gid, current.st_nlink))
                self.test.assertEqual(1, current.st_nlink)
                self.test.assertTrue(stat.S_ISREG(current.st_mode))
                self.test.assertIsNone(os.unlink(self.archive_path))  # Only this original private file, once.
                with self.test.assertRaises(FileNotFoundError): os.lstat(self.archive_path)
            except BaseException as error:
                self.cleanup_failures.append(('archive_path', error))
        self.d.bridge.os = self.original_os
        if self.cleanup_failures: raise self.cleanup_failures[0][1]

    def __enter__(self): return self

    def __exit__(self, typ, error, traceback):
        try: self.close()
        except BaseException as cleanup:
            if error is not None: raise error.with_traceback(traceback) from cleanup
            raise
        return False


class GoSendProgress77Test(unittest.TestCase):
    def test_owned_progress_pipe_and_passive_parent(self):
        self.assertEqual('posix', os.name)
        self.assertTrue(sys.platform.startswith('linux'))
        self.assertEqual(0, os.geteuid())  # Actual adopted pipe metadata is root-owned.
        definitions = _Definitions()
        b = definitions.bridge
        completed = []

        with self.subTest('valid_monotonic'), _Fixture(definitions, self) as x:
            x.prime()
            self.assertIs(x.channel.emit_progress(x.pump), True)
            self.assertIs(x.channel._progress_pump, x.pump)
            x.clock.value = 1.5; x.pump.state = 'transferring'; x.pump._downloaded = 64
            self.assertIs(x.channel.emit_progress(x.pump), True)
            x.channel.emit_terminal({'bytes': 0, 'peer_completed': False, 'restored': False}, 361.0)
            result = x.parent._wait_frame('RESULT')
            self.assertEqual(4, result['seq'])
            self.assertIs(result['data']['peer_completed'], False)
            self.assertIs(result['data']['restored'], False)
            self.assertEqual(64, x.parent.latest_progress()['archiveBytesSent'])
            self.assertEqual(2, x.parent._progress_received)
            self.assertEqual([2, 3], [r['seq'] for r in x.parent._progress_first])
            latest = x.parent.latest_progress(); latest['archiveBytesSent'] = 0
            self.assertEqual(64, x.parent.latest_progress()['archiveBytesSent'])
            self.assertEqual([], x.parent.raw_frames)
            self.assertIsNone(x.parent.result)
            self.assertIs(x.parent.process_reaped, False)
            completed.append('valid_monotonic')

        with self.subTest('throttle_expiry'), _Fixture(definitions, self) as x:
            x.prime(); self.assertIs(x.channel.emit_progress(x.pump), True); x.drain()
            x.clock.value = 1.499
            writes = len([e for e in x.io.events if e[0] == 'write'])
            self.assertIs(x.channel.emit_progress(x.pump), False)
            self.assertEqual(2, x.channel.write_seq)
            self.assertEqual(writes, len([e for e in x.io.events if e[0] == 'write']))
            x.clock.value = x.until; events = len(x.io.events)
            self.assertIs(x.channel.emit_progress(x.pump), False)
            self.assertEqual(events, len(x.io.events))
            self.assertEqual(2, x.channel.write_seq)
            self.assertEqual(301.0, x.entry.until)
            self.assertIs(x.channel._progress_failure, None)
            completed.append('throttle_expiry')

        with self.subTest('real_backpressure'), _Fixture(definitions, self) as x:
            x.prime(); filled = 0
            for attempt in range(1024):
                try: filled += os.write(x.output_write, b'x' * 4096)
                except BlockingIOError as error:
                    self.assertEqual(errno.EAGAIN, error.errno); break
            else: self.fail('HOST77 real pipe did not reach bounded backpressure')
            self.assertGreater(filled, 0)
            self.assertIs(x.channel.emit_progress(x.pump), False)
            self.assertEqual(1, x.channel.write_seq)
            self.assertEqual(filled, len(x.drain()))
            self.assertIsNone(x.channel._progress_failure)
            completed.append('real_backpressure')

        with self.subTest('no_byte_eagain'), _Fixture(definitions, self) as x:
            x.prime(); x.io.write_fault = 'eagain'
            self.assertIs(x.channel.emit_progress(x.pump), False)
            self.assertEqual(1, x.channel.write_seq); self.assertEqual(b'', x.drain())
            self.assertEqual(0, x.channel._progress_count)
            self.assertIsNone(x.channel._progress_failure)
            x.io.write_fault = None
            self.assertIs(x.channel.emit_progress(x.pump), True)
            self.assertEqual(2, x.channel.write_seq)
            completed.append('no_byte_eagain')

        with self.subTest('actual_partial_unknown'), _Fixture(definitions, self) as x:
            x.prime(); x.io.write_fault = 'partial'
            with self.assertRaises(b.SendBridgeError) as caught: x.channel.emit_progress(x.pump)
            self.assertEqual('progress_output_unknown', str(caught.exception))
            self.assertIs(x.channel._progress_failure, caught.exception)
            self.assertIs(x.channel.output.unknown, True)
            self.assertEqual(1, x.channel.write_seq); self.assertEqual(0, x.channel._progress_count)
            partial = x.drain(); self.assertGreater(len(partial), 0); self.assertFalse(partial.endswith(b'\n'))
            events = len(x.io.events)
            with self.assertRaises(b.SendBridgeError) as again: x.channel.emit_progress(x.pump)
            self.assertIs(again.exception, caught.exception); self.assertEqual(events, len(x.io.events))
            completed.append('actual_partial_unknown')

        with self.subTest('original_archive'), _Fixture(definitions, self) as x:
            x.prime(); self.assertIs(x.channel.emit_progress(x.pump), True); x.drain()
            x.pump.archive = object()
            with self.assertRaises(b.SendBridgeError) as caught: x.channel.emit_progress(x.pump)
            self.assertEqual('progress_original_changed', str(caught.exception))
            self.assertEqual(2, x.channel.write_seq)
            completed.append('original_archive')

        with self.subTest('strict_pump_field'), _Fixture(definitions, self) as x:
            x.prime(); x.pump._downloaded = True
            with self.assertRaises(b.SendBridgeError) as caught: x.channel.emit_progress(x.pump)
            self.assertEqual('progress_data_invalid', str(caught.exception)); self.assertEqual(1, x.channel.write_seq)
            completed.append('strict_pump_field')

        with self.subTest('original_request'), _Fixture(definitions, self) as x:
            x.prime(); self.assertIs(x.channel.emit_progress(x.pump), True); x.drain()
            x.request['fileName'] = 'changed-model.bin'
            with self.assertRaises(b.SendBridgeError) as caught: x.channel.emit_progress(x.pump)
            self.assertEqual('progress_request_changed', str(caught.exception)); self.assertEqual(2, x.channel.write_seq)
            completed.append('original_request')

        parent_refusals = (
            ('binding', 'output_binding_or_sequence'), ('sequence', 'output_binding_or_sequence'),
            ('fields', 'progress_data_invalid'), ('regression', 'progress_bytes_regressed'),
            ('after_terminal', 'progress_output_order'))
        for case, expected in parent_refusals:
            with self.subTest('parent_' + case), _Fixture(definitions, self) as x:
                x.prime(); value, binding, seq = x.data(), dict(x.binding), 2
                if case == 'binding': binding['nonce'] = '4' * 32
                elif case == 'sequence': seq = 3
                elif case == 'fields': value['accepted'] = 1
                elif case == 'regression':
                    x.wire('PROGRESS', 2, x.data(10)); x.consume_progress(); seq = 3
                elif case == 'after_terminal':
                    x.wire('RESULT', 2, {'bytes': 0, 'peer_completed': False, 'restored': False})
                    x.parent._read_frames(0); seq = 3
                x.wire('PROGRESS', seq, value, binding)
                with self.assertRaises(b.SendBridgeError) as caught: x.parent._read_frames(0)
                self.assertEqual(expected, str(caught.exception))
                self.assertIsNone(x.parent.result); self.assertIs(x.parent.process_reaped, False)
                completed.append('parent_' + case)

        with self.subTest('progress_not_result'), _Fixture(definitions, self) as x:
            x.prime(); x.pump.state = 'completed'; x.pump._accepted = True
            x.pump._downloaded = x.size; x.pump._download_complete = True
            x.pump.result = {'fileCount': x.count, 'totalSize': x.total,
                'archiveBytesSent': x.size, 'peer_completion_verified': True}  # Model DATA only.
            self.assertIs(x.channel.emit_progress(x.pump), True)
            x.parent._terminal_until = x.until + 60
            x.close_output()  # Actual EOF, not process reap or native restore.
            with self.assertRaises(b.SendBridgeError) as caught: x.parent._wait_frame('RESULT')
            self.assertEqual('f_output_eof', str(caught.exception))
            self.assertIs(x.parent.latest_progress()['peer_completion_verified'], True)
            self.assertIsNone(x.parent.result); self.assertIs(x.parent.process_reaped, False)
            self.assertIs(x.parent.status()['native_restore_verified'], False)
            completed.append('progress_not_result')

        known = ({'event': 'client', 'code': 'lease_or_services_timeout'},
                 {'event': 'client', 'code': 'own_connection_disconnect_requested'})
        with self.subTest('gatt_before_write'), _Fixture(definitions, self) as x:
            x.parent._consumed_gatt_original = None
            self.assertIs(x.parent.consumed_gatt_event(known[0], x.helper, 7, 7), False)
            self.assertIs(x.parent.native_event(known[0], x.helper, 7, 7), False)
            self.assertEqual('native_failed', x.parent._native_failure)
            self.assertIs(x.operation.cancelled.is_set(), False)
            completed.append('gatt_before_write')

        with self.subTest('gatt_consumed_cancel'), _Fixture(definitions, self) as x:
            self.assertIs(x.parent._consumed_gatt_original[1], x.accepted)
            self.assertIs(x.parent._consumed_gatt_current(), True)
            for event in known:
                self.assertIs(x.parent.consumed_gatt_event(event, x.helper, 7, 7), True)
                self.assertIs(x.parent.native_event(event, x.helper, 7, 7), True)
                self.assertIsNone(x.parent._native_failure)
            x.operation.cancelled.set()
            self.assertIs(x.parent.consumed_gatt_event(known[0], x.helper, 7, 7), False)
            self.assertIs(x.parent.native_event(known[0], x.helper, 7, 7), False)
            self.assertIs(x.operation.cancelled.is_set(), True)
            completed.append('gatt_consumed_cancel')

        with self.subTest('gatt_refs_cleanup'), _Fixture(definitions, self) as x:
            self.assertIs(x.parent.consumed_gatt_event(known[0], object(), 7, 7), False)
            self.assertIs(x.parent.consumed_gatt_event(known[0], x.helper, 8, 7), False)
            self.assertIs(x.parent.consumed_gatt_event({'event': 'cleanup', 'code': 'client_disconnect_failed'}, x.helper, 7, 7), False)
            self.assertIs(x.parent.consumed_gatt_event({'event': 'client', 'code': 'unknown'}, x.helper, 7, 7), False)
            x.accepted['code'] = 'cancelled_or_late_reply'
            self.assertIs(x.parent._consumed_gatt_current(), False)
            self.assertIs(x.parent.native_event(known[0], x.helper, 7, 7), False)
            self.assertEqual('native_failed', x.parent._native_failure)
            self.assertIs(x.operation.cancelled.is_set(), False)
            completed.append('gatt_refs_cleanup')

        with self.subTest('bounded_retention'), _Fixture(definitions, self) as x:
            x.prime()
            for index in range(640):
                x.clock.value = 1.0 + index * .01
                x.pump.state = 'waiting' if index % 2 == 0 else 'transferring'
                self.assertIs(x.channel.emit_progress(x.pump), True)
                x.consume_progress()
            self.assertEqual(640, x.channel._progress_count)
            self.assertEqual(641, x.channel.write_seq)
            self.assertEqual(640, x.parent._progress_received)
            self.assertEqual([2, 3], [r['seq'] for r in x.parent._progress_first])
            self.assertEqual([640, 641], [r['seq'] for r in x.parent._progress_last])
            self.assertEqual(1, len(x.parent.frame_history))
            x.pump.state = 'waiting'; seq = x.channel.write_seq
            self.assertIs(x.channel.emit_progress(x.pump), False); self.assertEqual(seq, x.channel.write_seq)
            x.channel.emit_terminal({'bytes': 0, 'peer_completed': False, 'restored': False}, 361.0)
            self.assertEqual(642, x.parent._wait_frame('RESULT')['seq'])
            self.assertLessEqual(x.channel._output_bytes, 512 * 1024)
            self.assertEqual(x.channel._output_bytes, len(x.parent.stdout_raw))
            self.assertEqual(2, len(x.parent.frame_history))
            self.assertIs(x.parent.status()['production_admitted'], False)
            completed.append('bounded_retention')

        self.assertEqual(18, len(completed))
        self.assertEqual(18, len(set(completed)))
        sys.stdout.write(MARKER)


if __name__ == '__main__':
    unittest.main()
