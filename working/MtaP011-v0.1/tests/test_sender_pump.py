"""New HOST-only single-worker MTA pump TLS cases (unexecuted SOURCE).

No old TestCase or old test method is imported/run. The phone-side fixture
uses actual localhost TCP/TLS/WS/HTTP; it is not a phone interoperability,
P011, native GATT, radio, DHCP or owned-interface proof. Server start/step are
called on this test's original worker, not on a new server/listener thread.
Actual FileRegistry selection and PreparedSend archive/certificate preparation
are consumed as dependencies, never claimed as newly retested old suites.

Certificates/private keys exist only in a new HOST temporary directory. All
paths/error trace are private; successful stdout is only a fixed safe marker.
Both new production dependencies are bound to their authors' frozen bytes.
The test author must not execute/import/AST-parse this file or any target.
"""
import errno
import hashlib
import io
import os
from pathlib import Path
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import types
import unittest
import warnings
import zipfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('runtime/mta_sender_pump.py',
          '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c', 33455)
PREPARATION_SOURCE = ('runtime/mta_send_preparation.py',
    '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814', 28532)
OPENSSL = r'C:\Program Files\Git\mingw64\bin\openssl.exe'
MARKER = ('HOST_SENDER_PUMP new_methods=1 old_methods=0 loopback_tls=true '
          'device=false phone=false\n')


def _source_bytes(reference):
    if type(reference) is not tuple or len(reference) != 3:
        raise AssertionError('Sender SOURCE not frozen')
    raw = (ROOT / reference[0]).read_bytes()
    if len(raw) != reference[2] or hashlib.sha256(raw).hexdigest() != reference[1]:
        raise AssertionError('Sender fixed SOURCE drift')
    return raw


def _definitions():
    # Future ROOT-only child. The checker privately snapshots each dependency.
    sys.path.insert(0, str(ROOT / 'runtime'))
    import mta_files
    import mta_transport
    import mta_protocol
    loaded = []
    for name, reference in (('HOST_actual_sender_pump', SOURCE),
                            ('HOST_actual_send_preparation', PREPARATION_SOURCE)):
        raw = _source_bytes(reference)
        module = types.ModuleType(name)
        module.__file__ = str(ROOT / reference[0])
        exec(compile(raw, name, 'exec'), module.__dict__)
        loaded.append(module)
    return loaded[0], loaded[1], mta_files, mta_transport, mta_protocol


class _LoopbackOwner(object):
    """Actual Windows/HOST sockets; no Linux SO_BINDTODEVICE/EBADF claim.

    Inventory precedes accept/wrap/close, retaining original raw/TLS objects.
    TLS close must actually return before fileno==-1 can close the original
    transferred FD; detached raw.fileno==-1 alone is never a closure claim.
    These are actual HOST socket facts, not Linux FD metadata/fstat proof.
    Only this owner-worker may call server methods or close the inventory.
    """
    def __init__(self, listener, until, cleanup_until):
        self.listener, self.until = listener, until
        self.worker = threading.current_thread()
        self.rows, self.attempts, self.events = [], [], []
        self.listener_closed = False
        self.listener_close_called = False
        self.error_type = TimeoutError
        self.cleanup_until = cleanup_until  # Issued before preparation's first IO.

    def _close_period(self, until):
        if type(until) is not float or until not in (self.until, self.cleanup_until):
            raise AssertionError('HOST close original cap changed')
        if time.monotonic() >= until: raise self.error_type('HOST cleanup original deadline')

    def check(self, until):
        if threading.current_thread() is not self.worker:
            raise AssertionError('HOST pump server worker changed')
        if type(until) is not float or until > self.until or time.monotonic() >= until:
            raise self.error_type('HOST pump original deadline')
        self.events.append('check')

    def listen(self, listener, count, until):
        self.check(until)
        if listener is not self.listener or count != 2: raise AssertionError('Foreign HOST listener')
        listener.listen(count)
        listener.setblocking(False)
        self.events.append('listen')
        self.check(until)

    def accept(self, listener, until):
        self.check(until)
        if listener is not self.listener: raise AssertionError('Foreign HOST listener')
        attempt = {'raw': None, 'called': False, 'returned': False,
                   'no_resource': False, 'failure': None}
        self.attempts.append(attempt)  # BEFORE actual accept, not after fileno.
        attempt['called'] = True
        try: raw, address = listener.accept()
        except BlockingIOError as error:
            attempt['failure'] = error
            if type(error.errno) is not int or error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK, 10035):
                raise
            attempt['no_resource'] = True
            return None
        except BaseException as error:
            attempt['failure'] = error
            raise
        attempt['raw'], attempt['returned'] = raw, True
        row = {'raw': raw, 'tls': None, 'wrap_called': False, 'close_called': False,
               'closed': False, 'peer': address, 'fd': None,
               'tls_close_called': False, 'tls_close_returned': False,
               'raw_close_called': False, 'raw_close_returned': False}
        self.rows.append(row)
        row['fd'] = raw.fileno()
        self.events.append('accept')
        raw.set_inheritable(False)
        raw.setblocking(False)
        self.check(until)
        return raw, address

    def wrap(self, raw, context, until):
        self.check(until)
        rows = [row for row in self.rows if row['raw'] is raw]
        if len(rows) != 1 or rows[0]['wrap_called']: raise AssertionError('HOST wrap identity/replay')
        row = rows[0]
        row['wrap_called'] = True
        wrapped = context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        row['tls'] = wrapped
        self.events.append('wrap')
        if wrapped.fileno() != row['fd'] or raw.fileno() != -1 or row['closed']:
            raise AssertionError('HOST original TLS ownership transfer changed')
        wrapped.setblocking(False)
        self.check(until)
        return wrapped

    def close_connection(self, raw, tls, until):
        if threading.current_thread() is not self.worker: raise AssertionError('HOST close worker changed')
        self._close_period(until)
        rows = [row for row in self.rows if row['raw'] is raw and row['tls'] is tls]
        if len(rows) != 1: raise AssertionError('HOST close foreign inventory')
        row = rows[0]
        if row['close_called']: return row['closed']
        row['close_called'] = True
        if tls is not None:
            if tls.fileno() != row['fd']: raise AssertionError('HOST TLS original FD changed')
            row['tls_close_called'] = True
            tls.close()
            row['tls_close_returned'] = True
        row['raw_close_called'] = True
        raw.close()
        row['raw_close_returned'] = True
        row['closed'] = (row['raw_close_returned'] and raw.fileno() == -1 and
                        (tls is None or row['tls_close_returned'] and tls.fileno() == -1))
        self.events.append('close_connection')
        return row['closed']

    def close_listener(self, listener, until):
        if threading.current_thread() is not self.worker or listener is not self.listener:
            raise AssertionError('HOST listener close identity changed')
        self._close_period(until)
        if not self.listener_close_called:
            self.listener_close_called = True
            listener.close()
            self.listener_closed = listener.fileno() == -1
            self.events.append('close_listener')
        return self.listener_closed


class _ProtocolPeer(object):
    """One simulated-phone thread with real TLS and actual protocol codecs."""
    def __init__(self, transport, protocol, port, task, scenario, until):
        self.transport, self.protocol = transport, protocol
        self.port, self.task, self.scenario, self.until = port, task, scenario, until
        self.thread = None
        self.sockets, self.certificates = [], []
        self.events, self.errors, self.archive = [], [], None
        self.done = threading.Event()
        self.ack = None

    def connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        self.sockets.append(raw)
        wrapped = context.wrap_socket(raw, server_hostname='127.0.0.1')
        self.sockets.append(wrapped)
        self.certificates.append(hashlib.sha256(wrapped.getpeercert(binary_form=True)).digest())
        return self.transport.Stream(wrapped, deadline=self.until+3.0)

    def _status(self, ws, task, kind=1, name='status'):
        message = self.protocol.WsMessage('action', 2, name,
            {'taskId': task, 'id': task, 'type': kind, 'reason': 'HOST fixture'})
        ws.send(message)  # Actual WebSocket client encodes the mask direction.
        return message

    def run(self):
        try:
            stream = self.connect()
            ws = self.transport.websocket_client(stream, '127.0.0.1', self.port)
            version = ws.receive()
            if (version.msg_type, version.name, version.id) != ('action', 'versionNegotiation', 0):
                raise AssertionError('HOST actual version action mismatch')
            ws.send(version.make_ack({'version': 1, 'threadLimit': 1}))
            request = ws.receive()
            if (request.msg_type, request.name, request.id) != ('action', 'sendRequest', 1):
                raise AssertionError('HOST actual send request mismatch')
            if request.payload['taskId'] != self.task:
                raise AssertionError('HOST original task mismatch')
            ws.send(request.make_ack())
            self.events.append('accepted')
            if self.scenario == 'peer_cancel':
                sent = self._status(ws, self.task, name='cancel')
                self.ack = ws.receive()
                if (self.ack.msg_type, self.ack.name, self.ack.id) != ('ack', sent.name, sent.id):
                    raise AssertionError('HOST cancel ACK mismatch')
            elif self.scenario in ('early_complete', 'task_mismatch'):
                self._status(ws, self.task if self.scenario == 'early_complete' else 'other-host-task')
                try:
                    self.ack = ws.receive()
                except (self.transport.TransportError, OSError):
                    self.events.append('rejected_connection_closed')
                else:
                    raise AssertionError('HOST refused action unexpectedly acknowledged')
            elif self.scenario == 'timeout':
                # Leave WS waiting; actual server absolute period must stop it.
                try: ws.receive()
                except (self.transport.TransportError, OSError):
                    self.events.append('expired_connection_closed')
                else: raise AssertionError('HOST expired server sent success')
            else:
                self.events.append('download_connecting_with_ws_open')
                download = self.connect()
                download.send(('GET /download?taskId='+self.task+
                    ' HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n').encode('ascii'))
                first, headers = self.transport.read_headers(download)
                if not first.startswith(b'HTTP/1.1 200 '):
                    raise AssertionError('HOST archive HTTP status mismatch')
                target = io.BytesIO()
                self.transport.download_body(download, headers, target)
                self.archive = target.getvalue()
                self.events.append('download_completed')
                sent = self._status(ws, self.task)
                self.events.append('completion_sent_after_download')
                self.ack = ws.receive()
                if (self.ack.msg_type, self.ack.name, self.ack.id) != ('ack', sent.name, sent.id):
                    raise AssertionError('HOST completion ACK mismatch')
                self.events.append('completion_ack_received')
        except BaseException as error:
            self.errors.append(error)
        finally:
            for raw in reversed(self.sockets): raw.close()
            self.done.set()

    def start(self):
        self.thread = threading.Thread(target=self.run, name='HOST_simulated_phone')
        self.thread.start()

    def joined(self):
        self.thread.join(5)
        return not self.thread.is_alive()


class _Case(object):
    """Real selected HOST input and actual PreparedSend, not a fixture ZIP."""
    def __init__(self, private, files, preparation, task, until, scenario):
        self.directory = tempfile.mkdtemp(prefix='pump-case-', dir=private)
        user = os.path.join(self.directory, 'user')
        os.makedirs(os.path.join(user, 'Text'))
        self.data = os.urandom(1024*1024)  # Retain >1 pump chunk even if ZIP is compressed.
        self.source_path = os.path.join(user, 'Text', 'transfer.bin')
        with open(self.source_path, 'wb') as output: output.write(self.data)
        registry = files.FileRegistry(user)
        self.selection = registry.open_selection([row['id'] for row in registry.list_files()])
        self.member = '0/'+self.selection.entries[0]['name']
        self.prepared = preparation.PreparedSend(self.selection, OPENSSL, task,
            'hostsender', until, self.directory)
        self.preparation_until = until
        self.cleanup_until = until+4.0  # Once, not a post-failure now+TTL.
        try:
            # Only this known HOST 3.12 deprecation for the target's 3.5 TLS
            # constant; no global warning filter or production TLS replacement.
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', message=r'ssl\.PROTOCOL_TLSv1_2 is deprecated',
                                        category=DeprecationWarning)
                if self.prepared.prepare() is not self.prepared:
                    raise AssertionError('HOST actual preparation original changed')
        except BaseException:
            self.prepared.close(self.cleanup_until)
            self.selection.close()
            raise
        self.prepared_directory = self.prepared._directory
        self.prepared_directory_metadata = os.lstat(self.prepared_directory)
        if not os.path.isdir(self.prepared_directory) or os.path.islink(self.prepared_directory):
            raise AssertionError('HOST original preparation directory unavailable')
        self.archive = self.prepared.archive_handle
        self.archive_bytes = self.archive.read()
        self.archive.seek(0)
        # A caller may only narrow the already-issued preparation period.
        # The timeout fixture starts with a short pump cap AFTER real RSA/ZIP
        # preparation, not an extension/replacement of preparation's original.
        pump_until = min(until, time.monotonic()+2.0) if scenario == 'timeout' else until
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.set_inheritable(False)
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.owner = _LoopbackOwner(self.listener, pump_until, self.cleanup_until)
        self.payload = self.prepared.request_payload
        self.context, self.task, self.until = self.prepared.tls_context, task, pump_until

    def close_inputs(self):
        self.archive_fd = self.archive.fileno()
        self.selection_fds = [entry['handle'].fileno() for entry in self.selection.entries]
        current = os.lstat(self.prepared_directory)
        self.prepared_directory_same = ((current.st_dev, current.st_ino) ==
            (self.prepared_directory_metadata.st_dev, self.prepared_directory_metadata.st_ino))
        if not self.prepared_directory_same:
            raise AssertionError('HOST original preparation directory changed before close')
        self.prepared_close = self.prepared.close(self.owner.cleanup_until)
        self.prepared_directory_absent = not os.path.lexists(self.prepared_directory)
        # PreparedSend borrows this actual selection: closing its own archive,
        # certificate/process resources must not silently close selected input.
        self.selection_still_readable = True
        for entry in self.selection.entries:
            if entry['handle'].closed:
                self.selection_still_readable = False
                continue
            entry['handle'].seek(0)
            if entry['handle'].read() != self.data:
                self.selection_still_readable = False
        self.selection.close()


def _masked_count(wire):
    """Inspect only fixture outbound WS headers, never replace production parse."""
    unused, separator, data = wire.partition(b'\r\n\r\n')
    if separator != b'\r\n\r\n': raise AssertionError('HOST client upgrade header absent')
    count = 0
    while data:
        if len(data) < 2 or not data[1] & 128:
            raise AssertionError('HOST client WS frame not masked')
        size, offset = data[1] & 127, 2
        if size == 126:
            if len(data) < 4: raise AssertionError('HOST client frame truncated')
            size, offset = int.from_bytes(data[2:4], 'big'), 4
        elif size == 127:
            if len(data) < 10: raise AssertionError('HOST client frame truncated')
            size, offset = int.from_bytes(data[2:10], 'big'), 10
        end = offset+4+size
        if len(data) < end: raise AssertionError('HOST client masked payload truncated')
        data = data[end:]
        count += 1
    return count


class SenderPumpTest(unittest.TestCase):
    def test_tls_download_and_terminal_boundaries(self):
        module, preparation, files, transport, protocol = _definitions()
        original_send = ssl.SSLSocket.send
        original_worker = threading.current_thread()
        completed = []
        base = tempfile.mkdtemp(prefix='host-mta-pump-private-')
        base_meta = os.lstat(base)
        removed = False
        try:
            for scenario in ('normal', 'partial_writes', 'peer_cancel',
                             'early_complete', 'task_mismatch', 'timeout'):
                with self.subTest(scenario=scenario):
                    # Actual archive/OpenSSL preparation consumes an original cap.
                    # Only timeout narrows pump's own cap after preparation.
                    preparation_until = time.monotonic()+20.0
                    task = 'host-pump-'+scenario
                    case = _Case(base, files, preparation, task, preparation_until, scenario)
                    until = case.until
                    self.assertLessEqual(until, case.preparation_until)
                    case.owner.error_type = module.PumpError
                    events, wire, partial, terminal_writes = [], {}, [], []
                    self.assertEqual(len(case.archive_bytes), case.prepared.archive_size)
                    self.assertEqual(1, case.prepared.file_count)
                    self.assertEqual(len(case.data), case.prepared.total_bytes)
                    self.assertIs(case.prepared.process_waited, True)
                    self.assertEqual(0, case.prepared.process_returncode)
                    self.assertEqual(0, case.prepared.process.returncode)
                    self.assertIs(case.prepared.communicate_called, True)
                    self.assertIs(case.prepared.terminate_called, False)
                    self.assertEqual(['archive', 'stdout', 'stderr'],
                                     [row.role for row in case.prepared.fds])
                    self.assertIs(case.prepared.fds[0].handle, case.archive)
                    pump = module.SenderPump(case.listener, case.archive, case.prepared.archive_size,
                        case.prepared.file_count, case.prepared.total_bytes, case.payload,
                        case.context, case.owner, until,
                        progress=lambda state, details: events.append((state, dict(details))))
                    peer = _ProtocolPeer(transport, protocol, case.port, task, scenario, until)
                    pump_exception = None
                    concurrent_download = False
                    def real_tls_send(sock, data, flags=0):
                        # Transparent real SSL send. Only the affected short-write
                        # case truncates the requested slice; it never fabricates
                        # sent bytes or a successful handshake/protocol result.
                        owned = [row for row in case.owner.rows if row['tls'] is sock]
                        row = next((row for row in pump.connections if row.tls is sock), None)
                        fragment = data
                        terminal = bool(owned and row is not None and row.after_flush == 'terminal')
                        if owned:
                            self.assertIs(threading.current_thread(), original_worker)
                        if scenario == 'partial_writes' and owned:
                            fragment = data[:3 if terminal else 4096]
                        if terminal:
                            self.assertIsNone(pump.result)
                            if scenario != 'peer_cancel':
                                self.assertIs(pump._download_complete, True)
                                self.assertEqual(pump.archive_size, pump._downloaded)
                                self.assertIs(pump._download.closed, True)
                                download_owner = [item for item in case.owner.rows
                                                  if item['raw'] is pump._download.raw]
                                self.assertEqual(1, len(download_owner))
                                self.assertIs(download_owner[0]['closed'], True)
                        sent = original_send(sock, fragment, flags)
                        wire.setdefault(sock, bytearray()).extend(fragment[:sent])
                        if owned and sent < len(data): partial.append((len(data), sent))
                        if terminal: terminal_writes.append((len(data), sent))
                        return sent
                    try:
                        with mock.patch.object(ssl.SSLSocket, 'send', real_tls_send):
                            self.assertIs(pump.start(), pump)
                            self.assertIs(pump.worker, original_worker)
                            peer.start()  # The only new thread is this phone fixture.
                            with mock.patch.object(threading.Thread, 'start',
                                    side_effect=AssertionError('HOST server thread forbidden')) as server_thread:
                                while pump.state not in ('completed', 'cancelled', 'failed'):
                                    if time.monotonic() > until+1.0:
                                        raise AssertionError('HOST pump did not honor original deadline')
                                    try: pump.step(max_wait=0.02)
                                    except transport.TransportError as error:
                                        pump_exception = error
                                        break
                                    if pump._download is not None and not pump._download.closed and \
                                            pump._ws is not None and not pump._ws.closed and pump._downloaded > 0:
                                        concurrent_download = True
                                    self.assertEqual(until, pump.until)
                                self.assertIs(pump.close(case.owner.cleanup_until), True)
                                self.assertEqual(0, server_thread.call_count)
                            self.assertTrue(peer.joined(), 'HOST phone fixture failed to exit')
                        self.assertEqual([], peer.errors)
                        self.assertIs(peer.done.is_set(), True)
                        self.assertTrue(all(sock.fileno() == -1 for sock in peer.sockets))
                        self.assertEqual(['waiting', 'negotiating', 'awaiting_confirmation', 'accepted'],
                                         [state for state, details in events[:4]])
                        self.assertEqual(until, pump.until)
                        self.assertIs(pump.worker, original_worker)
                        self.assertIsNone(pump.listener_close_error)
                        self.assertIs(pump.listener_closed, True)
                        self.assertEqual(-1, case.listener.fileno())
                        self.assertEqual(1, case.owner.events.count('close_listener'))
                        self.assertTrue(all(row.closed for row in pump.history))
                        self.assertTrue(all(row['close_called'] and row['closed'] for row in case.owner.rows))
                        self.assertTrue(all(row['raw_close_called'] and row['raw_close_returned'] and
                            row['tls_close_called'] and row['tls_close_returned'] for row in case.owner.rows))
                        self.assertTrue(all(attempt['returned'] or attempt['no_resource']
                            for attempt in case.owner.attempts))
                        self.assertEqual(len(case.owner.rows), case.owner.events.count('close_connection'))
                        for row in case.owner.rows:
                            self.assertEqual(-1, row['raw'].fileno())
                            self.assertEqual(-1, row['tls'].fileno())
                        self.assertIs(pump.status()['socket_cleanup_pending'], False)
                        # Same cleanup cap is a passive known-closed readback;
                        # neither owner callback nor socket close is called twice.
                        close_events = list(case.owner.events)
                        self.assertIs(pump.close(case.owner.cleanup_until), True)
                        self.assertEqual(close_events, case.owner.events)
                        self.assertIs(case.archive.closed, False)  # Borrowed, not closed by pump.

                        client_wire = bytes(wire[peer.sockets[1]])
                        self.assertEqual(2 if scenario == 'timeout' else 3, _masked_count(client_wire))
                        if scenario in ('normal', 'partial_writes'):
                            self.assertIsNone(pump_exception)
                            self.assertIsNone(pump.failure)
                            self.assertEqual('completed', pump.state)
                            self.assertTrue(concurrent_download)
                            self.assertEqual(2, len(case.owner.rows))
                            self.assertEqual(2, len(peer.certificates))
                            self.assertEqual(peer.certificates[0], peer.certificates[1])
                            self.assertEqual(case.archive_bytes, peer.archive)
                            self.assertEqual(hashlib.sha256(case.archive_bytes).digest(),
                                             hashlib.sha256(peer.archive).digest())
                            with zipfile.ZipFile(io.BytesIO(peer.archive)) as archive:
                                self.assertIsNone(archive.testzip())
                                self.assertEqual([case.member], archive.namelist())
                                self.assertEqual(case.data, archive.read(case.member))
                            self.assertEqual(len(case.archive_bytes), pump._downloaded)
                            self.assertIs(pump._download_complete, True)
                            self.assertIs(pump.result['peer_completion_verified'], True)
                            self.assertEqual(len(case.data), pump.result['totalSize'])
                            self.assertEqual(1, pump.result['fileCount'])
                            self.assertEqual(len(case.archive_bytes), pump.result['archiveBytesSent'])
                            self.assertEqual(['accepted', 'download_connecting_with_ws_open',
                                'download_completed', 'completion_sent_after_download', 'completion_ack_received'], peer.events)
                            self.assertTrue(terminal_writes)
                            self.assertEqual('awaiting_result', events[-1][0])
                            self.assertEqual(len(case.archive_bytes), events[-1][1]['archiveBytesSent'])
                            server_wire = bytes(wire[case.owner.rows[1]['tls']])
                            first, separator, actual_body = server_wire.partition(b'\r\n\r\n')
                            self.assertTrue(first.startswith(b'HTTP/1.1 200 '))
                            self.assertEqual(b'\r\n\r\n', separator)
                            self.assertEqual(case.archive_bytes, actual_body)
                            if scenario == 'partial_writes':
                                self.assertTrue(partial)
                                self.assertGreater(len(terminal_writes), 1)
                                self.assertTrue(any(sent < size for size, sent in terminal_writes))
                        else:
                            self.assertIsNone(pump.result)
                            self.assertEqual(1, len(case.owner.rows))
                            self.assertEqual(0, pump._downloaded)
                            self.assertIs(pump._download_complete, False)
                            self.assertIsNone(peer.archive)
                            if scenario == 'peer_cancel':
                                self.assertIsNone(pump_exception)
                                self.assertEqual('cancelled', pump.state)
                                self.assertIsInstance(pump.failure, transport.Cancelled)
                                self.assertEqual(('ack', 'cancel', 2),
                                    (peer.ack.msg_type, peer.ack.name, peer.ack.id))
                                self.assertTrue(terminal_writes)
                            else:
                                self.assertIs(pump_exception, pump.failure)
                                self.assertIsInstance(pump.failure, module.PumpError)
                                self.assertEqual('failed', pump.state)
                                self.assertIsNone(peer.ack)
                                if scenario == 'timeout':
                                    self.assertIn(str(pump.failure), ('Transfer deadline exceeded',
                                        'HOST pump original deadline'))
                                    self.assertGreaterEqual(time.monotonic(), until)
                                else:
                                    self.assertEqual({'early_complete': 'Completion before full archive transfer',
                                        'task_mismatch': 'Status task mismatch'}[scenario], str(pump.failure))
                        completed.append(scenario)
                    finally:
                        if not pump.listener_close_called: pump.close(case.owner.cleanup_until)
                        if peer.thread is not None and peer.thread.is_alive(): peer.joined()
                        case.close_inputs()
                        self.assertIs(case.prepared_close, True)
                        self.assertIs(case.prepared.status()['resource_pending'], False)
                        self.assertIs(case.prepared.status()['private_directory_removed'], True)
                        self.assertIs(case.prepared.status()['closure_verified'], True)
                        self.assertIs(case.prepared.status()['selection_closed_by_preparation'], False)
                        for row in case.prepared.fds:
                            self.assertIs(row.closed, True)
                            self.assertIs(row.unknown, False)
                            self.assertIs(row.handle.closed, True)
                            if row.role == 'archive':
                                self.assertIs(row.close_called, True)
                                self.assertIs(row.communicate_closed, False)
                            else:
                                # No fstat of historical pipe numbers after TLS
                                # work: preparation captured actual immediate EBADF.
                                self.assertIs(row.communicate_closed, True)
                                self.assertIs(row.close_called, False)
                        self.assertIs(case.prepared_directory_same, True)
                        self.assertIs(case.prepared_directory_absent, True)
                        self.assertIs(case.selection_still_readable, True)
                        self.assertIs(case.archive.closed, True)
                        self.assertIs(case.selection.lifecycle_status()['closure_verified'], True)
                        # These are actual HOST file FD EBADF, not socket metadata.
                        for fd in [case.archive_fd]+case.selection_fds:
                            with self.assertRaises(OSError) as caught: os.fstat(fd)
                            self.assertEqual(errno.EBADF, caught.exception.errno)
            self.assertEqual(6, len(completed))
        finally:
            # Exactly this newly-created HOST directory, one cleanup invocation.
            current = os.lstat(base)
            self.assertEqual((base_meta.st_dev, base_meta.st_ino), (current.st_dev, current.st_ino))
            shutil.rmtree(base)
            removed = True
        self.assertTrue(removed)
        self.assertFalse(os.path.exists(base))
        print(MARKER, end='')


if __name__ == '__main__':
    unittest.main()
