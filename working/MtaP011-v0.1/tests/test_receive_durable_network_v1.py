"""One affected HOST Linux method: current durable receive with real TLS/HTTP.

Two fresh independent phases use the original download, ZIP, CRC, hard-link,
fsync and close implementations. Only the ReceiverTransport constructor's
loopback admission is projected. A delegating WSS observer records an original
EOF exception; it never supplies a message, bytes, exception or replacement IO.
Native admission, full Executor/Bridge, P011, RF and phone do not execute.
ROOT alone executes this file from its fixed private-input snapshot.
"""
import ast
import builtins
import errno
import hashlib
import math
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
from unittest import mock
import warnings


ROOT = Path(__file__).resolve().parents[1]
SELECTOR = 'ReceiveDurableNetworkV1Tests.test_actual_tls_durable_late_cancel_and_missing_ack'
RESULT_SCHEMA = 'p011-receive-durable-network-v1'
SOURCE_PINS = (
    ('candidate/formal-receive-durable-state-v1/runtime/mta_storage.py', 56595,
     '365490e2dfe8a2c65d2b38fc8ae1a49747d09ed3b127677e9fe61e69866052d0'),
    ('candidate/formal-receive-durable-state-v1/runtime/mta_transport.py', 41435,
     '9b05ef49059e9b06536de32186e7de1cfd531461d3e096eb266d49f760069f8e'),
    ('runtime/mta_protocol.py', 17958,
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('runtime/p011_json.py', 8061,
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('candidate/file-utf8-v67/runtime/mta_files.py', 10987,
     'c6316be40cf34f017d1d2160f48989a55edfa0a60a2abe6a2ff6b656773f752b'),
    ('runtime/mta_send_preparation.py', 28532,
     '0e92fc68947601d0517cfe64a22d90d50b9952529c4594a6a189970420f69814'),
    ('runtime/mta_sender_pump.py', 33455,
     '81c3d7ff98ab71cde2ac2858daaffd267f129033b28ebde1dbd2f13f19ff447c'),
    ('tests/test_sender_pump.py', 34154,
     '7c803767b357cf91ceac7e64bb255805ddf0ce257893344e2bc756b0e4bbd3b7'),
    ('tests/test_receive_bound_integration.py', 13877,
     'd0790f870bf62848ccfcb6f8c4937dbd6961aae63c5d849179f84af2187798ee'),
)
FIXED_RESULT = {
    'schema': 'p011-receive-durable-network-v1',
    'passed': True,
    'methods': 1,
    'old_methods': 0,
    'phases': 2,
    'phase_order': ('late_cancel', 'ack_loss'),
    'files_per_phase': (2, 2),
    'bytes_per_phase': (274144, 274144),
    'tls_connections_per_phase': (2, 2),
    'actual_tls_connections': 4,
    'source_count': 9,
    'actual_loopback_tcp_tls_http': True,
    'actual_linux_storage': True,
    'original_archive_handle': True,
    'same_task_durable_fact': True,
    'durable_identity_retained': True,
    'late_cancel_original_failure': True,
    'late_cancel_success': False,
    'ack_original_stream_eof': True,
    'ack_traceback_bound': True,
    'ack_unsent_original_queue': True,
    'peer_ack_verified': False,
    'sender_completed': False,
    'saved_hashes_verified': True,
    'resources_closed': True,
    'threads_joined': True,
    'callers_exited': True,
    'constructor_loopback_admission_fixture': True,
    'host_socket_owner_fixture': True,
    'constructor_projection_restored': True,
    'observer_delegates_original': True,
    'observer_restored': True,
    'source_preserved': True,
    'network_fake': False,
    'storage_fake': False,
    'clock_fake': False,
    'native_admission_verified': False,
    'full_executor_bridge_tested': False,
    'device_tested': False,
    'phone_tested': False,
    'rf_requested': False,
    'full_restore_verified': False,
}


def _definitions():
    originals = {}
    for path, size, digest in SOURCE_PINS:
        raw = (ROOT / path).read_bytes()
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, digest):
            raise AssertionError('durable network fixed source differs: ' + path)
        originals[path] = raw
    modules = {}
    original_import = builtins.__import__

    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('relative project import refused')
        if name in modules:
            return modules[name]
        if name.startswith(('mta_', 'p011_')):
            raise ImportError('unlisted project definition')
        return original_import(name, globals, locals, fromlist, level)

    sources = (
        ('p011_json', SOURCE_PINS[3][0]),
        ('mta_protocol', SOURCE_PINS[2][0]),
        ('mta_storage', SOURCE_PINS[0][0]),
        ('mta_files', SOURCE_PINS[4][0]),
        ('mta_transport', SOURCE_PINS[1][0]),
        ('mta_send_preparation', SOURCE_PINS[5][0]),
        ('mta_sender_pump', SOURCE_PINS[6][0]),
    )
    for name, path in sources:
        raw = originals[path]
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        value = types.ModuleType(name)
        value.__file__ = str(ROOT / path)
        value.__dict__['__builtins__'] = dict(vars(builtins), __import__=fixed_import)
        modules[name] = value
        exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    tree = ast.parse(originals[SOURCE_PINS[7][0]].decode('utf-8'))
    rows = [row for row in tree.body
            if isinstance(row, ast.ClassDef) and row.name == '_LoopbackOwner']
    if len(rows) != 1:
        raise AssertionError('fixed original socket owner definition required')
    owner_namespace = dict(errno=errno, threading=threading, time=time)
    # Exact original class only: no old TestCase, old method or module main.
    selected = ast.Module(body=rows, type_ignores=[])
    exec(compile(selected, 'HOST_original_loopback_owner', 'exec'), owner_namespace)
    return modules, owner_namespace['_LoopbackOwner'], originals


class ReceiveDurableNetworkV1Tests(unittest.TestCase):
    def _phase(self, modules, owner_type, phase):
        storage_module, transport = modules['mta_storage'], modules['mta_transport']
        sender = modules['mta_sender_pump']
        begun = time.monotonic()
        until = float(begun + 30.0)
        cleanup_until = until + 5.0
        base = Path(tempfile.mkdtemp(prefix='mta-durable-network-host-'))
        base_identity = os.lstat(base)
        source, target, private = base / 'source', base / 'target', base / 'private'
        registry = selection = prepared = user_binding = binding = storage = None
        listener = owner = pump = receiver = worker = None
        finished, late_cancel, peer_close_armed = (threading.Event() for unused in range(3))
        results, failures, requests, downloaded, verified = [], [], [], [], []
        cancellation_points, eof_records, ws_records = [], [], []
        peer_close_calls, peer_close_returns, pump_failures = [], [], []
        cleanup_errors = []
        primary = None
        factory_original = transport.websocket_client
        admission_original = transport.private_ipv4
        stream_read_code = transport.Stream.read.__code__
        websocket_receive_code = transport.WebSocket.receive.__code__

        def cancelled():
            if phase == 'late_cancel' and not late_cancel.is_set():
                current = storage_module.SafeZipReceiver.durable_result(storage)
                if current is not None:
                    cancellation_points.append(storage._durable_result)
                    late_cancel.set()  # Only the real original durable point.
            return late_cancel.is_set()

        def observed_websocket(*args, **kwargs):
            value = factory_original(*args, **kwargs)
            self.assertIs(type(value), transport.WebSocket)
            self.assertIs(value.stream, args[0])
            self.assertEqual([], ws_records)
            self.assertNotIn('receive', value.__dict__)
            original_receive = value.receive
            self.assertIs(original_receive.__func__.__code__, websocket_receive_code)

            def observed_receive():
                try:
                    return original_receive()
                except BaseException as error:
                    if peer_close_armed.is_set() and storage._durable_result is not None:
                        trace, codes = error.__traceback__, []
                        for unused in range(16):
                            if trace is None:
                                break
                            frame = trace.tb_frame
                            if frame.f_globals is transport.__dict__:
                                codes.append(frame.f_code)
                            trace = trace.tb_next
                        eof_records.append((error, trace is None,
                            any(code is stream_read_code for code in codes),
                            any(code is websocket_receive_code for code in codes),
                            storage._durable_result))
                    raise  # Preserve the exact original exception; no fake EOF.

            value.receive = observed_receive
            ws_records.append((value, original_receive, observed_receive))
            return value  # Same original WebSocket, Stream and TLS socket.

        try:
            (source / 'Text').mkdir(parents=True)
            (source / 'GameResources').mkdir()
            target.mkdir(mode=0o700)
            private.mkdir(mode=0o700)
            payloads = {
                'Text/真实接收验证.txt': b'durable network receive\n' * 500,
                'GameResources/check.bin': os.urandom(262144),
            }
            self.assertEqual(274144, sum(len(value) for value in payloads.values()))
            for path, data in payloads.items():
                (source / path).write_bytes(data)
            registry = modules['mta_files'].FileRegistry(str(source))
            selection = registry.open_selection([row['id'] for row in registry.list_files()])
            prepared = modules['mta_send_preparation'].PreparedSend(selection,
                '/usr/bin/openssl', 'host-durable-receive', 'hostsender', until, str(private))
            user_binding = storage_module.DirectoryBinding(str(target), until, clock=time.monotonic)
            binding = user_binding.ensure_private_child('Received')
            storage = storage_module.SafeZipReceiver(binding.root, reserve_bytes=0, directory_binding=binding)
            self.assertIsNone(storage._durable_result)
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', message=r'ssl\.PROTOCOL_TLSv1_2 is deprecated',
                                        category=DeprecationWarning)
                prepared.prepare()
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.set_inheritable(False)
                listener.bind(('127.0.0.1', 0))
                owner = owner_type(listener, until, cleanup_until)
                pump = sender.SenderPump(listener, prepared.archive_handle, prepared.archive_size,
                    prepared.file_count, prepared.total_bytes, prepared.request_payload,
                    prepared.tls_context, owner, until)
                # Constructor only. All subsequent connect/TLS/HTTP/IO is original.
                with mock.patch.object(transport, 'private_ipv4', return_value='127.0.0.1') as allowance:
                    receiver = transport.ReceiverTransport('127.0.0.1', listener.getsockname()[1],
                        storage, cancelled=cancelled, absolute_until=until, clock=time.monotonic)
                self.assertEqual(1, allowance.call_count)
                self.assertIs(transport.private_ipv4, admission_original)
            if phase == 'ack_loss':
                transport.websocket_client = observed_websocket

            def confirm(request):
                requests.append(request)
                return True  # HOST user choice, not a native consent/admission claim.

            def receive():
                try:
                    results.append(receiver.run(confirm, progress=downloaded.append,
                        file_progress=lambda count, total: verified.append((count, total))))
                except BaseException as error:
                    failures.append(error)
                finally:
                    finished.set()

            pump.start()
            worker = threading.Thread(target=receive, name='HOST_actual_durable_receiver')
            worker.start()
            while not finished.is_set():
                self.assertLess(time.monotonic(), until)
                if pump.state in ('completed', 'cancelled', 'failed'):
                    break
                try:
                    pump.step(max_wait=.01)
                except BaseException as error:
                    pump_failures.append(error)
                    break
                if phase == 'ack_loss' and pump._terminal_pending is not None:
                    rows = [row for row in pump.connections if row.phase == 'ws']
                    self.assertEqual(1, len(rows))
                    row = rows[0]
                    self.assertIn(row, pump.history)
                    self.assertFalse(row.closed)
                    self.assertEqual('terminal_sending', row.ws_stage)
                    self.assertEqual('terminal', row.after_flush)
                    self.assertEqual(0, row.tx_offset)
                    self.assertIsNone(row.send_data)
                    self.assertGreater(len(row.tx), 0)
                    self.assertEqual(len(row.tx), row.flush_at)
                    self.assertEqual('completed', pump._terminal_pending[0])
                    self.assertIsNone(pump._terminal_pending[1])
                    self.assertTrue(pump._download_complete)
                    self.assertEqual(prepared.archive_size, pump._downloaded)
                    self.assertNotEqual('completed', pump.state)
                    self.assertIsNone(pump.result)
                    self.assertIs(owner.worker, threading.current_thread())
                    originals = [value for value in owner.rows
                                 if value['raw'] is row.raw and value['tls'] is row.tls]
                    self.assertEqual(1, len(originals))
                    self.assertFalse(originals[0]['close_called'])
                    self.assertIsNotNone(storage._durable_result)
                    peer_close_armed.set()  # Arm BEFORE actual close can wake recv.
                    peer_close_calls.append(row)
                    closed = sender.SenderPump._close_connection(pump, row, cleanup_until)
                    peer_close_returns.append(closed)
                    self.assertIs(closed, True)
                    self.assertIs(row.closed, True)
                    break  # Absolutely no next step: terminal ACK is never written.
            worker.join(max(0.0, until - time.monotonic()))
            self.assertFalse(worker.is_alive())
            self.assertTrue(finished.is_set())
            self.assertEqual(1, len(requests))
            self.assertEqual(2, len(owner.rows))
            self.assertEqual(2, len(receiver._life._records))
            self.assertTrue(all(row['wrap_called'] and isinstance(row['tls'], ssl.SSLSocket)
                                for row in owner.rows))
            self.assertTrue(all(row['tls'] is not None and row['transferred']
                                for row in receiver._life._records))
            self.assertIs(receiver.directory_binding, binding)
            self.assertTrue(pump._download_complete)
            self.assertEqual(prepared.archive_size, pump._downloaded)
            self.assertEqual(prepared.archive_size, downloaded[-1])
            self.assertEqual((274144, 274144), verified[-1])
            self.assertEqual(1, len(receiver._bound_downloads))
            download_row = receiver._bound_downloads[0]
            resource = download_row['resource']
            self.assertIs(type(resource), storage_module.DownloadFile)
            self.assertEqual(1, len(binding.downloads))
            self.assertEqual([], binding.archives)
            self.assertIs(resource, binding.downloads[0])
            self.assertIs(resource.binding, binding)
            self.assertIs(resource.handle, resource.row['handle_original'])
            durable_original = storage._durable_result
            self.assertIs(type(durable_original), tuple)
            self.assertEqual(5, len(durable_original))
            durable = storage_module.SafeZipReceiver.durable_result(storage)
            self.assertEqual(requests[0]['taskId'], durable['taskId'])
            self.assertEqual((2, 274144), (durable['fileCount'], durable['totalSize']))
            self.assertIs(durable['peer_ack_verified'], False)
            self.assertIsNotNone(receiver.local_commit_result)
            self.assertEqual(durable, receiver.local_commit_result)
            self.assertNotEqual('completed', pump.state)
            self.assertIsNone(pump.result)
            if phase == 'late_cancel':
                self.assertEqual([], results)
                self.assertEqual(1, len(failures))
                self.assertIs(type(failures[0]), storage_module.TransferCancelled)
                self.assertIs(storage._bound_failure, failures[0])
                self.assertIs(storage._bound_complete, False)
                self.assertEqual(1, len(cancellation_points))
                self.assertIs(cancellation_points[0], durable_original)
                self.assertTrue(late_cancel.is_set())
                self.assertIsNone(pump._terminal_pending)
                self.assertEqual([], peer_close_calls)
                self.assertEqual([], eof_records)
            else:
                self.assertEqual([], failures)
                self.assertEqual([], pump_failures)
                self.assertEqual(1, len(results))
                self.assertIs(results[0], receiver.local_commit_result)
                self.assertIs(storage._bound_complete, True)
                self.assertIsNone(storage._bound_failure)
                self.assertFalse(late_cancel.is_set())
                self.assertEqual([], cancellation_points)
                self.assertEqual(1, len(peer_close_calls))
                self.assertEqual([True], peer_close_returns)
                self.assertEqual(1, len(ws_records))
                self.assertEqual(1, len(eof_records))
                error, complete, in_read, in_receive, eof_durable = eof_records[0]
                self.assertIs(type(error), transport.TransportError)
                self.assertEqual(('Unexpected end of transfer',), error.args)
                self.assertIs(complete, True)
                self.assertIs(in_read, True)
                self.assertIs(in_receive, True)
                self.assertIs(eof_durable, durable_original)
            # Verify actual retained files, never a fixture directory listing.
            expected_root = Path(binding.root)
            result_root = Path(durable['directory'])
            self.assertEqual(expected_root, result_root.parent)
            self.assertTrue(result_root.name.startswith('received-'))
            self.assertIs(selection.entries, prepared._selection_originals[1])
            selected_names = tuple(entry['name'] for entry in selection.entries)
            self.assertEqual(selected_names, tuple(row[2] for row in prepared._selection_originals[3]))
            self.assertEqual(2, len(selected_names))
            self.assertEqual(set(payloads), set(selected_names))
            # Original _archive enumerates the retained selection: index/name.
            expected_members = {str(index) + '/' + name:
                (len(payloads[name]), hashlib.sha256(payloads[name]).hexdigest(), payloads[name])
                for index, name in enumerate(selected_names)}
            expected_keys = tuple(expected_members)
            actual_paths = set()
            for path in durable['files']:
                value = Path(path)
                relative = value.relative_to(result_root).as_posix()
                self.assertIn(relative, expected_keys)
                self.assertFalse(value.is_symlink())
                actual = value.read_bytes()
                expected_size, expected_sha, expected_data = expected_members[relative]
                self.assertEqual(expected_size, len(actual))
                self.assertEqual(expected_sha, hashlib.sha256(actual).hexdigest())
                self.assertTrue(actual == expected_data, 'retained payload bytes differ')
                actual_paths.add(relative)
            self.assertEqual(set(expected_keys), actual_paths)
            self.assertIs(storage._durable_result, durable_original)
            self.assertTrue(all(not thread.is_alive() for thread in receiver._life._callers))
            self.assertTrue(any(thread is worker for thread in receiver._life._callers))
        except BaseException as error:
            primary = error
            raise
        finally:
            def cleanup(label, callback):
                try:
                    if callback() is not True:
                        raise AssertionError(label + ' close unknown')
                except BaseException as error:
                    cleanup_errors.append((label, error))

            if receiver is not None:
                cleanup('receiver', lambda: receiver.close(1))
            if pump is not None:
                cleanup('pump', lambda: pump.close(cleanup_until))
            elif listener is not None:
                def close_listener():
                    listener.close()
                    return listener.fileno() == -1
                cleanup('listener', close_listener)
            if worker is not None and worker.is_alive():
                worker.join(max(0.0, min(2.0, cleanup_until - time.monotonic())))
            worker_alive = worker is not None and worker.is_alive()
            if worker_alive:
                cleanup_errors.append(('receiver thread', AssertionError('still alive')))
            # Restore only the scoped delegating observation, including failures.
            transport.websocket_client = factory_original
            for value, original_receive, observer in ws_records:
                if value.__dict__.get('receive') is not observer:
                    cleanup_errors.append(('WSS observer identity', AssertionError('changed')))
                else:
                    del value.__dict__['receive']
                    if (value.receive.__self__ is not value or
                            value.receive.__func__ is not original_receive.__func__):
                        cleanup_errors.append(('original WSS receive', AssertionError('changed')))
            if transport.private_ipv4 is not admission_original:
                cleanup_errors.append(('constructor projection', AssertionError('not restored')))
            if prepared is not None:
                cleanup('preparation', lambda: prepared.close(cleanup_until))
            if selection is not None:
                def close_selection():
                    selection.close()
                    return (selection.lifecycle_status()['closure_verified'] is True and
                            registry.lifecycle_status()['closure_verified'] is True)
                cleanup('selection', close_selection)
            if storage is not None and not worker_alive:
                cleanup('storage', storage.close)
            if binding is not None and not worker_alive:
                cleanup('received binding', binding.close)
            if user_binding is not None and not worker_alive:
                cleanup('user binding', user_binding.close)
            if not cleanup_errors:
                try:
                    current = os.lstat(base)
                    if ((current.st_dev, current.st_ino) != (base_identity.st_dev, base_identity.st_ino) or
                            not base.is_absolute() or base.parent != Path(tempfile.gettempdir())):
                        raise AssertionError('fresh test tree identity differs')
                    # Only this exact identity-checked freshly-created HOST tree.
                    shutil.rmtree(base)
                except BaseException as error:
                    cleanup_errors.append(('fresh test tree', error))
            if cleanup_errors:
                failure = AssertionError('HOST resource cleanup unknown; retained test tree: ' +
                    ','.join(label for label, error in cleanup_errors))
                if primary is not None:
                    raise failure from primary
                raise failure
        self.assertIs(transport.websocket_client, factory_original)
        self.assertIs(transport.private_ipv4, admission_original)
        self.assertFalse(worker.is_alive())
        status = receiver.lifecycle_status()  # No ignored current/finishing caller.
        self.assertIs(status['close_verified'], True)
        for name in ('sockets_pending', 'actors_pending', 'threads_pending', 'processes_pending',
                     'unknown_wrappers', 'unknown_resources', 'wrappers_pending'):
            self.assertEqual(0, status[name])
        self.assertFalse(status['cleanup_pending'])
        self.assertTrue(all(row['closed'] and row['removed'] and not row['failures']
                            for row in receiver._bound_downloads))
        self.assertTrue(resource.handle.closed)
        self.assertTrue(all(row['closed'] and not row['unknown'] for row in storage._bound_rows))
        self.assertFalse(storage.lifecycle_status()['resource_pending'])
        self.assertTrue(binding.closed())
        self.assertTrue(user_binding.closed())
        self.assertTrue(all(row['closed'] and row['tls_close_returned'] and row['raw_close_returned']
                            for row in owner.rows))
        self.assertEqual(-1, listener.fileno())
        self.assertTrue(prepared.status()['closure_verified'])
        self.assertFalse(base.exists())
        elapsed = float(time.monotonic() - begun)
        self.assertTrue(math.isfinite(elapsed) and 0.0 <= elapsed <= 35.0)
        return elapsed

    def test_actual_tls_durable_late_cancel_and_missing_ack(self):
        self.assertEqual('posix', os.name)
        self.assertTrue(sys.platform.startswith('linux'))
        modules, owner_type, originals = _definitions()
        elapsed = []
        for phase in ('late_cancel', 'ack_loss'):
            with self.subTest(phase=phase):
                elapsed.append(self._phase(modules, owner_type, phase))
        self.assertEqual(2, len(elapsed))
        self.assertTrue(all((ROOT / path).read_bytes() == raw for path, raw in originals.items()))
        result = dict(FIXED_RESULT)
        result['phase_elapsed_seconds'] = tuple(elapsed)
        print('RESULT=' + repr(result))


if __name__ == '__main__':
    if sys.argv[1:] != [SELECTOR]:
        raise SystemExit(2)
    suite = unittest.TestSuite([ReceiveDurableNetworkV1Tests(
        'test_actual_tls_durable_late_cancel_and_missing_ack')])
    outcome = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
