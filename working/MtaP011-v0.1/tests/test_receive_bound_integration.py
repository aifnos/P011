"""Affected bound HOST receive integration with real Linux/TLS/filesystem.

Only one new method. Existing HOST socket-owner definitions are reused; old
methods are not run. The socket constructor loopback allowance is an explicit
HOST fixture, not P011 radio, State/F admission or Xiaomi interoperability.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
sys.path.insert(0, str(ROOT / 'candidate/file-utf8-v67/runtime'))
sys.path.insert(0, str(ROOT / 'integration/ToolboxMta-v0.1/runtime'))
sys.path.insert(0, str(ROOT / 'candidate/receive-directory-fd-v1/runtime'))
from mta_files import FileRegistry
from mta_storage import DirectoryBinding, SafeZipReceiver
from mta_transport import ReceiverTransport
from mta_send_preparation import PreparedSend
from mta_sender_pump import SenderPump
from mta_toolbox_storage import FileStore

OWNER_SOURCE = (34154, '7c803767b357cf91ceac7e64bb255805ddf0ce257893344e2bc756b0e4bbd3b7')
raw = (ROOT / 'tests/test_sender_pump.py').read_bytes()
if (len(raw), hashlib.sha256(raw).hexdigest()) != OWNER_SOURCE:
    raise AssertionError('HOST socket owner source changed')
spec = importlib.util.spec_from_file_location('host_socket_owner_source', ROOT / 'tests/test_sender_pump.py')
owner_source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner_source)  # Definitions only, no old unittest.main/method.
OPENSSL = '/usr/bin/openssl'


class ReceiveBoundIntegrationTests(unittest.TestCase):
    def test_original_directory_archive_handle_tls_commit_and_filecenter(self):
        base = Path(tempfile.mkdtemp(prefix='mta-receive-filecenter-host-'))
        original = os.lstat(base)
        until = float(time.monotonic() + 30.0)
        cleanup_until = until + 5.0
        source = base / 'source'
        target = base / 'target'
        private = base / 'private'
        (source / 'Text').mkdir(parents=True)
        (source / 'GameResources').mkdir()
        target.mkdir(mode=0o700)
        private.mkdir()
        payloads = {'Text/接收验证.txt': '真实中文文件，确认后接收。\n'.encode('utf-8') * 500,
                    'GameResources/check.bin': os.urandom(1048576)}
        for path, data in payloads.items():
            (source / path).write_bytes(data)
        registry = selection = prepared = user_binding = binding = storage = None
        archive_resources, archive_handles = [], []
        listener = None
        pump = None
        receiver = None
        thread = None
        store = None
        accepted = threading.Event()
        prompted = threading.Event()
        finished = threading.Event()
        received, errors, requests, downloaded, verified, events = [], [], [], [], [], []
        passed = False
        primary_error = None
        cleanup_errors = []
        try:
            registry = FileRegistry(str(source))
            selection = registry.open_selection([row['id'] for row in registry.list_files()])
            prepared = PreparedSend(selection, OPENSSL, 'host-real-receive', 'hostsender', until, str(private))
            user_binding = DirectoryBinding(str(target), until, clock=time.monotonic)
            binding = user_binding.ensure_private_child('Received')
            storage = SafeZipReceiver(binding.root, reserve_bytes=0, directory_binding=binding)
            archive_resources, archive_handles = [], []
            original_create, original_receive = binding.create_download, storage.receive
            def create():
                resource = original_create()
                archive_resources.append(resource)
                return resource
            def receive_bound(*args, **kwargs):
                resource = kwargs.get('archive_resource')
                self.assertEqual(1, len(archive_resources))
                self.assertIs(resource, archive_resources[0])
                self.assertFalse(resource.handle.closed)
                archive_handles.append(resource.handle)
                return original_receive(*args, **kwargs)
            binding.create_download = create
            storage.receive = receive_bound
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', message=r'ssl\.PROTOCOL_TLSv1_2 is deprecated', category=DeprecationWarning)
                prepared.prepare()
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.set_inheritable(False)
                listener.bind(('127.0.0.1', 0))
                owner = owner_source._LoopbackOwner(listener, until, cleanup_until)
                pump = SenderPump(listener, prepared.archive_handle, prepared.archive_size,
                    prepared.file_count, prepared.total_bytes, prepared.request_payload,
                    prepared.tls_context, owner, until,
                    progress=lambda state, detail: events.append((state, detail)))
                # This admission projection lasts only for HOST construction.
                with mock.patch('mta_transport.private_ipv4', return_value='127.0.0.1'):
                    receiver = ReceiverTransport('127.0.0.1', listener.getsockname()[1],
                        storage, absolute_until=until, clock=time.monotonic)

            def consent(request):
                requests.append(request)
                prompted.set()
                while not accepted.wait(.02):
                    if time.monotonic() >= until:
                        return False
                return True

            def receive():
                try:
                    received.append(receiver.run(consent, progress=downloaded.append,
                        file_progress=lambda count, total: verified.append((count, total))))
                except BaseException as error:
                    errors.append(error)
                finally:
                    finished.set()

            pump.start()
            thread = threading.Thread(target=receive, name='host-actual-receiver')
            thread.start()
            consent_since = None
            consent_blocked_verified = False
            while pump.state not in ('completed', 'cancelled', 'failed'):
                if errors:raise errors[0]
                self.assertLess(time.monotonic(), until)
                pump.step(max_wait=.01)
                if errors:raise errors[0]
                if prompted.is_set() and not accepted.is_set():
                    if consent_since is None:
                        consent_since = time.monotonic()
                    self.assertIsNone(pump._download)
                    self.assertEqual([], downloaded)
                    self.assertEqual([], list((target / 'Received').iterdir()))
                    if time.monotonic() - consent_since >= .15:
                        consent_blocked_verified = True
                        accepted.set()
            thread.join(max(0, until - time.monotonic()))
            self.assertFalse(thread.is_alive())
            self.assertTrue(finished.is_set())
            self.assertEqual([], errors)
            self.assertTrue(consent_blocked_verified)
            self.assertEqual(1, len(requests))
            self.assertEqual(1, len(received))
            result = received[0]
            self.assertEqual('completed', pump.state)
            self.assertTrue(pump.result['peer_completion_verified'])
            self.assertTrue(result['peer_ack_verified'])
            self.assertEqual(2, result['fileCount'])
            self.assertEqual(sum(map(len, payloads.values())), result['totalSize'])
            self.assertEqual(prepared.archive_size, downloaded[-1])
            self.assertEqual((result['totalSize'], result['totalSize']), verified[-1])
            self.assertEqual(2, len(owner.rows))
            self.assertEqual(1, len(archive_resources))
            self.assertIs(archive_handles[0], archive_resources[0].handle)
            self.assertIs(receiver.directory_binding, binding)
            self.assertIs(receiver.local_commit_result, result)
            self.assertTrue(receiver.close(1))
            self.assertTrue(archive_resources[0].handle.closed)
            self.assertTrue(receiver.lifecycle_status()['close_verified'])
            self.assertTrue(pump.close(cleanup_until))
            self.assertTrue(all(row['closed'] for row in owner.rows))
            self.assertEqual(-1, listener.fileno())

            received_registry = FileRegistry(str(target))
            catalog = received_registry.list_files()
            self.assertEqual(2, len(catalog))
            store = FileStore(str(target))
            namespace = Path(result['directory']).name
            self.assertIn(namespace, [row['name'] for row in store.listing('Received')['entries']])
            read_count = 0
            for row in catalog:
                self.assertTrue(row['name'].startswith('Received/' + namespace + '/'))
                expected_path = next(path for path in payloads if row['name'].endswith('/' + path))
                expected = payloads[expected_path]
                handle, stat_value = store.open_file(row['name'])
                with handle:
                    actual = handle.read()
                self.assertEqual(len(expected), stat_value.st_size)
                self.assertEqual(expected, actual)
                self.assertEqual(hashlib.sha256(expected).digest(), hashlib.sha256(actual).digest())
                read_count += 1
            self.assertEqual(2, read_count)
            self.assertFalse(any(path.name.startswith('.mta-') for path in (target / 'Received').iterdir()))
            self.assertTrue(prepared.close(cleanup_until))
            self.assertTrue(prepared.status()['closure_verified'])
            self.assertEqual([], list(private.iterdir()))
            selection.close()
            self.assertTrue(selection.lifecycle_status()['closure_verified'])
            self.assertTrue(registry.lifecycle_status()['closure_verified'])
            store.close()
            store = None
            self.assertTrue(storage.close())
            self.assertTrue(binding.close())
            self.assertTrue(user_binding.close())
            passed = True
        except BaseException as failure:
            primary_error = failure
            raise
        finally:
            accepted.set()
            def cleanup(label, callback):
                try:
                    if callback() is not True:
                        raise AssertionError(label + ' close unknown')
                except BaseException as failure:
                    cleanup_errors.append((label, failure))
            if receiver is not None:
                cleanup('receiver', lambda: receiver.close(1))
            if pump is not None:
                cleanup('pump', lambda: pump.close(cleanup_until))
            elif listener is not None:
                def close_listener():
                    listener.close()
                    return listener.fileno() == -1
                cleanup('listener', close_listener)
            if thread is not None:
                def join_receiver():
                    thread.join(2)
                    return not thread.is_alive()
                cleanup('receiver thread', join_receiver)
            worker_alive = thread is not None and thread.is_alive()
            if store is not None:
                def close_store():
                    store.close()
                    return True
                cleanup('store', close_store)
            if prepared is not None:
                cleanup('preparation', lambda: prepared.close(cleanup_until))
            if selection is not None:
                def close_selection():
                    selection.close()
                    return selection.lifecycle_status()['closure_verified'] is True
                cleanup('selection', close_selection)
            if storage is not None and not worker_alive:
                cleanup('storage', storage.close)
            if binding is not None and not worker_alive:
                cleanup('received binding', binding.close)
            if user_binding is not None and not worker_alive:
                cleanup('user binding', user_binding.close)
            if not cleanup_errors:
                current = os.lstat(base)
                if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                    cleanup_errors.append(('test directory identity', AssertionError('changed')))
                else:
                    # Only this exact newly-created HOST test directory.
                    shutil.rmtree(base)
            if cleanup_errors and primary_error is None:
                raise AssertionError('HOST cleanup unknown; original temp retained: ' +
                    ','.join(label for label, failure in cleanup_errors))
        self.assertTrue(passed)
        print('RESULT=' + json.dumps(dict(passed=True, new_methods=1, old_methods=0,
            actual_prepared_send=True, actual_sender_pump=True, actual_receiver_transport=True,
            actual_tls_connections=2, consent_blocked_download_verified=True,
            actual_linux_directory_fd=True, one_original_archive_handle=True,
            original_binding_borrowed=True, binding_closure_verified=True,
            chinese_file_commit_verified=True, filecenter_read_verified=True,
            local_commit_verified=True, peer_ack_verified=True, socket_file_cleanup_verified=True,
            host_loopback_admission_fixture=True, host_loopback_owner=True,
            device_tested=False, phone_tested=False, rf_requested=False, full_restore_verified=False), sort_keys=True))


if __name__ == '__main__':
    unittest.main()
