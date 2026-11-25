"""New HOST integration: real sender pump -> receiver -> Received -> FileStore.

No old test method is run. Reuse the existing HOST loopback socket owner, not
its hand-written peer. Only the constructor's private-IP admission is a HOST
fixture; protocol, TLS, consent wait, ZIP, commit, ACK and file reads are real.
This does not admit State/F or certify P011/phone/RF/network restoration.
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
from mta_files import FileRegistry
from mta_storage import SafeZipReceiver
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
OPENSSL = str(Path(r'C:\Program Files\Git\mingw64\bin\openssl.exe'))


class ReceiveFileCenterIntegrationTests(unittest.TestCase):
    def test_real_pump_receive_consent_chinese_commit_filecenter_ack(self):
        base = Path(tempfile.mkdtemp(prefix='mta-receive-filecenter-host-'))
        original = os.lstat(base)
        until = float(time.monotonic() + 30.0)
        cleanup_until = until + 5.0
        source = base / 'source'
        target = base / 'target'
        private = base / 'private'
        (source / 'Text').mkdir(parents=True)
        (source / 'GameResources').mkdir()
        (target / 'Received').mkdir(parents=True)
        private.mkdir()
        payloads = {'Text/接收验证.txt': '真实中文文件，确认后接收。\n'.encode('utf-8') * 500,
                    'GameResources/check.bin': os.urandom(1048576)}
        for path, data in payloads.items():
            (source / path).write_bytes(data)
        registry = FileRegistry(str(source))
        selection = registry.open_selection([row['id'] for row in registry.list_files()])
        prepared = PreparedSend(selection, OPENSSL, 'host-real-receive', 'hostsender', until, str(private))
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
        try:
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
                        SafeZipReceiver(str(target / 'Received'), reserve_bytes=0), timeout=30)

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
                self.assertLess(time.monotonic(), until)
                pump.step(max_wait=.01)
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
            self.assertTrue(receiver.close(1))
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
            passed = True
        finally:
            accepted.set()
            if receiver is not None:
                receiver.close(1)
            if thread is not None:
                thread.join(2)
                if thread.is_alive():
                    raise AssertionError('Actual receiver worker remains; HOST private inputs retained')
            if pump is not None:
                pump.close(cleanup_until)
            elif listener is not None:
                listener.close()
            if store is not None:
                store.close()
            prepared.close(cleanup_until)
            selection.close()
            current = os.lstat(base)
            self.assertEqual((original.st_dev, original.st_ino), (current.st_dev, current.st_ino))
            # Only this exact newly-created HOST test directory, never user data.
            shutil.rmtree(base)
        self.assertTrue(passed)
        print('RESULT=' + json.dumps(dict(passed=True, new_methods=1, old_methods=0,
            actual_prepared_send=True, actual_sender_pump=True, actual_receiver_transport=True,
            actual_tls_connections=2, consent_blocked_download_verified=True,
            chinese_file_commit_verified=True, filecenter_read_verified=True,
            local_commit_verified=True, peer_ack_verified=True, socket_file_cleanup_verified=True,
            host_loopback_admission_fixture=True, host_loopback_owner=True,
            device_tested=False, phone_tested=False, rf_requested=False, full_restore_verified=False), sort_keys=True))


if __name__ == '__main__':
    unittest.main()
