"""One affected HOST method: native bound storage, transport boundary fixtures.

Old fixture definitions are reused without running any old test method. Real
Linux directory FDs, ZIP bytes, CRC, fsync and close execute in fresh test trees.
Transport._run_impl executes unchanged except the declared candidate delta;
WSS, connect/check/download and lifecycle are explicit narrow HOST fixtures,
not network, TLS, native Owner, consent UI, device or phone evidence.
"""
import ast
import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
HELPER = 'tests/test_receive_directory_fd.py'
HELPER_PIN = (21074, '218966bbcae1a539e61ec3088f2cdcb96bdc0312cac7b1ce352033e188a9327b')
OLD_STORAGE = 'candidate/receive-directory-fd-v1/runtime/mta_storage.py'
OLD_TRANSPORT = 'candidate/receive-directory-clock-v2/runtime/mta_transport.py'
NEW_STORAGE = 'candidate/receive-durable-result-v1/runtime/mta_storage.py'
NEW_TRANSPORT = 'candidate/receive-durable-result-v1/runtime/mta_transport.py'
DELTA = 'candidate/receive-durable-result-v1/exactsource-delta.json'


def _sources():
    raw = (BASE / HELPER).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != HELPER_PIN:
        raise AssertionError('original fixture definition differs')
    spec = importlib.util.spec_from_file_location('old_storage_fixture_definitions', BASE / HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)  # No unittest.main or old method.
    old_storage = helper._definitions()
    original_import = old_storage.__dict__['__builtins__']['__import__']
    protocol = original_import('mta_protocol')
    modules = {'mta_protocol': protocol}
    imports = builtins.__import__

    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('relative model imports refused')
        if name in modules:
            return modules[name]
        if name.startswith(('mta_', 'p011_')):
            raise ImportError('unlisted project definition')
        return imports(name, globals, locals, fromlist, level)

    def load(name, path):
        value = types.ModuleType(name)
        value.__file__ = str(BASE / path)
        namespace = dict(vars(builtins))
        namespace['__import__'] = fixed_import
        value.__dict__['__builtins__'] = namespace
        raw = (BASE / path).read_bytes()
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        exec(compile(raw, value.__file__, 'exec'), value.__dict__)
        return value

    new_storage = load('mta_storage', NEW_STORAGE)
    modules['mta_storage'] = new_storage
    old_transport = load('old_transport_actual_definitions', OLD_TRANSPORT)
    new_transport = load('new_transport_actual_definitions', NEW_TRANSPORT)
    delta = json.loads((BASE / DELTA).read_bytes())
    for change in delta['changes']:
        original = (BASE / change['original']).read_text(encoding='utf-8')
        actual = (BASE / change['candidate']).read_text(encoding='utf-8')
        forward = original
        for item in change['edits']:
            if forward.count(item['before']) != 1:
                raise AssertionError('one exact delta anchor required')
            forward = forward.replace(item['before'], item['after'], 1)
        if forward != actual:
            raise AssertionError('complete source forward proof differs')
        inverse = actual
        for item in reversed(change['edits']):
            if inverse.count(item['after']) != 1:
                raise AssertionError('one inverse delta anchor required')
            inverse = inverse.replace(item['after'], item['before'], 1)
        if inverse != original:
            raise AssertionError('complete source inverse proof differs')
    return helper, old_storage, new_storage, old_transport, new_transport


def _published(receiver):
    return any(entry['published'] for entry in receiver._bound_entries)


def _saved(case, receiver, task):
    value = receiver.durable_result()
    case.assertEqual(task, value['taskId'])
    case.assertEqual(2, value['fileCount'])
    case.assertEqual(value['totalSize'], sum(Path(path).stat().st_size for path in value['files']))
    case.assertTrue(all(Path(path).is_file() for path in value['files']))
    case.assertFalse(value['peer_ack_verified'])
    case.assertEqual('真实目录绑定\n'.encode('utf-8') * 100, Path(value['files'][0]).read_bytes())
    case.assertEqual(b'\x00\x01\x02' * 100, Path(value['files'][1]).read_bytes())
    return value


def _transport_fixture(case, transport, fixture, receiver, cancelled):
    """Actual run body with fake networking; actual shared download FD/storage."""
    total = len('真实目录绑定\n'.encode('utf-8') * 100) + 300
    request = dict(taskId='current-receive', fileCount=2, totalSize=total,
                   senderName='HOST', fileName='HOST.zip', mimeType='application/zip')
    messages = [transport.WsMessage('action', 0, 'versionNegotiation', {'version': 1}),
                transport.WsMessage('action', 1, 'sendRequest', request),
                transport.WsMessage('ack', 2, 'status', None)]
    sent, connections, closed = [], [], []
    ws = types.SimpleNamespace(receive=lambda: messages.pop(0), send=sent.append)
    owner = transport.ReceiverTransport.__new__(transport.ReceiverTransport)
    owner.host, owner.port = 'HOST-fixture', 1
    owner.receiver, owner.directory_binding = receiver, receiver.directory_binding
    owner.cancelled = cancelled
    owner.local_commit_result = None
    owner._bound_downloads = []
    owner._check = lambda: None
    owner._budget = types.SimpleNamespace(now=lambda: 1.0)
    owner._life = types.SimpleNamespace(close_socket=closed.append)

    def connect():
        value = types.SimpleNamespace(socket=object(), deadline=10.0)
        connections.append(value)
        return value

    def download(stream, actual_request, handle, maximum, progress):
        case.assertIs(stream, connections[1])
        case.assertEqual(request, actual_request)
        case.assertGreaterEqual(maximum, len(fixture.plain_archive().read_bytes()))
        # Fixture's input and retained download are actual files, not HTTP.
        raw = fixture.plain_archive().read_bytes()
        case.assertEqual(len(raw), handle.write(raw))
        handle.flush()
        os.fsync(handle.fileno())

    owner.connect, owner._download_into = connect, download
    return owner, ws, sent, connections, closed


class ReceiveDurableResultV1Tests(unittest.TestCase):
    def test_current_publication_failure_retention(self):
        self.assertEqual('posix', os.name)
        self.assertTrue(sys.platform.startswith('linux'))
        helper, old_storage, storage, old_transport, transport = _sources()
        completed = 0
        # Original defect, reproduced without re-running the earlier suite.
        with self.subTest(domain='old_late_cancel_counterexample'):
            with helper._Fixture(self, old_storage) as f:
                receiver = f.receiver(f.binding())
                with self.assertRaises(old_storage.TransferCancelled) as caught:
                    receiver.receive(str(f.plain_archive()), 'old-late',
                                     cancelled=lambda: _published(receiver))
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertFalse(receiver._bound_complete)
                self.assertTrue(_published(receiver))
                self.assertEqual(2, sum(p.is_file() for p in f.root.glob('received-*/**/*')))
                self.assertFalse(hasattr(receiver, 'durable_result'))
            completed += 1
        with self.subTest(domain='new_late_cancel_retained'):
            with helper._Fixture(self, storage) as f:
                receiver = f.receiver(f.binding())
                with self.assertRaises(storage.TransferCancelled) as caught:
                    receiver.receive(str(f.plain_archive()), 'new-late',
                                     cancelled=lambda: _published(receiver))
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertFalse(receiver._bound_complete)
                _saved(self, receiver, 'new-late')
                self.assertIs(receiver.close(), True)
                self.assertFalse(receiver.lifecycle_status()['resource_pending'])
            completed += 1
        with self.subTest(domain='normal_and_copy_isolation'):
            with helper._Fixture(self, storage) as f:
                receiver = f.receiver(f.binding())
                result = receiver.receive(str(f.plain_archive()), 'normal')
                saved = _saved(self, receiver, 'normal')
                self.assertEqual(set(result), {'taskId', 'directory', 'files', 'fileCount', 'totalSize'})
                self.assertEqual(result, {k: v for k, v in saved.items() if k != 'peer_ack_verified'})
                self.assertTrue(receiver._bound_complete)
                saved['files'].clear()
                saved['taskId'], saved['peer_ack_verified'] = 'foreign', True
                _saved(self, receiver, 'normal')
            completed += 1
        with self.subTest(domain='early_cancel_no_publication'):
            with helper._Fixture(self, storage) as f:
                receiver = f.receiver(f.binding())
                with self.assertRaises(storage.TransferCancelled):
                    receiver.receive(str(f.plain_archive()), 'early', cancelled=lambda: True)
                self.assertIsNone(receiver.durable_result())
                self.assertFalse(_published(receiver))
                self.assertFalse(list(f.root.glob('received-*')))
            completed += 1
        with self.subTest(domain='late_binding_failure_retained'):
            with helper._Fixture(self, storage) as f:
                binding = f.binding()
                receiver = f.receiver(binding)
                check = binding.check
                failure = storage.StorageError('HOST late binding failure fixture')

                def fail_after_publication():
                    if _published(receiver):
                        raise failure
                    return check()

                with mock.patch.object(binding, 'check', fail_after_publication):
                    with self.assertRaises(storage.StorageError) as caught:
                        receiver.receive(str(f.plain_archive()), 'binding-late')
                self.assertIs(failure, caught.exception)
                self.assertIs(receiver._bound_failure, failure)
                self.assertFalse(receiver._bound_complete)
                _saved(self, receiver, 'binding-late')
            completed += 1
        with self.subTest(domain='post_publication_close_refusal_fixture'):
            with helper._Fixture(self, storage) as f:
                receiver = f.receiver(f.binding())
                original_close = storage._close_original
                refused = []

                def close(row):
                    if _published(receiver) and not row['closed'] and not refused:
                        refused.append(row)
                        return False  # Narrow refusal fixture, not an OS EIO claim.
                    return original_close(row)

                with mock.patch.object(storage, '_close_original', close):
                    with self.assertRaises(storage.StorageError) as caught:
                        receiver.receive(str(f.plain_archive()), 'close-late')
                self.assertEqual(1, len(refused))
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertFalse(receiver._bound_complete)
                _saved(self, receiver, 'close-late')
            completed += 1
        with self.subTest(domain='transport_old_new_late_cancel'):
            for actual, retained in ((old_transport, False), (transport, True)):
                with helper._Fixture(self, storage) as f:
                    receiver = f.receiver(f.binding())
                    owner, ws, sent, connections, closed = _transport_fixture(
                        self, actual, f, receiver, lambda: _published(receiver))
                    with mock.patch.object(actual, 'websocket_client', return_value=ws):
                        with self.assertRaises(storage.TransferCancelled) as caught:
                            actual.ReceiverTransport._run_impl(owner, lambda request: True)
                    self.assertIs(receiver._bound_failure, caught.exception)
                    self.assertEqual(2, len(connections))
                    self.assertEqual([row.socket for row in connections], closed)
                    self.assertEqual(2, len(sent))  # Only version + request ACK, no completion.
                    self.assertTrue(all(message.msg_type == 'ack' for message in sent))
                    if retained:
                        self.assertEqual(_saved(self, receiver, 'current-receive'), owner.local_commit_result)
                    else:
                        self.assertIsNone(owner.local_commit_result)
            completed += 1
        with self.subTest(domain='transport_normal_result_unchanged'):
            outcomes = []
            for actual in (old_transport, transport):
                with helper._Fixture(self, storage) as f:
                    receiver = f.receiver(f.binding())
                    owner, ws, sent, connections, closed = _transport_fixture(
                        self, actual, f, receiver, lambda: False)
                    with mock.patch.object(actual, 'websocket_client', return_value=ws):
                        result = actual.ReceiverTransport._run_impl(owner, lambda request: True)
                    self.assertIs(result, owner.local_commit_result)
                    self.assertTrue(result['peer_ack_verified'])  # Explicit fake WS ACK only.
                    self.assertFalse(receiver.durable_result()['peer_ack_verified'])
                    self.assertEqual([row.socket for row in connections], closed)
                    outcomes.append((result['fileCount'], result['totalSize'], result['peer_ack_verified'],
                                     [message.name for message in sent]))
            self.assertEqual(outcomes[0], outcomes[1])
            completed += 1
        with self.subTest(domain='prior_publication_not_adopted'):
            with helper._Fixture(self, storage) as f:
                receiver = f.receiver(f.binding())
                receiver.receive(str(f.plain_archive()), 'prior-receive')
                owner, ws, sent, connections, closed = _transport_fixture(self, transport, f, receiver, lambda: False)
                with mock.patch.object(transport, 'websocket_client', return_value=ws):
                    with self.assertRaises(storage.StorageError):
                        transport.ReceiverTransport._run_impl(owner, lambda request: True)
                self.assertIsNone(owner.local_commit_result)
                _saved(self, receiver, 'prior-receive')
                self.assertEqual(2, len(sent))
            completed += 1
        with self.subTest(domain='transport_early_cancel_no_saved_fact'):
            with helper._Fixture(self, storage) as f:
                receiver = f.receiver(f.binding())
                owner, ws, sent, connections, closed = _transport_fixture(self, transport, f, receiver, lambda: True)
                with mock.patch.object(transport, 'websocket_client', return_value=ws):
                    with self.assertRaises(storage.TransferCancelled):
                        transport.ReceiverTransport._run_impl(owner, lambda request: True)
                self.assertIsNone(owner.local_commit_result)
                self.assertIsNone(receiver.durable_result())
                self.assertEqual(2, len(sent))
            completed += 1
        with self.subTest(domain='replacement_receiver_not_adopted'):
            with helper._Fixture(self, storage) as f:
                binding = f.binding()
                prior = f.receiver(binding)
                prior.receive(str(f.plain_archive()), 'current-receive')
                receiver = f.receiver(binding)
                owner, ws, sent, connections, closed = _transport_fixture(self, transport, f, receiver, None)

                def replace_after_publication():
                    if _published(receiver):
                        owner.receiver = prior
                        return True
                    return False

                owner.cancelled = replace_after_publication
                with mock.patch.object(transport, 'websocket_client', return_value=ws):
                    with self.assertRaises(storage.TransferCancelled) as caught:
                        transport.ReceiverTransport._run_impl(owner, lambda request: True)
                self.assertIs(receiver._bound_failure, caught.exception)
                self.assertIsNone(owner.local_commit_result)
                current, old = _saved(self, receiver, 'current-receive'), _saved(self, prior, 'current-receive')
                self.assertNotEqual(current['directory'], old['directory'])
                self.assertEqual(2, len(sent))
            completed += 1
        self.assertEqual(11, completed)
        print('RESULT=' + json.dumps(dict(passed=True, methods=1, domains=11, old_methods=0,
            old_late_cancel_counterexample=True, native_storage_syscalls=True,
            transport_run_body=True, fake_network_boundary=True,
            original_exceptions_preserved=True, prior_publication_not_adopted=True,
            replacement_receiver_not_adopted=True,
            late_failure_not_completed=True, real_peer_ack_verified=False,
            closure_fixture_not_native_fault=True, state_factory_executed=False,
            ipc_ui_connected=False, actual_selected_graph_unchanged=True,
            device=False, phone=False, network=False, rf=False), sort_keys=True))


if __name__ == '__main__':
    unittest.main()
