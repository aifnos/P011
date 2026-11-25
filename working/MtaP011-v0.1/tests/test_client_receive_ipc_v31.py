"""Four new HOST typed-IPC methods only; no lifecycle/native/device approval.

Only the frozen JSON/protocol/codec/F class definitions are loaded, lazily in
setUp. No older TestCase, F.run, DeploymentLoader.load/authenticate, Parent.start,
wait/reap, Provider, DHCP, RF, socket, filesystem receive or device code runs.
Parent collaborators below explicitly model an already-admitted process/pipe
and CONNECT slot. They do not prove a real loader, actor, child or BLE handoff.
All I/O uses in-memory fictional FIFO metadata. Truth/falsehood here concerns
typed file consent and private receive frames, never network permission,
restoration, data transfer, phone compatibility or P011 acceptance.

This source is prepared without executing it. Root owns the sole first run.
"""
import builtins
import hashlib
import json as host_json
from pathlib import Path
import stat
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
MANIFEST = 'host/client_transfer_executor_v31_source_manifest.json'
MANIFEST_SHA = '35e6f1ba210f9fbd476f866c35e66b01c8d707dea017beae067c6f75d4b2fc9a'
SOURCES = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_client_control_frame', 'candidate/client-transfer-executor-v31/runtime/mta_client_control_frame.py',
     '3cf4a9106389d9865ff77fed9f46c534288ce20df6841909b21eaa15f5bf1434'),
    ('mta_client_executor', 'candidate/client-transfer-executor-v31/runtime/mta_client_executor.py',
     'f499f897a15b8c4e26e9a30fb093f5632bcdc800af97397a473f0afcd3467682'),
)


def definitions():
    """Use root's frozen 35-source map; execute only four IPC definitions."""
    manifest_raw = (BASE / MANIFEST).read_bytes()
    if len(manifest_raw) != 8081 or hashlib.sha256(manifest_raw).hexdigest() != MANIFEST_SHA:
        raise ValueError('HOST IPC frozen source map changed')
    tree = host_json.loads(manifest_raw.decode('utf-8'))
    if tree.get('schema') != 'client-transfer-executor-v31-host' or type(tree.get('sources')) is not list:
        raise ValueError('HOST IPC source map schema changed')
    rows = tree['sources']
    if len(rows) != 35 or len({row['module'] for row in rows}) != 35:
        raise ValueError('HOST IPC source map graph changed')
    source = {}
    for row in rows:
        raw = (BASE / row['path']).read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('HOST IPC frozen mapped source changed')
        source[row['module']] = raw
    mapped = {row['module']: row for row in rows}
    modules, original = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('HOST IPC definition absent')
            return modules[name]
        return original(name, *args, **kwargs)
    for name, relative, pin in SOURCES:
        raw = source[name]
        if mapped[name]['path'] != relative or mapped[name]['sha256'] != pin:
            raise ValueError('HOST IPC frozen source changed')
        module = types.ModuleType('host_typed_ipc_v31_' + name)
        module.__file__ = str(BASE / relative)
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(raw, module.__dict__)
    if tuple(row['module'] for row in rows) != modules['mta_client_executor'].MODULES:
        raise ValueError('HOST IPC F/source-map order changed')
    return modules


def binding_fields():
    return {'version': 1, 'run_token': 'a' * 32, 'candidate_sha': 'b' * 64,
        'operation_id': 'HOST-local-operation', 'native_epoch': 8,
        'operation_epoch': 9, 'gatt_session': 12, 'nonce': 'c' * 32,
        'receive_consent': True}


def request_fields():
    return {'taskId': 'HOST-receive-task', 'fileCount': 1, 'totalSize': 8,
        'senderName': 'HOST synthetic sender', 'fileName': 'HOST-fixture.bin',
        'mimeType': 'application/octet-stream'}


class HostClock(object):
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class HostPipe(object):
    def __init__(self, fd): self.fd = fd
    def fileno(self): return self.fd
    def close(self): raise AssertionError('HOST IPC must not close/reap a process pipe')


def fifo_metadata(fd):
    return types.SimpleNamespace(st_dev=1, st_ino=1000 + fd,
        st_mode=stat.S_IFIFO | 0o600, st_uid=0, st_gid=0, st_nlink=1, st_size=0)


class HostPipeIo(object):
    """Fictional admitted Parent pipes only; no actual descriptor or process."""
    def __init__(self, clock):
        self.clock, self.buffers, self.writes = clock, {}, []
        self.short_write, self.advance_write = False, 0.0
        self.metadata = {fd: fifo_metadata(fd) for fd in (10, 11, 12)}
    def fstat(self, fd): return self.metadata[fd]
    def ready(self, fds, seconds):
        self.clock.value += seconds
        return [fd for fd in fds if self.buffers.get(fd)]
    def read(self, fd, count):
        chunk = self.buffers[fd].pop(0)
        if len(chunk) > count:
            self.buffers[fd].insert(0, chunk[count:]); chunk = chunk[:count]
        return chunk
    def write(self, fd, data):
        self.writes.append((fd, data)); self.clock.value += self.advance_write
        return len(data) - 1 if self.short_write else len(data)


class HostDeploymentCollaborator(object):
    """Identity collaborator, deliberately NOT native DeploymentLoader proof."""
    def __init__(self): self.value, self.calls = None, 0
    def authenticate(self, value):
        self.calls += 1
        if value is not self.value: raise ValueError('HOST deployment identity changed')


class ReceiveIpcV31Tests(unittest.TestCase):
    def setUp(self):
        self.modules = definitions()
        self.codec = self.modules['mta_client_control_frame']
        self.f = self.modules['mta_client_executor']
        self.protocol, self.json = self.modules['mta_protocol'], self.modules['p011_json']
        # Guard the omitted layers rather than accidentally executing a default
        # native path. Definitions already loaded; no lifecycle is permitted.
        for name in ('validate', 'stat', 'readlink', 'open', 'read', 'write',
                     'fstat', 'close', 'ready', 'ready_write', 'pipe_buf', 'popen'):
            patcher = mock.patch.object(self.f._LinuxIo, name,
                side_effect=AssertionError('actual Linux I/O forbidden in HOST typed IPC'))
            patcher.start(); self.addCleanup(patcher.stop)
        for target in ('subprocess.Popen', 'socket.socket', 'os.fork', 'os.kill', 'os.waitpid'):
            patcher = mock.patch(target, side_effect=AssertionError('actual process/network forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for cls, name in ((self.f.ClientExecutor, 'run'), (self.f.DeploymentLoader, 'load'),
                          (self.f.DeploymentLoader, 'authenticate'), (self.f.ParentExecutor, 'start'),
                          (self.f.ParentExecutor, 'send_connect'), (self.f.ParentExecutor, 'finish')):
            patcher = mock.patch.object(cls, name,
                side_effect=AssertionError('lifecycle/loader authority is outside HOST typed IPC'))
            patcher.start(); self.addCleanup(patcher.stop)

    def decoder(self):
        binding = self.codec.ControlBinding(binding_fields())
        decoder = self.codec.ControlFrameDecoder(binding)
        info = self.protocol.P2pInfo('HOST-Synthetic', 'HOST-synthetic-secret',
            '02:11:22:33:44:55', 3345, sender_id='HOST-remote-p2p')
        decoder.feed(self.codec.encode_connect(binding, info))
        original = decoder.take_connect()
        self.assertIs(type(original), self.codec.ConnectRequest)
        prompt = decoder.expect_receive(request_fields(), 110.0)
        return binding, decoder, original, prompt

    def parent(self):
        clock = HostClock(); io = HostPipeIo(clock)
        checker = HostDeploymentCollaborator()
        binding = self.codec.ControlBinding(binding_fields())
        pm = types.SimpleNamespace(run_token=binding_fields()['run_token'],
            candidate_sha=binding_fields()['candidate_sha'])
        dep = self.f.LoadedDeployment(checker, self.modules, pm, 'd' * 64,
            self.f.ROOT + '/client-' + pm.run_token, binding, self.f.RECEIVE_ROOT, ())
        checker.value = dep
        value = self.f.ParentExecutor(dep, _io=io, _clock=clock)
        # Explicit HOST admitted-state collaborators. Neither start, CONNECT
        # handoff, Loader, actor verification nor process execution is claimed.
        value.process = object(); value.spawn_ticket = {'unknown': False}
        value.actor = object(); value.pending = True
        value.pipes = [{'pipe': HostPipe(fd), 'fd': fd,
            'metadata': self.f._meta(io.fstat(fd)), 'unknown': False,
            'attempted': False, 'closed': False} for fd in (10, 11, 12)]
        value.connect_ticket = {'sent': True, 'unknown': False}
        value._connect_worker = threading.current_thread()
        value.frames = [self.f._public(ready=True)]
        unused_binding, unused_decoder, unused_request, original_prompt = self.decoder()
        prompt_data = original_prompt.private_data()
        wire = self.codec.encode_receive_event(binding, 0, 'prompt', prompt_data)
        return value, io, clock, binding, wire

    def feed_parent(self, parent, io, wire):
        io.buffers.setdefault(11, []).append(wire)
        while io.buffers.get(11): parent.poll()

    def decision_data(self, wire):
        return self.json.loads(wire[len(self.codec.RECEIVE_PREFIX):-1].decode('ascii'))

    def raw_decision(self, value):
        return self.codec.RECEIVE_PREFIX + self.json.dumps(value,
            ensure_ascii=True, sort_keys=True).encode('ascii') + b'\n'

    def test_codec_canonical_once_true_false_cancel_eof_and_wrong_original(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                binding, decoder, original, prompt = self.decoder()
                frame = self.codec.encode_receive_decision(binding, prompt, accepted)
                self.assertLessEqual(len(frame), self.codec.MAX_DECISION)
                self.assertTrue(all(byte < 128 for byte in frame))
                middle = len(frame) // 2
                decoder.feed(frame[:middle]); self.assertIsNone(decoder.take_receive_decision())
                decoder.feed(frame[middle:])
                decision = decoder.take_receive_decision()
                self.assertIs(type(decision), self.codec.ReceiveDecision)
                self.assertIs(decision._decoder, decoder); self.assertIs(decision.prompt, prompt)
                self.assertIs(decision.accepted, accepted); self.assertFalse(original.cancelled)
                self.assertIsNone(decoder.take_receive_decision())
                with self.assertRaises(self.codec.ControlFrameError): decoder.feed(frame)
                self.assertTrue(original.cancelled)
                with self.assertRaises(AttributeError): decision.accepted = not accepted
        for mode in ('cancel_before', 'cancel_after', 'bad_cancel', 'eof'):
            with self.subTest(priority=mode):
                binding, decoder, original, prompt = self.decoder()
                frame = self.codec.encode_receive_decision(binding, prompt, True)
                data = {'cancel_before': self.codec.CANCEL + frame,
                    'cancel_after': frame + self.codec.CANCEL,
                    'bad_cancel': b'NOT-A-COMMAND\n' + self.codec.CANCEL,
                    'eof': frame}[mode]
                decoder.feed(data, eof=mode == 'eof')
                self.assertTrue(original.cancelled); self.assertIsNone(decoder.take_receive_decision())
                self.assertEqual(decoder.status()['reason'], 'eof' if mode == 'eof' else 'cancelled')
        for key, value in (('task_id', 'HOST-other-task'), ('prompt_id', 'f' * 32),
                           ('binding_sha256', 'e' * 64), ('accepted', 1)):
            with self.subTest(wrong=key):
                binding, decoder, original, prompt = self.decoder()
                data = self.decision_data(self.codec.encode_receive_decision(binding, prompt, True))
                if key != 'accepted': self.assertNotEqual(data[key], value)
                data[key] = value
                with self.assertRaises(self.codec.ControlFrameError): decoder.feed(self.raw_decision(data))
                self.assertTrue(original.cancelled); self.assertIsNone(decoder.take_receive_decision())
        binding, decoder, original, prompt = self.decoder()
        frame = self.codec.encode_receive_decision(binding, prompt, True)
        with self.assertRaises(self.codec.ControlFrameError): decoder.feed(frame.replace(b'RECEIVE {', b'RECEIVE { '))
        self.assertTrue(original.cancelled)

    def test_parent_original_prompt_true_false_short_write_and_original_deadline(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                parent, io, clock, binding, wire = self.parent()
                self.feed_parent(parent, io, wire)
                prompt = parent.receive_status()['prompt']; original_until = prompt.until
                clone = self.codec.ReceivePrompt(binding, prompt.private_data())
                with self.assertRaises(self.f.ExecutorError): parent.answer_receive(clone, accepted)
                self.assertEqual(io.writes, [])
                clock.value = 105.0
                status = parent.answer_receive(prompt, accepted)
                self.assertEqual(status['state'], 'accepted' if accepted else 'refused_pending')
                self.assertTrue(parent.receive_reply_ticket['sent'])
                self.assertFalse(parent.receive_reply_ticket['unknown']); self.assertEqual(len(io.writes), 1)
                self.assertEqual(io.writes[0], (10, self.codec.encode_receive_decision(binding, prompt, accepted)))
                self.assertEqual(prompt.until, original_until)
                clock.value = 109.0
                with self.assertRaises(self.f.ExecutorError): parent.answer_receive(prompt, accepted)
                self.assertEqual(len(io.writes), 1); self.assertEqual(prompt.until, original_until)
        for failure in ('short', 'late_write', 'expired_before_write'):
            with self.subTest(failure=failure):
                parent, io, clock, unused, wire = self.parent(); self.feed_parent(parent, io, wire)
                prompt = parent.receive_prompt; until = prompt.until
                if failure == 'short': io.short_write = True
                elif failure == 'late_write': io.advance_write = 11.0
                else: clock.value = until
                if failure == 'expired_before_write':
                    with self.assertRaises(self.f.ExecutorError): parent.answer_receive(prompt, True)
                    self.assertIsNone(parent.receive_reply_ticket); self.assertEqual(io.writes, [])
                else:
                    parent.answer_receive(prompt, True)
                    self.assertTrue(parent.receive_reply_ticket['unknown'])
                    self.assertFalse(parent.receive_reply_ticket['sent']); self.assertEqual(len(io.writes), 1)
                    self.assertTrue(parent.failures)
                    with self.assertRaises(self.f.ExecutorError): parent.answer_receive(prompt, True)
                    self.assertEqual(len(io.writes), 1)
                self.assertEqual(prompt.until, until)

    def test_parent_wrong_binding_sequence_task_replay_and_no_restore_proof(self):
        for wrong in ('binding', 'sequence', 'task', 'replay'):
            with self.subTest(wrong=wrong):
                parent, io, clock, binding, prompt_wire = self.parent()
                if wrong == 'binding':
                    data = self.json.loads(prompt_wire[len(self.codec.RX_PREFIX):-1].decode('ascii'))
                    data['binding_sha256'] = 'f' * 64
                    wire = self.codec.RX_PREFIX + self.json.dumps(data, sort_keys=True).encode('ascii') + b'\n'
                else:
                    self.feed_parent(parent, io, prompt_wire); parent.answer_receive(parent.receive_prompt, True)
                    if wrong == 'replay': wire = prompt_wire
                    else:
                        payload = {'task_id': parent.receive_prompt.task_id, 'stage': 'files', 'count': 4, 'total': 8}
                        if wrong == 'task': payload['task_id'] = 'HOST-other-task'
                        wire = self.codec.encode_receive_event(binding, 3 if wrong == 'sequence' else 1,
                            'progress', payload)
                self.feed_parent(parent, io, wire)
                self.assertTrue(parent.failures); self.assertEqual(parent.reason, 'frame_invalid')
                self.assertTrue(parent.pending); self.assertFalse(parent.reaped); self.assertFalse(parent.absent)
                self.assertEqual(len(parent.frames), 1)
                status = parent.status()
                for key in ('done', 'parent_waited', 'parent_absence_verified', 'parent_resources_closed',
                            'send_available', 'receive_available', 'association_verified', 'ip_ready', 'phone_tested'):
                    self.assertIs(status[key], False)

    def test_parent_fragmented_private_progress_result_and_refusal_preserve_public_flags(self):
        parent, io, clock, binding, prompt_wire = self.parent()
        self.feed_parent(parent, io, prompt_wire[:5]); self.assertIsNone(parent.receive_prompt)
        self.feed_parent(parent, io, prompt_wire[5:]); parent.answer_receive(parent.receive_prompt, True)
        task = parent.receive_prompt.task_id
        frames = [self.codec.encode_receive_event(binding, 1, 'progress',
            {'task_id': task, 'stage': 'download', 'count': 40, 'total': 0}),
            self.codec.encode_receive_event(binding, 2, 'progress',
            {'task_id': task, 'stage': 'files', 'count': 8, 'total': 8}),
            self.codec.encode_receive_event(binding, 3, 'result',
            {'outcome': 'committed', 'task_id': task, 'file_count': 1, 'total_size': 8,
             'peer_ack_verified': True})]
        self.feed_parent(parent, io, b''.join(frames))
        status = parent.receive_status()
        self.assertEqual(status['state'], 'committed'); self.assertEqual(status['download_bytes'], 40)
        self.assertEqual(status['verified_file_bytes'], 8); self.assertTrue(status['result']['peer_ack_verified'])
        self.assertEqual(len(parent.receive_events), 4); self.assertEqual(len(parent.frames), 1)
        self.assertFalse(parent.failures); self.assertEqual(parent.buffers[1], b'')
        for key in ('done', 'parent_waited', 'parent_absence_verified', 'parent_resources_closed',
                    'send_available', 'receive_available', 'association_verified', 'ip_ready', 'phone_tested'):
            self.assertIs(parent.status()[key], False)
        self.assertNotIn(request_fields()['senderName'], repr(parent.status()))
        self.assertNotIn(request_fields()['fileName'], repr(parent.status()))
        parent, io, clock, binding, prompt_wire = self.parent()
        self.feed_parent(parent, io, prompt_wire); parent.answer_receive(parent.receive_prompt, False)
        self.feed_parent(parent, io, self.codec.encode_receive_event(binding, 1, 'result',
            {'outcome': 'refused', 'task_id': parent.receive_prompt.task_id,
             'file_count': 0, 'total_size': 0, 'peer_ack_verified': False}))
        self.assertEqual(parent.receive_status()['state'], 'refused'); self.assertFalse(parent.failures)
        self.assertEqual(len(io.writes), 1); self.assertFalse(parent.status()['done'])


if __name__ == '__main__': unittest.main()
