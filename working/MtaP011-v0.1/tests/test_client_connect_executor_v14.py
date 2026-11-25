"""Only new v14 methods: real candidate code over FakeIO, no platform calls."""
import ast
import errno
import hashlib
import importlib.util
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'runtime'))
sys.path.insert(0, str(BASE / 'tests'))
SOURCE = BASE / 'candidate/client-connect-v14/runtime/mta_client_executor.py'
CODEC = BASE / 'candidate/client-connect-v13/runtime/mta_client_control_frame.py'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

with mock.patch.dict(sys.modules):
    f = load('connect_v14_executor', SOURCE)
    codec = load('connect_v14_codec', CODEC)
    sys.modules['mta_client_executor'] = f
    ff = load('connect_v14_fixture', BASE / 'tests/test_client_executor.py')

protocol, json = codec.protocol, codec.json

def fields():
    return {'version': 1, 'run_token': ff.TOKEN, 'candidate_sha': 'c' * 64,
        'operation_id': 'local-operation', 'native_epoch': 8, 'operation_epoch': 8,
        'gatt_session': 12, 'nonce': 'd' * 32, 'receive_consent': True}

def info():
    return protocol.P2pInfo('Synthetic-Test', 'synthetic-secret', '02:11:22:33:44:55',
        3345, sender_id='remote-task')

class Control(ff.Control):
    def take_connect(self): return None

class ConnectionObservation(object):
    """HOST fixture only; no kernel/association authorization."""
    def __repr__(self): return '<private fixture connection observation>'

class Handoff(object):
    """Explicit HOST private issuer fixture; not native/helper authorization."""
    def __init__(self):
        self.worker = threading.current_thread()
        self.state = types.SimpleNamespace(lock=threading.RLock())
        self.operation = object()
        self.binding = None
        self.claims, self.checks = 0, 0
        self.invalid, self.after_claim, self.changed = False, False, False
    def _check(self):
        self.checks += 1
        if self.invalid or self.after_claim and self.claims: raise RuntimeError('private cancellation fixture')
    def claim_frame(self, used_codec, token, candidate, operation):
        self.claims += 1
        metadata = fields()
        metadata.update(run_token=token, candidate_sha=candidate, operation_id=operation)
        if self.changed: metadata['nonce'] = 'e' * 32
        self.binding = used_codec.ControlBinding(metadata)
        return used_codec.encode_connect(self.binding, info())

class Tests(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen', 'socket.socket', 'ctypes.CDLL'):
            patcher = mock.patch(target, side_effect=AssertionError('actual OS forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('fork', 'kill', 'waitpid', 'execve'):
            patcher = mock.patch('os.' + name, side_effect=AssertionError('actual process forbidden'), create=True)
            patcher.start(); self.addCleanup(patcher.stop)
        for name in ('validate', 'open', 'read', 'write', 'close', 'popen', 'ready', 'fstat', 'stat'):
            patcher = mock.patch.object(f._LinuxIo, name, side_effect=AssertionError('actual IO forbidden'))
            patcher.start(); self.addCleanup(patcher.stop)
        self.clock, self.io = ff.Clock(), None
        self.io = ff.FakeIo(self.clock)

    def dep(self):
        value, state = ff.deployment(self.io)
        value.manifest.candidate_sha = fields()['candidate_sha']
        value.connect_binding = codec.ControlBinding(fields())
        value.modules['mta_client_control_frame'] = codec
        value.modules['mta_client_connection'] = types.SimpleNamespace(ConnectionObservation=ConnectionObservation)
        state.connections = []
        original = value.modules['mta_client_linux_provider'].assemble
        def assemble(manifest):
            values = original(manifest)
            def connect(p2p, _checkpoint):
                state.connections.append((p2p, _checkpoint, _checkpoint()))
                return ConnectionObservation()
            values[4].connect_p2p = connect
            return values
        value.modules['mta_client_linux_provider'].assemble = assemble
        return value, state

    def child(self, input=None):
        value, state = self.dep()
        child = f.ClientExecutor(value, self.io, self.clock, input,
            _environ={'P011_CLIENT_EXECUTABLE_FD': '60'})
        return child, value, state

    def parent(self, handoff=None):
        value, state = self.dep()
        parent = f.ParentExecutor(value, self.io, self.clock,
            _handoff=handoff, _handoff_type=type(handoff) if handoff is not None else None,
            _handoff_codec=codec if handoff is not None else None)
        parent.start()
        self.io.buffers[parent.pipes[1]['fd']] = [f.PREFIX + json.dumps(f._public(ready=True), sort_keys=True).encode('ascii') + b'\n']
        parent.poll()
        return parent, value, state

    def source_fixture(self, change=None):
        run = f.ROOT + '/client-' + ff.TOKEN
        sources = {name: b'value=1\n' for name in f.MODULES}
        sources['p011_json'] = (BASE / 'runtime/p011_json.py').read_bytes()
        sources['mta_protocol'] = (BASE / 'runtime/mta_protocol.py').read_bytes()
        sources['mta_client_control_frame'] = CODEC.read_bytes()
        sources['mta_client_connection'] = b'import mta_protocol\nimport mta_p2p_client_ctrl\n'
        sources['mta_client_linux_provider'] = b'''import mta_client_connection
class ProviderManifest(object):
    def __init__(self, value, _manifest_sha256=None):
        for key,item in value.items(): setattr(self,key,item)
        self.manifest_sha256=_manifest_sha256
'''
        tree = {'version': 2, 'connect_binding': fields(), 'provider': {
            'run_token': ff.TOKEN, 'candidate_sha': fields()['candidate_sha'],
            'python_exe': '/usr/bin/python-fixture',
            'python_sha': hashlib.sha256(self.io.files['/usr/bin/python-fixture'][0]).hexdigest(),
            'wpa_exe': f.PHYSICAL_ROOT + '/client-' + ff.TOKEN + '/native/mta-wpa-supplicant',
            'wpa_sha': hashlib.sha256(b'\x7fELFwpa').hexdigest(),
            'executor_path': run + '/runtime/mta_client_executor.py',
            'executor_sha': hashlib.sha256(sources['mta_client_executor']).hexdigest()},
            'sources': [[name, hashlib.sha256(sources[name]).hexdigest()] for name in f.MODULES]}
        if change is not None: change(tree)
        for name, raw in sources.items(): self.io.add(run + '/runtime/' + name + '.py', raw)
        self.io.add(tree['provider']['wpa_exe'], b'\x7fELFwpa', 0o500)
        original_stat = self.io.stat
        links = {'/tmp': '/var/tmp', '/var/tmp': '/var/volatile/tmp'}
        def stat_at(path):
            if path.startswith(f.ROOT + '/'):
                physical = f.PHYSICAL_ROOT + path[len(f.ROOT):]
                if physical in self.io.files: return self.io.files[physical][1]
            if path in links:
                row = ff.metadata(0o120777, len(links[path]), ino=hash(path) & 0xffff)
                row.st_mtime_ns = row.st_ctime_ns = 100
                return row
            if path in ('/var/volatile', '/var/volatile/tmp'):
                return ff.metadata(0o041777, ino=hash(path) & 0xffff)
            if path == f.PHYSICAL_ROOT or path.startswith(f.PHYSICAL_ROOT + '/'):
                logical = f.ROOT + path[len(f.PHYSICAL_ROOT):]
                if path in self.io.files: return self.io.files[path][1]
                return original_stat(logical)
            return original_stat(path)
        self.io.stat, self.io.readlink = stat_at, lambda path: links[path]
        raw = json.dumps(tree, sort_keys=True).encode('ascii')
        self.io.add(run + '/deployment.json', raw)
        return f.DeploymentLoader(ff.TOKEN, hashlib.sha256(raw).hexdigest(), self.io, self.clock)

    def test_loader_version2_fixed23_order_actual_codec_binding(self):
        self.assertEqual(23, len(f.MODULES))
        self.assertEqual(('mta_protocol', 'mta_client_control_frame', 'mta_client_connection',
            'mta_client_linux_provider', 'mta_client_executor'), f.MODULES[-5:])
        loader = self.source_fixture(); dep = loader.load()
        self.assertIsNone(loader.authenticate(dep))
        self.assertIs(dep.connect_binding, loader._connect_binding)
        self.assertEqual(fields(), dep.connect_binding.private_metadata())
        self.assertEqual(27, len(loader.owner.rows))
        self.assertTrue(all(row['closed'] for row in loader.owner.rows))

    def test_loader_old_extra_missing_bool_or_wrong_binding_blocked(self):
        changes = [lambda t: t.update(version=1), lambda t: t.update(version=True),
            lambda t: t.pop('connect_binding'), lambda t: t.update(extra=True),
            lambda t: t['connect_binding'].update(run_token='f' * 32),
            lambda t: t['connect_binding'].update(candidate_sha='f' * 64),
            lambda t: t['connect_binding'].update(receive_consent=False)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.io = ff.FakeIo(self.clock)
                loader = self.source_fixture(change)
                with self.assertRaises((f.ExecutorError, codec.ControlFrameError, ValueError)): loader.load()
                self.assertIsNone(loader.value)
                self.assertEqual(0, self.io.created_count)

    def test_loader_retained_metadata_mutation_or_binding_replacement_rejected(self):
        loader = self.source_fixture(); dep = loader.load()
        loader._connect_metadata['gatt_session'] = 99
        with self.assertRaises(f.ExecutorError): loader.authenticate(dep)
        loader._connect_metadata['gatt_session'] = 12
        module = dep.modules['mta_client_control_frame']
        dep.connect_binding = module.ControlBinding(fields())
        with self.assertRaises(f.ExecutorError): loader.authenticate(dep)

    def test_stdin_fragmented_connect_no_secret_history(self):
        binding = codec.ControlBinding(fields())
        frame = codec.encode_connect(binding, info())
        self.io.buffers[0] = [frame[:3], frame[3:80], frame[80:]]
        control = f._StdinControl(self.io, codec, binding)
        self.assertFalse(control.poll())
        request = control.take_connect()
        self.assertEqual(info().to_dict(), request.private_info().to_dict())
        self.assertEqual([], control.raw)
        self.assertIsNone(control.take_connect())

    def test_stdin_cancel_and_eof_win_before_claim(self):
        for tail in (codec.CANCEL, b''):
            binding = codec.ControlBinding(fields())
            self.io.buffers[0] = [codec.encode_connect(binding, info()), tail]
            control = f._StdinControl(self.io, codec, binding)
            # FakeIO readiness for an empty value is made truthful for queued EOF.
            base_ready = self.io.ready
            self.io.ready = lambda fds, seconds: [0] if self.io.buffers.get(0) else base_ready(fds, seconds)
            self.assertTrue(control.poll()); self.assertIsNone(control.take_connect())
            self.assertEqual([], control.raw)

    def test_stdin_duplicate_nonce_bad_frame_and_fd_change_failclosed(self):
        binding = codec.ControlBinding(fields()); frame = codec.encode_connect(binding, info())
        self.io.buffers[0] = [frame, frame]
        control = f._StdinControl(self.io, codec, binding)
        with self.assertRaises(codec.ControlFrameError): control.poll()
        self.assertTrue(control.cancelled); self.assertEqual([], control.raw)
        self.io.buffers[0] = [b'UNKNOWN\n']
        control = f._StdinControl(self.io, codec, binding)
        with self.assertRaises(codec.ControlFrameError): control.poll()
        control = f._StdinControl(self.io, codec, binding)
        self.io.fds[0]['meta'] = ff.metadata(self.io.fds[0]['meta'].st_mode, ino=999)
        with self.assertRaises(f.ExecutorError): control.poll()

    def test_f_connect_once_private_observation_and_same_restore(self):
        child, dep, state = self.child()
        self.io.buffers[0] = [codec.encode_connect(dep.connect_binding, info())]
        original = dep.modules['mta_client_linux_provider'].assemble
        def assemble(pm):
            values = original(pm); connect = values[4].connect_p2p
            def call(p2p, _checkpoint):
                value = connect(p2p, _checkpoint)
                self.io.buffers[0].append(codec.CANCEL)
                return value
            values[4].connect_p2p = call
            return values
        dep.modules['mta_client_linux_provider'].assemble = assemble
        frames = []; child.emit = frames.append
        result = child.run()
        self.assertEqual(1, len(state.connections))
        self.assertIs(child.connect_request, child.connection_ticket['request'])
        self.assertFalse(child.connection_ticket['unknown'])
        self.assertTrue(result['done']); self.assertTrue(child.assembly[4].restored)
        self.assertEqual(2, len(frames)); self.assertEqual(set(f._public()), set(frames[-1]))
        self.assertFalse(result['association_verified']); self.assertFalse(result['ip_ready'])
        self.assertNotIn('synthetic-secret', repr(frames))
        self.assertNotIn('synthetic-secret', repr(child.raw))
        self.assertEqual([], child.input.raw)

    def test_f_queued_cancel_calls_no_connection_but_restores(self):
        child, dep, state = self.child()
        self.io.buffers[0] = [codec.encode_connect(dep.connect_binding, info()), codec.CANCEL]
        result = child.run()
        self.assertEqual([], state.connections); self.assertFalse(child.connect_attempted)
        self.assertTrue(result['done'])

    def test_f_checkpoint_expiry_sticky_no_deadline_refresh(self):
        child, dep, state = self.child()
        self.io.buffers[0] = [codec.encode_connect(dep.connect_binding, info())]
        original = dep.modules['mta_client_linux_provider'].assemble
        saved = []
        def assemble(pm):
            values = original(pm)
            def call(p2p, _checkpoint):
                deadline = values[4].record.deadline; saved.append(deadline)
                self.clock.value = deadline
                self.assertTrue(_checkpoint()); self.assertTrue(_checkpoint())
                return ConnectionObservation()
            values[4].connect_p2p = call
            return values
        dep.modules['mta_client_linux_provider'].assemble = assemble
        self.assertTrue(child.run()['done'])
        self.assertEqual(saved[0], child.assembly[4].record.deadline)
        self.assertEqual('expired', child._connect_stop_reason)
        self.assertTrue(child.cancel_requested)

    def test_f_connection_exception_retains_ticket_and_restores_no_success_upgrade(self):
        child, dep, state = self.child()
        self.io.buffers[0] = [codec.encode_connect(dep.connect_binding, info())]
        original = dep.modules['mta_client_linux_provider'].assemble
        def assemble(pm):
            values = original(pm)
            def call(p2p, _checkpoint): raise RuntimeError('private fake connection failure')
            values[4].connect_p2p = call
            return values
        dep.modules['mta_client_linux_provider'].assemble = assemble
        result = child.run()
        self.assertTrue(child.assembly[4].restored); self.assertTrue(child.failures)
        self.assertTrue(child.connection_ticket['unknown'])
        self.assertIsNotNone(child.connection_ticket['info'])
        self.assertFalse(result['association_verified'])

    def test_f_malformed_connection_result_saved_before_reject_and_restore(self):
        child, dep, state = self.child()
        self.io.buffers[0] = [codec.encode_connect(dep.connect_binding, info())]
        original = dep.modules['mta_client_linux_provider'].assemble
        malformed = object()
        def assemble(pm):
            values = original(pm)
            values[4].connect_p2p = lambda p2p, _checkpoint: malformed
            return values
        dep.modules['mta_client_linux_provider'].assemble = assemble
        result = child.run()
        self.assertIs(malformed, child.connection_ticket['returned'])
        self.assertTrue(child.connection_ticket['unknown']); self.assertTrue(child.failures)
        self.assertTrue(child.assembly[4].restored)
        self.assertFalse(result['association_verified']); self.assertFalse(result['ip_ready'])

    def test_f_invalid_binding_before_assembly_no_creator(self):
        child, dep, state = self.child(Control())
        dep.connect_binding = None
        result = child.run()
        self.assertIsNone(child.assembly_ticket); self.assertFalse(result['done'])
        self.assertEqual([], state.connections)

    def test_parent_registered_same_worker_once_original_frame_no_raw(self):
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        parent.send_connect(handoff)
        self.assertEqual(1, handoff.claims)
        ticket = parent.connect_ticket
        self.assertTrue(ticket['sent']); self.assertFalse(ticket['unknown'])
        self.assertIs(ticket['handoff'], handoff)
        self.assertIsNot(ticket['binding'], dep.connect_binding)
        self.assertEqual(ticket['binding']._wire, dep.connect_binding._wire)
        self.assertIs(self.io.writes[-1][1], ticket['frame'])
        self.assertNotIn('synthetic-secret', repr(parent.raw))
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)
        self.assertEqual(1, len(self.io.writes))

    def test_parent_ready_then_bad_frame_sticky_failure_zero_claim_secret_write(self):
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        self.assertTrue(parent.frames[-1]['client_init_ready'])
        self.io.buffers[parent.pipes[1]['fd']] = [b'NOT_A_CLIENT_FRAME\n']
        parent.poll()
        self.assertTrue(parent.frames[-1]['client_init_ready'])
        self.assertTrue(parent.failures); self.assertEqual('frame_invalid', parent.reason)
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)
        self.assertFalse(parent.connect_attempted); self.assertIsNone(parent.connect_ticket)
        self.assertEqual(0, handoff.claims); self.assertEqual([], self.io.writes)

    def test_parent_default_missing_or_foreign_handoff_zero_secret_write(self):
        parent, dep, state = self.parent()
        with self.assertRaises(f.ExecutorError): parent.send_connect(Handoff())
        self.assertEqual([], self.io.writes)
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        with self.assertRaises(f.ExecutorError): parent.send_connect(Handoff())
        self.assertEqual(0, handoff.claims); self.assertEqual([], self.io.writes)

    def test_parent_cancel_before_or_during_claim_prevents_write(self):
        for when in ('before', 'after'):
            self.io = ff.FakeIo(self.clock)
            handoff = Handoff(); parent, dep, state = self.parent(handoff)
            handoff.invalid = when == 'before'; handoff.after_claim = when == 'after'
            if when == 'before':
                with self.assertRaises(RuntimeError): parent.send_connect(handoff)
            else:
                parent.send_connect(handoff)
                self.assertTrue(parent.connect_ticket['unknown'])
                self.assertIsNotNone(parent.connect_ticket['frame'])
            self.assertEqual([], self.io.writes)

    def test_parent_binding_mismatch_after_claim_zero_write_once(self):
        handoff = Handoff(); handoff.changed = True
        parent, dep, state = self.parent(handoff)
        result = parent.send_connect(handoff)
        self.assertTrue(result['resource_pending']); self.assertFalse(parent.connect_ticket['write_attempted'])
        self.assertEqual(1, handoff.claims); self.assertEqual([], self.io.writes)
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)

    def test_parent_short_unknown_write_retained_no_retry_cancel_still_same_pipe(self):
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        base_write = self.io.write
        def write(fd, data): base_write(fd, data); return len(data) - 1
        self.io.write = write
        result = parent.send_connect(handoff)
        self.assertTrue(result['resource_pending']); self.assertTrue(parent.connect_ticket['write_attempted'])
        self.assertFalse(parent.connect_ticket['sent']); self.assertTrue(parent.connect_ticket['unknown'])
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)
        self.assertEqual(1, len(self.io.writes))
        self.io.write = base_write; parent.cancel()
        self.assertEqual(f.CANCEL, self.io.writes[-1][1])
        self.assertEqual(self.io.writes[0][0], self.io.writes[-1][0])

    def test_parent_postwrite_pipe_change_retains_original_ticket(self):
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        base_write = self.io.write
        def write(fd, data):
            count = base_write(fd, data)
            self.io.fds[fd]['meta'] = ff.metadata(self.io.fds[fd]['meta'].st_mode, ino=1234)
            return count
        self.io.write = write
        result = parent.send_connect(handoff)
        self.assertTrue(result['resource_pending']); self.assertFalse(parent.connect_ticket['sent'])
        self.assertIsNotNone(parent.connect_ticket['frame']); self.assertEqual(1, len(self.io.writes))

    def test_parent_wrong_worker_or_registered_reference_changed_zero_claim(self):
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        handoff.operation = object()
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)
        self.assertEqual(0, handoff.claims)
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        handoff.worker = threading.Thread()
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)
        self.assertEqual([], self.io.writes)

    def test_parent_foreign_binding_rejected_before_claim_or_write(self):
        handoff = Handoff(); parent, dep, state = self.parent(handoff)
        dep.connect_binding = codec.ControlBinding(dict(fields(), run_token='f' * 32))
        with self.assertRaises(f.ExecutorError): parent.send_connect(handoff)
        self.assertEqual(0, handoff.claims); self.assertEqual([], self.io.writes)

    def test_python35_ast_no_new_threads_socket_process_methods(self):
        tree = ast.parse(SOURCE.read_text(encoding='utf-8'), feature_version=(3, 5))
        forbidden = {'fork', 'kill', 'terminate', 'send_signal', 'connect', 'socket', 'Thread'}
        calls = {node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertFalse(calls & forbidden)
        self.assertEqual({'reason', 'attempted', 'client_init_ready', 'done', 'resource_pending',
            'cancel_requested', 'send_available', 'receive_available', 'association_verified',
            'ip_ready', 'phone_tested'}, set(f._public()))

class ActualDomainTest(unittest.TestCase):
    """One actual PC libcrypto/thread method; no native/process/pipe/socket IO."""
    def setUp(self):
        self.fixture_module = load('connect_v14_actual_handoff_fixture',
            BASE / 'tests/test_client_connect_handoff_v13.py')
        self.fixture_module.HandoffTests.setUp(self)
    def tearDown(self): self.fixture_module.HandoffTests.tearDown(self)
    def run_owned(self, action): self.fixture_module.HandoffTests.run_owned(self, action)

    def test_actual_state_handoff_claim_state_codec_loader_domain_decode(self):
        hf = self.fixture_module
        with mock.patch.dict(sys.modules, {'mta_protocol': hf.protocol}):
            state_codec = load('connect_v14_actual_state_codec', CODEC)
        private_protocol = types.ModuleType('mta_protocol')
        exec((BASE / 'runtime/mta_protocol.py').read_bytes(), private_protocol.__dict__)
        with mock.patch.dict(sys.modules, {'mta_protocol': private_protocol}):
            loader_codec = load('connect_v14_actual_loader_codec', CODEC)
        self.assertIsNot(state_codec.protocol.P2pInfo, loader_codec.protocol.P2pInfo)
        self.assertIs(state_codec.protocol, hf.h.protocol)
        def action(owner):
            owner.decrypt()
            clock = ff.Clock(); io = ff.FakeIo(clock)
            dep, state = ff.deployment(io)
            dep.manifest.candidate_sha = fields()['candidate_sha']
            metadata = dict(fields(), nonce=owner.nonce, native_epoch=3,
                operation_epoch=3, gatt_session=7)
            dep.modules['mta_client_control_frame'] = loader_codec
            dep.connect_binding = loader_codec.ControlBinding(metadata)
            parent = f.ParentExecutor(dep, io, clock, _handoff=owner,
                _handoff_type=hf.h.ReceiveConnectHandoff, _handoff_codec=state_codec)
            parent.start()
            io.buffers[parent.pipes[1]['fd']] = [f.PREFIX + json.dumps(f._public(ready=True), sort_keys=True).encode('ascii') + b'\n']
            parent.poll(); parent.send_connect(owner)
            ticket = parent.connect_ticket
            self.assertTrue(ticket['sent']); self.assertFalse(ticket['unknown'])
            self.assertIs(type(ticket['binding']), state_codec.ControlBinding)
            self.assertIs(type(ticket['request']), loader_codec.ConnectRequest)
            self.assertIsNot(ticket['binding'], dep.connect_binding)
            self.assertEqual(self.plain.to_dict(), ticket['request'].private_info().to_dict())
            self.assertIs(ticket['frame'], io.writes[0][1])
            self.assertEqual(1, len(io.writes)); self.assertFalse(owner.status()['production_available'])
            with self.assertRaises(f.ExecutorError): parent.send_connect(owner)
            self.assertEqual([], parent.raw[1:])
            self.assertNotIn('fixture-only-psk', repr(parent.status()))
        self.run_owned(action)
        self.assertEqual([], self.errors + self.reader_errors)

if __name__ == '__main__': unittest.main()
