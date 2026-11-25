"""One new HOST method; ROOT alone decides and performs its first execution.

Actual Linux ZIP/CRC/fsync/held-directory publication, Transport._run_impl,
Executor._confirm_receive/_run_native_receive/new failure methods, codec and
Parent._receive_event execute. Logical stdin/stdout 0/1 map to real held Linux
pipes; no real descriptor 0/1 is replaced. Peer/IP admission, Owner constructor
and Owner.run are explicit identity/composition fixtures, NOT native authority.
WSS/connect/download/check/lifecycle fixtures are reused as definitions only.
Fault callbacks model cancellation, clock/pipe/IPC failures inside fresh trees.
No old test method, full 35-module chain, F.run, Parent start/wait/finish, State,
service/UI, device, phone, TLS, network, RF or restoration proof is executed.
"""
import ast
import builtins
from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import stat
import sys
import threading
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
HELPER = 'tests/test_receive_durable_result_v1.py'
HELPER_PIN = (18094, '53347fc25bd35e0dc505814118b77fde01abfad6737d347518118beb71e402b5')
TRANSFER = 'candidate/client-transfer-v30-r3/runtime/mta_client_transfer.py'
TRANSFER_PIN = (30747, '8633b2a1156c3012ec613e776eaee7e9339c14c76cffff9c8e5ff75646f35184')
EXECUTOR = 'candidate/receive-durable-state-v1/runtime/mta_client_executor.py'
CODEC = 'candidate/receive-durable-state-v1/runtime/mta_client_control_frame.py'
EXECUTOR_DELTA = 'candidate/receive-durable-state-v1/executor-exactsource-delta.json'
CONTROL_DELTA = 'candidate/receive-durable-state-v1/exactsource-control-bridge-delta.json'


def _pin(path, expected):
    raw = (BASE / path).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != expected:
        raise AssertionError('fixed fixture/source definition differs: ' + path)
    return raw


def _exact_delta(original_path, candidate_path, edits):
    original = (BASE / original_path).read_bytes()
    candidate = (BASE / candidate_path).read_bytes()
    forward, inverse = original, candidate
    for item in edits:
        before, after = item['before'].encode('utf-8'), item['after'].encode('utf-8')
        if forward.count(before) != 1:
            raise AssertionError('single forward source anchor required')
        forward = forward.replace(before, after, 1)
    for item in reversed(edits):
        before, after = item['before'].encode('utf-8'), item['after'].encode('utf-8')
        if inverse.count(after) != 1:
            raise AssertionError('single inverse source anchor required')
        inverse = inverse.replace(after, before, 1)
    if forward != candidate or inverse != original:
        raise AssertionError('complete exact-source delta differs')


def _sources():
    _pin(HELPER, HELPER_PIN)
    spec = importlib.util.spec_from_file_location('durable_storage_definitions_only', BASE / HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)  # Definitions only: no old TestCase methods.
    fixture, old_storage, storage, old_transport, transport = helper._sources()
    original_import = storage.__dict__['__builtins__']['__import__']
    protocol = original_import('mta_protocol')
    modules = {'mta_protocol': protocol, 'p011_json': protocol.__dict__['__builtins__']['__import__']('p011_json'),
               'mta_storage': storage, 'mta_transport': transport}
    imports = builtins.__import__

    def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('relative model imports refused')
        if name in modules:
            return modules[name]
        if name.startswith(('mta_', 'p011_')):
            raise ImportError('unlisted project definition')
        return imports(name, globals, locals, fromlist, level)

    def load(name, path, raw=None):
        raw = (BASE / path).read_bytes() if raw is None else raw
        ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
        value = types.ModuleType(name)
        value.__file__ = str(BASE / path)
        value.__dict__['__builtins__'] = dict(vars(builtins), __import__=fixed_import)
        exec(compile(raw, value.__file__, 'exec'), value.__dict__)
        modules[name] = value
        return value

    executor_delta = json.loads((BASE / EXECUTOR_DELTA).read_bytes())
    _exact_delta(executor_delta['original'], EXECUTOR, executor_delta['edits'])
    # Business changes must not alter Parent.finish or the generic cancel gate.
    before = ast.parse((BASE / executor_delta['original']).read_text(encoding='utf-8'))
    after = ast.parse((BASE / EXECUTOR).read_text(encoding='utf-8'))
    def method(tree, cls, name):
        owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls)
        return ast.dump(next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == name))
    if method(before, 'ParentExecutor', 'finish') != method(after, 'ParentExecutor', 'finish') or \
            method(before, 'ClientExecutor', '_emit_receive') != method(after, 'ClientExecutor', '_emit_receive'):
        raise AssertionError('original finish/cancellation method changed')
    control_delta = json.loads((BASE / CONTROL_DELTA).read_bytes())
    entry = next(row for row in control_delta['entries'] if row['candidate'][0] == CODEC)
    _pin(entry['source'][0], (entry['source'][1], entry['source'][2]))
    _pin(CODEC, (entry['candidate'][1], entry['candidate'][2]))
    _exact_delta(entry['source'][0], CODEC, entry['replacements'])
    codec, executor = load('mta_client_control_frame', CODEC), load('mta_client_executor', EXECUTOR)
    # The omitted native definitions are loud identity fixtures, not imported
    # historical native suites. Their methods only run as declared below.
    for name in ('mta_ip', 'mta_p2p_client_init', 'mta_client_dora', 'mta_client_dynamic_ip',
                 'mta_client_peer', 'mta_scoped_sockets'):
        modules[name] = types.ModuleType('HOST_identity_fixture_' + name)
    transfer = load('mta_client_transfer', TRANSFER, _pin(TRANSFER, TRANSFER_PIN))
    return helper, fixture, modules, codec, executor, transfer


class Clock(object):
    def __init__(self): self.value = 100.0
    def __call__(self): return self.value


class HeldPipeIo(object):
    """Actual held Linux pipes, with explicitly injected post-publication faults."""
    def __init__(self, clock):
        self.clock = clock
        self.input_read, self.input_write = os.pipe()
        self.output_read, self.output_write = os.pipe()
        self.original_output = self.output_write
        self.all_fds = [self.input_read, self.input_write, self.output_read, self.output_write]
        self.output_reads = [self.output_read]
        self.writes, self.ready_calls = [], []
        self.short = self.not_ready = False
        self.advance_write = 0.0
        self.pipe_buf_override = None
        self.after_write = None
    def fstat(self, fd):
        return os.fstat(self.input_read if fd == 0 else self.output_write if fd == 1 else fd)
    def pipe_buf(self, fd):
        if fd != 1: raise AssertionError('only held stdout is admitted')
        return self.pipe_buf_override if self.pipe_buf_override is not None else os.fpathconf(self.output_write, 'PC_PIPE_BUF')
    def ready_write(self, fd, seconds):
        if fd != 1 or not 0 <= seconds <= .05: raise AssertionError('single <=50ms stdout poll only')
        self.ready_calls.append(seconds)
        if self.not_ready: return False  # Explicit unavailable-pipe fixture.
        return bool(select.select([], [self.output_write], [], seconds)[1])
    def ready(self, fds, seconds):
        if tuple(fds) != (0,) or not 0 <= seconds <= .05:
            raise AssertionError('only held stdin poll is admitted')
        return [0] if select.select([self.input_read], [], [], seconds)[0] else []
    def read(self, fd, count):
        if fd != 0: raise AssertionError('only held stdin read is admitted')
        return os.read(self.input_read, count)
    def write(self, fd, frame):
        if fd != 1: raise AssertionError('only held stdout write is admitted')
        actual = frame[:-1] if self.short else frame
        returned = os.write(self.output_write, actual)
        self.writes.append((frame, returned, self.output_write))
        self.clock.value += self.advance_write
        if self.after_write is not None: self.after_write(frame)
        return returned
    def replace_stdout(self):
        read_fd, write_fd = os.pipe()
        self.all_fds.extend((read_fd, write_fd)); self.output_reads.append(read_fd)
        self.output_write = write_fd  # Old original remains held until cleanup.
    def drain(self):
        output = b''
        for fd in self.output_reads:
            while select.select([fd], [], [], 0)[0]: output += os.read(fd, 4096)
        return output
    def close(self):
        for fd in reversed(self.all_fds): os.close(fd)


def _binding_fields():
    return dict(version=1, run_token='a' * 32, candidate_sha='b' * 64,
        operation_id='HOST-local-operation', native_epoch=8, operation_epoch=9,
        gatt_session=12, nonce='c' * 32, receive_consent=True)


def _forbidden(*args, **kwargs):
    raise AssertionError('native/process/network/restoration authority is outside this HOST method')


@contextmanager
def _failed_native(case, sources, diagnostic=None, reject=None):
    """Actual receive exception branch; admitted native parents are fixtures."""
    helper, fixture, modules, codec, executor, transfer = sources
    storage, transport = modules['mta_storage'], modules['mta_transport']
    clock = Clock()
    with fixture._Fixture(case, storage) as f:
        binding = f.binding()
        pipe = HeldPipeIo(clock)
        try:
            case.assertTrue(stat.S_ISFIFO(pipe.fstat(1).st_mode))
            case.assertGreaterEqual(pipe.pipe_buf(1), codec.MAX_RX_FRAME)
            control_binding = codec.ControlBinding(_binding_fields())
            input_owner = executor._StdinControl(pipe, codec, control_binding)
            info = modules['mta_protocol'].P2pInfo('HOST', 'HOST-fixture-secret', '02:11:22:33:44:55', 3345)
            os.write(pipe.input_write, codec.encode_connect(control_binding, info))
            case.assertIs(type(input_owner.take_connect()), codec.ConnectRequest)
            dep = executor.LoadedDeployment(types.SimpleNamespace(directory_type=storage.DirectoryBinding), modules,
                types.SimpleNamespace(run_token='a' * 32, candidate_sha='b' * 64), 'd' * 64,
                executor.ROOT + '/client-' + 'a' * 32, control_binding, str(f.root), (), binding)
            value = executor.ClientExecutor(dep, _io=pipe, _clock=clock, _input=input_owner)
            provider = types.SimpleNamespace(_client_peer_owner_v29=None, _client_transfer_owner_v30=None)
            lease = types.SimpleNamespace(record=types.SimpleNamespace(deadline=110.0))
            value.assembly = (provider, object(), object(), object(), lease)
            stop_calls, fault_calls, sent, closed = [], [], [], []
            diagnostic_baseline = []
            class DynamicIpFixture(object): pass
            class NeighborRecordFixture(object): pass
            class PeerFixture(object):
                def __init__(self, original):
                    self.ip_owner, self.unknown = original, False
                    provider._client_peer_owner_v29 = self
                def read(self): return NeighborRecordFixture()
                def closed_facts(self): return ((True, True),)  # Explicit modeled native closure.
            ip_owner = DynamicIpFixture(); ip_owner.handoff = types.SimpleNamespace(_until=110.0)
            value.ip_ticket = {'returned': ip_owner, 'unknown': False}
            modules['mta_client_dynamic_ip'].ClientDynamicIp = DynamicIpFixture
            modules['mta_client_peer'].ClientPeerReader = PeerFixture
            modules['mta_client_peer'].NeighborRecord = NeighborRecordFixture

            def owner_init(owner, native_peer, receiver, _executor=None):
                case.assertIs(_executor, value); case.assertIs(native_peer.ip_owner, ip_owner)
                owner.receiver, owner.executor, owner.input = receiver, value, input_owner
                owner.deadline, owner._running = 110.0, False
                owner.transport = None
                owner.transport_ticket = {'returned': None, 'complete': False}
                provider._client_transfer_owner_v30 = owner
                f.receivers.append(receiver)  # Fresh test-tree owned cleanup only.

            def owner_cancel(owner):
                stop_calls.append(helper._published(owner.receiver))
                if helper._published(owner.receiver):
                    value.cancel_requested = input_owner.cancelled = True
                    input_owner.decoder.cancel()  # Historical accepted decision survives.
                    if not fault_calls:
                        fault_calls.append(True)
                        diagnostic_baseline.append((len(pipe.writes), len(pipe.ready_calls), len(stop_calls)))
                        if diagnostic is not None: diagnostic(value, owner, pipe, clock)
                    return True
                return input_owner.poll()

            def owner_run(owner, confirm, progress, file_progress):
                owner._running = True
                actual, ws, messages, connections, closure = helper._transport_fixture(
                    case, transport, f, owner.receiver, owner._cancelled)
                actual.deadline = owner.deadline
                owner.transport = actual
                owner.transport_ticket.update(returned=actual, complete=True)
                try:
                    with mock.patch.object(transport, 'websocket_client', return_value=ws):
                        return transport.ReceiverTransport._run_impl(actual,
                            lambda request: confirm(request, owner.deadline, owner._cancelled), progress, file_progress)
                except BaseException:
                    if reject is not None: reject(value, owner)
                    raise
                finally:
                    owner._running = False; sent.extend(messages); closed.extend(closure)

            def consent_after_prompt(frame):
                event = codec.decode_receive_event(control_binding, frame)
                if event['kind'] == 'prompt':
                    os.write(pipe.input_write, codec.encode_receive_decision(control_binding, value.receive_prompt, True))
            pipe.after_write = consent_after_prompt
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(executor, 'RECEIVE_ROOT', str(f.root)))
                stack.enter_context(mock.patch.object(executor, '_receive_directory', return_value=()))
                stack.enter_context(mock.patch.object(transfer.ClientTransferOwner, '__init__', owner_init))
                stack.enter_context(mock.patch.object(transfer.ClientTransferOwner, '_cancelled', owner_cancel))
                stack.enter_context(mock.patch.object(transfer.ClientTransferOwner, 'run', owner_run))
                with case.assertRaises(storage.TransferCancelled) as caught:
                    value._run_native_receive()
                owner, receiver = value.receive_ticket['returned'], value.receive_ticket['receiver']
                case.assertIs(caught.exception, receiver._bound_failure)
                case.assertIs(caught.exception, value.receive_failure_original)
                case.assertEqual(2, len(sent))  # Only version/sendRequest ACK, never completion.
                case.assertEqual(2, len(closed))
                saved = helper._saved(case, receiver, 'current-receive')
                case.assertFalse(value.done); case.assertFalse(value.receive_resources_closed)
                yield types.SimpleNamespace(executor=value, owner=owner, receiver=receiver,
                    original=caught.exception, saved=saved, pipe=pipe, clock=clock, stop_calls=stop_calls,
                    wire=pipe.drain(), binding=control_binding, diagnostic_baseline=diagnostic_baseline[0])
        finally:
            pipe.close()


def _parent(executor, modules, binding, prompt_wire, accepted=True):
    clock = Clock()
    dep = executor.LoadedDeployment(object(), modules,
        types.SimpleNamespace(run_token='a' * 32, candidate_sha='b' * 64), 'd' * 64,
        executor.ROOT + '/client-' + 'a' * 32, binding)
    value = executor.ParentExecutor(dep, _io=types.SimpleNamespace(), _clock=clock)
    value.connect_ticket = {'unknown': False, 'sent': True}  # Explicit admitted CONNECT fixture.
    value._receive_event(prompt_wire)
    value.receive_reply_ticket = {'prompt': value.receive_prompt, 'unknown': False,
        'sent': True, 'accepted': accepted}  # Actual immutable Parent prompt identity.
    return value


class ReceiveDurableExecutorV1Tests(unittest.TestCase):
    def test_bound_failure_original_pipe_and_parent_contract(self):
        self.assertEqual('posix', os.name); self.assertTrue(sys.platform.startswith('linux'))
        sources = _sources()
        helper, fixture, modules, codec, executor, transfer = sources
        completed = 0
        with ExitStack() as guards:
            for target in ('subprocess.Popen', 'socket.socket', 'os.fork', 'os.kill', 'os.waitpid'):
                guards.enter_context(mock.patch(target, side_effect=_forbidden, create=True))
            for cls, name in ((executor.ClientExecutor, 'run'), (executor.DeploymentLoader, 'load'),
                    (executor.DeploymentLoader, 'authenticate'), (executor.ParentExecutor, 'start'),
                    (executor.ParentExecutor, 'finish'), (transfer.ClientTransferOwner, '_quick')):
                guards.enter_context(mock.patch.object(cls, name, side_effect=_forbidden))
            with self.subTest(domain='actual_late_cancel_original_failure_and_parent'):
                with _failed_native(self, sources) as row:
                    value = row.executor
                    self.assertEqual('saved_failed', value.receive_outcome)
                    self.assertEqual(row.saved, value.receive_result)
                    self.assertIsNot(row.saved, value.receive_result)
                    self.assertFalse(value.receive_result['peer_ack_verified'])
                    self.assertTrue(value._saved_failure_emit_attempted); self.assertTrue(value._rx_terminal)
                    self.assertEqual([], value.receive_terminal_failures)
                    baseline_writes, baseline_polls, baseline_stops = row.diagnostic_baseline
                    self.assertEqual(1, len(row.pipe.writes) - baseline_writes)
                    self.assertEqual(1, len(row.pipe.ready_calls) - baseline_polls)
                    self.assertEqual(baseline_stops, len(row.stop_calls))
                    result_ticket = value.receive_events[-1]
                    self.assertTrue(result_ticket['sent']); self.assertTrue(result_ticket['write_attempted'])
                    self.assertEqual(len(result_ticket['wire']), result_ticket['write_result'])
                    self.assertLessEqual(len(result_ticket['wire']), codec.MAX_RX_FRAME)
                    calls, writes = len(row.stop_calls), len(row.pipe.writes)
                    with self.assertRaises(executor.ExecutorError): value._emit_saved_failure()
                    self.assertEqual(calls, len(row.stop_calls)); self.assertEqual(writes, len(row.pipe.writes))
                    wires = row.wire.splitlines(keepends=True)
                    parent = _parent(executor, modules, row.binding, wires[0])
                    for wire in wires[1:]: parent._receive_event(wire)
                    self.assertEqual('saved_failed', parent.receive_state)
                    self.assertEqual('saved_failed', parent.receive_result['outcome'])
                    self.assertFalse(parent.receive_result['peer_ack_verified'])
                    self.assertFalse(parent.status()['done']); self.assertFalse(parent.reaped)
                    self.assertFalse(parent.absent); self.assertFalse(parent.closed)
                    self.assertIsNone(parent.exit_code)
                    with self.assertRaises(executor.ExecutorError): parent._receive_event(wires[-1])
                    good_wires, good_binding = wires, row.binding
                completed += 1
            diagnostics = {
                'original_cap_expired': lambda v, o, p, c: setattr(c, 'value', 110.0),
                'clock_regressed': lambda v, o, p, c: setattr(c, 'value', 99.0),
                'held_stdout_changed': lambda v, o, p, c: p.replace_stdout(),
                'short_single_write': lambda v, o, p, c: setattr(p, 'short', True),
                'full_write_crossed_cap': lambda v, o, p, c: setattr(p, 'advance_write', 10.0),
                'one_not_ready_poll': lambda v, o, p, c: setattr(p, 'not_ready', True),
                'earlier_frame_not_sent': lambda v, o, p, c: v.receive_events[-1].update(sent=False),
                'earlier_frame_short': lambda v, o, p, c: v.receive_events[-1].update(write_result=0),
                'events_budget_full': lambda v, o, p, c: v.receive_events.extend(
                    [dict(v.receive_events[-1]) for unused in range(codec.MAX_RX_EVENTS - len(v.receive_events))]),
                'pipe_buf_too_small_on_initial_capture': lambda v, o, p, c: (
                    setattr(v, 'output_metadata', None), setattr(p, 'pipe_buf_override', codec.MAX_RX_FRAME - 1)),
            }
            for domain, fault in diagnostics.items():
                with self.subTest(domain=domain):
                    with _failed_native(self, sources, diagnostic=fault) as row:
                        value = row.executor
                        self.assertEqual('saved_failed', value.receive_outcome)
                        self.assertEqual(row.saved, value.receive_result)
                        self.assertFalse(value._rx_terminal); self.assertTrue(value.receive_terminal_failures)
                        self.assertTrue(value._saved_failure_emit_attempted)
                        baseline_writes, baseline_polls, baseline_stops = row.diagnostic_baseline
                        self.assertLessEqual(len(row.pipe.writes) - baseline_writes, 1)
                        self.assertLessEqual(len(row.pipe.ready_calls) - baseline_polls, 1)
                        self.assertEqual(baseline_stops, len(row.stop_calls))
                        writes, polls, events, calls = (len(row.pipe.writes), len(row.pipe.ready_calls),
                            len(value.receive_events), len(row.stop_calls))
                        with self.assertRaises(executor.ExecutorError): value._emit_saved_failure()
                        self.assertEqual((writes, polls, events, calls), (len(row.pipe.writes),
                            len(row.pipe.ready_calls), len(value.receive_events), len(row.stop_calls)))
                        self.assertIs(value.receive_failure_original, row.original)
                        # The prompt + extraction progress polls preceded the
                        # failure; this last diagnostic contributes at most one.
                        diagnostic_tickets = [e for e in value.receive_events if e['kind'] == 'result']
                        self.assertLessEqual(len(diagnostic_tickets), 1)
                        self.assertLessEqual(sum(e['write_attempted'] for e in diagnostic_tickets), 1)
                        if domain == 'short_single_write':
                            self.assertEqual(len(diagnostic_tickets[0]['wire']) - 1, diagnostic_tickets[0]['write_result'])
                        if domain == 'original_cap_expired': self.assertEqual('deadline', value.receive_terminal_failures[-1].code)
                    completed += 1
            rejects = {
                'transport_publication_metadata_changed': lambda v, o: o.transport.local_commit_result.update(taskId='foreign'),
                'transport_ticket_not_complete': lambda v, o: o.transport_ticket.update(complete=False),
                'original_owner_changed': lambda v, o: setattr(o, 'executor', object()),
                'original_receiver_changed': lambda v, o: setattr(o, 'receiver', object()),
                'original_accepted_decision_missing': lambda v, o: setattr(v.input.decoder, '_claimed_receive_decision', None),
                'receive_ticket_unknown': lambda v, o: v.receive_ticket.update(unknown=True),
                'transport_receiver_changed': lambda v, o: setattr(o.transport, 'receiver', object()),
                'transport_directory_changed': lambda v, o: setattr(o.transport, 'directory_binding', object()),
                'original_decision_replaced_by_clone': lambda v, o: setattr(v, 'receive_decision',
                    codec.ReceiveDecision(v.input.decoder, True)),
                'original_request_metadata_changed': lambda v, o: v.receive_request.update(totalSize=0),
            }
            for domain, fault in rejects.items():
                with self.subTest(domain=domain):
                    with _failed_native(self, sources, reject=fault) as row:
                        self.assertEqual('cancelled', row.executor.receive_outcome)
                        self.assertIsNone(row.executor.receive_result)
                        self.assertIsNone(row.executor._saved_failure_originals)
                        self.assertFalse(row.executor._saved_failure_emit_attempted)
                        self.assertFalse(row.executor._rx_terminal)
                        self.assertFalse(any(event['kind'] == 'result' for event in row.executor.receive_events))
                    completed += 1
            for domain in ('missing_consent', 'refused_consent', 'unknown_consent', 'unsent_consent',
                           'wrong_task', 'wrong_count', 'wrong_size', 'wrong_sequence'):
                with self.subTest(domain='parent_' + domain):
                    parent = _parent(executor, modules, good_binding, good_wires[0])
                    for wire in good_wires[1:-1]: parent._receive_event(wire)
                    payload = dict(codec.decode_receive_event(good_binding, good_wires[-1])['payload'])
                    sequence = len(parent.receive_events)
                    if domain == 'missing_consent': parent.receive_reply_ticket = None
                    elif domain == 'refused_consent': parent.receive_reply_ticket['accepted'] = False
                    elif domain == 'unknown_consent': parent.receive_reply_ticket['unknown'] = True
                    elif domain == 'unsent_consent': parent.receive_reply_ticket['sent'] = False
                    elif domain == 'wrong_task': payload['task_id'] = 'foreign'
                    elif domain == 'wrong_count': payload['file_count'] += 1
                    elif domain == 'wrong_size': payload['total_size'] += 1
                    else: sequence += 1
                    wire = codec.encode_receive_event(good_binding, sequence, 'result', payload)
                    with self.assertRaises(executor.ExecutorError): parent._receive_event(wire)
                    self.assertIsNone(parent.receive_result); self.assertFalse(parent.status()['done'])
                completed += 1
            with self.subTest(domain='saved_failed_codec_no_pre_prompt_or_peer_ack'):
                self.assertNotIn('saved_failed', codec.PRE_PROMPT_TERMINALS)
                payload = dict(codec.decode_receive_event(good_binding, good_wires[-1])['payload'])
                with self.assertRaises(codec.ControlFrameError): codec.encode_receive_event(good_binding, 0, 'result', payload)
                payload['peer_ack_verified'] = True
                with self.assertRaises(codec.ControlFrameError): codec.encode_receive_event(good_binding, 1, 'result', payload)
                completed += 1
        self.assertEqual(30, completed)
        # Unique ASCII marker is the only stdout contract. The HOST runner
        # additionally requires unittest stderr Ran 1 / OK and HOST child exit 0.
        print('RECEIVE_DURABLE_EXECUTOR_FIXTURE_CONTRACT=1')


if __name__ == '__main__':
    unittest.main()
