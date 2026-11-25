"""One affected HOST contract for saved_failed codec and selected Bridge methods.

The actual pinned codec/json/protocol definitions run. Only the actual Bridge
_project/run/status AST methods run; identity/factory/Parent/finish/observation/
Session outcome and restoration dependencies are explicit HOST fixtures. No
whole Bridge/State/Executor, real consent, disk save, child, RF or phone runs.
Business SOURCE pins intentionally await ROOT's separate mechanical binding.
"""
import ast
from collections import namedtuple
import copy
import hashlib
import json
import math
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_CODEC = ('candidate/client-integrated-v37/runtime/mta_client_control_frame.py', 20942,
    'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278')
CODEC = ('candidate/receive-durable-state-v1/runtime/mta_client_control_frame.py', 21203,
    '66eae58a95eaf8344934d15aca2685de1c176b8408a56786995e9f9078c6032c')
ORIGINAL_BRIDGE = ('candidate/formal-receive-profile-classification-clock-v1/runtime/mta_client_state_bridge.py', 21284,
    '849613b9e62cffdca6fe91ed6a9ba787b6c9b93a53b1a6e4df704b03d1a5b962')
BRIDGE = ('candidate/receive-durable-state-v1/runtime/mta_client_state_bridge.py', 21356,
    '239e353c336b678638502d1a3dd612e6ce5110c005b1a0228f697d3af56cdc29')
JSON_SOURCE = ('runtime/p011_json.py', 8061,
    'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88')
PROTOCOL = ('runtime/mta_protocol.py', 17958,
    '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57')
DELTA = ('candidate/receive-durable-state-v1/exactsource-control-bridge-delta.json', 4478,
    '41b1cd371fb5908e0292c42e6debc6b0238e2ca7195eb78922534c40bbcff4db')
PINS = (ORIGINAL_CODEC, CODEC, ORIGINAL_BRIDGE, BRIDGE, JSON_SOURCE, PROTOCOL, DELTA)


def fixed(pin):
    raw = (ROOT / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('durable_control_bridge_fixture_pin')
    return raw


def module(pin, name):
    value = types.ModuleType(name)
    value.__file__ = str(ROOT / pin[0])
    raw = fixed(pin)
    ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    exec(compile(raw, value.__file__, 'exec'), value.__dict__)
    return value


def binding(codec):
    return codec.ControlBinding(dict(version=1, run_token='1' * 32,
        candidate_sha='2' * 64, operation_id='fixture-operation', native_epoch=1,
        operation_epoch=1, gatt_session=1, nonce='3' * 32, receive_consent=True))


def result(outcome='saved_failed', count=3, total=7, ack=False, task='fixture-task'):
    return dict(outcome=outcome, task_id=task, file_count=count, total_size=total,
                peer_ack_verified=ack)


def bridge_methods():
    tree = ast.parse(fixed(BRIDGE).decode('utf-8'), feature_version=(3, 5))
    classes = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'StateClientBridge']
    if len(classes) != 1:
        raise ValueError('fixture_bridge_class')
    methods = [row for row in classes[0].body if isinstance(row, ast.FunctionDef) and
               row.name in ('_project', 'run', 'status')]
    if len(methods) != 3 or {row.name for row in methods} != {'_project', 'run', 'status'}:
        raise ValueError('fixture_bridge_methods')
    helpers = [row for row in tree.body if isinstance(row, (ast.ClassDef, ast.FunctionDef)) and
               row.name in ('StateBridgeError', '_fail')]
    constants = [row for row in tree.body if isinstance(row, ast.Assign) and
                 any(isinstance(item, ast.Name) and item.id in ('_CODES', 'PARENT_SOURCE_SHA',
                     'CODEC_SOURCE_SHA', 'POLL_SECONDS', 'FINISH_SECONDS')
                     for target in row.targets for item in ast.walk(target))]
    if len(helpers) != 2 or len(constants) != 4:
        raise ValueError('fixture_bridge_definitions')
    selected = ast.ClassDef(name='StateClientBridge', bases=[], keywords=[],
        body=copy.deepcopy(methods), decorator_list=[])
    unit = ast.Module(body=copy.deepcopy(constants + helpers) + [selected], type_ignores=[])
    namespace = dict(math=math, threading=threading)
    exec(compile(ast.fix_missing_locations(unit), BRIDGE[0], 'exec'), namespace)
    return namespace


class InjectedFailure(RuntimeError):
    pass


def bridge_fixture(namespace, prompt, payload, primary_failure=None):
    """Only actual selected methods; all Parent/owner decisions below are fixtures."""
    calls, outcomes = [], []
    executor = types.ModuleType('mta_client_executor')

    class LoadedDeploymentFixture:
        pass

    class ParentFixture:
        def __init__(self, value, **kwargs):
            calls.append('fixture_parent_construct')
            self.connect_attempted, self.frames = True, []
            self.eof, self.failures = dict(stdout=False, stderr=False), []

        @staticmethod
        def start(parent, seconds):
            calls.append(('fixture_parent_start', seconds))

    executor.LoadedDeployment, executor.ParentExecutor = LoadedDeploymentFixture, ParentFixture
    executor.CONNECT_CODEC_SHA = namespace['CODEC_SOURCE_SHA']
    deployment = LoadedDeploymentFixture()
    deployment.modules = {'mta_client_executor': executor}
    deployment.manifest = types.SimpleNamespace(executor_sha=namespace['PARENT_SOURCE_SHA'])
    deployment.loader = types.SimpleNamespace(authenticate=lambda value: calls.append('fixture_authenticate'))
    OutcomeFixture = namedtuple('OutcomeFixture', 'value local_commit peer_ack')

    def outcome(*args):
        outcomes.append(args)
        return OutcomeFixture(*args)

    namespace['sessions'] = types.SimpleNamespace(Outcome=outcome)
    namespace['handoffs'] = types.SimpleNamespace(ReceiveConnectHandoff=types.SimpleNamespace(
        decrypt=lambda handoff: calls.append('fixture_decrypt')))
    bridge = namespace['StateClientBridge']()
    bridge.state = types.SimpleNamespace(lock=threading.RLock(), closing=False,
        request=None, discoverable=True, state='connecting', transfer={})
    bridge.operation = types.SimpleNamespace(result=None)
    bridge.state.operation = bridge.operation
    bridge.session = types.SimpleNamespace(_task_deadline=200.0)
    bridge.handoff = types.SimpleNamespace(deadline=200.0,
        _check=lambda: calls.append('fixture_handoff_check'))
    bridge.cancelled = threading.Event()
    bridge._owners = lambda worker=False: calls.append(('fixture_owner', worker))
    bridge._now = lambda: 100.0
    bridge.clock = lambda: 100.0
    bridge._factory = lambda handoff: deployment
    bridge._state_codec = object()  # Identity/authentication is not exercised by this fixture.
    bridge.started = bridge.running = False
    bridge.reason, bridge.result = 'not_started', None
    bridge._prompt = bridge._choice = None
    bridge._choice_taken = bridge._cancel_sent = False
    bridge.parent = bridge.deployment = bridge._executor = None
    bridge._restore_snapshot = False
    bridge.failures = []
    bridge.factory_ticket = dict(started=False, returned=None, authenticated=False)
    bridge.parent_ticket = dict(started=False, returned=None)
    observed = dict(state='terminal', prompt=prompt, result=dict(payload),
        download_bytes=9, verified_file_bytes=payload['total_size'])

    def observe():
        calls.append('fixture_observe')
        if primary_failure is not None:
            raise primary_failure
        bridge._project(observed)
        return observed

    def finish():
        calls.append('fixture_finish')
        bridge._project(observed)  # Synthetic late valid terminal observation.

    def restore():
        calls.append('fixture_restore')
        return False  # No resource/Parent/radio restoration proof is supplied.

    bridge._observe, bridge._finish_parent, bridge.restoration_verified = observe, finish, restore
    return bridge, executor, calls, outcomes


class ReceiveDurableControlBridgeFixture(unittest.TestCase):
    def test_one_affected_saved_failed_contract(self):
        sources = {pin[0]: fixed(pin) for pin in PINS}
        delta = json.loads(sources[DELTA[0]].decode('ascii'))
        self.assertEqual(delta['schema'], 'p011-receive-durable-control-bridge-source-delta-v1')
        self.assertEqual(delta['evidence'], 'SOURCE_ONLY_NOT_TESTED_NOT_BOUND')
        self.assertIs(delta['mechanical_executor_codec_pins_deferred'], True)
        for name in ('pre_prompt_terminals_changed', 'frame_size_or_sequence_budget_changed',
                     'committed_failure_suppression_changed', 'resource_close_or_restore_gate_changed', 'deployed'):
            self.assertIs(delta[name], False)
        self.assertEqual(len(delta['entries']), 2)
        for row, source_pin, candidate_pin, expected_count in zip(delta['entries'],
                (ORIGINAL_CODEC, ORIGINAL_BRIDGE), (CODEC, BRIDGE), (1, 4)):
            self.assertEqual(row['source'], list(source_pin))
            self.assertEqual(row['candidate'], list(candidate_pin))
            self.assertEqual(len(row['replacements']), expected_count)
            original = sources[source_pin[0]]
            current = original
            for replacement in row['replacements']:
                self.assertIs(type(replacement['count']), int)
                self.assertEqual(replacement['count'], 1)
                old, new = replacement['before'].encode('ascii'), replacement['after'].encode('ascii')
                self.assertEqual(current.count(old), 1)
                current = current.replace(old, new)
            self.assertEqual(current, sources[candidate_pin[0]])
            for replacement in reversed(row['replacements']):
                old, new = replacement['before'].encode('ascii'), replacement['after'].encode('ascii')
                self.assertEqual(current.count(new), 1)
                current = current.replace(new, old)
            self.assertEqual(current, original)
        actual_json = module(JSON_SOURCE, 'HOST_actual_p011_json')
        with patch.dict(sys.modules, {'p011_json': actual_json}):
            protocol = module(PROTOCOL, 'HOST_actual_protocol')
        with patch.dict(sys.modules, {'p011_json': actual_json, 'mta_protocol': protocol}):
            codec = module(CODEC, 'HOST_actual_durable_control_codec')
            old_codec = module(ORIGINAL_CODEC, 'HOST_actual_previous_control_codec')
        key = binding(codec)
        self.assertEqual(codec.PRE_PROMPT_TERMINALS, old_codec.PRE_PROMPT_TERMINALS)
        self.assertNotIn('saved_failed', codec.PRE_PROMPT_TERMINALS)
        for name in ('MAX_FRAME', 'MAX_RX_FRAME', 'MAX_RX_EVENTS', 'MAX_TOTAL'):
            self.assertEqual(getattr(codec, name), getattr(old_codec, name))
        valid = result()
        wire = codec.encode_receive_event(key, 1, 'result', valid)
        self.assertEqual(codec.decode_receive_event(key, wire)['payload'], valid)
        self.assertLessEqual(len(wire), codec.MAX_RX_FRAME)
        with self.assertRaises(old_codec.ControlFrameError):
            old_codec.encode_receive_event(binding(old_codec), 1, 'result', valid)
        for value in (result(count=1, total=0), result(count=256, total=512 * 1024 * 1024)):
            self.assertEqual(codec.decode_receive_event(key,
                codec.encode_receive_event(key, 47, 'result', value))['payload'], value)
        malformed = [dict(valid, peer_ack_verified=True), dict(valid, peer_ack_verified=0),
            dict(valid, file_count=0), dict(valid, file_count=True), dict(valid, file_count=257),
            dict(valid, file_count=-1), dict(valid, total_size=True), dict(valid, total_size=-1),
            dict(valid, total_size=512 * 1024 * 1024 + 1), dict(valid, task_id=''),
            dict(valid, task_id='bad/task'), dict(valid, outcome='saved_failed_unknown'),
            dict(valid, extra=True)]
        for value in malformed:
            with self.subTest(rejected_fields=tuple(sorted(value))):
                with self.assertRaises(codec.ControlFrameError):
                    codec.encode_receive_event(key, 1, 'result', value)
        for sequence in (0, -1, 48, True, 1.0):
            with self.assertRaises(codec.ControlFrameError):
                codec.encode_receive_event(key, sequence, 'result', valid)
        self.assertEqual(codec.decode_receive_event(key, wire)['sequence'], 1)
        value = codec.decode_receive_event(key, wire)
        value['payload']['peer_ack_verified'] = True
        invalid_wire = codec.RX_PREFIX + actual_json.dumps(value, ensure_ascii=True, sort_keys=True).encode('ascii') + b'\n'
        with self.assertRaises(codec.ControlFrameError):
            codec.decode_receive_event(key, invalid_wire)
        with self.assertRaises(codec.ControlFrameError):
            codec.decode_receive_event(key, wire[:-1])
        with self.assertRaises(codec.ControlFrameError):
            codec.decode_receive_event(key, codec.RX_PREFIX + b' ' * codec.MAX_RX_FRAME + b'\n')
        with self.assertRaises(codec.ControlFrameError):
            codec.encode_receive_event(key, 1, 'result', result(outcome='failed', count=1, total=1))
        for outcome in ('failed', 'cancelled', 'unavailable'):
            payload = result(outcome=outcome, count=0, total=0, task='')
            self.assertEqual(codec.encode_receive_event(key, 0, 'result', payload),
                             old_codec.encode_receive_event(binding(old_codec), 0, 'result', payload))
        prompt = codec.ReceivePrompt(key, dict(prompt_id='4' * 32, task_id='fixture-task',
            file_count=3, total_size=7, sender_name='HOST fixture', file_name='fixture.bin', until=200.0))
        for outcome, primary in (('saved_failed', None), ('saved_failed', InjectedFailure('fixture_original_pipe_failure')),
                                 ('failed', None), ('committed', None),
                                 ('committed', InjectedFailure('fixture_after_commit_failure'))):
            with self.subTest(bridge_outcome=outcome, original_failure=primary is not None):
                namespace = bridge_methods()
                payload = result(outcome=outcome, count=0 if outcome == 'failed' else 3,
                                 total=0 if outcome == 'failed' else 7)
                bridge, executor, calls, outcomes = bridge_fixture(namespace, prompt, payload, primary)
                with patch.dict(sys.modules, {'mta_client_executor': executor}):
                    if outcome == 'committed':
                        returned = bridge.run()
                        self.assertIs(returned.local_commit, True)
                        self.assertIs(returned.peer_ack, False)
                        self.assertEqual(len(outcomes), 1)
                    elif primary is not None:
                        with self.assertRaises(InjectedFailure) as raised:
                            bridge.run()
                        self.assertIs(raised.exception, primary)
                        self.assertEqual(outcomes, [])
                    else:
                        with self.assertRaises(namespace['StateBridgeError']) as raised:
                            bridge.run()
                        self.assertEqual(raised.exception.code, 'receive_failed')
                        self.assertEqual(outcomes, [])
                status = bridge.status()
                local = outcome in ('committed', 'saved_failed')
                self.assertIs(status['local_commit_verified'], local)
                self.assertIs(status['peer_ack_verified'], False)
                self.assertEqual(status['result']['file_count'], payload['file_count'])
                self.assertEqual(status['result']['total_size'], payload['total_size'])
                self.assertEqual(bridge.state.transfer['filesDone'], payload['file_count'] if local else 0)
                self.assertIs(bridge.state.transfer['localCommitVerified'], local)
                self.assertIs(bridge.state.transfer['peerAckVerified'], False)
                self.assertIs(status['restore_pending'], True)
                self.assertIs(status['parent_restore_verified'], False)
                self.assertIs(status['receive_available'], False)
                self.assertIs(status['phone_tested'], False)
                self.assertEqual(bridge.state.state, 'restoring')
                self.assertEqual(calls.count('fixture_finish'), 1)
                self.assertEqual(calls.count('fixture_restore'), 1)
                self.assertIn(('fixture_parent_start', 300), calls)
        print('RECEIVE_DURABLE_CONTROL_BRIDGE_FIXTURE_CONTRACT=1')


if __name__ == '__main__':
    unittest.main(verbosity=2)
