"""One new narrow HOST method; not a 35-source lifecycle or device test.

Actual pinned codec encoders/decoders and Parent receive-frame parser execute.
The CONNECT-sent flag, binding metadata and prompt are explicitly synthetic IPC
prerequisites. No Parent.start/Popen, F.run, RF, TLS, file consent, commit,
restore or physical pipe is invoked or inferred. No existing test is imported.
"""
import builtins
import hashlib
import json
from pathlib import Path
import types
import unittest

BASE = Path(__file__).resolve().parents[1]
INPUTS = (
    ('p011_json', 'runtime/p011_json.py',
     'fb6c803b185283258c2312e630df8bb80d6299007e95a1f3cf31250aa0e8ca88'),
    ('mta_protocol', 'runtime/mta_protocol.py',
     '4f7c2bd46cde114f0a2a0c33b31631aa463f09e71b156d26e34daf2251dd8a57'),
    ('mta_client_control_frame', 'candidate/client-terminal-v34/runtime/mta_client_control_frame.py',
     'd1a8fce91ab705524f14edac8d81e8d391c0cddbf8f4ac96ee7a6446c0512278'),
    ('mta_client_executor', 'candidate/client-terminal-v34/runtime/mta_client_executor.py',
     'ea2807f60f531549854210f4a8b4f8ef066614049ba4c55aa55fedda4c2ba4bc'),
)


def definitions():
    modules, original_import = {}, builtins.__import__
    def private_import(name, *args, **kwargs):
        if name.startswith(('mta_', 'p011_')):
            if name not in modules: raise ImportError('HOST unplanned private import')
            return modules[name]
        return original_import(name, *args, **kwargs)
    for name, path, pin in INPUTS:
        raw = (BASE / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != pin:
            raise ValueError('HOST fixed source changed')
        module = types.ModuleType(name)
        module.__file__ = 'HOST-fixed-terminal-v34/' + name + '.py'
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=private_import)
        modules[name] = module
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return modules


class NoNativeIO:
    def __getattr__(self, name):
        raise AssertionError('HOST forbidden native IO: ' + name)


class ClientTerminalV34Tests(unittest.TestCase):
    def test_native_codec_and_parent_pre_prompt_terminals_are_stop_only(self):
        modules = definitions()
        codec, f = modules['mta_client_control_frame'], modules['mta_client_executor']
        self.assertEqual(f.CONNECT_CODEC_SHA, INPUTS[2][2])
        self.assertEqual(codec.PRE_PROMPT_TERMINALS, frozenset(('failed', 'cancelled', 'unavailable')))
        binding = codec.ControlBinding({'version': 1, 'run_token': '1' * 32,
            'candidate_sha': '2' * 64, 'operation_id': 'HOST-v34-operation',
            'native_epoch': 8, 'operation_epoch': 8, 'gatt_session': 12,
            'nonce': '3' * 32, 'receive_consent': True})
        manifest = types.SimpleNamespace(run_token='1' * 32, candidate_sha='2' * 64)
        deployment = f.LoadedDeployment(None, modules, manifest, '4' * 64,
            '/HOST-only-not-deployed', binding)
        def parent():
            value = f.ParentExecutor(deployment, _io=NoNativeIO(), _clock=lambda: 1.0)
            # Explicit modeled prerequisite, NOT a native CONNECT/child proof.
            value.connect_ticket = {'unknown': False, 'sent': True}
            return value
        def payload(outcome):
            return {'outcome': outcome, 'task_id': '', 'file_count': 0,
                'total_size': 0, 'peer_ack_verified': False}
        def raw(sequence, value):
            document = {'version': 1, 'binding_sha256': binding._digest,
                'sequence': sequence, 'kind': 'result', 'payload': dict(value)}
            return codec.RX_PREFIX + modules['p011_json'].dumps(document,
                ensure_ascii=True, sort_keys=True).encode('ascii') + b'\n'

        allowed, duplicates, encoded_bad, decoded_bad, parent_bad = 0, 0, 0, 0, 0
        for outcome in ('failed', 'cancelled', 'unavailable'):
            good = payload(outcome)
            wire = codec.encode_receive_event(binding, 0, 'result', good)
            self.assertEqual(codec.decode_receive_event(binding, wire)['payload'], good)
            value = parent()
            f.ParentExecutor._receive_event(value, wire)
            observed = f.ParentExecutor.receive_status(value)
            self.assertEqual(observed['state'], outcome)
            self.assertEqual(observed['result'], good)
            self.assertIsNone(observed['prompt'])
            self.assertIsNone(value.receive_reply_ticket)
            self.assertEqual(observed['download_bytes'], 0)
            self.assertEqual(observed['verified_file_bytes'], 0)
            self.assertEqual(value.frames, [])
            self.assertFalse(value.attempted)
            self.assertFalse(value.closed)
            self.assertFalse(value.reaped)
            self.assertFalse(value.absent)
            allowed += 1
            with self.assertRaises(f.ExecutorError):
                f.ParentExecutor._receive_event(value, wire)
            duplicates += 1

            invalid = [(1, good)]
            for key, item in (('task_id', None), ('task_id', 0), ('file_count', 1),
                    ('total_size', 1), ('peer_ack_verified', True), ('peer_ack_verified', 1),
                    ('outcome', 'committed'), ('outcome', 'refused'),
                    ('outcome', 'confirmation_timeout'), ('outcome', 'timeout')):
                bad = dict(good); bad[key] = item; invalid.append((0, bad))
            for sequence, bad in invalid:
                with self.assertRaises(codec.ControlFrameError):
                    codec.encode_receive_event(binding, sequence, 'result', bad)
                encoded_bad += 1
                bad_wire = raw(sequence, bad)
                with self.assertRaises(codec.ControlFrameError):
                    codec.decode_receive_event(binding, bad_wire)
                decoded_bad += 1
                with self.assertRaises((codec.ControlFrameError, f.ExecutorError)):
                    f.ParentExecutor._receive_event(parent(), bad_wire)
                parent_bad += 1

            # A stateless codec can validate a nonempty post-prompt task. The
            # actual Parent still rejects it when this original prompt is absent.
            other = dict(good); other['task_id'] = 'HOST-other-task'
            other_wire = codec.encode_receive_event(binding, 0, 'result', other)
            with self.assertRaises(f.ExecutorError):
                f.ParentExecutor._receive_event(parent(), other_wire)
            parent_bad += 1
            for field in ('receive_reply_ticket', 'receive_counts'):
                changed = parent()
                setattr(changed, field, {'unknown': False, 'sent': True, 'accepted': True}
                    if field == 'receive_reply_ticket' else {'download': 1, 'files': 0})
                with self.assertRaises(f.ExecutorError):
                    f.ParentExecutor._receive_event(changed, wire)
                parent_bad += 1

        prompt = {'prompt_id': '5' * 32, 'task_id': 'HOST-v34-task', 'file_count': 1,
            'total_size': 3, 'sender_name': 'HOST modeled sender',
            'file_name': 'HOST.bin', 'until': 10.0}
        prompt_wire = codec.encode_receive_event(binding, 0, 'prompt', prompt)
        for outcome in ('committed', 'refused'):
            value = parent()
            f.ParentExecutor._receive_event(value, prompt_wire)
            result = payload(outcome); result['task_id'] = prompt['task_id']
            if outcome == 'committed':
                result['file_count'], result['total_size'] = 1, 3
            with self.assertRaises(f.ExecutorError):
                f.ParentExecutor._receive_event(value,
                    codec.encode_receive_event(binding, 1, 'result', result))
            parent_bad += 1
        # Confirmation timeout requires the already parsed original prompt,
        # not an accepted/refused decision which never arrived on timeout.
        value = parent()
        f.ParentExecutor._receive_event(value, prompt_wire)
        result = payload('confirmation_timeout'); result['task_id'] = prompt['task_id']
        f.ParentExecutor._receive_event(value,
            codec.encode_receive_event(binding, 1, 'result', result))
        self.assertEqual(value.receive_state, 'confirmation_timeout')
        self.assertIsNone(value.receive_reply_ticket)
        print('HOST_PRE_PROMPT_TERMINAL_V34_ONLY ' + json.dumps({
            'allowed': allowed, 'duplicates_rejected': duplicates,
            'encoded_negative': encoded_bad, 'decoded_negative': decoded_bad,
            'parent_negative': parent_bad, 'confirmation_timeout_requires_prompt': True,
            'parent_spawn_executed': False, 'rf_tested': False,
            'restore_verified': False, 'phone_tested': False}, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
