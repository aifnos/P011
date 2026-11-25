"""One affected HOST status fixture; not a whole State/session/phone test.

Execute only the selected real State.status AST method from the pinned actual
deploy-v5 source and the one-line candidate. Session/worker/bridge/probe/GO/
network/deadline DATA are explicitly synthetic dependency fixtures. No State
constructor, operation worker, restore proof, IO, RF, device or phone runs.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import threading
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
ORIGIN = ('candidate/formal-send-filecenter-deploy-v5/runtime/mta_service.py', 145540,
          '64a74b3e9082ac06070377d541544e29766f93887c39dcc92d72a87d7ceb7e51')
CANDIDATE = ('candidate/formal-send-cancel-status-v1/runtime/mta_service.py', 145733,
             '4b1971056673e492e42d59410594192ea7165687ec0ac807cb61deccd5e75d82')
MANIFEST = ('candidate/formal-send-filecenter-deploy-v5/assets/ordinary-source-manifest.json', 20796,
            'd000945a5e749a7f4d651305ef0e3a0b9f7fce96ffc2360dfed04b0d37ba230c')
DELTA = ('candidate/formal-send-cancel-status-v1/exactsource-delta.json', 1458,
         '1dcaa43c0d0bc465bda3e8a1b0f8ea18f342346713fb80e1e5a3dff0f6e4d2aa')
CANCEL_REASON = '已取消发送；未报告传输成功'
PREPARING = '正在准备原选中文件；尚未开启无线发送'
SCANNING = '网络已准备，等待选择实际附近设备'
RESTORING = '资源关闭与网络恢复仍待核验；请勿重复开启互传'
RECOVERY_FIXTURE = '资源与网络恢复待核验（HOST fixture）'


def source(pin):
    raw = (ROOT / pin[0]).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin[1:]:
        raise ValueError('fixture_source_pin')
    return raw


def selected_status(raw, filename):
    tree = ast.parse(raw.decode('utf-8'), feature_version=(3, 5))
    states = [row for row in tree.body if isinstance(row, ast.ClassDef) and row.name == 'State']
    if len(states) != 1:
        raise ValueError('fixture_state_class')
    methods = [row for row in states[0].body if isinstance(row, ast.FunctionDef) and row.name == 'status']
    if len(methods) != 1:
        raise ValueError('fixture_selected_status')
    unit = ast.Module(body=[ast.ClassDef(name='State', bases=[], keywords=[],
        body=[copy.deepcopy(methods[0])], decorator_list=[])], type_ignores=[])
    namespace = dict(time=types.SimpleNamespace(monotonic=lambda: 100.0),
                     SendWorker=SendWorkerFixture, StateClientBridge=ReceiveBridgeFixture)
    exec(compile(ast.fix_missing_locations(unit), filename, 'exec'), namespace)
    return namespace['State']


class SendWorkerFixture:
    """Type fixture only; no actual sender worker is created or executed."""
    def status(self):
        raise AssertionError('unused_send_worker_fixture')


class ReceiveBridgeFixture:
    """Synthetic closed cancellation DATA, not a real receive actor proof."""
    def __init__(self, calls):
        self.calls = calls

    def status(self):
        self.calls.append('receive.status')
        return dict(restore_pending=False, result=dict(outcome='cancelled'))


def status_fixture(state_type, kind, phase, closed, initial_state='preparing',
                   initial_reason=PREPARING, receive_bridge=False,
                   no_session=False, wifi_pending=False, radio_pending=False,
                   probes_closed=True, go_pending=False, go_progress=False):
    calls = []

    def dependency(name, value):
        def call(*args):
            calls.append(name)
            return value
        return call

    state = state_type()
    state.lock = threading.RLock()
    state_type.status.__globals__['time'] = types.SimpleNamespace(
        monotonic=dependency('time.monotonic', 100.0))
    state.session = None if no_session else types.SimpleNamespace(
        status=dependency('session.status', dict(phase=phase, closed=closed)))
    state.operation = types.SimpleNamespace(kind=kind, scan=None, send_worker=None,
        client_bridge=ReceiveBridgeFixture(calls) if receive_bridge else None)
    state.state, state.reason = initial_state, initial_reason
    state.wifi_restore_pending, state.radio_restore_pending = wifi_pending, radio_pending
    state._probes_closed = dependency('_probes_closed', probes_closed)  # Fixture, not a close proof.
    progress = dict(state='cancelled', archiveBytesSent=64, archiveSize=256,
        fileCount=1, totalSize=192, peer_completion_verified=False)
    state._go_public_status = dependency('_go_public_status',
        dict(resource_pending=go_pending, progress=progress if go_progress else None)
        if go_progress or go_pending else None)
    state.discoverable = state.scanning = True  # Synthetic fixture, no radio.
    state.transfer = dict(direction='send', bytes=64, totalBytes=256,
                          peerCompletionVerified=False)
    state.devices, state.peer_seen, state.received = {}, {}, []
    state.nickname, state.request = 'HOST fixture', None
    state.wifi_status = dependency('wifi_status', dict(fixture=True, pending=wifi_pending))
    state.receive_available, state.receive_reason, state.scan_available = False, 'HOST fixture', False
    state._go_send_admitted = dependency('_go_send_admitted', False)  # Not a permission grant.
    original_state, original_reason = state.state, state.reason
    result = state.status()
    if state.state != original_state or state.reason != original_reason:
        raise AssertionError('passive_status_mutated_fixture')
    return result, calls


class FormalSendCancelStatusFixtureTests(unittest.TestCase):
    def test_one_affected_status_fixture(self):
        before, after = source(ORIGIN), source(CANDIDATE)
        spec = json.loads(source(DELTA).decode('utf-8'))
        self.assertEqual(set(spec), {'schema', 'evidence', 'source', 'candidate', 'selected_manifest',
            'replacements', 'runtime_source_only', 'deployed', 'session_close_predicate_changed',
            'restoration_branch_changed', 'success_predicate_changed'})
        self.assertEqual(spec['schema'], 'p011-formal-send-cancel-status-source-delta-v1')
        self.assertEqual(spec['evidence'], 'SOURCE_ONLY_NOT_EXECUTED')
        self.assertEqual(spec['source'], list(ORIGIN))
        self.assertEqual(spec['candidate'], list(CANDIDATE))
        self.assertEqual(spec['selected_manifest'], list(MANIFEST))
        self.assertIs(spec['runtime_source_only'], True)
        for name in ('deployed', 'session_close_predicate_changed', 'restoration_branch_changed',
                     'success_predicate_changed'):
            self.assertIs(spec[name], False)
        self.assertEqual(len(spec['replacements']), 1)
        row = spec['replacements'][0]
        self.assertEqual(set(row), {'name', 'before', 'after', 'count'})
        self.assertEqual(row['name'], 'closed_sender_cancelled_status_reason')
        self.assertIs(type(row['count']), int)
        self.assertEqual(row['count'], 1)
        old_block, new_block = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        self.assertEqual(before.count(old_block), 1)
        self.assertEqual(before.replace(old_block, new_block), after)
        self.assertEqual(after.count(new_block), 1)
        self.assertEqual(after.replace(new_block, old_block), before)
        selected = [item for item in json.loads(source(MANIFEST).decode('ascii'))['sources']
                    if item['module'] == 'mta_service']
        self.assertEqual(len(selected), 1)
        self.assertEqual((selected[0]['source'], selected[0]['bytes'], selected[0]['sha256']), ORIGIN)
        original_type = selected_status(before, ORIGIN[0])
        candidate_type = selected_status(after, CANDIDATE[0])
        cases = []
        for kind in ('send', 'go_send'):
            cases += [(kind + '_cancel_prepare', dict(kind=kind, phase='cancelled', closed=True), 'idle', CANCEL_REASON),
                      (kind + '_cancel_scan', dict(kind=kind, phase='cancelled', closed=True,
                       initial_state='scanning', initial_reason=SCANNING), 'idle', CANCEL_REASON),
                      (kind + '_completed', dict(kind=kind, phase='completed', closed=True), 'completed',
                       '已发送并收到对端协议完成；手机界面仍需人工核对'),
                      (kind + '_unconfirmed', dict(kind=kind, phase='sent_unconfirmed', closed=True), 'error',
                       '已发送字节；未收到对端完成确认，请勿重复发送'),
                      (kind + '_failed', dict(kind=kind, phase='failed', closed=True), 'error',
                       '发送未完成；资源已关闭，没有报告成功'),
                      (kind + '_open_cancel', dict(kind=kind, phase='cancelled', closed=False), 'preparing', PREPARING)]
            for phase in ('pending', 'awaiting_finalizer_exit', 'transport_close', 'release', 'extra', 'restore'):
                cases.append((kind + '_' + phase, dict(kind=kind, phase=phase, closed=False), 'restoring', RESTORING))
        cases += [('receive_cancel_result', dict(kind='receive', phase='cancelled', closed=True,
                    receive_bridge=True), 'idle', '已取消接收；原生资源已关闭'),
                  ('receive_cancel_without_result', dict(kind='receive', phase='cancelled', closed=True), 'idle', PREPARING),
                  ('receive_completed', dict(kind='receive', phase='completed', closed=True), 'completed',
                   '文件已保存；手机端完成提示仍需人工核对'),
                  ('send_no_session', dict(kind='send', phase='cancelled', closed=True, no_session=True), 'preparing', PREPARING),
                  ('send_cancel_wifi_pending', dict(kind='send', phase='cancelled', closed=True,
                    wifi_pending=True, initial_reason=RECOVERY_FIXTURE), 'idle', RECOVERY_FIXTURE),
                  ('send_cancel_radio_pending', dict(kind='send', phase='cancelled', closed=True,
                    radio_pending=True, initial_reason=RECOVERY_FIXTURE), 'idle', RECOVERY_FIXTURE),
                  ('send_cancel_probes_pending', dict(kind='send', phase='cancelled', closed=True,
                    probes_closed=False, initial_reason=RECOVERY_FIXTURE), 'idle', RECOVERY_FIXTURE),
                  ('go_send_cancel_go_pending', dict(kind='go_send', phase='cancelled', closed=True,
                    go_pending=True, initial_reason=RECOVERY_FIXTURE), 'idle', RECOVERY_FIXTURE),
                  ('go_send_cancel_progress', dict(kind='go_send', phase='cancelled', closed=True, go_progress=True), 'idle', CANCEL_REASON)]
        self.assertEqual(len(cases), 33)
        for name, args, expected_state, expected_reason in cases:
            with self.subTest(case=name):
                original, original_calls = status_fixture(original_type, **args)
                actual, actual_calls = status_fixture(candidate_type, **args)
                self.assertEqual(actual_calls, original_calls)
                self.assertEqual((actual['state'], actual['reason']), (expected_state, expected_reason))
                affected = args['kind'] in ('send', 'go_send') and args['phase'] == 'cancelled' and \
                    args['closed'] and not args.get('no_session', False) and not actual['restorePending']
                if affected:
                    self.assertEqual(original['reason'], args.get('initial_reason', PREPARING))
                    self.assertEqual(original['state'], 'idle')
                    self.assertEqual({key: value for key, value in actual.items() if key != 'reason'},
                                     {key: value for key, value in original.items() if key != 'reason'})
                    self.assertNotIn('已发送并收到', actual['reason'])
                    self.assertNotIn('资源已关闭', actual['reason'])
                    self.assertEqual(actual['transfer']['bytes'], 64)
                else:
                    self.assertEqual(actual, original)
                    self.assertEqual(actual['reason'].encode('utf-8'), original['reason'].encode('utf-8'))
                if expected_state == 'restoring' or 'pending' in name and args['phase'] == 'cancelled':
                    self.assertIs(actual['restorePending'], True)
            print('FORMAL_SEND_CANCEL_STATUS_CASE=' + name)
        print('FORMAL_SEND_CANCEL_STATUS_CASES=33')


if __name__ == '__main__':
    unittest.main(verbosity=2)
