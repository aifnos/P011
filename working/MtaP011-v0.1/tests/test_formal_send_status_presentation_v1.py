"""One affected actual-QML method; HTTP completion order is an explicit model.

Only request() is a delayed in-memory seam. No original XHR, HTTP server, socket,
runtime/Owner, old TestCase, visible window, device, phone or RF is executed.
The unchanged old page supplies two counterexamples, not an old-suite replay.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('candidate/formal-send-filecenter-ui-v5/device/mta/MtaPage.qml', 26769,
          '1084ea1a5a906bbf0f56ea20df031ea9b4a1fd0931879e80cd6dfb475f7eabc2')
CANDIDATE = ('candidate/formal-send-status-presentation-v1/device/mta/MtaPage.qml', 27307,
             '667b3e54c9fc7dbbd41e4fe8533e9926eab7a1942b6220248626bb30acf0f6fc')
DELTA = ('candidate/formal-send-status-presentation-v1/exactsource-delta.json', 3589,
         '2525a8e170129c7ab4682f33c8b99e4c320b1e22b2ff36796d3bc95dc2862bf6')
HELPER = ('tests/qml_candidate_fixture_v1.py', 7249,
          '346c11f2a432101d0bc0cc40c8bcccb5b50c2f39eba4a396a291f5f5949fecd3')
BINDING = ('out/mta-ui-send-picker-v1-c69296a193ff43ce8e5b901d/mta/MtaPage.qml', 26769,
           '1084ea1a5a906bbf0f56ea20df031ea9b4a1fd0931879e80cd6dfb475f7eabc2')
DEPENDENCIES = (
    ('MtaButton.qml', ('candidate/formal-send-filecenter-ui-v5/device/mta/MtaButton.qml', 758,
                     '7e1d4e378b8e3293e617f4dc432cce3c70ae7fe377f2ea26950aa9bb11393bff')),
    ('MtaLabel.qml', ('candidate/formal-send-filecenter-ui-v5/device/mta/MtaLabel.qml', 352,
                    '77caf248c2f83ed50f5221082084e5af360d08fc917df98eb84449e24903bd75')),
    ('MtaTheme.js', ('candidate/formal-send-filecenter-ui-v5/device/mta/MtaTheme.js', 262,
                   '5848aa8bf1dab57cfe590dd80da1122eb819c75c1f208f69ad4184bf669a99ff')),
)
INPUT_ROWS = (SOURCE, CANDIDATE, DELTA, HELPER, BINDING) + tuple(row[1] for row in DEPENDENCIES)
SELECTOR = 'StatusPresentationTests.test_actual_status_action_fence_delayed_callbacks'


def source_contract(inputs):
    for path, size, pin in INPUT_ROWS:
        raw = inputs[path]
        if (len(raw), hashlib.sha256(raw).hexdigest()) != (size, pin):
            raise ValueError('status_presentation_input_pin')
    spec = json.loads(inputs[DELTA[0]])
    if (set(spec) != {'schema', 'evidence', 'source', 'candidate', 'bindings', 'replacements',
                     'runtime_source_only', 'deployed', 'actions_changed', 'native_changed'} or
            spec['schema'] != 'p011-formal-send-status-presentation-source-delta-v1' or
            spec['evidence'] != 'SOURCE_ONLY_NOT_EXECUTED' or
            spec['source'] != list(SOURCE) or spec['candidate'] != list(CANDIDATE) or
            spec['bindings'] != [list(SOURCE), list(BINDING)] or
            spec['runtime_source_only'] is not True or
            any(spec[key] is not False for key in ('deployed', 'actions_changed', 'native_changed'))):
        raise ValueError('status_presentation_delta_shape')
    names = ('presentation_fence_property', 'refresh_presentation_fence', 'action_presentation_fence',
             'leave_presentation_fence', 'reset_presentation_fence')
    if tuple(row['name'] for row in spec['replacements']) != names:
        raise ValueError('status_presentation_delta_scope')
    before, after = inputs[SOURCE[0]], inputs[CANDIDATE[0]]
    if before != inputs[BINDING[0]]:
        raise ValueError('actual_package_binding')
    forward = before
    for row in spec['replacements']:
        if set(row) != {'name', 'before', 'after', 'count'} or type(row['count']) is not int or row['count'] != 1:
            raise ValueError('status_presentation_replacement')
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        if not old or not new or forward.count(old) != 1:
            raise ValueError('status_presentation_forward_anchor')
        forward = forward.replace(old, new, 1)
    if forward != after:
        raise ValueError('status_presentation_full_forward')
    reverse = after
    for row in reversed(spec['replacements']):
        old, new = row['before'].encode('utf-8'), row['after'].encode('utf-8')
        if reverse.count(new) != 1:
            raise ValueError('status_presentation_inverse_anchor')
        reverse = reverse.replace(new, old, 1)
    if reverse != before:
        raise ValueError('status_presentation_full_inverse')
    for start, end in ((b'    function request(', b'    function selectedFileIds('),
                       (b'    function applyStatus(', b'    function refresh(')):
        original = before[before.index(start):before.index(end)]
        candidate = after[after.index(start):after.index(end)]
        if candidate != original:
            raise ValueError('unchanged_xhr_or_status_projection')
    tail = b'    onServiceUrlChanged: resetConnection()'
    if before[before.index(tail):] != after[after.index(tail):]:
        raise ValueError('unchanged_layout_actions_timers')
    return dict(full_byte_forward=True, full_byte_inverse=True, replacements=5,
                xhr_request_unchanged=True, apply_status_unchanged=True,
                layout_actions_timers_unchanged=True, backend_or_admission_changed=False)


def load_helper(test):
    raw = (ROOT / HELPER[0]).read_bytes()
    test.assertEqual(HELPER[1:], (len(raw), hashlib.sha256(raw).hexdigest()))
    spec = importlib.util.spec_from_file_location('private_status_presentation_qml_fixture', ROOT / HELPER[0])
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(ROOT / HELPER[0]), 'exec'), module.__dict__)
    return module


HARNESS = '''import QtQuick 2.10
Item {
    id:fixture;objectName:"statusPresentationFixture";width:800;height:268
    property var requests:[]
    function record(path,form,done){
        if(path!=="/v1/status"&&path!=="/v1/action")throw new Error("HOST unexpected request");
        if(path==="/v1/status"&&form!==null)throw new Error("HOST status method");
        if(path==="/v1/action"&&(!form||["cancel","send_prepare"].indexOf(form.action)<0))throw new Error("HOST action method");
        requests.push({path:path,form:form,done:done,replied:false});
    }
    function reply(index,ok,value){
        if(index<0||index>=requests.length||requests[index].replied)throw new Error("HOST response order");
        requests[index].replied=true;requests[index].done(ok,value);
    }
    function connect(){subject.serviceUrl="http://127.0.0.1:1";subject.token="HOST_TOKEN_ONE";}
    function refresh(){subject.refresh();}
    function issue(){subject.issue("cancel");}
    function prepare(){subject.selectedFiles=[{id:"HOST_FILE"}];subject.prepareSelected();}
    function reset(){subject.resetConnection();}
    function retoken(){subject.token="HOST_TOKEN_TWO";}
    function leave(){subject.prepareLeave();}
    function snapshot(){
        return {state:subject.currentState,reason:subject.status.reason||"",online:subject.backendOnline,
            connection:subject.connectionReason,statusPending:subject.statusPending,
            actionPending:subject.actionPending,preparationPending:subject.sendPreparationPending,
            prepared:subject.preparedFileIds,selected:subject.selectedDeviceId,message:subject.message,
            leaving:subject.leaving,epoch:subject.lifetime.epoch,
            requests:requests.map(function(row){return {path:row.path,action:row.form?row.form.action:null};})};
    }
    MtaPage {
        id:subject;anchors.fill:parent;hostPreview:true
        function request(path,form,done){
            if(!validEndpoint()||leaving){done(false,{reason:"互传服务未就绪"});return;}
            fixture.record(path,form,done);
        }
    }
}
'''


def status_value(state='idle', reason='HOST-current'):
    return dict(state=state, reason=reason, devices=[], received=[], request=None, transfer={},
                scanning=False, discoverable=False, restorePending=False,
                capabilities=dict(send=dict(available=True, reason='HOST-send'),
                                  receive=dict(available=False, reason='HOST-receive'),
                                  scan=False, rename=True))


class StatusPresentationTests(unittest.TestCase):
    def test_actual_status_action_fence_delayed_callbacks(self):
        inputs = {row[0]: (ROOT / row[0]).read_bytes() for row in INPUT_ROWS}
        self.assertEqual(5, source_contract(inputs)['replacements'])
        helper = load_helper(self)
        completed = []

        def fixture(pin=CANDIDATE):
            value = helper.QtFixture(self, [('MtaPage.qml', pin)] + list(DEPENDENCIES), HARNESS)
            value.call('connect')
            self.assertEqual([dict(path='/v1/status', action=None)], value.snapshot()['requests'])
            value.call('reply', 0, True, status_value())
            self.assertFalse(value.snapshot()['statusPending'])
            self.assertTrue(value.snapshot()['online'])
            return value

        for late_ok in (True, False):
            for pin in (SOURCE, CANDIDATE):
                value = fixture(pin)
                try:
                    value.call('refresh')  # GET=1 retained before the action.
                    value.call('issue')    # POST=2 owns the current presentation.
                    value.call('reply', 2, True, status_value(reason='HOST-cancelled'))
                    current = value.snapshot()
                    self.assertFalse(current['actionPending'])
                    value.call('reply', 1, late_ok, status_value('preparing', 'HOST-old') if late_ok else dict(reason='HOST-old-error'))
                    late = value.snapshot()
                    if pin == SOURCE:
                        self.assertEqual('preparing' if late_ok else 'unavailable', late['state'])
                        self.assertNotEqual(current, late, 'original page supplies the concrete counterexample')
                    else:
                        self.assertEqual(current, late, 'old GET cannot overwrite new POST or mark it offline')
                        value.call('refresh')
                        value.call('reply', 3, True, status_value('restoring', 'HOST-fresh'))
                        self.assertEqual('restoring', value.snapshot()['state'])
                        self.assertFalse(value.snapshot()['statusPending'])
                finally:
                    value.close()
            completed.append('late_get_' + ('success' if late_ok else 'failure') + '_after_action_success')

        for late_ok in (True, False):
            value = fixture()
            try:
                value.call('refresh')  # GET=1
                value.call('prepare')  # actual prepareSelected -> send_prepare POST=2
                self.assertTrue(value.snapshot()['preparationPending'])
                value.call('reply', 2, False, dict(reason='HOST-action-error'))
                current = value.snapshot()
                self.assertFalse(current['actionPending'])
                self.assertFalse(current['preparationPending'])
                self.assertEqual([], current['prepared'])
                self.assertTrue(current['statusPending'])
                self.assertEqual(4, len(current['requests']), 'failed action launches fresh GET=3')
                value.call('reply', 1, late_ok, status_value('preparing', 'HOST-old') if late_ok else dict(reason='HOST-old-error'))
                self.assertEqual(current, value.snapshot(), 'old callback cannot clear a newer pending GET')
                value.call('reply', 3, True, status_value(reason='HOST-reconciled'))
                self.assertFalse(value.snapshot()['statusPending'])
                self.assertEqual('HOST-reconciled', value.snapshot()['reason'])
            finally:
                value.close()
            completed.append('late_get_' + ('success' if late_ok else 'failure') + '_after_action_error')

        value = fixture()
        try:
            value.call('issue')  # POST=1, no GET in flight.
            before = value.snapshot()
            for unused in range(3):
                value.call('refresh')
            self.assertEqual(before, value.snapshot(), 'polling does not compete with the current POST')
            value.call('reply', 1, True, {})  # Original success-without-status path requests GET=2.
            self.assertFalse(value.snapshot()['actionPending'])
            self.assertTrue(value.snapshot()['statusPending'])
            value.call('reply', 2, True, status_value('completed', 'HOST-result'))
            self.assertEqual('completed', value.snapshot()['state'])
            value.call('refresh')
            value.call('reply', 3, False, dict(reason='HOST-current-status-error'))
            self.assertFalse(value.snapshot()['online'], 'current failure must not be discarded')
            self.assertFalse(value.snapshot()['statusPending'])
            value.call('refresh')
            value.call('reply', 4, True, {})
            self.assertFalse(value.snapshot()['online'], 'current malformed response keeps the original guard')
            self.assertFalse(value.snapshot()['statusPending'])
            value.call('refresh')
            value.call('reply', 5, True, status_value())
            self.assertTrue(value.snapshot()['online'], 'correct fresh status can recover normal polling')
        finally:
            value.close()
        completed.append('action_period_no_poll_and_current_status_reconciliation')

        value = fixture()
        try:
            value.call('refresh')  # old GET=1
            value.call('issue')    # old POST=2
            value.call('retoken')  # actual token change -> reset -> new GET=3
            before = value.snapshot()
            value.call('reply', 1, False, dict(reason='HOST-old-token-get'))
            self.assertEqual(before, value.snapshot())
            value.call('reply', 3, True, status_value(reason='HOST-new-token'))
            value.call('issue')    # new POST=4
            current = value.snapshot()
            self.assertTrue(current['actionPending'])
            value.call('reply', 2, False, dict(reason='HOST-old-token-action'))
            self.assertEqual(current, value.snapshot(), 'old POST cannot release the newer actionPending or toast')
            value.call('reply', 4, True, status_value(reason='HOST-new-action'))
            self.assertFalse(value.snapshot()['actionPending'])
            self.assertEqual('HOST-new-action', value.snapshot()['reason'])
        finally:
            value.close()
        completed.append('token_change_retains_new_get_and_action_pending')

        value = fixture()
        try:
            value.call('refresh')  # GET=1
            value.call('reset')    # same credentials, actual reset, GET=2
            current = value.snapshot()
            value.call('reply', 1, True, status_value('completed', 'HOST-old-reset'))
            self.assertEqual(current, value.snapshot())
            value.call('reply', 2, True, status_value(reason='HOST-reset-current'))
            self.assertFalse(value.snapshot()['statusPending'])
            self.assertEqual('HOST-reset-current', value.snapshot()['reason'])
        finally:
            value.close()
        completed.append('explicit_reset_retains_fresh_get')

        value = fixture()
        try:
            value.call('refresh')  # GET=1
            value.call('prepare')  # POST=2
            value.call('leave')
            current = value.snapshot()
            self.assertTrue(current['leaving'])
            self.assertFalse(current['actionPending'])
            self.assertFalse(current['statusPending'])
            value.call('reply', 1, True, status_value('completed', 'HOST-after-leave'))
            value.call('reply', 2, False, dict(reason='HOST-after-leave-error'))
            value.call('refresh')
            value.call('issue')
            self.assertEqual(current, value.snapshot(), 'leaving permits no stale presentation or new request')
        finally:
            value.close()
        completed.append('leave_blocks_old_get_post_and_new_requests')

        value = fixture()
        try:
            value.call('refresh')  # GET=1
            value.call('issue')    # POST=2
            current = value.snapshot()
            value.call('reply', 1, True, status_value('completed', 'HOST-old-during-action'))
            self.assertEqual(current, value.snapshot())
            value.call('refresh')
            self.assertEqual(current, value.snapshot())
            value.call('reply', 2, False, dict(reason='本地服务响应超时，状态待核实'))
            self.assertFalse(value.snapshot()['actionPending'])
            self.assertTrue(value.snapshot()['statusPending'])
            value.call('reply', 3, True, status_value(reason='HOST-timeout-reconciled'))
            self.assertFalse(value.snapshot()['statusPending'])
            self.assertEqual('HOST-timeout-reconciled', value.snapshot()['reason'])
        finally:
            value.close()
        completed.append('old_get_during_action_and_timeout_callback_reconciliation')

        self.assertEqual(9, len(completed))
        print('HOST_STATUS_PRESENTATION_V1_PASS methods=1 scenarios=9 http_model=true xhr=false old_suite=0')


if __name__ == '__main__':
    unittest.main()
