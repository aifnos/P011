"""One affected HOST actual-QML method; saved_failed is strict inert IPC DATA.

The actual GUI20-bound old Receiver page and versioned candidate run with fixed
QML dependencies. Only request() is a delayed in-memory entry seam. This does
not execute/validate native receive, real saving, IPC transport, restoration,
FileCenter media, XHR or a phone. It tests the display and unchanged UI gates.
No test or window is started by importing the module; no old TestCase is used.
"""
import ast
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest


_HELPER_PATH = Path(__file__).resolve().parent / 'qml_candidate_fixture_v1.py'
_HELPER_RAW = _HELPER_PATH.read_bytes()
if (len(_HELPER_RAW) != 7249 or hashlib.sha256(_HELPER_RAW).hexdigest() !=
        '346c11f2a432101d0bc0cc40c8bcccb5b50c2f39eba4a396a291f5f5949fecd3'):
    raise RuntimeError('receive_durable_fixture_helper_pin')
_HELPER_SPEC = importlib.util.spec_from_file_location('p011_receive_durable_qml_fixture_v1', _HELPER_PATH)
_HELPER = importlib.util.module_from_spec(_HELPER_SPEC)
# Execute only the exact checked bytes, without a second loader read or sys.path.
exec(compile(_HELPER_RAW, str(_HELPER_PATH), 'exec'), _HELPER.__dict__)
QtFixture, dependencies, verify_delta = _HELPER.QtFixture, _HELPER.dependencies, _HELPER.verify_delta


SOURCE = ('candidate/formal-receive-filecenter-ui-v1/device/mta/MtaPage.qml', 27441,
          '6f87bdfc8e3b00a85642dd849963219962c47b563d71bf65c291d1e73bcb77b2')
CANDIDATE = ('candidate/receive-durable-state-v1/device/mta/MtaPage.qml', 28426,
             'b5f69f032395999c5bd2bdbb3759e7cb47859baee0a87fe462341b1b99ff0755')
DELTA = ('candidate/receive-durable-state-v1/exactsource-delta.json', 2864,
         '3846c335f69e1ba8866668fa12ee173ff359836eecfba0b385101c91779fbe50')

HARNESS = '''import QtQuick 2.10
Item {
    id:fixture;objectName:"durableReceiverHostFixture";width:800;height:268
    property var requests:[]
    property var actions:[]
    function record(path,form,done){
        if(path!=="/v1/status"&&path!=="/v1/action")throw new Error("HOST unexpected receive IO");
        requests.push({path:path,form:form===null?null:JSON.parse(JSON.stringify(form)),done:done,replied:false});
    }
    function prime(){
        if(requests.length!==1||requests[0].path!=="/v1/status")throw new Error("HOST initial status");
        requests[0].replied=true;requests[0].done(false,{reason:"HOST inert service"});
    }
    function apply(value,tab,offline){
        page.tab=tab;page.applyStatus(value);if(offline)page.backendOnline=false;
    }
    function find(item,name){
        if(item.objectName===name)return item;
        for(var i=0;i<item.children.length;i++){var child=find(item.children[i],name);if(child)return child;}
        return null;
    }
    function pressPrimary(){
        var item=find(page,"mtaPrimary");
        if(!item||!item.enabled)throw new Error("HOST primary gate");item.clicked();
    }
    function snapshot(){
        var primary=find(page,"mtaPrimary"),secondary=find(page,"mtaSecondary"),files=find(page,"mtaFiles");
        var rename=find(page,"mtaRename"),refresh=find(page,"mtaRefresh"),rows=[];
        for(var i=0;i<requests.length;i++)rows.push({path:requests[i].path,form:requests[i].form,replied:requests[i].replied});
        return {friendly:page.friendlyState(),info:page.infoText(),
            durable:typeof page.durableReceiveFailure==="function"?page.durableReceiveFailure():false,
            currentState:page.currentState,tab:page.tab,online:page.backendOnline,radioBusy:page.radioBusy,
            selectionBusy:page.selectionBusy,preparing:page.preparing,transferring:page.transferring,
            restoring:page.restoring,hasRequest:page.hasRequest,actionPending:page.actionPending,
            statusPending:page.statusPending,leaving:page.leaving,sendCapability:page.capability("send"),
            receiveCapability:page.capability("receive"),canPrepare:page.canPrepareSend(),
            primaryEnabled:primary.enabled,secondaryEnabled:secondary.enabled,filesEnabled:files.enabled,
            renameEnabled:rename.enabled,refreshEnabled:refresh.enabled,
            primaryText:primary.text,secondaryText:secondary.text,
            requests:rows,actions:actions.slice(0),width:page.width,height:page.height,
            endpoint:page.serviceUrl,token:page.token};
    }
    MtaPage {
        id:page;anchors.fill:parent;hostPreview:true;nicknameEditorAvailable:true
        function request(path,form,done){fixture.record(path,form,done);}
        onActionObserved:function(action){fixture.actions.push(action);}
    }
}
'''


def status_value(state='error', commit=False, outcome='failed', pending=False,
                 capability=False, direction='receive'):
    return dict(state=state, nickname='HOST Receiver DATA', devices=[], received=[],
                discoverable=False, scanning=False, restorePending=pending,
                reason='HOST original receive failure',
                capabilities=dict(receive=dict(available=capability, reason='HOST unavailable'),
                                  send=dict(available=False), scan=False, rename=False),
                transfer=dict(direction=direction, bytes=7, totalBytes=10, archiveBytes=10),
                receiveLifecycle=dict(local_commit_verified=commit,
                                      result=dict(outcome=outcome)),
                networkRecovery=dict(restorePending=pending, recoveryLocked=False))


def unaffected(snapshot):
    return {key: value for key, value in snapshot.items()
            if key not in ('friendly', 'info', 'durable')}


class DurableReceiveStateTests(unittest.TestCase):
    def test_actual_receiver_saved_failed_display_and_unchanged_action_gates(self):
        spec, bindings = verify_delta(self, DELTA,
                                     'p011-receive-durable-state-source-delta-v1',
                                     SOURCE, CANDIDATE)
        self.assertEqual(3, len(spec['replacements']))
        self.assertEqual(2, len(bindings))
        # The actual GUI20 validator is parsed as DATA, never executed.
        validator_tree = ast.parse(bindings[1])
        assignments = [node for node in validator_tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'PINS'
                               for target in node.targets)]
        self.assertEqual(1, len(assignments))
        pins = ast.literal_eval(assignments[0].value)
        page_pins = [row for row in pins if row[0] == 'mta/MtaPage.qml']
        self.assertEqual([('mta/MtaPage.qml', SOURCE[1], SOURCE[2])], page_pins)

        cases = []
        for state in ('error', 'failed', 'idle'):
            cases.append((state + '_strict_saved_failed', status_value(state, True, 'saved_failed'),
                          'receive', False, 'saved'))
        cases.extend((
            ('restoring_strict_saved_failed', status_value('restoring', True, 'saved_failed', True),
             'receive', False, 'pending'),
            ('error_with_pending_saved_failed', status_value('error', True, 'saved_failed', True),
             'receive', False, 'pending'),
        ))
        for commit in (False, None, 1, 'true', {}, []):
            cases.append(('unknown_commit_' + repr(commit), status_value('error', commit, 'saved_failed'),
                          'receive', False, 'none'))
        for outcome in ('failed', 'cancelled', 'saved_unconfirmed', 'completed', '', None, True):
            cases.append(('wrong_outcome_' + repr(outcome), status_value('error', True, outcome),
                          'receive', False, 'none'))
        missing_lifecycle = status_value()
        del missing_lifecycle['receiveLifecycle']
        cases.append(('missing_lifecycle', missing_lifecycle, 'receive', False, 'none'))
        missing_result = status_value('error', True, 'saved_failed')
        del missing_result['receiveLifecycle']['result']
        cases.append(('missing_result', missing_result, 'receive', False, 'none'))
        cases.extend((
            ('offline_stale_saved_failed', status_value('error', True, 'saved_failed'),
             'receive', True, 'none'),
            ('sender_tab_stale_saved_failed', status_value('error', True, 'saved_failed'),
             'send', False, 'none'),
            ('send_direction_stale_saved_failed', status_value('connecting', True, 'saved_failed', direction='send'),
             'receive', False, 'none'),
            ('ordinary_completed', status_value('completed', True, 'completed'), 'receive', False, 'none'),
            ('ordinary_restoring', status_value('restoring', False, 'failed', True), 'receive', False, 'none'),
            ('ordinary_connecting', status_value('connecting', False, 'failed'), 'receive', False, 'none'),
        ))
        incoming = status_value('awaiting_confirmation', True, 'saved_failed', capability=True)
        incoming['request'] = dict(id='HOST-request', name='HOST sender', fileCount=1, totalBytes=10)
        cases.append(('incoming_request_priority', incoming, 'receive', False, 'none'))

        results = {}
        for label, pin in (('original', SOURCE), ('candidate', CANDIDATE)):
            fixture = QtFixture(self, [('MtaPage.qml', pin)] + dependencies(receive=True), HARNESS)
            try:
                fixture.call('prime')
                rows = {}
                for name, value, tab, offline, expected in cases:
                    fixture.call('apply', copy.deepcopy(value), tab, offline)
                    actual = fixture.snapshot()
                    self.assertEqual((800, 268, '', ''),
                                     (actual['width'], actual['height'], actual['endpoint'], actual['token']))
                    self.assertEqual(1, len(actual['requests']), name)
                    self.assertEqual([], actual['actions'], name)
                    rows[name] = actual
                    if label != 'candidate':
                        continue
                    if expected == 'saved':
                        self.assertIs(actual['durable'], True, name)
                        self.assertEqual('文件已保存，但传输取消/失败', actual['friendly'], name)
                        self.assertIn('文件已保存，但传输取消/失败', actual['info'], name)
                        self.assertNotIn('传输完成', actual['friendly'], name)
                    elif expected == 'pending':
                        self.assertIs(actual['durable'], True, name)
                        self.assertEqual('文件已保存，恢复待核验', actual['friendly'], name)
                        self.assertIn('原网络恢复仍待核验', actual['info'], name)
                        self.assertNotIn('恢复完成', actual['info'], name)
                    elif name != 'incoming_request_priority':
                        self.assertIs(actual['durable'], False, name)
                # DATA never makes a new receive/rename/file action admissible.
                restoring = rows['restoring_strict_saved_failed']
                self.assertIs(restoring['radioBusy'], True)
                for gate in ('primaryEnabled', 'secondaryEnabled', 'filesEnabled', 'renameEnabled'):
                    self.assertIs(restoring[gate], False, gate)
                self.assertEqual('restoring', restoring['currentState'])
                # Run one actual unchanged signal handler; HTTP remains inert.
                fixture.call('apply', copy.deepcopy(incoming), 'receive', False)
                fixture.call('pressPrimary')
                action_snapshot = fixture.snapshot()
                self.assertEqual(['accept'], action_snapshot['actions'])
                self.assertEqual({'action': 'accept', 'requestId': 'HOST-request'},
                                 action_snapshot['requests'][-1]['form'])
                self.assertEqual('/v1/action', action_snapshot['requests'][-1]['path'])
                results[label] = (rows, action_snapshot)
            finally:
                fixture.close()
        for name, _, _, _, expected in cases:
            old, new = results['original'][0][name], results['candidate'][0][name]
            self.assertEqual(unaffected(old), unaffected(new), name)
            if expected == 'none':
                self.assertEqual(old['friendly'], new['friendly'], name)
                self.assertEqual(old['info'], new['info'], name)
        self.assertEqual(unaffected(results['original'][1]), unaffected(results['candidate'][1]))
        self.host_only_case_count = len(cases)
        print('RECEIVE_DURABLE_QML_FIXTURE_CONTRACT=1')


if __name__ == '__main__':
    unittest.main()
