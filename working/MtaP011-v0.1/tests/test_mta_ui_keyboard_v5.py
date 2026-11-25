"""Affected PC JavaScript logic only; not Qt lifecycle or P011 acceptance.

The two tests execute actual function bodies from this new QML source in Node.
They do not import a receiver/sender graph, instantiate Qt, invoke ADB or start RF.
ROOT is the sole caller of this new test file; the producing agent does not run it.
"""
import json
from pathlib import Path
import re
import subprocess
import unittest


BASE = Path(__file__).resolve().parents[1]
NODE = Path('E:/nodejs/node.exe')
SOURCE = BASE / 'candidate/formal-send-filecenter-ui-v5'


def function(source, name):
    matches = list(re.finditer(r'\bfunction\s+' + re.escape(name) + r'\s*\([^)]*\)\s*\{', source))
    if len(matches) != 1:
        raise ValueError('qml_function_shape')
    match = matches[0]
    depth = 1
    at = match.end()
    # These selected functions contain no brace character inside a string/comment.
    while at < len(source) and depth:
        if source[at] == '{': depth += 1
        elif source[at] == '}': depth -= 1
        at += 1
    if depth:
        raise ValueError('qml_function_extent')
    return source[match.start():at]


def execute(script):
    if not NODE.is_file():
        raise RuntimeError('fixed_pc_node_missing')
    # Local scope avoids a newer Node build's unrelated global navigator property.
    result = subprocess.run([str(NODE), '--eval', '(function(){\n' + script + '\n})();'], capture_output=True, timeout=8,
                            encoding='utf-8', errors='strict')
    if result.returncode != 0 or result.stderr or len(result.stdout) > 4096:
        raise AssertionError('affected_js_failed:' + result.stderr[:2048])
    return json.loads(result.stdout)


class MtaUiKeyboardV5(unittest.TestCase):
    def test_original_keyboard_identity_reentry_and_idempotent_restore(self):
        raw = (SOURCE / 'entry/Bridge.qml').read_text(encoding='utf-8')
        code = '\n'.join(function(raw, name) for name in
                         ('restoreFactoryKeyboard', 'syncFactoryKeyboard'))
        script = r"""
const assert = require('assert');
function keyboard(initial) {
    let value=initial, writes=[];
    return {get visible(){return value}, set visible(next){value=next;writes.push(next)}, writes};
}
var navigator={sceneSource:''}, entryUrl='file:///fixed/entry', disposed=false;
var factoryKeyboard=keyboard(true), ownedFactoryKeyboard=null;
var factoryKeyboardCaptured=false, factoryKeyboardVisible=false, factoryKeyboardHidden=false;
""" + code + r"""
syncFactoryKeyboard();
assert.strictEqual(factoryKeyboard.visible,true);
assert.deepStrictEqual(factoryKeyboard.writes,[]);
assert.strictEqual(factoryKeyboardCaptured,false);
const original=factoryKeyboard;
navigator.sceneSource=entryUrl;syncFactoryKeyboard();
assert.strictEqual(ownedFactoryKeyboard,original);
assert.strictEqual(factoryKeyboardVisible,true);
assert.strictEqual(original.visible,false);
assert.strictEqual(factoryKeyboardHidden,true);
syncFactoryKeyboard();syncFactoryKeyboard();
assert.strictEqual(factoryKeyboardVisible,true);
assert.deepStrictEqual(original.writes,[false]);
const replacement=keyboard(true);factoryKeyboard=replacement;
syncFactoryKeyboard();
assert.deepStrictEqual(replacement.writes,[]);
navigator.sceneSource='file:///other/page';syncFactoryKeyboard();
assert.strictEqual(original.visible,true);
assert.deepStrictEqual(replacement.writes,[]);
restoreFactoryKeyboard();
assert.deepStrictEqual(original.writes,[false,true]);
// A different scene changes the original object before re-entering MTA.
original.visible=false;
navigator.sceneSource=entryUrl;syncFactoryKeyboard();
assert.strictEqual(factoryKeyboardVisible,false);
navigator.sceneSource='';syncFactoryKeyboard();
assert.strictEqual(original.visible,false);
original.visible=true;
navigator.sceneSource=entryUrl;syncFactoryKeyboard();
assert.strictEqual(factoryKeyboardVisible,true);
disposed=true;syncFactoryKeyboard();restoreFactoryKeyboard();
assert.strictEqual(original.visible,true);
assert.deepStrictEqual(replacement.writes,[]);
// Explicit destruction uses the same restore method; Qt delivery is not simulated.
disposed=false;factoryKeyboard=null;ownedFactoryKeyboard=null;
factoryKeyboardCaptured=false;factoryKeyboardHidden=false;
syncFactoryKeyboard();assert.strictEqual(factoryKeyboardCaptured,false);
factoryKeyboard=keyboard(false);navigator.sceneSource=entryUrl;syncFactoryKeyboard();
assert.strictEqual(factoryKeyboardVisible,false);
navigator.sceneSource='';syncFactoryKeyboard();
assert.strictEqual(factoryKeyboard.visible,false);
console.log(JSON.stringify({passed:true,cases:10,qtRuntimeVerified:false,deviceInvoked:false}));
"""
        result = execute(script)
        self.assertEqual(result, dict(passed=True, cases=10,
                                     qtRuntimeVerified=False, deviceInvoked=False))

    def test_idle_sender_default_reason_only_and_original_business_messages(self):
        raw = (SOURCE / 'device/mta/MtaPage.qml').read_text(encoding='utf-8')
        code = '\n'.join(function(raw, name) for name in ('capability', 'capabilityReason',
            'activeDiscovery', 'activeScan', 'sendWaitingText', 'infoText'))
        script = r"""
const assert=require('assert');
var status, backendOnline, currentState, tab, radioBusy, discoveryBusy, actionPending;
var restoring, preparing, hasRequest, sending, selectedFiles, connectionReason;
function reset(){
    status={state:'idle',reason:'receive-default',capabilities:{send:{available:true},receive:{available:false,reason:'receive-default'}}};
    backendOnline=true;currentState='idle';tab='send';radioBusy=false;discoveryBusy=false;
    actionPending=false;restoring=false;preparing=false;hasRequest=false;sending=false;
    selectedFiles=[];connectionReason='disconnected';
}
""" + code + r"""
reset();assert.strictEqual(infoText(),'先从文件中心选择要发送的文件');
selectedFiles=[{id:'fixed'}];assert.strictEqual(infoText(),'点“准备并搜索”，准备完成后选择本轮在线设备');
reset();status.reason='business-error';assert.strictEqual(infoText(),'business-error');
reset();currentState='error';assert.strictEqual(infoText(),'receive-default');
reset();currentState='failed';assert.strictEqual(infoText(),'receive-default');
reset();status.capabilities.send.available=false;assert.strictEqual(infoText(),'receive-default');
status.reason='';status.capabilities.send.reason='send-not-ready';assert.strictEqual(infoText(),'send-not-ready');
reset();status.restorePending=true;assert.strictEqual(infoText(),'receive-default');
reset();status.scanning=true;discoveryBusy=true;assert.strictEqual(infoText(),'receive-default');
reset();status.discoverable=true;discoveryBusy=true;assert.strictEqual(infoText(),'receive-default');
reset();currentState='scanning';assert.strictEqual(infoText(),'receive-default');
reset();tab='receive';assert.strictEqual(infoText(),'receive-default');
reset();status.capabilities.receive.available=true;assert.strictEqual(infoText(),'receive-default');
reset();status.capabilities.receive=false;assert.strictEqual(infoText(),'receive-default');
reset();delete status.capabilities.receive;assert.strictEqual(infoText(),'receive-default');
reset();actionPending=true;assert.strictEqual(infoText(),'receive-default');
reset();radioBusy=true;assert.strictEqual(infoText(),'receive-default');
reset();backendOnline=false;assert.strictEqual(infoText(),'disconnected');
reset();restoring=true;assert.strictEqual(infoText(),'传输已结束，正在还原本次网络设置');
reset();preparing=true;assert.strictEqual(infoText(),'正在准备原选文件与发送网络；可取消准备，请勿重复开始');
reset();hasRequest=true;assert.strictEqual(infoText(),'请确认发送方与文件大小，再选择接受或拒绝');
reset();sending=true;currentState='connecting';status.goSendLifecycle={progress:{state:'awaiting_confirmation'}};
assert.strictEqual(infoText(),'请在对方设备上确认接收文件');
status.goSendLifecycle.progress.state='awaiting_result';
assert.strictEqual(infoText(),'字节已发送，正在等待对方完成确认；请勿重复发送');
console.log(JSON.stringify({passed:true,cases:23,qtRuntimeVerified:false,deviceInvoked:false}));
"""
        result = execute(script)
        self.assertEqual(result, dict(passed=True, cases=23,
                                     qtRuntimeVerified=False, deviceInvoked=False))


if __name__ == '__main__':
    unittest.main()
