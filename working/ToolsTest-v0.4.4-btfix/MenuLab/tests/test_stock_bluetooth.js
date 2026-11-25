/* PC-only simulation of functions extracted from the actual stock QML patch.
 * No ADB, Bluetooth access, pairing, or target Qt compilation is performed.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');
const qml = fs.readFileSync(path.join(__dirname, '../patch/SetBtPage.readable.qml'), 'utf8');
const mergeSource = fs.readFileSync(path.join(__dirname, '../examples/device/BtMerge.js'), 'utf8').replace(/^\.pragma library\s*/, '');

function block(at) {
    const first = qml.indexOf('{', at);
    let depth = 0, quote = '', comment = '';
    for (let i = first; i < qml.length; i++) {
        const c = qml[i], n = qml[i + 1];
        if (comment === '//') { if (c === '\n') comment = ''; continue; }
        if (comment === '/*') { if (c === '*' && n === '/') { comment = ''; i++; } continue; }
        if (quote) { if (c === '\\') i++; else if (c === quote) quote = ''; continue; }
        if (c === '/' && (n === '/' || n === '*')) { comment = c + n; i++; continue; }
        if (c === '"' || c === "'") { quote = c; continue; }
        if (c === '{') depth++;
        if (c === '}' && --depth === 0) return qml.slice(first, i + 1);
    }
    throw Error('Unbalanced source at ' + at);
}

function fn(name) {
    const at = qml.indexOf('function ' + name + '(');
    assert(at >= 0, 'missing actual function ' + name);
    return qml.slice(at, qml.indexOf('{', at)) + block(at);
}

function handler(name, after = 0) {
    const at = qml.indexOf(name + ':', after);
    assert(at >= 0, 'missing actual handler ' + name);
    return block(at);
}

function fixture() {
    const rows = [], events = [];
    const model = {
        get count() { return rows.length; },
        get: i => rows[i],
        append: o => rows.push({...o}),
        insert: (i, o) => rows.splice(i, 0, {...o}),
        clear: () => { rows.length = 0; },
        remove: i => rows.splice(i, 1),
        move: (from, to) => rows.splice(to, 0, rows.splice(from, 1)[0])
    };
    const c = {
        rows, events, btmodel: model, view: {model},
        pageAlive: true, btEnabled: true, discoveryStarted: false,
        strPaired: 'paired', strNotPaired: 'available', strFound: 'found', strCache: 'cache',
        btMacList: [], btInfo: {state: 'scaning'},
        BtMerge: vm.runInNewContext(mergeSource + ';({merge:merge})'),
        btStatus: 1, lastMac: '', lastName: '',
        BtConnectStatus: {Bt_Close: 0, Bt_Connected: 3, Bt_Connecting: 2},
        btManager: {},
        discovery: {snapshot: {active: false}, start() { events.push('start'); }, stop() { events.push('stop'); }},
        initTimer: {interval: 30, start() { events.push('timerStart'); }, restart() { events.push('timerRestart'); }, stop() { events.push('timerStop'); }},
        engineSocket: {sendBtScan(v) { events.push('stockScan:' + v); }},
        console: {log() {}}, qsTr: s => s,
        main: {showTip(s) { events.push('tip'); }},
        UILogic: {backToSetPage() { events.push('back'); }}
    };
    c.btManager.getStatus = () => c.btStatus;
    c.btManager.getLastConnBtMac = () => c.lastMac;
    c.btManager.getLastConnBtSsid = () => c.lastName;
    vm.createContext(c);
    for (const name of ['ensurePlaceholder', 'startDiscovery', 'stopDiscovery', 'mergeDiscovery', 'acceptStockResult', 'isHaveItem', 'getPairedItemCount', 'addFirstConnectedItem', 'removeItem'])
        vm.runInContext(fn(name), c);
    c.run = code => vm.runInContext(code.startsWith('{') ? '(function()' + code + ')()' : code, c);
    c.on = handler('onSig_btOn', qml.indexOf('property var btMacList'));
    c.off = handler('onSig_btOff');
    c.init = handler('onTriggered', qml.indexOf('id:initTimer'));
    return c;
}

const cases = [];
function test(name, body) { body(); cases.push(name); }
function snap(devices) { return {powered: true, devices}; }
function dev(address, name, seen = false) { return {address, name, seen_this_session: seen}; }

test('initial enabled entry issues stock replay and private bounded discovery once', () => {
    const c = fixture(); c.run(c.init); c.run(c.init);
    assert.deepStrictEqual(c.events, ['stockScan:true', 'start']);
    assert.strictEqual(c.rows.length, 1);
});
test('closed entry never initiates either scan', () => {
    const c = fixture(); c.btEnabled = false; c.btStatus = 0; c.run(c.init);
    assert.deepStrictEqual(c.events, []);
});
test('successful on schedules delayed start and tolerates stale manager status', () => {
    const c = fixture(); c.btStatus = 0; c.res = true; c.run(c.on);
    assert.deepStrictEqual(c.events, ['timerRestart']);
    assert.strictEqual(c.initTimer.interval, 250);
    c.run(c.init); c.run(c.on); c.run(c.init);
    assert.strictEqual(c.events.filter(x => x === 'start').length, 1);
    assert.strictEqual(c.rows.length, 1);
});
test('off cancels pending start clears rows and rejects late snapshots or stock results', () => {
    const c = fixture(); c.mergeDiscovery(snap([dev('AA', 'A')])); c.run(c.off); c.run(c.init);
    c.mergeDiscovery(snap([dev('BB', 'B')])); c.acceptStockResult('CC', 'C', false);
    c.res = true; c.run(c.on);
    assert.strictEqual(c.rows.length, 0);
    assert.strictEqual(c.events.filter(x => x === 'start').length, 0);
    assert.strictEqual(c.btInfo.state, 'close');
});
test('off then on can create a second independent search session', () => {
    const c = fixture(); c.run(c.init); c.run(c.off);
    c.btEnabled = true; c.res = true; c.run(c.on); c.run(c.init);
    assert.strictEqual(c.events.filter(x => x === 'start').length, 2);
});
test('merge distinguishes historical cache and this-session discovery without pairing', () => {
    const c = fixture(); c.mergeDiscovery(snap([dev('AA', 'Cache'), dev('BB', 'New', true)]));
    assert.deepStrictEqual(c.rows.map(x => x.group), ['cache', 'found']);
    assert(c.rows.every(x => x.discoveryOnly && x.state === 'normal'));
    assert.deepStrictEqual(c.events, []);
});
test('unnamed device is visible and same-MAC later name refresh does not duplicate', () => {
    const c = fixture(); c.mergeDiscovery(snap([dev('aa', '')]));
    assert(c.rows[0].ssid.length > 0);
    c.mergeDiscovery(snap([dev('AA', 'Named', true)]));
    assert.strictEqual(c.rows.length, 1); assert.strictEqual(c.rows[0].ssid, 'Named');
    assert.strictEqual(c.rows[0].group, 'found');
});
test('stock result promotes generic row and preserves connecting or connected state', () => {
    for (const state of ['connecting', 'connected']) {
        const c = fixture(); c.mergeDiscovery(snap([dev('AA', 'Old')])); c.rows[0].state = state;
        c.acceptStockResult('aa', 'Audio', true);
        assert.strictEqual(c.rows.length, 1); assert.strictEqual(c.rows[0].group, 'paired');
        assert.strictEqual(c.rows[0].discoveryOnly, false); assert.strictEqual(c.rows[0].state, state);
        assert.strictEqual(c.rows[0].ssid, 'Audio'); assert.strictEqual(c.btInfo.state, 'scanResult');
    }
});
test('generic snapshots never demote stock row or overwrite nonempty name with empty', () => {
    const c = fixture(); c.acceptStockResult('AA', 'Audio', true); c.rows[0].state = 'connected';
    c.mergeDiscovery(snap([dev('AA', '', true)])); c.acceptStockResult('AA', '', true);
    assert.strictEqual(c.rows[0].ssid, 'Audio'); assert.strictEqual(c.rows[0].group, 'paired');
    assert.strictEqual(c.rows[0].discoveryOnly, false); assert.strictEqual(c.rows[0].state, 'connected');
});
test('stock anonymous then named result becomes visible without duplicate', () => {
    const c = fixture(); c.acceptStockResult('AA', '', false); c.acceptStockResult('AA', 'Speaker', false);
    assert.strictEqual(c.rows.length, 1); assert.strictEqual(c.rows[0].ssid, 'Speaker');
});
test('generic click emits only warning and cannot reach original pairing path', () => {
    const c = fixture(); c.model = {discoveryOnly: true};
    const click = handler('onClicked', qml.indexOf('id:mouse'));
    c.run('(function() ' + click + ')()');
    assert.deepStrictEqual(c.events, ['tip']);
});
test('back and destruction reject late updates and stop helper', () => {
    for (const code of [handler('onBackClicked'), handler('Component.onDestruction')]) {
        const c = fixture(); c.run(code); c.mergeDiscovery(snap([dev('AA', 'Late')]));
        assert.strictEqual(c.pageAlive, false); assert.strictEqual(c.rows.length, 0);
        assert(c.events.includes('stop'));
    }
});
test('discovery merge ignores powered-off snapshots', () => {
    const c = fixture(); c.mergeDiscovery({powered: false, devices: [dev('AA', 'A')]});
    assert.strictEqual(c.rows.length, 0);
});
test('unchanged snapshot preserves row identity and omitting diagnostic rows removes only those rows', () => {
    const c = fixture(); c.acceptStockResult('AA', 'Audio', true);
    const s = snap([dev('BB', 'Nearby', true)]); c.mergeDiscovery(s);
    const stock = c.rows[0], generic = c.rows[1]; c.mergeDiscovery(s);
    assert.strictEqual(c.rows[0], stock); assert.strictEqual(c.rows[1], generic);
    c.mergeDiscovery(snap([]));
    assert.strictEqual(c.rows.length, 1); assert.strictEqual(c.rows[0], stock);
});
test('diagnostic rows are bounded to 100 and no-device error snapshot leaves existing rows alone', () => {
    const c = fixture(); c.mergeDiscovery(snap(Array.from({length: 130}, (_, i) => dev('ID' + i, 'Test' + i))));
    assert.strictEqual(c.rows.length, 100);
    c.mergeDiscovery({powered: true, error: 'temporary'}); assert.strictEqual(c.rows.length, 100);
});
test('connected startup insertion is idempotent and stock-eligible', () => {
    const c = fixture(); c.lastMac = 'AA'; c.lastName = 'Speaker';
    c.addFirstConnectedItem(); c.addFirstConnectedItem();
    assert.strictEqual(c.rows.length, 1); assert.strictEqual(c.rows[0].state, 'connected');
    assert.strictEqual(c.rows[0].discoveryOnly, false);
});

assert(qml.includes('import "file:///mnt/data/p011-menu" as Toolbox'));
assert(!qml.includes('sacnResult'));
console.log(JSON.stringify({status: 'PASS_PC_SIMULATION_ONLY', cases, count: cases.length, qt_engine_compilation: false, device_access: false}, null, 2));
