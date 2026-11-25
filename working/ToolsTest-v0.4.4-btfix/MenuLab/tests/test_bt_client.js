/* Host-only lifecycle mocks executing functions extracted from actual QML.
 * This does not instantiate Qt or access ADB, D-Bus or a Bluetooth adapter. */
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const qmlPath = path.resolve(__dirname, "../examples/device/BtDiscovery.qml");
const qml = fs.readFileSync(qmlPath, "utf8");

function blockEnd(source, opening) {
    let depth = 0, quote = "", escaped = false, lineComment = false, blockComment = false;
    for (let index = opening; index < source.length; index++) {
        const character = source[index], next = source[index + 1];
        if (lineComment) { if (character === "\n") lineComment = false; continue; }
        if (blockComment) { if (character === "*" && next === "/") { blockComment = false; index++; } continue; }
        if (quote) {
            if (escaped) escaped = false;
            else if (character === "\\") escaped = true;
            else if (character === quote) quote = "";
            continue;
        }
        if (character === "/" && next === "/") { lineComment = true; index++; continue; }
        if (character === "/" && next === "*") { blockComment = true; index++; continue; }
        if (character === '"' || character === "'") { quote = character; continue; }
        if (character === "{") depth++;
        if (character === "}" && --depth === 0) return index + 1;
    }
    throw new Error("Unterminated QML JavaScript block");
}

const functionPattern = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
const extracted = [];
let match;
while ((match = functionPattern.exec(qml)) !== null) {
    const opening = qml.indexOf("{", match.index);
    const end = blockEnd(qml, opening);
    extracted.push(qml.slice(match.index, end));
    functionPattern.lastIndex = end;
}
assert.strictEqual(extracted.length, 6, "Expected all six actual client functions");
const destructionStart = qml.indexOf("Component.onDestruction:");
assert.notStrictEqual(destructionStart, -1);
const destructionOpening = qml.indexOf("{", destructionStart);
const destruction = qml.slice(destructionOpening + 1, blockEnd(qml, destructionOpening) - 1);

function harness(owner = "toolbox") {
    const requests = [], notices = [], logs = [];
    let clock = 100000, destroyed = false, updates = 0, objectTouchesAfterDestroy = 0;
    const state = {
        owner, requestId: "", alive: true, busy: false, serial: 0, sequence: 0,
        lastStartAt: 0, pending: null, controlRequest: null, lastMark: "",
        lifetime: {alive: true},
        snapshot: {available: false, powered: false, discovering: false,
            status: "idle", active: false, devices: [], counts: {total: 0, named: 0, observed: 0}, error: ""},
        watchdog: {running: false, restart() { this.running = true; }, stop() { this.running = false; }},
        Date: {now() { return clock; }},
        console: {log(...args) { logs.push(args.join(" ")); }},
        updated() { updates++; },
        notice(message) { notices.push(message); },
        main: {showTip(message) { notices.push("stock:" + message); }},
        Api: {request(url, action, callback) {
            const request = {url, action, callback, aborted: false, completed: false};
            request.reply = function(ok, data) {
                if (request.completed) return;
                request.completed = true;
                callback(ok, data);
            };
            request.abort = function() {
                request.aborted = true;
                // Real Api.js may synchronously finish an aborted request.
                request.reply(false, {error: "aborted"});
            };
            requests.push(request);
            return request;
        }}
    };
    state.client = new Proxy(state, {
        get(target, key) {
            if (destroyed) { objectTouchesAfterDestroy++; throw new Error("Destroyed QML object read: " + String(key)); }
            return target[key];
        },
        set(target, key, value) {
            if (destroyed) { objectTouchesAfterDestroy++; throw new Error("Destroyed QML object write: " + String(key)); }
            target[key] = value; return true;
        }
    });
    const context = vm.createContext(state);
    vm.runInContext(extracted.join("\n"), context, {filename: qmlPath});
    return {
        state, requests, notices, logs,
        advance(milliseconds) { clock += milliseconds; },
        updates() { return updates; },
        touches() { return objectTouchesAfterDestroy; },
        destroy() {
            vm.runInContext(destruction, context, {filename: qmlPath + ":destruction"});
            destroyed = true;
        }
    };
}

function snapshot(owner, requestId, generation = 1, active = true) {
    return {available: true, powered: true, discovering: true,
        status: active ? "scanning" : "completed", active,
        owner, request_id: requestId, generation, remaining_ms: active ? 19000 : 0,
        error: "", counts: {total: 3, named: 2, observed: 2},
        devices: [
            {address: "00:11:22:33:44:01", name: "mock1", named: true,
                seen_this_session: true, source: "added", last_seen_age_ms: 100},
            {address: "00:11:22:33:44:02", name: "mock2", named: true,
                seen_this_session: true, source: "updated", last_seen_age_ms: 200},
            {address: "00:11:22:33:44:03", name: "", named: false,
                seen_this_session: false, source: "cache", last_seen_age_ms: null}
        ]};
}

function assertCache(value) {
    assert.strictEqual(value.active, false);
    assert.strictEqual(value.status, "idle");
    assert.strictEqual(value.remaining_ms, 0);
    assert.strictEqual(value.counts.observed, 0);
    assert.strictEqual(value.counts.total, 3);
    assert.strictEqual(value.counts.named, 2);
    for (const device of value.devices) {
        assert.strictEqual(device.seen_this_session, false);
        assert.strictEqual(device.source, "cache");
    }
}

let passed = 0;
function test(name, run) {
    run(); passed++;
    process.stdout.write("PASS " + name + "\n");
}

test("cross-owner snapshots are copied to cache without mutating input", () => {
    const h = harness();
    h.state.requestId = "own";
    const data = snapshot("stock", "foreign");
    h.state.applySnapshot(data);
    assertCache(h.state.snapshot);
    assert.strictEqual(data.active, true);
    assert.strictEqual(data.counts.observed, 2);
    assert.strictEqual(data.devices[0].seen_this_session, true);
    assert.notStrictEqual(h.state.snapshot.devices[0], data.devices[0]);
});

test("new page and same-owner prior request never present cached results as current", () => {
    const h = harness();
    h.state.applySnapshot(snapshot("toolbox", "old"));
    assertCache(h.state.snapshot);
    h.state.requestId = "new";
    h.state.applySnapshot(snapshot("toolbox", "old", 2, false));
    assertCache(h.state.snapshot);
});

test("current request retains active countdown and observed events including completion", () => {
    const h = harness();
    h.state.requestId = "current";
    h.state.applySnapshot(snapshot("toolbox", "current"));
    assert.strictEqual(h.state.snapshot.active, true);
    assert.strictEqual(h.state.snapshot.remaining_ms, 19000);
    assert.strictEqual(h.state.snapshot.counts.observed, 2);
    assert.strictEqual(h.state.snapshot.devices[0].source, "added");
    h.state.applySnapshot(snapshot("toolbox", "current", 1, false));
    assert.strictEqual(h.state.snapshot.status, "completed");
    assert.strictEqual(h.state.snapshot.counts.observed, 2);
});

test("stop reply cannot overwrite a newer start", () => {
    const h = harness();
    h.state.start();
    const firstId = h.state.requestId;
    h.state.stop();
    const oldStop = h.requests[h.requests.length - 1];
    h.state.start();
    const newId = h.state.requestId;
    assert.notStrictEqual(newId, firstId);
    const newData = snapshot("toolbox", newId, 2);
    h.state.applySnapshot(newData);
    const count = h.updates();
    oldStop.reply(true, snapshot("toolbox", firstId, 1, false));
    assert.strictEqual(h.state.snapshot, newData);
    assert.strictEqual(h.updates(), count);
});

test("late start callback cannot overwrite newer request or schedule another poll", () => {
    const h = harness();
    h.state.start();
    const oldStart = h.requests[0], oldId = h.state.requestId;
    h.state.stop(); h.state.start();
    const newId = h.state.requestId, count = h.requests.length;
    oldStart.reply(true, snapshot("toolbox", oldId));
    assert.strictEqual(h.state.requestId, newId);
    assert.strictEqual(h.requests.length, count);
    assert.strictEqual(h.updates(), 0);
});

test("start cancels prior poll and aborted callback cannot apply stale data", () => {
    const h = harness();
    h.state.refresh();
    const poll = h.requests[0];
    h.state.start();
    assert.strictEqual(poll.aborted, true);
    assert.strictEqual(h.updates(), 0);
    assert.strictEqual(h.notices.length, 0);
    assert.strictEqual(h.state.busy, false);
});

test("double start is deduplicated for three seconds, active owned session remains deduplicated", () => {
    const h = harness();
    h.state.start();
    const firstId = h.state.requestId;
    h.state.start(); h.advance(2999); h.state.start();
    assert.strictEqual(h.requests.length, 1);
    assert.strictEqual(h.state.requestId, firstId);
    h.state.applySnapshot(snapshot("toolbox", firstId));
    h.advance(6000); h.state.start();
    assert.strictEqual(h.requests.length, 1);
    h.state.applySnapshot(snapshot("toolbox", firstId, 1, false));
    h.state.start();
    assert.strictEqual(h.requests.length, 2);
    assert.notStrictEqual(h.state.requestId, firstId);
});

test("stop without request is harmless and repeated stop creates no extra request", () => {
    const h = harness();
    h.state.stop();
    assert.strictEqual(h.requests.length, 0);
    h.state.start(); h.state.stop();
    const count = h.requests.length;
    h.state.stop();
    assert.strictEqual(h.requests.length, count);
});

test("GET callback after destruction never reads destroyed client", () => {
    const h = harness();
    h.state.refresh();
    const poll = h.requests[0], callback = poll.callback;
    h.destroy();
    // Invoke underlying callback too, even though abort completed Api already.
    callback(true, snapshot("toolbox", "old"));
    callback(false, {error: "late"});
    assert.strictEqual(h.touches(), 0);
    assert.strictEqual(h.updates(), 0);
    assert.strictEqual(h.notices.length, 0);
});

test("start and teardown-stop callbacks after destruction never read destroyed client", () => {
    const h = harness();
    h.state.start();
    const action = h.requests[0], id = h.state.requestId;
    h.destroy();
    const teardown = h.requests[h.requests.length - 1];
    assert.strictEqual(teardown.action, "bt_stop:toolbox:" + id);
    assert.strictEqual(teardown.aborted, false);
    action.reply(true, snapshot("toolbox", id));
    teardown.reply(true, snapshot("toolbox", id, 1, false));
    assert.strictEqual(h.touches(), 0);
    assert.strictEqual(h.updates(), 0);
});

test("ordinary stop callback pending across destruction is guarded", () => {
    const h = harness();
    h.state.start(); h.state.stop();
    const stop = h.requests[h.requests.length - 1];
    h.destroy();
    stop.reply(true, snapshot("toolbox", "old", 1, false));
    assert.strictEqual(h.touches(), 0);
    assert.strictEqual(h.updates(), 0);
});

test("request IDs satisfy backend alphanumeric length and notices contain no device identity", () => {
    const h = harness("stock");
    h.state.start();
    assert.match(h.state.requestId, /^[A-Za-z0-9]{1,32}$/);
    const error = snapshot("stock", h.state.requestId);
    error.status = "error"; error.active = false; error.error = "PoweredOff";
    h.state.applySnapshot(error);
    assert.strictEqual(h.notices.length, 2);
    assert(h.logs.every(line => !line.includes("00:11:22") && !line.includes("mock1")));
});

process.stdout.write("RESULT " + passed + " host mock tests passed; Qt runtime/device acceptance not implied.\n");
