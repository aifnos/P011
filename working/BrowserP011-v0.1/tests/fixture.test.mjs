// SPDX-License-Identifier: GPL-3.0-or-later
// Node VM fixture logic only. This does not exercise Chromium, Qt or the device.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const html = readFileSync(new URL('../app/home.html', import.meta.url), 'utf8');
const classic = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
const moduleSource = html.match(/<script type="module">\s*([\s\S]*?)<\/script>/)[1];

async function runFixture({ fetchFails = false, scrollable = true } = {}) {
    const fields = new Map();
    for (const id of ['module', 'optional', 'fetch', 'input', 'typing', 'manual']) {
        const listeners = [];
        fields.set(id, {
            textContent: `${id}：等待`, className: 'wait', value: '',
            addEventListener(kind, callback, options) { listeners.push({ kind, callback, once: options?.once }); },
            dispatchEvent(event) {
                for (const listener of [...listeners]) {
                    if (listener.kind === event.type) {
                        listener.callback(event);
                        if (listener.once) listeners.splice(listeners.indexOf(listener), 1);
                    }
                }
            },
        });
    }
    let fetchCount = 0;
    const context = vm.createContext({
        window: {},
        document: {
            getElementById(id) { assert(fields.has(id)); return fields.get(id); },
            documentElement: { scrollHeight: scrollable ? 1000 : 228, clientHeight: 228 },
        },
        Event: class { constructor(type) { this.type = type; this.isTrusted = false; } },
        requestAnimationFrame(callback) { callback(); },
        async fetch(url) {
            fetchCount++;
            assert.equal(url, 'data:application/json,%7B%22probe%22%3A122%7D');
            if (fetchFails) throw new Error('fixed simulated fetch failure');
            return { async json() { return JSON.parse(decodeURIComponent(url.split(',')[1])); } };
        },
    });
    vm.runInContext(classic, context);
    const module = new vm.SourceTextModule(moduleSource, { context });
    await module.link(() => { throw new Error('No imports permitted in this self-contained fixture'); });
    await module.evaluate();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(fetchCount, 1);
    assert.equal(fields.get('typing').value, '', 'synthetic test value is removed');
    assert(!fields.get('manual').textContent.includes('已观察到'), 'synthetic event cannot pass physical input observation');
    return { flags: context.window.p011ProbeFlags, fields };
}

let result = await runFixture();
assert.equal(result.flags, 31, 'all five local DOM capability bits complete');
assert.equal(result.fields.get('module').className, 'pass');
assert.equal(result.fields.get('optional').className, 'pass');
assert.equal(result.fields.get('fetch').className, 'pass');
assert.equal(result.fields.get('input').className, 'pass');
result.fields.get('typing').value = 'private test text';
result.fields.get('typing').dispatchEvent({ type: 'input', isTrusted: true });
assert.equal(result.fields.get('manual').textContent, '实际输入事件：已观察到');
assert.equal(result.flags, 31, 'manual visual indicator is separate from scripted capability bits');
assert(!result.fields.get('manual').textContent.includes('private test text'));
assert.equal((await runFixture({ fetchFails: true })).flags, 27, 'Fetch rejection must not set its pass bit');
assert.equal((await runFixture({ scrollable: false })).flags, 15, 'non-scrollable DOM must not set scrollability bit');
process.stdout.write(JSON.stringify({ scope: 'host-node-vm-fixture-logic', passed: true,
    scenarios: 4, qt_executed: false, chromium_executed: false, device_executed: false }) + '\n');

