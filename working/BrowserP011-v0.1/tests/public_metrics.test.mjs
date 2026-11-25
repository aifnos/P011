// SPDX-License-Identifier: GPL-3.0-or-later
// Synthetic DOM logic only; never opens a network connection or browser.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../app/public_metrics.js', import.meta.url), 'utf8')
    .replace(/^\.pragma library\s*$/m, '');
const library = vm.createContext({});
vm.runInContext(source, library);
const fixedScript = library.script();
const keys = ['ready_complete', 'body_present', 'viewport_width', 'viewport_height',
    'scroll_width', 'scroll_height', 'image_count', 'loaded_image_count', 'text_length'].sort();

function run({ complete = true, bodyPresent = true, invalidGeometry = false } = {}) {
    const privateText = 'PRIVATE_SYNTHETIC_TEXT_NEVER_SERIALIZED';
    const image = (loaded, width, height) => Object.freeze({ complete: loaded, naturalWidth: width,
        naturalHeight: height, get src() { throw new Error('URL access forbidden'); } });
    const body = Object.freeze({ innerText: privateText, scrollWidth: 810, scrollHeight: 700 });
    const document = Object.freeze({ body: bodyPresent ? body : null, readyState: complete ? 'complete' : 'loading',
        documentElement: Object.freeze({ scrollWidth: invalidGeometry ? NaN : 800, scrollHeight: 650 }),
        images: Object.freeze([image(true, 30, 40), image(true, 0, 0), image(false, 30, 40)]),
        get URL() { throw new Error('Document URL access forbidden'); } });
    const window = Object.freeze({ innerWidth: invalidGeometry ? Infinity : 800, innerHeight: 228,
        get location() { throw new Error('Window URL access forbidden'); } });
    const result = vm.runInNewContext(fixedScript, { document, window });
    assert.deepEqual(Object.keys(result).sort(), keys);
    for (const key of keys) assert(['boolean', 'number'].includes(typeof result[key]));
    assert(!JSON.stringify(result).includes(privateText));
    assert.equal(result.loaded_image_count, 1);
    assert.equal(result.image_count, 3);
    return result;
}

const normal = run();
assert.equal(normal.ready_complete, true);
assert.equal(normal.body_present, true);
assert.equal(normal.viewport_width, 800);
assert.equal(normal.viewport_height, 228);
assert.equal(normal.scroll_width, 810);
assert.equal(normal.scroll_height, 700);
assert(normal.text_length > 20);
const empty = run({ complete: false, bodyPresent: false });
assert.equal(empty.ready_complete, false);
assert.equal(empty.body_present, false);
assert.equal(empty.text_length, 0);
const invalid = run({ invalidGeometry: true });
assert.equal(invalid.viewport_width, 0);
assert.equal(invalid.scroll_width, 0);
process.stdout.write(JSON.stringify({ scope: 'HOST_SYNTHETIC_PUBLIC_METRICS_ONLY', passed: true,
    scenarios: 3, network_accessed: false, device_executed: false, chromium_executed: false }) + '\n');
