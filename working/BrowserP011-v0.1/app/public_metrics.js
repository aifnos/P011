// SPDX-License-Identifier: GPL-3.0-or-later
.pragma library

// The page receives this fixed script only. Its result contains numbers and
// booleans; text, URLs, account state and console contents never cross the API.
function script() {
    return `(function () {
        const body = document.body;
        const root = document.documentElement;
        const images = Array.from(document.images || []);
        function bounded(value) {
            const number = Number(value);
            return Number.isFinite(number) ? Math.max(0, Math.min(100000000, Math.floor(number))) : 0;
        }
        return {
            ready_complete: document.readyState === "complete",
            body_present: !!body,
            viewport_width: bounded(window.innerWidth),
            viewport_height: bounded(window.innerHeight),
            scroll_width: bounded(Math.max(root ? root.scrollWidth : 0, body ? body.scrollWidth : 0)),
            scroll_height: bounded(Math.max(root ? root.scrollHeight : 0, body ? body.scrollHeight : 0)),
            image_count: bounded(images.length),
            loaded_image_count: bounded(images.filter(function (image) {
                return image.complete && image.naturalWidth > 0 && image.naturalHeight > 0;
            }).length),
            text_length: bounded(body ? (body.innerText || "").length : 0)
        };
    })()`;
}
