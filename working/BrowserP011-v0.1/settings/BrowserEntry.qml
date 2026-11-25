// SPDX-License-Identifier: GPL-3.0-or-later
// Native Qt 5 settings page. Qt 6 runs only in a separate browser process.
import QtQuick 2.7
import "qrc:/ZybQmlFiles/Funcs/UILogics.js" as UILogic

Rectangle {
    id: entry
    anchors.fill: parent
    color: "#16171b"
    property string pageType: "p011BrowserEntry"
    property string endpoint: ""
    property string token: ""
    property string state: "starting"
    property string message: "正在打开浏览器…"
    property bool alive: true
    property bool pending: false
    property bool leaving: false
    property bool closeQueued: false
    property var currentRequest: null
    property var requestDone: null

    function readEndpoint() {
        var xhr = new XMLHttpRequest();
        pending = true;
        currentRequest = xhr;
        requestTimeout.restart();
        requestDone = function(ok, reply) {
            if (!ok) {
                showError();
                if (closeQueued) returnToSettings();
                return;
            }
            try {
                var value = JSON.parse(reply);
                if (value.schema !== "p011.browser.endpoint.v1" ||
                        value.host !== "127.0.0.1" || typeof value.port !== "number" ||
                        value.port % 1 !== 0 || value.port < 1 || value.port > 65535 ||
                        typeof value.token !== "string" || !/^[0-9a-f]{64}$/.test(value.token))
                    throw "invalid endpoint";
                endpoint = "http://127.0.0.1:" + value.port;
                token = value.token;
                if (closeQueued) closeBrowser();
                else openBrowser();
            } catch (error) {
                showError();
                if (closeQueued) returnToSettings();
            }
        };
        xhr.onreadystatechange = function() {
            if (!entry.alive || xhr !== entry.currentRequest ||
                    xhr.readyState !== XMLHttpRequest.DONE) return;
            finishRequest(xhr.status === 0 || xhr.status === 200, xhr.responseText);
        };
        try {
            xhr.open("GET", "file:///mnt/data/p011-browser/settings/endpoint.json");
            xhr.send();
        } catch (error) { finishRequest(false, ""); }
    }

    function finishRequest(ok, reply) {
        requestTimeout.stop();
        var done = requestDone;
        requestDone = null;
        currentRequest = null;
        pending = false;
        if (done) done(ok, reply);
    }

    function showError() {
        state = "error";
        message = "浏览器暂不可用，请稍后重试";
    }

    function request(operation, done) {
        if (pending || (operation !== "/open" && operation !== "/status" && operation !== "/close") ||
                !/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(endpoint) || !/^[0-9a-f]{64}$/.test(token)) {
            done(false, null);
            return;
        }
        var xhr = new XMLHttpRequest();
        pending = true;
        currentRequest = xhr;
        requestTimeout.restart();
        requestDone = function(ok, text) {
            var reply = null;
            try {
                reply = JSON.parse(text);
                if (!reply || typeof reply.ok !== "boolean" ||
                        ["ready", "starting", "running", "stopped", "error"].indexOf(reply.state) < 0)
                    throw "invalid reply";
            } catch (error) { ok = false; }
            done(ok && reply !== null && reply.ok, reply);
        };
        xhr.onreadystatechange = function() {
            if (!entry.alive || xhr !== entry.currentRequest ||
                    xhr.readyState !== XMLHttpRequest.DONE) return;
            finishRequest(xhr.status === 200, xhr.responseText);
        };
        try {
            xhr.open("POST", endpoint + operation);
            xhr.setRequestHeader("X-P011-Native-UI", "browser-qml-runtime");
            xhr.setRequestHeader("X-P011-Browser-Token", token);
            xhr.send("");
        } catch (error) { finishRequest(false, ""); }
    }

    function updateState(ok, reply) {
        if (!ok) { showError(); return; }
        state = reply.state;
        if (state === "running") message = "浏览器已打开";
        else if (state === "starting") message = "正在打开浏览器…";
        else if (state === "ready" || state === "stopped") message = "浏览器已关闭";
        else showError();
    }

    function openBrowser() {
        if (pending || leaving) return;
        if (endpoint === "") { readEndpoint(); return; }
        message = "正在打开浏览器…";
        request("/open", function(ok, reply) {
            updateState(ok, reply);
            if (closeQueued) closeBrowser();
        });
    }

    function returnToSettings() {
        leaving = false;
        closeQueued = false;
        UILogic.backToSetPage();
    }

    function closeBrowser() {
        closeQueued = true;
        if (pending) return;
        if (endpoint === "") { returnToSettings(); return; }
        request("/close", function(ok, reply) {
            updateState(ok, reply);
            // A failed close is shown for a retry; it is never reported closed.
            if (ok && (state === "stopped" || state === "ready")) returnToSettings();
            else if (ok) message = "正在关闭浏览器…";
            else { leaving = false; closeQueued = false; }
        });
    }

    function leave() {
        if (leaving) return;
        leaving = true;
        if (endpoint === "" && !pending) returnToSettings();
        else closeBrowser();
    }

    Rectangle {
        x: 12; y: 8; width: 128; height: 48; radius: 6
        color: backHit.pressed ? "#55565f" : "#36383e"
        Text { anchors.centerIn: parent; text: "返回设置"; color: "white"; font.pixelSize: 22 }
        MouseArea { id: backHit; anchors.fill: parent; onClicked: entry.leave() }
    }
    Text {
        anchors.horizontalCenter: parent.horizontalCenter; y: 16
        text: "浏览器"; color: "white"; font.pixelSize: 26; font.bold: true
    }
    Text {
        x: 32; y: 90; width: parent.width - 64; height: 78
        text: entry.message; color: "#e4e5e9"; font.pixelSize: 24
        horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
        wrapMode: Text.Wrap
    }
    Rectangle {
        x: (parent.width - 220) / 2; y: 192; width: 220; height: 54; radius: 7
        color: openHit.pressed ? "#5476b6" : "#365687"
        visible: !entry.leaving && (entry.state === "ready" || entry.state === "stopped" || entry.state === "error")
        opacity: entry.pending ? 0.5 : 1
        Text { anchors.centerIn: parent; text: "打开浏览器"; color: "white"; font.pixelSize: 23 }
        MouseArea { id: openHit; anchors.fill: parent; enabled: !entry.pending; onClicked: entry.openBrowser() }
    }
    Timer {
        id: requestTimeout; interval: 4000
        onTriggered: {
            var xhr = entry.currentRequest;
            if (xhr) { xhr.onreadystatechange = function() {}; xhr.abort(); }
            entry.finishRequest(false, "");
        }
    }
    Timer {
        interval: 1000; repeat: true
        running: entry.alive && entry.visible && entry.endpoint !== "" &&
                 (entry.state === "starting" || entry.state === "running" || entry.closeQueued)
        onTriggered: {
            if (entry.pending) return;
            if (entry.closeQueued) { entry.closeBrowser(); return; }
            entry.request("/status", function(ok, reply) {
                entry.updateState(ok, reply);
                if (entry.closeQueued) entry.closeBrowser();
            });
        }
    }
    Component.onCompleted: readEndpoint()
    Component.onDestruction: {
        alive = false;
        requestTimeout.stop();
        if (currentRequest) { currentRequest.onreadystatechange = function() {}; currentRequest.abort(); }
        currentRequest = null;
        requestDone = null;
        // Best effort only. The controller's independent native-UI identity /
        // heartbeat watchdog remains responsible if this request is lost.
        if ((state === "running" || state === "starting") &&
                /^http:\/\/127\.0\.0\.1:[0-9]+$/.test(endpoint) && /^[0-9a-f]{64}$/.test(token)) {
            try {
                var closeRequest = new XMLHttpRequest();
                closeRequest.open("POST", endpoint + "/close");
                closeRequest.setRequestHeader("X-P011-Native-UI", "browser-qml-runtime");
                closeRequest.setRequestHeader("X-P011-Browser-Token", token);
                closeRequest.send("");
            } catch (error) {}
        }
        token = "";
    }
}
