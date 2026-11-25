// Fixed 800x268 scene for the copied factory UI; not a service/guardian.
// The future same-worker Owner session alone creates private credentials.json.
// Runtime credentials must never be included in SOURCE, logs or public ZIPs.
import QtQuick 2.10

Rectangle {
    id: entry
    width: 800
    height: 268
    color: "#101115"
    readonly property string sessionId: "@SESSION@"
    readonly property string credentialsUrl: "file://@REMOTE@/credentials.json"
    property var request: null
    property bool disposed: false
    property bool leaving: false
    property bool failed: false
    property string message: "正在连接本地互传服务"

    function abortCredentials() {
        readDeadline.stop();
        if (request) {
            var old = request;
            request = null;
            old.onreadystatechange = function() {};
            old.abort();
        }
    }

    function failClosed() {
        if (disposed || leaving || failed) return;
        failed = true;
        abortCredentials();
        hostLoader.active = false;
        message = "本地服务未就绪，请返回后重试";
        console.log("P011_MTA FORMAL_UI_FAILED");
    }

    function leave() {
        if (disposed || leaving) return;
        leaving = true;
        abortCredentials();
        // Unload first: the retained MtaHost/MtaPage destructors abort XHRs.
        hostLoader.active = false;
        message = "正在结束互传";
        console.log("P011_MTA FORMAL_UI_EXIT_REQUESTED");
        // Quit only this copied factory application, never a stock process.
        // The future session worker must still call its original Owner.close().
        Qt.quit();
    }

    function readCredentials() {
        if (disposed || leaving || failed || request) return;
        var xhr = new XMLHttpRequest();
        request = xhr;
        xhr.onreadystatechange = function() {
            if (disposed || leaving || failed || request !== xhr ||
                    xhr.readyState !== XMLHttpRequest.DONE) return;
            request = null;
            readDeadline.stop();
            if ((xhr.status !== 0 && xhr.status !== 200) ||
                    xhr.responseText.length < 1 || xhr.responseText.length > 1024) {
                failClosed();
                return;
            }
            var value;
            try { value = JSON.parse(xhr.responseText); }
            catch (e) { failClosed(); return; }
            if (!value || value.session !== sessionId ||
                    typeof value.endpoint !== "string" || typeof value.token !== "string" ||
                    !/^[0-9a-f]{64}$/.test(value.token)) {
                failClosed();
                return;
            }
            var address = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.exec(value.endpoint);
            if (!address || Number(address[1]) > 65535) {
                failClosed();
                return;
            }
            // Initial properties preserve the actual Owner credential pair.
            // Bootstrap is intentionally disabled; no synthetic service/token.
            hostLoader.setSource(Qt.resolvedUrl("device/MtaHost.qml"), {
                endpoint: value.endpoint,
                accessToken: value.token,
                bootstrapAllowed: false,
                hostPreview: false
            });
            value = null;
        };
        readDeadline.start();
        try {
            xhr.open("GET", credentialsUrl);
            xhr.send();
        } catch (e) {
            failClosed();
        }
    }

    Loader {
        id: hostLoader
        anchors.fill: parent
        asynchronous: false
        onLoaded: {
            if (entry.disposed || entry.leaving || entry.failed) {
                active = false;
                return;
            }
            entry.message = "";
            console.log("P011_MTA FORMAL_UI_READY");
        }
        onStatusChanged: if (status === Loader.Error) entry.failClosed()
    }
    Connections {
        target: hostLoader.item
        onExitRequested: entry.leave()
    }
    Text {
        anchors.centerIn: parent
        width: 720
        height: 92
        visible: hostLoader.item === null
        text: entry.message
        color: "#a7a9b7"
        font.pixelSize: 24
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        wrapMode: Text.Wrap
    }
    Rectangle {
        x: 288
        y: 192
        width: 224
        height: 62
        radius: 10
        color: exitPointer.pressed ? "#30323d" : "#242630"
        visible: entry.failed && !entry.leaving
        Text {
            anchors.fill: parent
            text: "返回"
            color: "#ffffff"
            font.pixelSize: 24
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        MouseArea { id: exitPointer; anchors.fill: parent; onClicked: entry.leave() }
    }
    Timer {
        id: readDeadline
        interval: 4000
        repeat: false
        onTriggered: entry.failClosed()
    }
    Keys.onEscapePressed: entry.leave()
    Component.onCompleted: readCredentials()
    Component.onDestruction: {
        disposed = true;
        abortCredentials();
        hostLoader.active = false;
    }
}
