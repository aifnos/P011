// Fixed MTA scene bridge; only the original keyboard reference is borrowed.
// Never searches parent objects, changes keyboard geometry or opens wireless.
import QtQuick 2.10

Item {
    id: bridge
    property var navigator: null
    property var factoryKeyboard: null
    property var ownedFactoryKeyboard: null
    property bool factoryKeyboardCaptured: false
    property bool factoryKeyboardVisible: false
    property bool factoryKeyboardHidden: false
    property bool disposed: false
    property bool entered: false
    readonly property string entryUrl: "file://@REMOTE@/FormalEntry.qml"

    function restoreFactoryKeyboard() {
        if (!factoryKeyboardHidden) return;
        factoryKeyboardHidden = false;
        // Restore the same borrowed object, not a later replacement reference.
        if (ownedFactoryKeyboard) ownedFactoryKeyboard.visible = factoryKeyboardVisible;
    }
    function syncFactoryKeyboard() {
        if (disposed || !navigator || navigator.sceneSource !== entryUrl) {
            restoreFactoryKeyboard();
            return;
        }
        if (!factoryKeyboardCaptured) {
            if (!factoryKeyboard || typeof factoryKeyboard.visible !== "boolean") return;
            ownedFactoryKeyboard = factoryKeyboard;
            factoryKeyboardVisible = factoryKeyboard.visible;
            factoryKeyboardCaptured = true;
        }
        if (ownedFactoryKeyboard) {
            ownedFactoryKeyboard.visible = false;
            factoryKeyboardHidden = true;
        }
    }

    Connections {
        target: bridge.navigator
        onSceneSourceChanged: bridge.syncFactoryKeyboard()
    }
    Timer {
        id: enterTimer
        interval: 1200
        repeat: false
        running: true
        onTriggered: {
            if (!bridge.disposed && !bridge.entered && bridge.navigator &&
                    bridge.factoryKeyboard && typeof bridge.factoryKeyboard.visible === "boolean") {
                bridge.entered = true;
                bridge.navigator.sceneSource = bridge.entryUrl;
                bridge.syncFactoryKeyboard();
                console.log("P011_MTA FORMAL_SCENE_ENTERED");
            } else {
                console.log("P011_MTA FORMAL_SCENE_FAILED");
            }
        }
    }

    Component.onDestruction: {
        disposed = true;
        enterTimer.stop();
        restoreFactoryKeyboard();
        ownedFactoryKeyboard = null;
        factoryKeyboard = null;
        navigator = null;
    }
}
