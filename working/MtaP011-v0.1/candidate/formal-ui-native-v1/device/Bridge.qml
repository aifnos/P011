// Fixed scene bridge, loaded only by the new pinned v2.4.0 Z03 copy.
// No keep-awake, vendor socket calls, radio methods or arbitrary page source.
import QtQuick 2.10

Item {
    id: bridge
    property var navigator: null
    property bool disposed: false
    property bool entered: false
    readonly property string entryUrl: "file://@REMOTE@/FormalEntry.qml"

    Timer {
        id: enterTimer
        interval: 1200
        repeat: false
        running: true
        onTriggered: {
            if (!bridge.disposed && !bridge.entered && bridge.navigator) {
                bridge.entered = true;
                bridge.navigator.sceneSource = bridge.entryUrl;
                console.log("P011_MTA FORMAL_SCENE_ENTERED");
            } else {
                console.log("P011_MTA FORMAL_SCENE_FAILED");
            }
        }
    }

    Component.onDestruction: {
        disposed = true;
        enterTimer.stop();
        navigator = null;
    }
}
