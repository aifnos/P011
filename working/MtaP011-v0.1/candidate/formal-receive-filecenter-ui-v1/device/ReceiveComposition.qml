import QtQuick 2.10
import "toolbox" as Toolbox

// Actual Receiver composition. One Owner and its attached Companion supply both pairs.
Toolbox.ExtensionPage {
    objectName: "formalReceiveFileCenterComposition"
    width: 800
    height: 268
    clip: true
    mtaHostSource: Qt.resolvedUrl("mta/MtaHost.qml")
    bootstrapAllowed: false
    mtaBootstrapAllowed: false
    hostPreview: false
    initialPage: "Mta"
}
