import QtQuick 2.10
import "toolbox" as Toolbox

// Actual composition. The original Owner and companion supply both pairs.
Toolbox.ExtensionPage {
    objectName: "receiveFileCenterComposition"
    width: 800
    height: 268
    clip: true
    mtaHostSource: Qt.resolvedUrl("mta/MtaHost.qml")
    bootstrapAllowed: false
    mtaBootstrapAllowed: false
    hostPreview: false
    initialPage: "Mta"
}

