import QtQuick 2.10
import "MtaTheme.js" as Theme
Rectangle {
    id: control
    property string text: ""
    property bool accent: false
    property int fontSize: 24
    readonly property bool pressed: pointer.pressed
    signal clicked()
    width: 112; height: 62; radius: Theme.radius
    color: pointer.pressed ? Qt.darker(accent ? Theme.accent : Theme.button, 1.2) : (accent ? Theme.accent : Theme.button)
    opacity: enabled ? 1 : 0.4
    MtaLabel {
        anchors.fill: parent; anchors.margins: 5
        text: control.text; font.pixelSize: control.fontSize
        horizontalAlignment: Text.AlignHCenter; elide: Text.ElideRight
    }
    MouseArea { id: pointer; anchors.fill: parent; enabled: control.enabled; onClicked: control.clicked() }
}

