// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
Rectangle {
    id: control
    property string label: ""
    property int textSize: 20
    signal clicked()
    width: 60
    height: 40
    radius: 4
    color: !enabled ? "#273440" : pointer.pressed ? "#476b81" : "#29495f"
    Text {
        anchors.centerIn: parent
        text: control.label
        color: control.enabled ? "#f4f8fc" : "#8a98a4"
        font.pixelSize: control.textSize
    }
    MouseArea { id: pointer; anchors.fill: parent; enabled: control.enabled; onClicked: control.clicked() }
}
