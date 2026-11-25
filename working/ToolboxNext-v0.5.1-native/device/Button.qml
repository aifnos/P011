import QtQuick 2.10
import "Theme.js" as Theme
Rectangle {
    id:control
    property string text:""
    property bool accent:false
    property int fontSize:28
    readonly property bool pressed:area.pressed
    signal clicked()
    width:120;height:56;radius:Theme.radius
    color:area.pressed?Qt.darker(accent?Theme.accent:Theme.button,1.25):(accent?Theme.accent:Theme.button)
    opacity:enabled?1:.4
    Label {anchors.fill:parent;anchors.margins:5;text:control.text;font.pixelSize:control.fontSize;horizontalAlignment:Text.AlignHCenter;elide:Text.ElideRight}
    MouseArea {id:area;anchors.fill:parent;enabled:control.enabled;onClicked:control.clicked()}
}
