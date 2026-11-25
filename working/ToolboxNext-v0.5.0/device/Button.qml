import QtQuick 2.10
Rectangle {
    id:control; property string text:""; property bool accent:false; signal clicked()
    width:100; height:36; radius:6; color:!enabled?"#242f34":hit.pressed?"#365e58":accent?"#087f69":"#2b3b45"
    Text{anchors.fill:parent;anchors.margins:4;text:control.text;color:control.enabled?"#eef7f5":"#748b91";font.pixelSize:18;horizontalAlignment:Text.AlignHCenter;verticalAlignment:Text.AlignVCenter;elide:Text.ElideRight}
    MouseArea{id:hit;anchors.fill:parent;enabled:control.enabled;onClicked:control.clicked()}
}
