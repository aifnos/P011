import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Rectangle {
    id:control;property string text:"";property bool accent:false;property bool danger:false;signal clicked()
    implicitWidth:120;implicitHeight:44;radius:6;opacity:enabled?1:0.4
    color:area.pressed?"#55565b":accent?Style.mainColor:Style.digbgColor
    ToolText {anchors.fill:parent;anchors.margins:5;horizontalAlignment:Text.AlignHCenter;text:control.text;color:control.accent?"#0f0f0f":control.danger?Style.subColor:"white";font.pixelSize:22}
    MouseArea{id:area;anchors.fill:parent;onClicked:control.clicked()}
}
