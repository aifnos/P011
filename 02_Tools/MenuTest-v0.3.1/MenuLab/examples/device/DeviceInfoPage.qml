import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Column {
    Component.onCompleted: console.log("P011_MENULAB: device-info ready")
    spacing: 16
    property string firmware: typeof devManager !== "undefined" ? devManager.getVersion() : "原厂上下文不可用"
    Text { x: 26; text: "固件版本"; color: "#9ec2b7"; font.pixelSize: 24; font.family: Style.fontFamily }
    Text { x: 26; width: parent.width - 52; wrapMode: Text.Wrap; text: firmware; color: "white"; font.pixelSize: 24; font.family: Style.fontFamily }
    Text { x: 26; text: "MenuLab 页面原型 · 仅读取版本，不修改系统设置"; color: "#9baba7"; font.pixelSize: 20; font.family: Style.fontFamily }
}
