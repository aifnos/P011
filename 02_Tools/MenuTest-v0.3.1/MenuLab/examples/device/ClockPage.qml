import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item {
    Component.onCompleted: console.log("P011_MENULAB: clock ready")
    id: page
    property date now: new Date()
    Timer { interval: 1000; running: page.visible; repeat: true; onTriggered: page.now = new Date() }
    Column {
        anchors.centerIn: parent
        spacing: 12
        Text { anchors.horizontalCenter: parent.horizontalCenter; text: Qt.formatTime(page.now, "hh:mm:ss"); color: "white"; font.pixelSize: 62; font.family: Style.fontFamily }
        Text { anchors.horizontalCenter: parent.horizontalCenter; text: Qt.formatDate(page.now, "yyyy-MM-dd dddd"); color: "#a6c8be"; font.pixelSize: 24; font.family: Style.fontFamily }
    }
}
