import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
Item {
    Component.onCompleted: console.log("P011_MENULAB: timer ready")
    id: page
    signal userAction(string action)
    property int remainingMs: 60000
    property double deadlineMs: 0
    property bool counting: false
    function toggle() {
        if (counting) {
            remainingMs = Math.max(0, deadlineMs - Date.now());
            counting = false;
            userAction("timer_pause");
        } else {
            if (remainingMs <= 0) remainingMs = 60000;
            deadlineMs = Date.now() + remainingMs;
            counting = true;
            userAction("timer_start");
        }
    }
    Timer {
        interval: 100; running: page.counting; repeat: true
        onTriggered: {
            page.remainingMs = Math.max(0, page.deadlineMs - Date.now());
            if (page.remainingMs === 0) { page.counting = false; page.userAction("timer_done"); }
        }
    }
    Text {
        x: 42; y: 28
        text: page.remainingMs > 0 ? Math.ceil(page.remainingMs / 1000).toString() + " 秒" : "时间到"
        color: "white"; font.pixelSize: 52; font.family: Style.fontFamily
    }
    Row {
        anchors.right: parent.right; anchors.rightMargin: 36; anchors.verticalCenter: parent.verticalCenter
        spacing: 16
        Rectangle {
            width: 132; height: 64; radius: 10; color: "#247c61"
            Text { anchors.centerIn: parent; text: page.counting ? "暂停" : "开始"; color: "white"; font.pixelSize: 26; font.family: Style.fontFamily }
            MouseArea { anchors.fill: parent; onClicked: page.toggle() }
        }
        Rectangle {
            width: 132; height: 64; radius: 10; color: "#343840"
            Text { anchors.centerIn: parent; text: "重置"; color: "white"; font.pixelSize: 26; font.family: Style.fontFamily }
            MouseArea { anchors.fill: parent; onClicked: { page.counting = false; page.remainingMs = 60000; page.userAction("timer_reset"); } }
        }
    }
    // This prototype keeps no background timer after the page is destroyed.
    Component.onDestruction: counting = false
}
