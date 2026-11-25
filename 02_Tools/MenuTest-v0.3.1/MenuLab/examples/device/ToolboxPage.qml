// Menu integration prototype; not yet validated inside P011 Z03.
// This is loaded INSIDE the original 800x268 page area. No extra y=106 or rotation.
import QtQuick 2.10
import "MenuCapture.js" as Capture
import "qrc:/ZybQmlFiles/Style"
import "qrc:/ZybQmlFiles/Funcs/UILogics.js" as UILogic

Rectangle {
    id: toolbox
    anchors.fill: parent
    color: Style.mainbgColor
    property string pageType: "p011toolbox"
    property string selectedTitle: ""
    property bool showingChild: child.source.toString().length > 0

    property bool captureBusy: false
    property string captureLabel: "toolbox"
    function mark(value) {
        console.log("P011_MENULAB_EVENT|" + Date.now() + "|" + value);
    }
    function scheduleCapture(label) {
        captureLabel = label;
        captureDelay.restart();
    }
    function capturePage() {
        if (captureBusy || !visible || width < 1 || height < 1) return;
        var n = Capture.reserve();
        if (n === 0) return;
        var filename = Date.now() + "-" + n + "-" + captureLabel.replace(/[^a-zA-Z0-9_-]/g, "_") + ".png";
        captureBusy = true;
        mark("geometry:" + width + "x" + height);
        try {
            var started = toolbox.grabToImage(function(result) {
                var saved = false;
                try { saved = result.saveToFile("/mnt/data/p011-menu/_captures/" + filename); }
                catch (e) { console.warn("P011_MENULAB_CAPTURE_ERROR: " + e); }
                captureBusy = false;
                mark((saved ? "capture_saved:" : "capture_failed:") + filename);
            });
            if (!started) { captureBusy = false; mark("capture_not_started:" + filename); }
        } catch (e) {
            captureBusy = false;
            console.warn("P011_MENULAB_CAPTURE_ERROR: " + e);
        }
    }
    function noteAction(action) {
        mark(action);
        scheduleCapture(action);
    }
    Component.onCompleted: {
        console.log("P011_MENULAB: toolbox ready", width, height);
        mark("toolbox_ready");
        if (typeof devManager !== "undefined") mark("scan_mode:" + devManager.getScanForWhat());
        scheduleCapture("toolbox");
    }
    Timer { id: captureDelay; interval: 450; repeat: false; onTriggered: toolbox.capturePage() }
    Timer { interval: 10000; repeat: true; running: toolbox.visible; onTriggered: toolbox.scheduleCapture(toolbox.showingChild ? toolbox.selectedTitle : "toolbox") }


    function goBack() {
        console.log("P011_MENULAB: back", showingChild ? selectedTitle : "home");
        mark(showingChild ? "back_child" : "back_home");
        if (showingChild) {
            scheduleCapture("toolbox");
            child.source = "";
            selectedTitle = "";
        } else {
            UILogic.backToHome();
        }
    }

    Rectangle {
        id: header
        width: parent.width
        height: 60
        color: "#17191f"
        Rectangle {
            id: backButton
            x: 12; y: 8; width: 96; height: 44; radius: 8
            color: backArea.pressed ? "#41464e" : "#292d35"
            Text { anchors.centerIn: parent; text: "返回"; color: "white"; font.pixelSize: 24; font.family: Style.fontFamily }
            MouseArea { id: backArea; anchors.fill: parent; onClicked: toolbox.goBack() }
        }
        Text {
            anchors.centerIn: parent
            text: toolbox.showingChild ? toolbox.selectedTitle : "工具箱"
            color: "white"; font.pixelSize: 28; font.family: Style.fontFamily
        }
    }

    Rectangle {
        x: parent.width - 106; y: 8; width: 92; height: 44; radius: 8
        color: "#292d35"
        Text { anchors.centerIn: parent; text: "截屏"; color: "white"; font.pixelSize: 22; font.family: Style.fontFamily }
        MouseArea { anchors.fill: parent; onClicked: toolbox.noteAction("manual_capture") }
    }
    Row {
        anchors { left: parent.left; right: parent.right; top: header.bottom; topMargin: 22; leftMargin: 20; rightMargin: 20 }
        spacing: 16
        visible: !toolbox.showingChild
        Repeater {
            model: [
                { title: "时钟", file: "ClockPage.qml", note: "日期与时间" },
                { title: "计时器", file: "TimerPage.qml", note: "一分钟倒计时" },
                { title: "设备信息", file: "DeviceInfoPage.qml", note: "查看当前固件" }
            ]
            delegate: Rectangle {
                width: (toolbox.width - 72) / 3
                height: 126; radius: 12
                color: hit.pressed ? "#264337" : "#232b2a"
                border.color: "#3d5c4e"
                Column {
                    anchors.centerIn: parent; spacing: 12
                    Text { anchors.horizontalCenter: parent.horizontalCenter; text: modelData.title; color: "white"; font.pixelSize: 30; font.family: Style.fontFamily }
                    Text { anchors.horizontalCenter: parent.horizontalCenter; text: modelData.note; color: "#b7c9c3"; font.pixelSize: 20; font.family: Style.fontFamily }
                }
                MouseArea {
                    id: hit
                    anchors.fill: parent
                    onClicked: {
                        console.log("P011_MENULAB: open", modelData.file);
                        toolbox.selectedTitle = modelData.title;
                        child.source = Qt.resolvedUrl(modelData.file);
                    }
                }
            }
        }
    }

    Loader {
        id: child
        anchors { left: parent.left; right: parent.right; top: header.bottom; bottom: parent.bottom }
        visible: toolbox.showingChild
        onStatusChanged: {
            if (status === Loader.Ready) {
                console.log("P011_MENULAB: child ready", source);
                toolbox.mark("child_ready:" + source.toString().split("/").pop());
                toolbox.scheduleCapture(source.toString().split("/").pop());
            }
            if (status === Loader.Error) {
                console.warn("P011 MenuLab child load failed:", source);
                source = "";
                toolbox.selectedTitle = "";
                UILogic.showTip("工具页面加载失败");
            }
        }
    }
    Connections {
        target: child.item
        ignoreUnknownSignals: true
        onUserAction: toolbox.noteAction(action)
    }
    Component.onDestruction: console.log("P011_MENULAB_EVENT|" + Date.now() + "|toolbox_destroyed")
}
