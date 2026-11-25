// SPDX-License-Identifier: GPL-3.0-or-later
import QtQuick
Rectangle {
    id: keyboard
    height: 136
    color: "#101e29"
    property bool symbols: false
    property bool uppercase: false
    signal committed(string value)
    signal backspaceRequested()
    signal enterRequested()
    signal hideRequested()
    MouseArea { anchors.fill: parent }
    Column {
        anchors.top: parent.top
        anchors.topMargin: 4
        anchors.horizontalCenter: parent.horizontalCenter
        spacing: 4
        Repeater {
            model: keyboard.symbols ? ["1234567890", "-/:.?&=%#_", "@+~!$(),;*"]
                : ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
            delegate: Row {
                required property string modelData
                property string letters: modelData
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: 4
                Repeater {
                    model: parent.letters.split("")
                    delegate: BrowserButton {
                        required property string modelData
                        width: 72
                        height: 28
                        textSize: 20
                        label: keyboard.uppercase && !keyboard.symbols ? modelData.toUpperCase() : modelData
                        onClicked: keyboard.committed(label)
                    }
                }
            }
        }
        Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 4
            BrowserButton { width: 88; height: 32; label: keyboard.uppercase ? "小写" : "大写"; onClicked: keyboard.uppercase = !keyboard.uppercase }
            BrowserButton { width: 88; height: 32; label: keyboard.symbols ? "字母" : "123/符"; onClicked: keyboard.symbols = !keyboard.symbols }
            BrowserButton { width: 232; height: 32; label: "空格"; onClicked: keyboard.committed(" ") }
            BrowserButton { width: 112; height: 32; label: "退格"; onClicked: keyboard.backspaceRequested() }
            BrowserButton { width: 112; height: 32; label: "确认"; onClicked: keyboard.enterRequested() }
            BrowserButton { width: 112; height: 32; label: "收起"; onClicked: keyboard.hideRequested() }
        }
    }
}
