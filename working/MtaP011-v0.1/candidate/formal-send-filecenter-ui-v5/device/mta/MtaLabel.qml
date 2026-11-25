import QtQuick 2.10
// Uses an installed font only; no font is shipped by this candidate.
Text {
    color: "#ffffff"
    font.family: typeof nativeFontFamily !== "undefined" ? nativeFontFamily : "Source Han Sans SC"
    font.pixelSize: 24
    verticalAlignment: Text.AlignVCenter
    renderType: Text.NativeRendering
    textFormat: Text.PlainText
}

