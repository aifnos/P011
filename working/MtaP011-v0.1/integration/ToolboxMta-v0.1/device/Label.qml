import QtQuick 2.10
Text {
    color:"#ffffff"
    font.family:typeof nativeFontFamily!=="undefined"?nativeFontFamily:"Source Han Sans SC"
    font.pixelSize:28
    verticalAlignment:Text.AlignVCenter
    renderType:Text.NativeRendering
    textFormat:Text.PlainText
}
