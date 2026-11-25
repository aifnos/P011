import QtQuick 2.10
import "qrc:/ZybQmlFiles/Style"
ListView {
    id:view;property var rows:[];property bool showSource:false;model:rows;clip:true;spacing:4;boundsBehavior:Flickable.StopAtBounds
    delegate:Rectangle {
        width:view.width;height:Math.max(42,val.paintedHeight+16)+(view.showSource?src.paintedHeight+6:0);radius:4;color:index%2?"#18191b":"#252629"
        ToolText{x:10;y:4;width:parent.width*0.32;height:34;text:modelData.key;font.pixelSize:21}
        ToolText{id:val;x:parent.width*0.34;y:8;width:parent.width*0.64-12;text:String(modelData.value)+(modelData.unit?" "+modelData.unit:"");color:modelData.available?Style.mainColor:"#888a90";font.pixelSize:21;wrapMode:Text.WrapAnywhere;elide:Text.ElideNone}
        ToolText{id:src;x:10;y:Math.max(42,val.paintedHeight+16);width:parent.width-20;text:(modelData.source||"")+(modelData.note?" · "+modelData.note:"");color:"#a8a9af";font.pixelSize:16;wrapMode:Text.WrapAnywhere;elide:Text.ElideNone;visible:view.showSource}
    }
    Rectangle{width:3;radius:1;color:Style.mainColor;x:parent.width-3;height:Math.max(12,view.visibleArea.heightRatio*view.height);y:view.visibleArea.yPosition*view.height;visible:view.contentHeight>view.height}
}
